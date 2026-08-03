import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  generateKeypair,
  pubkeyFingerprint,
  signPayload,
} from '../../services/security/agent-identity.js';
import {
  createWholeBrainPurge,
  hashRetainedPurgeArtifact,
  verifyWholeBrainPurgeIntent,
  verifyWholeBrainPurgeReceipt,
  writeDurableRetainedPurgeArtifact,
} from '../../services/security/whole-brain-purge.js';

function targetClient() {
  return {
    released: false,
    destroyed: false,
    async query(sql) {
      const text = String(sql);
      if (text.includes('pg_backend_pid')) return { rows: [{ pid: 4242 }] };
      if (text.includes('pg_stat_activity')) return { rows: [{ count: 1 }] };
      if (text.includes('pg_catalog.pg_tables')) return { rows: [{ tablename: 'aimos_memories' }] };
      if (text.includes('count(*)') && text.includes('aimos_memories')) return { rows: [{ count: 2 }] };
      throw new Error(`unexpected target SQL: ${text}`);
    },
    release(destroy = false) {
      this.released = true;
      this.destroyed = destroy;
    },
  };
}

function recreatedPool() {
  return {
    ended: false,
    async query(sql) {
      const text = String(sql);
      if (text.includes('schema_migrations')) return { rows: [{ count: 61 }] };
      if (text.includes('to_regclass')) return { rows: [{ relation: null }] };
      throw new Error(`unexpected recreated SQL: ${text}`);
    },
    async end() { this.ended = true; },
  };
}

test('whole-brain purge is offline, exact-confirmation, categorical, and content-hash free', async () => {
  const maintenanceSql = [];
  let databasePresent = true;
  let fullConnectionChecks = 0;
  const targetClients = [];
  const targetPool = {
    ended: false,
    async connect() {
      const client = targetClient();
      targetClients.push(client);
      return client;
    },
    async end() { this.ended = true; },
  };
  const maintenancePool = {
    async query(sql) {
      maintenanceSql.push(String(sql));
      if (String(sql).includes('FROM pg_database')) {
        return { rowCount: databasePresent ? 1 : 0, rows: databasePresent ? [{ exists: 1 }] : [] };
      }
      if (String(sql).includes('DROP DATABASE')) databasePresent = false;
      if (String(sql).includes('FROM pg_stat_activity') && !String(sql).includes('pid <>')) {
        fullConnectionChecks += 1;
        return { rows: [{ count: fullConnectionChecks === 1 ? 1 : 0 }] };
      }
      if (String(sql).includes('count(*)')) return { rows: [{ count: 0 }] };
      return { rows: [] };
    },
  };
  const deleted = [];
  const fresh = recreatedPool();
  const signer = generateKeypair();
  const persistedIntents = [];
  const service = createWholeBrainPurge({
    targetPool,
    maintenancePool,
    allowCanonical: false,
    filesystemScope: [],
    keychainListFn: () => [
      { service: 'com.aimos.credentials.test', account: 'aimos' },
      { service: `com.aimos.credentials.test.${'a'.repeat(64)}`, account: 'aimos' },
    ],
    keychainDeleteFn: (serviceName, account) => {
      deleted.push([serviceName, account]);
      return true;
    },
    recreateFn: async () => ({ pool: fresh, migrationCount: 61 }),
    signReceiptFn: async (body) => {
      const nonce = 'receipt-nonce';
      const signedTs = 1783780000;
      return {
        signature: signPayload(signer.privkey, body, nonce, signedTs),
        publicKey: signer.pubkey,
        nonce,
        signedTs,
      };
    },
    persistIntentFn: async (intent) => {
      persistedIntents.push(intent);
      return { durable: true, artifact_sha256: hashRetainedPurgeArtifact(intent) };
    },
    nowFn: (() => {
      const values = [new Date('2026-07-11T12:00:00Z'), new Date('2026-07-11T12:00:01Z')];
      return () => values.shift() || new Date('2026-07-11T12:00:01Z');
    })(),
    uuidFn: () => 'purge-ceremony-test',
  });

  const receipt = await service.execute({
    databaseName: 'aimos_purge_test',
    companyId: 'hom',
    confirmation: 'PURGE AIMOS hom aimos_purge_test',
    actor: { fingerprint: pubkeyFingerprint(signer.pubkey), epoch: '2026-07-11T00:00:00.000Z' },
    softwareRelease: 'HOM-AIMOS/test',
  });

  assert.equal(targetPool.ended, true);
  assert.equal(targetClients.at(-1).destroyed, true);
  assert.equal(fresh.ended, true);
  assert.equal(deleted.length, 2);
  assert.ok(maintenanceSql.some((sql) => /ALLOW_CONNECTIONS false/.test(sql)));
  assert.ok(maintenanceSql.some((sql) => /pg_terminate_backend/.test(sql)));
  assert.ok(maintenanceSql.some((sql) => /DROP DATABASE "aimos_purge_test"$/.test(sql)));
  assert.ok(maintenanceSql.every((sql) => !/WITH \(FORCE\)/.test(sql)));
  assert.equal(fullConnectionChecks, 2);
  assert.equal(receipt.body.completion_status, 'complete');
  assert.equal(persistedIntents.length, 1);
  assert.equal(verifyWholeBrainPurgeIntent(persistedIntents[0]).valid, true);
  assert.equal(receipt.body.intent_sha256, hashRetainedPurgeArtifact(persistedIntents[0]));
  assert.equal(receipt.body.postcondition.mode, 'reinitialized_empty');
  assert.equal(verifyWholeBrainPurgeReceipt(receipt).valid, true);
  assert.doesNotMatch(JSON.stringify(receipt), /content_hash|mutation_hash|prev(?:ious)?_hash/i);
});

test('scratch whole-brain purge destroys only the disposable database and verifies the signed receipt', async () => {
  let databasePresent = true;
  const targetClients = [];
  const targetPool = {
    ended: false,
    async connect() {
      const client = targetClient();
      targetClients.push(client);
      return client;
    },
    async end() { this.ended = true; },
  };
  const maintenancePool = {
    async query(sql) {
      const text = String(sql);
      if (text.includes('FROM pg_database')) {
        return { rowCount: databasePresent ? 1 : 0, rows: databasePresent ? [{ exists: 1 }] : [] };
      }
      if (text.includes('DROP DATABASE')) databasePresent = false;
      if (text.includes('count(*)')) return { rows: [{ count: 0 }] };
      return { rows: [] };
    },
  };
  const signer = generateKeypair();
  const fingerprint = pubkeyFingerprint(signer.pubkey);
  const persistedIntents = [];
  const service = createWholeBrainPurge({
    targetPool,
    maintenancePool,
    completionMode: 'destroy',
    allowCanonical: false,
    signReceiptFn: async (body) => {
      const nonce = 'scratch-purge-receipt';
      const signedTs = 1783780100;
      return {
        signature: signPayload(signer.privkey, body, nonce, signedTs),
        publicKey: signer.pubkey,
        nonce,
        signedTs,
      };
    },
    persistIntentFn: async (intent) => {
      persistedIntents.push(intent);
      return { durable: true, artifact_sha256: hashRetainedPurgeArtifact(intent) };
    },
    nowFn: () => new Date('2026-07-11T12:00:02Z'),
    uuidFn: () => 'scratch-purge-ceremony',
  });

  const receipt = await service.execute({
    databaseName: 'aimos_benchmark_test',
    companyId: 'hom',
    confirmation: 'PURGE AIMOS hom aimos_benchmark_test',
    actor: { fingerprint, epoch: '2026-07-11T00:00:00.000Z' },
    softwareRelease: 'HOM-AIMOS/test',
  });

  assert.equal(targetPool.ended, true);
  assert.equal(targetClients.at(-1).destroyed, true);
  assert.equal(receipt.body.credential_items_deleted, 0);
  assert.equal(receipt.body.derived_files_deleted, 0);
  assert.deepEqual(receipt.body.postcondition, {
    mode: 'destroyed',
    database_present: false,
    empty_verified: null,
    migration_count: null,
  });
  assert.equal(verifyWholeBrainPurgeReceipt(receipt).valid, true);
  assert.equal(persistedIntents.length, 1);
  assert.equal(receipt.body.intent_sha256, hashRetainedPurgeArtifact(persistedIntents[0]));

  const tampered = structuredClone(receipt);
  tampered.body.target.database = 'aimos_benchmark_other';
  tampered.canonical_body = JSON.stringify(tampered.body);
  assert.equal(verifyWholeBrainPurgeReceipt(tampered).valid, false);
});

test('whole-brain purge cannot target canonical AIMOS unless the ceremony explicitly enables it', async () => {
  const service = createWholeBrainPurge({
    targetPool: { connect: async () => { throw new Error('must not connect'); } },
    allowCanonical: false,
  });
  await assert.rejects(
    service.inventory({ databaseName: 'aimos', companyId: 'hom' }),
    /canonical purge is not enabled/
  );
});

test('a signed durable intent survives interruption after database destruction', async () => {
  let databasePresent = true;
  let persistedIntent = null;
  const targetPool = {
    async connect() { return targetClient(); },
    async end() {},
  };
  const maintenancePool = {
    async query(sql) {
      const text = String(sql);
      if (text.includes('FROM pg_database')) {
        return { rowCount: databasePresent ? 1 : 0, rows: databasePresent ? [{ exists: 1 }] : [] };
      }
      if (text.includes('DROP DATABASE')) databasePresent = false;
      if (text.includes('count(*)')) return { rows: [{ count: 0 }] };
      return { rows: [] };
    },
  };
  const signer = generateKeypair();
  const service = createWholeBrainPurge({
    targetPool,
    maintenancePool,
    completionMode: 'destroy',
    keychainListFn: () => [{ service: 'interrupt.fixture', account: 'aimos' }],
    keychainDeleteFn: () => { throw new Error('simulated_process_interruption'); },
    signReceiptFn: async (body) => {
      const nonce = body.schema;
      const signedTs = 1783780200;
      return {
        signature: signPayload(signer.privkey, body, nonce, signedTs),
        publicKey: signer.pubkey,
        nonce,
        signedTs,
      };
    },
    persistIntentFn: async (intent) => {
      persistedIntent = structuredClone(intent);
      return { durable: true, artifact_sha256: hashRetainedPurgeArtifact(intent) };
    },
    nowFn: () => new Date('2026-07-11T12:00:03Z'),
    uuidFn: () => 'interrupted-purge-ceremony',
  });

  await assert.rejects(
    service.execute({
      databaseName: 'aimos_test_interruption',
      companyId: 'hom',
      confirmation: 'PURGE AIMOS hom aimos_test_interruption',
      actor: {
        fingerprint: pubkeyFingerprint(signer.pubkey),
        epoch: '2026-07-11T00:00:00.000Z',
      },
      softwareRelease: 'HOM-AIMOS/test',
    }),
    /simulated_process_interruption/,
  );

  assert.equal(databasePresent, false);
  assert.equal(verifyWholeBrainPurgeIntent(persistedIntent).valid, true);
  assert.equal(persistedIntent.body.planned_postcondition, 'destroyed');
});

test('retained purge artifacts are write-once and private on disk', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-purge-artifact-'));
  const artifactPath = path.join(directory, 'intent.json');
  const artifact = { body: { schema: 'test' }, signature: 'fixture' };
  try {
    const persisted = writeDurableRetainedPurgeArtifact(artifactPath, artifact);
    assert.equal(persisted.durable, true);
    assert.equal(persisted.artifact_sha256, hashRetainedPurgeArtifact(artifact));
    assert.equal(fs.statSync(artifactPath).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(fs.readFileSync(artifactPath, 'utf8')), artifact);
    assert.throws(
      () => writeDurableRetainedPurgeArtifact(artifactPath, artifact),
      /refusing to overwrite retained purge artifact/,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('whole-brain purge owner has no server, route, MCP, job, or tool-registry import', () => {
  const files = [
    'server.js',
    ...fs.readdirSync('routes').filter((name) => name.endsWith('.js')).map((name) => `routes/${name}`),
    ...fs.readdirSync('jobs').filter((name) => name.endsWith('.js')).map((name) => `jobs/${name}`),
    'services/orchestration/tool-registry.js',
  ];
  for (const file of files) {
    assert.doesNotMatch(fs.readFileSync(file, 'utf8'), /whole-brain-purge|purge-brain/);
  }
});

test('benchmark cleanup delegates to the offline signed purge owner without shared scratch custody', () => {
  const runner = fs.readFileSync('scripts/benchmark/run-isolated.mjs', 'utf8');
  const ceremony = fs.readFileSync('scripts/ceremony/purge-brain.mjs', 'utf8');
  assert.doesNotMatch(runner, /DROP DATABASE|dropScratchDatabase/);
  assert.match(runner, /scripts\/ceremony\/purge-brain\.mjs/);
  assert.match(runner, /verifyWholeBrainPurgeReceipt/);
  assert.match(runner, /HOUSEKEEPER_CERT_CACHE/);
  assert.match(runner, /restoreSharedFiles\(\)/);
  assert.match(ceremony, /completionMode: scratchTarget \? 'destroy' : 'reinitialize'/);
  assert.match(ceremony, /keychainListFn: scratchTarget \? \(\(\) => \[\]\) : undefined/);
  assert.match(ceremony, /filesystemScope: scratchTarget \? \[\] : defaultPurgeFilesystemScope/);
});

test('multi-target scratch ceremony authenticates once and binds one confirmation to the complete target manifest', () => {
  const ceremony = fs.readFileSync('scripts/ceremony/purge-brain.mjs', 'utf8');
  const enrollmentDb = fs.readFileSync('scripts/identity/db.js', 'utf8');
  const masterResolutionCount = [...ceremony.matchAll(/master = await resolveVerifiedMaster\(/g)].length;
  const passphrasePromptCount = [...ceremony.matchAll(/await readPassphrase\('Master passphrase: '\)/g)].length;
  assert.equal(masterResolutionCount, 1);
  assert.equal(passphrasePromptCount, 1);
  assert.match(
    enrollmentDb,
    /\(id, master_pubkey, fingerprint, keychain_service, keychain_account\)/,
  );
  assert.match(ceremony, /let account = master\.keychain_account \|\| requestedAccount \|\| null/);
  assert.match(ceremony, /const requestedNames = cliValues\('--aimos-db'\)/);
  assert.match(ceremony, /const allScratch = process\.argv\.includes\('--all-scratch'\)/);
  assert.match(ceremony, /choose either --all-scratch or explicit --aimos-db targets/);
  assert.match(ceremony, /\^aimos_\(test\|benchmark\|purge\)_\[A-Za-z0-9_\]\+\$/);
  assert.match(ceremony, /no AIMOS scratch brains found/);
  assert.match(ceremony, /cliValue\('--keychain-account'\)/);
  assert.match(ceremony, /for \(const databaseName of databaseNames\)/);
  assert.match(ceremony, /domain: 'aimos-multi-target-purge\/v1'/);
  assert.match(ceremony, /createHash\('sha256'\)\.update\(targetManifest, 'utf8'\)\.digest\('hex'\)/);
  assert.match(ceremony, /`PURGE AIMOS hom \$\{databaseNames\.length\} SCRATCH BRAINS \$\{targetManifestSha256\}`/);
  assert.match(ceremony, /multi-target purge confirmation mismatch/);
  assert.match(ceremony, /\? `PURGE AIMOS hom \$\{databaseName\}`/);
  assert.match(
    ceremony,
    /: await readLine\(`Type exactly \$\{JSON\.stringify\(`PURGE AIMOS hom \$\{databaseName\}`\)\}`\)/,
  );
  assert.match(ceremony, /canonical AIMOS cannot be included in a multi-target purge ceremony/);
  const owner = fs.readFileSync('services/security/whole-brain-purge.js', 'utf8');
  assert.match(owner, /refusing to overwrite retained purge artifact/);
  assert.match(ceremony, /writeDurableRetainedPurgeArtifact/);
  assert.match(owner, /fs\.fsyncSync\(descriptor\)/);
  assert.match(owner, /fs\.fsyncSync\(directoryDescriptor\)/);
});
