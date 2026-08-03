import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { verifySchedulerGenesisReadiness } from '../../services/orchestration/scheduler.js';
import { verifyGenesisManifest } from '../../scripts/verify-genesis-manifest.mjs';
import { generateKeypair, signPayloadWithContext } from '../../services/security/agent-identity.js';
import { contentHash } from '../../services/security/identity-chain.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function mutationHash(contentHashBuffer, nonce, ts) {
  return createHash('sha256')
    .update(Buffer.concat([contentHashBuffer, Buffer.from(nonce), Buffer.from(String(ts))]))
    .digest();
}

function buildReadyRows() {
  const manifest = verifyGenesisManifest({ brainRoot: root });
  const { pubkey, privkey } = generateKeypair();
  return {
    manifest,
    pubkey,
    rows: manifest.files.map((record, index) => {
      const body = {
        genesis_manifest_schema: manifest.schema,
        genesis_manifest_version: manifest.version,
        genesis_corpus_root: manifest.corpusRoot,
        genesis_file_path: record.path,
        genesis_file_sha256: record.sha256,
        genesis_file_bytes: record.bytes,
      };
      const nonce = randomBytes(16).toString('base64url');
      const ts = 1_700_000_000 + index;
      const cHash = contentHash(body);
      return {
        key: `guide:housekeeper:${path.basename(record.path, '.md')}`,
        value: readFileSync(record.absolutePath, 'utf8'),
        agent_id: 'housekeeper',
        body_json: body,
        content_hash: cHash,
        mutation_hash: mutationHash(cHash, nonce, ts),
        prev_mutation_hash: null,
        ts_signed: ts,
        nonce,
        sig: Buffer.from(signPayloadWithContext(privkey, body, 'POST', '/aimos/save', nonce, ts), 'base64url'),
      };
    }),
  };
}

function readinessQuery(rows, { housekeeper = true, pubkey = null } = {}) {
  return async (sql) => {
    if (sql.includes('FROM agent_identity')) {
      return { rows: housekeeper ? [{ agent_id: 'housekeeper', pubkey }] : [] };
    }
    if (sql.includes('FROM aimos_memories')) return { rows };
    throw new Error(`unexpected query: ${createHash('sha256').update(sql).digest('hex')}`);
  };
}

test('scheduler readiness requires housekeeper plus all manifest-bound Guide memories', async () => {
  const { manifest, pubkey, rows } = buildReadyRows();
  const ready = await verifySchedulerGenesisReadiness({
    brainRoot: root,
    queryFn: readinessQuery(rows, { pubkey }),
  });
  assert.deepEqual(ready, {
    ok: true,
    manifestVersion: manifest.version,
    corpusRoot: manifest.corpusRoot,
    guideMemories: manifest.files.length,
  });

  const incomplete = await verifySchedulerGenesisReadiness({
    brainRoot: root,
    queryFn: readinessQuery(rows.slice(1), { pubkey }),
  });
  assert.equal(incomplete.ok, false);
  assert.equal(incomplete.reason, 'genesis_corpus_incomplete_or_unbound');
  assert.equal(incomplete.missing.length, 1);

  const tamperedRows = rows.map((row, index) => index === 0
    ? { ...row, body_json: { ...row.body_json, genesis_corpus_root: '0'.repeat(64) } }
    : row);
  const tampered = await verifySchedulerGenesisReadiness({
    brainRoot: root,
    queryFn: readinessQuery(tamperedRows, { pubkey }),
  });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.reason, 'genesis_corpus_incomplete_or_unbound');
  assert.equal(tampered.missing.length, 1, 'tampered signed provenance body must not satisfy readiness');

  const noHousekeeper = await verifySchedulerGenesisReadiness({
    brainRoot: root,
    queryFn: readinessQuery(rows, { housekeeper: false, pubkey }),
  });
  assert.equal(noHousekeeper.ok, false);
  assert.equal(noHousekeeper.reason, 'housekeeper_system_identity_missing');
});

test('public scheduler has no optional signal or personal Sunday job surface', () => {
  const source = readFileSync(path.join(root, 'services', 'orchestration', 'scheduler.js'), 'utf8');
  assert.match(source, /WHERE m\.company_id = \$2/);
  assert.match(source, /\[expectedKeys, COMPANY\]/);
  assert.doesNotMatch(source, /company_id = 'system'|clientId: 'system'/);
  assert.doesNotMatch(source, /agent_alarms/);
  assert.doesNotMatch(source, /jobs\/signal-generators\.js/);
  assert.doesNotMatch(source, /jobs\/sunday-signal-scan\.js/);
  assert.doesNotMatch(source, /SIGNAL_GEN_JOB_ID|SUNDAY_SIGNAL_SCAN_JOB_ID/);
  assert.doesNotMatch(source, /Telegram|planetary|numerology|Shmita|Mercury/i);
});
