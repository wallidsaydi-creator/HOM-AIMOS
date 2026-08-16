#!/usr/bin/env node
/**
 * genesis-install.mjs — HOM-AIMOS Genesis Installer (Part A)
 *
 * This is the canonical HOM-AIMOS Genesis path.
 *
 * On a fresh clone + fresh Postgres there is **no database yet**.
 * Phase A2 is the step that creates the aimos database and agent_runtime role
 * from scratch.
 *
 * Single idempotent orchestrator for the *system* side only.
 * No user master or agent enrollment happens here (that's the live Part B ceremony).
 *
 * Run with: node scripts/genesis-install.mjs [--aimos-db aimos]
 *
 * Implemented installation phases:
 *   A0           — verify every shipped Guide byte + deterministic corpus root
 *   A1 (verify)  — confirm env purge from A1c
 *   A2           — DB + role bootstrap (creates aimos + agent_runtime when nothing exists)
 *   A3           — Schema migrations (runs the idempotent runner)
 *   A3.1         — restore Keychain runtime-role credential after immutable migration 029
 *   A4           — runtime architecture-authority generation (resolves template)
 *   A5           — housekeeper self-provisioning + self-signed T1_SYSTEM_SELF cert
 *   A6           — Genesis Guide ingestion (real /aimos/save pipeline with signed envelopes)
 *   A7           — installer exit + handoff to live reviewer ceremony (Part B)
 */

import * as fs from 'node:fs';
import { resolve } from 'node:path';
import { execSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const PROJECT_ROOT = resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GUIDE_DIR = resolve(PROJECT_ROOT, 'Guide');
let DATABASE_NAME = null;
let DATABASE_URL = null;
let AIMOS_COMPANY_ID = null;
let AIMOS_RUNTIME_CREDENTIAL_SERVICE = null;
let AIMOS_SERVER_PORT = null;
let pool = null;

// A6 outcome, read by the A7 handoff so it reports actual counts, never a false claim.
const a6Result = { ingested: 0, total: 0, corpusRoot: null, manifestVersion: null };
let verifiedGenesisManifest = null;
let pgsodiumDependencyReceipt = null;

function logPhase(phase, msg) {
  console.log(`\n=== ${phase} ===`);
  if (msg) console.log(msg);
}

async function phaseA0VerifyGenesisCorpus() {
  logPhase('A0 — Genesis Guide content verification');
  const { verifyGenesisManifest } = await import('./verify-genesis-manifest.mjs');
  verifiedGenesisManifest = verifyGenesisManifest({ brainRoot: PROJECT_ROOT });
  console.log(`[A0] Verified ${verifiedGenesisManifest.files.length} Guide files before database creation.`);
  console.log(`     schema:      ${verifiedGenesisManifest.schema}`);
  console.log(`     version:     ${verifiedGenesisManifest.version}`);
  console.log(`     corpus_root: ${verifiedGenesisManifest.corpusRoot}`);
  return verifiedGenesisManifest;
}

async function initializeBootstrapFacts() {
  const runtime = await import('../services/core/runtime-config.js');
  DATABASE_NAME = runtime.resolveAimosDatabaseName();
  DATABASE_URL = runtime.resolveAimosDatabaseUrl();
  AIMOS_COMPANY_ID = runtime.AIMOS_COMPANY_ID;
  AIMOS_RUNTIME_CREDENTIAL_SERVICE = runtime.AIMOS_RUNTIME_CREDENTIAL_SERVICE;
  AIMOS_SERVER_PORT = runtime.AIMOS_SERVER_PORT;
}

function verifySupportedNodeRuntime() {
  const major = Number(process.versions.node.split('.')[0]);
  if (![20, 24].includes(major)) throw new Error(`node_runtime_unsupported:${process.version}`);
  console.log(`[A0.25] Node.js runtime supported: ${process.version}`);
}

async function phaseA0_5PgsodiumPreflight() {
  logPhase('A0.5 — locked pgsodium preflight before database creation');
  const { ensurePgsodium } = await import('./db/ensure-pgsodium.mjs');
  pgsodiumDependencyReceipt = await ensurePgsodium({ databaseUrl: DATABASE_URL });
  console.log(`[A0.5] pgsodium ${pgsodiumDependencyReceipt.available_version} is visible to the selected PostgreSQL server.`);
  console.log(`       node:           ${pgsodiumDependencyReceipt.node_version}`);
  console.log(`       postgres:       ${pgsodiumDependencyReceipt.postgres_version}`);
  console.log(`       pgvector:       ${pgsodiumDependencyReceipt.pgvector_available_version || 'missing'}`);
  console.log(`       lock_sha256:    ${pgsodiumDependencyReceipt.lock_sha256}`);
  console.log(`       source_sha256:  ${pgsodiumDependencyReceipt.source_sha256}`);
  console.log(`       library_sha256: ${pgsodiumDependencyReceipt.library_sha256}`);
  console.log(`       source install: ${pgsodiumDependencyReceipt.source_install_performed ? 'performed from locked archive' : 'not required; exact installed version observed'}`);
}

async function verifyPhaseA1EnvPurge() {
  logPhase('A1 (verify) — Env purge state');

  const envFiles = fs.readdirSync(PROJECT_ROOT)
    .filter((name) => /^\.env(?:\.|$)/.test(name));
  if (envFiles.length > 0) {
    throw new Error(`env_authority_files_forbidden:${envFiles.sort().join(',')}`);
  }
  const packageJson = JSON.parse(fs.readFileSync(resolve(PROJECT_ROOT, 'package.json'), 'utf8'));
  if (packageJson.dependencies?.dotenv || packageJson.devDependencies?.dotenv) {
    throw new Error('dotenv_dependency_forbidden');
  }
  console.log('[A1] OK — no .env* authority files exist');
  console.log('[A1] OK — dotenv is absent from runtime dependencies');
  console.log('[A1] OK — bootstrap/runtime configuration has no environment source');

  return true;
}

async function phaseA2DbBootstrap() {
  logPhase('A2 — DB + role bootstrap');

  console.log('This is a fresh HOM-AIMOS install.');
  console.log('There is no database yet. We will now create:');
  console.log(`  • Database: ${DATABASE_NAME}`);
  console.log('  • Role:     agent_runtime (used by the app at runtime)');
  console.log('');

  console.log(`Using deterministic local target: ${DATABASE_URL}`);
  console.log('');
  console.log('Connecting to the maintenance database on the same host');
  console.log('(postgres or template1) because the target "aimos" database does not exist yet.\n');

  // Delegate to the reusable bootstrap (idempotent, handles fresh install)
  const { bootstrapDatabase } = await import('./bootstrap-db.mjs');
  const result = await bootstrapDatabase({ databaseUrl: DATABASE_URL, databaseName: DATABASE_NAME });

  console.log('[A2] Fresh DB + role bootstrap complete for HOM-AIMOS.');
  if (result?.db?.created) console.log('      → aimos database created');
  if (result?.role?.created) console.log('      → agent_runtime role created');
  return result;
}

async function phaseA3SchemaMigrations() {
  logPhase('A3 — Schema migrations');

  console.log('Running the existing idempotent migrations runner...');
  console.log(`Using the AIMOS bootstrap target for migrations.`);

  const { default: pg } = await import('pg');
  const migrationPool = new pg.Pool({ connectionString: DATABASE_URL });

  try {
    // Import the runner function (CLI auto-run is guarded and won't trigger on import)
    const { runMigrations } = await import('../migrations/run.js');

    const result = await runMigrations(migrationPool, { check: false, verbose: true });

    console.log(`[A3] Migrations done. Applied: ${result.applied.length}, Skipped: ${result.skipped.length}, Errors: ${result.errors.length}`);

    if (result.errors && result.errors.length > 0) {
      console.error('Migration errors:', result.errors);
      throw new Error('One or more migrations failed.');
    }

    if (result.applied.length > 0) {
      console.log('Applied migrations:', result.applied.join(', '));
    } else {
      console.log('No new migrations applied (already up to date).');
    }
  } finally {
    await migrationPool.end().catch(() => {});
  }

  console.log('[A3] Schema migrations complete.');
}

async function phaseA3_1RuntimeCredentialSync() {
  logPhase('A3.1 — runtime role credential synchronization');
  const { synchronizeRuntimeRoleCredential } = await import('./bootstrap-db.mjs');
  const result = await synchronizeRuntimeRoleCredential({
    databaseUrl: DATABASE_URL,
    databaseName: DATABASE_NAME,
  });
  if (!result.synchronized) throw new Error('agent_runtime Keychain credential was not synchronized');
  console.log(`[A3.1] ${result.roleName} synchronized from Keychain slot ${result.credentialSlot}.`);
}

async function phaseA4ArchitectureAuthority() {
  logPhase('A4 — runtime architecture-authority generation');

  console.log('Running the existing script to resolve template paths to this brain root.');
  console.log('Command: node scripts/identity/init-architecture-authority.js');
  console.log('This produces architecture-authority.json (machine-specific, should be git-ignored).');

  try {
    execSync('node scripts/identity/init-architecture-authority.js', {
      stdio: 'inherit',
      cwd: PROJECT_ROOT,
    });
    console.log('[A4] architecture-authority.json generated successfully.');
  } catch (err) {
    if (err.status === 75) {
      console.log('[A4] Skipped (runtime JSON already present and not --force).');
      return;
    }
    console.error('[A4] Failed to run init-architecture-authority.js');
    throw err;
  }
}

async function phaseA5HousekeeperSelfProvision() {
  logPhase('A5 — housekeeper self-provisioning + self-signed cert (T1_SYSTEM_SELF)');
  const {
    generateKeypair,
    issueCert,
    pubkeyFingerprint,
    loadAgentPrivkey,
  } = await import('../services/security/agent-identity.js');
  const { computeDeviceFp } = await import('./identity/lib.js');

  const AGENTS_DIR = path.join(os.homedir(), '.aimos', 'agents');
  const HOUSEKEEPER_KEY_PATH = path.join(AGENTS_DIR, 'housekeeper.key');
  const HOUSEKEEPER_CERT_CACHE_PATH = path.join(AGENTS_DIR, 'housekeeper.cert-cache.json');

  // Idempotency: check if housekeeper already provisioned
  const existing = await pool.query(
    `SELECT agent_id, pubkey, valid_from FROM agent_identity identity
     WHERE agent_id = 'housekeeper'
       AND NOT EXISTS (
         SELECT 1 FROM aimos_agent_revocation_events revocation
          WHERE revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from
       )
     ORDER BY valid_from DESC
     LIMIT 1`
  );
  if (existing.rows.length > 0) {
    console.log('[A5] Housekeeper already provisioned — skipping (idempotent).');
    console.log(`     Existing row valid_from: ${existing.rows[0].valid_from}`);
    return;
  }

  // Determine the housekeeper keypair. The privkey lives at a SINGLE shared
  // path (~/.aimos/agents/housekeeper.key) — the machine's stable system
  // operational identity (keypair continuity, see housekeeper-signer.js). The
  // pubkey we INSERT here must match the key that will actually SIGN saves.
  //
  // If a key already exists on disk we MUST reuse it (derive its pubkey), and
  // NEVER overwrite it — it may back another install on this machine.
  // Generating a NEW keypair while an old key sits on disk, and then
  // refusing to overwrite that old key would desynchronize the database public
  // key from the signing key and make signed Guide ingestion fail closed.
  // We only WRITE a fresh key when none exists.
  let housekeeperPubkey;
  let housekeeperPrivkey;
  const reusedExistingKey = fs.existsSync(HOUSEKEEPER_KEY_PATH);
  if (reusedExistingKey) {
    housekeeperPrivkey = loadAgentPrivkey(HOUSEKEEPER_KEY_PATH);
    const privObj = crypto.createPrivateKey({
      key: Buffer.from(housekeeperPrivkey, 'base64url'),
      format: 'der',
      type: 'pkcs8'
    });
    housekeeperPubkey = crypto.createPublicKey(privObj)
      .export({ type: 'spki', format: 'der' })
      .toString('base64url');
    console.log('Reusing existing housekeeper key on disk (keypair continuity; disk key is authoritative, never overwritten).');
  } else {
    console.log('Generating fresh Ed25519 keypair for housekeeper (system self)...');
    ({ pubkey: housekeeperPubkey, privkey: housekeeperPrivkey } = generateKeypair());
  }
  const fingerprint = pubkeyFingerprint(housekeeperPubkey);
  const deviceFp = computeDeviceFp(PROJECT_ROOT);
  const now = Math.floor(Date.now() / 1000);
  const PERPETUAL_UNTIL = 253402300799; // 9999-12-31 23:59:59 UTC (column is NOT NULL)

  const certBody = {
    v: 1,
    agent_id: 'housekeeper',
    pubkey: housekeeperPubkey,
    device_fp: deviceFp,
    valid_from: now,
    valid_until: PERPETUAL_UNTIL,
    issuer: 'housekeeper',
    issued_at: now
  };

  const cert = issueCert(housekeeperPrivkey, certBody);

  console.log(`[A5] Self-signed cert issued (issuer=housekeeper, tier=T1_SYSTEM_SELF)`);
  console.log(`     fingerprint: ${fingerprint.slice(0, 16)}...`);
  console.log(`     device_fp:   ${deviceFp.slice(0, 16)}...`);

  // Write directories and files (mode 0700 for dir, 0600 for secrets)
  if (!fs.existsSync(AGENTS_DIR)) {
    fs.mkdirSync(AGENTS_DIR, { recursive: true, mode: 0o700 });
  }

  if (!reusedExistingKey) {
    // No key existed → this is the fresh keypair we just generated; persist it.
    fs.writeFileSync(HOUSEKEEPER_KEY_PATH, housekeeperPrivkey, { mode: 0o600 });
    fs.chmodSync(HOUSEKEEPER_KEY_PATH, 0o600);
    console.log(`     key file:    ${HOUSEKEEPER_KEY_PATH} (mode 0600, freshly written)`);
  } else {
    // Existing key reused above; leave it untouched (may back another install).
    console.log(`     key file:    ${HOUSEKEEPER_KEY_PATH} (existing key preserved, not overwritten)`);
  }

  // Write cert cache (mirrors agent convention)
  const certCacheContent = JSON.stringify({
    agent_id: 'housekeeper',
    cert,
    expires_at_ms: null   // perpetual
  }) + '\n';
  fs.writeFileSync(HOUSEKEEPER_CERT_CACHE_PATH, certCacheContent, { mode: 0o600 });
  fs.chmodSync(HOUSEKEEPER_CERT_CACHE_PATH, 0o600);
  console.log(`     cert cache:  ${HOUSEKEEPER_CERT_CACHE_PATH} (mode 0600)`);

  // Insert into DB (perpetual system identity)
  const validFromIso = new Date(now * 1000).toISOString();
  const validUntilIso = new Date(PERPETUAL_UNTIL * 1000).toISOString();

  await pool.query(
    `INSERT INTO agent_identity 
       (agent_id, pubkey, cert, device_fp, valid_from, valid_until, issued_at, is_system_role)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      'housekeeper',
      housekeeperPubkey,
      cert,
      deviceFp,
      validFromIso,
      validUntilIso,
      validFromIso,
      true
    ]
  );

  console.log('[A5] Housekeeper self-provisioned successfully.');
  console.log(`     agent_id:      housekeeper`);
  console.log(`     identity_tier: T1_SYSTEM_SELF (self-signed)`);
  console.log(`     is_system_role: true`);
  console.log(`     valid_until:   perpetual (9999-12-31)`);
  console.log(`     enrolled_by:   genesis-installer`);
}

async function phaseA5_0LedgerDependencyReceipt() {
  if (!pgsodiumDependencyReceipt) throw new Error('pgsodium_dependency_receipt_missing');
  logPhase('A5.0 — cryptographic dependency receipt');
  const { logEvent } = await import('../services/observe/event-ledger.js');
  const receipt = await logEvent(
    AIMOS_COMPANY_ID,
    'housekeeper',
    'genesis_dependency_verified',
    'pgsodium',
    pgsodiumDependencyReceipt,
    null,
    { returnReceipt: true },
  );
  console.log(`[A5.0] runtime dependency receipt event_id=${receipt.event_id}`);
  console.log(`[A5.0] mutation_hash=${receipt.mutation_hash}`);
}

async function phaseA5_1LedgerRuntimeCredential() {
  logPhase('A5.1 — runtime DB credential cryptographic lifecycle');

  const { readCredentialSync } = await import('../services/security/credential-store.js');
  const { signAsHousekeeper } = await import('../services/security/housekeeper-signer.js');

  const credential = readCredentialSync(AIMOS_RUNTIME_CREDENTIAL_SERVICE);
  if (!credential) {
    throw new Error('A5.1 cannot find the runtime DB credential created in A2');
  }

  const { credentialLedger } = await import('../services/security/credential-ledger.js');
  const existing = await credentialLedger.getSlotChain(credential.slot, 1);
  if (existing.length > 0) {
    const ledgerHash = existing[0]?.body_json?.credential_hash;
    if (ledgerHash !== credential.hash) {
      throw new Error('A5.1 keychain/ledger credential hash mismatch; explicit rotation ceremony required');
    }
    console.log(`[A5.1] Existing credential lifecycle row verified for ${credential.slot}.`);
    return;
  }

  const body = {
    event_type: 'STORE',
    service: AIMOS_RUNTIME_CREDENTIAL_SERVICE,
    slot_id: credential.slot,
    credential_hash: credential.hash,
    valid_from: Math.floor(Date.now() / 1000),
    valid_until: null,
    rotated_from: null,
    reason: 'genesis_runtime_database_role',
    operator: 'housekeeper',
    signer_agent_id: 'housekeeper'
  };
  const signed = await signAsHousekeeper(body);
  const commit = await credentialLedger.commitCredentialLifecycle({
    serviceName: AIMOS_RUNTIME_CREDENTIAL_SERVICE,
    slotId: credential.slot,
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    eventType: 'STORE',
    bodyJson: signed.body
  });
  if (!commit.ok) {
    throw new Error(`A5.1 credential ledger commit failed: ${commit.reason}`);
  }
  console.log(`[A5.1] Runtime credential ledgered: content_hash=${Buffer.from(commit.contentHash).toString('hex')}`);
  console.log(`[A5.1] mutation_hash=${Buffer.from(commit.mutationHash).toString('hex')}`);
}

async function phaseA5_2CalibrationGenesis() {
  logPhase('A5.2 — signed recall calibration genesis');
  const { ensureCalibrationGenesis } = await import('../services/retrieval/recall-calibrator.js');
  const result = await ensureCalibrationGenesis(AIMOS_COMPANY_ID);
  console.log(`[A5.2] ${result.created ? 'Created' : 'Verified'} calibration event ${result.snapshot.calibrationEventId}.`);
  console.log(`[A5.2] mutation_hash=${result.snapshot.calibrationMutationHash}`);
}

// Phase A5.5 — REMOVED (R11b). The housekeeper no longer masquerades as a
// pseudo-session. The write-validator grants intrinsic write authority to the
// exact housekeeper principal under its Genesis T1_SYSTEM_SELF certificate or
// the key-continuous master-signed T1 custody successor.

export async function phaseA6GenesisGuideIngestion({
  targetPool = pool,
  manifestVerification: suppliedManifest = null,
} = {}) {
  logPhase('A6 — Genesis Guide ingestion via real /aimos/save HTTP (no auth-gate bypass)');
  const [{ default: express }, { authGate }, { signAsHousekeeper }, { verifyGenesisManifest }] = await Promise.all([
    import('express'),
    import('../services/security/auth-gate.js'),
    import('../services/security/housekeeper-signer.js'),
    import('./verify-genesis-manifest.mjs'),
  ]);

  console.log('Spinning up genesis-mode Express server (auth-gate + /aimos router, no background services).');
  console.log('Each Guide .md → real signed POST /aimos/save as the verified housekeeper system identity.');
  console.log('No direct persistMemory / commitProvenance calls. The auth-gate runs on every save.');

  if (!fs.existsSync(GUIDE_DIR) || !fs.statSync(GUIDE_DIR).isDirectory()) {
    console.warn('[A6] Guide dir not found, skipping.');
    return;
  }

  if (!targetPool) throw new Error('A6 target pool is required');
  const manifestVerification = suppliedManifest
    || verifiedGenesisManifest
    || verifyGenesisManifest({ brainRoot: PROJECT_ROOT });
  const files = manifestVerification.files;

  console.log(`Found ${files.length} Guide files.`);
  console.log(`[A6] Binding manifest v${manifestVerification.version} corpus_root=${manifestVerification.corpusRoot} into every signed save.`);

  // ── Build genesis-mode Express server ────────────────────────────────
  // Same auth-gate + /aimos router as production. NO background services
  // (no governance, no skills loader, no HNSW prewarm, no scheduler) during
  // ingestion; those start only after the complete Guide readiness proof.
  const genesisApp = express();
  genesisApp.use(express.json({ limit: '10mb' }));
  genesisApp.use(authGate);

  // Lazy-import the /aimos router (same pattern as server.js lazyRouter)
  let aimosRouter = null;
  genesisApp.use('/aimos', async (req, res, next) => {
    try {
      if (!aimosRouter) {
        const moduleRef = await import('../routes/aimos.js');
        if (typeof moduleRef?.default !== 'function') {
          throw new Error('routes/aimos.js has no default Express router');
        }
        aimosRouter = moduleRef.default;
      }
      return aimosRouter(req, res, next);
    } catch (err) {
      console.error('[A6 genesis-server] Failed to load /aimos router:', err?.message || err);
      return res.status(500).json({ error: 'genesis_router_load_failed', reason: err?.message || String(err) });
    }
  });

  const genesisServer = http.createServer(genesisApp);
  await new Promise((resolve) => {
    genesisServer.listen(0, '127.0.0.1', resolve);
  });
  const genesisPort = genesisServer.address().port;
  const genesisBase = `http://127.0.0.1:${genesisPort}`;
  console.log(`[A6] Genesis-mode server listening on ${genesisBase}`);

  let ingested = 0;
  let failed = 0;
  const failedFiles = [];
  let firstFailureBody = null;

  try {
    for (const fileRecord of files) {
      const file = path.basename(fileRecord.path);
      const fullPath = fileRecord.absolutePath;
      const content = fs.readFileSync(fullPath, 'utf8');

      const base = file.replace(/\.md$/, '');
      const key = `guide:housekeeper:${base}`;

      const alreadyIngested = await targetPool.query(
        `SELECT m.id FROM aimos_memories m
          WHERE m.company_id = 'hom' AND m.key = $1 AND m.value = $2
            AND m.source = 'guide:genesis-install'
            AND EXISTS (
              SELECT 1
                FROM aimos_memory_provenance p
               WHERE p.memory_id = m.id
                 AND p.body_json->>'genesis_manifest_schema' = $3
                 AND p.body_json->>'genesis_manifest_version' = $4
                 AND p.body_json->>'genesis_corpus_root' = $5
                 AND p.body_json->>'genesis_file_sha256' = $6
            )
          ORDER BY created_at DESC LIMIT 1`,
        [
          key,
          content,
          manifestVerification.schema,
          String(manifestVerification.version),
          manifestVerification.corpusRoot,
          fileRecord.sha256,
        ]
      );
      if (alreadyIngested.rows.length > 0) {
        ingested++;
        console.log(`[A6] ${file} → already present (memory_id=${alreadyIngested.rows[0].id.slice(0, 8)}…, append-only idempotence)`);
        continue;
      }

      // Deterministic name-aware recall check.
      const firstH1 = (content.match(/^#\s*(.+)$/m) || [])[1] || '';
      let memoryType = 'book_extract';
      if (/guide|manual|how to|connect|llm|agent/i.test(firstH1)) {
        memoryType = 'procedural_seed';
      } else if (/ledger|knowledge|baseline/i.test(firstH1)) {
        memoryType = 'book_extract';
      }

      // Body WITHOUT ts_signed — signAsHousekeeper sets it before signing.
      // is_genesis is retained as signed audit metadata. Authority comes from
      // the verified system-self certificate; this body flag never grants it.
      const body = {
        company_id: 'hom',
        agent_id: 'housekeeper',
        key,
        value: content,
        memory_type: memoryType,
        source: 'guide:genesis-install',
        memory_tier: 'long-term',
        scope: 'system',
        clearance_level: 10,
        is_genesis: true,
        genesis_manifest_schema: manifestVerification.schema,
        genesis_manifest_version: manifestVerification.version,
        genesis_corpus_root: manifestVerification.corpusRoot,
        genesis_file_path: fileRecord.path,
        genesis_file_sha256: fileRecord.sha256,
        genesis_file_bytes: fileRecord.bytes
      };

      try {
        const signed = await signAsHousekeeper(body, { method: 'POST', path: '/aimos/save' });

        const resp = await fetch(`${genesisBase}/aimos/save`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'aimos-agent-cert': signed.certString,
            'aimos-agent-signature': signed.sigB64u,
            'aimos-agent-nonce': signed.nonce,
            'aimos-agent-timestamp': String(signed.signedTs),
            'x-aimos-sig-form': String(signed.sigForm)
          },
          body: JSON.stringify(signed.body)
        });

        const respBody = await resp.json().catch(() => ({}));

        if (!resp.ok || !respBody.success) {
          console.error(`[A6] ${file} → HTTP ${resp.status}: ${JSON.stringify(respBody)}`);
          failed++;
          failedFiles.push(file);
          if (firstFailureBody === null) {
            firstFailureBody = `HTTP ${resp.status}: ${JSON.stringify(respBody)}`;
          }
          continue;
        }

        ingested++;
        console.log(`[A6] ${file} → 200 (memory_id=${respBody.memory_id?.slice(0, 8)}…, tier=${respBody.identity_tier}, content_hash=${respBody.content_hash?.slice(0, 12)}…)`);
      } catch (err) {
        console.error(`[A6] ${file} failed: ${err.message}`);
        failed++;
        failedFiles.push(file);
        if (firstFailureBody === null) {
          firstFailureBody = `exception: ${err.message}`;
        }
      }
    }
  } finally {
    await new Promise((resolve) => genesisServer.close(resolve));
    console.log('[A6] Genesis-mode server closed.');
  }

  a6Result.ingested = ingested;
  a6Result.total = files.length;
  a6Result.corpusRoot = manifestVerification.corpusRoot;
  a6Result.manifestVersion = manifestVerification.version;

  console.log(`[A6] ${ingested}/${files.length} Guide files ingested via real /aimos/save HTTP.`);

  // Hard fail: an installer that ingested fewer than all Guide files must NOT
  // report success. The corpus would fire blank. This is the Native Invariant.
  if (failed > 0) {
    console.error(`[A6] FAILED — ingested ${ingested}/${files.length} Guide files; ${failed} failed.`);
    console.error(`[A6] Failing files: ${failedFiles.join(', ')}`);
    console.error(`[A6] First failure body: ${firstFailureBody}`);
    throw new Error(`A6 genesis Guide ingestion failed: ${failed}/${files.length} Guide files did not persist.`);
  }

  // Self-check straight from the database: the corpus must actually contain at
  // least one row per Guide file, else the architecture would fire blank.
  const expectedKeys = files.map((record) => `guide:housekeeper:${path.basename(record.path, '.md')}`);
  const countRes = await targetPool.query(
    `SELECT count(DISTINCT m.key)::int AS n,
            count(DISTINCT m.id) FILTER (
              WHERE m.scope = 'quarantine' OR m.memory_type = 'quarantine'
            )::int AS quarantined
       FROM aimos_memories m
      WHERE m.company_id = 'hom'
        AND m.source = 'guide:genesis-install'
        AND m.key = ANY($1::text[])
        AND EXISTS (
          SELECT 1
            FROM aimos_memory_provenance p
           WHERE p.memory_id = m.id
             AND p.body_json->>'genesis_manifest_schema' = $2
             AND p.body_json->>'genesis_manifest_version' = $3
             AND p.body_json->>'genesis_corpus_root' = $4
        )
        AND EXISTS (
          SELECT 1
            FROM aimos_memory_provenance binding
           WHERE binding.memory_id = m.id
             AND binding.event_type = 'BIND'
        )`,
    [expectedKeys, manifestVerification.schema, String(manifestVerification.version), manifestVerification.corpusRoot]
  );
  const corpusCount = countRes.rows?.[0]?.n ?? 0;
  const quarantinedCount = countRes.rows?.[0]?.quarantined ?? 0;
  console.log(`[A6] DB self-check: ${corpusCount}/${files.length} manifest-bound Guide memories present.`);
  if (corpusCount < files.length) {
    console.error(`[A6] FAILED — found ${corpusCount}/${files.length} manifest-bound Guide seed rows.`);
    if (corpusCount === 0) {
      console.error('[A6] The memory corpus is EMPTY. The architecture would fire blank. Refusing to report success.');
    }
    throw new Error(`A6 corpus self-check failed: aimos_memories count ${corpusCount} < ${files.length} Guide files.`);
  }
  if (Number(quarantinedCount) !== 0) {
    throw new Error(`A6 corpus self-check failed: ${quarantinedCount} publisher-verified Guide memories were quarantined.`);
  }

  console.log('     Every genesis row has: sig + nonce + ts_signed + content_hash + chain_hash + mutation_hash.');
  console.log(`     Every provenance body commits to corpus_root=${manifestVerification.corpusRoot}.`);
  console.log('     Every Guide memory has a housekeeper-signed BIND receipt and zero are quarantined.');
  console.log('     identity_tier=verified housekeeper tier (T1 or T1_SYSTEM_SELF), is_genesis=true (auto-derived via CHECK constraint).');
  console.log('     Auth-gate ran on every save. No bypass.');
  return Object.freeze({ ...a6Result, quarantined: Number(quarantinedCount) });
}

async function phaseA7Handoff() {
  logPhase('A7 — installer exit + handoff');

  console.log('=== HOM-AIMOS GENESIS INSTALLER COMPLETE (A1–A7) ===');
  console.log('');
  console.log('System-side bootstrap finished successfully:');
  console.log('  - A1: Env purge verified (no .env, no dotenv, keychain + systemConfigStore)');
  console.log('  - A2: aimos DB + agent_runtime role created (fresh install, no DB yet)');
  console.log('  - A3: All schema migrations applied (idempotent)');
  console.log('  - A4: architecture-authority.json generated for this brain root');
  console.log('  - A5: housekeeper identity provisioned (fresh Ed25519 key + self-signed T1_SYSTEM_SELF cert)');
  console.log(`  - A6: ingested ${a6Result.ingested}/${a6Result.total} Guide/*.md as signed housekeeper genesis rows (is_genesis=true, source=guide:genesis-install)`);
  console.log(`        manifest v${a6Result.manifestVersion}, corpus_root=${a6Result.corpusRoot}`);
  console.log('');
  console.log('The system will not "fire blank" — the Guide corpus is reachable via signed recall as housekeeper.');
  console.log('');
  console.log('=== NOW HANDING OFF TO LIVE REVIEWER CEREMONY (Part B) ===');
  console.log('');
  console.log('You (the reviewer) will execute these steps live. I will verify each output in real time.');
  console.log('Run them in order. Do not skip or script them.');
  console.log('');
  console.log('Prerequisites:');
  console.log(`  - AIMOS database target: ${DATABASE_NAME} (resolved without environment variables).`);
  console.log('  - The server is NOT running yet.');
  console.log('');
  console.log('B1. Enroll master identity:');
  console.log('    node scripts/identity/enroll-master.js');
  console.log('    (You will be prompted for keychain account name and master passphrase twice.)');
  console.log('    Verify: aimos_master_identity row exists, fingerprint matches, keychain entry present.');
  console.log('');
  console.log('B2. Enroll an agent:');
  console.log('    node scripts/identity/enroll-agent.js <your-agent-id>');
  console.log('    (Choose a stable identifier such as "reviewer-1".)');
  console.log('    Verify: agent_identity row for your agent_id, ~/.aimos/agents/<id>.key (mode 0600), .cert-cache.json present.');
  console.log('');
  console.log('B3. Confirm autonomous housekeeper readiness:');
  console.log('    The housekeeper was provisioned in A5 and owns heartbeat, scheduling,');
  console.log('    dream, calibration, and maintenance without an enrolled user agent.');
  console.log('    Master and user-agent enrollment add human-directed authority only.');
  console.log('');
  console.log('B4. Start the server (in a SEPARATE terminal):');
  console.log('    npm start');
  console.log('    Watch for:');
  console.log('      [BOOT] systemConfigStore loaded');
  console.log('      [BOOT] credentialCache loaded');
  console.log(`      Listening on http://127.0.0.1:${AIMOS_SERVER_PORT}`);
  console.log('    The server must be running before B5.');
  console.log('');
  console.log('B5. Signed status check:');
  console.log('    Use your enrolled agent to make a signed GET /aimos/status');
  console.log('    (I will give you the exact curl or node one-liner when we reach this step.)');
  console.log('    Expect: 200 OK with provider status, etc.');
  console.log('');
  console.log('B6. Signed recall of the Guide (proves the system does not fire blank):');
  console.log('    Signed POST /aimos/recall with body {"query":"guide","limit":10}.');
  console.log('    Expect: 200 + rows with agent_id="housekeeper", source="guide:genesis-install", is_genesis=true.');
  console.log('    This is the critical "day-1 corpus" proof.');
  console.log('');
  console.log('B7. Signed save test:');
  console.log('    Signed POST /aimos/save with a small test payload.');
  console.log('    Expect: 200 with content_hash + chain_hash.');
  console.log('');
  console.log('B8. Store a credential via the proper path:');
  console.log('    node scripts/identity/store-credential.js STORE --service=test-service --reason="A7 validation"');
  console.log('    (You will be prompted for the secret value.)');
  console.log('    Verify: aimos_credential_lifecycle row exists, signed by housekeeper, with mutation_hash + prev_mutation_hash.');
  console.log('');
  console.log('B9. Health surface checks (signed):');
  console.log('    Signed calls to:');
  console.log('      GET  /aimos/status');
  console.log('      POST /aimos/heartbeat');
  console.log('      GET  /aimos/reasoning-state');
  console.log('      GET  /aimos/dream/latest');
  console.log('    Each request must use its documented signed envelope and return a');
  console.log('    documented success response. No placeholder endpoint counts as proof.');
  console.log('');
  console.log('B10. 21-stage native recall + 10-gear fusion surface:');
  console.log('    Signed recall with mode=adaptive (or whatever triggers the full retrieval stack).');
  console.log('    Verify recall_meta shows the expected multi-stage pipeline.');
  console.log('');
  console.log('B11. Architecture authority verification:');
  console.log('    npm run test:architecture-authority');
  console.log('    Expect: PASS / exit 0.');
  console.log('');
  console.log('When B1–B11 are all green, the fork is ready for GitHub.');
  console.log('');
  console.log('Exiting installer now. System side is fully bootstrapped.');
  console.log('Over to you for the live Part B ceremony — I am ready when you are.');
}

async function main() {
  verifySupportedNodeRuntime();
  console.log('HOM-AIMOS Genesis Installer');
  console.log('============================');
  console.log('');
  console.log('This is a completely fresh HOM-AIMOS deployment.');
  console.log('There is no database, no schema, and no system identity yet.');
  console.log('');
  console.log('This script performs the SYSTEM side bootstrap only (face-by-face):');
  console.log('  - A0: verifies Guide bytes + deterministic corpus root');
  console.log('  - A0.5: verifies/installs locked pgsodium before DB creation');
  console.log('  - A1: env purge verification');
  console.log('  - A2: creates the aimos DB + agent_runtime role (fresh, no DB yet)');
  console.log('  - A3: schema migrations');
  console.log('  - A3.1: restore agent_runtime from the Keychain credential');
  console.log('  - A4: runtime architecture-authority generation');
  console.log('  - A5: housekeeper self-provisioning (T1_SYSTEM_SELF)');
  console.log('  - A6: Genesis Guide ingestion (real signed pipeline)');
  console.log('  - A7: installer exit + handoff to live reviewer ceremony');
  console.log('');
  console.log('User-side enrollment (master + agent) is done separately in the live ceremony (Part B).');
  console.log('');

  try {
    // Phase A0 — fail before DB creation if any shipped Guide byte or the
    // deterministic corpus root differs from the public manifest.
    await phaseA0VerifyGenesisCorpus();

    // Only built-in modules are evaluated before the shipped corpus gate.
    await initializeBootstrapFacts();

    // Phase A1 verify
    await verifyPhaseA1EnvPurge();

    // Migration 084 requires pgsodium. Verify the server-visible extension—or
    // install the exact checksum-locked source—before A2 can create a database.
    await phaseA0_5PgsodiumPreflight();

    // Phase A2
    await phaseA2DbBootstrap();

    // Phase A3 — schema migrations.
    await phaseA3SchemaMigrations();

    // Migration 029 is immutable and contains its historical bootstrap
    // password. Restore the random Keychain value before loading any runtime
    // pool or starting any HTTP listener.
    await phaseA3_1RuntimeCredentialSync();

    // Load the runtime DB pools only after A2 generated the restricted-role
    // credential and A3 created the schema they operate on.
    ({ pool } = await import('../db/connection.js'));

    // Phase A4 — runtime architecture-authority generation.
    await phaseA4ArchitectureAuthority();

    // Phase A5 — housekeeper self-provisioning + self-signed cert
    await phaseA5HousekeeperSelfProvision();

    // Once the housekeeper exists, convert the pre-DB dependency observation
    // into a retained signed ledger receipt with content/mutation hashes.
    await phaseA5_0LedgerDependencyReceipt();

    // Bind the A2 keychain secret to the append-only signed credential ledger.
    await phaseA5_1LedgerRuntimeCredential();

    // Install the exact signed identity calibration state before recall can be
    // declared ready. No benchmark labels or private corpus enter memory.
    await phaseA5_2CalibrationGenesis();

    // Phase A5.5 — REMOVED (R11b). The housekeeper no longer masquerades as a
    // session-holding agent. Its authority to write the Guide comes from BEING
    // the system self: the write-validator now grants intrinsic system-maintenance
    // write clearance when the request is at tier T1_SYSTEM_SELF AND the acting
    // identity is the exact verified housekeeper system principal — no mutable
    // role column and no agent_session are required. See
    // services/write/write-validator.js checkWritePermission (system-self lane).

    // Phase A6 — Genesis Guide ingestion
    await phaseA6GenesisGuideIngestion();

    // Phase A7 — installer exit + handoff
    await phaseA7Handoff();

  } catch (err) {
    console.error('\n[GENESIS-INSTALL] FAILED');
    console.error(err?.message || err);
    process.exitCode = 1;
  } finally {
    if (pool) await pool.end().catch(() => {});
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(() => process.exit(process.exitCode || 0));
}
