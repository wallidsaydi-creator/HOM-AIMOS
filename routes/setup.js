import express from 'express';
import crypto from 'crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { query } from '../db/connection.js';
import { runAgent } from '../services/orchestration/agent-runner.js';
import { enrollAgentWithDeps, KC_SERVICE } from '../scripts/identity/lib.js';
import { keychainGet, keychainSet } from '../scripts/identity/keychain.js';
import * as identityDb from '../scripts/identity/db.js';
import { getAgentCert, loadAgentPrivkey } from '../services/security/agent-identity.js';
import {
  getLatestIntegrationToken
} from '../services/integrations/identity-vault.js';
import { getOperatorAgentId, systemConfigStore } from '../services/security/system-config-store.js';
import { peekCachedCredential } from '../services/security/credential-cache.js';
import { requireCapability } from '../services/security/require-capability.js';
import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';

const router = express.Router();

// ─── R1 Step 5: enroll brute-force defense ────────────────────────────────────
// POST /aimos/identity/enroll accepts master_passphrase and is otherwise open
// (first-run bootstrap). Add per-source exponential backoff and an absolute
// attempt cap that requires operator intervention (process restart / manual
// reset) to clear. Constant-time passphrase comparison itself lives in
// enrollAgentWithDeps (scripts/identity/lib.js).
const ENROLL_ATTEMPTS = new Map(); // ip → { fails, nextAllowedMs, locked }
const ENROLL_ABSOLUTE_CAP = 10;    // hard lock after this many failures per source
const ENROLL_BASE_BACKOFF_MS = 500;
const ENROLL_MAX_BACKOFF_MS = 60_000;

function enrollSourceKey(req) {
  return String(req.ip || req.socket?.remoteAddress || 'unknown');
}

function enrollBackoffCheck(req) {
  const key = enrollSourceKey(req);
  const rec = ENROLL_ATTEMPTS.get(key);
  if (!rec) return { ok: true };
  if (rec.locked) {
    return { ok: false, status: 429, error: 'enroll_locked — too many failed attempts from this source; operator intervention required to reset' };
  }
  if (rec.nextAllowedMs && Date.now() < rec.nextAllowedMs) {
    const retryMs = rec.nextAllowedMs - Date.now();
    return { ok: false, status: 429, error: `enroll_backoff — retry in ${Math.ceil(retryMs / 1000)}s`, retryMs };
  }
  return { ok: true };
}

function enrollRecordFailure(req) {
  const key = enrollSourceKey(req);
  const rec = ENROLL_ATTEMPTS.get(key) || { fails: 0, nextAllowedMs: 0, locked: false };
  rec.fails += 1;
  if (rec.fails >= ENROLL_ABSOLUTE_CAP) {
    rec.locked = true;
  } else {
    const backoff = Math.min(ENROLL_BASE_BACKOFF_MS * (2 ** (rec.fails - 1)), ENROLL_MAX_BACKOFF_MS);
    rec.nextAllowedMs = Date.now() + backoff;
  }
  ENROLL_ATTEMPTS.set(key, rec);
}

function enrollRecordSuccess(req) {
  ENROLL_ATTEMPTS.delete(enrollSourceKey(req));
}
const COMPANY = AIMOS_COMPANY_ID;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BRAIN_ROOT = path.resolve(__dirname, '..');
const AGENTS_DIR = path.join(os.homedir(), '.aimos', 'agents');
const AGENT_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function agentPaths(agentId) {
  return {
    privateKeyPath: path.join(AGENTS_DIR, `${agentId}.key`),
    certCachePath: path.join(AGENTS_DIR, `${agentId}.cert-cache.json`)
  };
}

function assertAgentId(agentId) {
  const id = String(agentId || '').trim();
  if (!AGENT_ID_RE.test(id)) {
    const error = new Error('agent_id must be 1-64 chars: letters, numbers, underscore, hyphen');
    error.status = 400;
    throw error;
  }
  return id;
}

function assertIdentityFile(pathValue) {
  const stat = statSync(pathValue);
  if (!stat.isFile()) {
    const error = new Error(`Aimos identity path is not a file: ${pathValue}`);
    error.status = 409;
    throw error;
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    const error = new Error(`Aimos identity file must be owned by current user: ${pathValue}`);
    error.status = 409;
    throw error;
  }
  const mode = stat.mode & 0o777;
  if (mode !== 0o600) {
    const error = new Error(`Aimos identity file mode must be 0600: ${pathValue}`);
    error.status = 409;
    throw error;
  }
}

function readPrivateKeyMaterial({ privateKey, privateKeyPath }) {
  if (privateKey && privateKeyPath) {
    const error = new Error('Provide either private_key or private_key_path, not both');
    error.status = 400;
    throw error;
  }
  if (privateKey) {
    const material = String(privateKey).trim();
    if (!material) {
      const error = new Error('private_key is empty');
      error.status = 400;
      throw error;
    }
    return { material, sourcePath: null };
  }
  if (privateKeyPath) {
    const sourcePath = String(privateKeyPath).trim();
    assertIdentityFile(sourcePath);
    const material = readFileSync(sourcePath, 'utf8').trim();
    if (!material) {
      const error = new Error(`Aimos private key is empty: ${sourcePath}`);
      error.status = 409;
      throw error;
    }
    return { material, sourcePath };
  }
  const error = new Error('private_key_path or private_key is required');
  error.status = 400;
  throw error;
}

function verifyPrivateKeyForCert(agentId, privateKey, cert, fallbackPubkey) {
  const certBody = readCertBody(cert, 'agent_identity.cert');
  if (String(certBody.agent_id || '') !== agentId) {
    const error = new Error(`Aimos cert belongs to ${certBody.agent_id || 'unknown'}, expected ${agentId}`);
    error.status = 409;
    throw error;
  }
  const pubkey = String(certBody.pubkey || fallbackPubkey || '').trim();
  if (!pubkey) {
    const error = new Error(`Aimos cert for ${agentId} is missing pubkey`);
    error.status = 409;
    throw error;
  }
  try {
    const privateKeyObject = crypto.createPrivateKey({
      key: Buffer.from(privateKey, 'base64url'),
      format: 'der',
      type: 'pkcs8'
    });
    const publicKeyObject = crypto.createPublicKey({
      key: Buffer.from(pubkey, 'base64url'),
      format: 'der',
      type: 'spki'
    });
    const challenge = Buffer.from(`aimos-agent-key-check\n${agentId}\n${Date.now()}`, 'utf8');
    const signature = crypto.sign(null, challenge, privateKeyObject);
    if (!crypto.verify(null, challenge, publicKeyObject, signature)) {
      const error = new Error(`Aimos private key does not match agent ${agentId}`);
      error.status = 409;
      throw error;
    }
  } catch (error) {
    if (Number.isInteger(error?.status)) throw error;
    const err = new Error(`Aimos private key is invalid for agent ${agentId}`);
    err.status = 409;
    throw err;
  }
}

function readCertBody(cert, filePath) {
  try {
    const envelope = JSON.parse(Buffer.from(cert, 'base64url').toString('utf8'));
    if (!envelope?.body || typeof envelope.body !== 'object') {
      throw new Error('missing body');
    }
    return envelope.body;
  } catch (error) {
    const err = new Error(`Aimos cert envelope is invalid: ${filePath}`);
    err.status = 409;
    throw err;
  }
}

function writeCertCache(agentId, cert, validUntil) {
  const { certCachePath } = agentPaths(agentId);
  const expiresAtMs = validUntil ? new Date(validUntil).getTime() : null;
  writeFileSync(
    certCachePath,
    JSON.stringify({ agent_id: agentId, cert, expires_at_ms: Number.isFinite(expiresAtMs) ? expiresAtMs : null }) + '\n',
    { mode: 0o600 }
  );
  chmodSync(certCachePath, 0o600);
  return certCachePath;
}

async function loadActiveIdentityRow(agentId) {
  const id = assertAgentId(agentId);
  const result = await query(
    `SELECT agent_id, pubkey, cert, device_fp, valid_from, valid_until,
            issued_at, chain_head
       FROM agent_identity
      WHERE agent_id = $1
        AND NOT EXISTS (
          SELECT 1 FROM aimos_agent_revocation_events r
           WHERE r.agent_id = agent_identity.agent_id
             AND r.agent_valid_from = agent_identity.valid_from
        )
        AND (valid_until IS NULL OR valid_until > NOW())
      ORDER BY valid_from DESC
      LIMIT 1`,
    [id]
  );
  const row = result.rows[0] || null;
  if (!row?.cert || !row?.pubkey) {
    const error = new Error(`No valid Aimos enrollment for agent ${id}`);
    error.status = 404;
    throw error;
  }
  return row;
}

async function buildPinnedEnrollment(agentId, req, options = {}) {
  const id = assertAgentId(agentId);
  const row = options.row || await loadActiveIdentityRow(id);

  const { privateKeyPath = agentPaths(id).privateKeyPath } = options;
  assertIdentityFile(privateKeyPath);
  loadAgentPrivkey(privateKeyPath);

  mkdirSync(AGENTS_DIR, { recursive: true, mode: 0o700 });
  const cert = await getAgentCert(id, { forceRefresh: true, cachePath: agentPaths(id).certCachePath });
  const certCachePath = writeCertCache(id, cert, row.valid_until);
  assertIdentityFile(certCachePath);

  const certBody = readCertBody(cert, certCachePath);
  if (String(certBody.agent_id || '') !== id) {
    const error = new Error(`Aimos cert belongs to ${certBody.agent_id || 'unknown'}, expected ${id}`);
    error.status = 409;
    throw error;
  }

  return {
    agent_id: id,
    base_url: `${req.protocol}://${req.get('host')}`,
    private_key_path: privateKeyPath,
    cert_cache_path: certCachePath,
    private_key_sha256: sha256Hex(readFileSync(privateKeyPath)),
    cert_cache_sha256: sha256Hex(readFileSync(certCachePath)),
    public_key_sha256: sha256Hex(Buffer.from(String(certBody.pubkey || row.pubkey), 'base64url')),
    valid_from: row.valid_from,
    valid_until: row.valid_until,
    fingerprint: sha256Hex(Buffer.from(row.pubkey, 'base64url'))
  };
}

function identityError(res, error) {
  const status = Number.isInteger(error?.status) ? error.status : 500;
  return res.status(status).json({
    success: false,
    error: error?.message || String(error)
  });
}

function googleConfigured() {
  return !!(
    systemConfigStore.readConfigString('GOOGLE_CLIENT_ID')
    && peekCachedCredential('google_client_secret')
  );
}

async function checkNeon() {
  try {
    await query('SELECT 1');
    return true;
  } catch {
    return false;
  }
}

// R1 Step 5: identity enumeration now requires a verified cert holding the
// admin_override capability from the verified append-only authorization chain;
// capabilities are snake_case with no colons — see the ledger for the full
// set). The blanket open prefix was removed in auth-gate.js. The key-presence
// boolean — a target map showing which agents have a private key on this host —
// is REMOVED from the response.
router.get('/aimos/identity/agents', requireCapability('admin_override'), async (req, res) => {
  try {
    const q = String(req.query?.q || '').trim().toLowerCase();
    const params = [];
    let filter = `NOT EXISTS (
        SELECT 1 FROM aimos_agent_revocation_events r
         WHERE r.agent_id = agent_identity.agent_id
           AND r.agent_valid_from = agent_identity.valid_from
      )
      AND (valid_until IS NULL OR valid_until > NOW())`;
    if (q) {
      params.push(`%${q}%`);
      filter += ` AND LOWER(agent_id) LIKE $${params.length}`;
    }
    const result = await query(
      `SELECT agent_id, pubkey, valid_from, valid_until
         FROM agent_identity
        WHERE ${filter}
        ORDER BY valid_from DESC
        LIMIT 40`,
      params
    );
    res.json({
      success: true,
      agents: result.rows.map((row) => ({
        agent_id: row.agent_id,
        fingerprint: sha256Hex(Buffer.from(row.pubkey, 'base64url')),
        valid_from: row.valid_from,
        valid_until: row.valid_until
        // key_present REMOVED (R1 Step 5) — nothing outside the host needs it.
      }))
    });
  } catch (error) {
    identityError(res, error);
  }
});

router.post('/aimos/identity/enroll', async (req, res) => {
  // R1 Step 5: per-source exponential backoff + absolute attempt cap.
  const backoff = enrollBackoffCheck(req);
  if (!backoff.ok) {
    return res.status(backoff.status).json({ success: false, error: backoff.error });
  }
  try {
    const agentId = assertAgentId(req.body?.agent_id);
    const passphrase = String(req.body?.master_passphrase || '');
    if (!passphrase) {
      return res.status(400).json({ success: false, error: 'master_passphrase is required' });
    }
    const validityDays = req.body?.validity_days === undefined ? 30 : Number(req.body.validity_days);
    if (!Number.isInteger(validityDays) || validityDays <= 0 || validityDays > 365) {
      return res.status(400).json({ success: false, error: 'validity_days must be an integer from 1 to 365' });
    }

    const { privateKeyPath } = agentPaths(agentId);
    if (existsSync(privateKeyPath)) {
      return res.status(409).json({
        success: false,
        error: `Aimos private key already exists for agent ${agentId}`
      });
    }

    const masterRow = await identityDb.getMaster();
    const keychainAccount = masterRow?.keychain_account || String(req.body?.keychain_account || '').trim();
    if (!keychainAccount) {
      return res.status(400).json({
        success: false,
        error: 'keychain_account is required because this legacy master row predates the persisted locator',
      });
    }

    const result = await enrollAgentWithDeps(agentId, passphrase, {
      keychain: { get: keychainGet, set: keychainSet },
      db: identityDb,
      kcService: KC_SERVICE,
      kcAccount: keychainAccount,
      brainRoot: BRAIN_ROOT
    }, { validityDays });

    if (!result.ok) {
      // R1 Step 5: a bad passphrase / rejected enrollment counts against the
      // per-source backoff + absolute cap.
      enrollRecordFailure(req);
      return res.status(409).json({
        success: false,
        reason: result.reason,
        error: result.detail || result.reason
      });
    }

    mkdirSync(AGENTS_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(privateKeyPath, result.agentPrivkey, { mode: 0o600 });
    chmodSync(privateKeyPath, 0o600);
    writeCertCache(agentId, result.cert, new Date(result.validUntil * 1000).toISOString());

    enrollRecordSuccess(req);
    const pinned = await buildPinnedEnrollment(agentId, req);
    res.json({
      success: true,
      enrolled: true,
      pinned
    });
  } catch (error) {
    enrollRecordFailure(req);
    identityError(res, error);
  }
});

router.post('/aimos/identity/connect', async (req, res) => {
  try {
    const agentId = assertAgentId(req.body?.agent_id);
    const row = await loadActiveIdentityRow(agentId);
    const persistKey = req.body?.persist_key !== false;
    const defaultPrivateKeyPath = agentPaths(agentId).privateKeyPath;
    const hasExplicitKey = Boolean(req.body?.private_key || req.body?.private_key_path);

    let privateKeyPath = defaultPrivateKeyPath;
    if (hasExplicitKey) {
      const { material, sourcePath } = readPrivateKeyMaterial({
        privateKey: req.body?.private_key,
        privateKeyPath: req.body?.private_key_path
      });
      verifyPrivateKeyForCert(agentId, material, row.cert, row.pubkey);

      if (persistKey) {
        mkdirSync(AGENTS_DIR, { recursive: true, mode: 0o700 });
        if (existsSync(defaultPrivateKeyPath)) {
          const existingHash = sha256Hex(readFileSync(defaultPrivateKeyPath));
          const incomingHash = sha256Hex(material);
          if (existingHash !== incomingHash) {
            return res.status(409).json({
              success: false,
              error: `Aimos private key already exists for agent ${agentId} with a different fingerprint`
            });
          }
        } else {
          writeFileSync(defaultPrivateKeyPath, material, { mode: 0o600 });
        }
        chmodSync(defaultPrivateKeyPath, 0o600);
        privateKeyPath = defaultPrivateKeyPath;
      } else if (sourcePath) {
        privateKeyPath = sourcePath;
      } else {
        return res.status(400).json({
          success: false,
          error: 'Raw private_key connection requires persist_key=true so the runtime has a stable signing key path'
        });
      }
    }

    const pinned = await buildPinnedEnrollment(agentId, req, { row, privateKeyPath });
    res.json({
      success: true,
      connected: true,
      pinned
    });
  } catch (error) {
    identityError(res, error);
  }
});

router.post('/aimos/identity/select', async (req, res) => {
  try {
    const pinned = await buildPinnedEnrollment(req.body?.agent_id, req);
    res.json({
      success: true,
      selected: true,
      pinned
    });
  } catch (error) {
    identityError(res, error);
  }
});

router.get('/status', async (req, res) => {
  const googleToken = await getLatestIntegrationToken(COMPANY, 'google', ['gmail']).catch(() => null);
  const googleConnected = googleToken?.access_token_present === true;
  const neonOnline = await checkNeon();

  const obsidianOnline = (() => {
    try {
      const home = os.homedir();
      return existsSync(`${home}/Obsidian/brain`) || existsSync(`${home}/Documents/Obsidian`);
    } catch { return false; }
  })();

  // Flat schema matching Swift SetupStatusResponse
  res.json({
    success: true,
    complete: neonOnline,
    backend: true,
    neon: neonOnline,
    google: googleConnected,
    obsidian: obsidianOnline,
    // legacy nested shape preserved for other consumers
    services: {
      google: { configured: googleConfigured(), connected: googleConnected },
      neon: { configured: true, connected: neonOnline },
    },
  });
});

router.post('/test', async (req, res) => {
  try {
    const operatorAgentId = getOperatorAgentId();
    if (!operatorAgentId) {
      return res.status(400).json({ success: false, error: 'operator_agent_not_designated — set OPERATOR_AGENT_ID via set-system-config.js' });
    }
    const result = await runAgent(operatorAgentId, 'Run a setup health test and confirm system readiness.', {
      skipAimos: true,
      intent: 'setup',
      executionContext: req.executionContext,
    });
    res.json({
      success: true,
      model: result.modelResolved || result.model || null,
      response: result.response || ''
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error?.message || String(error) });
  }
});

export default router;
