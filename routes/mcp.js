import express from 'express';
import { randomUUID } from 'crypto';
import { URL } from 'url';
import dns from 'node:dns';
import net from 'node:net';
import { fetchWithTimeout } from '../services/orchestration/http.js';
import { buildAimosMcpManifest } from '../services/orchestration/aimos-mcp-catalog.js';
import { query } from '../db/connection.js';

const router = express.Router();

// In-memory cache hydrated from mcp_connections table on first access.
// Key: connection id (UUID), Value: connection object.
const connections = new Map();
let cacheHydrated = false;

async function hydrateConnections() {
  if (cacheHydrated) return;
  try {
    const result = await query(
      `SELECT id, company_id, name, url, protocol, status, metadata,
              COALESCE(last_error, '') AS last_error,
              created_at, updated_at
       FROM mcp_connections
       WHERE status IN ('connected', 'error')`
    );
    for (const row of result.rows || []) {
      connections.set(row.id, {
        id: row.id,
        companyId: row.company_id,
        name: row.name,
        url: row.url,
        protocol: row.protocol || 'mcp',
        status: row.status,
        metadata: row.metadata || {},
        lastError: row.last_error,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      });
    }
    cacheHydrated = true;
  } catch (e) {
    console.error('[MCP] Failed to hydrate connections from DB:', e.message);
  }
}

/**
 * R1 Step 7: SSRF protection with DNS resolution.
 *
 * The old filter only matched LITERAL private-IP / localhost strings, so a
 * hostname that *resolves* to 127.0.0.1 (DNS rebinding) sailed through, and
 * callRemote re-fetched the stored URL without re-validating. Now:
 *   - the hostname is RESOLVED and EVERY resolved address is checked against
 *     the private / loopback / link-local / metadata blocklist, and
 *   - validation runs again at fetch time (callRemote), so a record that
 *     flipped to a private address after connect is caught.
 */
function ipIsBlocked(ip) {
  const kind = net.isIP(ip);
  if (kind === 4) {
    const o = ip.split('.').map(Number);
    if (o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    const [a, b] = o;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||        // link-local + 169.254.169.254 metadata
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || // CGNAT 100.64.0.0/10
      a >= 224                            // multicast / reserved
    );
  }
  if (kind === 6) {
    const v = ip.toLowerCase();
    // IPv4-mapped (::ffff:a.b.c.d) — extract and re-check the IPv4.
    const mapped = v.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return ipIsBlocked(mapped[1]);
    return (
      v === '::1' || v === '::' ||
      v.startsWith('fe80') ||   // link-local
      v.startsWith('fc') || v.startsWith('fd') || // unique-local
      v.startsWith('fec0')      // deprecated site-local
    );
  }
  return true; // unparseable → block
}

function isBlockedHostnameLiteral(hostname) {
  return (
    hostname === 'localhost' ||
    hostname === '0.0.0.0' ||
    hostname.endsWith('.localhost')
  );
}

async function assertSafeUrl(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    const err = new Error('Invalid URL');
    err.statusCode = 400;
    throw err;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    const err = new Error('Only http and https protocols are allowed');
    err.statusCode = 400;
    throw err;
  }

  let hostname = parsed.hostname.toLowerCase();
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    hostname = hostname.slice(1, -1); // strip IPv6 brackets
  }

  if (isBlockedHostnameLiteral(hostname)) {
    const err = new Error('Requests to localhost are not allowed');
    err.statusCode = 400;
    throw err;
  }

  // If the host is already a literal IP, validate it directly (no DNS).
  if (net.isIP(hostname)) {
    if (ipIsBlocked(hostname)) {
      const err = new Error('Requests to private/internal IP addresses are not allowed');
      err.statusCode = 400;
      throw err;
    }
    return parsed;
  }

  // Resolve the hostname and validate EVERY resolved address.
  let addresses;
  try {
    addresses = await dns.promises.lookup(hostname, { all: true });
  } catch {
    const err = new Error('Hostname could not be resolved');
    err.statusCode = 400;
    throw err;
  }
  if (!addresses.length) {
    const err = new Error('Hostname resolved to no addresses');
    err.statusCode = 400;
    throw err;
  }
  for (const { address } of addresses) {
    if (ipIsBlocked(address)) {
      const err = new Error('Hostname resolves to a private/internal address (SSRF blocked)');
      err.statusCode = 400;
      throw err;
    }
  }
  return parsed;
}

function normalizeUrl(value) {
  const url = String(value || '').trim();
  if (!url) return '';
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

async function resolveConnection(id) {
  await hydrateConnections();
  const conn = connections.get(String(id || '').trim());
  if (!conn) throw new Error('connection not found');
  return conn;
}

async function callRemote(connection, path, options = {}) {
  // R1 Step 7: re-validate at FETCH time. The stored URL is re-resolved and
  // re-checked so a DNS record that flipped to a private address after connect
  // (rebinding) is rejected before we ever open the socket.
  await assertSafeUrl(connection.url);
  const headers = {
    'Content-Type': 'application/json',
    ...(connection.headers || {}),
    ...(options.headers || {})
  };
  const res = await fetchWithTimeout(`${connection.url}${path}`, {
    ...options,
    headers
  }, 12_000);
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(payload?.error || `Remote MCP error (${res.status})`);
  }
  return payload;
}

async function createConnectionFromBody(body = {}) {
  const url = normalizeUrl(body?.url);
  const headers = body?.headers && typeof body.headers === 'object' ? body.headers : {};
  if (!url) {
    const error = new Error('url is required');
    error.statusCode = 400;
    throw error;
  }

  await assertSafeUrl(url);

  const companyId = String(body?.company_id || 'hom').trim();
  const name = String(body?.name || body?.url || url).trim();
  const id = randomUUID();

  const metadata = { ...body, headers };
  delete metadata.url;
  delete metadata.name;
  delete metadata.company_id;

  // Persist to DB
  await query(
    `INSERT INTO mcp_connections (id, company_id, name, url, protocol, status, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (company_id, name) DO UPDATE SET
       url = EXCLUDED.url,
       protocol = EXCLUDED.protocol,
       status = EXCLUDED.status,
       metadata = EXCLUDED.metadata,
       updated_at = NOW()`,
    [id, companyId, name, url, 'mcp', 'connected', JSON.stringify(metadata)]
  );

  const connection = {
    id,
    companyId,
    name,
    url,
    protocol: 'mcp',
    status: 'connected',
    metadata,
    lastError: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  connections.set(id, connection);
  return connection;
}

router.post('/connect', async (req, res) => {
  try {
    const connection = await createConnectionFromBody(req.body);
    res.json({ success: true, connection });
  } catch (error) {
    res.status(error.statusCode || 500).json({ success: false, error: error?.message || String(error) });
  }
});

router.post('/connections', async (req, res) => {
  const url = normalizeUrl(req.body?.url);
  if (!url) return res.status(400).json({ success: false, error: 'url is required' });
  try {
    const connection = await createConnectionFromBody(req.body);
    res.json(connection);
  } catch (error) {
    res.status(error.statusCode || 500).json({ success: false, error: error?.message || String(error) });
  }
});

router.get('/connections', async (req, res) => {
  await hydrateConnections();
  const items = Array.from(connections.values());
  const format = String(req.query?.format || '').trim().toLowerCase();
  if (format === 'wrapped' || format === 'object') {
    return res.json({ success: true, items });
  }
  res.json(items);
});

router.delete('/connections/:id', async (req, res) => {
  const id = String(req.params.id || '').trim();
  try {
    await query(
      `UPDATE mcp_connections SET status = 'disconnected', updated_at = NOW() WHERE id = $1`,
      [id]
    );
    connections.delete(id);
    res.json({ success: true, removed: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error?.message || String(error) });
  }
});

router.get('/tools', async (req, res) => {
  const connectionId = String(req.query.connectionId || '').trim();
  if (!connectionId) {
    return res.status(400).json({ success: false, error: 'connectionId is required' });
  }
  try {
    const connection = await resolveConnection(connectionId);
    let payload;
    try {
      payload = await callRemote(connection, '/mcp/tools', { method: 'GET' });
    } catch {
      payload = await callRemote(connection, '/tools', { method: 'GET' });
    }
    res.json({ success: true, ...payload });
  } catch (error) {
    res.status(500).json({ success: false, error: error?.message || String(error) });
  }
});

router.post('/execute', async (req, res) => {
  const connectionId = String(req.body?.connectionId || '').trim();
  const tool = String(req.body?.tool || '').trim();
  const args = req.body?.args && typeof req.body.args === 'object' ? req.body.args : {};

  if (!connectionId || !tool) {
    return res.status(400).json({ success: false, error: 'connectionId and tool are required' });
  }

  try {
    const connection = await resolveConnection(connectionId);
    let payload;
    try {
      payload = await callRemote(connection, '/mcp/execute', {
        method: 'POST',
        body: JSON.stringify({ tool, args })
      });
    } catch {
      payload = await callRemote(connection, '/execute', {
        method: 'POST',
        body: JSON.stringify({ tool, args })
      });
    }
    res.json({ success: true, ...payload });
  } catch (error) {
    res.status(500).json({ success: false, error: error?.message || String(error) });
  }
});

router.get('/manifest', async (req, res) => {
  res.json({
    success: true,
    ...buildAimosMcpManifest({
      name: 'HOM MCP Bridge',
      version: '2.0.0',
      transport: 'http'
    }),
    role: 'bridge',
    sourceOfTruth: {
      aimosManifest: '/aimos/mcp/tools/list',
      aimosCall: '/aimos/mcp/tools/call'
    },
    bridgeRoutes: {
      connect: '/mcp/connect',
      connections: '/mcp/connections',
      tools: '/mcp/tools',
      execute: '/mcp/execute'
    }
  });
});

export default router;
