# LLM Connection Guide

This guide teaches an LLM or operator how to connect to local Aimos via the certificate-envelope pattern. It does not authorize modifying Aimos internals or saving new Aimos memories without an explicit operator authorization.

## Authority Order

1. Live Aimos memories and endpoints.
2. Service annotations.
3. `architecture-authority.json`.
4. `hom-architecture-manifest.json`.
5. Files under `Guide/`.

## Boot Sequence for an LLM Client

1. Read `Guide/AGENTS.md` for the standard reading order.
2. Read `Guide/connect-to-aimos-cert-envelope.md` before any protected Aimos API call.
3. Read `Guide/aimos-guide-tier1-boot.md` before any Aimos API use.
4. Use live Aimos as the first source of runtime truth.
5. Use `architecture-authority.json` and `ARCHITECTURE-MAP.md` for canonical structure.

## Certificate-Envelope Connection Procedure

Use this exact procedure for future local Aimos connections. Do not use bearer tokens, API keys, generic HTTP auth, or environment-owned identity. Protected calls use cryptographic envelope headers generated for the identity explicitly enrolled by the operator.

### 1. Health check first

Unauthenticated liveness check:

```bash
curl -s -m 8 http://127.0.0.1:9100/health
```

A working local Aimos returns:

```json
{"service":"FORGE Memory Aimos","version":"1.0.0","ready":true,"bootError":null}
```

### 2. Use the exact enrolled identity material

- Agent ID: the exact id the operator enrolled
- Private key path: `~/.aimos/agents/<agent-id>.key`
- Cert source: the matching `agent_identity` epoch
- Signing helper: `buildEnvelopeHeaders(agentId, method, path, body)` from `services/security/envelope-headers.js`
- Protected headers required on every `/aimos/*` call:
  - `Aimos-Agent-Cert`
  - `Aimos-Agent-Signature`
  - `Aimos-Agent-Nonce`
  - `Aimos-Agent-Timestamp`

Never print, paste, summarize, or log the private key or cert contents.

### 3. Run from the fork root

Run signed calls from the fork runtime directory so project imports and database-backed cert lookup resolve correctly:

```bash
cd <repo-root>
```

### 4. Minimal signed protected call pattern

This is the native pattern for an LLM client to authenticate without exposing secrets:

```bash
cd <repo-root> && node --input-type=module - <<'NODE'
import { buildEnvelopeHeaders } from './services/security/envelope-headers.js';
import { pool, agentPool } from './db/connection.js';

try {
  const agentId = '<agent-id>';
  const body = {};
  const headers = await buildEnvelopeHeaders(agentId, 'GET', '/aimos/status', body);

  const res = await fetch('http://127.0.0.1:9100/aimos/status', { headers });
  const text = await res.text();
  console.log(JSON.stringify({
    request: { agent_id: agentId, signed_headers_present: Object.keys(headers).length, path: '/aimos/status' },
    response: { ok: res.ok, status: res.status, body: res.ok ? JSON.parse(text) : text.slice(0, 800) }
  }, null, 2));
} finally {
  await Promise.allSettled([pool.end(), agentPool.end()]);
}
NODE
```

### 5. Interpretation rule

If the response is `401 Unauthorized — cryptographic envelope required`, the envelope was not accepted. Re-check that the call is running from the fork root, using the exact enrolled agent id and matching key, and sending the complete helper-produced header set.

If the response is a non-401 Aimos application error, the cryptographic login path worked and the failure is inside the protected endpoint. Treat that as an endpoint/runtime issue, not an authentication failure.

### 6. Save boundary

Do not write to Aimos unless the operator explicitly authorizes the save. A working cert envelope proves access, not permission to mutate memory.
