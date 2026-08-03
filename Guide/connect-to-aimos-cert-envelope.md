# Connect to Aimos via Certificate Envelope

Last verified: 2026-07-12
Runtime: `<repo-root>`
Aimos base URL: `http://127.0.0.1:9100`
Calling identity: an agent explicitly enrolled by the operator
Key/cert directory: `~/.aimos/agents`

This guide teaches an LLM/operator how to connect to local Aimos. It does not authorize modifying Aimos internals or saving new Aimos memories.

## Non-negotiable rule

Protected Aimos routes require certificate-envelope headers. Do not use bearer tokens, API keys, generic `Authorization` headers, or environment-owned identity for protected `/aimos/*` requests.

Every protected request must include:

- `Aimos-Agent-Cert`
- `Aimos-Agent-Signature`
- `Aimos-Agent-Nonce`
- `Aimos-Agent-Timestamp`

Never print, paste, log, copy, summarize, or expose private key or cert contents. It is acceptable to verify key file existence, mode, and byte size.

## Enrolled identity material

For an enrolled agent `<agent-id>`, verify the private key exists with mode `0600` without reading or printing it:

```text
~/.aimos/agents/<agent-id>.key
```

The public cert should be loaded through Aimos's own identity helper:

```js
getAgentCert('<agent-id>')
```

Do not manually paste the cert into shell headers. Helper output can include status text; direct header interpolation is a common failure mode.

## 1. Health check first

`/health` is unauthenticated and only proves liveness, not protected Aimos access.

```bash
cd <repo-root>
curl -s -m 8 http://127.0.0.1:9100/health
```

Expected response shape:

```json
{"service":"FORGE Memory Aimos","version":"1.0.0","ready":true,"bootError":null}
```

## 2. Signed status + recall smoke test

Run this from `<repo-root>` so imports, database connection, and certificate lookup resolve correctly.

```bash
cd <repo-root>
node --input-type=module - <<'NODE'
import { buildEnvelopeHeaders } from './services/security/envelope-headers.js';
import { pool, agentPool } from './db/connection.js';

const base = 'http://127.0.0.1:9100';
const agentId = '<agent-id>';
async function call(method, path, requestBody = {}) {
  const headers = await buildEnvelopeHeaders(agentId, method, path, requestBody);
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { ...headers, 'Content-Type': 'application/json' },
    ...(method === 'GET' ? {} : { body: JSON.stringify(requestBody) }),
  });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text.slice(0, 800); }
  console.log(JSON.stringify({
    path,
    status: res.status,
    ok: res.ok,
    connected: body?.connected,
    total_memories: body?.total_memories,
    memories_returned: Array.isArray(body?.memories) ? body.memories.length : undefined,
    first_key: body?.memories?.[0]?.key,
    error: body?.error
  }, null, 2));
}

try {
  await call('GET', '/aimos/status');
  await call('POST', '/aimos/recall', {
    query: 'HOM Aimos connection',
    limit: 2,
  });
} finally {
  await Promise.allSettled([pool.end(), agentPool.end()]);
}
NODE
```

Expected output shape (the count is live-state dependent):

```json
{
  "path": "/aimos/status",
  "status": 200,
  "ok": true,
  "connected": true,
  "total_memories": 9
}
```

A successful recall returns HTTP 200 plus native recall evidence. Verify the actual response contract against the live route.

## 3. Signing contract

Use Aimos's local helper implementation as source of truth. It binds the exact method, path, body, nonce, timestamp, certificate, and identity epoch:

```js
import { buildEnvelopeHeaders } from './services/security/envelope-headers.js';
```

For GET-style status routes, sign an empty object. Recall is POST-only and must sign the exact JSON body:

```js
await buildEnvelopeHeaders('<agent-id>', 'GET', '/aimos/status', {});
await buildEnvelopeHeaders('<agent-id>', 'POST', '/aimos/recall', {
  query: 'HOM Aimos connection',
  limit: 2,
});
```

Do not place recall authority, identity, or query state in an unsigned query string.

## 4. Failure signatures

### `401 Unauthorized — cryptographic envelope required`

The request did not carry a valid envelope. Check:

1. Running from `<repo-root>`.
2. Agent id exactly matches the operator-enrolled identity.
3. Private key exists at `~/.aimos/agents/<agent-id>.key` with mode `0600`.
4. Cert is loaded with `getAgentCert('<agent-id>')`.
5. All four `Aimos-Agent-*` headers are present.
6. GET requests are signed with `{}`.

### Header invalid value / byte conversion errors

Usually caused by command substitution that captured status text along with the cert. Do not inject helper stdout directly into headers. Use the Node pattern above.

### `loadAgentPrivkey: key not found`

The key path or signing identity is wrong. Align the identity trio:

1. `agent_id`
2. private key path
3. active `agent_identity` cert row

### `getAgentCert: no active cert for agent <id>`

The key may exist, but Aimos does not have an active cert row for that identity. Use an active enrolled identity, or enroll the new one explicitly if authorized.

## 5. Save boundary

Do not write to Aimos unless the operator explicitly authorizes the save. A working cert envelope proves access, not permission to mutate memory.

When saving is explicitly authorized, use the real `/aimos/save` route through the same certificate-envelope mechanism, preserve truth metadata, and report the real response without exposing secrets.
