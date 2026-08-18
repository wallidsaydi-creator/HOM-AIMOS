import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

test('server does not advertise recall readiness before local embedding inference succeeds', () => {
  const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  const embeddings = fs.readFileSync(path.join(ROOT, 'services/core/embeddings.js'), 'utf8');
  const prewarm = server.indexOf('await prewarmEmbeddingRuntime()');
  const ready = server.indexOf('backgroundReady = true');
  assert.ok(prewarm >= 0 && ready > prewarm);
  assert.match(embeddings, /export async function prewarmEmbeddingRuntime\(\)/);
  assert.match(embeddings, /dimension !== 768/);
  assert.match(embeddings, /canonical_memory_changed: false/);
  assert.match(embeddings, /authority_changed: false/);
});
