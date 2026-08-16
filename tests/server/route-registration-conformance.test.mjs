import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import express from 'express';

const root = path.resolve(new URL('../../', import.meta.url).pathname);

test('every literal HTTP route pattern registers under the installed Express router', () => {
  const files = [
    path.join(root, 'server.js'),
    ...readdirSync(path.join(root, 'routes'))
      .filter((name) => name.endsWith('.js'))
      .sort()
      .map((name) => path.join(root, 'routes', name)),
  ];
  const literalRoute = /\b(?:app|router)\.(?:all|delete|get|head|options|patch|post|put|use)\(\s*(['"])([^'"\r\n]+)\1/g;
  const invalid = [];

  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(literalRoute)) {
      const route = match[2];
      try {
        const probe = express.Router();
        probe.use(route, (_req, _res, next) => next());
      } catch (error) {
        invalid.push({
          file: path.relative(root, file),
          route,
          error: String(error?.message || error),
        });
      }
    }
  }

  assert.deepEqual(invalid, []);
});

test('native StreamableHTTP MCP and the external MCP bridge have one route owner each', async () => {
  const [serverSource, nativeMcp] = await Promise.all([
    Promise.resolve(readFileSync(path.join(root, 'server.js'), 'utf8')),
    import('../../routes/aimos-mcp-streamable.js'),
  ]);

  assert.equal(typeof nativeMcp.default, 'function');
  assert.match(serverSource, /app\.use\('\/mcp', lazyRouter\('\.\/routes\/aimos-mcp-streamable\.js'/);
  assert.match(serverSource, /app\.use\('\/mcp\/bridge', lazyRouter\('\.\/routes\/mcp\.js'/);
  assert.doesNotMatch(
    readFileSync(path.join(root, 'routes', 'aimos-mcp-streamable.js'), 'utf8'),
    /router\.post\('\/bridge\//,
  );
});
