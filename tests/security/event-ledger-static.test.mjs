import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RUNTIME_ROOTS = ['services', 'routes', 'jobs', 'scripts'];

function sourceFiles(root) {
  const out = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(full));
    else if (/\.(?:mjs|js)$/.test(entry.name)) out.push(full);
  }
  return out;
}

test('event ledger has one native append owner and no runtime mutation or DDL', () => {
  const inserts = [];
  const forbidden = [];
  for (const relativeRoot of RUNTIME_ROOTS) {
    for (const file of sourceFiles(path.join(ROOT, relativeRoot))) {
      const source = fs.readFileSync(file, 'utf8');
      const insertCount = [...source.matchAll(/INSERT\s+INTO\s+(?:public\.)?aimos_events/gi)].length;
      if (insertCount) inserts.push({ file: path.relative(ROOT, file), insertCount });
      if (/\b(?:UPDATE\s+(?:public\.)?aimos_events|DELETE\s+FROM\s+(?:public\.)?aimos_events|TRUNCATE\s+(?:TABLE\s+)?(?:public\.)?aimos_events)\b/i.test(source)) {
        forbidden.push(path.relative(ROOT, file));
      }
      if (/\b(?:ALTER\s+TABLE|CREATE\s+TABLE|CREATE\s+INDEX)[\s\S]{0,100}\baimos_events\b/i.test(source)) {
        forbidden.push(path.relative(ROOT, file));
      }
    }
  }

  assert.deepEqual(inserts, [{ file: 'services/observe/event-ledger.js', insertCount: 1 }]);
  assert.deepEqual([...new Set(forbidden)], []);
});

test('migration makes post-cutover proof mandatory for the restricted role', () => {
  const migration = fs.readFileSync(path.join(ROOT, 'migrations/051-cryptographic-event-ledger.sql'), 'utf8');
  assert.match(migration, /ADD COLUMN IF NOT EXISTS proof_required boolean/);
  assert.match(migration, /ALTER COLUMN proof_required SET DEFAULT true/);
  assert.match(migration, /proof_required IS NULL[\s\S]+proof_required IS TRUE/);
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public\.aimos_events FROM agent_runtime/);
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public\.aimos_events FROM aimos_app/);

  const grant = migration.match(/GRANT INSERT \(([\s\S]+?)\) ON public\.aimos_events TO agent_runtime/);
  assert(grant, 'restricted event INSERT column grant must exist');
  assert.doesNotMatch(grant[1], /\bproof_required\b/);
});
