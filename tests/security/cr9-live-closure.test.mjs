import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';

import {
  createBackupHeader,
  decryptBufferForTest,
  encryptBufferForTest,
} from '../../scripts/ceremony/lib/cr9-backup-crypto.mjs';
import { reconstructCr9DatabaseAdministration } from '../../scripts/ceremony/lib/cr9-database-owner.mjs';
import {
  CR9_POSTGRES_CONTRACT,
  evaluatePrivilegeClosure,
  normalizeSemanticDefinition,
  normalizeSchemaDump,
  privilegeRepairSql,
} from '../../scripts/ceremony/lib/cr9-postgres.mjs';

function closedAudit(overrides = {}) {
  const sequencePrivileges = CR9_POSTGRES_CONTRACT.expectedRuntimeSequences
    .flatMap((name) => [`${name}:SELECT`, `${name}:USAGE`]).sort();
  return {
    role: { superuser: false, create_role: false, create_db: false, replication: false, bypass_rls: false },
    memberships: [],
    database_privileges: { connect: true, create: false, temporary: false },
    schema_privileges: { public_usage: true, public_create: false },
    sequence_privileges: sequencePrivileges,
    required_insert_sequences: [...CR9_POSTGRES_CONTRACT.expectedRuntimeSequences],
    non_extension_functions: [...CR9_POSTGRES_CONTRACT.expectedNonExtensionFunctions],
    public_non_extension_functions: [],
    delete_tables: [],
    truncate_tables: [],
    owned_relations: [],
    owned_functions: [],
    rls: [{ table: 'public.aimos_memories', enabled: true, forced: false, owner: 'operator' }],
    migrations_098_099: [{ filename: '098-x' }, { filename: '099-x' }],
    semantics_098_099: {
      receipt_index: 'CREATE INDEX aimos_request_receipts_company_mutation_lookup',
      valence_columns: Array.from({ length: 11 }, (_, index) => ({ name: `c${index}` })),
      valence_constraints: ['a', 'b', 'c'],
      valence_indexes: ['a', 'b', 'c'],
    },
    ...overrides,
  };
}

test('CR9 normalizes only the random pg_dump restriction key', () => {
  const body = (token) => `-- dump\n\\restrict ${token}\nCREATE TABLE "x"();\n\\unrestrict ${token}\n`;
  const first = normalizeSchemaDump(body('random-one'));
  const second = normalizeSchemaDump(body('random-two'));
  assert.equal(first, second);
  assert.match(first, /\\restrict homaimoscr9[0-9a-f]{64}/);
  assert.match(first, /CREATE TABLE "x"\(\);/);
});

test('CR9 semantic normalization removes only redundant outer CHECK parentheses', () => {
  assert.equal(normalizeSemanticDefinition(' CHECK  (((value > 0))) '), 'CHECK (value > 0)');
  assert.equal(normalizeSemanticDefinition('FOREIGN KEY (a) REFERENCES b(id) ON DELETE RESTRICT'), 'FOREIGN KEY (a) REFERENCES b(id) ON DELETE RESTRICT');
});

test('CR9 privilege closure detects TEMP and broad sequences, then accepts the exact contract', () => {
  const closed = closedAudit();
  assert.equal(evaluatePrivilegeClosure(closed).valid, true);
  const open = closedAudit({
    database_privileges: { connect: true, create: false, temporary: true },
    sequence_privileges: [...closed.sequence_privileges, 'public.unused_id_seq:USAGE'].sort(),
  });
  const result = evaluatePrivilegeClosure(open);
  assert.equal(result.valid, false);
  assert.equal(result.checks.database_exact, false);
  assert.equal(result.checks.exact_sequences, false);
  assert.deepEqual(result.excess_sequences, ['public.unused_id_seq:USAGE']);
});

test('CR9 repair is surgical and grants no table, function, delete or truncate authority', () => {
  const sql = privilegeRepairSql('aimos');
  assert.match(sql, /REVOKE TEMPORARY ON DATABASE "aimos" FROM PUBLIC, agent_runtime/);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM agent_runtime/);
  assert.equal((sql.match(/"public"\."[a-z0-9_]+"/g) || []).length, 10);
  assert.doesNotMatch(sql, /ON TABLE|ON FUNCTION|DELETE|TRUNCATE|CREATE DATABASE|DROP DATABASE/);
});

test('CR9 AES-GCM binds exact manifest AAD and rejects wrong passphrase and substitution', async () => {
  const weak = { N: 1024, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };
  const header = createBackupHeader({
    sourceSchemaSha256: '1'.repeat(64),
    sourceSemanticSchemaSha256: '4'.repeat(64),
    authorizationSha256: '2'.repeat(64),
    sourceCommit: '3'.repeat(40),
    salt: randomBytes(32),
    iv: randomBytes(12),
  });
  const plaintext = Buffer.from('HOM-AIMOS encrypted backup proof bytes');
  const encrypted = await encryptBufferForTest(plaintext, 'one sufficiently long passphrase', header, { kdf: weak });
  const restored = await decryptBufferForTest(encrypted.ciphertext, encrypted.tag, 'one sufficiently long passphrase', header, { kdf: weak });
  assert.deepEqual(restored, plaintext);
  await assert.rejects(
    decryptBufferForTest(encrypted.ciphertext, encrypted.tag, 'another incorrect passphrase', header, { kdf: weak }),
  );
  await assert.rejects(
    decryptBufferForTest(encrypted.ciphertext, encrypted.tag, 'one sufficiently long passphrase', { ...header, database: 'substituted' }, { kdf: weak }),
  );
});

test('CR9 database effect reconstruction enforces one start and one exact terminal', () => {
  const start = {
    id: 'start-id', key: 'action-id', operation: 'database_administration_started', mutation_hash: 'a'.repeat(64),
    metadata: { schema: 'hom.aimos.database-administration-effect/v1', action_id: 'action-id', operation: 'repair', target_sha256: 'b'.repeat(64), input_sha256: 'c'.repeat(64), authorization_sha256: 'd'.repeat(64) },
  };
  const terminal = {
    id: 'terminal-id', key: 'action-id', operation: 'database_administration_terminal', parent_event_id: 'start-id',
    metadata: { ...start.metadata, start_event_id: 'start-id', start_mutation_hash: 'a'.repeat(64), disposition: 'SUCCEEDED', result_sha256: 'e'.repeat(64) },
  };
  const proof = reconstructCr9DatabaseAdministration([start, terminal]);
  assert.equal(proof.complete.length, 1);
  assert.equal(proof.open.length, 0);
  assert.equal(proof.timeComplexity, 'O(n)');
  assert.throws(() => reconstructCr9DatabaseAdministration([start, { ...terminal, parent_event_id: 'wrong' }]), /terminal_binding_invalid/);

  const v2Start = {
    ...start,
    metadata: {
      ...start.metadata,
      schema: 'hom.aimos.database-administration-effect/v2',
      authorization_sha256: undefined,
      operator_plan_sha256: 'f'.repeat(64),
    },
  };
  const v2Terminal = {
    ...terminal,
    metadata: {
      ...terminal.metadata,
      schema: 'hom.aimos.database-administration-effect/v2',
      authorization_sha256: undefined,
      operator_plan_sha256: 'f'.repeat(64),
    },
  };
  assert.equal(reconstructCr9DatabaseAdministration([v2Start, v2Terminal]).complete.length, 1);
  assert.throws(() => reconstructCr9DatabaseAdministration([
    v2Start,
    { ...v2Terminal, metadata: { ...v2Terminal.metadata, operator_plan_sha256: '0'.repeat(64) } },
  ]), /terminal_binding_invalid/);
});
