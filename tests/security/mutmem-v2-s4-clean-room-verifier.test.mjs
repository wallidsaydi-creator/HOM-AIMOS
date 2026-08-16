import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  createFocusedVectors,
  nodeVerdict,
} from '../../scripts/verification/mutmem-v2-s4-fixture-factory.mjs';

const VERIFY = new URL('../../verifiers/mutmem-python/verify.py', import.meta.url);
const PYTHON_OWNER = new URL('../../verifiers/mutmem-python/mutmem_verifier.py', import.meta.url);
const REQUIREMENTS = new URL('../../verifiers/mutmem-python/requirements.lock', import.meta.url);
const SBOM = new URL('../../verifiers/mutmem-python/SBOM.spdx.json', import.meta.url);

function runPython(raw, operation = 'verify-bundle') {
  const child = spawnSync('python3', [VERIFY.pathname, operation, '-'], {
    input: typeof raw === 'string' ? raw : JSON.stringify(raw),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  assert.notEqual(child.status, null, child.error?.message || 'Python verifier did not terminate');
  return {
    status: child.status,
    stderr: child.stderr,
    output: JSON.parse(child.stdout),
  };
}

test('V2-S4 focused signed vectors have exact Node/Python verdict and reason parity', () => {
  for (const vector of createFocusedVectors()) {
    const node = nodeVerdict(vector.bundle);
    const python = runPython(vector.bundle);
    assert.equal(node.verdict, vector.expected, `${vector.id}: Node verdict`);
    assert.equal(node.reason, vector.reason, `${vector.id}: Node reason`);
    assert.equal(python.output.verdict, vector.expected, `${vector.id}: Python verdict`);
    assert.equal(python.output.primary_reason, vector.reason, `${vector.id}: Python reason`);
    assert.equal(python.status, vector.expected === 'valid' ? 0 : 1, `${vector.id}: Python exit`);

    if (node.proof) {
      assert.deepEqual(python.output.records, node.proof.records, `${vector.id}: records`);
      assert.deepEqual(python.output.sql_rows, node.proof.sqlRows, `${vector.id}: SQL summaries`);
      assert.equal(python.output.parity, node.proof.parity, `${vector.id}: parity`);
      assert.equal(python.output.proof_root, node.proof.proofRoot.toString('hex'), `${vector.id}: root`);
      assert.equal(
        python.output.bundle_sha256,
        node.proof.bundleSha256.toString('hex'),
        `${vector.id}: bundle hash`,
      );
      assert.deepEqual(
        python.output.event_stream_results,
        node.proof.eventStreamResults,
        `${vector.id}: event streams`,
      );
    }
  }
});

test('V2-S4 hostile parser rejects duplicate keys and excessive nesting in bounded time', () => {
  const duplicate = runPython('{"format":{},"format":{}}');
  assert.equal(duplicate.status, 1);
  assert.equal(duplicate.output.primary_reason, 'json_duplicate_key');

  const deep = runPython(`${'['.repeat(35)}null${']'.repeat(35)}`);
  assert.equal(deep.status, 1);
  assert.equal(deep.output.primary_reason, 'canonical_json_depth_limit');
});

test('V2-S4 malformed invocation exits 3 and cannot be mistaken for validity', () => {
  const child = spawnSync('python3', [VERIFY.pathname, 'verify-bundle'], {
    encoding: 'utf8',
  });
  assert.equal(child.status, 3);
  assert.equal(JSON.parse(child.stdout).primary_reason, 'malformed_invocation');
});

test('V2-S4 Python verifier has no AIMOS runtime, authority, network, or environment dependency', async () => {
  const [owner, cli] = await Promise.all([
    readFile(PYTHON_OWNER, 'utf8'),
    readFile(VERIFY, 'utf8'),
  ]);
  const imports = [...owner.matchAll(/^(?:from|import)\s+([^\s.]+)/gm)]
    .map((match) => match[1]);
  assert.deepEqual(imports, [
    '__future__',
    'base64',
    'hashlib',
    'json',
    'math',
    'struct',
    'uuid',
    'dataclasses',
    'datetime',
    'typing',
    'cryptography',
    'cryptography',
  ]);
  assert.doesNotMatch(
    owner,
    /process\.env|os\.environ|subprocess|socket|requests|urllib|services\/|routes\/|db\/|Keychain|private[_ -]?key/i,
  );
  assert.doesNotMatch(cli, /process\.env|os\.environ|subprocess|socket|requests|urllib/);
  assert.match(cli, /read\(MAX_BUNDLE_BYTES \+ 1\)/);
  assert.doesNotMatch(
    cli,
    /raw\s*=\s*(?:sys\.stdin\.buffer\.read\(\)|Path\([^\n]+\)\.read_bytes\(\))/,
  );
});

test('V2-S4 dependency lock and SPDX SBOM cover the complete CPython runtime closure', async () => {
  const [lock, sbomRaw] = await Promise.all([
    readFile(REQUIREMENTS, 'utf8'),
    readFile(SBOM, 'utf8'),
  ]);
  const sbom = JSON.parse(sbomRaw);
  const expected = new Map([
    ['cryptography', '49.0.0'],
    ['cffi', '2.0.0'],
    ['pycparser', '3.0'],
  ]);
  for (const [name, version] of expected) {
    assert.match(lock, new RegExp(`^${name}==${version}$`, 'm'));
    const entry = sbom.packages.find((pkg) => pkg.name === name);
    assert.equal(entry?.versionInfo, version);
    const installed = execFileSync(
      'python3',
      ['-c', `from importlib.metadata import version; print(version('${name}'))`],
      { encoding: 'utf8' },
    ).trim();
    assert.equal(installed, version);
  }
});
