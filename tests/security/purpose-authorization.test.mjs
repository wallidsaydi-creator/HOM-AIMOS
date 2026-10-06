import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { generateKeypair, pubkeyFingerprint } from '../../services/security/agent-identity.js';
import {
  assertLocalFileNotProtected,
  authorizePurposeLocalFileRead,
  createPurposeAuthorizationProof,
  inspectAllowedLocalFileWrite,
  purposeAuthorizationArtifactSha256,
  readPurposeAuthorizedLocalFile,
  serializePurposeAuthorizationProof,
  verifyPurposeAuthorizationProof,
  writeAllowedLocalFile,
} from '../../services/security/purpose-authorization.js';

function fixture(agentId = 'purpose-agent') {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-purpose-auth-')));
  fs.chmodSync(root, 0o700);
  const file = path.join(root, 'fixture.txt');
  fs.writeFileSync(file, 'retained proof fixture', { mode: 0o600 });
  const master = generateKeypair();
  const validFrom = new Date(Date.now() - 1_000).toISOString();
  const validUntil = new Date(Date.now() + 60_000).toISOString();
  const proof = createPurposeAuthorizationProof(master.privkey, {
    purposeId: 'mutmem-v2-s6:test',
    protocolId: 'hom-aimos-canary-cross-transport-v3',
    protocolConfirmationSha256: '1'.repeat(64),
    sourceRootSha256: '2'.repeat(64),
    corpusRootSha256: '3'.repeat(64),
    databaseNameSha256: '4'.repeat(64),
    companyId: 'hom',
    subjectAgentId: agentId,
    subjectValidFrom: validFrom,
    subjectValidUntil: validUntil,
    operation: 'local_file_read',
    tool: 'read_file',
    readRoot: root,
    clearanceCeiling: 10,
    masterFingerprint: pubkeyFingerprint(master.pubkey),
  }, { signedTs: 1_786_200_000, nonce: 'purpose-proof-nonce' });
  return { root, file, master, validFrom, validUntil, serialized: serializePurposeAuthorizationProof(proof) };
}

test('master-signed purpose authorization binds exact epoch, protocol, tool, and read root', (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  const verified = verifyPurposeAuthorizationProof(value.serialized, value.master.pubkey);
  assert.equal(verified.valid, true);
  const admitted = authorizePurposeLocalFileRead({
    serialized: value.serialized,
    masterPubkeyB64u: value.master.pubkey,
    executionContext: {
      actorAgentId: 'purpose-agent',
      actorValidFromIso: value.validFrom,
      identityTier: 'T1',
      companyId: 'hom',
    },
    agentId: 'purpose-agent',
    tool: 'read_file',
    filepath: value.file,
    clearanceLevel: 10,
    expectedProtocolConfirmationSha256: '1'.repeat(64),
  });
  assert.equal(admitted.valid, true);
  assert.equal(admitted.artifactSha256, purposeAuthorizationArtifactSha256(value.serialized));
  assert.equal(admitted.operation, 'local_file_read');
  assert.equal(readPurposeAuthorizedLocalFile({
    serialized: value.serialized,
    masterPubkeyB64u: value.master.pubkey,
    executionContext: {
      actorAgentId: 'purpose-agent', actorValidFromIso: value.validFrom,
      identityTier: 'T1', companyId: 'hom',
    },
    agentId: 'purpose-agent', tool: 'read_file', filepath: value.file,
    clearanceLevel: 10, expectedProtocolConfirmationSha256: '1'.repeat(64),
  }), 'retained proof fixture');
});

test('protected credential paths are denied even under an otherwise valid read root', () => {
  const protectedRoot = path.join(os.tmpdir(), 'aimos-protected-fixture');
  assert.throws(
    () => assertLocalFileNotProtected(path.join(protectedRoot, 'agents', 'housekeeper.key'), [protectedRoot]),
    /local_file_protected_path/,
  );
  assert.throws(
    () => assertLocalFileNotProtected(path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.key')),
    /local_file_protected_path/,
  );
  assert.throws(() => assertLocalFileNotProtected('/safe/.env.local', []), /local_file_protected_path/);
  assert.doesNotThrow(() => assertLocalFileNotProtected('/safe/report.txt', []));
});

test('an operator identity still needs its own signed exact-epoch proof and cannot read the AIMOS key root', (t) => {
  const value = fixture('operator');
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  const base = {
    serialized: value.serialized,
    masterPubkeyB64u: value.master.pubkey,
    executionContext: {
      actorAgentId: 'operator', actorValidFromIso: value.validFrom,
      identityTier: 'T1', companyId: 'hom',
    },
    agentId: 'operator', tool: 'read_file', clearanceLevel: 10,
    expectedProtocolConfirmationSha256: '1'.repeat(64),
  };
  assert.equal(readPurposeAuthorizedLocalFile({ ...base, filepath: value.file }), 'retained proof fixture');
  assert.throws(
    () => readPurposeAuthorizedLocalFile({
      ...base, filepath: path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.key'),
    }),
    /local_file_protected_path/,
  );
  assert.throws(
    () => readPurposeAuthorizedLocalFile({ ...base, expectedProtocolConfirmationSha256: null, filepath: value.file }),
    /purpose_authorization_protocol_commitment_required/,
  );
});

test('write preflight denies unowned paths and native write requires a verified signed action', async (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-file-write-')));
  fs.chmodSync(root, 0o700);
  const outsideRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-file-outside-')));
  fs.chmodSync(outsideRoot, 0o700);
  t.after(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outsideRoot, { recursive: true, force: true });
  });
  const ordinary = path.join(root, 'nested', 'report.txt');
  assert.throws(() => inspectAllowedLocalFileWrite({
    filepath: ordinary, content: 'safe report', allowedRoots: [root],
  }), /ENOENT/);
  assert.equal(fs.existsSync(path.join(root, 'nested')), false);
  fs.mkdirSync(path.join(root, 'nested'), { mode: 0o700 });
  assert.equal(inspectAllowedLocalFileWrite({
    filepath: ordinary, content: 'safe report', allowedRoots: [root],
  }).requested, ordinary);
  const writeEpoch = new Date().toISOString();
  await assert.rejects(writeAllowedLocalFile({
    filepath: ordinary, content: 'unaudited',
    toolActionAuthority: { actorAgentId: 'purpose-agent', actorValidFromIso: writeEpoch },
    executionContext: { actorAgentId: 'purpose-agent', actorValidFromIso: writeEpoch, companyId: 'hom' },
    agentId: 'purpose-agent',
  }), /verified_tool_action_required/);
  assert.equal(fs.existsSync(ordinary), false);

  const outside = path.join(outsideRoot, 'secret.txt');
  fs.writeFileSync(outside, 'unchanged', { mode: 0o600 });
  const finalLink = path.join(root, 'linked.txt');
  fs.symlinkSync(outside, finalLink);
  assert.throws(
    () => inspectAllowedLocalFileWrite({ filepath: finalLink, content: 'overwrite', allowedRoots: [root] }),
    /local_file_target_invalid/,
  );
  const brokenLink = path.join(root, 'broken.txt');
  fs.symlinkSync(path.join(outsideRoot, 'missing.txt'), brokenLink);
  assert.throws(
    () => inspectAllowedLocalFileWrite({ filepath: brokenLink, content: 'overwrite', allowedRoots: [root] }),
    /local_file_target_invalid/,
  );
  const parentLink = path.join(root, 'redirect');
  fs.symlinkSync(outsideRoot, parentLink);
  assert.throws(
    () => inspectAllowedLocalFileWrite({ filepath: path.join(parentLink, 'secret.txt'), content: 'overwrite', allowedRoots: [root] }),
    /local_file_directory_custody_invalid/,
  );
  const hardLink = path.join(root, 'hardlink.txt');
  fs.linkSync(outside, hardLink);
  assert.equal(inspectAllowedLocalFileWrite({
    filepath: hardLink, content: 'new inode', allowedRoots: [root],
  }).requested, hardLink);
  assert.equal(fs.readFileSync(outside, 'utf8'), 'unchanged');
  assert.equal(fs.readFileSync(hardLink, 'utf8'), 'unchanged');

  const unsafe = path.join(root, 'writable');
  fs.mkdirSync(unsafe, { mode: 0o777 });
  fs.chmodSync(unsafe, 0o777);
  assert.throws(
    () => inspectAllowedLocalFileWrite({ filepath: path.join(unsafe, 'file.txt'), content: 'unsafe', allowedRoots: [root] }),
    /local_file_directory_custody_invalid/,
  );
  assert.equal(fs.readFileSync(outside, 'utf8'), 'unchanged');
});

test('purpose authorization rejects tamper, wrong epoch, path escape, and symlink traversal', (t) => {
  const value = fixture();
  const outsideRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-purpose-outside-')));
  const outside = path.join(outsideRoot, 'outside.txt');
  fs.writeFileSync(outside, 'outside', { mode: 0o600 });
  const escaped = path.join(outsideRoot, 'escape.txt');
  fs.writeFileSync(escaped, 'escape', { mode: 0o600 });
  const link = path.join(value.root, 'link.txt');
  fs.symlinkSync(outside, link);
  const hardLink = path.join(value.root, 'hardlink.txt');
  fs.linkSync(outside, hardLink);
  t.after(() => {
    fs.rmSync(value.root, { recursive: true, force: true });
    fs.rmSync(outsideRoot, { recursive: true, force: true });
  });
  const base = {
    serialized: value.serialized,
    masterPubkeyB64u: value.master.pubkey,
    executionContext: {
      actorAgentId: 'purpose-agent',
      actorValidFromIso: value.validFrom,
      identityTier: 'T1',
      companyId: 'hom',
    },
    agentId: 'purpose-agent',
    tool: 'read_file',
    clearanceLevel: 10,
    expectedProtocolConfirmationSha256: '1'.repeat(64),
  };
  assert.throws(
    () => authorizePurposeLocalFileRead({
      ...base,
      executionContext: { ...base.executionContext, actorValidFromIso: new Date().toISOString() },
      filepath: value.file,
    }),
    /execution_scope_mismatch/,
  );
  assert.throws(
    () => authorizePurposeLocalFileRead({ ...base, filepath: escaped }),
    /path_escape/,
  );
  assert.throws(
    () => authorizePurposeLocalFileRead({ ...base, filepath: link }),
    /file_realpath_invalid|symlink_forbidden/,
  );
  assert.throws(
    () => authorizePurposeLocalFileRead({ ...base, filepath: hardLink }),
    /hardlink_forbidden/,
  );
  const tampered = structuredClone(value.serialized);
  tampered.body.clearance_ceiling = 12;
  assert.equal(verifyPurposeAuthorizationProof(tampered, value.master.pubkey).valid, false);
});
