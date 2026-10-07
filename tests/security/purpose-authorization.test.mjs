import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { prepareEventMetadata } from '../../services/observe/event-ledger.js';
import { generateKeypair, pubkeyFingerprint } from '../../services/security/agent-identity.js';
import {
  assertLocalFileNotProtected,
  authorizePurposeLocalFileRead,
  createPurposeAuthorizationProof,
  hashBoundedLocalFile,
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
  const signedTs = Math.floor(Date.now() / 1000);
  const validFrom = new Date((signedTs - 10) * 1000).toISOString();
  const validUntil = new Date((signedTs + 600) * 1000).toISOString();
  const proof = createPurposeAuthorizationProof(master.privkey, {
    purposeId: 'mutmem-v2-s6:test',
    companyId: 'hom',
    subjectAgentId: agentId,
    subjectValidFrom: validFrom,
    subjectValidUntil: validUntil,
    operation: 'local_file_read',
    tool: 'read_file',
    readRoot: root,
    targetFile: file,
    targetContentSha256: hashBoundedLocalFile(file),
    clearanceCeiling: 10,
    expiresAt: new Date((signedTs + 300) * 1000).toISOString(),
    masterFingerprint: pubkeyFingerprint(master.pubkey),
  }, { signedTs, nonce: 'purpose-proof-nonce' });
  return { root, file, master, validFrom, validUntil, serialized: serializePurposeAuthorizationProof(proof) };
}

test('event ledger retains only the signed purpose-proof commitment needed by native verification', () => {
  const hash = 'a'.repeat(64);
  const prepared = prepareEventMetadata({
    purpose_authorization_sha256: hash,
    purpose_authorization: 'bearer-like-proof',
    password_sha256: 'b'.repeat(64),
  });
  assert.equal(prepared.purpose_authorization_sha256, hash);
  assert.equal(prepared.purpose_authorization, '[REDACTED]');
  assert.equal(prepared.password_sha256, '[REDACTED]');
  assert.equal(prepareEventMetadata({ purpose_authorization_sha256: 'not-a-hash' }).purpose_authorization_sha256,
    '[REDACTED]');
});

test('master-signed purpose authorization binds exact epoch, file, content, and five-minute window', (t) => {
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
    clearanceLevel: 10,
  }), 'retained proof fixture');
  assert.throws(() => authorizePurposeLocalFileRead({
    serialized: value.serialized,
    masterPubkeyB64u: value.master.pubkey,
    executionContext: {
      actorAgentId: 'different-agent', actorValidFromIso: value.validFrom,
      identityTier: 'T1', companyId: 'hom',
    },
    agentId: 'different-agent', tool: 'read_file', filepath: value.file,
    clearanceLevel: 10,
  }), /purpose_authorization_execution_scope_mismatch/);
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
  };
  assert.equal(readPurposeAuthorizedLocalFile({ ...base, filepath: value.file }), 'retained proof fixture');
  assert.throws(
    () => readPurposeAuthorizedLocalFile({
      ...base, filepath: path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.key'),
    }),
    /purpose_authorization_target_mismatch/,
  );
  assert.throws(
    () => readPurposeAuthorizedLocalFile({ ...base, filepath: value.file, nowMs: Date.parse(value.serialized.body.expires_at) }),
    /purpose_authorization_expired_or_not_yet_valid/,
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
    /target_mismatch/,
  );
  assert.throws(
    () => authorizePurposeLocalFileRead({ ...base, filepath: link }),
    /target_mismatch/,
  );
  assert.throws(
    () => authorizePurposeLocalFileRead({ ...base, filepath: hardLink }),
    /target_mismatch/,
  );
  const tampered = structuredClone(value.serialized);
  tampered.body.clearance_ceiling = 12;
  assert.equal(verifyPurposeAuthorizationProof(tampered, value.master.pubkey).valid, false);
  const otherMaster = generateKeypair();
  assert.equal(verifyPurposeAuthorizationProof(value.serialized, otherMaster.pubkey).valid, false);
  const extended = structuredClone(value.serialized);
  extended.body.expires_at = new Date((extended.ts_signed + 301) * 1000).toISOString();
  assert.equal(verifyPurposeAuthorizationProof(extended, value.master.pubkey).valid, false);
  const adjacent = path.join(value.root, 'adjacent.txt');
  fs.writeFileSync(adjacent, 'different file', { mode: 0o600 });
  assert.throws(
    () => authorizePurposeLocalFileRead({ ...base, filepath: adjacent }),
    /target_mismatch/,
  );
  fs.writeFileSync(value.file, 'changed contents', { mode: 0o600 });
  assert.throws(
    () => readPurposeAuthorizedLocalFile({ ...base, filepath: value.file }),
    /target_hash_mismatch/,
  );
  fs.rmSync(value.file);
  fs.symlinkSync(outside, value.file);
  assert.throws(
    () => readPurposeAuthorizedLocalFile({ ...base, filepath: value.file }),
    /symlink_forbidden/,
  );
});
