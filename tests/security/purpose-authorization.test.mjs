import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { generateKeypair, pubkeyFingerprint } from '../../services/security/agent-identity.js';
import {
  authorizePurposeLocalFileRead,
  createPurposeAuthorizationProof,
  purposeAuthorizationArtifactSha256,
  serializePurposeAuthorizationProof,
  verifyPurposeAuthorizationProof,
} from '../../services/security/purpose-authorization.js';

function fixture() {
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
    subjectAgentId: 'purpose-agent',
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
});

test('purpose authorization rejects tamper, wrong epoch, path escape, and symlink traversal', (t) => {
  const value = fixture();
  const outsideRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-purpose-outside-')));
  const outside = path.join(outsideRoot, 'outside.txt');
  fs.writeFileSync(outside, 'outside', { mode: 0o600 });
  const link = path.join(value.root, 'link.txt');
  fs.symlinkSync(outside, link);
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
    () => authorizePurposeLocalFileRead({ ...base, filepath: outside }),
    /path_escape/,
  );
  assert.throws(
    () => authorizePurposeLocalFileRead({ ...base, filepath: link }),
    /file_realpath_invalid|symlink_forbidden/,
  );
  const tampered = structuredClone(value.serialized);
  tampered.body.clearance_ceiling = 12;
  assert.equal(verifyPurposeAuthorizationProof(tampered, value.master.pubkey).valid, false);
});
