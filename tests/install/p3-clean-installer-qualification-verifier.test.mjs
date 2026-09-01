import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  verifyP3InstallerQualification,
} from '../../scripts/verification/verify-p3-clean-installer-qualification.mjs';

const receipt = JSON.parse(await readFile(new URL(
  '../../verifiers/mutmem-conformance/v2/p3-clean-installer-qualification.json',
  import.meta.url,
), 'utf8'));
const sha = (value) => createHash('sha256').update(value).digest('hex');

function rebindContainerHashes(candidate) {
  const terminal = { ...candidate.signed_terminal };
  delete terminal.receipt_sha256;
  candidate.signed_terminal.receipt_sha256 = sha(Buffer.from(canonicalJson(terminal)));
  const outer = { ...candidate };
  delete outer.qualification_sha256;
  candidate.qualification_sha256 = sha(Buffer.from(canonicalJson(outer)));
  return candidate;
}

test('current retained-installation P3 receipt remains verifiable offline', () => {
  const result = verifyP3InstallerQualification(structuredClone(receipt));
  assert.equal(result.verified, true);
  assert.equal(result.zero_residue, false);
  assert.equal(result.retained_installation, true);
  assert.equal(result.qualification_sha256, receipt.qualification_sha256);
});

test('current P3 verifier requires a retained ready installation and canonical health at both boundaries', () => {
  const candidate = structuredClone(receipt);
  candidate.schema = 'hom.aimos.p3-clean-installer-qualification/v3';
  candidate.counts = {
    ...candidate.counts,
    identities: 2,
    housekeepers: 1,
    masters: 1,
    selected_grant_clearance: 10,
    selected_grant_data_class: 'confidential',
  };
  delete candidate.disposable_cleanup;
  delete candidate.disposable_cleanup_complete;
  candidate.canonical_runtime_not_manipulated = true;
  candidate.canonical_health_before = { ready: true };
  candidate.canonical_health_after = { ready: true };
  candidate.retained_installation = {
    state_root_present: true,
    source_root_present: true,
    postgres_root_present: true,
    service_manifest_present: true,
    service_unit_present: true,
    service_loaded: true,
    postgres_port_listening: true,
    http_port_listening: true,
    credential_items_present: true,
    master_slot_present: true,
    ready: true,
  };
  candidate.retained_installation_ready = true;
  candidate.failed_attempt_cleanup = null;
  rebindContainerHashes(candidate);
  const result = verifyP3InstallerQualification(candidate);
  assert.equal(result.verified, true);
  assert.equal(result.retained_installation, true);

  candidate.retained_installation.service_loaded = false;
  rebindContainerHashes(candidate);
  assert.throws(
    () => verifyP3InstallerQualification(candidate),
    /p3_qualification_retained_installation_invalid/,
  );
});

test('offline P3 verifier denies signature substitution even with rebound container hashes', () => {
  const candidate = structuredClone(receipt);
  candidate.signed_terminal.signature = `${candidate.signed_terminal.signature[0] === 'A' ? 'B' : 'A'}${candidate.signed_terminal.signature.slice(1)}`;
  rebindContainerHashes(candidate);
  assert.throws(
    () => verifyP3InstallerQualification(candidate),
    /p3_terminal_event_invalid/,
  );
});
