import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { verifyGenesisManifest } from '../../scripts/verify-genesis-manifest.mjs';
import { isPublisherVerifiedGenesisGuide } from '../../services/write/persist-memory.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function fixture(identityTier = 'T1') {
  const manifest = verifyGenesisManifest({ brainRoot: ROOT });
  const record = manifest.files.find((entry) => entry.path === 'Guide/aimos-llm-guide.md');
  const value = fs.readFileSync(path.join(ROOT, record.path), 'utf8');
  return {
    authority: {
      kind: 'verified_request',
      agentId: 'housekeeper',
      identityTier,
      body: {
        genesis_manifest_schema: manifest.schema,
        genesis_manifest_version: manifest.version,
        genesis_corpus_root: manifest.corpusRoot,
        genesis_file_path: record.path,
        genesis_file_sha256: record.sha256,
        genesis_file_bytes: record.bytes,
      },
    },
    companyId: 'hom',
    agentId: 'housekeeper',
    key: 'guide:housekeeper:aimos-llm-guide',
    value,
    source: 'guide:genesis-install',
  };
}

test('master-signed T1 housekeeper remains a manifest-bound Genesis Guide publisher', () => {
  assert.equal(isPublisherVerifiedGenesisGuide(fixture('T1')), true);
});

test('legacy self-signed system housekeeper remains a manifest-bound Genesis Guide publisher', () => {
  assert.equal(isPublisherVerifiedGenesisGuide(fixture('T1_SYSTEM_SELF')), true);
});

test('ordinary T1 agent cannot inherit Genesis Guide publisher authority', () => {
  const input = fixture('T1');
  input.authority.agentId = 'ordinary-t1-agent';
  assert.equal(isPublisherVerifiedGenesisGuide(input), false);
});

test('manifest-bound publisher authority fails closed on content drift', () => {
  const input = fixture('T1');
  input.value += '\nunauthorized drift';
  assert.equal(isPublisherVerifiedGenesisGuide(input), false);
});
