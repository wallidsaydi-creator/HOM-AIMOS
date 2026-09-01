#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  MUTMEM_RECALL_RESULT_KINDS_V2,
  MUTMEM_RECALL_SINGLETON_KINDS_V2,
} from '../../services/security/protocol/mutmem-portable-evidence-v2.js';
import {
  MUTMEM_PORTABLE_DOMAIN_HEX_V2,
  MUTMEM_PORTABLE_OBJECT_SCHEMAS_V2,
  MUTMEM_PORTABLE_PREDICATE_CODES_V2,
  evaluateMutMemPortablePredicatesV2,
} from '../../services/security/protocol/mutmem-portable-predicates-v2.js';
import {
  MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2,
  MUTMEM_PORTABLE_MUTATION_V2,
  evaluateMutMemPortableMutationBundleV2,
} from '../../services/security/protocol/mutmem-portable-mutation-v2.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'verifiers/mutmem-conformance/v2');
const VECTOR_FILE = path.join(OUTPUT, 'vectors.json');
const MUTATION_VECTOR_FILE = path.join(OUTPUT, 'mutation-vectors.json');
const LIVE_EVENT_ID = '10217fc3-2c04-418c-8f8f-61346e29a88b';
const PRIVATE_LIVE_FILE = path.join(
  ROOT,
  'artifacts/security/mutmem-v2/p1-live-projection',
  `${LIVE_EVENT_ID}.json`,
);
const PRIVATE_MUTATION_FILE = path.join(
  ROOT,
  'artifacts/security/mutmem-v2/p1-live-mutation/64e723e3cae6c1bbdcdb7b0d.json',
);
const LIVE_OUTPUT = path.join(OUTPUT, 'live-projection.json');
const LIVE_MUTATION_OUTPUT = path.join(OUTPUT, 'live-mutation-projections.json');
const MANIFEST_OUTPUT = path.join(OUTPUT, 'protocol-manifest.json');
const SOURCE_FILES = Object.freeze([
  'services/security/protocol/canonical-json.js',
  'services/security/protocol/mutmem-protocol.js',
  'services/security/protocol/content-state-occurrence-v3.js',
  'services/security/protocol/mutmem-portable-evidence-v2.js',
  'services/security/protocol/mutmem-portable-predicates-v2.js',
  'services/security/protocol/mutmem-portable-mutation-v2.js',
  'scripts/verification/mutmem-portable-predicate-fixture-factory.mjs',
  'scripts/verification/generate-mutmem-portable-predicate-vectors.mjs',
  'scripts/verification/mutmem-portable-mutation-fixture-factory.mjs',
  'scripts/verification/generate-mutmem-portable-mutation-vectors.mjs',
  'scripts/verification/generate-mutmem-p1-protocol-manifest.mjs',
  'scripts/verification/prove-mutmem-p1-live-projection.mjs',
  'scripts/verification/prove-mutmem-p1-live-mutation-projection.mjs',
]);

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function json(file) {
  return JSON.parse(await readFile(file, 'utf8'));
}

async function writeGenerated(file, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  const fileHash = sha(bytes);
  const temporary = `${file}.tmp-${process.pid}`;
  const hashFile = `${file}.sha256`;
  const hashTemporary = `${hashFile}.tmp-${process.pid}`;
  await writeFile(temporary, bytes, { mode: 0o644 });
  await writeFile(hashTemporary, `${fileHash}  ${path.basename(file)}\n`, { mode: 0o644 });
  await rename(temporary, file);
  await rename(hashTemporary, hashFile);
  return fileHash;
}

async function main() {
  const [vectors, mutationVectors, privateBytes, privateArtifact,
    privateMutationBytes, privateMutationArtifact] = await Promise.all([
    json(VECTOR_FILE),
    json(MUTATION_VECTOR_FILE),
    readFile(PRIVATE_LIVE_FILE),
    json(PRIVATE_LIVE_FILE),
    readFile(PRIVATE_MUTATION_FILE),
    json(PRIVATE_MUTATION_FILE),
  ]);
  const privateArtifactSha256 = sha(privateBytes);
  const bundle = privateArtifact.bundle;
  const reference = evaluateMutMemPortablePredicatesV2(bundle);
  if (reference.valid !== true || bundle.bundle_id !== `P1-LIVE-${LIVE_EVENT_ID}`) {
    throw new Error('p1_protocol_live_projection_invalid');
  }
  const occurrence = bundle.objects.find((object) => object.kind === 'occurrence');
  const liveUnsigned = {
    schema: 'hom.aimos.mutmem-p1-live-projection-public/v1',
    event_id: LIVE_EVENT_ID,
    bundle_sha256: bundle.bundle_sha256,
    object_root_sha256: bundle.object_root_sha256,
    result_count: bundle.result_count,
    object_count: bundle.object_count,
    occurrence_form: occurrence?.body?.occurrence_form || null,
    reference_predicates_valid: true,
    predicate_count: MUTMEM_PORTABLE_PREDICATE_CODES_V2.length,
    private_artifact_sha256: privateArtifactSha256,
    private_artifact_distributed: false,
    memory_write: false,
    domain_database_mutation: false,
  };
  const live = {
    ...liveUnsigned,
    manifest_sha256: sha(Buffer.from(canonicalJson(liveUnsigned), 'utf8')),
  };
  await mkdir(OUTPUT, { recursive: true });
  const liveFileSha256 = await writeGenerated(LIVE_OUTPUT, live);

  const mutationProjections = privateMutationArtifact.projections || [];
  if (mutationProjections.length !== 3) throw new Error('p1_protocol_live_mutation_count_invalid');
  for (const projection of mutationProjections) {
    const result = evaluateMutMemPortableMutationBundleV2(projection.bundle);
    if (result.valid !== true) throw new Error('p1_protocol_live_mutation_invalid');
  }
  const liveMutationUnsigned = {
    schema: 'hom.aimos.mutmem-p1-live-mutation-public/v1',
    terminal_kinds: mutationProjections.map((entry) => entry.result.terminal_kind),
    bundle_sha256s: mutationProjections.map((entry) => entry.bundle.bundle_sha256),
    valence_row_ids: mutationProjections.map((entry) => entry.valence_row_id),
    private_artifact_sha256: sha(privateMutationBytes),
    private_artifact_distributed: false,
    memory_write: false,
    domain_database_mutation: false,
  };
  const liveMutation = {
    ...liveMutationUnsigned,
    manifest_sha256: sha(Buffer.from(canonicalJson(liveMutationUnsigned), 'utf8')),
  };
  const liveMutationFileSha256 = await writeGenerated(
    LIVE_MUTATION_OUTPUT,
    liveMutation,
  );

  const sources = await Promise.all(SOURCE_FILES.map(async (relative) => ({
    path: relative,
    sha256: sha(await readFile(path.join(ROOT, relative))),
  })));
  const sourceRootSha256 = sha(Buffer.from(canonicalJson(sources), 'utf8'));
  const unsigned = {
    schema: 'hom.aimos.mutmem-portable-protocol-manifest/v2',
    version: 2,
    status: 'p1_protocol_versioned',
    canonicalization: 'hom-aimos/canonical-json/v1',
    hash: 'sha256',
    signature: 'ed25519',
    external_trust_root_required: true,
    authority_profiles: ['master_signed_recall_grant', 'housekeeper_system_principal'],
    schemas: MUTMEM_PORTABLE_OBJECT_SCHEMAS_V2,
    domain_hex: MUTMEM_PORTABLE_DOMAIN_HEX_V2,
    singleton_order: MUTMEM_RECALL_SINGLETON_KINDS_V2,
    result_object_order: MUTMEM_RECALL_RESULT_KINDS_V2,
    object_count_formula: '13 + 5 * result_count',
    maximum_result_count: 200,
    failure_codes: MUTMEM_PORTABLE_PREDICATE_CODES_V2,
    vectors: {
      schema: vectors.schema,
      intended_n: vectors.intended_n,
      valid_n: vectors.valid_n,
      invalid_n: vectors.invalid_n,
      vectors_root_sha256: vectors.vectors_root_sha256,
      manifest_sha256: vectors.manifest_sha256,
      file_sha256: sha(await readFile(VECTOR_FILE)),
    },
    live_projection: {
      schema: live.schema,
      event_id: live.event_id,
      bundle_sha256: live.bundle_sha256,
      object_root_sha256: live.object_root_sha256,
      manifest_sha256: live.manifest_sha256,
      file_sha256: liveFileSha256,
      private_artifact_sha256: live.private_artifact_sha256,
      private_artifact_distributed: false,
    },
    mutation_profile: {
      schema: MUTMEM_PORTABLE_MUTATION_V2.schema,
      native_outcome_schema: MUTMEM_PORTABLE_MUTATION_V2.native_outcome_schema,
      domain_hex: MUTMEM_PORTABLE_MUTATION_V2.domain.toString('hex'),
      terminal_kinds: MUTMEM_PORTABLE_MUTATION_V2.terminal_kinds,
      failure_codes: MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2,
      vectors: {
        schema: mutationVectors.schema,
        intended_n: mutationVectors.intended_n,
        valid_n: mutationVectors.valid_n,
        invalid_n: mutationVectors.invalid_n,
        vectors_root_sha256: mutationVectors.vectors_root_sha256,
        manifest_sha256: mutationVectors.manifest_sha256,
        file_sha256: sha(await readFile(MUTATION_VECTOR_FILE)),
      },
      live_projection: {
        schema: liveMutation.schema,
        terminal_kinds: liveMutation.terminal_kinds,
        bundle_sha256s: liveMutation.bundle_sha256s,
        manifest_sha256: liveMutation.manifest_sha256,
        file_sha256: liveMutationFileSha256,
        private_artifact_sha256: liveMutation.private_artifact_sha256,
        private_artifact_distributed: false,
      },
    },
    source_files: sources,
    source_root_sha256: sourceRootSha256,
    production_runtime_importers: 0,
    memory_write: false,
    domain_database_mutation: false,
    independent_crypto_verification_owner: 'P2',
  };
  const manifest = {
    ...unsigned,
    protocol_root_sha256: sha(Buffer.from(canonicalJson(unsigned), 'utf8')),
  };
  const manifestFileSha256 = await writeGenerated(MANIFEST_OUTPUT, manifest);
  console.log(JSON.stringify({
    success: true,
    protocol_root_sha256: manifest.protocol_root_sha256,
    manifest_file_sha256: manifestFileSha256,
    source_root_sha256: sourceRootSha256,
    vector_root_sha256: manifest.vectors.vectors_root_sha256,
    mutation_vector_root_sha256: manifest.mutation_profile.vectors.vectors_root_sha256,
    live_bundle_sha256: manifest.live_projection.bundle_sha256,
    schema_count: Object.keys(manifest.schemas).length,
    failure_code_count: manifest.failure_codes.length,
  }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error.message}`);
  process.exitCode = 1;
});
