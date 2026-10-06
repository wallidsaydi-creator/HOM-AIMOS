#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanCr7EffectCensus } from './prove-cr7-durable-action-census.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const FROZEN_R7_CENSUS_ROOT = '305c0048188c8f944080abd8454bbcfc1e82ea3a3b3902cbf1156e4259758859';
const FROZEN_RETAINED_EFFECT_ROOT = 'f5faabbe51ca0e42658922129eeb83fc73591ba529e0c4c335bda08eabac14d2';
const PUBLIC_R7_ARCHIVE = 'scripts/verification/fixtures/cr7-r7-public-main-678af3c.tar.gz';
const PUBLIC_R7_ARCHIVE_SHA256 = '5a878f566a00226c17722012c9092c3417889bd651bb33366427c294747f3890';
const RETIRED_IDS = Object.freeze([
  '4b82bf0049dd68d748458dadebc8c5fed9ad22539e4418045f4641220bc52dbe',
  'c825c12ee1adae3db4867d5878e84ddfefa9ac6282b1cb8bc3f29a1d4f854e9c',
]);
const ADDED_IDS = Object.freeze([
  'cba9d47c455ef8516aa0216ccd6134e52b341760f85734bb8ea292440adfea4e', // write
  '2ab0a44cbe822a534296093c7bec194501d0bda538e657bb5ccc095b26c1b7d1', // rename
  '49b19627c52f225b724b8a8085480c268a70b80cbc5208dd4599b2f81afe4480', // failed-write cleanup
  'fdffd45bf1bc74f67206b37b6e9e5f265c2f27bc93d73e27aebe6774a5979fe4', // boot orphan cleanup
]);

function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function read(relative) { return fs.readFileSync(path.join(ROOT, relative), 'utf8'); }
function assert(value, reason) { if (!value) throw new Error(`cr7_r8_successor_failed:${reason}`); }
function inOrder(source, anchors, label) {
  let after = -1;
  for (const anchor of anchors) {
    const index = source.indexOf(anchor, after + 1);
    assert(index > after, `${label}:${anchor}`);
    after = index;
  }
}

export function proveCr7R8FileWriteSuccessor() {
  assert(sha256(fs.readFileSync(path.join(ROOT, PUBLIC_R7_ARCHIVE))) === PUBLIC_R7_ARCHIVE_SHA256,
    'public_historical_fixture_changed');
  const census = scanCr7EffectCensus();
  const byId = new Map(census.effects.map((effect) => [effect.effect_id, effect]));
  assert(census.source_file_count === 366 && census.unclassified_effect_site_count === 0, 'census_totality');
  assert(census.effect_site_count === 103 - RETIRED_IDS.length + ADDED_IDS.length, 'forward_effect_count');
  for (const id of RETIRED_IDS) assert(!byId.has(id), `retired_effect_present:${id}`);
  for (const id of ADDED_IDS) {
    const effect = byId.get(id);
    assert(effect?.file === 'services/security/purpose-authorization.js'
      && effect.effect_class === 'durable_file', `new_effect_missing:${id}`);
  }
  const newIds = new Set(ADDED_IDS);
  const retained = census.effects.filter((effect) => !newIds.has(effect.effect_id))
    .map((effect) => ({
      id: effect.effect_id,
      status: effect.ownership_status,
      class: effect.effect_class,
      anchor: effect.source_anchor,
    })).sort((left, right) => left.id.localeCompare(right.id));
  assert(retained.length === 101
    && sha256(JSON.stringify(retained)) === FROZEN_RETAINED_EFFECT_ROOT,
  'historical_retained_effect_set_changed');
  assert((census.by_ownership_status.OPEN_UNRECONCILED || 0) === ADDED_IDS.length,
    'legacy_scanner_open_partition_changed');

  const native = read('services/security/purpose-authorization.js');
  const tool = read('services/orchestration/tool-registry.js');
  const boot = read('server.js');
  inOrder(tool, [
    'await verifyToolActionAuthority(options.toolActionAuthority',
    'const written = await writeAllowedLocalFile({',
  ], 'write_owner_order');
  inOrder(native, [
    'function writeAllowedLocalFileNative(',
    'fs.writeFileSync(fd, content',
    'fs.renameSync(temporary, requested)',
    'syncDirectory(parent)',
  ], 'private_write_order');
  inOrder(native, [
    'export async function writeAllowedLocalFile(',
    'await verifyToolActionAuthority(toolActionAuthority',
    'inspectAllowedLocalFileWrite({',
    'const effect = await materialEffectOwner.begin({',
    "operation: 'local_file_write'",
    'written = writeAllowedLocalFileNative({',
    "disposition: 'SUCCEEDED'",
  ], 'native_owner_order');
  assert(!native.includes('export function writeAllowedLocalFileNative')
    && !native.includes('fs.mkdirSync(')
    && native.includes('`.${path.basename(requested)}.aimos-${actionId}`'),
  'private_existing_parent_contract');
  inOrder(native, [
    'export function createLocalFileWriteOrphanReconciler(',
    "metadata.effect_operation !== 'local_file_write'",
    "materialEffectTargetHash('filesystem', target) !== start.metadata.target_sha256",
    'const verifiedStart = await verifyStartFn(start.startEventId, AIMOS_COMPANY_ID)',
    'const cleanup = await effectOwner.begin({',
    'fs.unlinkSync(candidate)',
    "disposition: 'SUCCEEDED'",
  ], 'orphan_cleanup_order');
  inOrder(boot, [
    'const verifiedRows = await readHistoryFn(AIMOS_COMPANY_ID',
    'await reconcileLocalFileWriteOrphans(open)',
    'return materialEffectOwner.reconcileOpen({ historyFn:readHistoryFn })',
    'await reconcileCr7OpenActionsAtBoot()',
    "app.listen(PORT, '127.0.0.1'",
  ], 'boot_recovery_order');

  const sourceManifest = [
    'services/security/purpose-authorization.js',
    'services/orchestration/tool-registry.js',
    'services/security/material-effect-owner.js',
    'server.js',
  ].map((file) => ({ file, sha256: sha256(read(file)) }));
  const body = {
    schema: 'hom.aimos.cr7-r8-file-write-successor/v1',
    frozen_r7_census_root_sha256: FROZEN_R7_CENSUS_ROOT,
    frozen_retained_effect_root_sha256: FROZEN_RETAINED_EFFECT_ROOT,
    public_r7_archive_sha256: PUBLIC_R7_ARCHIVE_SHA256,
    historical_effect_count: 103,
    retired_effect_ids: RETIRED_IDS,
    new_effect_ids: ADDED_IDS,
    current_effect_count: census.effect_site_count,
    current_census_root_sha256: census.effect_root_sha256,
    legacy_scanner_open_count: ADDED_IDS.length,
    successor_static_owner_pattern_count: ADDED_IDS.length,
    static_owner_order_verified: true,
    signed_native_write_qualification_executed: false,
    live_restart_qualification_executed: false,
    historical_source_gate_rebased: true,
    historical_fixture_execution_required: true,
    release_closed: false,
    source_manifest: sourceManifest,
  };
  return Object.freeze({
    ...body,
    proof_root_sha256: sha256(JSON.stringify(body)),
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(proveCr7R8FileWriteSuccessor(), null, 2));
}
