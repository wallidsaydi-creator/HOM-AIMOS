#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_ROOT = path.resolve(SCRIPT_DIR, '..', '..');

export function collectServiceCensus(root = DEFAULT_ROOT) {
  const servicesRoot = path.join(root, 'services');
  const groups = {};
  const files = [];

  for (const entry of fs.readdirSync(servicesRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    const groupFiles = fs.readdirSync(path.join(servicesRoot, entry.name), { withFileTypes: true })
      .filter((item) => item.isFile() && item.name.endsWith('.js') && item.name !== 'index.js')
      .map((item) => item.name)
      .sort();
    if (groupFiles.length === 0) continue;
    groups[entry.name] = groupFiles;
    for (const file of groupFiles) files.push(`services/${entry.name}/${file}`);
  }

  files.sort();
  return {
    groups,
    files,
    groupCount: Object.keys(groups).length,
    serviceCount: files.length,
    digest: createHash('sha256').update(files.join('\n') + '\n').digest('hex'),
  };
}

export function synchronizeManifest(root = DEFAULT_ROOT) {
  const manifestPath = path.join(root, 'hom-architecture-manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const census = collectServiceCensus(root);
  const priorGroups = manifest.service_inventory?.groups || {};

  const groups = {};
  for (const [name, groupFiles] of Object.entries(census.groups)) {
    groups[name] = {
      layer: priorGroups[name]?.layer || name,
      path: `services/${name}/`,
      services: groupFiles.length,
      files: groupFiles,
    };
  }

  manifest.updated = new Date().toISOString().slice(0, 10);
  manifest.total_services = census.serviceCount;
  delete manifest.aimos_memories;
  manifest.runtime_data_authority = 'Live PostgreSQL ledgers; no installation-specific row count is canonical in this public manifest.';
  manifest.service_inventory = {
    service_groups: census.groupCount,
    counted_service_files: census.serviceCount,
    census_sha256: census.digest,
    counting_policy: {
      counted: 'top-level services/<group>/*.js excluding index.js barrels and hidden directories',
      excluded_root_infrastructure_files: fs.readdirSync(path.join(root, 'services'), { withFileTypes: true })
        .filter((item) => item.isFile() && item.name.endsWith('.js'))
        .map((item) => `services/${item.name}`)
        .sort(),
    },
    groups,
  };

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  return { manifestPath, census };
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : '';
if (import.meta.url === invokedPath) {
  const rootArg = process.argv.find((arg) => arg.startsWith('--brain-root='));
  const root = rootArg ? path.resolve(rootArg.slice('--brain-root='.length)) : DEFAULT_ROOT;
  const { manifestPath, census } = synchronizeManifest(root);
  console.log(`[OK] synchronized ${manifestPath}`);
  console.log(`     groups: ${census.groupCount}`);
  console.log(`     services: ${census.serviceCount}`);
  console.log(`     census_sha256: ${census.digest}`);
}
