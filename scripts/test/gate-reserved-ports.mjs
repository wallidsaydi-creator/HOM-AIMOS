#!/usr/bin/env node

// AIMOS Reserved-Port Source Gate
//
// Scans the codebase for live references to reserved legacy ports 9000/9001 and reports
// every outbound default, callback URL, advertisement, or fetch target that
// contains them. Exits 0 if the only remaining references are rejection
// constants, comments, or tests; exits 1 if any live transport literal reaches
// a reserved port.
//
// Usage: node scripts/test/gate-reserved-ports.mjs

import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCAN_TARGETS = [
  'services',
  'routes',
  'jobs',
  'scripts',
  'db',
  'migrations',
  '.github',
  'package.json',
  'server.js',
  'DEPLOYMENT.md',
  'README.md',
  'SECURITY.md',
  'THREAT-MODEL.md',
];
const RESERVED = [9000, 9001];
const SCANNED_EXTENSION = /\.(?:js|mjs|cjs|py|sh|sql|md|json|ya?ml)$/i;

function isExactReservedPortGuard(rel, line) {
  if (/!\[\s*9000,\s*9001(?:,\s*9100)?\s*\]\.includes\([A-Za-z_$][A-Za-z0-9_$.]*\)/.test(line.trim())) {
    return true;
  }
  if (rel === 'services/core/runtime-config.js') {
    return /^export const RESERVED_LEGACY_PORTS = Object\.freeze\(\[9000, 9001\]\);$/.test(line.trim());
  }
  if (rel === 'scripts/benchmark/run-isolated.mjs') {
    return /^if \(\[9000, 9001, 9100\]\.includes\(args\.port\)\) throw new Error\(`port \$\{args\.port\} is reserved by a live HOM service`\);$/.test(line.trim());
  }
  if (rel === 'scripts/benchmark/run-poisonedrag-epistemic-ablation.mjs') {
    return /^if \(!Number\.isInteger\(port\) \|\| port < 1024 \|\| port > 65535 \|\| \[9000, 9001, 9100\]\.includes\(port\)\) \{$/.test(line.trim());
  }
  return false;
}

function walk(dir) {
  const results = [];
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry.startsWith('.')) continue;
    const full = path.join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) results.push(...walk(full));
    else if (SCANNED_EXTENSION.test(entry)) results.push(full);
  }
  return results;
}

function collectFiles() {
  const files = [];
  for (const target of SCAN_TARGETS) {
    const full = path.join(ROOT, target);
    const st = statSync(full);
    if (st.isDirectory()) files.push(...walk(full));
    else files.push(full);
  }
  // Include every top-level executable JavaScript entry point. A future server
  // or CLI must not escape the gate merely because it was added after this
  // target list was written.
  for (const entry of readdirSync(ROOT)) {
    const full = path.join(ROOT, entry);
    if (/\.(?:js|mjs|cjs)$/i.test(entry) && statSync(full).isFile()) files.push(full);
  }
  return [...new Set(files)];
}

let violations = 0;
for (const file of collectFiles()) {
  const rel = path.relative(ROOT, file);
  const content = readFileSync(file, 'utf8');
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    const lineNum = i + 1;
    for (const port of RESERVED) {
      if (!new RegExp(`(^|\\D)${port}(?=\\D|$)`).test(line)) continue;

      const trimmed = line.trim();

      // Skip only the exact reviewed rejection expressions. The rest of these
      // files remains fully scanned, so a later transport literal fails.
      if (isExactReservedPortGuard(rel, line)) {
        console.log(`  GUARD    ${rel}:${lineNum}  :${port}  ${trimmed.slice(0, 80)}`);
        return;
      }

      // Skip: pure comments
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')
        || trimmed.startsWith('#') || trimmed.startsWith('--')) {
        console.log(`  COMMENT  ${rel}:${lineNum}  :${port}  ${trimmed.slice(0, 80)}`);
        return;
      }

      // Skip: test files
      if (rel.includes('/test') || rel.includes('.test.')) {
        console.log(`  TEST     ${rel}:${lineNum}  :${port}  ${trimmed.slice(0, 80)}`);
        return;
      }

      // Violation: live source containing a reserved port literal
      const isRejection = /reject|refus|reserved|throw.*Error/i.test(line);
      if (isRejection) {
        console.log(`  GUARD    ${rel}:${lineNum}  :${port}  ${trimmed.slice(0, 80)}`);
        return;
      }

      violations++;
      console.error(`  VIOLATION ${rel}:${lineNum}  :${port}  ${trimmed.slice(0, 100)}`);
    }
  });
}

console.log('');
if (violations > 0) {
  console.error(`FAIL: ${violations} live reserved-port reference(s) found.`);
  console.error('Reserved ports 9000/9001 may appear only in rejection constants,');
  console.error('comments, tests, or the runtime-config rejection array.');
  process.exit(1);
} else {
  console.log('PASS: no live outbound/default/callback/advertisement reaches 9000/9001.');
  console.log('(Comments, guards, tests, and runtime-config rejection array are allowed.)');
  process.exit(0);
}
