#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  evaluateMutMemReproducibilityAssessment,
} from '../../services/security/protocol/mutmem-reproducibility-contract.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const file = path.join(ROOT, 'eval', 'publication', 'mutmem-v1-reproducibility-assessment.json');
const assessment = JSON.parse(readFileSync(file, 'utf8'));
const result = evaluateMutMemReproducibilityAssessment(assessment);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (process.argv.includes('--require-v2-ready') && !result.v2_release_ready) {
  process.exitCode = 2;
}
