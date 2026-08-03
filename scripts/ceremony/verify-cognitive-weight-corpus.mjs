#!/usr/bin/env node

import { agentPool, pool } from '../../db/connection.js';
import { AIMOS_COMPANY_ID, resolveAimosDatabaseName } from '../../services/core/runtime-config.js';
import { verifyCognitiveWeightCorpus } from '../../services/security/cognitive-weight-verifier.js';

const companyArg = process.argv.find((arg) => arg.startsWith('--company-id='));
const companyId = companyArg ? companyArg.slice('--company-id='.length).trim() : AIMOS_COMPANY_ID;
if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(companyId)) {
  throw new Error('cognitive_company_id_invalid');
}

try {
  const proof = await verifyCognitiveWeightCorpus({ companyId });
  const states = Object.values(proof.records.reduce((acc, row) => {
    const key = row.certification_status;
    acc[key] ||= { certification_status: key, count: 0, valid: 0 };
    acc[key].count += 1;
    if (row.ok) acc[key].valid += 1;
    return acc;
  }, {})).sort((a, b) => a.certification_status.localeCompare(b.certification_status));
  const rejected = proof.records.filter((row) => !row.ok);
  console.log(JSON.stringify({
    database: resolveAimosDatabaseName(),
    company_id: companyId,
    total: proof.records.length,
    verified: proof.records.length - rejected.length,
    rejected,
    sql_portable_parity: proof.parity,
    cognitive_corpus_proof_root: proof.proofRoot.toString('hex'),
    states,
  }, null, 2));
  if (rejected.length || !proof.parity) process.exitCode = 1;
} finally {
  await Promise.allSettled([agentPool.end(), pool.end()]);
}
