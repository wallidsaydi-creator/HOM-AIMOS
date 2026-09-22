#!/usr/bin/env node
// One-passphrase operator authorization for one pending consequential action.

import { createHash } from 'node:crypto';
import os from 'node:os';

import { agentPool, pool } from '../../db/connection.js';
import { AIMOS_SERVER_PORT } from '../../services/core/runtime-config.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { createOperatorActionAuthorizationProof } from '../../services/security/protocol/operator-action-authorization-v1.js';
import { buildConsequentialActionProjectionV1 } from '../../services/security/protocol/consequential-action-v1.js';
import { getToolApprovalRequest } from '../../services/orchestration/tool-approval-store.js';
import { getNativeToolProfile } from '../../services/orchestration/tool-registry.js';
import { decryptMasterPrivkey, KC_ACCOUNT_DEFAULT, KC_SERVICE } from './lib.js';
import { keychainGet } from './keychain.js';
import * as identityDb from './db.js';
import { readLine, readPassphrase } from './passphrase.js';

const args = process.argv.slice(2);
const approvalId = args.find((arg) => !arg.startsWith('--')) || null;
const accountArg = args.find((arg) => arg.startsWith('--keychain-account='));

if (!approvalId) {
  console.error('Usage: authorize-tool-action.js <approval_request_id> [--keychain-account=<account>]');
  process.exit(64);
}

async function main() {
  const approval = await getToolApprovalRequest(approvalId);
  if (!approval || approval.status !== 'pending') throw new Error('pending_tool_approval_required');
  const master = await identityDb.getMaster();
  const agent = await identityDb.getAgent(approval.agentId);
  if (!master || !agent) throw new Error('operator_action_identity_authority_missing');
  const nativeProfile = getNativeToolProfile(approval.tool);
  if (!nativeProfile.profile.action_authority) throw new Error('tool_is_not_consequential');
  const projection = buildConsequentialActionProjectionV1({
    tool: approval.tool,
    args: approval.args || {},
    profile: nativeProfile.profile,
  });
  const osUser = String(os.userInfo().username || '').trim() || null;
  const keychainService = master.keychain_service || KC_SERVICE;
  const keychainAccount = accountArg?.split('=').slice(1).join('=')
    || master.keychain_account || KC_ACCOUNT_DEFAULT
    || await readLine('Keychain account name', { default: osUser });
  const blob = await keychainGet(keychainService, keychainAccount);
  if (!blob) throw new Error('master_keychain_missing');
  const passphrase = await readPassphrase('Master passphrase: ');
  const masterPrivkeyB64u = decryptMasterPrivkey(passphrase, blob);
  if (!masterPrivkeyB64u) throw new Error('wrong_passphrase_or_tampered_keychain_blob');
  const proof = createOperatorActionAuthorizationProof(masterPrivkeyB64u, {
    company_id: 'hom',
    subject_agent_id: approval.agentId,
    subject_valid_from: new Date(agent.valid_from).toISOString(),
    subject_cert_fingerprint_sha256: createHash('sha256')
      .update(String(agent.cert), 'utf8').digest('hex'),
    approval_request_id: approval.id,
    approval_request_mutation_sha256: approval.requestMutationHash,
    tool_name: approval.tool,
    action_scope: projection.action_scope,
    risk_class: projection.risk_class,
    arguments_sha256: approval.argsHash,
    security_value_sha256: projection.value_sha256,
    master_fingerprint: master.fingerprint,
  });
  const requestPath = `/tools/approvals/${approval.id}/approve`;
  const body = { operator_proof: proof };
  const headers = await buildEnvelopeHeaders(approval.agentId, 'POST', requestPath, body);
  const response = await fetch(`http://127.0.0.1:${AIMOS_SERVER_PORT}${requestPath}`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok || result?.success !== true) {
    throw new Error(`operator_action_authorization_failed:${response.status}:${JSON.stringify(result)}`);
  }
  console.log(JSON.stringify({
    success: true,
    status: 'OPERATOR_ACTION_AUTHORIZED_AND_EXECUTED',
    approval_request_id: approval.id,
    proof_sha256: proof.proof_sha256,
    tool: approval.tool,
    result: result.result,
  }, null, 2));
}

main().catch((error) => {
  console.error('[ERR]', error?.message || error);
  process.exitCode = 1;
}).finally(async () => {
  try { await pool.end(); } catch {}
  try { await agentPool.end(); } catch {}
});
