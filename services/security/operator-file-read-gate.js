// Admission for the one-file operator route. The production adapter supplies
// the verified exact-epoch grant; tests can exercise this boundary without
// starting a database or model runtime.

import path from 'node:path';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';

export async function inspectOperatorFileReadRequest({
  authority,
  requestAgentId,
  operatorAgentId,
  originalUrl,
  body,
  getGrant,
}) {
  const actor = String(authority?.actorAgentId || '');
  const operator = String(operatorAgentId || '');
  if (!actor || !operator || actor !== String(requestAgentId || '')
      || actor.toLowerCase() !== operator.toLowerCase()
      || authority?.companyId !== AIMOS_COMPANY_ID
      || authority?.authSource !== 'envelope' || authority?.identityTier !== 'T1'
      || !Number.isFinite(Date.parse(authority?.actorValidFromIso))
      || authority?.signedMethod !== 'POST'
      || authority?.signedPath !== '/tools/files/read'
      || originalUrl !== '/tools/files/read'
      || !authority?.requestReceiptId
      || !/^[0-9a-f]{64}$/.test(String(authority?.requestReceiptMutationHash || ''))) {
    return { ok: false, status: 403, error: 'operator_agent_required' };
  }
  const filepath = body?.filepath;
  const purposeAuthorization = body?.purpose_authorization;
  if (!body || Array.isArray(body)
      || Object.keys(body).sort().join(',') !== 'filepath,purpose_authorization'
      || typeof filepath !== 'string' || !path.isAbsolute(filepath)
      || path.resolve(filepath) !== filepath
      || !purposeAuthorization || typeof purposeAuthorization !== 'object'
      || Array.isArray(purposeAuthorization)) {
    return { ok: false, status: 400, error: 'filepath_and_purpose_authorization_required' };
  }
  if (purposeAuthorization.body?.company_id !== authority.companyId
      || purposeAuthorization.body?.subject_agent_id !== actor
      || Date.parse(purposeAuthorization.body?.subject_valid_from)
        !== Date.parse(authority.actorValidFromIso)
      || purposeAuthorization.body?.target_file !== filepath) {
    return { ok: false, status: 403, error: 'local_file_scope_mismatch' };
  }
  let grant;
  try {
    grant = await getGrant({
      companyId: authority.companyId,
      subjectAgentId: actor,
      subjectValidFrom: authority.actorValidFromIso,
    });
  } catch {
    return { ok: false, status: 503, error: 'local_file_authorization_unavailable' };
  }
  if (!grant?.allowed || !Number.isInteger(grant.clearanceCeiling)
      || grant.clearanceCeiling < 3 || grant.clearanceCeiling > 12) {
    return { ok: false, status: 403, error: 'local_file_clearance_required' };
  }
  return {
    ok: true,
    actor,
    filepath,
    purposeAuthorization,
    clearanceLevel: grant.clearanceCeiling,
  };
}
