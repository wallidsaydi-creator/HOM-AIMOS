import { agentPool } from '../../db/connection.js';
import { credentialLedger } from '../security/credential-ledger.js';
import { refreshCachedCredential } from '../security/credential-cache.js';
import {
  credentialSlotId,
  readCredential,
  storeCredential,
} from '../security/credential-store.js';
import { signAsHousekeeper } from '../security/housekeeper-signer.js';
import { canonicalJson } from '../security/agent-identity.js';
import { readVerifiedEventById } from '../observe/event-ledger.js';

export const IDENTITY_VAULT_CLUSTER_ID = 'identity_vault.auth';
export const IDENTITY_VAULT_NAMESPACE = 'identity_vault';
export const MYSORE_MVS_THRESHOLD = 0.42;

function normalizeProvider(provider) {
  const value = String(provider || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)) {
    throw new Error('Provider is required for identity vault append');
  }
  return value;
}

function normalizeProviderList(provider, aliases = []) {
  const values = [provider, ...aliases]
    .map((value) => String(value || '').trim().toLowerCase())
    .filter((value) => /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value));
  return [...new Set(values)];
}

function tokenService(provider, kind) {
  return `oauth_${normalizeProvider(provider)}_${kind}_token`;
}

function normalizeVaultMetadata(metadata) {
  const value = metadata == null ? {} : metadata;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Identity vault metadata must be an object');
  }
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded, 'utf8') > 16 * 1024) {
    throw new Error('Identity vault metadata exceeds 16 KiB');
  }
  const forbidden = /(^|_)(access_token|refresh_token|token|secret|password|credential|authorization)($|_)/i;
  const inspect = (node) => {
    if (Array.isArray(node)) return node.forEach(inspect);
    if (!node || typeof node !== 'object') return;
    for (const [key, child] of Object.entries(node)) {
      if (forbidden.test(key)) throw new Error(`Identity vault metadata contains forbidden secret field: ${key}`);
      inspect(child);
    }
  };
  inspect(value);
  return JSON.parse(encoded);
}

function normalizeCredentialUseEvidence(evidence) {
  if (evidence == null) return [];
  if (!Array.isArray(evidence)) throw new Error('credentialUseEvidence must be an array');
  return evidence.map((entry) => {
    const useId = String(entry?.useId || '').trim();
    const terminalProvenanceId = String(entry?.terminalProvenanceId || '').trim();
    const terminalMutationHash = String(entry?.terminalMutationHash || '').trim().toLowerCase();
    if (!useId || !terminalProvenanceId || !/^[0-9a-f]{64}$/.test(terminalMutationHash)) {
      throw new Error('Identity vault credential-use evidence is malformed');
    }
    return Object.freeze({ use_id: useId, terminal_provenance_id: terminalProvenanceId, terminal_mutation_hash: terminalMutationHash });
  });
}

async function verifyCredentialUseEvidence(evidence, provider, initiatingSubjectAgentId, companyId) {
  const normalized = normalizeCredentialUseEvidence(evidence);
  const verified = await Promise.all(normalized.map(async (entry) => {
    const row = await credentialLedger.getLifecycleRow(entry.terminal_provenance_id);
    const body = row && (typeof row.body_json === 'string' ? JSON.parse(row.body_json) : row.body_json);
    if (
      !row
      || row.event_type !== 'USE_COMPLETED'
      || body?.use_id !== entry.use_id
      || Buffer.from(row.mutation_hash || []).toString('hex') !== entry.terminal_mutation_hash
    ) {
      throw new Error('Identity vault credential-use evidence is not a verified completion');
    }
    const reservation = await credentialLedger.getLifecycleRow(body.reservation_provenance_id);
    const reservationBody = reservation
      && (typeof reservation.body_json === 'string' ? JSON.parse(reservation.body_json) : reservation.body_json);
    const requestAuthorityComplete = reservationBody?.authority_kind === 'housekeeper_observation_of_verified_request'
      && typeof reservationBody.request_receipt_id === 'string'
      && /^[0-9a-f]{64}$/.test(String(reservationBody.request_receipt_mutation_hash || ''))
      && typeof reservationBody.request_admission_event_id === 'string'
      && /^[0-9a-f]{64}$/.test(String(reservationBody.request_admission_mutation_hash || ''));
    const autonomousAuthorityComplete = reservationBody?.authority_kind === 'housekeeper_autonomous'
      && reservationBody.subject_agent_id === 'housekeeper'
      && reservationBody.request_receipt_id == null
      && reservationBody.request_admission_event_id == null;
    if (
      !reservation
      || reservation.event_type !== 'USE_RESERVED'
      || reservationBody?.use_id !== entry.use_id
      || reservationBody?.reservation_mutation_hash != null
      || Buffer.from(reservation.mutation_hash || []).toString('hex') !== body.reservation_mutation_hash
      || reservation.service_name !== row.service_name
      || reservation.slot_id !== row.slot_id
      || reservationBody?.credential_hash !== body.credential_hash
      || reservationBody?.subject_agent_id !== body.subject_agent_id
      || typeof reservationBody?.autonomous_action_event_id !== 'string'
      || !/^[0-9a-f]{64}$/.test(String(reservationBody?.autonomous_action_mutation_hash || ''))
      || (!requestAuthorityComplete && !autonomousAuthorityComplete)
    ) {
      throw new Error('Identity vault credential-use reservation evidence is invalid');
    }
    const authorityEvent = await readVerifiedEventById(
      reservationBody.autonomous_action_event_id,
      companyId,
    );
    const authorityMetadata = typeof authorityEvent.metadata === 'string'
      ? JSON.parse(authorityEvent.metadata)
      : authorityEvent.metadata;
    if (
      authorityEvent.operation !== 'credential_use_authorized'
      || String(authorityEvent.key) !== entry.use_id
      || Buffer.from(authorityEvent.mutation_hash || []).toString('hex')
        !== reservationBody.autonomous_action_mutation_hash
      || authorityMetadata?.credential_use_id !== entry.use_id
      || authorityMetadata?.service !== reservation.service_name
      || authorityMetadata?.slot_id !== reservation.slot_id
      || authorityMetadata?.credential_hash !== reservationBody.credential_hash
      || String(authorityMetadata?.effective_provenance_id) !== String(reservationBody.effective_provenance_id)
      || authorityMetadata?.effective_mutation_hash !== reservationBody.effective_mutation_hash
      || authorityMetadata?.operation !== reservationBody.operation
      || authorityMetadata?.endpoint !== reservationBody.endpoint
      || authorityMetadata?.request_hash !== reservationBody.request_hash
      || authorityMetadata?.subject_agent_id !== reservationBody.subject_agent_id
    ) {
      throw new Error('Identity vault credential-use exact authority event is invalid');
    }
    return Object.freeze({
      ...entry,
      reservation_provenance_id: String(reservation.provenance_id),
      reservation_mutation_hash: Buffer.from(reservation.mutation_hash).toString('hex'),
      service: reservation.service_name,
      operation: reservationBody.operation,
      endpoint: reservationBody.endpoint,
      use_group_id: reservationBody.use_group_id || null,
      subject_agent_id: reservationBody.subject_agent_id,
      request_hash: reservationBody.request_hash,
      request_receipt_id: reservationBody.request_receipt_id || null,
      request_receipt_mutation_hash: reservationBody.request_receipt_mutation_hash || null,
      request_admission_event_id: reservationBody.request_admission_event_id || null,
      request_admission_mutation_hash: reservationBody.request_admission_mutation_hash || null,
      parent_action_event_id: reservationBody.parent_action_event_id || null,
      outcome_hash: body.outcome_hash,
    });
  }));
  if (!verified.length) return verified;
  if (new Set(verified.map((entry) => entry.use_id)).size !== verified.length) {
    throw new Error('Identity vault credential-use evidence contains duplicate uses');
  }
  if (provider !== 'google' || verified.length !== 2) {
    throw new Error('Identity vault credential-use evidence is unsupported for this provider');
  }
  const groups = new Set(verified.map((entry) => entry.use_group_id));
  const subjects = new Set(verified.map((entry) => entry.subject_agent_id));
  const causalAuthorities = new Set(verified.map((entry) => canonicalJson({
    request_hash: entry.request_hash,
    request_receipt_id: entry.request_receipt_id,
    request_receipt_mutation_hash: entry.request_receipt_mutation_hash,
    request_admission_event_id: entry.request_admission_event_id,
    request_admission_mutation_hash: entry.request_admission_mutation_hash,
    parent_action_event_id: entry.parent_action_event_id,
  })));
  const outcomes = new Set(verified.map((entry) => entry.outcome_hash));
  const expected = new Set([
    'oauth_google_refresh_token\0google.oauth.refresh.refresh_token',
    'google_client_secret\0google.oauth.refresh.client_secret',
  ]);
  const actual = new Set(verified.map((entry) => `${entry.service}\0${entry.operation}`));
  if (
    groups.size !== 1
    || groups.has(null)
    || subjects.size !== 1
    || !subjects.has(initiatingSubjectAgentId)
    || causalAuthorities.size !== 1
    || outcomes.size !== 1
    || [...verified].some((entry) => entry.endpoint !== 'https://oauth2.googleapis.com/token')
    || expected.size !== actual.size
    || [...expected].some((entry) => !actual.has(entry))
  ) {
    throw new Error('Identity vault Google refresh evidence is not the exact credential pair');
  }
  return verified;
}

export function computeMysoreMvs(markovMse, humanMse) {
  const machine = Number(markovMse);
  const human = Number(humanMse);
  if (!Number.isFinite(machine) || !Number.isFinite(human) || human <= 0) return 0;
  return 1 - (machine / human);
}

async function prepareToken(provider, kind, value) {
  if (value == null || value === '') return null;
  const service = tokenService(provider, kind);
  const stored = await storeCredential(service, value);
  return { service, ...stored };
}

async function commitTokenLifecycle(client, prepared, provider, kind, companyId, vaultBinding) {
  if (!prepared) return null;

  await client.query(
    'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
    [`identity-vault:${companyId}:${prepared.slot}`]
  );
  const verified = await credentialLedger.readVerifiedSlotChain(prepared.slot, client);
  const effective = verified.effectiveStore || null;
  const effectiveBody = effective
    ? (typeof effective.body_json === 'string' ? JSON.parse(effective.body_json) : effective.body_json)
    : null;
  const previousStore = [...verified.rows]
    .reverse()
    .find((row) => row.event_type === 'STORE' || row.event_type === 'ROTATE') || null;
  if (
    effective
    && effectiveBody?.credential_hash === prepared.hash
    && canonicalJson(effectiveBody?.identity_vault || null) === canonicalJson({
      namespace: IDENTITY_VAULT_NAMESPACE,
      company_id: companyId,
      provider,
      credential_kind: kind,
      expires_at: vaultBinding.expiresAt,
      metadata: vaultBinding.metadata,
      auth_type: vaultBinding.authType,
      cluster_id: vaultBinding.clusterId,
      initiating_subject_agent_id: vaultBinding.initiatingSubjectAgentId,
      credential_use_evidence: vaultBinding.credentialUseEvidence,
    })
  ) {
    return {
      ok: true,
      existing: true,
      provenanceId: effective.provenance_id,
      mutationHash: effective.mutation_hash,
    };
  }

  const eventType = verified.rowCount > 0 ? 'ROTATE' : 'STORE';
  const body = {
    event_type: eventType,
    service: prepared.service,
    slot_id: prepared.slot,
    credential_hash: prepared.hash,
    valid_from: Math.floor(Date.now() / 1000),
    valid_until: null,
    rotated_from: previousStore?.provenance_id || null,
    reason: 'identity_vault_oauth_exchange',
    operator: 'housekeeper',
    signer_agent_id: 'housekeeper',
    subject_agent_id: 'housekeeper',
    memory_id: null,
    session_id: null,
    platform: provider,
    account: kind,
    identity_vault: {
      namespace: IDENTITY_VAULT_NAMESPACE,
      company_id: companyId,
      provider,
      credential_kind: kind,
      expires_at: vaultBinding.expiresAt,
      metadata: vaultBinding.metadata,
      auth_type: vaultBinding.authType,
      cluster_id: vaultBinding.clusterId,
      initiating_subject_agent_id: vaultBinding.initiatingSubjectAgentId,
      credential_use_evidence: vaultBinding.credentialUseEvidence,
    },
    ts_created: Math.floor(Date.now() / 1000),
    ts_saved: Math.floor(Date.now() / 1000),
  };
  const signed = await signAsHousekeeper(body);
  const committed = await credentialLedger.commitCredentialLifecycle({
    serviceName: prepared.service,
    slotId: prepared.slot,
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    eventType,
    bodyJson: signed.body,
    client,
  });
  if (!committed.ok) {
    throw new Error(`identity_vault_credential_lifecycle_failed:${committed.reason}`);
  }
  return committed;
}

export async function appendIntegrationToken({
  companyId,
  provider,
  accessToken,
  refreshToken = null,
  expiresAt = null,
  metadata = {},
  authType = 'oauth',
  clusterId = IDENTITY_VAULT_CLUSTER_ID,
  initiatingSubjectAgentId = 'housekeeper',
  credentialUseEvidence = [],
}) {
  const normalizedProvider = normalizeProvider(provider);
  if (authType === 'oauth' && !accessToken) {
    throw new Error('OAuth access token is required');
  }

  const normalizedInitiatingSubject = String(initiatingSubjectAgentId || '').trim();
  const vaultBinding = Object.freeze({
    expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
    metadata: normalizeVaultMetadata(metadata),
    authType: String(authType || '').trim().toLowerCase(),
    clusterId: String(clusterId || '').trim(),
    initiatingSubjectAgentId: normalizedInitiatingSubject,
    credentialUseEvidence: await verifyCredentialUseEvidence(
      credentialUseEvidence,
      normalizedProvider,
      normalizedInitiatingSubject,
      companyId,
    ),
  });
  if (!vaultBinding.authType || !vaultBinding.clusterId || !vaultBinding.initiatingSubjectAgentId) {
    throw new Error('Identity vault signed authority fields are incomplete');
  }
  let access = null;
  let refresh = null;
  let client = null;
  try {
    // Keychain succeeds before PostgreSQL by necessity. Version slots are
    // content-addressed, so retrying the same exchange is idempotent. Every
    // signed authority field is validated before either live pointer moves.
    access = await prepareToken(normalizedProvider, 'access', accessToken);
    refresh = await prepareToken(normalizedProvider, 'refresh', refreshToken);
    client = await agentPool.connect();
    await client.query('BEGIN');
    await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', companyId]);
    await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', 'housekeeper']);
    const accessLifecycle = await commitTokenLifecycle(client, access, normalizedProvider, 'access', companyId, vaultBinding);
    const refreshLifecycle = await commitTokenLifecycle(client, refresh, normalizedProvider, 'refresh', companyId, vaultBinding);
    await client.query('COMMIT');
    await Promise.all([
      access ? refreshCachedCredential(access.service) : null,
      refresh ? refreshCachedCredential(refresh.service) : null,
    ].filter(Boolean));
    return {
      company_id: companyId,
      provider: normalizedProvider,
      expires_at: vaultBinding.expiresAt,
      metadata: vaultBinding.metadata,
      auth_type: vaultBinding.authType,
      cluster_id: vaultBinding.clusterId,
      access_token_present: Boolean(access),
      refresh_token_present: Boolean(refresh),
      access_lifecycle_mutation_hash: accessLifecycle?.mutationHash
        ? Buffer.from(accessLifecycle.mutationHash).toString('hex')
        : null,
      refresh_lifecycle_mutation_hash: refreshLifecycle?.mutationHash
        ? Buffer.from(refreshLifecycle.mutationHash).toString('hex')
        : null,
    };
  } catch (error) {
    if (client) {
      try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    }
    error.keychain_reconciliation = {
      provider: normalizedProvider,
      access_slot: access?.slot || null,
      access_hash: access?.hash || null,
      refresh_slot: refresh?.slot || null,
      refresh_hash: refresh?.hash || null,
      plaintext_retained_only_in_keychain: true,
    };
    throw error;
  } finally {
    client?.release();
  }
}

async function materializeProvider(companyId, provider) {
  const normalizedProvider = normalizeProvider(provider);
  const accessService = tokenService(normalizedProvider, 'access');
  const refreshService = tokenService(normalizedProvider, 'refresh');
  const [access, refresh] = await Promise.all([
    readCredential(accessService),
    readCredential(refreshService),
  ]);
  if (!access && !refresh) return null;
  const [accessLifecycle, refreshLifecycle] = await Promise.all([
    access ? credentialLedger.readVerifiedSlotChain(access.slot) : null,
    refresh ? credentialLedger.readVerifiedSlotChain(refresh.slot) : null,
  ]);
  const accessBody = accessLifecycle?.effectiveStore?.body_json || null;
  const refreshBody = refreshLifecycle?.effectiveStore?.body_json || null;
  const accessVault = accessBody?.identity_vault || null;
  const refreshVault = refreshBody?.identity_vault || null;
  const validVaultBinding = (binding, kind) => (
    binding?.namespace === IDENTITY_VAULT_NAMESPACE
    && binding?.company_id === companyId
    && binding?.provider === normalizedProvider
    && binding?.credential_kind === kind
  );
  const accessValid = !access || (
    accessBody?.credential_hash === access.hash
    && validVaultBinding(accessVault, 'access')
  );
  const refreshValid = !refresh || (
    refreshBody?.credential_hash === refresh.hash
    && validVaultBinding(refreshVault, 'refresh')
  );
  const accessCheckout = accessValid && access?.value && accessLifecycle?.effectiveStore
    ? Object.freeze({
      serviceName: accessService,
      value: access.value,
      credentialHash: access.hash,
      slotId: access.slot,
      effectiveProvenanceId: String(accessLifecycle.effectiveStore.provenance_id),
      effectiveMutationHash: Buffer.from(accessLifecycle.effectiveStore.mutation_hash).toString('hex'),
    })
    : null;
  const refreshCheckout = refreshValid && refresh?.value && refreshLifecycle?.effectiveStore
    ? Object.freeze({
      serviceName: refreshService,
      value: refresh.value,
      credentialHash: refresh.hash,
      slotId: refresh.slot,
      effectiveProvenanceId: String(refreshLifecycle.effectiveStore.provenance_id),
      effectiveMutationHash: Buffer.from(refreshLifecycle.effectiveStore.mutation_hash).toString('hex'),
    })
    : null;
  const authority = accessVault || refreshVault;
  if (!authority || !accessValid || !refreshValid) {
    throw new Error(`identity_vault_lifecycle_binding_invalid:${normalizedProvider}`);
  }
  if (accessVault && refreshVault) {
    const withoutKind = (binding) => {
      const { credential_kind: _kind, ...rest } = binding;
      return rest;
    };
    if (canonicalJson(withoutKind(accessVault)) !== canonicalJson(withoutKind(refreshVault))) {
      throw new Error(`identity_vault_torn_exchange:${normalizedProvider}`);
    }
  }
  return {
    id: String(accessLifecycle?.effectiveStore?.provenance_id || refreshLifecycle?.effectiveStore?.provenance_id),
    company_id: companyId,
    provider: normalizedProvider,
    access_token_slot: access?.slot || null,
    access_token_hash: access?.hash || null,
    refresh_token_slot: refresh?.slot || null,
    refresh_token_hash: refresh?.hash || null,
    expires_at: authority.expires_at || null,
    metadata: authority.metadata || {},
    auth_type: authority.auth_type,
    cluster_id: authority.cluster_id,
    created_at: accessLifecycle?.effectiveStore?.created_at || refreshLifecycle?.effectiveStore?.created_at || null,
    updated_at: accessLifecycle?.effectiveStore?.created_at || refreshLifecycle?.effectiveStore?.created_at || null,
    access_token: accessValid ? (access?.value || '') : '',
    refresh_token: refreshValid ? (refresh?.value || '') : '',
    access_token_present: Boolean(access && accessValid && access.value),
    refresh_token_present: Boolean(refresh && refreshValid && refresh.value),
    credential_integrity: accessValid && refreshValid,
    access_token_checkout: accessCheckout,
    refresh_token_checkout: refreshCheckout,
  };
}

export async function getLatestIntegrationToken(companyId, provider, aliases = []) {
  const providers = normalizeProviderList(provider, aliases);
  if (!providers.length) return null;
  for (const candidate of providers) {
    const row = await materializeProvider(companyId, candidate);
    if (row) return row;
  }
  return null;
}

export async function syncIdentityVault({
  companyId,
  provider,
  aliases = [],
  markovMse = 0.58,
  humanMse = 1
}) {
  const mvs = computeMysoreMvs(markovMse, humanMse);
  const failingMvs = mvs < MYSORE_MVS_THRESHOLD;
  const tokenRow = await getLatestIntegrationToken(companyId, provider, aliases);
  return {
    tokenRow,
    accessToken: tokenRow?.access_token || '',
    refreshToken: tokenRow?.refresh_token || '',
    accessCredentialCheckout: tokenRow?.access_token_checkout || null,
    refreshCredentialCheckout: tokenRow?.refresh_token_checkout || null,
    expiresAt: tokenRow?.expires_at ? new Date(tokenRow.expires_at) : null,
    metadata: tokenRow?.metadata || {},
    provider: tokenRow?.provider || String(provider || '').trim().toLowerCase(),
    mvs,
    failingMvs,
    recursivelyRecalled: false,
  };
}

export const __private__ = {
  credentialSlotId,
  normalizeProvider,
  normalizeCredentialUseEvidence,
  normalizeVaultMetadata,
  verifyCredentialUseEvidence,
  tokenService,
};
