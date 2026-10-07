#!/usr/bin/env node

// Offline post-migration activation of two least-privilege serving identities.
// The administrator credential is used only by this process. PostgreSQL sees
// SCRAM verifiers in ALTER ROLE; plaintext remains in versioned Keychain slots.

import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { resolveAimosInstallationContext } from '../../services/installation-context.js';
import { readCredentialSync, storeCredentialSync } from '../../services/security/credential-store.js';
import { resolveClusterAdminConfig } from './cluster-admin.mjs';
import { makePostgresScramVerifier } from './scram-verifier.mjs';

const ROLES = Object.freeze([
  ['aimos_service_reader', 'aimos_service_reader_db_password'],
  ['aimos_identity_writer', 'aimos_identity_writer_db_password'],
]);

function slotForInstance(base, instance) {
  return instance === 'canonical' ? base : `${base}-${instance}`;
}

function getOrCreateCredential(service) {
  let credential = readCredentialSync(service);
  if (!credential) {
    storeCredentialSync(service, randomBytes(48).toString('base64url'));
    credential = readCredentialSync(service);
  }
  if (!credential?.value || !/^[A-Za-z0-9_-]{43,}$/.test(credential.value)) {
    throw new Error(`serving_role_credential_readback_invalid:${service}`);
  }
  return credential;
}

async function proveLogin(config, role, password) {
  const client = new pg.Client({ ...config, user: role, password });
  try {
    await client.connect();
    const result = await client.query(`SELECT current_user,
      (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS superuser,
      (SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user) AS bypass_rls,
      current_setting('app.current_client_id', true) AS company_id`);
    const row = result.rows[0];
    if (row.current_user !== role || row.superuser || row.bypass_rls
        || row.company_id !== 'hom') throw new Error('serving_role_login_postcondition_invalid');
  } finally {
    await client.end().catch(() => {});
  }
}

export async function activateServingRoles({
  argv = process.argv.slice(2), database = 'aimos',
} = {}) {
  const context = resolveAimosInstallationContext(argv);
  const adminConfig = await resolveClusterAdminConfig({ argv, database });
  const admin = new pg.Client(adminConfig);
  const outputs = [];
  try {
    await admin.connect();
    for (const [role, baseService] of ROLES) {
      const attrs = (await admin.query(`SELECT oid, rolcanlogin, rolsuper, rolbypassrls,
        rolcreatedb, rolcreaterole, rolreplication, rolinherit
        FROM pg_roles WHERE rolname=$1`, [role])).rows[0];
      if (!attrs || attrs.rolsuper || attrs.rolbypassrls || attrs.rolcreatedb
          || attrs.rolcreaterole || attrs.rolreplication || attrs.rolinherit) {
        throw new Error(`serving_role_stage_invalid:${role}`);
      }
      const memberships = await admin.query(
        'SELECT 1 FROM pg_auth_members WHERE member=$1 OR roleid=$1 LIMIT 1', [attrs.oid]);
      if (memberships.rowCount) throw new Error(`serving_role_membership_forbidden:${role}`);
      const service = slotForInstance(baseService, context.instance);
      const credential = getOrCreateCredential(service);
      if (!attrs.rolcanlogin) {
        const verifier = makePostgresScramVerifier(credential.value);
        await admin.query(`ALTER ROLE ${role} WITH LOGIN NOSUPERUSER NOBYPASSRLS
          NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD '${verifier}'`);
      }
      await proveLogin({ ...adminConfig, database }, role, credential.value);
      outputs.push(Object.freeze({ role, slot: credential.slot, hash: credential.hash }));
    }
  } finally {
    await admin.end().catch(() => {});
  }
  return Object.freeze(outputs);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  activateServingRoles().then((roles) => {
    process.stdout.write(`${JSON.stringify(roles)}\n`);
  }).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
