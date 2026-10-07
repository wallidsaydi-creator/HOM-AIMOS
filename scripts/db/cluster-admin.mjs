// Offline AIMOS database administration connection. Runtime server modules do
// not import this owner; the generated secret remains in the existing Keychain.

import { resolveAimosInstallationContext } from '../../services/installation-context.js';
import { readCredentialSync } from '../../services/security/credential-store.js';
import {
  CLUSTER_ADMIN_ROLE,
  clusterAdminCredentialService,
  verifyExistingSecureCluster,
} from './secure-cluster.mjs';

export async function resolveClusterAdminConfig({
  argv = process.argv.slice(2), database = 'postgres',
} = {}) {
  const context = resolveAimosInstallationContext(argv);
  if (context.postgres_port === 5432) {
    throw new Error('isolated_cluster_required_for_admin_config');
  }
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(database)) {
    throw new Error('cluster_admin_database_invalid');
  }
  const service = clusterAdminCredentialService(context.instance);
  const credential = readCredentialSync(service);
  if (!credential?.value) throw new Error('cluster_admin_credential_unavailable');
  await verifyExistingSecureCluster({
    stateRoot: context.state_root,
    port: context.postgres_port,
    adminPassword: credential.value,
  });
  return Object.freeze({
    host: '127.0.0.1', port: context.postgres_port, database,
    user: CLUSTER_ADMIN_ROLE, password: credential.value,
    ssl: false, connectionTimeoutMillis: 5000,
  });
}
