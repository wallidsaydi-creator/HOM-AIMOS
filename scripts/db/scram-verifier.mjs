// Produce a PostgreSQL SCRAM verifier from a generated ASCII database secret.
// Provisioning sends the verifier in ALTER ROLE, never the plaintext secret.

import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';

export function makePostgresScramVerifier(password, {
  salt = randomBytes(16), iterations = 15_000,
} = {}) {
  if (typeof password !== 'string' || !/^[A-Za-z0-9_-]{43,}$/.test(password)) {
    throw new Error('postgres_scram_generated_secret_required');
  }
  if (!Buffer.isBuffer(salt) || salt.length < 16
      || !Number.isInteger(iterations) || iterations < 4096) {
    throw new Error('postgres_scram_parameters_invalid');
  }
  const salted = pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, 32, 'sha256');
  const clientKey = createHmac('sha256', salted).update('Client Key').digest();
  const storedKey = createHash('sha256').update(clientKey).digest();
  const serverKey = createHmac('sha256', salted).update('Server Key').digest();
  salted.fill(0);
  clientKey.fill(0);
  return `SCRAM-SHA-256$${iterations}:${salt.toString('base64')}`
    + `$${storedKey.toString('base64')}:${serverKey.toString('base64')}`;
}
