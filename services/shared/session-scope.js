/**
 * session-scope.js — Canonical retained-session key contract
 *
 * A session is isolated by a literal `sess:<session_id>:` key prefix. SQL
 * callers must use the escaped LIKE pattern from this module so `_`, `%`, and
 * `\\` inside a legitimate session id cannot widen the scope.
 */

const MAX_SESSION_ID_BYTES = 160;

export function normalizeSessionId(value) {
  const sessionId = String(value ?? '').trim();
  if (!sessionId) throw new Error('session_id_required');
  if (Buffer.byteLength(sessionId, 'utf8') > MAX_SESSION_ID_BYTES) {
    throw new Error('session_id_too_long');
  }
  if(/[\u0000-\u001f\u007f]/u.test(sessionId)) {
    throw new Error('session_id_control_character');
  }
  return sessionId;
}

export function sessionKeyPrefix(sessionId) {
  return `sess:${normalizeSessionId(sessionId)}:`;
}

export function escapeSqlLikeLiteral(value) {
  return String(value).replace(/[\\%_]/g, (character) => `\\${character}`);
}

export function sessionKeyLikePattern(sessionId, suffix = '') {
  return `${escapeSqlLikeLiteral(sessionKeyPrefix(sessionId))}${escapeSqlLikeLiteral(suffix)}%`;
}

export const SESSION_SCOPE_CONSTANTS = Object.freeze({
  MAX_SESSION_ID_BYTES,
});
