import { canonicalJson } from './canonical-json.js';

/**
 * Render a request memory value into the exact text form owned by the native
 * persistence path. JSON requests admit strings or structured JSON values.
 */
export function serializeMemoryValue(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object') return JSON.stringify(value);
  throw new Error('memory_value_not_serializable');
}

/**
 * Compare a signed request value with its retained text projection. Structured
 * values are compared canonically because PostgreSQL JSONB does not retain
 * object member order; strings remain exact strings and are never reparsed.
 */
export function signedMemoryValueMatchesRetained(signedValue, retainedValue) {
  if (typeof signedValue === 'string') {
    return signedValue === String(retainedValue ?? '');
  }
  if (!signedValue || typeof signedValue !== 'object' || typeof retainedValue !== 'string') {
    return false;
  }
  try {
    const parsedRetained = JSON.parse(retainedValue);
    if (!parsedRetained || typeof parsedRetained !== 'object') return false;
    return canonicalJson(signedValue) === canonicalJson(parsedRetained);
  } catch {
    return false;
  }
}
