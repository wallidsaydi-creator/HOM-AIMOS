// Authority-free deterministic JSON canonicalization for AIMOS protocol
// commitments. This module performs no signing, persistence, I/O, policy, or
// runtime configuration. It is the single implementation owner; identity and
// evidence modules consume this exact function.

export const CANONICAL_JSON_DEPTH_LIMIT = 32;

// RFC 8785 practical subset retained byte-for-byte from agent-identity.js.
// Object keys use UTF-16 code-unit order, arrays preserve order, and all
// unsupported or non-finite values fail closed with the historical reason text.
export function canonicalJson(value, depth = 0) {
  if (depth > CANONICAL_JSON_DEPTH_LIMIT) {
    throw new Error('canonicalJson: depth limit exceeded');
  }
  if (value === null) return 'null';
  if (value === undefined) {
    throw new Error('canonicalJson: undefined is not serializable');
  }
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonicalJson: non-finite number');
    }
    return JSON.stringify(value);
  }
  if (t === 'string') return JSON.stringify(value);
  if (t === 'bigint') {
    throw new Error('canonicalJson: bigint not supported');
  }
  if (Array.isArray(value)) {
    const parts = value.map((entry) => canonicalJson(entry, depth + 1));
    return `[${parts.join(',')}]`;
  }
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`);
    return `{${parts.join(',')}}`;
  }
  throw new Error(`canonicalJson: unsupported type ${t}`);
}
