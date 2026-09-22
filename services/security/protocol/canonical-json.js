// Authority-free deterministic JSON canonicalization for AIMOS protocol
// commitments. This module performs no signing, persistence, I/O, policy, or
// runtime configuration. It is the single implementation owner; identity and
// evidence modules consume this exact function.

export const CANONICAL_JSON_DEPTH_LIMIT = 32;

// Admission only; historical canonicalJson bytes below are unchanged.
// RFC 8259 §4 / RFC 8785 §3.1: decoded member names must be unique within
// each object. Check the wire BEFORE JSON.parse discards earlier members.
// O(wire length) scan, O(wire length) bounded key storage, depth <= 32.
export function assertUniqueJsonMembers(text) {
  if (typeof text !== 'string') throw new TypeError('json_wire_string_required');
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      const start = i++;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === '\\') i++;
        i++;
      }
      if (i >= text.length) throw new SyntaxError('json_string_unterminated');
      const frame = stack.at(-1);
      if (frame?.keys && frame.keyExpected) {
        const key = JSON.parse(text.slice(start, i + 1));
        if (frame.keys.has(key)) {
          const error = new SyntaxError('json_duplicate_member');
          error.code = 'json_duplicate_member'; throw error;
        }
        frame.keys.add(key); frame.keyExpected = false;
      }
    } else if (ch === '{' || ch === '[') {
      if (stack.length > CANONICAL_JSON_DEPTH_LIMIT) {
        const error = new SyntaxError('json_depth_invalid');
        error.code = 'json_depth_invalid'; throw error;
      }
      stack.push(ch === '{' ? { keys: new Set(), keyExpected: true } : {});
    } else if (ch === '}' || ch === ']') stack.pop();
    else if (ch === ',' && stack.at(-1)?.keys) stack.at(-1).keyExpected = true;
  }
}

export function parseJsonWire(text) {
  assertUniqueJsonMembers(text);
  return JSON.parse(text);
}

// New exact-wire profile validation, not a historical serializer replacement.
// Numeric tokens are retained as bytes; this does not assign them application
// meaning. Typed consumers must still enforce their numeric/authority domains.
export function assertSignedJsonBytesV1(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 64 * 1024 * 1024) {
    throw new Error('signed_json_size_invalid');
  }
  let value;
  try { value = parseJsonWire(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { throw new Error('signed_json_wire_invalid'); }
  function scalar(text) {
    for (const char of text) {
      const code = char.codePointAt(0);
      if (code === 0 || (code >= 0xd800 && code <= 0xdfff)) throw new Error('signed_json_wire_invalid');
    }
  }
  function visit(node, depth) {
    if (depth > CANONICAL_JSON_DEPTH_LIMIT) throw new Error('signed_json_wire_invalid');
    if (typeof node === 'string') scalar(node);
    else if (Array.isArray(node)) for (const child of node) visit(child, depth + 1);
    else if (node && typeof node === 'object') for (const key of Object.keys(node)) {
      scalar(key); visit(node[key], depth + 1);
    }
  }
  visit(value, 0);
}

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
