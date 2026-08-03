/**
 * QMD — Query Memory Database
 * Parser: converts a QMD query string into an AST.
 *
 * Supported syntax:
 *
 *   FIND type:framework WHERE contains("positioning") HOPS 2 LIMIT 10
 *   TRAVERSE FROM key:"F1*" FOLLOW cross_refs,entity_edges HOPS 3
 *   MATCH agent:coder WHERE type:after_action_review AND created > 7d
 *   GRAPH AROUND id:<uuid> HOPS 2 RETURN adjacency
 *   PATH FROM type:book_extract TO type:framework MAX_DEPTH 4
 *   COUNT type:event_log WHERE created > 24h GROUP BY agent_id
 *   RETURN adjacency | keys_only | default
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: aimos.js
// Pipeline: RECALL | Position: QMD language parser (AST generation)
// ─────────────────────────────────────────────────────────────────────────────

// ─── TOKEN TYPES ──────────────────────────────────────────────────────────────
const TT = {
  KEYWORD:    'KEYWORD',
  FIELD_VAL:  'FIELD_VAL',   // key:value
  STRING:     'STRING',      // "quoted"
  NUMBER:     'NUMBER',
  DURATION:   'DURATION',    // 7d, 24h, 1h
  OPERATOR:   'OPERATOR',    // >, <, AND, OR
  IDENT:      'IDENT',
  COMMA:      'COMMA',
  LPAREN:     'LPAREN',
  RPAREN:     'RPAREN',
  UUID:       'UUID',
  GLOB:       'GLOB',        // patterns with *
  EOF:        'EOF',
};

const KEYWORDS = new Set([
  'FIND', 'TRAVERSE', 'MATCH', 'GRAPH', 'PATH', 'COUNT',
  'WHERE', 'FROM', 'TO', 'FOLLOW', 'HOPS', 'LIMIT', 'RETURN',
  'AROUND', 'AND', 'OR', 'GROUP', 'BY', 'MAX_DEPTH', 'contains',
]);

const VALID_VERBS    = new Set(['FIND', 'TRAVERSE', 'MATCH', 'GRAPH', 'PATH', 'COUNT']);
const VALID_FOLLOW   = new Set(['cross_refs', 'entity_edges']);
const VALID_RETURN   = new Set(['default', 'adjacency', 'keys_only']);
const UUID_RE        = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DURATION_RE    = /^(\d+)(d|h|m)$/;
const MAX_QUERY_LEN  = 2048;

// ─── LEXER ─────────────────────────────────────────────────────────────────────
function tokenize(input) {
  if (typeof input !== 'string') throw new QMDSyntaxError('Query must be a string');
  if (input.length > MAX_QUERY_LEN) throw new QMDSyntaxError(`Query exceeds max length of ${MAX_QUERY_LEN}`);

  const tokens = [];
  let i = 0;
  const src = input.trim();
  const len = src.length;

  while (i < len) {
    // skip whitespace
    if (/\s/.test(src[i])) { i++; continue; }

    // quoted string
    if (src[i] === '"' || src[i] === "'") {
      const quote = src[i++];
      let val = '';
      while (i < len && src[i] !== quote) {
        if (src[i] === '\\') i++; // basic escape
        val += src[i++];
      }
      if (i >= len) throw new QMDSyntaxError('Unterminated string literal');
      i++; // closing quote
      tokens.push({ type: TT.STRING, value: val });
      continue;
    }

    // parentheses
    if (src[i] === '(') { tokens.push({ type: TT.LPAREN, value: '(' }); i++; continue; }
    if (src[i] === ')') { tokens.push({ type: TT.RPAREN, value: ')' }); i++; continue; }
    if (src[i] === ',') { tokens.push({ type: TT.COMMA, value: ',' }); i++; continue; }

    // operator >  <
    if (src[i] === '>' || src[i] === '<') {
      tokens.push({ type: TT.OPERATOR, value: src[i++] });
      continue;
    }

    // word token (keyword, identifier, field:value, duration, number)
    if (/[A-Za-z0-9_\-.*]/.test(src[i])) {
      let word = '';
      const start = i;
      while (i < len && /[A-Za-z0-9_\-.*:"/]/.test(src[i]) && src[i] !== ',' && src[i] !== ')') {
        word += src[i++];
      }

      // field:value  e.g. type:framework  agent:coder  key:"F1*"
      if (word.includes(':') && !word.startsWith('http')) {
        const colonIdx = word.indexOf(':');
        const field = word.slice(0, colonIdx);
        const val   = word.slice(colonIdx + 1).replace(/^["']|["']$/g, '');
        // field:value tokens carry field+value
        tokens.push({ type: TT.FIELD_VAL, field, value: val });
        continue;
      }

      // UUID
      if (UUID_RE.test(word)) {
        tokens.push({ type: TT.UUID, value: word });
        continue;
      }

      // Duration  7d / 24h / 1m
      if (DURATION_RE.test(word)) {
        const m = word.match(DURATION_RE);
        tokens.push({ type: TT.DURATION, value: word, amount: parseInt(m[1], 10), unit: m[2] });
        continue;
      }

      // Pure number
      if (/^\d+$/.test(word)) {
        tokens.push({ type: TT.NUMBER, value: parseInt(word, 10) });
        continue;
      }

      // Keyword (case-insensitive check)
      const upper = word.toUpperCase();
      if (KEYWORDS.has(upper) || KEYWORDS.has(word)) {
        tokens.push({ type: TT.KEYWORD, value: upper === 'CONTAINS' ? 'contains' : upper });
        continue;
      }

      // AND / OR operators
      if (upper === 'AND' || upper === 'OR') {
        tokens.push({ type: TT.OPERATOR, value: upper });
        continue;
      }

      // glob pattern or plain ident
      if (word.includes('*')) {
        tokens.push({ type: TT.GLOB, value: word });
      } else {
        tokens.push({ type: TT.IDENT, value: word });
      }
      continue;
    }

    throw new QMDSyntaxError(`Unexpected character '${src[i]}' at position ${i}`);
  }

  tokens.push({ type: TT.EOF });
  return tokens;
}

// ─── PARSER ───────────────────────────────────────────────────────────────────
class QMDSyntaxError extends Error {
  constructor(msg) {
    super(msg);
    this.name = 'QMDSyntaxError';
  }
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos    = 0;
  }

  peek() { return this.tokens[this.pos]; }

  consume(type, value) {
    const tok = this.tokens[this.pos];
    if (type && tok.type !== type) {
      throw new QMDSyntaxError(
        `Expected token type ${type}${value ? ` (${value})` : ''} but got ${tok.type} "${tok.value ?? ''}"`
      );
    }
    if (value !== undefined && tok.value !== value) {
      throw new QMDSyntaxError(`Expected "${value}" but got "${tok.value}"`);
    }
    this.pos++;
    return tok;
  }

  accept(type, value) {
    const tok = this.tokens[this.pos];
    if (tok.type !== type) return null;
    if (value !== undefined && tok.value !== value) return null;
    this.pos++;
    return tok;
  }

  // Parse top-level statement
  parse() {
    const verb = this.consume(TT.KEYWORD);
    if (!VALID_VERBS.has(verb.value)) {
      throw new QMDSyntaxError(`Unknown verb "${verb.value}". Expected one of: ${[...VALID_VERBS].join(', ')}`);
    }

    switch (verb.value) {
      case 'FIND':     return this.parseFind();
      case 'TRAVERSE': return this.parseTraverse();
      case 'MATCH':    return this.parseMatch();
      case 'GRAPH':    return this.parseGraph();
      case 'PATH':     return this.parsePath();
      case 'COUNT':    return this.parseCount();
      default:
        throw new QMDSyntaxError(`Unhandled verb "${verb.value}"`);
    }
  }

  // ─── FIND ──────────────────────────────────────────────────────────────────
  // FIND type:framework WHERE contains("positioning") HOPS 2 LIMIT 10
  // FIND key:"F1*" LIMIT 5
  parseFind() {
    const node = { verb: 'FIND', filters: [], hops: 2, limit: 10, return: 'default' };

    // First token after FIND: expect a field:value (type/key) or WHERE
    const first = this.peek();
    if (first.type === TT.FIELD_VAL) {
      this.pos++;
      node.filters.push({ field: first.field, op: '=', value: first.value });
    }

    // Optional WHERE clause
    if (this.accept(TT.KEYWORD, 'WHERE')) {
      node.where = this.parseWhereClause();
    }

    // Optional HOPS
    if (this.accept(TT.KEYWORD, 'HOPS')) {
      node.hops = this.parsePositiveInt('HOPS', 1, 4);
    }

    // Optional LIMIT
    if (this.accept(TT.KEYWORD, 'LIMIT')) {
      node.limit = this.parsePositiveInt('LIMIT', 1, 200);
    }

    // Optional RETURN
    if (this.accept(TT.KEYWORD, 'RETURN')) {
      node.return = this.parseReturnFormat();
    }

    return node;
  }

  // ─── TRAVERSE ──────────────────────────────────────────────────────────────
  // TRAVERSE FROM key:"F1*" FOLLOW cross_refs,entity_edges HOPS 3
  parseTraverse() {
    const node = { verb: 'TRAVERSE', from: null, follow: ['cross_refs', 'entity_edges'], hops: 2, limit: 50, return: 'default' };

    this.consume(TT.KEYWORD, 'FROM');

    // Accept field:value, UUID, or IDENT as the start node
    const anchor = this.peek();
    if (anchor.type === TT.FIELD_VAL) {
      this.pos++;
      node.from = { field: anchor.field, value: anchor.value };
    } else if (anchor.type === TT.UUID) {
      this.pos++;
      node.from = { field: 'id', value: anchor.value };
    } else if (anchor.type === TT.IDENT) {
      this.pos++;
      node.from = { field: 'key', value: anchor.value };
    } else {
      throw new QMDSyntaxError('TRAVERSE FROM requires a field:value, UUID, or identifier');
    }

    if (this.accept(TT.KEYWORD, 'FOLLOW')) {
      node.follow = this.parseFollowList();
    }

    if (this.accept(TT.KEYWORD, 'HOPS')) {
      node.hops = this.parsePositiveInt('HOPS', 1, 4);
    }

    if (this.accept(TT.KEYWORD, 'LIMIT')) {
      node.limit = this.parsePositiveInt('LIMIT', 1, 200);
    }

    if (this.accept(TT.KEYWORD, 'RETURN')) {
      node.return = this.parseReturnFormat();
    }

    return node;
  }

  // ─── MATCH ─────────────────────────────────────────────────────────────────
  // MATCH agent:coder WHERE type:after_action_review AND created > 7d
  parseMatch() {
    const node = { verb: 'MATCH', filters: [], where: null, limit: 20, return: 'default' };

    const first = this.peek();
    if (first.type === TT.FIELD_VAL) {
      this.pos++;
      node.filters.push({ field: first.field, op: '=', value: first.value });
    }

    if (this.accept(TT.KEYWORD, 'WHERE')) {
      node.where = this.parseWhereClause();
    }

    if (this.accept(TT.KEYWORD, 'LIMIT')) {
      node.limit = this.parsePositiveInt('LIMIT', 1, 200);
    }

    if (this.accept(TT.KEYWORD, 'RETURN')) {
      node.return = this.parseReturnFormat();
    }

    return node;
  }

  // ─── GRAPH AROUND ──────────────────────────────────────────────────────────
  // GRAPH AROUND id:<uuid> HOPS 2 RETURN adjacency
  parseGraph() {
    const node = { verb: 'GRAPH', center: null, hops: 2, limit: 50, return: 'adjacency' };

    this.consume(TT.KEYWORD, 'AROUND');

    const anchor = this.peek();
    if (anchor.type === TT.FIELD_VAL) {
      this.pos++;
      node.center = { field: anchor.field, value: anchor.value };
    } else if (anchor.type === TT.UUID) {
      this.pos++;
      node.center = { field: 'id', value: anchor.value };
    } else {
      throw new QMDSyntaxError('GRAPH AROUND requires id:<uuid> or field:value');
    }

    if (this.accept(TT.KEYWORD, 'HOPS')) {
      node.hops = this.parsePositiveInt('HOPS', 1, 4);
    }

    if (this.accept(TT.KEYWORD, 'LIMIT')) {
      node.limit = this.parsePositiveInt('LIMIT', 1, 200);
    }

    if (this.accept(TT.KEYWORD, 'RETURN')) {
      node.return = this.parseReturnFormat();
    }

    return node;
  }

  // ─── PATH ──────────────────────────────────────────────────────────────────
  // PATH FROM type:book_extract TO type:framework MAX_DEPTH 4
  parsePath() {
    const node = { verb: 'PATH', from: null, to: null, max_depth: 4, limit: 20 };

    this.consume(TT.KEYWORD, 'FROM');
    const from = this.peek();
    if (from.type === TT.FIELD_VAL) {
      this.pos++;
      node.from = { field: from.field, value: from.value };
    } else {
      throw new QMDSyntaxError('PATH FROM requires field:value');
    }

    this.consume(TT.KEYWORD, 'TO');
    const to = this.peek();
    if (to.type === TT.FIELD_VAL) {
      this.pos++;
      node.to = { field: to.field, value: to.value };
    } else {
      throw new QMDSyntaxError('PATH TO requires field:value');
    }

    if (this.accept(TT.KEYWORD, 'MAX_DEPTH')) {
      node.max_depth = this.parsePositiveInt('MAX_DEPTH', 1, 6);
    }

    if (this.accept(TT.KEYWORD, 'LIMIT')) {
      node.limit = this.parsePositiveInt('LIMIT', 1, 200);
    }

    return node;
  }

  // ─── COUNT ─────────────────────────────────────────────────────────────────
  // COUNT type:event_log WHERE created > 24h GROUP BY agent_id
  parseCount() {
    const node = { verb: 'COUNT', filters: [], where: null, group_by: null };

    const first = this.peek();
    if (first.type === TT.FIELD_VAL) {
      this.pos++;
      node.filters.push({ field: first.field, op: '=', value: first.value });
    }

    if (this.accept(TT.KEYWORD, 'WHERE')) {
      node.where = this.parseWhereClause();
    }

    if (this.accept(TT.KEYWORD, 'GROUP')) {
      this.consume(TT.KEYWORD, 'BY');
      const col = this.peek();
      if (col.type === TT.IDENT || col.type === TT.FIELD_VAL) {
        this.pos++;
        node.group_by = col.value || col.field;
      } else {
        throw new QMDSyntaxError('GROUP BY requires a column name');
      }
    }

    return node;
  }

  // ─── WHERE CLAUSE ──────────────────────────────────────────────────────────
  // Supports: contains("text"), type:X, agent:X, clearance:N, created > Nd
  // Connected by AND / OR
  parseWhereClause() {
    const conditions = [];

    while (true) {
      const cond = this.parseCondition();
      conditions.push(cond);

      const op = this.peek();
      // AND/OR may be tokenized as KEYWORD or OPERATOR depending on position
      const isLogical = (op.value === 'AND' || op.value === 'OR') &&
                        (op.type === TT.OPERATOR || op.type === TT.KEYWORD);
      if (isLogical) {
        this.pos++;
        conditions.push({ logical: op.value });
      } else {
        break;
      }
    }

    return conditions;
  }

  parseCondition() {
    const tok = this.peek();

    // contains("text")
    if (tok.type === TT.KEYWORD && tok.value === 'contains') {
      this.pos++;
      this.consume(TT.LPAREN);
      const strTok = this.consume(TT.STRING);
      this.consume(TT.RPAREN);
      return { type: 'contains', value: strTok.value };
    }

    // field:value  (type, agent, clearance, scope, key, memory_tier)
    if (tok.type === TT.FIELD_VAL) {
      this.pos++;
      return { type: 'field_eq', field: tok.field, value: tok.value };
    }

    // created > 7d  / created < 1h
    if (tok.type === TT.IDENT && tok.value.toLowerCase() === 'created') {
      this.pos++;
      const op = this.consume(TT.OPERATOR);
      if (op.value !== '>' && op.value !== '<') {
        throw new QMDSyntaxError(`Created filter expects > or < but got "${op.value}"`);
      }
      const dur = this.consume(TT.DURATION);
      return { type: 'created', op: op.value, duration: { amount: dur.amount, unit: dur.unit } };
    }

    throw new QMDSyntaxError(`Unexpected token in WHERE clause: ${tok.type} "${tok.value ?? ''}"`);
  }

  // ─── HELPERS ───────────────────────────────────────────────────────────────
  parsePositiveInt(label, min, max) {
    const tok = this.peek();
    if (tok.type !== TT.NUMBER) throw new QMDSyntaxError(`${label} requires a number`);
    this.pos++;
    const n = tok.value;
    if (n < min || n > max) throw new QMDSyntaxError(`${label} must be between ${min} and ${max}, got ${n}`);
    return n;
  }

  parseFollowList() {
    const list = [];
    while (true) {
      const tok = this.peek();
      if (tok.type !== TT.IDENT) break;
      const val = tok.value.toLowerCase();
      if (!VALID_FOLLOW.has(val)) {
        throw new QMDSyntaxError(`FOLLOW value "${val}" is not valid. Use: ${[...VALID_FOLLOW].join(', ')}`);
      }
      list.push(val);
      this.pos++;
      if (!this.accept(TT.COMMA)) break;
    }
    if (!list.length) throw new QMDSyntaxError('FOLLOW requires at least one edge type');
    return list;
  }

  parseReturnFormat() {
    const tok = this.peek();
    if (tok.type !== TT.IDENT) throw new QMDSyntaxError('RETURN requires a format identifier');
    const val = tok.value.toLowerCase();
    if (!VALID_RETURN.has(val)) {
      throw new QMDSyntaxError(`RETURN "${val}" is not valid. Use: ${[...VALID_RETURN].join(', ')}`);
    }
    this.pos++;
    return val;
  }
}

// ─── PUBLIC API ────────────────────────────────────────────────────────────────
/**
 * Parse a QMD query string and return an AST node.
 * Throws QMDSyntaxError on invalid input.
 *
 * @param {string} input
 * @returns {object} AST
 */
export function parseQMD(input) {
  const tokens = tokenize(input);
  const parser  = new Parser(tokens);
  const ast     = parser.parse();

  // ensure EOF
  const remaining = parser.peek();
  if (remaining.type !== TT.EOF) {
    throw new QMDSyntaxError(`Unexpected token after query end: "${remaining.value ?? remaining.type}"`);
  }

  return ast;
}

export { QMDSyntaxError };
