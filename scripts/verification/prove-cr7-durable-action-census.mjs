#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RUNTIME_ROOTS = ['routes', 'services', 'jobs', 'db', 'middleware'];
const SQL_EFFECT = /\b(INSERT\s+INTO\s+[a-z_".]|UPDATE\s+(?!SET\b)[a-z_".${}]+|DELETE\s+FROM\s+[a-z_".]|TRUNCATE\s+(?:TABLE\s+)?[a-z_".]|CREATE\s+(?:TABLE|INDEX|ROLE|DATABASE|SCHEMA|FUNCTION|TRIGGER)\s+[a-z_".]|ALTER\s+(?:TABLE|ROLE|DATABASE|FUNCTION)\s+[a-z_".${}]|DROP\s+(?:TABLE|INDEX|ROLE|DATABASE|SCHEMA|FUNCTION)\s+[a-z_".${}]|GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|EXECUTE|USAGE|CONNECT|CREATE|TEMPORARY)\b|REVOKE\s+(?:SELECT|INSERT|UPDATE|DELETE|EXECUTE|USAGE|CONNECT|CREATE|TEMPORARY)\b)/i;
const FILE_EFFECT = /\b(?:fs\.)?(writeFile|writeFileSync|appendFile|appendFileSync|rename|renameSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|chmod|chmodSync|copyFile|copyFileSync|cp|cpSync|createWriteStream)\s*\(/;
const PROCESS_EFFECT = /(?<![.\w])(execFile|execFileSync|spawn|spawnSync|fork)\s*\(/;
const NETWORK_EFFECT = /(?<![.\w])(fetch|fetchWithTimeout)\s*\(/;
const NODE_NETWORK_EFFECT = /\b(?:http|https|lib)\.(request|get)\s*\(/;
const DNS_EFFECT = /\bdns(?:\.promises)?\.(lookup|resolve|resolve4|resolve6)\s*\(/;
const CREDENTIAL_EFFECT = /\b(keychainSetSync|keychainDeleteFn)\s*\(/;

const PROVEN_ATOMIC_DATABASE_OWNERS = new Set([
  'services/observe/event-ledger.js',
  'services/security/request-receipt-ledger.js',
  'services/security/memory-provenance.js',
  'services/security/memory-lineage.js',
  'services/security/save-envelope.js',
  'services/security/recall-authorization.js',
  'services/security/credential-ledger.js',
  'services/security/system-config-ledger.js',
  'services/security/concept-edge-provenance.js',
  'services/governance/governor-config-ledger.js',
  'services/governance/valence-ledger.js',
  'services/core/permissions.js',
  'services/write/persist-memory.js',
  'services/retrieval/quim-index.js',
  'services/retrieval/concept-ppr-native.js',
]);

const PROVEN_CREDENTIAL_USE_OWNERS = new Set([
  'services/integrations/google-tools.js',
  'services/integrations/integration-tools.js',
  'services/integrations/stripe-tools.js',
  'services/integrations/telegram-tools.js',
  'services/integrations/x-search.js',
  'services/integrations/x-tools.js',
]);
const R5_FILE_EFFECT_OWNERS = new Set([
  'jobs/golem-scanner.js',
  'routes/agent-execution.js',
  'routes/setup.js',
  'services/orchestration/skills-runtime.js',
  'services/orchestration/tool-registry.js',
]);
const R5_EXTERNAL_EFFECT_OWNERS = new Set([
  'jobs/golem-scanner.js',
  'routes/mcp.js',
  'services/core/providers.js',
  'services/core/scheming-monitor.js',
  'services/integrations/google-tools.js',
  'services/integrations/integration-tools.js',
  'services/integrations/stripe-tools.js',
  'services/integrations/telegram-tools.js',
  'services/integrations/web-search.js',
  'services/integrations/x-search.js',
  'services/integrations/x-tools.js',
  'services/orchestration/agent-tools.js',
  'services/orchestration/http.js',
]);
const OFFLINE_SIGNED_MAINTENANCE_OWNERS = new Set([
  'services/governance/governor-config-ledger.js',
  'services/security/system-config-ledger.js',
  'services/security/recall-authorization.js',
]);
const R4_OPERATIONAL_ATOMIC_OWNERS = new Set([
  'jobs/nightly-dream.js',
  'services/core/directive-claims.js',
  'services/dream/spiced-consolidator.js',
  'services/orchestration/scheduler.js',
  'services/temporal/retrieval-pheromone.js',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'artifacts') return [];
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) return walk(absolute);
      return entry.isFile() && entry.name.endsWith('.js') ? [absolute] : [];
    });
}

function runtimeFiles() {
  return [path.join(ROOT, 'server.js'), ...RUNTIME_ROOTS.flatMap((name) => walk(path.join(ROOT, name)))]
    .filter((file) => fs.existsSync(file))
    .sort();
}

// Remove JavaScript comments without erasing string/template contents, because
// SQL effects live inside those strings. This is a lexical census, not a parser;
// exact frozen anchors and focused tests prevent it from becoming authority.
function stripComments(source) {
  let output = '';
  let state = 'code';
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    if (state === 'line_comment') {
      if (char === '\n') { state = 'code'; output += '\n'; } else output += ' ';
      continue;
    }
    if (state === 'block_comment') {
      if (char === '*' && next === '/') { output += '  '; index += 1; state = 'code'; }
      else output += char === '\n' ? '\n' : ' ';
      continue;
    }
    if (state === 'code') {
      if (char === '/' && next === '/') { output += '  '; index += 1; state = 'line_comment'; continue; }
      if (char === '/' && next === '*') { output += '  '; index += 1; state = 'block_comment'; continue; }
      if (char === "'") state = 'single';
      else if (char === '"') state = 'double';
      else if (char === '`') state = 'template';
      output += char;
      continue;
    }
    output += char;
    if (escaped) { escaped = false; continue; }
    if (char === '\\') { escaped = true; continue; }
    if ((state === 'single' && char === "'")
      || (state === 'double' && char === '"')
      || (state === 'template' && char === '`')) state = 'code';
  }
  return output;
}

function normalizedAnchor(line) {
  return String(line || '').trim().replace(/\s+/g, ' ').slice(0, 320);
}

function ownershipFor({ file, effectClass, anchor }) {
  if (file === 'services/security/whole-brain-purge.js') {
    return { ownership_status: 'RETAINED_OFFLINE_SIGNED_CEREMONY', current_owner: 'whole_brain_purge_intent_and_terminal' };
  }
  if (file === 'services/write/codebook-service.js') {
    return { ownership_status: 'DORMANT_UNREACHABLE', current_owner: null };
  }
  if (effectClass === 'credential_effect' && file === 'services/security/credential-store.js') {
    return {
      ownership_status: 'R3_CREDENTIAL_CUSTODY_START_TERMINAL',
      current_owner: 'services/security/credential-ledger.js',
    };
  }
  if (effectClass === 'durable_database' && R4_OPERATIONAL_ATOMIC_OWNERS.has(file)) {
    return { ownership_status: 'R4_OPERATIONAL_ATOMIC', current_owner: file };
  }
  if (effectClass === 'durable_database' && OFFLINE_SIGNED_MAINTENANCE_OWNERS.has(file)) {
    return { ownership_status: 'OFFLINE_SIGNED_MAINTENANCE', current_owner: file };
  }
  if (effectClass === 'durable_database' && PROVEN_ATOMIC_DATABASE_OWNERS.has(file)) {
    return { ownership_status: 'CANDIDATE_ATOMIC_EXISTING_LEDGER', current_owner: file };
  }
  if (effectClass === 'external_effect' && PROVEN_CREDENTIAL_USE_OWNERS.has(file)
      && !/execFile\s*\(\s*['"]osascript/.test(anchor)) {
    return { ownership_status: 'R5_CREDENTIAL_USE_START_TERMINAL', current_owner: 'credentialLedger' };
  }
  if (effectClass === 'durable_file' && file === 'services/security/agent-identity.js') {
    return { ownership_status: 'DORMANT_UNREACHABLE', current_owner: null };
  }
  if (effectClass === 'durable_file' && R5_FILE_EFFECT_OWNERS.has(file)) {
    return { ownership_status: 'R5_FILE_START_TERMINAL', current_owner: file };
  }
  if (effectClass === 'external_effect' && R5_EXTERNAL_EFFECT_OWNERS.has(file)) {
    return {
      ownership_status: file === 'services/orchestration/http.js'
        ? 'R5_SUBORDINATE_TRANSPORT'
        : 'R5_EXTERNAL_START_TERMINAL',
      current_owner: file === 'services/orchestration/http.js'
        ? 'verified_native_caller_action'
        : file,
    };
  }
  return { ownership_status: 'OPEN_UNRECONCILED', current_owner: null };
}

function classify({ file, kind, anchor }) {
  if (file === 'services/security/whole-brain-purge.js') return 'destructive_offline_effect';
  if (kind === 'sql') return 'durable_database';
  if (kind === 'file') return 'durable_file';
  if (kind === 'credential') return 'credential_effect';
  if (kind === 'network') return 'external_effect';
  if (kind === 'process' && /osascript/.test(anchor)) return 'external_effect';
  if (kind === 'process') return 'external_observation';
  throw new Error(`cr7_effect_kind_unclassified:${kind}`);
}

function shouldIgnoreSql(file, line) {
  if (/original_operation\s*:/.test(line)) return true;
  if (file === 'db/connection.js' && /sql\.includes|throw new Error/.test(line)) return true;
  if (file === 'services/write/quality-gate.js') return true;
  if (file === 'services/security/red-team-toolkit.js') return true;
  if (file === 'services/runtime/serving-control.js') return true;
  return false;
}

export function scanCr7EffectCensus() {
  const effects = [];
  const ordinalByAnchor = new Map();
  for (const absolute of runtimeFiles()) {
    const file = path.relative(ROOT, absolute).split(path.sep).join('/');
    const source = stripComments(fs.readFileSync(absolute, 'utf8'));
    const lines = source.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const candidates = [];
      const sqlMatch = line.includes('`') ? line.match(SQL_EFFECT) : null;
      const sqlTail = lines.slice(index, index + 8).join('\n');
      const updateHasSet = !/^UPDATE\b/i.test(String(sqlMatch?.[0] || '')) || /\bSET\b/i.test(sqlTail);
      if (sqlMatch && updateHasSet && !shouldIgnoreSql(file, line)) {
        candidates.push({ kind: 'sql', match: sqlMatch[0] });
      }
      if (FILE_EFFECT.test(line)) candidates.push({ kind: 'file', match: line.match(FILE_EFFECT)?.[1] });
      if (CREDENTIAL_EFFECT.test(line)) candidates.push({ kind: 'credential', match: line.match(CREDENTIAL_EFFECT)?.[1] });
      if (PROCESS_EFFECT.test(line)) candidates.push({ kind: 'process', match: line.match(PROCESS_EFFECT)?.[1] });
      if (NETWORK_EFFECT.test(line)
          && !/function\s+fetchWithTimeout/.test(line)
          && !/description\s*:/.test(line)
          && /(?:await\s+|return\s+|=\s*)fetch(?:WithTimeout)?\s*\(/.test(line)) {
        candidates.push({ kind: 'network', match: line.match(NETWORK_EFFECT)?.[1] });
      }
      if (NODE_NETWORK_EFFECT.test(line)) {
        candidates.push({ kind: 'network', match: line.match(NODE_NETWORK_EFFECT)?.[1] });
      }
      if (DNS_EFFECT.test(line)) {
        candidates.push({ kind: 'network', match: line.match(DNS_EFFECT)?.[1] });
      }
      for (const candidate of candidates) {
        // One AppleScript invocation is one external effect site, not both a
        // generic process and an external effect.
        if (candidate.kind === 'process' && /execFile\s*\(\s*['"]osascript['"]/.test(line)) {
          candidate.kind = 'network';
          candidate.match = 'osascript';
        }
        const anchor = normalizedAnchor(line);
        const anchorKey = `${file}\0${candidate.kind}\0${anchor}`;
        const ordinal = (ordinalByAnchor.get(anchorKey) || 0) + 1;
        ordinalByAnchor.set(anchorKey, ordinal);
        const effectClass = classify({ file, kind: candidate.kind, anchor });
        const ownership = ownershipFor({ file, effectClass, anchor });
        effects.push(Object.freeze({
          effect_id: sha256(`HOM-AIMOS-CR7-EFFECT-SITE-v1\0${anchorKey}\0${ordinal}`),
          file,
          line: index + 1,
          kind: candidate.kind,
          effect_class: effectClass,
          operation_anchor: String(candidate.match || ''),
          source_anchor: anchor,
          ...ownership,
          required_binding: effectClass === 'durable_database'
            ? 'same_restricted_transaction_or_exact_row_result_terminal'
            : effectClass === 'destructive_offline_effect'
              ? 'signed_offline_intent_and_terminal_with_recovery_disposition'
              : 'verified_start_terminal_with_indeterminate_and_orphan_reconciliation',
        }));
      }
    }
  }
  effects.sort((left, right) => left.file.localeCompare(right.file)
    || left.line - right.line || left.kind.localeCompare(right.kind));
  const effectRoot = sha256(Buffer.from(canonicalJson(effects.map((effect) => ({
    effect_id: effect.effect_id,
    file: effect.file,
    line: effect.line,
    kind: effect.kind,
    effect_class: effect.effect_class,
    ownership_status: effect.ownership_status,
    source_anchor: effect.source_anchor,
  }))), 'utf8'));
  const byClass = {};
  const byStatus = {};
  for (const effect of effects) {
    byClass[effect.effect_class] = (byClass[effect.effect_class] || 0) + 1;
    byStatus[effect.ownership_status] = (byStatus[effect.ownership_status] || 0) + 1;
  }
  return Object.freeze({
    schema: 'hom.aimos.cr7-executable-effect-census/v1',
    source_file_count: runtimeFiles().length,
    effect_site_count: effects.length,
    unclassified_effect_site_count: effects.filter((effect) => !effect.effect_class).length,
    effect_root_sha256: effectRoot,
    by_class: Object.freeze(byClass),
    by_ownership_status: Object.freeze(byStatus),
    effects: Object.freeze(effects),
  });
}

function main() {
  const result = scanCr7EffectCensus();
  if (result.source_file_count !== 357) throw new Error(`cr7_runtime_source_census_changed:${result.source_file_count}`);
  if (result.unclassified_effect_site_count !== 0) throw new Error('cr7_unclassified_effect_site');
  if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
  else console.log(JSON.stringify({
    schema: result.schema,
    source_file_count: result.source_file_count,
    effect_site_count: result.effect_site_count,
    unclassified_effect_site_count: result.unclassified_effect_site_count,
    effect_root_sha256: result.effect_root_sha256,
    by_class: result.by_class,
    by_ownership_status: result.by_ownership_status,
  }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
