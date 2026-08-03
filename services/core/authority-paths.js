// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: meta-improvement.js, bootstrap scripts
// → Calls: fs, path
// Pipeline: META-IMPROVEMENT | Position: Authority path resolution
// ─────────────────────────────────────────────────────────────────────────────
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BRAIN_ROOT = path.resolve(__dirname, '..');
const AUTHORITY_PATH = path.resolve(BRAIN_ROOT, 'architecture-authority.json');
// ACTUAL_BRAIN_ROOT is the directory containing architecture-authority.json (one level
// above services/). Used to resolve template-form relative paths (./  ../) — those
// paths are relative to the brain root, NOT to services/. The existing BRAIN_ROOT
// variable is actually services/ (legacy misnomer) and is kept for AUTHORITY_PATH
// resolution which works through the services/architecture-authority.json symlink.
const ACTUAL_BRAIN_ROOT = path.resolve(__dirname, '..', '..');

function normalizeString(value) {
  return String(value || '').trim();
}

function stripPlaceholderSegments(input) {
  return normalizeString(input).replace(/<[^>]+>/g, '__placeholder__');
}

function normalizeForCompare(input) {
  return stripPlaceholderSegments(input)
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .replace(/\/$/, '')
    .toLowerCase();
}

function isAbsolutePathCandidate(candidate) {
  return path.isAbsolute(candidate) || /^[A-Za-z]:[\\/]/.test(candidate);
}

function escapeRegex(input) {
  return String(input || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function loadArchitectureAuthority() {
  return JSON.parse(fs.readFileSync(AUTHORITY_PATH, 'utf8'));
}

export function getAuthorityFilePath() {
  return AUTHORITY_PATH;
}

export function collectLogicalPaths(authority = loadArchitectureAuthority()) {
  const paths = {};

  for (const [key, entry] of Object.entries(authority.authority_layers || {})) {
    if (entry?.path) paths[key] = entry.path;
  }

  for (const [key, value] of Object.entries(authority.path_authority?.logical_paths || {})) {
    if (value) paths[key] = value;
  }

  for (const [key, value] of Object.entries(authority.documents || {})) {
    if (value) paths[key] = value;
  }

  if (authority.boot?.cwd) paths.boot_cwd = authority.boot.cwd;

  return paths;
}

export function resolveAuthorityPath(key, authority = loadArchitectureAuthority()) {
  const logicalPaths = collectLogicalPaths(authority);
  return logicalPaths[key] || null;
}

export function getStaleAliases(authority = loadArchitectureAuthority()) {
  return Array.isArray(authority.path_authority?.stale_aliases)
    ? authority.path_authority.stale_aliases
    : [];
}

export function absolutizePath(candidate, authority = loadArchitectureAuthority()) {
  const normalized = normalizeString(candidate);
  if (!normalized) return '';
  if (isAbsolutePathCandidate(normalized)) return path.resolve(normalized);
  // Template-form relative paths (./  ../  .  ..) resolve against ACTUAL_BRAIN_ROOT —
  // the directory containing architecture-authority.json. This lets the
  // template ship portable relative paths that resolve correctly regardless of CWD.
  if (normalized === '.' || normalized === '..' || normalized.startsWith('./') || normalized.startsWith('../')) {
    return path.resolve(ACTUAL_BRAIN_ROOT, normalized);
  }
  // Other relative paths (e.g. "backend/scripts" extracted from text) resolve
  // against repo_root if the authority declares one, else CWD (legacy behavior).
  const repoRoot = resolveAuthorityPath('repo_root', authority);
  return repoRoot ? path.resolve(repoRoot, normalized) : path.resolve(normalized);
}

function safeStat(candidate) {
  try {
    return fs.statSync(candidate);
  } catch {
    return null;
  }
}

export function resolveWorksetPaths(workset = {}, authority = loadArchitectureAuthority()) {
  const buckets = ['logicalPaths', 'paths', 'directDependencies', 'tests', 'docs'];
  const roots = new Set();
  const files = new Set();
  const resolvedEntries = [];

  for (const bucket of buckets) {
    const values = Array.isArray(workset?.[bucket]) ? workset[bucket] : [];
    for (const rawValue of values) {
      const value = normalizeString(rawValue);
      if (!value) continue;

      const logicalMatch = resolveAuthorityPath(value, authority);
      const candidate = absolutizePath(logicalMatch || value, authority);
      if (!candidate) continue;

      const stat = safeStat(candidate);
      if (stat?.isDirectory()) {
        roots.add(candidate);
      } else {
        files.add(candidate);
      }

      resolvedEntries.push({
        bucket,
        input: value,
        resolved: candidate,
        kind: stat?.isDirectory() ? 'directory' : 'file',
        exists: Boolean(stat),
      });
    }
  }

  return {
    roots: Array.from(roots).sort(),
    files: Array.from(files).sort(),
    resolvedEntries,
  };
}

export function isPathWithinWorkset(candidate, resolvedWorkset, authority = loadArchitectureAuthority()) {
  const absolute = absolutizePath(candidate, authority);
  if (!absolute) return false;

  if (resolvedWorkset?.files?.includes(absolute)) return true;
  return Array.isArray(resolvedWorkset?.roots)
    && resolvedWorkset.roots.some((root) => absolute === root || absolute.startsWith(`${root}${path.sep}`));
}

export function validateMutationOperations(operations = [], resolvedWorkset, authority = loadArchitectureAuthority()) {
  const allowed = [];
  const blocked = [];

  for (const operation of Array.isArray(operations) ? operations : []) {
    const candidatePath = normalizeString(
      operation?.path
      || operation?.targetPath
      || operation?.file
      || operation?.target
    );

    if (!candidatePath) {
      blocked.push({
        operation,
        reason: 'missing_path',
      });
      continue;
    }

    const absolute = absolutizePath(candidatePath, authority);
    if (!isPathWithinWorkset(absolute, resolvedWorkset, authority)) {
      blocked.push({
        operation,
        path: candidatePath,
        absolute,
        reason: 'outside_declared_workset',
      });
      continue;
    }

    allowed.push({
      operation,
      path: candidatePath,
      absolute,
    });
  }

  return { allowed, blocked };
}

export function matchStaleAlias(candidate, authority = loadArchitectureAuthority()) {
  const normalizedCandidate = normalizeForCompare(candidate);
  if (!normalizedCandidate) return null;

  for (const aliasEntry of getStaleAliases(authority)) {
    const alias = normalizeString(aliasEntry.alias);
    const aliasNormalized = normalizeForCompare(alias);
    if (!aliasNormalized) continue;

    if (normalizedCandidate === aliasNormalized || normalizedCandidate.startsWith(`${aliasNormalized}/`)) {
      const suffix = normalizedCandidate.slice(aliasNormalized.length).replace(/^\/+/, '');
      const canonicalBase = normalizeString(aliasEntry.canonical);
      const canonical = suffix ? `${canonicalBase.replace(/\/+$/, '')}/${suffix}` : canonicalBase;
      return {
        alias: aliasEntry.alias,
        canonical,
        reason: aliasEntry.reason || 'stale path alias',
      };
    }
  }

  return null;
}

export function extractPathCandidates(text) {
  const input = String(text || '');
  const matches = new Set();
  const patterns = [
    /\/Users\/[^\s"'`]+/g,
    /\b(?:backend|\.claude)\/[^\s"'`]+/g,
  ];

  for (const pattern of patterns) {
    for (const match of input.matchAll(pattern)) {
      matches.add(match[0].replace(/[),.;:}]+$/, ''));
    }
  }

  return Array.from(matches);
}

export function findStalePathReferencesInText(text, authority = loadArchitectureAuthority()) {
  const input = String(text || '');
  const findings = [];

  for (const aliasEntry of getStaleAliases(authority)) {
    const alias = normalizeString(aliasEntry.alias);
    if (!alias) continue;
    const pattern = new RegExp(`(^|[^A-Za-z0-9_./-])(${escapeRegex(alias)}(?:/[A-Za-z0-9._<>-]+)*)`, 'gi');

    for (const match of input.matchAll(pattern)) {
      const candidate = match[2];
      const stale = matchStaleAlias(candidate, authority);
      if (!stale) continue;
      findings.push(stale);
    }
  }

  return findings.filter((entry, index, array) =>
    array.findIndex((candidate) => candidate.alias === entry.alias && candidate.canonical === entry.canonical) === index
  );
}

export function verifyPathReferencesInText(text, authority = loadArchitectureAuthority()) {
  const stale = findStalePathReferencesInText(text, authority);
  const stalePaths = new Set(
    stale.flatMap((entry) => [normalizeForCompare(entry.alias), normalizeForCompare(entry.canonical)])
  );

  const canonicalBases = getStaleAliases(authority)
    .map((entry) => normalizeForCompare(entry.canonical))
    .filter(Boolean);

  const missing = extractPathCandidates(text)
    .filter((candidate) => !stalePaths.has(normalizeForCompare(candidate)))
    .filter((candidate) => {
      if (candidate.includes('<') || candidate.includes('>') || candidate.includes('*') || candidate.includes('${')) return false;
      const normalized = normalizeForCompare(candidate);
      if (canonicalBases.some((base) => normalized === base || normalized.startsWith(`${base}/`))) return false;
      const absolute = absolutizePath(candidate, authority);
      return absolute && !fs.existsSync(absolute);
    })
    .map((candidate) => ({
      path: candidate,
      absolute: absolutizePath(candidate, authority),
    }));

  return { stale, missing };
}
