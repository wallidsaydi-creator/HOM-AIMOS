import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

import { fetchWithTimeout } from './http.js';
import {
  discoverActiveProviders,
  getProviderRegistry,
  listProviderModels as listProviderModelsFromCore
} from '../core/providers.js';
import {
  TASK_TYPES,
  getModelPreference,
  getModelPreferences
} from './model-preferences.js';
import { getRunEventsSince } from './run-events.js';
import {
  listSkills as listRuntimeSkills,
  loadSkillsFromDisk
} from './skills-runtime.js';
import { peekCachedCredential } from '../security/credential-cache.js';
import { systemConfigStore } from '../security/system-config-store.js';

const BRAIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const REPO_ROOT = path.resolve(BRAIN_ROOT, '..', '..');
const CODEX_HOME = path.join(os.homedir(), '.codex');
const CODEX_CONFIG_PATH = path.join(CODEX_HOME, 'config.toml');
const CODEX_PLUGIN_CACHE_ROOT = path.join(CODEX_HOME, 'plugins', 'cache');
const MARKETPLACE_MANIFEST_RELATIVE_PATHS = [
  '.agents/plugins/marketplace.json',
  '.claude-plugin/marketplace.json'
];
const SKILL_ROOTS = [
  path.join(BRAIN_ROOT, 'skills'),
  path.join(REPO_ROOT, '.agents', 'skills'),
  path.join(os.homedir(), '.agents', 'skills'),
  path.join(CODEX_HOME, 'skills')
];
const COMMAND_CONFIG_SCHEMA = Object.freeze({
  retrieval_threshold: {
    key: 'retrieval_threshold',
    type: 'number',
    defaultValue: 0.72,
    min: 0,
    max: 1,
    description: 'Similarity threshold for retrieval and memory recall.'
  },
  dream_frequency: {
    key: 'dream_frequency',
    type: 'number',
    defaultValue: 3,
    min: 0,
    max: 24,
    description: 'Background consolidation cadence in hours.'
  },
  provider_default: {
    key: 'provider_default',
    type: 'string',
    defaultValue: '',
    description: 'Active provider context for slash command selection.'
  },
  memory_controls_enabled: {
    key: 'memory_controls_enabled',
    type: 'boolean',
    defaultValue: true,
    description: 'Master toggle for memory-aware orchestration controls.'
  },
  aimos_runtime_shadow_telemetry: {
    key: 'aimos_runtime_shadow_telemetry',
    type: 'boolean',
    defaultValue: true,
    description: 'Keep runtime telemetry in the shadow inspector instead of the transcript.'
  },
  aimos_runtime_live_sync: {
    key: 'aimos_runtime_live_sync',
    type: 'boolean',
    defaultValue: true,
    description: 'Emit SYSTEM_SYNC events for TUI-originated runtime config changes.'
  }
});

function toConfigPluginId(marketplaceName, pluginName) {
  return `${pluginName}@${marketplaceName}`;
}

function defaultConfigValues() {
  return Object.fromEntries(
    Object.values(COMMAND_CONFIG_SCHEMA).map((entry) => [entry.key, entry.defaultValue])
  );
}

function loadCommandCenterConfig() {
  return {
    ...defaultConfigValues(),
    provider_default: systemConfigStore.readConfigString('LLM_PROVIDER') || '',
  };
}

function buildConfigEntries() {
  const values = loadCommandCenterConfig();
  return Object.values(COMMAND_CONFIG_SCHEMA).map((schema) => ({
    key: schema.key,
    type: schema.type,
    description: schema.description,
    defaultValue: schema.defaultValue,
    value: values[schema.key]
  }));
}

export function getCommandConfigSchema() {
  return Object.values(COMMAND_CONFIG_SCHEMA);
}

export function listCommandConfig() {
  return buildConfigEntries();
}

export function getCommandConfigEntry(key) {
  const entry = buildConfigEntries().find((item) => item.key === key);
  if (!entry) throw new Error(`Unknown config key '${key}'`);
  return entry;
}

export async function listProviderModels(providerId) {
  return listProviderModelsFromCore(providerId);
}

export async function listProviders() {
  const registry = getProviderRegistry();
  const providerIds = Object.keys(registry).sort((left, right) => left.localeCompare(right));
  return Promise.all(providerIds.map((providerId) => resolveProviderCapability(providerId)));
}

function getSelectedProvider() {
  return String(
    systemConfigStore.readConfigString('LLM_PROVIDER')
    || getModelPreference('chat')?.provider
    || ''
  ).trim();
}

function hasDirectCredential(providerId) {
  switch (String(providerId || '').trim().toLowerCase()) {
    case 'anthropic':
      return !!peekCachedCredential('anthropic_api_key');
    case 'gemini':
      return !!(peekCachedCredential('gemini_api_key') || peekCachedCredential('google_api_key'));
    case 'openai':
      return !!peekCachedCredential('openai_api_key');
    case 'codex':
      return !!peekCachedCredential('codex_api_key') || !!peekCachedCredential('openai_api_key');
    case 'openrouter':
      return !!peekCachedCredential('openrouter_api_key');
    case 'groq':
      return !!peekCachedCredential('groq_api_key');
    case 'deepseek':
      return !!peekCachedCredential('deepseek_api_key');
    case 'together':
      return !!peekCachedCredential('together_api_key');
    case 'xai':
      return !!peekCachedCredential('xai_api_key');
    case 'venice':
      return !!peekCachedCredential('venice_api_key');
    case 'perplexity':
      return peekCachedCredential('perplexity_api_key');
    default:
      return false;
  }
}

function authModeForProvider(providerId, providerType) {
  const normalizedProvider = String(providerId || '').trim().toLowerCase();
  if (normalizedProvider === 'ollama' || normalizedProvider === 'lmstudio') return 'local';
  if (providerType === 'openai_compatible' || providerType === 'adapter') return 'api_key';
  return 'manual';
}

async function resolveProviderCapability(providerId) {
  const provider = String(providerId || '').trim().toLowerCase();
  const registry = getProviderRegistry();
  const discovered = discoverActiveProviders().find((item) => item.provider === provider);
  const registryEntry = registry[provider];

  if (!registryEntry && !discovered) {
    throw new Error(`Unknown provider '${provider}'`);
  }

  const providerType = registryEntry?.type || discovered?.type || null;
  const authMode = authModeForProvider(provider, providerType);
  const directCredential = hasDirectCredential(provider);
  const localOrCliConnected = authMode === 'local' || authMode === 'cli';

  let available = !!discovered?.active;
  let connected = localOrCliConnected ? available : (available || null);
  let reason = discovered?.reason || null;

  if (directCredential) {
    available = true;
    connected = true;
    reason = 'configured via verified Keychain credential';
  } else if (authMode === 'api_key') {
    connected = available;
  }

  return {
    providerId: provider,
    type: providerType,
    authMode,
    available,
    activeContext: provider === getSelectedProvider(),
    connected,
    reason,
    defaultModel: registryEntry?.defaultModel || discovered?.defaultModel || null,
    modelHints: registryEntry?.modelHints || discovered?.modelHints || []
  };
}

function readCodexConfigText() {
  try {
    if (!fs.existsSync(CODEX_CONFIG_PATH)) return '';
    return fs.readFileSync(CODEX_CONFIG_PATH, 'utf8');
  } catch {
    return '';
  }
}

function parseEnabledPluginsFromToml(text) {
  const pluginMap = new Map();
  let currentPluginId = null;

  for (const rawLine of String(text || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    const sectionMatch = line.match(/^\[plugins\."(.+)"\]$/);
    if (sectionMatch) {
      currentPluginId = sectionMatch[1];
      if (!pluginMap.has(currentPluginId)) pluginMap.set(currentPluginId, false);
      continue;
    }
    if (!currentPluginId) continue;
    const enabledMatch = line.match(/^enabled\s*=\s*(true|false)$/i);
    if (enabledMatch) {
      pluginMap.set(currentPluginId, enabledMatch[1].toLowerCase() === 'true');
    }
  }

  return pluginMap;
}

function normalizeMarketplacePluginSource(manifestPath, plugin) {
  if (typeof plugin?.source === 'string') {
    return path.resolve(path.dirname(manifestPath), plugin.source);
  }
  if (plugin?.source?.source === 'local' && plugin?.source?.path) {
    return path.resolve(path.dirname(manifestPath), plugin.source.path);
  }
  if (plugin?.source?.path) {
    return path.resolve(path.dirname(manifestPath), plugin.source.path);
  }
  return null;
}

function listMarketplaceManifestCandidates() {
  const roots = [
    REPO_ROOT,
    os.homedir()
  ];

  return roots.flatMap((root) =>
    MARKETPLACE_MANIFEST_RELATIVE_PATHS.map((relativePath) => path.join(root, relativePath))
  );
}

function loadMarketplacePlugins() {
  const entries = [];

  for (const manifestPath of listMarketplaceManifestCandidates()) {
    if (!fs.existsSync(manifestPath)) continue;
    try {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      const marketplaceName = String(manifest?.name || '').trim();
      if (!marketplaceName || !Array.isArray(manifest?.plugins)) continue;
      for (const plugin of manifest.plugins) {
        const pluginName = String(plugin?.name || '').trim();
        if (!pluginName) continue;
        const sourcePath = normalizeMarketplacePluginSource(manifestPath, plugin);
        if (!sourcePath) continue;
        entries.push({
          id: toConfigPluginId(marketplaceName, pluginName),
          ref: `${marketplaceName}/${pluginName}`,
          marketplaceName,
          pluginName,
          sourcePath,
          manifestPath,
          interface: plugin?.interface || null,
          description: String(
            plugin?.description || manifest?.metadata?.description || manifest?.description || ''
          ).trim()
        });
      }
    } catch {
      // Skip invalid marketplace manifests; surfaced as unavailable rather than breaking the shell.
    }
  }

  return entries;
}

function parsePluginCapabilities(pluginRoot, manifest) {
  const skills = [];
  const skillRoot = manifest?.skills
    ? path.resolve(pluginRoot, manifest.skills)
    : path.resolve(pluginRoot, 'skills');
  if (fs.existsSync(skillRoot)) {
    scanSkillMarkdownFiles(skillRoot, 0, []).forEach((skillPath) => {
      skills.push(path.basename(path.dirname(skillPath)));
    });
  }

  const apps = [];
  const appPath = manifest?.apps ? path.resolve(pluginRoot, manifest.apps) : null;
  if (appPath && fs.existsSync(appPath)) {
    try {
      const payload = JSON.parse(fs.readFileSync(appPath, 'utf8'));
      for (const appName of Object.keys(payload?.apps || {})) {
        apps.push(appName);
      }
    } catch {
      // Ignore invalid app metadata.
    }
  }

  const mcpServers = [];
  const mcpPath = path.resolve(pluginRoot, '.mcp.json');
  if (fs.existsSync(mcpPath)) {
    try {
      const payload = JSON.parse(fs.readFileSync(mcpPath, 'utf8'));
      for (const serverName of Object.keys(payload?.mcpServers || payload?.servers || {})) {
        mcpServers.push(serverName);
      }
    } catch {
      // Ignore invalid MCP metadata.
    }
  }

  return {
    skills: Array.from(new Set(skills)),
    apps: Array.from(new Set(apps)),
    mcpServers: Array.from(new Set(mcpServers))
  };
}

function scanInstalledPlugins() {
  const entries = [];
  if (!fs.existsSync(CODEX_PLUGIN_CACHE_ROOT)) return entries;

  const marketplaceDirs = fs.readdirSync(CODEX_PLUGIN_CACHE_ROOT, { withFileTypes: true })
    .filter((entry) => entry.isDirectory());

  for (const marketplaceDir of marketplaceDirs) {
    const marketplaceName = marketplaceDir.name;
    const marketplacePath = path.join(CODEX_PLUGIN_CACHE_ROOT, marketplaceName);
    const pluginDirs = fs.readdirSync(marketplacePath, { withFileTypes: true })
      .filter((entry) => entry.isDirectory());

    for (const pluginDir of pluginDirs) {
      const pluginName = pluginDir.name;
      const pluginPath = path.join(marketplacePath, pluginName);
      const versionDirs = fs.readdirSync(pluginPath, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .sort((left, right) => right.name.localeCompare(left.name));

      for (const versionDir of versionDirs) {
        const rootPath = path.join(pluginPath, versionDir.name);
        const manifestPath = path.join(rootPath, '.codex-plugin', 'plugin.json');
        if (!fs.existsSync(manifestPath)) continue;
        try {
          const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
          const capabilities = parsePluginCapabilities(rootPath, manifest);
          entries.push({
            id: toConfigPluginId(marketplaceName, pluginName),
            ref: `${marketplaceName}/${pluginName}`,
            marketplaceName,
            pluginName,
            cachePath: rootPath,
            manifest,
            capabilities
          });
          break;
        } catch {
          // Keep scanning versions if one is invalid.
        }
      }
    }
  }

  return entries;
}

export function listPlugins() {
  const discoverable = loadMarketplacePlugins();
  const installed = scanInstalledPlugins();
  const enabledPlugins = parseEnabledPluginsFromToml(readCodexConfigText());
  const pluginMap = new Map();

  for (const plugin of discoverable) {
    pluginMap.set(plugin.id, {
      id: plugin.id,
      ref: plugin.ref,
      marketplace: plugin.marketplaceName,
      plugin: plugin.pluginName,
      displayName: plugin.interface?.displayName || plugin.pluginName,
      description: plugin.description,
      status: 'discoverable',
      discoverable: true,
      installed: false,
      loaded: enabledPlugins.get(plugin.id) === true,
      skills: [],
      apps: [],
      mcpServers: [],
      error: null
    });
  }

  for (const installedPlugin of installed) {
    const entry = pluginMap.get(installedPlugin.id) || {
      id: installedPlugin.id,
      ref: installedPlugin.ref,
      marketplace: installedPlugin.marketplaceName,
      plugin: installedPlugin.pluginName,
      displayName: installedPlugin.manifest?.interface?.displayName || installedPlugin.pluginName,
      description: String(
        installedPlugin.manifest?.interface?.shortDescription
          || installedPlugin.manifest?.description
          || ''
      ).trim(),
      discoverable: false,
      installed: true,
      loaded: enabledPlugins.get(installedPlugin.id) === true,
      skills: [],
      apps: [],
      mcpServers: [],
      error: null
    };

    entry.installed = true;
    entry.loaded = enabledPlugins.get(installedPlugin.id) === true;
    entry.status = entry.loaded ? 'loaded' : 'installed';
    entry.cachePath = installedPlugin.cachePath;
    entry.skills = installedPlugin.capabilities.skills;
    entry.apps = installedPlugin.capabilities.apps;
    entry.mcpServers = installedPlugin.capabilities.mcpServers;
    pluginMap.set(installedPlugin.id, entry);
  }

  for (const [pluginId, enabled] of enabledPlugins.entries()) {
    if (!pluginMap.has(pluginId)) {
      const [pluginName, marketplaceName] = pluginId.includes('@')
        ? pluginId.split('@')
        : [pluginId, 'unknown'];
      pluginMap.set(pluginId, {
        id: pluginId,
        ref: `${marketplaceName}/${pluginName}`,
        marketplace: marketplaceName,
        plugin: pluginName,
        displayName: pluginId,
        description: '',
        status: enabled ? 'error' : 'discoverable',
        discoverable: false,
        installed: false,
        loaded: enabled,
        skills: [],
        apps: [],
        mcpServers: [],
        error: enabled ? 'Enabled in config.toml but missing from plugin cache' : null
      });
    }
  }

  return Array.from(pluginMap.values()).sort((left, right) => left.id.localeCompare(right.id));
}

function parseSimpleFrontmatter(text) {
  const lines = String(text || '').split(/\r?\n/);
  if (lines[0]?.trim() !== '---') return { metadata: {}, body: text };
  const metadata = {};
  let index = 1;
  for (; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim() === '---') {
      index += 1;
      break;
    }
    const match = line.match(/^([A-Za-z0-9_.-]+):\s*(.+)$/);
    if (match) {
      metadata[match[1]] = match[2].trim().replace(/^["']|["']$/g, '');
    }
  }
  return {
    metadata,
    body: lines.slice(index).join('\n')
  };
}

function parseSimpleYamlFile(filePath) {
  if (!fs.existsSync(filePath)) return {};
  try {
    const metadata = {};
    const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const match = line.match(/^([A-Za-z0-9_.-]+):\s*(.+)$/);
      if (!match) continue;
      metadata[match[1]] = match[2].trim().replace(/^["']|["']$/g, '');
    }
    return metadata;
  } catch {
    return {};
  }
}

function readMarkdownSkillMetadata(skillPath, rootPath) {
  const text = fs.readFileSync(skillPath, 'utf8');
  const { metadata, body } = parseSimpleFrontmatter(text);
  const skillDir = path.dirname(skillPath);
  const yamlMetadata = parseSimpleYamlFile(path.join(skillDir, 'agents', 'openai.yaml'));
  const description = String(
    metadata.description
      || yamlMetadata.description
      || body
        .split(/\r?\n/)
        .map((line) => line.trim())
        .find((line) => line && !line.startsWith('#'))
      || ''
  ).trim();

  return {
    name: String(metadata.name || yamlMetadata.name || path.basename(skillDir)).trim(),
    displayName: String(
      metadata.display_name || metadata.displayName || yamlMetadata.display_name || ''
    ).trim() || null,
    description,
    path: skillPath,
    scope: classifySkillScope(rootPath),
    type: 'markdown',
    dependencies: metadata.dependencies || yamlMetadata.dependencies || null,
    policy: metadata.policy || yamlMetadata.policy || null
  };
}

function classifySkillScope(rootPath) {
  if (rootPath === SKILL_ROOTS[0]) return 'repo';
  if (rootPath === SKILL_ROOTS[1]) return 'repo-agents';
  if (rootPath === SKILL_ROOTS[2]) return 'user-agents';
  return 'user-codex';
}

function scanSkillMarkdownFiles(dirPath, depth = 0, out = []) {
  if (depth > 8 || !fs.existsSync(dirPath)) return out;
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      scanSkillMarkdownFiles(fullPath, depth + 1, out);
    } else if (entry.isFile() && entry.name === 'SKILL.md') {
      out.push(fullPath);
    }
  }
  return out;
}

export function listUnifiedSkills(agentId = 'anonymous') {
  loadSkillsFromDisk();
  const runtimeSkills = listRuntimeSkills();
  const deduped = new Map();

  for (const rootPath of SKILL_ROOTS) {
    if (!fs.existsSync(rootPath)) continue;
    const markdownFiles = scanSkillMarkdownFiles(rootPath, 0, []);
    for (const skillPath of markdownFiles) {
      try {
        const skill = readMarkdownSkillMetadata(skillPath, rootPath);
        const key = skill.name.toLowerCase();
        if (!deduped.has(key)) {
          deduped.set(key, skill);
        }
      } catch {
        // Ignore unreadable markdown skills.
      }
    }
  }

  for (const skill of runtimeSkills) {
    const normalized = {
      name: skill.name,
      displayName: null,
      description: skill.description || '',
      path: path.join(BRAIN_ROOT, 'skills', `${skill.name}.json`),
      scope: 'repo',
      type: 'runtime-json',
      dependencies: null,
      policy: skill.policy || null
    };
    const key = normalized.name.toLowerCase();
    if (!deduped.has(key)) {
      deduped.set(key, normalized);
    } else if (deduped.get(key)?.type !== 'runtime-json') {
      deduped.set(key, { ...normalized, shadowedBy: deduped.get(key)?.path || null });
    }
  }

  return Array.from(deduped.values())
    .map((skill) => ({
      ...skill,
      active: skill.type === 'runtime-json'
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

export function queryTelemetry({ afterEventId = null, limit = 100 } = {}) {
  const events = getRunEventsSince(afterEventId, limit);
  return {
    afterEventId,
    latestEventId: events.length ? events[events.length - 1].id : afterEventId,
    events
  };
}

export async function getCommandCenterSnapshot(agentId = 'anonymous', telemetryQuery = {}) {
  return {
    providers: await listProviders(),
    activeProvider: getSelectedProvider() || null,
    selectedModel: getModelPreference('chat'),
    modelPreferences: getModelPreferences(),
    config: listCommandConfig(),
    plugins: listPlugins(),
    skills: listUnifiedSkills(agentId),
    telemetry: queryTelemetry(telemetryQuery),
    taskTypes: [...TASK_TYPES]
  };
}
