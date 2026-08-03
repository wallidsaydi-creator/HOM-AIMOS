import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { query } from '../db/connection.js';
import { validatePipelines } from '../services/pipeline-manifest.js';

import {
  getCommandCenterSnapshot,
  getCommandConfigEntry,
  getCommandConfigSchema,
  listProviderModels
} from '../services/orchestration/command-center.js';

const router = express.Router();
const BRAIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SERVICES_ROOT = path.join(BRAIN_ROOT, 'services');
const ROUTES_ROOT = path.join(BRAIN_ROOT, 'routes');

function resolveAgentId(req) {
  // R1: identity is the verified cert only (req.agentId). The previous
  // query/body fallback let a caller attribute command-center actions to any
  // agent id it typed. 'anonymous' is used only for internal-token callers.
  return String(req.agentId || 'anonymous').trim();
}

function walkFiles(root, predicate) {
  const files = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(fullPath, predicate));
    } else if (entry.isFile() && predicate(fullPath)) {
      files.push(fullPath);
    }
  }
  return files.sort((a, b) => a.localeCompare(b));
}

function firstPathSegment(relativePath) {
  const parts = relativePath.split(path.sep);
  return parts.length > 1 ? parts[0] : '_root';
}

function countRouteDeclarations(source) {
  return (source.match(/\brouter\.(?:get|post|put|delete|patch|use)\s*\(/g) || []).length;
}

function buildServiceCensus({ servicesRoot = SERVICES_ROOT } = {}) {
  const files = walkFiles(servicesRoot, (filePath) => filePath.endsWith('.js') || filePath.endsWith('.ts'));
  const domains = {};
  for (const filePath of files) {
    const domain = firstPathSegment(path.relative(servicesRoot, filePath));
    domains[domain] = (domains[domain] || 0) + 1;
  }
  return {
    total: files.length,
    domains: Object.fromEntries(Object.entries(domains).sort(([left], [right]) => left.localeCompare(right)))
  };
}

function buildRouteCensus({ routesRoot = ROUTES_ROOT } = {}) {
  const files = walkFiles(routesRoot, (filePath) => filePath.endsWith('.js'));
  const surfaces = files.map((filePath) => {
    const source = fs.readFileSync(filePath, 'utf8');
    return {
      name: path.relative(routesRoot, filePath).split(path.sep).join('/'),
      declarations: countRouteDeclarations(source),
      size_bytes: fs.statSync(filePath).size
    };
  }).sort((left, right) => right.declarations - left.declarations || left.name.localeCompare(right.name));
  return {
    files: files.length,
    declarations: surfaces.reduce((sum, surface) => sum + surface.declarations, 0),
    surfaces
  };
}

async function buildMemoryArchitecture({ queryImpl = query } = {}) {
  const result = await queryImpl('SELECT COUNT(*) AS total FROM aimos_memories');
  const total = Number(result?.rows?.[0]?.total || 0);
  return {
    authority: 'aimos_memories',
    total_memories: Number.isFinite(total) ? total : 0,
    retrieval: {
      owner: 'services/retrieval',
      primary_entry: 'services/retrieval/native-recall-pipeline.js:executeNativeRecall',
      authority_service: 'services/retrieval/native-recall.js',
      freshness_service: 'services/temporal/freshness-metadata.js'
    },
    governance: {
      retention_law: 'services/governance/aladdin-compliance.js',
      deletion_policy: 'delete/ttl/decay are not operator actions in HOM Control Center'
    }
  };
}

function buildRuntimeStatus() {
  return {
    aimos_backend_path: BRAIN_ROOT,
    health_path: '/health',
    protected_auth: 'native_certificate_envelope',
    command_center_route: '/command-center/aimos-control-center',
    product_vessel: 'HOM Tauri'
  };
}

function buildOperatorActions() {
  return [
    {
      id: 'probe.health',
      label: 'Probe Aimos health',
      method: 'GET',
      path: '/health',
      auth: 'none',
      mutation: false
    },
    {
      id: 'probe.signed_recall',
      label: 'Probe signed recall',
      method: 'POST',
      path: '/aimos/recall',
      body: {
        query: 'HOM control center',
        limit: 1,
        projection: 'demo_redacted'
      },
      auth: 'native_certificate_envelope',
      mutation: false
    },
    {
      id: 'refresh.control_center_snapshot',
      label: 'Refresh Control Center snapshot',
      method: 'GET',
      path: '/command-center/aimos-control-center',
      auth: 'native_certificate_envelope',
      mutation: false
    }
  ];
}

export async function buildAimosControlCenterSnapshot({
  now = () => new Date(),
  queryImpl = query,
  pipelineValidationImpl = validatePipelines
} = {}) {
  const pipelineValidation = await pipelineValidationImpl();
  return {
    artifact_kind: 'hom_aimos_control_center_snapshot_v1',
    product_name: 'HOM',
    generated_at: now().toISOString(),
    read_only: true,
    runtime_status: buildRuntimeStatus(),
    service_census: buildServiceCensus(),
    route_census: buildRouteCensus(),
    memory_architecture: await buildMemoryArchitecture({ queryImpl }),
    pipeline_manifest: {
      path: 'services/pipeline-manifest.js',
      valid: Boolean(pipelineValidation?.valid),
      total: Number(pipelineValidation?.total || 0),
      ok: Number(pipelineValidation?.ok || 0)
    },
    operator_actions: buildOperatorActions()
  };
}

router.get('/aimos-control-center', async (_req, res) => {
  try {
    res.json({
      success: true,
      snapshot: await buildAimosControlCenterSnapshot()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error?.message || String(error),
      snapshot: null
    });
  }
});

router.get('/snapshot', async (req, res) => {
  const afterEventId = req.query?.afterEventId || null;
  const limit = Number(req.query?.limit || 100);
  res.json({
    success: true,
    snapshot: await getCommandCenterSnapshot(resolveAgentId(req), {
      afterEventId,
      limit
    })
  });
});

router.get('/providers', async (req, res) => {
  const snapshot = await getCommandCenterSnapshot(resolveAgentId(req), {
    afterEventId: null,
    limit: 50
  });
  res.json({
    success: true,
    providers: snapshot.providers,
    activeProvider: snapshot.activeProvider
  });
});

router.get('/models', async (req, res) => {
  const provider = String(req.query?.provider || '').trim();
  if (!provider) {
    return res.status(400).json({ success: false, error: 'provider is required' });
  }
  const result = await listProviderModels(provider);
  res.json({ success: true, ...result });
});

router.post('/providers/select', async (req, res) => {
  return res.status(410).json({
    success: false,
    error: 'unsigned provider selection retired; use the master-signed LLM_PROVIDER configuration ceremony',
  });
});

router.post('/models/select', async (req, res) => {
  return res.status(410).json({
    success: false,
    error: 'unsigned model selection retired; use the master-signed model preference configuration ceremony',
  });
});

router.get('/config/schema', async (_req, res) => {
  res.json({
    success: true,
    schema: getCommandConfigSchema()
  });
});

router.get('/config', async (req, res) => {
  const key = String(req.query?.key || '').trim();
  try {
    if (key) {
      return res.json({
        success: true,
        entry: getCommandConfigEntry(key)
      });
    }
    const snapshot = await getCommandCenterSnapshot(resolveAgentId(req), {
      afterEventId: null,
      limit: 20
    });
    return res.json({
      success: true,
      config: snapshot.config
    });
  } catch (error) {
    return res.status(400).json({ success: false, error: error?.message || String(error) });
  }
});

router.post('/config/set', async (req, res) => {
  return res.status(410).json({
    success: false,
    error: 'unsigned command-center configuration retired; use set-system-config.js',
  });
});

router.post('/config/reset', async (req, res) => {
  return res.status(410).json({
    success: false,
    error: 'signed configuration is superseded by appending a new master-signed value; reset is not a deletion operation',
  });
});

router.get('/plugins', async (req, res) => {
  const snapshot = await getCommandCenterSnapshot(resolveAgentId(req), {
    afterEventId: null,
    limit: 20
  });
  res.json({
    success: true,
    plugins: snapshot.plugins
  });
});

router.get('/skills', async (req, res) => {
  const snapshot = await getCommandCenterSnapshot(resolveAgentId(req), {
    afterEventId: null,
    limit: 20
  });
  res.json({
    success: true,
    skills: snapshot.skills
  });
});

router.get('/telemetry', async (req, res) => {
  const snapshot = await getCommandCenterSnapshot(resolveAgentId(req), {
    afterEventId: req.query?.afterEventId || null,
    limit: Number(req.query?.limit || 200)
  });
  res.json({
    success: true,
    telemetry: snapshot.telemetry
  });
});

export default router;
