// Canonical in-process recall controls. Persistent controls belong to the
// signed configuration ledger; these defaults deliberately have no ENV source.
import { systemConfigStore } from '../security/system-config-store.js';

function enabled(configKey) {
  return systemConfigStore.readConfigString(configKey) === 'true';
}

export const RECALL_SPEED_CONFIG = Object.freeze({
  cache: Object.freeze({
    get enabled() { return enabled('RECALL_CACHE_ENABLED'); },
    similarityThreshold: 0.85,
    ttlMs: 300_000,
  }),
  earlyExit: Object.freeze({
    get enabled() { return enabled('RECALL_EARLY_EXIT_ENABLED'); },
    topScoreThreshold: 0.82,
    scoreGapThreshold: 0.15,
    mvsThreshold: 0.42,
    avgTop5Threshold: 0.65,
    fallbackQmdThreshold: 0.60,
  }),
  hybridWeights: Object.freeze({ vector: 0.65, bm25: 0.35 }),
  governance: Object.freeze({ get enabled() { return enabled('RECALL_GOVERNANCE_ENABLED'); } }),
  instrumentation: Object.freeze({ get enabled() { return enabled('RECALL_INSTRUMENTATION_ENABLED'); } }),
  temporalTruth: Object.freeze({
    get freshnessRankingEnabled() { return enabled('RECALL_FRESHNESS_RANKING_ENABLED'); }
  }),
});

export default RECALL_SPEED_CONFIG;
