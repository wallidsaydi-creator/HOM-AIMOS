// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (during step 19)
// → Calls: all registered tool integrations (web, x, gmail, drive, etc.)
// Pipeline: AGENT_RUN_PIPELINE
// Position: tool execution
// Sources: OpenAI Function Calling (tool abstraction), Anthropic Tool Use
// Batch8 Wave4 sources: ASA, Transparent and Controllable Recommendation
// Filtering, AI Agent Systems. Adds passive tool-representation diagnostics
// only; it never unlocks or auto-approves tools.
//
// SERVICE CONNECTION GUIDE:
// 1. ↔ Interacts with: native integration and memory services
// 2. ← Called by: agent-runner.js (Translates LLM intent into executable code)
// 3. → Pushes to: aimos_save (All 'episodic' tool outcomes pass quality-gate here)
// 4. → Calls: knowledge-gate.js (Checks if the tool is blocked by missing evidence)
// ─────────────────────────────────────────────────────────────────────────────

import { analyzeSituation } from './sun-tzu-analyzer.js';
import { beginServingWork, getServingAbortSignal } from '../runtime/serving-control.js';
import { assessQuality } from '../write/quality-gate.js';
import { searchWeb } from '../integrations/web-search.js';
import { xSearchRecent } from '../integrations/x-search.js';
import { xPostTweet, xReplyToTweet, xQuoteTweet } from '../integrations/x-tools.js';
import { getOperatorAgentId, isOperatorAgentId } from '../security/system-config-store.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { canonicalJson } from '../security/protocol/canonical-json.js';
import { ORIGIN_FAMILY_PROFILE_SHA256_V1 } from '../security/protocol/origin-binding-v1.js';
import { consequentialActionPolicyForTool } from '../security/protocol/consequential-action-v1.js';
import { runAgent } from './agent-runner.js';
import { validateExecution, createExecutionPlan } from '../write/execution-interceptor.js';
import { classifyIntent, enforceVerbPolicy } from '../write/intent-classifier.js';
import {
  gmailListInbox, gmailSearchMessages, gmailSendMessage, gmailReplyMessage,
  youtubeSearch, youtubeChannelStats, youtubeListChannelVideos,
  driveListFiles, driveReadTextFile,
  calendarListEvents, calendarTodayEvents, calendarCreateEvent,
  docsGetDocument, sheetsGetValues, googleGetProfile
} from '../integrations/google-tools.js';
import {
  stripeAccountSummary,
  stripeListCustomers,
  stripeListSubscriptions,
  stripeListPaymentIntents
} from '../integrations/stripe-tools.js';
import {
  listIntegrationStatus,
  githubListRepos,
  githubSearchIssues,
  salesforceListObjects,
  contactsSearch,
  imessageListChats,
  imessageSearchContact,
  imessageSend,
  imessageRequestAccess
} from '../integrations/integration-tools.js';
import { telegramSendMessage } from '../integrations/telegram-tools.js';
import { createScheduledTask, listScheduledTasks } from './scheduler.js';
import { query, withTransaction } from '../../db/connection.js';
import { executeCanonicalSave, executeHousekeeperCanonicalSave } from '../write/canonical-save-owner.js';
import {
  claimToolApprovalExecution,
  createToolApprovalRequest,
} from './tool-approval-store.js';
import { beginToolAction, finishToolAction, createToolInputState, readToolInputState, recordToolInputResult, recordToolContextInput, mergeToolInputState, classifyNativeResult, invalidateToolInputState, verifyToolActionAuthority } from './tool-action-ledger.js';
import { createKnowledgeGateState, shouldBlockToolForMissingKnowledge, recordKnowledgeToolEvent } from '../security/knowledge-gate.js';
import { scanToolExecution, scanToolResult } from '../security/canary-tracker.js';
import { buildToolRepresentation as buildToolRepresentationDiagnostic } from './tool-representation-diagnostics.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import { readVerifiedRequestReceiptByMutationHash } from '../security/request-receipt-ledger.js';
import { readVerifiedEventById } from '../observe/event-ledger.js';
import { executeCanonicalRecall } from '../retrieval/native-recall-pipeline.js';
import { masterPubkeyCache } from '../security/master-pubkey-cache.js';
import { authorizePurposeLocalFileRead } from '../security/purpose-authorization.js';

const COMPANY = AIMOS_COMPANY_ID;
const AIMOS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const X_INTENT_MARKERS = [
  'twitter',
  'x.com',
  'tweet',
  'tweets',
  'x api',
  'twitter api',
  'social listening',
  'social-listening',
  'search x',
  'search on x',
  'search twitter'
];

async function notifyToolObserver(observer, payload) {
  if (typeof observer !== 'function') return;
  try {
    await observer(payload);
  } catch {
    // Observer failures must never break tool execution.
  }
}

// ─── AIMOS ───────────────────────────────────────────────────────────────────

// Discovery is not execution authority. Both this native admission check and
// the canonical SAVE/RECALL owners consume the SAME exact-epoch master grant;
// the owners still lock/recheck it when consuming a concrete signed action.
// Generic tool capabilities cannot grant or revoke these memory rights.
export async function readNativeMemoryToolGrant(executionContext) {
  const context = executionContext;
  if (!context || context.authSource !== 'envelope' || context.companyId !== COMPANY
    || !context.actorAgentId || !context.actorValidFromIso || !context.requestReceiptId
    || !context.requestReceiptMutationHash || !context.requestAdmissionEventId
    || !context.requestAdmissionMutationHash) throw new Error('native_memory_tool_request_authority_required');
  return withTransaction(async client => {
    await client.query('SET TRANSACTION READ ONLY');
    const receipt = await readVerifiedRequestReceiptByMutationHash({
      companyId: context.companyId, requestReceiptMutationHash: context.requestReceiptMutationHash, client,
    });
    const admission = await readVerifiedEventById(context.requestAdmissionEventId,context.companyId,{client});
    const metadata = admission.metadata;
    if (receipt.requestReceiptId !== context.requestReceiptId
      || receipt.actorAgentId !== context.actorAgentId
      || receipt.actorValidFromIso !== new Date(context.actorValidFromIso).toISOString()
      || receipt.signedMethod !== context.signedMethod || receipt.signedPath !== context.signedPath
      || receipt.signedTs !== context.signedTs
      || admission.operation !== 'request_admission_verified' || admission.signer_agent_id !== 'housekeeper'
      || Buffer.from(admission.mutation_hash).toString('hex') !== context.requestAdmissionMutationHash
      || metadata.request_receipt_id !== receipt.requestReceiptId
      || metadata.request_receipt_mutation_hash !== receipt.requestReceiptMutationHash
      || metadata.actor_agent_id !== receipt.actorAgentId
      || new Date(metadata.actor_valid_from).toISOString() !== receipt.actorValidFromIso
      || metadata.request_hash !== receipt.requestHash) throw new Error('native_memory_tool_request_binding_invalid');
    await client.query("SELECT set_config('app.current_agent_id',$1,true)",[context.actorAgentId]);
    const identity = (await client.query(`SELECT 1 FROM agent_identity identity
      WHERE identity.agent_id=$1 AND identity.valid_from=$2
        AND identity.valid_from<=clock_timestamp() AND identity.valid_until>clock_timestamp()
        AND NOT EXISTS(SELECT 1 FROM aimos_agent_revocation_events revoked
          WHERE revoked.agent_id=identity.agent_id AND revoked.agent_valid_from=identity.valid_from)`,
    [context.actorAgentId,context.actorValidFromIso])).rows[0];
    if (!identity) throw new Error('native_memory_tool_actor_epoch_not_active');
    const grant = await recallAuthorizationService.getEffective({ companyId:context.companyId,
      subjectAgentId:context.actorAgentId,subjectValidFrom:context.actorValidFromIso,client });
    if (!grant) return null;
    return Object.freeze({ schema:'hom.aimos.native-memory-tool-grant-reference/v1',
      company_id:context.companyId,actor_agent_id:context.actorAgentId,
      actor_valid_from:receipt.actorValidFromIso,actor_cert_fingerprint:receipt.actorCertFingerprint,
      grant_event_id:grant.eventId,grant_mutation_sha256:grant.mutationHash.toString('hex'),
      allowed:grant.allowed,write_allowed:grant.writeAllowed,
      clearance_ceiling:grant.clearanceCeiling,data_class_ceiling:grant.dataClassCeiling });
  }, { restricted:true,client_id:context.companyId,agent_id:context.actorAgentId });
}

async function aimosRecall(rawCommand = {}, options = {}) {
  const { query: q, key, memory_id } = rawCommand;
  if (!q && !key && !memory_id) {
    throw new Error('aimos_recall requires query, key, or memory_id');
  }
  const executionContext = options.executionContext || options.credentialUseContext || null;
  if (!executionContext || !options.toolActionAuthority) {
    throw new Error('verified_tool_recall_authority_required');
  }
  const result = await executeCanonicalRecall({
    req: {
      ip: 'native-tool-action',
      headers: {},
      originalUrl: 'tool:aimos_recall',
    },
    rawCommand,
    executionContext,
    requestAuthority: options.toolActionAuthority,
    transportBinding: { transport: 'tool', toolName: 'aimos_recall' },
  });
  if (result.status !== 200) throw new Error(result.body?.error || 'native_tool_recall_failed');
  // Match the canonical HTTP JSON value before committing the tool outcome.
  // Optional JavaScript-only undefined fields are not part of that value.
  return JSON.parse(JSON.stringify(result.body));
}


async function aimosSave({ content, tags = [], agent_id = 'unknown', source_memory_ids }, options = {}) {
  const executionContext = options.executionContext || options.credentialUseContext || null;
  const actorAgentId = String(executionContext?.actorAgentId || '').trim();
  const actorValidFromIso = executionContext?.actorValidFromIso || null;
  const companyId = String(executionContext?.companyId || '').trim();
  const runtimeAgentId = String(agent_id || '').trim();
  if (!actorAgentId || !actorValidFromIso || !companyId || !options.toolActionAuthority) {
    throw new Error('verified_tool_save_authority_required');
  }
  const memoryAuthority = actorAgentId === 'housekeeper'
    && ['T1', 'T1_SYSTEM_SELF'].includes(executionContext.identityTier)
    ? { allowed: true, writeAllowed: true, clearanceCeiling: 12 }
    : await recallAuthorizationService.getEffective({
        companyId,
        subjectAgentId: actorAgentId,
        subjectValidFrom: actorValidFromIso,
      });
  if (!memoryAuthority?.allowed || !memoryAuthority.writeAllowed) {
    throw new Error('master_signed_memory_write_grant_required');
  }
  const requestedClearance = Math.max(1, Number(options.clearanceLevel ?? 1));
  if (!Number.isFinite(requestedClearance) || requestedClearance > memoryAuthority.clearanceCeiling) {
    throw new Error('clearance_exceeds_verified_authority');
  }
  const key = `agent_save:${actorAgentId}:${options.toolActionAuthority.eventId}`;
  const saveSpec = {
    company_id: companyId,
    agent_id: actorAgentId,
    key,
    value: content,
    memory_type: 'episodic',
    source: tags.length ? `tool:aimos_save:${tags.map(String).sort().join(',')}` : 'tool:aimos_save',
    scope: 'private',
    clearance_level: requestedClearance,
    session_id: options.sessionKey || null,
    ...(options.inputMemoryIds == null && source_memory_ids === undefined
      ? {} : { source_memory_ids: options.inputMemoryIds ?? source_memory_ids }),
  };
  const commitAction = await beginToolAction({
    tool: 'aimos_save_commit',
    args: saveSpec,
    inputState: options.nativeToolInputs,
    runtimeAgentId,
    executionContext,
    parentEventId: options.toolActionAuthority.eventId,
  });
  let saved;
  try {
    saved = await executeCanonicalSave({ ...saveSpec, mutation_authority: commitAction.authority });
    if (saved?.rejected) throw new Error(saved.reason || 'tool_save_rejected');
    await finishToolAction({
      action: commitAction,
      executionContext,
      succeeded: true,
      result: { memory_id: saved?.id || null },
    });
  } catch (error) {
    try {
      await finishToolAction({ action: commitAction, executionContext, succeeded: false, error: error?.message || error });
    } catch (ledgerError) {
      error.toolActionLedgerError = ledgerError?.message || String(ledgerError);
    }
    throw error;
  }
  if (saved?.rejected) {
    return { success: false, rejected: true, error: saved.reason, quality_score: saved.quality_score };
  }
  return {
    success: true,
    memory_id: saved?.id || null,
    content_hash: saved?.live_content_hash?.toString('hex') || null,
    save_mutation_hash: saved?.ledger_commit?.mutationHash?.toString('hex') || null,
    binding_mutation_hash: saved?.binding_commit?.mutationHash?.toString('hex') || null,
    tool_action_event_id: options.toolActionAuthority.eventId,
    tool_action_mutation_hash: options.toolActionAuthority.eventMutationHash,
    save_commit_event_id: commitAction.authority.eventId,
    save_commit_mutation_hash: commitAction.authority.eventMutationHash,
  };
}


// ─── TOOL DEFINITIONS (OpenAI function-calling schema) ────────────────────────

export const ALL_TOOL_DEFS = {
  web_search: {
    profile: {
      owner: 'services/integrations/web-search.js#searchWeb',
      operation_class: 'read', required_clearance: 1,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'web-search-provider',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'web_search',
        description: 'Search the web for current information, news, or research.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search query' },
            max_results: { type: 'integer', description: 'Max results (default 5)' }
          },
          required: ['query']
        }
      }
    },
    fn: async ({ query: q, max_results = 5 }, invocationOptions = {}) => {
      const result = await searchWeb({
        query: q,
        maxResults: max_results,
        useContext: invocationOptions.credentialUseContext || {},
      });
      return result;
    }
  },

  // x_search: available for explicit requests only. Removed from INLINE_TOOL_NAME_ALIASES to prevent autonomous drain.
  x_search: {
    profile: {
      owner: 'services/integrations/x-search.js#xSearchRecent',
      operation_class: 'read', required_clearance: 3,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'x',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'x_search',
        description: 'Search recent X (Twitter) posts for market signals and trend intelligence.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'X search query, e.g. "(AI OR SaaS) lang:en -is:retweet"' },
            max_results: { type: 'integer', description: 'Max posts (10-100)' }
          },
          required: ['query']
        }
      }
    },
    fn: async ({ query: q, max_results = 20 }, invocationOptions = {}) => xSearchRecent({
      query: q,
      maxResults: max_results,
      useContext: invocationOptions.credentialUseContext || {},
    })
  },

  x_post: {
    profile: {
      owner: 'services/integrations/x-tools.js#xPostTweet',
      operation_class: 'external_write', required_clearance: 5,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'x',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'x_post',
        description: 'Post a new tweet on X (Twitter) from the configured account.',
        parameters: {
          type: 'object',
          properties: {
            text: { type: 'string', description: 'The text content of the tweet (max 280 characters).' }
          },
          required: ['text']
        }
      }
    },
    fn: async ({ text }, invocationOptions = {}) => xPostTweet({ text, useContext: invocationOptions.credentialUseContext || {} })
  },

  x_reply: {
    profile: {
      owner: 'services/integrations/x-tools.js#xReplyToTweet',
      operation_class: 'external_write', required_clearance: 5,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'x',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'x_reply',
        description: 'Reply to an existing tweet on X (Twitter).',
        parameters: {
          type: 'object',
          properties: {
            text: { type: 'string', description: 'The reply text (max 280 characters).' },
            replyToTweetId: { type: 'string', description: 'The ID of the tweet to reply to.' }
          },
          required: ['text', 'replyToTweetId']
        }
      }
    },
    fn: async ({ text, replyToTweetId }, invocationOptions = {}) => xReplyToTweet({ text, replyToTweetId, useContext: invocationOptions.credentialUseContext || {} })
  },

  x_quote: {
    profile: {
      owner: 'services/integrations/x-tools.js#xQuoteTweet',
      operation_class: 'external_write', required_clearance: 5,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'x',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'x_quote',
        description: 'Quote tweet another post with your commentary. Use this for engagement — quote tweets are not restricted like replies.',
        parameters: {
          type: 'object',
          properties: {
            text: { type: 'string', description: 'Your commentary to add to the quote tweet (max 280 characters).' },
            quote_tweet_id: { type: 'string', description: 'The ID of the tweet to quote.' }
          },
          required: ['text', 'quote_tweet_id']
        }
      }
    },
    fn: async (args, invocationOptions = {}) => xQuoteTweet({
      text: args.text,
      quoteTweetId: args.quote_tweet_id,
      useContext: invocationOptions.credentialUseContext || {},
    })
  },

  gmail_inbox: {
    profile: {
      owner: 'services/integrations/google-tools.js#gmailListInbox',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'gmail_inbox',
        description: 'Read recent emails from Gmail inbox.',
        parameters: {
          type: 'object',
          properties: {
            max: { type: 'integer', description: 'Number of emails to fetch (default 10)' },
            filter: { type: 'string', description: 'Gmail search filter (e.g. "is:unread")' }
          }
        }
      }
    },
    fn: async ({ max = 10, filter = '' }, invocationOptions = {}) => gmailListInbox(
      { maxResults: max, query: filter },
      invocationOptions.credentialUseContext || {},
    )
  },

  gmail_search: {
    profile: {
      owner: 'services/integrations/google-tools.js#gmailSearchMessages',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'gmail_search',
        description: 'Search Gmail messages by keyword, sender, subject, or date.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Gmail search query' },
            max: { type: 'integer', description: 'Max results' }
          },
          required: ['query']
        }
      }
    },
    fn: async ({ query: q, max = 10 }, invocationOptions = {}) => gmailSearchMessages(
      { query: q, maxResults: max },
      invocationOptions.credentialUseContext || {},
    )
  },

  gmail_send: {
    profile: {
      owner: 'services/integrations/google-tools.js#gmailSendMessage',
      operation_class: 'external_write', required_clearance: 4,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'gmail_send',
        description: 'Send an email via Gmail.',
        parameters: {
          type: 'object',
          properties: {
            to: { type: 'string', description: 'Recipient email address' },
            subject: { type: 'string', description: 'Email subject' },
            body: { type: 'string', description: 'Email body (plain text)' }
          },
          required: ['to', 'subject', 'body']
        }
      }
    },
    fn: async ({ to, subject, body }, invocationOptions = {}) => gmailSendMessage(
      { to, subject, body },
      invocationOptions.credentialUseContext || {},
    )
  },

  gmail_reply: {
    profile: {
      owner: 'services/integrations/google-tools.js#gmailReplyMessage',
      operation_class: 'external_write', required_clearance: 4,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'gmail_reply',
        description: 'Reply to one exact Gmail message.',
        parameters: {
          type: 'object',
          properties: {
            messageId: { type: 'string', description: 'Exact Gmail message identifier' },
            body: { type: 'string', description: 'Exact reply body' },
          },
          required: ['messageId', 'body'],
        },
      },
    },
    fn: async ({ messageId, body }, options = {}) => gmailReplyMessage(
      { messageId, body },
      options.credentialUseContext || {},
    ),
  },

  youtube_search: {
    profile: {
      owner: 'services/integrations/google-tools.js#youtubeSearch',
      operation_class: 'read', required_clearance: 1,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'youtube_search',
        description: 'Search YouTube for videos.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search query' },
            max: { type: 'integer', description: 'Max results' }
          },
          required: ['query']
        }
      }
    },
    fn: async ({ query: q, max = 10 }, invocationOptions = {}) => youtubeSearch(
      { query: q, maxResults: max },
      invocationOptions.credentialUseContext || {},
    )
  },

  youtube_channel: {
    profile: {
      owner: 'services/integrations/google-tools.js#youtubeChannelStats+youtubeListChannelVideos',
      operation_class: 'read', required_clearance: 1,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'youtube_channel',
        description: 'Get YouTube channel stats and recent videos.',
        parameters: { type: 'object', properties: {} }
      }
    },
    fn: async (_args, invocationOptions = {}) => {
      const useContext = invocationOptions.credentialUseContext || {};
      const [stats, videos] = await Promise.all([
        youtubeChannelStats(null, useContext),
        youtubeListChannelVideos({ maxResults: 10 }, useContext)
      ]);
      return { stats, videos };
    }
  },


  drive_list: {
    profile: {
      owner: 'services/integrations/google-tools.js#driveListFiles',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'drive_list',
        description: 'List files in Google Drive.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Drive search query' },
            max: { type: 'integer', description: 'Max files' }
          }
        }
      }
    },
    fn: async ({ query: q = '', max = 20 }, invocationOptions = {}) => driveListFiles(
      { query: q, maxResults: max },
      invocationOptions.credentialUseContext || {},
    )
  },

  drive_read: {
    profile: {
      owner: 'services/integrations/google-tools.js#driveReadTextFile',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'drive_read',
        description: 'Read the text content of a Google Drive file.',
        parameters: {
          type: 'object',
          properties: {
            file_id: { type: 'string', description: 'Google Drive file ID' }
          },
          required: ['file_id']
        }
      }
    },
    fn: async ({ file_id }, invocationOptions = {}) => driveReadTextFile(file_id, invocationOptions.credentialUseContext || {})
  },

  calendar_today: {
    profile: {
      owner: 'services/integrations/google-tools.js#calendarTodayEvents',
      operation_class: 'read', required_clearance: 1,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'calendar_today',
        description: "Get today's calendar events.",
        parameters: { type: 'object', properties: {} }
      }
    },
    fn: async (_args, invocationOptions = {}) => calendarTodayEvents(invocationOptions.credentialUseContext || {})
  },

  calendar_events: {
    profile: {
      owner: 'services/integrations/google-tools.js#calendarListEvents',
      operation_class: 'read', required_clearance: 1,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'calendar_events',
        description: 'Get upcoming calendar events.',
        parameters: {
          type: 'object',
          properties: {
            max: { type: 'integer', description: 'Max events' }
          }
        }
      }
    },
    fn: async ({ max = 20 }, invocationOptions = {}) => calendarListEvents(
      { maxResults: max },
      invocationOptions.credentialUseContext || {},
    )
  },

  calendar_create: {
    profile: {
      owner: 'services/integrations/google-tools.js#calendarCreateEvent',
      operation_class: 'external_write', required_clearance: 3,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'calendar_create',
        description: 'Create a new calendar event.',
        parameters: {
          type: 'object',
          properties: {
            summary: { type: 'string', description: 'Event title' },
            description: { type: 'string', description: 'Event description' },
            start: { type: 'string', description: 'Start time ISO 8601' },
            end: { type: 'string', description: 'End time ISO 8601' }
          },
          required: ['summary', 'start', 'end']
        }
      }
    },
    fn: async ({ summary, description, start, end }, invocationOptions = {}) => calendarCreateEvent(
      { summary, description, start, end },
      invocationOptions.credentialUseContext || {},
    )
  },

  docs_read: {
    profile: {
      owner: 'services/integrations/google-tools.js#docsGetDocument',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'docs_read',
        description: 'Read a Google Doc.',
        parameters: {
          type: 'object',
          properties: {
            document_id: { type: 'string', description: 'Google Doc ID' }
          },
          required: ['document_id']
        }
      }
    },
    fn: async ({ document_id }, invocationOptions = {}) => docsGetDocument(document_id, invocationOptions.credentialUseContext || {})
  },

  sheets_read: {
    profile: {
      owner: 'services/integrations/google-tools.js#sheetsGetValues',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'sheets_read',
        description: 'Read values from a Google Sheet range.',
        parameters: {
          type: 'object',
          properties: {
            spreadsheet_id: { type: 'string', description: 'Google Sheet ID' },
            range: { type: 'string', description: 'A1 range (e.g. Sheet1!A1:D20)' }
          },
          required: ['spreadsheet_id', 'range']
        }
      }
    },
    fn: async ({ spreadsheet_id, range }, invocationOptions = {}) => sheetsGetValues(
      spreadsheet_id,
      range,
      invocationOptions.credentialUseContext || {},
    )
  },

  google_profile: {
    profile: {
      owner: 'services/integrations/google-tools.js#googleGetProfile',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'google',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'google_profile',
        description: 'Get the connected Google account profile to verify suite connectivity.',
        parameters: { type: 'object', properties: {} }
      }
    },
    fn: async (_args, invocationOptions = {}) => googleGetProfile(invocationOptions.credentialUseContext || {})
  },

  stripe_account_summary: {
    profile: {
      owner: 'services/integrations/stripe-tools.js#stripeAccountSummary',
      operation_class: 'read', required_clearance: 3,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'stripe',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'stripe_account_summary',
        description: 'Get Stripe account status summary.',
        parameters: { type: 'object', properties: {} }
      }
    },
    fn: async (_args, invocationOptions = {}) => stripeAccountSummary(invocationOptions.credentialUseContext || {})
  },

  stripe_list_customers: {
    profile: {
      owner: 'services/integrations/stripe-tools.js#stripeListCustomers',
      operation_class: 'read', required_clearance: 3,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'stripe',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'stripe_list_customers',
        description: 'List Stripe customers.',
        parameters: {
          type: 'object',
          properties: {
            limit: { type: 'integer', description: 'Max customers (1-100)' },
            email: { type: 'string', description: 'Filter by email' }
          }
        }
      }
    },
    fn: async ({ limit = 10, email = '' }, invocationOptions = {}) => stripeListCustomers({
      limit,
      email,
      useContext: invocationOptions.credentialUseContext || {},
    })
  },

  stripe_list_subscriptions: {
    profile: {
      owner: 'services/integrations/stripe-tools.js#stripeListSubscriptions',
      operation_class: 'read', required_clearance: 3,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'stripe',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'stripe_list_subscriptions',
        description: 'List Stripe subscriptions.',
        parameters: {
          type: 'object',
          properties: {
            limit: { type: 'integer', description: 'Max subscriptions (1-100)' },
            status: { type: 'string', description: 'Subscription status (all, active, canceled, etc.)' }
          }
        }
      }
    },
    fn: async ({ limit = 10, status = 'all' }, invocationOptions = {}) => stripeListSubscriptions({
      limit,
      status,
      useContext: invocationOptions.credentialUseContext || {},
    })
  },

  stripe_list_payment_intents: {
    profile: {
      owner: 'services/integrations/stripe-tools.js#stripeListPaymentIntents',
      operation_class: 'read', required_clearance: 3,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'stripe',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'stripe_list_payment_intents',
        description: 'List recent Stripe payment intents.',
        parameters: {
          type: 'object',
          properties: {
            limit: { type: 'integer', description: 'Max payment intents (1-100)' }
          }
        }
      }
    },
    fn: async ({ limit = 10 }, invocationOptions = {}) => stripeListPaymentIntents({
      limit,
      useContext: invocationOptions.credentialUseContext || {},
    })
  },

  integrations_status: {
    profile: {
      owner: 'services/integrations/integration-tools.js#listIntegrationStatus',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'native_record', source_namespace: 'hom.aimos.configuration',
      source_evidence_requirement: 'configuration_and_credential_lifecycle_records',
      result_integrity_ceiling: 'agent', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'integrations_status',
        description: 'List status for all integrated apps (Google, GitHub, X, Salesforce, Stripe, iMessage).',
        parameters: { type: 'object', properties: {} }
      }
    },
    fn: async () => listIntegrationStatus()
  },

  github_list_repos: {
    profile: {
      owner: 'services/integrations/integration-tools.js#githubListRepos',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'github',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'github_list_repos',
        description: 'List GitHub repositories for the connected account.',
        parameters: {
          type: 'object',
          properties: {
            limit: { type: 'integer', description: 'Max repositories (1-100)' },
            visibility: { type: 'string', description: 'all, public, or private' }
          }
        }
      }
    },
    fn: async ({ limit = 20, visibility = 'all' }, invocationOptions = {}) => githubListRepos(
      { limit, visibility },
      invocationOptions.credentialUseContext || {},
    )
  },

  github_search_issues: {
    profile: {
      owner: 'services/integrations/integration-tools.js#githubSearchIssues',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'github',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'github_search_issues',
        description: 'Search GitHub issues and pull requests.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'GitHub issue search query' },
            limit: { type: 'integer', description: 'Max results (1-100)' }
          },
          required: ['query']
        }
      }
    },
    fn: async ({ query: q, limit = 10 }, invocationOptions = {}) => githubSearchIssues(
      { query: q, limit },
      invocationOptions.credentialUseContext || {},
    )
  },

  salesforce_list_objects: {
    profile: {
      owner: 'services/integrations/integration-tools.js#salesforceListObjects',
      operation_class: 'read', required_clearance: 3,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'salesforce',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'salesforce_list_objects',
        description: 'List available Salesforce objects from the connected org.',
        parameters: {
          type: 'object',
          properties: {
            limit: { type: 'integer', description: 'Max objects to return' }
          }
        }
      }
    },
    fn: async ({ limit = 50 }, invocationOptions = {}) => salesforceListObjects(
      { limit },
      invocationOptions.credentialUseContext || {},
    )
  },

  contacts_search: {
    profile: {
      owner: 'services/integrations/integration-tools.js#contactsSearch',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'host_automation', source_namespace: 'local.contacts',
      source_evidence_requirement: 'local_automation_action_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'contacts_search',
        description: 'Search macOS Contacts by name, phone number, or email address.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Name, phone number, or email fragment to search for' }
          },
          required: ['query']
        }
      }
    },
    fn: async ({ query: q }, options = {}) => contactsSearch({ query: q }, options.credentialUseContext || {})
  },

  imessage_chats: {
    profile: {
      owner: 'services/integrations/integration-tools.js#imessageListChats',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'host_automation', source_namespace: 'local.imessage',
      source_evidence_requirement: 'local_automation_action_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'imessage_chats',
        description: 'List recent iMessage chats (macOS local automation).',
        parameters: {
          type: 'object',
          properties: {
            limit: { type: 'integer', description: 'Max chats to return' }
          }
        }
      }
    },
    fn: async ({ limit = 10 }, options = {}) => imessageListChats({ limit }, options.credentialUseContext || {})
  },

  imessage_search_contact: {
    profile: {
      owner: 'services/integrations/integration-tools.js#imessageSearchContact',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: true,
      source_kind: 'host_automation', source_namespace: 'local.imessage',
      source_evidence_requirement: 'local_automation_action_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'imessage_search_contact',
        description: 'Search for iMessage contacts/buddies by name or handle to find the correct identifier for sending messages.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Name or part of a handle to search for' }
          },
          required: ['query']
        }
      }
    },
    fn: async ({ query: q }, options = {}) => imessageSearchContact({ query: q }, options.credentialUseContext || {})
  },

  imessage_request_access: {
    profile: {
      owner: 'services/integrations/integration-tools.js#imessageRequestAccess',
      operation_class: 'internal_write', required_clearance: 5,
      autonomous_approval_required: true,
      source_kind: 'host_automation', source_namespace: 'local.imessage',
      source_evidence_requirement: 'local_automation_action_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'imessage_request_access',
        description: 'Request the exact local Messages automation permission.',
        parameters: {
          type: 'object',
          properties: {
            request_access: { type: 'boolean', description: 'Must be true for this explicit permission request' },
          },
          required: ['request_access'],
        },
      },
    },
    fn: async ({ request_access: requestAccess }, options = {}) => {
      if (requestAccess !== true) throw new Error('imessage_request_access_confirmation_required');
      return { success: true, chat_count: await imessageRequestAccess(options.credentialUseContext || {}) };
    },
  },

  imessage_send: {
    profile: {
      owner: 'services/integrations/integration-tools.js#imessageSend',
      operation_class: 'external_write', required_clearance: 4,
      autonomous_approval_required: true,
      source_kind: 'host_automation', source_namespace: 'local.imessage',
      source_evidence_requirement: 'local_automation_action_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'imessage_send',
        description: 'Send an iMessage to a contact/number.',
        parameters: {
          type: 'object',
          properties: {
            to: { type: 'string', description: 'Recipient iMessage identifier (phone/email)' },
            message: { type: 'string', description: 'Message content' }
          },
          required: ['to', 'message']
        }
      }
    },
    fn: async ({ to, message }, options = {}) => imessageSend({ to, message }, options.credentialUseContext || {})
  },

  telegram_send: {
    profile: {
      owner: 'services/integrations/telegram-tools.js#telegramSendMessage',
      operation_class: 'external_write', required_clearance: 4,
      autonomous_approval_required: true,
      source_kind: 'credential_account', source_namespace: 'telegram',
      source_evidence_requirement: 'credential_use_receipt',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'restricted',
    },
    schema: {
      type: 'function',
      function: {
        name: 'telegram_send',
        description: 'Send one exact Telegram message.',
        parameters: {
          type: 'object',
          properties: {
            chat_id: { type: 'string', description: 'Exact Telegram chat identifier' },
            text: { type: 'string', description: 'Exact message text' },
            parse_mode: { type: 'string', description: 'Optional Telegram parse mode' },
          },
          required: ['chat_id', 'text'],
        },
      },
    },
    fn: async ({ chat_id: chatId, text, parse_mode: parseMode = null }, options = {}) => (
      telegramSendMessage({
        chatId,
        text,
        parseMode,
        useContext: options.credentialUseContext || {},
      })
    ),
  },

  aimos_recall: {
    profile: {
      owner: 'services/retrieval/native-recall-pipeline.js#executeCanonicalRecall',
      operation_class: 'read', required_clearance: 1,
      autonomous_approval_required: false,
      source_kind: 'native_memory', source_namespace: 'hom.aimos.memory',
      source_evidence_requirement: 'native_recall_receipt_and_memory_origins',
      result_integrity_ceiling: 'agent', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'aimos_recall',
        description: 'Search Aimos memory for relevant past information, decisions, or context, or open an exact memory when key or memory_id is known.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'What to search for in memory' },
            key: { type: 'string', description: 'Exact Aimos memory key when known' },
            memory_id: { type: 'string', description: 'Exact Aimos memory ID when known' },
            limit: { type: 'integer', description: 'Max memories to return' },
            memory_type_filter: { type: 'string', description: 'Optional memory type filter' },
            source_filter: { type: 'string', description: 'Optional source filter' },
            session_id: { type: 'string', description: 'Optional ingestion session scope' },
            mode: { type: 'string', enum: ['adaptive', 'linear'], description: 'Recall mode' },
            sort: { type: 'string', enum: ['semantic', 'chronological'], description: 'Ordering mode' }
          }
        }
      }
    },
    fn: async (args, options) => aimosRecall(args, options)
  },

  aimos_save: {
    profile: {
      owner: 'services/write/canonical-save-owner.js#executeCanonicalSave',
      operation_class: 'memory_write', required_clearance: 2,
      autonomous_approval_required: false,
      source_kind: 'native_memory', source_namespace: 'hom.aimos.memory',
      source_evidence_requirement: 'canonical_save_terminal_and_memory_origin',
      result_integrity_ceiling: 'agent', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'aimos_save',
        description: 'Save important information, decisions, or findings to Aimos memory.',
        parameters: {
          type: 'object',
          properties: {
            content: { type: 'string', description: 'Information to store' },
            tags: { type: 'array', items: { type: 'string' }, description: 'Tags for retrieval' },
            source_memory_ids: { type: 'array', items: { type: 'string' }, description: 'Additional retained memory inputs; runtime-collected inputs cannot be removed' }
          },
          required: ['content']
        }
      }
    },
    fn: async ({ content, tags = [], source_memory_ids }, agentId, options = {}) => (
      aimosSave({ content, tags, agent_id: agentId, source_memory_ids }, options)
    )
  },

  write_file: {
    profile: {
      owner: 'services/orchestration/tool-registry.js#write_file',
      operation_class: 'internal_write', required_clearance: 5,
      autonomous_approval_required: false,
      source_kind: 'local_file', source_namespace: 'local.files',
      source_evidence_requirement: 'verified_tool_action_and_file_content_hash',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'write_file',
        description: 'Save content directly to a local file on the Mac (e.g. your Desktop). Use absolute paths.',
        parameters: {
          type: 'object',
          properties: {
            filepath: { type: 'string', description: 'Absolute path to save the file (e.g. /absolute/path/report.html)' },
            content: { type: 'string', description: 'The exact content to write to the file' }
          },
          required: ['filepath', 'content']
        }
      }
    },
    fn: async ({ filepath, content }, agentId, options = {}) => {
      try {
        const authorizedArgs = options.toolActionArguments || { filepath, content };
        if (authorizedArgs.filepath !== filepath || authorizedArgs.content !== content) {
          throw new Error('consequential_action_argument_substitution');
        }
        await verifyToolActionAuthority(options.toolActionAuthority, {
          expectedCompanyId: COMPANY,
          expectedTool: 'write_file',
          expectedActorAgentId: options.executionContext?.actorAgentId
            || options.credentialUseContext?.actorAgentId,
          expectedArguments: authorizedArgs,
        });
        const resolved = path.resolve(filepath);
        const filename = path.basename(resolved).toLowerCase();
        
        // ─── Phase 2: Dual-Mode Lockdown ──────────────────────────────────────
        const isWithin = (candidate, root) => candidate === root || candidate.startsWith(`${root}${path.sep}`);
        const isBrainFile = isWithin(resolved, AIMOS_ROOT);

        if (isBrainFile) {
          // Inside Brain: Requires Reasoning Trace
          const { checkReasoningTrace } = await import('./reasoning-trace-check.js');
          const trace = await checkReasoningTrace(agentId, resolved, {
            canonicalMemories: options.canonicalMemories || [],
          });
          
          if (!trace.valid) {
            return {
              success: false,
              error: `Constitutional Lock: Modification of brain infrastructure rejected. Missing active reasoning trace for path: ${filepath}. Reason: ${trace.reason}`
            };
          }
          console.info(`[fortress] Authorized brain write for ${agentId} on ${filename} (Trace score: ${trace.score})`);
        }

        const uselessFiles = ['memory.md', 'style.md', 'working-memory.md', 'session-memory.md'];

        if (uselessFiles.includes(filename)) {
          return {
            success: false,
            error: `Blocked: creation of local mirror memory file '${filename}' is permanently forbidden. Use Aimos only.`
          };
        }

        const home = os.homedir();
        const ALLOWED_WRITE_DIRS = [
          path.join(home, '.aimos', 'exports'),
          path.join(home, 'Desktop'),
          path.join(home, 'Documents'),
        ];
        const BLOCKED_PATTERNS = [/\.\./, /^\/(etc|usr|var|System|Library|bin|sbin|tmp)\b/];
        if (BLOCKED_PATTERNS.some((p) => p.test(resolved))) {
          return { error: `Path rejected by security policy: ${filepath}` };
        }
        if (!ALLOWED_WRITE_DIRS.some((directory) => isWithin(resolved, directory))) {
          return { error: `file_write restricted to allowed directories. Rejected: ${filepath}` };
        }

        const dir = path.dirname(resolved);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(resolved, content, 'utf8');
        const readback = fs.readFileSync(resolved);
        const stat = fs.statSync(resolved);
        return {
          success: true,
          message: `Successfully wrote ${readback.length} bytes to ${resolved}`,
          content_sha256: createHash('sha256').update(readback).digest('hex'),
          byte_length: readback.length,
          mode: stat.mode & 0o777,
        };
      } catch (err) {
        throw new Error(`Failed to write file: ${err.message}`);
      }
    }
  },

  hive_search_specialists: {
    profile: {
      owner: 'services/orchestration/tool-registry.js#hive_search_specialists',
      operation_class: 'read', required_clearance: 1,
      autonomous_approval_required: false,
      source_kind: 'native_record', source_namespace: 'hom.aimos.agent_profiles',
      source_evidence_requirement: 'native_profile_record_origin',
      result_integrity_ceiling: 'agent', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'hive_search_specialists',
        description: 'Search the collective H.O.M hive for specialized agents by name or capability. Use this to discover who to delegate tasks to.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Capability or keyword to search for (e.g. "research", "finance", "coding")' },
            limit: { type: 'integer', description: 'Max specialists to return (default 5)' }
          },
          required: ['query']
        }
      }
    },
    fn: async ({ query: q, limit = 5 }) => {
      try {
        const rows = await query(
          `SELECT agent_id, name, persona 
           FROM agent_profiles 
           WHERE company_id = $1 
             AND (name ILIKE $2 OR persona ILIKE $2 OR agent_id ILIKE $2)
           LIMIT $3`,
          [COMPANY, `%${q}%`, limit]
        );
        return {
          success: true,
          specialists: rows.rows.map(r => ({
            id: r.agent_id,
            name: r.name,
            capability_summary: r.persona.length > 200 ? r.persona.substring(0, 200) + '...' : r.persona
          }))
        };
      } catch (err) {
        return { error: `Specialist search failed: ${err.message}` };
      }
    }
  },

  schedule_task: {
    profile: {
      owner: 'services/orchestration/scheduler.js#createScheduledTask',
      operation_class: 'orchestration', required_clearance: 5,
      autonomous_approval_required: false,
      source_kind: 'native_record', source_namespace: 'hom.aimos.scheduler',
      source_evidence_requirement: 'signed_schedule_record',
      result_integrity_ceiling: 'agent', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'schedule_task',
        description: 'Create a persisted recurring schedule that triggers an agent task using cron syntax.',
        parameters: {
          type: 'object',
          properties: {
            cron_expression: { type: 'string', description: 'Cron expression, e.g. "0 9 * * 1"' },
            task_description: { type: 'string', description: 'Prompt to run when the schedule fires' },
            agent_id: { type: 'string', description: `Agent ID to run (default: ${getOperatorAgentId()})` },
            label: { type: 'string', description: 'Human-readable label for this schedule' }
          },
          required: ['cron_expression', 'task_description', 'label']
        }
      }
    },
    fn: async ({ cron_expression, task_description, agent_id = getOperatorAgentId(), label }, options = {}) => {
      const schedule = await createScheduledTask({
        cronExpression: cron_expression,
        taskDescription: task_description,
        agentId: agent_id,
        label,
        authority: options.toolActionAuthority,
        actionArguments: options.toolActionArguments,
      });
      return { success: true, scheduled: true, schedule };
    }
  },

  list_scheduled_tasks: {
    profile: {
      owner: 'services/orchestration/scheduler.js#listScheduledTasks',
      operation_class: 'read', required_clearance: 2,
      autonomous_approval_required: false,
      source_kind: 'native_record', source_namespace: 'hom.aimos.scheduler',
      source_evidence_requirement: 'signed_schedule_record',
      result_integrity_ceiling: 'agent', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'list_scheduled_tasks',
        description: 'List persisted scheduled tasks and their latest execution status.',
        parameters: { type: 'object', properties: {} }
      }
    },
    fn: async () => {
      const items = await listScheduledTasks();
      return { success: true, items };
    }
  },

  delegate_task: {
    profile: {
      owner: 'services/orchestration/agent-runner.js#runAgent',
      operation_class: 'orchestration', required_clearance: 3,
      autonomous_approval_required: false,
      source_kind: 'native_derivation', source_namespace: 'hom.aimos.delegation',
      source_evidence_requirement: 'parent_tool_action_child_run_and_result_origin',
      result_integrity_ceiling: 'agent', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'delegate_task',
        description: 'Delegate a complex task to a specialized sub-agent. Returns structured result with status, confidence, response, and diagnostics. Parent can use wait=true to block until child completes (up to timeout).',
        parameters: {
          type: 'object',
          properties: {
            agent_id: { type: 'string', description: 'The precise ID of the specialized agent to wake up (e.g. "academic-researcher", "data-analyst", "frontend", etc.)' },
            task_prompt: { type: 'string', description: 'A highly detailed instructional prompt explaining exactly what you want the sub-agent to do.' },
            wait: { type: 'boolean', description: 'If true, block until child completes or timeout (default: false = fire-and-forget)' },
            delegation_context: { type: 'object', description: 'Scoped task data passed to the child; never identity or operation authority' },
            source_memory_ids: { type: 'array', items: { type: 'string' }, description: 'Additional retained inputs; inherited runtime inputs remain mandatory' }
          },
          required: ['agent_id', 'task_prompt']
        }
      }
    },
    fn: async ({ agent_id, task_prompt, wait = false, delegation_context = {}, source_memory_ids }, originAgentId = '', options = {}) => {
      try {
        const executionContext = options.executionContext || options.credentialUseContext;
        if (!executionContext?.actorAgentId || !options.toolActionAuthority) {
          throw new Error('verified_delegation_authority_required');
        }
        const authorizedArgs = options.toolActionArguments || {
          agent_id, task_prompt, wait, delegation_context,
          ...(source_memory_ids === undefined ? {} : { source_memory_ids }),
        };
        if (authorizedArgs.agent_id !== agent_id
            || authorizedArgs.task_prompt !== task_prompt
            || (authorizedArgs.wait ?? false) !== wait
            || canonicalJson(authorizedArgs.delegation_context ?? {}) !== canonicalJson(delegation_context)
            || canonicalJson(authorizedArgs.source_memory_ids ?? null)
              !== canonicalJson(source_memory_ids ?? null)) {
          throw new Error('consequential_action_argument_substitution');
        }
        await verifyToolActionAuthority(options.toolActionAuthority, {
          expectedCompanyId: COMPANY,
          expectedTool: 'delegate_task',
          expectedActorAgentId: executionContext.actorAgentId,
          expectedArguments: authorizedArgs,
        });
        const taskId = `delegate-${agent_id}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const childInputs = createToolInputState(options.inputMemoryIds || [], options.nativeToolInputs);
        recordToolContextInput(childInputs, { kind: 'derived',
          owner: 'services/orchestration/tool-registry.js#delegate_task',
          ref: options.toolActionAuthority.eventId, value: { task_prompt, delegation_context } });
        console.log(`[orchestrator] ${wait ? 'Awaiting' : 'Queueing'} delegated task ${taskId} for sub-agent: ${agent_id}`);

        // ─── P0-5: Structured delegation with return channels ─────────────────
        // Child writes result to Aimos: delegation:{task_id}:result
        // Parent can poll or use wait=true for synchronous result.
        // Exit status enables conditional branching.

        const executeDelegate = async () => {
          const startedAt = Date.now();
          let result;
          let structured;
          try {
            const effectiveParentRunId = options.runId || options.parentRunId || null;
            const effectiveDelegationContext = {
              ...delegation_context,
              sourceAgentId: originAgentId || options.agentId || getOperatorAgentId(),
              parentRunId: effectiveParentRunId,
              conversationSessionKey: options.sessionKey || delegation_context.conversationSessionKey || null
            };
            result = await runAgent(agent_id, task_prompt, {
                skipAimos: true,
                originAgentId,
                delegationContext: effectiveDelegationContext,
                parentRunId: effectiveParentRunId,
                sessionKey: options.sessionKey || null,
                taskType: options.taskType || 'delegated_task',
                _scopedState: options._scopedState || null,
                depth: Number(options.depth || 0) + 1,
                executionContext,
                credentialUseContext: options.credentialUseContext || executionContext,
                sourceMemoryIds: options.inputMemoryIds || [],
                nativeToolInputs: childInputs,
                ...(options.selectedModel ? {
                  model: options.selectedModel,
                  requestedModel: options.selectedModel,
                  strictRequestedModel: true,
                  modelPlan: [options.selectedModel],
                } : {}),
              });

            const elapsed = Date.now() - startedAt;
            const response = typeof result === 'string' ? result : (result?.response || JSON.stringify(result));
            const confidence = typeof result === 'object' ? (result?.confidence || 0.5) : 0.5;

            // Structured return protocol (Quine-inspired)
            structured = {
              status: 0, // 0=success
              confidence,
              response: String(response || ''),
              diagnostics: [],
              wisdom: { task_id: taskId, agent_id, elapsed_ms: elapsed },
              task_id: taskId
            };

            console.log(`[orchestrator] Delegated task ${taskId} completed in ${elapsed}ms (status: 0)`);
          } catch (err) {
            const elapsed = Date.now() - startedAt;
            structured = {
              status: err.message?.includes('timeout') ? 1 : 2, // 1=partial(timeout), 2=failed
              confidence: 0,
              response: '',
              diagnostics: [err.message],
              wisdom: { task_id: taskId, agent_id, elapsed_ms: elapsed, error: err.message },
              task_id: taskId
            };

            console.error(`[orchestrator] Delegated task ${taskId} failed after ${elapsed}ms (status: ${structured.status})`, err.message);
          }
          // The original actor owns the result. The child runtime name is
          // attribution, not a new signer or a Housekeeper privilege grant.
          const sourceMemoryIds = [...new Set([
            ...(options.inputMemoryIds || []), ...readToolInputState(childInputs).memory_ids,
          ])].sort();
          structured.origin_inputs = {
            memory_ids: sourceMemoryIds,
            parent_tool_event_id: options.toolActionAuthority.eventId,
            child: readToolInputState(childInputs),
          };
          const spec = {
            company_id: COMPANY,
            agent_id: executionContext.actorAgentId,
            key: `delegation:${taskId}:result`,
            value: JSON.stringify(structured),
            scope: 'private',
            memory_type: 'delegation_result',
            clearance_level: Number(options.clearanceLevel || 1),
            source: 'tool-registry',
            session_id: options.sessionKey || null,
            source_memory_ids: sourceMemoryIds,
          };
          const commitAction = await beginToolAction({
            tool: 'aimos_save_commit', args: spec, runtimeAgentId: originAgentId,
            inputState: childInputs,
            executionContext, parentEventId: options.toolActionAuthority.eventId,
          });
          try {
            const saved = await executeCanonicalSave({ ...spec, mutation_authority: commitAction.authority });
            if (saved?.rejected || !saved?.id) throw new Error(saved?.reason || 'delegation_result_save_failed');
            await finishToolAction({ action: commitAction, executionContext, succeeded: true, result: { memory_id: saved.id } });
            if (wait) mergeToolInputState(options.nativeToolInputs, childInputs);
            return { ...structured, memory_id: saved.id, save_commit_event_id: commitAction.receipt.event_id };
          } catch (error) {
            await finishToolAction({ action: commitAction, executionContext, succeeded: false, error: error.message });
            throw error;
          }
        };

        if (wait) {
          // Synchronous mode: block until child completes
          const result = await executeDelegate();
          return result;
        }

        // Async mode: fire-and-forget with result saved to Aimos
        setImmediate(() => { executeDelegate().catch(error => {
          console.error(`[orchestrator] Delegated result persistence failed for ${taskId}: ${error.message}`);
        }); });

        return {
          success: true,
          queued: true,
          task_id: taskId,
          agent_id: agent_id,
          message: `Task queued for ${agent_id}. Result will be at delegation:${taskId}:result`
        };
      } catch (err) {
        console.error(`[orchestrator] Delegation failed:`, err);
        return {
          status: 2,
          error: `Failed to execute sub-agent ${agent_id}: ${err.message}`,
          diagnostics: [err.message]
        };
      }
    }
  },

  read_file: {
    profile: {
      owner: 'services/orchestration/tool-registry.js#read_file',
      operation_class: 'read', required_clearance: 3,
      autonomous_approval_required: false,
      source_kind: 'local_file', source_namespace: 'local.files',
      source_evidence_requirement: 'authorized_file_read_and_content_hash',
      result_integrity_ceiling: 'untrusted', confidentiality_floor: 'confidential',
    },
    schema: {
      type: 'function',
      function: {
        name: 'read_file',
        description: 'Read the contents of a local file on the Mac. Use absolute paths.',
        parameters: {
          type: 'object',
          properties: {
            filepath: { type: 'string', description: 'Absolute path of the file to read (e.g. /absolute/path/data.txt)' }
          },
          required: ['filepath']
        }
      }
    },
    fn: async ({ filepath }) => {
      try {
        if (!fs.existsSync(filepath)) {
          return { error: `File not found: ${filepath}` };
        }
        const content = fs.readFileSync(filepath, 'utf8');
        // Truncate if too large to prevent breaking the context window
        if (content.length > 50000) {
          return { content: content.substring(0, 50000) + '\\n\\n...[TRUNCATED: File too large]...' };
        }
        return { content };
      } catch (err) {
        return { error: `Failed to read file: ${err.message}` };
      }
    }
  },

  sun_tzu_analyze: {
    profile: {
      owner: 'services/orchestration/sun-tzu-analyzer.js#analyzeSituation',
      operation_class: 'read', required_clearance: 1,
      autonomous_approval_required: false,
      source_kind: 'native_derivation', source_namespace: 'hom.aimos.analysis',
      source_evidence_requirement: 'signed_tool_action_and_input_origins',
      result_integrity_ceiling: 'agent', confidentiality_floor: 'internal',
    },
    schema: {
      type: 'function',
      function: {
        name: 'sun_tzu_analyze',
        description: 'Analyze any strategic situation through Sun Tzu\'s Art of War framework. Returns a full battlefield analysis: engagement classification, Five Constant Factors, force ratios, CHENG/CH\'I assessment, and a decisive recommended move.',
        parameters: {
          type: 'object',
          properties: {
            situation: { type: 'string', description: 'Description of the strategic situation to analyze' },
            context: { type: 'string', description: 'Additional context: market conditions, competitors, resources, constraints' }
          },
          required: ['situation']
        }
      }
    },
    fn: async ({ situation, context }) => analyzeSituation({ situation, context })
  }
};

// ─── SUITE → TOOL MAP ─────────────────────────────────────────────────────────

const SUITE_TO_TOOLS = {
  'full': ['web_search', 'gmail_inbox', 'gmail_search', 'gmail_send', 'gmail_reply', 'youtube_search', 'youtube_channel','drive_list', 'drive_read', 'docs_read', 'sheets_read', 'google_profile', 'calendar_today', 'calendar_events', 'calendar_create', 'stripe_account_summary', 'stripe_list_customers', 'stripe_list_subscriptions', 'stripe_list_payment_intents', 'integrations_status', 'github_list_repos', 'github_search_issues', 'salesforce_list_objects', 'contacts_search', 'imessage_chats', 'imessage_search_contact', 'imessage_request_access', 'imessage_send', 'telegram_send', 'aimos_recall', 'aimos_save', 'write_file', 'read_file', 'schedule_task', 'list_scheduled_tasks', 'delegate_task', 'hive_search_specialists', 'x_search', 'x_post', 'x_reply', 'x_quote', 'sun_tzu_analyze'],
  'web-search': ['web_search', 'aimos_recall', 'aimos_save'],
  'x-search': ['x_search', 'aimos_recall', 'aimos_save'],
  'x': ['x_search', 'x_post', 'x_reply', 'x_quote', 'aimos_recall', 'aimos_save'],
  'google': ['web_search', 'gmail_inbox', 'gmail_search', 'gmail_send', 'gmail_reply', 'youtube_search', 'youtube_channel','drive_list', 'drive_read', 'docs_read', 'sheets_read', 'google_profile', 'calendar_today', 'calendar_events', 'calendar_create', 'aimos_recall', 'aimos_save'],
  'sheets': ['sheets_read', 'aimos_recall', 'aimos_save'],
  'google-profile': ['google_profile'],
  'stripe': ['stripe_account_summary', 'stripe_list_customers', 'stripe_list_subscriptions', 'stripe_list_payment_intents', 'aimos_recall', 'aimos_save'],
  'integrations': ['integrations_status', 'github_list_repos', 'github_search_issues', 'salesforce_list_objects', 'contacts_search', 'imessage_chats', 'imessage_search_contact', 'imessage_request_access', 'imessage_send', 'telegram_send', 'aimos_recall', 'aimos_save'],
  'gmail-read': ['gmail_inbox', 'gmail_search', 'aimos_recall', 'aimos_save'],
  'gmail-send': ['gmail_send', 'gmail_reply'],
  'gmail-search': ['gmail_search'],
  'youtube': ['youtube_search', 'youtube_channel','aimos_recall', 'aimos_save'],
  'drive': ['drive_list', 'drive_read', 'aimos_recall', 'aimos_save'],
  'calendar': ['calendar_today', 'calendar_events', 'calendar_create', 'aimos_recall', 'aimos_save'],
  'docs': ['docs_read', 'aimos_recall', 'aimos_save'],
  'aimos': ['aimos_recall', 'aimos_save'],
  'research': ['web_search', 'gmail_search', 'youtube_search','drive_list', 'drive_read', 'docs_read', 'sheets_read', 'google_profile', 'stripe_account_summary', 'stripe_list_customers', 'stripe_list_subscriptions', 'integrations_status', 'github_list_repos', 'salesforce_list_objects', 'contacts_search', 'imessage_search_contact', 'aimos_recall', 'aimos_save', 'delegate_task'],
  'sun-tzu': ['sun_tzu_analyze', 'aimos_recall', 'aimos_save']
};

// ─── CLEARANCE LEVELS PER TOOL (Aimos Order v2 Layer 1: Decision Rights) ─────
// Level 1 = any agent, Level 3 = mid-tier, Level 5 = CEO/Reviewer only
const TOOL_CLEARANCE_LEVELS = Object.freeze(Object.fromEntries(
  Object.entries(ALL_TOOL_DEFS).map(([name, tool]) => [name, tool.profile.required_clearance]),
));

const SIDE_EFFECT_TOOLS = new Set(Object.entries(ALL_TOOL_DEFS)
  .filter(([, tool]) => tool.profile.operation_class !== 'read').map(([name]) => name));

const QUOTA_SPENDING_TOOLS = new Set(Object.entries(ALL_TOOL_DEFS)
  .filter(([, tool]) => tool.profile.autonomous_approval_required).map(([name]) => name));
const CORROBORATED_ACTION_EXECUTION = Symbol('hom.aimos.corroborated-action-execution');

const TOOL_DIRECTIONS = Object.freeze({
  READ: 'read',
  MEMORY_WRITE: 'memory_write',
  INTERNAL_WRITE: 'internal_write',
  EXTERNAL_WRITE: 'external_write',
  ORCHESTRATION: 'orchestration'
});

// Code-owned policy declarations, not connector connectivity or result verdicts.
// Louck M2: opaque output inherits every input's restrictions; an authenticated
// transport never makes its content an independent trusted corroborator.
function freezeToolDefinition(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeToolDefinition(child);
    Object.freeze(value);
  }
  return value;
}

for (const [name, definition] of Object.entries(ALL_TOOL_DEFS)) {
  const p = definition.profile;
  const actionAuthority = consequentialActionPolicyForTool(name);
  const fields = ['owner', 'operation_class', 'required_clearance', 'autonomous_approval_required',
    'source_kind', 'source_namespace', 'source_evidence_requirement',
    'result_integrity_ceiling', 'confidentiality_floor'];
  if (!p || Object.keys(p).length !== fields.length || fields.some(field => !Object.hasOwn(p, field))
    || typeof definition.fn !== 'function' || definition.schema?.function?.name !== name
    || definition.schema?.function?.parameters?.type !== 'object'
    || typeof p.owner !== 'string' || !/^services\/[a-z0-9\/-]+\.js#[A-Za-z0-9_+]+$/.test(p.owner)
    || !Object.values(TOOL_DIRECTIONS).includes(p.operation_class)
    || !Number.isInteger(p.required_clearance) || p.required_clearance < 1 || p.required_clearance > 12
    || typeof p.autonomous_approval_required !== 'boolean'
    || !['credential_account', 'native_memory', 'native_record', 'native_derivation', 'local_file', 'host_automation'].includes(p.source_kind)
    || typeof p.source_namespace !== 'string' || !/^[a-z0-9._-]+$/.test(p.source_namespace)
    || typeof p.source_evidence_requirement !== 'string' || !/^[a-z_]+$/.test(p.source_evidence_requirement)
    || !['untrusted', 'agent'].includes(p.result_integrity_ceiling)
    || !['internal', 'confidential', 'restricted'].includes(p.confidentiality_floor)
    || (['external_write', 'internal_write', 'orchestration'].includes(p.operation_class)
      ? actionAuthority == null : actionAuthority != null)) {
    throw new Error(`native_tool_profile_invalid:${name}`);
  }
  definition.profile = freezeToolDefinition({
    schema: 'hom.aimos.native-tool-profile/v1',
    tool: name,
    version: 1,
    family_profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
    ...p,
    ...(actionAuthority ? { action_authority: actionAuthority } : {}),
    argument_schema: definition.schema.function.parameters,
    input_policy: {
      arguments: 'exact_signed_arguments',
      context: 'all_runtime_consumed_inputs',
      source: p.source_evidence_requirement,
      missing_origin: 'unknown_protected',
    },
    result_policy: {
      family_ids: ['derived', 'derived.tool_result'],
      family_rule: 'closure_of_all_input_families_and_tool_result',
      confidentiality_rule: 'join_all_inputs_and_profile_floor',
      integrity_rule: 'meet_all_inputs_and_profile_ceiling',
      action_rule: 'no_new_action_authority',
      independent_authority: false,
    },
  });
  definition.profile_sha256 = createHash('sha256')
    .update(canonicalJson(definition.profile), 'utf8').digest('hex');
  freezeToolDefinition(definition);
}
Object.freeze(ALL_TOOL_DEFS);

export function getNativeToolProfile(name) {
  if (!Object.hasOwn(ALL_TOOL_DEFS, name)) throw new Error(`native_tool_unregistered:${String(name)}`);
  const definition = ALL_TOOL_DEFS[name];
  if (!definition.profile_sha256 || !Object.isFrozen(definition.profile)) {
    throw new Error(`native_tool_profile_invalid:${name}`);
  }
  return Object.freeze({ profile: definition.profile, sha256: definition.profile_sha256 });
}

function resolveToolDirection(toolName = '') {
  return getNativeToolProfile(toolName).profile.operation_class;
}

function normalizeDirection(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  switch (normalized) {
    case 'read':
      return TOOL_DIRECTIONS.READ;
    case 'memory_write':
    case 'memory-write':
    case 'memory':
      return TOOL_DIRECTIONS.MEMORY_WRITE;
    case 'internal_write':
    case 'internal-write':
    case 'internal':
      return TOOL_DIRECTIONS.INTERNAL_WRITE;
    case 'external_write':
    case 'external-write':
    case 'external':
      return TOOL_DIRECTIONS.EXTERNAL_WRITE;
    case 'orchestration':
    case 'orchestrate':
      return TOOL_DIRECTIONS.ORCHESTRATION;
    default:
      return null;
  }
}

function buildDirectionalityPolicy(options = {}) {
  const policy = options?.directionalityPolicy;
  const policyProvided = !!policy
    || Array.isArray(options?.allowedDirections)
    || Array.isArray(options?.deniedDirections);
  if (!policyProvided) return null;

  const allow = new Set();
  const deny = new Set();
  const allowCandidates = [
    ...(Array.isArray(policy?.allow) ? policy.allow : []),
    ...(Array.isArray(options?.allowedDirections) ? options.allowedDirections : [])
  ];
  const denyCandidates = [
    ...(Array.isArray(policy?.deny) ? policy.deny : []),
    ...(Array.isArray(options?.deniedDirections) ? options.deniedDirections : [])
  ];

  for (const candidate of allowCandidates) {
    const normalized = normalizeDirection(candidate);
    if (normalized) allow.add(normalized);
  }
  for (const candidate of denyCandidates) {
    const normalized = normalizeDirection(candidate);
    if (normalized) deny.add(normalized);
  }

  if (!allow.size) {
    Object.values(TOOL_DIRECTIONS).forEach((direction) => allow.add(direction));
  }

  return {
    enabled: policy?.enabled !== false,
    allow,
    deny,
    reason: policy?.reason || null
  };
}

function getToolSchema(name) {
  return ALL_TOOL_DEFS[name]?.schema?.function?.parameters || null;
}

function preflightValidateArgs(name, args) {
  const params = getToolSchema(name);
  if (!params || typeof params !== 'object') return [];
  const required = Array.isArray(params.required) ? params.required : [];
  const issues = [];

  for (const key of required) {
    const value = args?.[key];
    if (value === undefined || value === null || value === '') {
      issues.push(`Missing required argument: ${key}`);
    }
  }

  return issues;
}

function buildToolPlan(name, args, agentId) {
  const nativeProfile = getNativeToolProfile(name);
  const sideEffecting = SIDE_EFFECT_TOOLS.has(name);
  return {
    kind: 'tool_preflight',
    intent: name,
    tool: name,
    agentId,
    risk: sideEffecting ? 'high' : (name === 'x_search' ? 'medium' : 'low'),
    direction: resolveToolDirection(name),
    native_tool_profile: nativeProfile.profile,
    native_tool_profile_sha256: nativeProfile.sha256,
    preview: previewArgs(args),
    sideEffecting,
    args: args || {},
    createdAt: new Date().toISOString()
  };
}

export function buildToolRepresentation(name, options = {}) {
  return buildToolRepresentationDiagnostic(name, {
    ...options,
    toolDefs: ALL_TOOL_DEFS,
    sideEffectTools: SIDE_EFFECT_TOOLS,
    quotaSpendingTools: QUOTA_SPENDING_TOOLS,
    toolClearanceLevels: TOOL_CLEARANCE_LEVELS,
    suiteToTools: SUITE_TO_TOOLS,
    resolveToolDirection
  });
}

function previewArgs(args) {
  try {
    const serialized = JSON.stringify(args || {});
    if (serialized.length <= 280) return serialized;
    return `${serialized.slice(0, 277)}...`;
  } catch {
    return '{}';
  }
}

function isExplicitXIntent(intent = '', userPrompt = '', args = {}) {
  const normalizedIntent = String(intent || '').trim().toLowerCase();
  const normalizedPrompt = String(userPrompt || '').trim().toLowerCase();
  const queryText = String(args?.query || '').trim().toLowerCase();

  if (normalizedIntent === 'x_search' || normalizedIntent === 'x' || normalizedIntent === 'twitter') {
    return true;
  }

  return X_INTENT_MARKERS.some((marker) =>
    normalizedIntent.includes(marker) || normalizedPrompt.includes(marker) || queryText.includes(marker)
  );
}

export function getToolsForAgent(toolSuitesOrNames, options = {}) {
  const agentId = String(options.agentId || '').trim().toLowerCase();
  const allowLocalDisk = isOperatorAgentId(agentId);
  const toolSet = new Set();
  const denySet = new Set(Array.isArray(options.deny) ? options.deny : []);
  const allowSet = new Set(Array.isArray(options.allow) ? options.allow : []);

  const suites = Array.isArray(toolSuitesOrNames)
    ? toolSuitesOrNames
    : [toolSuitesOrNames].filter(Boolean);

  for (const suite of suites) {
    if (SUITE_TO_TOOLS[suite]) {
      for (const tool of SUITE_TO_TOOLS[suite]) {
        toolSet.add(tool);
      }
      continue;
    }
    // Support direct tool names from policy deltas.
    if (ALL_TOOL_DEFS[suite]) {
      toolSet.add(suite);
    }
  }

  for (const toolName of allowSet) {
    if (ALL_TOOL_DEFS[toolName]) toolSet.add(toolName);
  }

  for (const toolName of denySet) {
    toolSet.delete(toolName);
  }

  // Local filesystem access is restricted to the executive lane only.
  if (allowLocalDisk) {
    toolSet.add('write_file');
    toolSet.add('read_file');
  } else {
    toolSet.delete('write_file');
    toolSet.delete('read_file');
  }

  // Scheduling is an orchestration power reserved for the executive lane.
  if (!isOperatorAgentId(agentId)) {
    toolSet.delete('schedule_task');
    toolSet.delete('list_scheduled_tasks');
  }

  return [...toolSet].filter(name => Object.hasOwn(ALL_TOOL_DEFS, name)).map(name => {
    getNativeToolProfile(name);
    return ALL_TOOL_DEFS[name];
  });
}

export function getToolRepresentationsForAgent(toolSuitesOrNames, options = {}) {
  return getToolsForAgent(toolSuitesOrNames, options)
    .map((toolDef) => toolDef?.schema?.function?.name)
    .filter(Boolean)
    .map((name) => buildToolRepresentation(name, options));
}

export async function executeTool(name, args, agentId, options = {}) {
  const finishWork = beginServingWork('native_tool');
  try {
  options = { ...options, signal: AbortSignal.any([getServingAbortSignal(), ...(options.signal ? [options.signal] : [])]) };
  const nativeProfile = getNativeToolProfile(name);
  const tool = ALL_TOOL_DEFS[name];
  const inputState = options.nativeToolInputs || createToolInputState();
  readToolInputState(inputState);
  const executionContext = options.executionContext || options.credentialUseContext || null;
  let signedToolAction = null;
  let finalizing = false;
  let toolInvoked = false;
  let memoryGrant = null;
  // Every caller receives the same JSON-visible result that this native owner
  // classifies. A denial start records an attempt, never dispatch authority.
  async function completeResult(result, disposition, disclosedResult = result) {
    finalizing = true;
    if (!signedToolAction) signedToolAction = await beginToolAction({
      tool: name, args: args || {}, runtimeAgentId: String(agentId || ''),
      executionContext, parentEventId: options.securityDecisionEventId || null,
      inputState, nativeProfile, dispatchAllowed: false,
    });
    const classification = await classifyNativeResult({ state: inputState,
      companyId: executionContext.companyId, actionEventId: signedToolAction.receipt.event_id,
      profile: nativeProfile.profile, result, disclosedResult,
      execution: { disposition, tool_invoked: toolInvoked } });
    const terminal = await finishToolAction({ action: signedToolAction, executionContext,
      disposition, result, classification });
    recordToolInputResult(inputState, { action: signedToolAction, terminal, result, disclosedResult, classification });
    recordKnowledgeToolEvent(options.knowledgeGateState, {
      toolName: name, result: disclosedResult, blocked: disposition !== 'SUCCEEDED',
    });
    await notifyToolObserver(options.onToolResult, { toolName: name, args,
      result: disclosedResult, blocked: disposition !== 'SUCCEEDED' });
    return disclosedResult;
  }
  try {
  const allowedTools = Array.isArray(options.allowedTools) ? new Set(options.allowedTools) : null;
  if (allowedTools && !allowedTools.has(name)) {
    throw new Error(`Tool '${name}' is not allowed for this run.`);
  }
  const validationIssues = preflightValidateArgs(name, args);
  if (validationIssues.length) {
    throw new Error(`Tool preflight failed for '${name}': ${validationIssues.join('; ')}`);
  }
  if (name === 'aimos_recall' || name === 'aimos_save') {
    memoryGrant = await readNativeMemoryToolGrant(options.executionContext || options.credentialUseContext);
    if (!memoryGrant?.allowed || (name === 'aimos_save' && !memoryGrant.write_allowed)) {
      throw new Error(name === 'aimos_save' ? 'master_signed_memory_write_grant_required' : 'master_signed_memory_read_grant_required');
    }
    const requestedClearance = Number(options.clearanceLevel ?? memoryGrant.clearance_ceiling);
    if (!Number.isInteger(requestedClearance) || requestedClearance < 1) throw new Error('native_memory_tool_clearance_invalid');
    options = { ...options, clearanceLevel:Math.min(requestedClearance,memoryGrant.clearance_ceiling) };
  } else if (options.clearanceLevel == null && executionContext?.authSource === 'envelope') {
    const actorGrant = await readNativeMemoryToolGrant(executionContext);
    if (!actorGrant?.allowed) throw new Error('master_signed_agent_clearance_required');
    options = { ...options, clearanceLevel: actorGrant.clearance_ceiling };
  }

  const toolDirection = resolveToolDirection(name);
  const directionalityPolicy = buildDirectionalityPolicy(options);
  if (directionalityPolicy?.enabled) {
    const explicitlyDenied = directionalityPolicy.deny.has(toolDirection);
    const explicitlyAllowed = directionalityPolicy.allow.has(toolDirection);
    if (explicitlyDenied || !explicitlyAllowed) {
      const blockedResult = {
        error: `Tool '${name}' blocked by directionality policy`,
        blocked: true,
        directionality: {
          toolDirection,
          reason: directionalityPolicy.reason || null,
          explicitlyDenied
        }
      };
      return await completeResult(blockedResult, 'DENIED');
    }
  }

  const taskHasXIntent = (options.taskDescription || options.userPrompt || '').toLowerCase().match(/auto.?engage|x auto|x_search|tweet|twitter|quote tweet/);
  if (name === 'x_search' && !isExplicitXIntent(options.intent, options.userPrompt, args) && !taskHasXIntent) {
    throw new Error("Tool 'x_search' is restricted to explicit X/Twitter requests.");
  }

  const knowledgeGateBlock = shouldBlockToolForMissingKnowledge(options.knowledgeGateState, name);
  if (knowledgeGateBlock.blocked && !options.approvalEvidence) {
    const blockedResult = {
      error: knowledgeGateBlock.message,
      blocked: true,
      knowledgeGate: knowledgeGateBlock
    };
    return await completeResult(blockedResult, 'DENIED');
  }

  // ─── CLEARANCE GATE (Aimos Order v2 Layer 1: Decision Rights) ──────────────
  const requiredClearance = nativeProfile.profile.required_clearance;
  const agentClearance = Number(options.clearanceLevel || 1);
  if (agentClearance < requiredClearance) {
    const escalation = {
      type: 'clearance_escalation',
      tool: name,
      agentId,
      requiredClearance,
      agentClearance,
      timestamp: new Date().toISOString()
    };
    const blockedResult = {
      error: `Clearance insufficient: agent level ${agentClearance} < tool requires ${requiredClearance}`,
      escalation,
      blocked: true
    };
    return await completeResult(blockedResult, 'DENIED');
  }

  // Direct native callers do not pass through agent-runner's tool-list
  // filter. Local disk reads therefore need their own native-owner check.
  // The designated operator keeps its signed system-config boundary. Any
  // other identity must present a master-signed, exact-epoch purpose proof
  // restricted to the requested file's owner-only root.
  let purposeAuthorizationReceipt = null;
  if (name === 'read_file' && !isOperatorAgentId(agentId)) {
    const serialized = options.purposeAuthorization || null;
    if (!serialized) throw new Error('master_signed_local_file_read_authorization_required');
    if (!/^[0-9a-f]{64}$/.test(String(options.protocolConfirmationSha256 || ''))) {
      throw new Error('purpose_authorization_protocol_commitment_required');
    }
    const masterPubkey = await masterPubkeyCache.get();
    if (!masterPubkey) throw new Error('purpose_authorization_master_pubkey_unavailable');
    purposeAuthorizationReceipt = authorizePurposeLocalFileRead({
      serialized,
      masterPubkeyB64u: masterPubkey,
      executionContext: options.executionContext || options.credentialUseContext || null,
      agentId,
      tool: name,
      filepath: args?.filepath,
      clearanceLevel: agentClearance,
      expectedProtocolConfirmationSha256: options.protocolConfirmationSha256 || null,
    });
  }

  const approvalRequired = Boolean(nativeProfile.profile.action_authority);
  const approvalEvidence = options.approvalEvidence || null;
  const approved = Boolean(approvalEvidence);
  if (options.approved === true && !approvalEvidence) {
    throw new Error('signed_tool_approval_execution_evidence_required');
  }

  if (!approved && approvalRequired && options[CORROBORATED_ACTION_EXECUTION] !== true) {
    const plan = buildToolPlan(name, args, agentId);
    const approvalRequest = await createToolApprovalRequest({
      tool: name,
      args: args || {},
      agentId: String(agentId || 'unknown'),
      plan,
      authority: options.executionContext || options.credentialUseContext || null,
      parentEventId: options.securityDecisionEventId || null,
    });
    const result = {
      error: `Approval required before executing '${name}'`,
      requiresApproval: true,
      sandbox: false,
      plan,
      approvalRequestId: approvalRequest.id,
      approvalRequest
    };
    return await completeResult(result, 'DENIED');
  }

  // ─── Wire #29: Intent Classifier — scope enforcement before execution ───────
  {
    const intentClass = classifyIntent(options.userPrompt || '', [name]);
    // Tool dispatch is an internal function call, not an HTTP request. Map the
    // declared tool direction to the equivalent policy verb so read-only tools
    // do not get misclassified as writes merely because they are invoked.
    const policyVerb = toolDirection === TOOL_DIRECTIONS.READ ? 'GET' : 'POST';
    const verbPolicy = enforceVerbPolicy(intentClass.scope, policyVerb);
    if (!verbPolicy.allowed) {
      const blockedResult = {
        error: `Intent scope enforcement blocked tool '${name}': ${verbPolicy.reason}`,
        blocked: true,
        intentScope: intentClass.scope
      };
      return await completeResult(blockedResult, 'DENIED');
    }
  }

  // ─── Wire #28: Execution Interceptor — fail-closed gate wrapping execution ─
  {
    if (options.approvedPlan) {
      const interceptResult = await validateExecution(name, 'POST', args, options.approvedPlan, COMPANY);
      if (!interceptResult.allowed) {
        const blockedResult = {
          error: `Execution interceptor blocked tool '${name}': ${interceptResult.reason}`,
          blocked: true,
          violations: interceptResult.violations
        };
        return await completeResult(blockedResult, 'DENIED');
      }
    }
  }

    let actionParentEventId = options.securityDecisionEventId || null;
    let actionAuthorization = null;
    if (approvalEvidence) {
      const approvalClaim = await claimToolApprovalExecution({
        ...approvalEvidence,
        tool: name,
        args: args || {},
        agentId: String(agentId || ''),
        authority: options.executionContext || options.credentialUseContext || null,
      });
      actionParentEventId = approvalClaim.receipt.event_id;
      actionAuthorization = {
        eventId: approvalClaim.receipt.event_id,
        mutationSha256: approvalClaim.receipt.mutation_hash,
        operatorProof: approvalEvidence.operatorProof || null,
      };
    }
    signedToolAction = await beginToolAction({
      tool: name,
      args: args || {},
      runtimeAgentId: String(agentId || ''),
      executionContext,
      parentEventId: actionParentEventId,
      purposeAuthorizationReceipt,
      inputState,
      nativeProfile,
      memoryGrant,
      actionAuthorization,
    });
    if (signedToolAction.authority.actionOriginDecision
        && signedToolAction.authority.actionOriginDecision !== 'ALLOW') {
      return await completeResult({
        error: `Consequential action '${name}' ${signedToolAction.authority.actionOriginDecision.toLowerCase()} by origin authority`,
        blocked: true,
        code: signedToolAction.authority.actionOriginDecision === 'INDETERMINATE'
          ? 'CONSEQUENTIAL_ACTION_INDETERMINATE'
          : 'CONSEQUENTIAL_ACTION_DENIED',
      }, signedToolAction.authority.actionOriginDecision === 'INDETERMINATE'
        ? 'INDETERMINATE' : 'DENIED');
    }
    const canaryContext = {
      parentEventId: signedToolAction.receipt.event_id,
      authority: executionContext,
    };
    const canaryExecution = await scanToolExecution(
      name,
      args || {},
      options.runId || signedToolAction.receipt.event_id,
      canaryContext,
    );
    if (canaryExecution.blocked) {
      const error = new Error(`Canary token blocked before '${name}' tool dispatch.`);
      error.code = 'CANARY_TOOL_EXECUTION_BLOCKED';
      error.blocked = true;
      error.canaryTokens = canaryExecution.canariesFound;
      error.killChainDiagnostics = canaryExecution.kill_chain_diagnostics;
      throw error;
    }
    const invocationOptions = {
      ...options,
      nativeToolInputs: inputState,
      inputMemoryIds: signedToolAction.sourceMemoryIds,
      toolActionAuthority: signedToolAction.authority,
      toolActionArguments: Object.freeze(JSON.parse(canonicalJson(args || {}))),
      credentialUseContext: Object.freeze({
        ...(options.executionContext || options.credentialUseContext || {}),
        signal: options.signal && executionContext?.signal
          ? AbortSignal.any([options.signal, executionContext.signal]) : options.signal || executionContext?.signal,
        deadlineAt: options.deadlineAt === undefined ? executionContext?.deadlineAt
          : Math.min(options.deadlineAt, executionContext?.deadlineAt ?? Infinity),
        autonomousActionEventId: signedToolAction.authority.eventId,
        toolActionAuthority: signedToolAction.authority,
        toolActionArguments: Object.freeze(JSON.parse(canonicalJson(args || {}))),
      }),
    };
    const invokeTool = () => {
      invocationOptions.credentialUseContext.signal?.throwIfAborted();
      if (performance.now() >= (invocationOptions.credentialUseContext.deadlineAt ?? Infinity)) {
        throw new DOMException('Tool operation deadline exceeded', 'TimeoutError');
      }
      options.signal.throwIfAborted();
      toolInvoked = true;
      if (name === 'aimos_save' || name === 'delegate_task' || name === 'write_file') {
        return tool.fn(args, agentId, invocationOptions);
      }
      if (name === 'aimos_recall') {
        return tool.fn(args, invocationOptions);
      }
      return tool.fn(args, invocationOptions);
    };
    // Settle the native integration before signing its consumed inputs/result.
    // Integration-owned request/child deadlines still apply. A dispatcher
    // Promise.race cannot cancel a side effect or freeze inputs it still reads.
    const result = await invokeTool();
    const canaryExposure = await scanToolResult(
      name,
      result,
      options.runId || signedToolAction.receipt.event_id,
      { ...canaryContext, toolInvoked: true },
    );
    const returnedResult = canaryExposure.canariesFound.length > 0
      ? {
          error: `Canary token detected in '${name}' tool result; raw result withheld.`,
          blocked: true,
          toolExecuted: true,
          canary_count: canaryExposure.canariesFound.length,
          kill_chain_diagnostics: canaryExposure.kill_chain_diagnostics,
        }
      : result;
    const disposition = returnedResult?.blocked || returnedResult?.requiresApproval ? 'DENIED'
      : result?.error || result?.success === false || result?.ok === false ? 'FAILED' : 'SUCCEEDED';
    return await completeResult(result, disposition, returnedResult);
  } catch (error) {
    if (!finalizing) {
      const disposition = !toolInvoked ? 'DENIED'
        : options.signal.aborted || error?.httpOutcome === 'INDETERMINATE' || /Timeout|Abort/.test(error?.name || '')
          || /(?:timed?\s*out|timeout)/i.test(String(error?.message || '')) ? 'INDETERMINATE' : 'FAILED';
      try {
        return await completeResult({ error: String(error?.message || error) }, disposition,
          { error: `Native tool ${disposition.toLowerCase()}.`, code: `NATIVE_TOOL_${disposition}`,
            blocked: disposition === 'DENIED', toolExecuted: toolInvoked });
      } catch (evidenceError) { error = evidenceError; }
    }
    invalidateToolInputState(inputState);
    error.code = 'NATIVE_TOOL_RESULT_EVIDENCE_INCOMPLETE';
    throw error;
  }
  } finally { finishWork(); }
}

// Only the native corroboration route receives this capability. Callers cannot
// spell or serialize the private Symbol; without a matching v2 elevation the
// ordinary origin verdict remains DENY and the tool is never invoked.
export async function executeCorroboratedToolAction({
  registry,
  memoryId,
  agentId,
  executionContext,
} = {}) {
  if (!registry?.action?.tool || !registry?.action?.arguments
      || !memoryId || !agentId || !executionContext?.requestReceiptMutationHash) {
    throw new Error('corroborated_tool_action_input_invalid');
  }
  const nativeToolInputs = createToolInputState([memoryId]);
  const knowledgeGateState = createKnowledgeGateState({
    agentId,
    prompt: registry.claim.rendered_value,
    intent: 'verification',
    taskType: 'security',
    sessionId: executionContext.requestReceiptId,
  });
  const recalled = await executeTool('aimos_recall', { memory_id: memoryId }, agentId, {
    executionContext,
    credentialUseContext: executionContext,
    nativeToolInputs,
    knowledgeGateState,
  });
  if (!Array.isArray(recalled?.memories)
      || recalled.memories.length !== 1
      || recalled.memories[0]?.id !== memoryId
      || knowledgeGateState.knowledgeEvidence.length !== 1
      || knowledgeGateState.lastRecalledMemoryId !== memoryId) {
    throw new Error('corroborated_tool_exact_recall_required');
  }
  return executeTool(
    registry.action.tool,
    registry.action.arguments,
    agentId,
    {
      executionContext,
      credentialUseContext: executionContext,
      nativeToolInputs,
      knowledgeGateState,
      [CORROBORATED_ACTION_EXECUTION]: true,
    },
  );
}

export function preflightTool(name, args, agentId) {
  if (!Object.hasOwn(ALL_TOOL_DEFS, name)) {
    return { ok: false, issues: [`Unknown tool: ${name}`], plan: null };
  }
  const issues = preflightValidateArgs(name, args);
  return {
    ok: issues.length === 0,
    issues,
    plan: buildToolPlan(name, args, agentId)
  };
}
