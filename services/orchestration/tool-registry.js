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
import { assessQuality } from '../write/quality-gate.js';
import { searchWeb } from '../integrations/web-search.js';
import { xSearchRecent } from '../integrations/x-search.js';
import { xPostTweet, xReplyToTweet, xQuoteTweet } from '../integrations/x-tools.js';
import { getOperatorAgentId, isOperatorAgentId } from '../security/system-config-store.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { runAgent } from './agent-runner.js';
import { validateExecution, createExecutionPlan } from '../write/execution-interceptor.js';
import { classifyIntent, enforceVerbPolicy } from '../write/intent-classifier.js';
import {
  gmailListInbox, gmailSearchMessages, gmailSendMessage,
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
  imessageSend
} from '../integrations/integration-tools.js';
import { createScheduledTask, listScheduledTasks } from './scheduler.js';
import { query } from '../../db/connection.js';
import { persistMemory } from '../write/persist-memory.js';
import {
  claimToolApprovalExecution,
  createToolApprovalRequest,
} from './tool-approval-store.js';
import { beginToolAction, finishToolAction } from './tool-action-ledger.js';
import { shouldBlockToolForMissingKnowledge } from '../security/knowledge-gate.js';
import { scanToolExecution, scanToolResult } from '../security/canary-tracker.js';
import { buildToolRepresentation as buildToolRepresentationDiagnostic } from './tool-representation-diagnostics.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import { resolveNativeRecallAuthority } from '../retrieval/native-recall.js';
import { executeNativeRecall } from '../retrieval/native-recall-pipeline.js';

const COMPANY = AIMOS_COMPANY_ID;
const AIMOS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DELEGATE_TASK_TIMEOUT_MS = 10_000;
const TOOL_EXEC_TIMEOUT_MS = 12_000;
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

async function aimosRecall(rawCommand = {}, options = {}) {
  const { query: q, key, memory_id } = rawCommand;
  if (!q && !key && !memory_id) {
    throw new Error('aimos_recall requires query, key, or memory_id');
  }
  const executionContext = options.executionContext || options.credentialUseContext || null;
  if (!executionContext || !options.toolActionAuthority) {
    throw new Error('verified_tool_recall_authority_required');
  }
  const recallAuthority = await resolveNativeRecallAuthority({
    rawCommand,
    executionContext,
    requestAuthority: options.toolActionAuthority,
    transportBinding: { transport: 'tool', toolName: 'aimos_recall' },
  });
  const result = await executeNativeRecall({
    ip: 'native-tool-action',
    headers: {},
    originalUrl: 'tool:aimos_recall',
  }, recallAuthority);
  if (result.status !== 200) throw new Error(result.body?.error || 'native_tool_recall_failed');
  return result.body;
}


async function aimosSave({ content, tags = [], agent_id = 'unknown' }, options = {}) {
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
  };
  const commitAction = await beginToolAction({
    tool: 'aimos_save_commit',
    args: saveSpec,
    runtimeAgentId,
    executionContext,
    parentEventId: options.toolActionAuthority.eventId,
  });
  let saved;
  try {
    saved = await persistMemory({ ...saveSpec, mutation_authority: commitAction.authority });
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

  youtube_search: {
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
    fn: async ({ query: q }) => contactsSearch({ query: q })
  },

  imessage_chats: {
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
    fn: async ({ limit = 10 }) => imessageListChats({ limit })
  },

  imessage_search_contact: {
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
    fn: async ({ query: q }) => imessageSearchContact({ query: q })
  },

  imessage_send: {
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
    fn: async ({ to, message }) => imessageSend({ to, message })
  },

  aimos_recall: {
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
    schema: {
      type: 'function',
      function: {
        name: 'aimos_save',
        description: 'Save important information, decisions, or findings to Aimos memory.',
        parameters: {
          type: 'object',
          properties: {
            content: { type: 'string', description: 'Information to store' },
            tags: { type: 'array', items: { type: 'string' }, description: 'Tags for retrieval' }
          },
          required: ['content']
        }
      }
    },
    fn: async ({ content, tags = [] }, agentId, options = {}) => (
      aimosSave({ content, tags, agent_id: agentId }, options)
    )
  },

  write_file: {
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
        const resolved = path.resolve(filepath);
        const filename = path.basename(resolved).toLowerCase();
        
        // ─── Phase 2: Dual-Mode Lockdown ──────────────────────────────────────
        const isWithin = (candidate, root) => candidate === root || candidate.startsWith(`${root}${path.sep}`);
        const isBrainFile = isWithin(resolved, AIMOS_ROOT);

        if (isBrainFile) {
          // Inside Brain: Requires Reasoning Trace
          const { checkReasoningTrace } = await import('./reasoning-trace-check.js');
          const trace = await checkReasoningTrace(agentId, resolved);
          
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
        return { success: true, message: `Successfully wrote ${content.length} bytes to ${resolved}` };
      } catch (err) {
        return { error: `Failed to write file: ${err.message}` };
      }
    }
  },

  hive_search_specialists: {
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
    fn: async ({ cron_expression, task_description, agent_id = getOperatorAgentId(), label }) => {
      const schedule = await createScheduledTask({
        cronExpression: cron_expression,
        taskDescription: task_description,
        agentId: agent_id,
        label
      });
      return { success: true, scheduled: true, schedule };
    }
  },

  list_scheduled_tasks: {
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
            delegation_context: { type: 'object', description: 'Scoped state passed to child (like env vars — not persisted to Aimos)' }
          },
          required: ['agent_id', 'task_prompt']
        }
      }
    },
    fn: async ({ agent_id, task_prompt, wait = false, delegation_context = {} }, originAgentId = '', options = {}) => {
      try {
        const taskId = `delegate-${agent_id}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        console.log(`[orchestrator] ${wait ? 'Awaiting' : 'Queueing'} delegated task ${taskId} for sub-agent: ${agent_id}`);

        // ─── P0-5: Structured delegation with return channels ─────────────────
        // Child writes result to Aimos: delegation:{task_id}:result
        // Parent can poll or use wait=true for synchronous result.
        // Exit status enables conditional branching.

        const executeDelegate = async () => {
          const startedAt = Date.now();
          try {
            const effectiveParentRunId = options.runId || options.parentRunId || null;
            const effectiveDelegationContext = {
              ...delegation_context,
              sourceAgentId: originAgentId || options.agentId || getOperatorAgentId(),
              parentRunId: effectiveParentRunId,
              conversationSessionKey: options.sessionKey || delegation_context.conversationSessionKey || null
            };
            const result = await Promise.race([
              runAgent(agent_id, task_prompt, {
                skipAimos: true,
                originAgentId,
                delegationContext: effectiveDelegationContext,
                parentRunId: effectiveParentRunId,
                sessionKey: options.sessionKey || null,
                taskType: options.taskType || 'delegated_task',
                _scopedState: options._scopedState || null
              }),
              new Promise((_, reject) =>
                setTimeout(() => reject(new Error(`Delegated task exceeded ${DELEGATE_TASK_TIMEOUT_MS}ms timeout`)), DELEGATE_TASK_TIMEOUT_MS)
              )
            ]);

            const elapsed = Date.now() - startedAt;
            const response = typeof result === 'string' ? result : (result?.response || JSON.stringify(result));
            const confidence = typeof result === 'object' ? (result?.confidence || 0.5) : 0.5;

            // Structured return protocol (Quine-inspired)
            const structured = {
              status: 0, // 0=success
              confidence,
              response: String(response || '').slice(0, 4000),
              diagnostics: [],
              wisdom: { task_id: taskId, agent_id, elapsed_ms: elapsed },
              task_id: taskId
            };

            // Save result to Aimos for parent retrieval
            await persistMemory({
              company_id: COMPANY,
              key: `delegation:${taskId}:result`,
              value: JSON.stringify(structured),
              scope: 'system',
              memory_type: 'delegation_result',
              clearance_level: 5,
              source: 'tool-registry',
              mutation_authority: 'housekeeper'
            });

            console.log(`[orchestrator] Delegated task ${taskId} completed in ${elapsed}ms (status: 0)`);
            return structured;
          } catch (err) {
            const elapsed = Date.now() - startedAt;
            const structured = {
              status: err.message?.includes('timeout') ? 1 : 2, // 1=partial(timeout), 2=failed
              confidence: 0,
              response: '',
              diagnostics: [err.message],
              wisdom: { task_id: taskId, agent_id, elapsed_ms: elapsed, error: err.message },
              task_id: taskId
            };

            // Save failure result
            await persistMemory({
              company_id: COMPANY,
              key: `delegation:${taskId}:result`,
              value: JSON.stringify(structured),
              scope: 'system',
              memory_type: 'delegation_result',
              clearance_level: 5,
              source: 'tool-registry',
              mutation_authority: 'housekeeper'
            }).catch(() => {});

            console.error(`[orchestrator] Delegated task ${taskId} failed after ${elapsed}ms (status: ${structured.status})`, err.message);
            return structured;
          }
        };

        if (wait) {
          // Synchronous mode: block until child completes
          const result = await executeDelegate();
          return result;
        }

        // Async mode: fire-and-forget with result saved to Aimos
        setImmediate(() => { executeDelegate().catch(() => {}); });

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
  'full': ['web_search', 'gmail_inbox', 'gmail_search', 'gmail_send', 'youtube_search', 'youtube_channel','drive_list', 'drive_read', 'docs_read', 'sheets_read', 'google_profile', 'calendar_today', 'calendar_events', 'calendar_create', 'stripe_account_summary', 'stripe_list_customers', 'stripe_list_subscriptions', 'stripe_list_payment_intents', 'integrations_status', 'github_list_repos', 'github_search_issues', 'salesforce_list_objects', 'contacts_search', 'imessage_chats', 'imessage_search_contact', 'imessage_send', 'aimos_recall', 'aimos_save', 'write_file', 'read_file', 'schedule_task', 'list_scheduled_tasks', 'delegate_task', 'hive_search_specialists', 'x_search', 'x_post', 'x_reply', 'x_quote', 'sun_tzu_analyze'],
  'web-search': ['web_search', 'aimos_recall', 'aimos_save'],
  'x-search': ['x_search', 'aimos_recall', 'aimos_save'],
  'x': ['x_search', 'x_post', 'x_reply', 'x_quote', 'aimos_recall', 'aimos_save'],
  'google': ['web_search', 'gmail_inbox', 'gmail_search', 'youtube_search', 'youtube_channel','drive_list', 'drive_read', 'docs_read', 'sheets_read', 'google_profile', 'calendar_today', 'calendar_events', 'calendar_create', 'aimos_recall', 'aimos_save'],
  'sheets': ['sheets_read', 'aimos_recall', 'aimos_save'],
  'google-profile': ['google_profile'],
  'stripe': ['stripe_account_summary', 'stripe_list_customers', 'stripe_list_subscriptions', 'stripe_list_payment_intents', 'aimos_recall', 'aimos_save'],
  'integrations': ['integrations_status', 'github_list_repos', 'github_search_issues', 'salesforce_list_objects', 'contacts_search', 'imessage_chats', 'imessage_search_contact', 'imessage_send', 'aimos_recall', 'aimos_save'],
  'gmail-read': ['gmail_inbox', 'gmail_search', 'aimos_recall', 'aimos_save'],
  'gmail-send': ['gmail_send'],
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
const TOOL_CLEARANCE_LEVELS = {
  sun_tzu_analyze: 1,
  aimos_recall: 1,
  aimos_save: 2,
  web_search: 1,
  x_search: 3,
  x_post: 5,
  x_reply: 5,
  x_quote: 5,
  gmail_inbox: 2,
  gmail_search: 2,
  gmail_send: 4,
  youtube_search: 1,
  youtube_channel: 1,
  drive_list: 2,
  drive_read: 2,
  docs_read: 2,
  sheets_read: 2,
  google_profile: 2,
  calendar_today: 1,
  calendar_events: 1,
  calendar_create: 3,
  stripe_account_summary: 3,
  stripe_list_customers: 3,
  stripe_list_subscriptions: 3,
  stripe_list_payment_intents: 3,
  integrations_status: 2,
  github_list_repos: 2,
  github_search_issues: 2,
  salesforce_list_objects: 3,
  contacts_search: 2,
  imessage_chats: 2,
  imessage_search_contact: 2,
  imessage_send: 4,
  write_file: 5,
  read_file: 3,
  schedule_task: 5,
  list_scheduled_tasks: 2,
  delegate_task: 3,
  hive_search_specialists: 1,
};

const SIDE_EFFECT_TOOLS = new Set([
  'gmail_send',
  'calendar_create',
  'imessage_send',
  'aimos_save',
  'write_file',
  'schedule_task',
  'delegate_task',
  'x_post',
  'x_reply',
  'x_quote'
]);

const QUOTA_SPENDING_TOOLS = new Set([
  'web_search',
  'x_search',
  'x_post',
  'x_reply',
  'x_quote',
  'gmail_inbox',
  'gmail_search',
  'gmail_send',
  'youtube_search',
  'youtube_channel',
  'drive_list',
  'drive_read',
  'calendar_today',
  'calendar_events',
  'calendar_create',
  'docs_read',
  'sheets_read',
  'google_profile',
  'stripe_account_summary',
  'stripe_list_customers',
  'stripe_list_subscriptions',
  'stripe_list_payment_intents',
  'integrations_status',
  'github_list_repos',
  'github_search_issues',
  'salesforce_list_objects',
  'contacts_search',
  'imessage_chats',
  'imessage_search_contact',
  'imessage_send'
]);

const TOOL_DIRECTIONS = Object.freeze({
  READ: 'read',
  MEMORY_WRITE: 'memory_write',
  INTERNAL_WRITE: 'internal_write',
  EXTERNAL_WRITE: 'external_write',
  ORCHESTRATION: 'orchestration'
});

const TOOL_DIRECTION_BY_NAME = Object.freeze({
  sun_tzu_analyze: TOOL_DIRECTIONS.READ,
  aimos_recall: TOOL_DIRECTIONS.READ,
  aimos_save: TOOL_DIRECTIONS.MEMORY_WRITE,
  web_search: TOOL_DIRECTIONS.READ,
  x_search: TOOL_DIRECTIONS.READ,
  x_post: TOOL_DIRECTIONS.EXTERNAL_WRITE,
  x_reply: TOOL_DIRECTIONS.EXTERNAL_WRITE,
  x_quote: TOOL_DIRECTIONS.EXTERNAL_WRITE,
  gmail_inbox: TOOL_DIRECTIONS.READ,
  gmail_search: TOOL_DIRECTIONS.READ,
  gmail_send: TOOL_DIRECTIONS.EXTERNAL_WRITE,
  youtube_search: TOOL_DIRECTIONS.READ,
  youtube_channel: TOOL_DIRECTIONS.READ,
  drive_list: TOOL_DIRECTIONS.READ,
  drive_read: TOOL_DIRECTIONS.READ,
  docs_read: TOOL_DIRECTIONS.READ,
  sheets_read: TOOL_DIRECTIONS.READ,
  google_profile: TOOL_DIRECTIONS.READ,
  calendar_today: TOOL_DIRECTIONS.READ,
  calendar_events: TOOL_DIRECTIONS.READ,
  calendar_create: TOOL_DIRECTIONS.EXTERNAL_WRITE,
  stripe_account_summary: TOOL_DIRECTIONS.READ,
  stripe_list_customers: TOOL_DIRECTIONS.READ,
  stripe_list_subscriptions: TOOL_DIRECTIONS.READ,
  stripe_list_payment_intents: TOOL_DIRECTIONS.READ,
  integrations_status: TOOL_DIRECTIONS.READ,
  github_list_repos: TOOL_DIRECTIONS.READ,
  github_search_issues: TOOL_DIRECTIONS.READ,
  salesforce_list_objects: TOOL_DIRECTIONS.READ,
  contacts_search: TOOL_DIRECTIONS.READ,
  imessage_chats: TOOL_DIRECTIONS.READ,
  imessage_search_contact: TOOL_DIRECTIONS.READ,
  imessage_send: TOOL_DIRECTIONS.EXTERNAL_WRITE,
  write_file: TOOL_DIRECTIONS.INTERNAL_WRITE,
  read_file: TOOL_DIRECTIONS.READ,
  schedule_task: TOOL_DIRECTIONS.ORCHESTRATION,
  list_scheduled_tasks: TOOL_DIRECTIONS.READ,
  delegate_task: TOOL_DIRECTIONS.ORCHESTRATION,
  hive_search_specialists: TOOL_DIRECTIONS.READ
});

function resolveToolDirection(toolName = '') {
  return TOOL_DIRECTION_BY_NAME[toolName] || TOOL_DIRECTIONS.READ;
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

async function runWithTimeout(toolName, fn, timeoutMs = TOOL_EXEC_TIMEOUT_MS) {
  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`Tool timeout after ${timeoutMs}ms (${toolName})`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([fn(), timeoutPromise]);
  } finally {
    clearTimeout(timeoutId);
  }
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
  const sideEffecting = SIDE_EFFECT_TOOLS.has(name);
  return {
    kind: 'tool_preflight',
    intent: name,
    tool: name,
    agentId,
    risk: sideEffecting ? 'high' : (name === 'x_search' ? 'medium' : 'low'),
    direction: resolveToolDirection(name),
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

  return [...toolSet].map(name => ALL_TOOL_DEFS[name]).filter(Boolean);
}

export function getToolRepresentationsForAgent(toolSuitesOrNames, options = {}) {
  return getToolsForAgent(toolSuitesOrNames, options)
    .map((toolDef) => toolDef?.schema?.function?.name)
    .filter(Boolean)
    .map((name) => buildToolRepresentation(name, options));
}

export async function executeTool(name, args, agentId, options = {}) {
  const tool = ALL_TOOL_DEFS[name];
  if (!tool) throw new Error(`Unknown tool: ${name}`);
  const allowedTools = Array.isArray(options.allowedTools) ? new Set(options.allowedTools) : null;
  if (allowedTools && !allowedTools.has(name)) {
    throw new Error(`Tool '${name}' is not allowed for this run.`);
  }
  const validationIssues = preflightValidateArgs(name, args);
  if (validationIssues.length) {
    throw new Error(`Tool preflight failed for '${name}': ${validationIssues.join('; ')}`);
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
      await notifyToolObserver(options.onToolResult, {
        toolName: name,
        args,
        result: blockedResult,
        blocked: true
      });
      return blockedResult;
    }
  }

  const taskHasXIntent = (options.taskDescription || options.userPrompt || '').toLowerCase().match(/auto.?engage|x auto|x_search|tweet|twitter|quote tweet/);
  if (name === 'x_search' && !isExplicitXIntent(options.intent, options.userPrompt, args) && !taskHasXIntent) {
    throw new Error("Tool 'x_search' is restricted to explicit X/Twitter requests.");
  }

  const knowledgeGateBlock = shouldBlockToolForMissingKnowledge(options.knowledgeGateState, name);
  if (knowledgeGateBlock.blocked) {
    const blockedResult = {
      error: knowledgeGateBlock.message,
      blocked: true,
      knowledgeGate: knowledgeGateBlock
    };
    await notifyToolObserver(options.onToolResult, {
      toolName: name,
      args,
      result: blockedResult,
      blocked: true,
      knowledgeGate: knowledgeGateBlock
    });
    return blockedResult;
  }

  // ─── CLEARANCE GATE (Aimos Order v2 Layer 1: Decision Rights) ──────────────
  const requiredClearance = TOOL_CLEARANCE_LEVELS[name] || 1;
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
    await notifyToolObserver(options.onToolResult, {
      toolName: name,
      args,
      result: blockedResult,
      blocked: true
    });
    return blockedResult;
  }

  const autonomous = options.autonomous === true;
  const approvalRequiredForAutonomy = autonomous && QUOTA_SPENDING_TOOLS.has(name);
  const approvalEvidence = options.approvalEvidence || null;
  const approved = Boolean(approvalEvidence);
  if (options.approved === true && !approvalEvidence) {
    throw new Error('signed_tool_approval_execution_evidence_required');
  }

  if (!approved && approvalRequiredForAutonomy) {
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
    await notifyToolObserver(options.onToolResult, {
      toolName: name,
      args,
      result,
      blocked: false
    });
    return result;
  }

  // ─── Wire #29: Intent Classifier — scope enforcement before execution ───────
  try {
    const intentClass = classifyIntent(options.userPrompt || '', [name]);
    const verbPolicy = enforceVerbPolicy(intentClass.scope, 'POST');
    if (!verbPolicy.allowed) {
      const blockedResult = {
        error: `Intent scope enforcement blocked tool '${name}': ${verbPolicy.reason}`,
        blocked: true,
        intentScope: intentClass.scope
      };
      await notifyToolObserver(options.onToolResult, {
        toolName: name,
        args,
        result: blockedResult,
        blocked: true
      });
      return blockedResult;
    }
  } catch (err) {
    console.warn('[tool-registry] Intent classification failed:', err.message);
  }

  // ─── Wire #28: Execution Interceptor — fail-closed gate wrapping execution ─
  try {
    if (options.approvedPlan) {
      const interceptResult = await validateExecution(name, 'POST', args, options.approvedPlan, COMPANY);
      if (!interceptResult.allowed) {
        const blockedResult = {
          error: `Execution interceptor blocked tool '${name}': ${interceptResult.reason}`,
          blocked: true,
          violations: interceptResult.violations
        };
        await notifyToolObserver(options.onToolResult, {
          toolName: name,
          args,
          result: blockedResult,
          blocked: true
        });
        return blockedResult;
      }
    }
  } catch (err) {
    console.warn('[tool-registry] Execution interceptor failed:', err.message);
  }

  let signedToolAction = null;
  let terminalToolActionRecorded = false;
  try {
    let actionParentEventId = options.securityDecisionEventId || null;
    if (approvalEvidence) {
      const approvalClaim = await claimToolApprovalExecution({
        ...approvalEvidence,
        tool: name,
        args: args || {},
        agentId: String(agentId || ''),
        authority: options.executionContext || options.credentialUseContext || null,
      });
      actionParentEventId = approvalClaim.receipt.event_id;
    }
    const executionContext = options.executionContext || options.credentialUseContext || null;
    signedToolAction = await beginToolAction({
      tool: name,
      args: args || {},
      runtimeAgentId: String(agentId || ''),
      executionContext,
      parentEventId: actionParentEventId,
    });
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
      toolActionAuthority: signedToolAction.authority,
      credentialUseContext: Object.freeze({
        ...(options.executionContext || options.credentialUseContext || {}),
        autonomousActionEventId: signedToolAction.authority.eventId,
      }),
    };
    const invokeTool = () => {
      if (name === 'aimos_save' || name === 'delegate_task') {
        return tool.fn(args, agentId, invocationOptions);
      }
      if (name === 'aimos_recall') {
        return tool.fn(args, invocationOptions);
      }
      return tool.fn(args, invocationOptions);
    };
    const result = await runWithTimeout(name, invokeTool, TOOL_EXEC_TIMEOUT_MS);
    const canaryExposure = await scanToolResult(
      name,
      result,
      options.runId || signedToolAction.receipt.event_id,
      { ...canaryContext, toolInvoked: true },
    );
    await finishToolAction({
      action: signedToolAction,
      executionContext,
      succeeded: true,
      result,
    });
    terminalToolActionRecorded = true;
    const returnedResult = canaryExposure.canariesFound.length > 0
      ? {
          error: `Canary token detected in '${name}' tool result; raw result withheld.`,
          blocked: true,
          toolExecuted: true,
          canary_count: canaryExposure.canariesFound.length,
          kill_chain_diagnostics: canaryExposure.kill_chain_diagnostics,
        }
      : result;
    await notifyToolObserver(options.onToolResult, {
      toolName: name,
      args,
      result: returnedResult,
      blocked: Boolean(returnedResult?.blocked),
    });
    return returnedResult;
  } catch (error) {
    if (signedToolAction && !terminalToolActionRecorded) {
      try {
        await finishToolAction({
          action: signedToolAction,
          executionContext: options.executionContext || options.credentialUseContext || null,
          succeeded: false,
          error: error?.message || error,
        });
      } catch (ledgerError) {
        error.toolActionLedgerError = ledgerError?.message || String(ledgerError);
      }
    }
    await notifyToolObserver(options.onToolResult, {
      toolName: name,
      args,
      error,
      blocked: Boolean(error?.blocked),
    });
    throw error;
  }
}

export function preflightTool(name, args, agentId) {
  const tool = ALL_TOOL_DEFS[name];
  if (!tool) {
    return { ok: false, issues: [`Unknown tool: ${name}`], plan: null };
  }
  const issues = preflightValidateArgs(name, args);
  return {
    ok: issues.length === 0,
    issues,
    plan: buildToolPlan(name, args, agentId)
  };
}
