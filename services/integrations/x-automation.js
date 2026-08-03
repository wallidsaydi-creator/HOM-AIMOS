// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Available — diagnostic-only until native X posting is explicitly wired
// Purpose: X/Twitter automation planning without hidden tool execution or posting
// Wire into: jobs/ scheduled job or routes/aimos.js tool-registry hook
// ─────────────────────────────────────────────────────────────────────────────

import { callNativeLlm } from '../shared/native-llm.js';

function buildSafetyRules() {
  return `CONTENT SAFETY:
- Diagnostic-only: do not post, call tools, emit curl commands, or claim posting occurred.
- Never mention Aimos, nightly dream, governance resolver, brain contract, memory tiers, clearance levels, agent IDs, tool registry, or any internal system name.
- Only HOM brand + customer-facing value. Talk about problems and outcomes, not architecture.`;
}

async function draftXDiagnostic(prompt, label) {
  try {
    const output = await callNativeLlm({ prompt });
    const text = String(output || '').trim();
    console.log(`[x-automation] ${label} diagnostic draft completed:`, text.slice(0, 200));
    return {
      success: true,
      diagnostic_only: true,
      posted: false,
      output: text
    };
  } catch (error) {
    console.error(`[x-automation] ${label} diagnostic draft failed:`, error?.message || String(error));
    return {
      success: false,
      diagnostic_only: true,
      posted: false,
      error: error?.message || String(error)
    };
  }
}

export async function runXAutoEngage() {
  const prompt = `You are drafting a diagnostic X engagement plan for HOM.

Task:
1. Propose three audience pain-point themes around AI agent memory, autonomous AI, and enterprise AI governance.
2. For each theme, draft one quote-tweet style response that adds genuine value without pitching.
3. Include what evidence would be needed before any real posting action.

${buildSafetyRules()}`;

  return draftXDiagnostic(prompt, 'runXAutoEngage');
}

export async function runXDailyPosts() {
  const prompt = `You are drafting diagnostic X post candidates for HOM.

Task:
1. Create two original post drafts that provide genuine value to people building with AI or managing distributed teams.
2. Focus on customer pain points and outcomes, not internal features.
3. Return drafts only. Do not claim they were posted.

${buildSafetyRules()}`;

  return draftXDiagnostic(prompt, 'runXDailyPosts');
}

export async function runXDailySummary() {
  const prompt = `You are drafting a diagnostic daily social summary template for HOM.

Task:
1. Produce a concise summary structure for today's public-facing signals.
2. Include sections for actions taken, outcomes, notable signals, and tomorrow's focus.
3. Mark any missing evidence as "needs Aimos/event evidence" rather than inventing.

${buildSafetyRules()}`;

  return draftXDiagnostic(prompt, 'runXDailySummary');
}
