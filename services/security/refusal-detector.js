/**
 * refusal-detector.js — Detect and mitigate LLM refusal bias
 * Source: Defensive Refusal Bias (Scale AI, ICLR 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js (post-inference refusal check)
 * 2. → Pulls from: Raw model output strings
 * 3. → Pushes to: services/observe/event-ledger.js (Refusal metrics)
 * 4. ↔ Interacts with: knowledge-gate.js (Mitigates authorization paradox)
 *
 * LOGIC GUIDE: Detects LLM refusal patterns. Mitigates by stripping auth 
 * signals on retry or routing security tasks to less biased open models.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────

import { logEvent } from '../observe/event-ledger.js';

const REFUSAL_PATTERNS = {
  inability: [/i can'?t (help|assist|provide)/i, /i'?m unable to/i, /i cannot (provide|help|assist)/i],
  apology: [/i apologize,? but/i, /i'?m sorry,? but i (can'?t|cannot|won'?t)/i],
  policy: [/against (?:my|our) (?:guidelines|policies)/i, /violates (?:ethical|safety) guidelines/i],
  misuse: [/potentially (?:harmful|dangerous|malicious)/i, /could be (?:used|misused) for/i]
};

const OFFENSIVE_VOCAB = [
  'exploit', 'payload', 'shell', 'bypass', 'crack',
  'brute', 'dump', 'pivot', 'c2', 'obfuscate', 'evasion'
];

const AUTH_SIGNALS_STRONG = ['blue team', 'ctf', 'nccdc', 'ccdc', 'authorized', 'training exercise'];
const AUTH_SIGNALS_WEAK = ['our network', 'our system', 'pentest', 'defender', 'competition'];

const TASK_CATEGORIES = [
  { name: 'malware_analysis', pattern: /malware|virus|trojan|ransomware|reverse.?engineer|disassembl|decompil/i },
  { name: 'vuln_assessment', pattern: /vulnerab|cve|exploit|metasploit|nmap.*vuln|security.?scan/i },
  { name: 'incident_response', pattern: /incident|breach|compromis|attack.*detect|forensic|investig.*attack/i },
  { name: 'system_hardening', pattern: /harden|secure.*config|lock.?down|security.*baseline|cis.?benchmark/i },
  { name: 'credential_mgmt', pattern: /credential|password|hash|ntlm|kerberos|ldap.*auth|active.?directory.*user/i },
  { name: 'firewall_config', pattern: /firewall|iptables|pf|ufw|acl|allow.*port|block.*port|packet.?filter/i },
  { name: 'network_scan', pattern: /scan.*port|port.*scan|nmap|netcat|nc\s|reconnaissance|network.*discover/i },
  { name: 'log_analysis', pattern: /log.*analy|siem|splunk|elastic|grep.*log|parse.*log|audit.*log/i }
];

export function detectRefusal(response) {
  for (const [category, patterns] of Object.entries(REFUSAL_PATTERNS)) {
    for (const regex of patterns) {
      if (regex.test(response)) {
        logEvent('hom', 'refusal-detector', 'security_detection', `refusal-detector:${category}`, {
          reasoning: `Security event: LLM refusal detected — category: ${category}, pattern: ${regex.source}`,
          severity: 'medium',
          details: { category, pattern: regex.source }
        }).catch(() => { /* non-fatal */ });
        return { refused: true, category, pattern: regex.source };
      }
    }
  }
  return { refused: false };
}

export function classifyTaskCategory(prompt) {
  for (const { name, pattern } of TASK_CATEGORIES) {
    if (pattern.test(prompt)) return name;
  }
  return 'general';
}

export function detectOffensiveVocab(text) {
  const cleaned = text.replace(/powershell/gi, '__PS__');
  return OFFENSIVE_VOCAB.filter(term => new RegExp(`\\b${term}\\b`, 'i').test(cleaned));
}

export function detectAuthSignals(text) {
  const lower = text.toLowerCase();
  return {
    strong: AUTH_SIGNALS_STRONG.filter(s => lower.includes(s)),
    weak: AUTH_SIGNALS_WEAK.filter(s => lower.includes(s))
  };
}

export function stripAuthSignals(prompt) {
  let cleaned = prompt;
  for (const signal of [...AUTH_SIGNALS_STRONG, ...AUTH_SIGNALS_WEAK]) {
    cleaned = cleaned.replace(new RegExp(signal, 'gi'), '');
  }
  return cleaned.replace(/\s{2,}/g, ' ').trim();
}

export function shouldRetryWithoutAuth(response, prompt) {
  const refusal = detectRefusal(response);
  if (!refusal.refused) return { retry: false };
  const authSignals = detectAuthSignals(prompt);
  if (authSignals.strong.length > 0 || authSignals.weak.length > 0) {
    return { retry: true, strippedPrompt: stripAuthSignals(prompt), reason: 'authorization_paradox' };
  }
  return { retry: false, refusalCategory: refusal.category };
}

export { AUTH_SIGNALS_STRONG, AUTH_SIGNALS_WEAK, OFFENSIVE_VOCAB };
