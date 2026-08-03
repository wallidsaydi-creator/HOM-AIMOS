// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js
// Pipeline: TOOL_REGISTRY | Position: Strategic analysis tool (Art of War)
// ─────────────────────────────────────────────────────────────────────────────
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KNOWLEDGE_PATH = path.resolve(__dirname, '..', 'knowledge', 'briefings', 'Knowledge', 'ArtOfWar.md');

let cachedKnowledge = null;

function loadKnowledge() {
  if (cachedKnowledge) return cachedKnowledge;
  try {
    cachedKnowledge = fs.readFileSync(KNOWLEDGE_PATH, 'utf8');
  } catch {
    cachedKnowledge = '';
  }
  return cachedKnowledge;
}

const FORCE_RATIOS = [
  { ratio: '10:1', action: 'Surround and dominate. Total encirclement — leave no escape.' },
  { ratio: '5:1', action: 'Attack immediately. Overwhelming force, decisive strike.' },
  { ratio: '2:1', action: 'Divide and conquer. Split forces — frontal pressure + flanking maneuver.' },
  { ratio: 'Equal', action: 'Fight only if highly capable. Offer battle only with superior skill or positioning.' },
  { ratio: 'Inferior', action: 'Evade. Do not engage directly — reposition to more favorable terrain.' },
  { ratio: 'Greatly inferior', action: 'Flee. Withdraw entirely. An obstinate small force will be captured by a larger one.' }
];

const FIVE_FACTORS = {
  tao: {
    name: 'Tao (Moral Law)',
    question: 'Are your people aligned? Do you have moral authority — harmony between leader and team?',
    strong: 'Followers undismayed by danger. Complete accord between vision and execution.',
    weak: 'Restless, distrustful forces invite external attack and internal anarchy.'
  },
  heaven: {
    name: 'Heaven (Timing)',
    question: 'Is the environment favorable? Market cycles, seasonal patterns, macro conditions.',
    strong: 'Moving with the cycle — environmental forces amplify your action.',
    weak: 'Fighting against the current — prolonged warfare benefits no one.'
  },
  earth: {
    name: 'Earth (Terrain)',
    question: 'What is the landscape? Open ground, narrow pass, contested territory, death ground?',
    strong: 'Favorable terrain secured before engagement. Measurement enables estimation.',
    weak: 'Operating on enemy terrain without preparation. Besieging walled cities.'
  },
  commander: {
    name: 'Commander (Five Virtues)',
    question: 'Do you have the right leadership? Wisdom, sincerity, benevolence, courage, strictness.',
    strong: 'Leader who refuses sovereign interference and employs officers with discrimination.',
    weak: 'Personal affection overrides military necessity. Grasping commanders create exploitable vulnerabilities.'
  },
  method: {
    name: 'Method & Discipline',
    question: 'Is your organization ready to execute? Systems, training, supply, accountability.',
    strong: '30,000 disciplined defeat 200,000 undisciplined. Constant practice prevents crisis.',
    weak: 'Novices practicing on critical operations. Unclear commands, unenforced orders.'
  }
};

const ENGAGEMENT_TYPES = {
  attack: {
    name: 'ATTACK',
    condition: 'Superabundance of strength. Initiative is yours.',
    doctrine: 'Offensive indicates superabundance of strength. Strike where unprepared, appear where unexpected.',
    hierarchy: [
      '1. Balk enemy plans (best)',
      '2. Prevent junction of enemy forces',
      '3. Attack enemy in the field',
      '4. Besiege walled cities (worst — avoid if possible)'
    ]
  },
  defense: {
    name: 'DEFENSE',
    condition: 'Insufficient strength for attack. Position and prepare.',
    doctrine: 'Defense is the planning of attack. Defensive posture indicates insufficient strength — use it to gather force.',
    principles: [
      'Make yourself invincible first, then wait for enemy vulnerability',
      'Position ensures safety before engaging',
      'Seek battle only after victory has been won through prior stratagem'
    ]
  },
  patience: {
    name: 'PATIENCE',
    condition: 'Conditions not ripe. The sage moves only when occasion requires.',
    doctrine: 'Resort to armed force only when driven by necessity. Never attack with exhausted armies. Stupid haste is preferable to clever delay — but only when conditions ripen.',
    warnings: [
      'Prolonged warfare benefits no country',
      'Time degrades weapons, morale, strength, and treasury simultaneously',
      'Wait for recovery — delay major operations until forces recover and conditions ripen'
    ]
  }
};

/**
 * Analyze a strategic situation through Sun Tzu's Art of War framework.
 *
 * @param {object} params
 * @param {string} params.situation - Description of the strategic situation
 * @param {string} [params.context] - Additional context (market, competitors, resources)
 * @returns {object} Full battlefield analysis framework
 */
export async function analyzeSituation({ situation, context }) {
  const knowledge = loadKnowledge();
  if (!knowledge) {
    return { error: 'Art of War knowledge base not found. Cannot perform battlefield analysis.' };
  }

  const situationText = String(situation || '').trim();
  if (!situationText) {
    return { error: 'No situation provided. Describe the strategic situation to analyze.' };
  }

  return {
    skill: 'sun-tzu-analyzer',
    version: '1.0.0',
    input: {
      situation: situationText,
      context: String(context || '').trim() || null
    },
    framework: {
      engagement_types: ENGAGEMENT_TYPES,
      five_factors: FIVE_FACTORS,
      force_ratios: FORCE_RATIOS,
      cheng_chi: {
        cheng: 'DIRECT — Facing enemy, normal array, frontal/straightforward approach, expected operations. Use to withstand enemy attack and remain unshaken.',
        chi: 'INDIRECT — Lateral diversion, abnormal maneuvers, flank/rear approach, surprise, unexpected quarter. Use to secure victory.',
        warning: 'Any maneuver intended as indirect (CH\'I) that is perceived by enemy immediately becomes direct (CHENG), losing its value. Never treat these as fixed categories.',
        principle: 'Like 5 musical notes creating infinite combinations — direct and indirect methods combine inexhaustibly.'
      },
      supreme_excellence: 'Breaking enemy resistance WITHOUT fighting > winning battles through combat. Capturing intact > destroying. Pre-emptive victory: winning before bloodshed.',
      intelligence_framework: {
        know_both: 'Know enemy + know self = invincible in every battle.',
        know_self: 'Know self only = mixed results, one victory for every defeat.',
        know_neither: 'Know neither = certain defeat in every engagement.'
      },
      deception: [
        'All warfare is based on deception',
        'Seem unable when able, inactive when active, far when near, near when far',
        'Entice enemy with baits; feign disorder to crush him',
        'Irritate choleric opponents; pretend weakness to induce arrogance',
        'Never divulge military devices beforehand'
      ],
      warnings: [
        'No country has ever benefited from prolonged warfare',
        'Sovereign interference causes military disaster',
        'Never attack with exhausted armies',
        'Protracted campaigns invite opportunistic attacks by rivals',
        'One may know how to conquer without being able to do it',
        'Do not fight first and seek victory afterwards — plan secretly, move surreptitiously'
      ]
    },
    instructions: `You are Reviewer, executive runtime for HOM. Apply the Art of War battlefield analysis framework to the situation described.

ANALYSIS STRUCTURE (follow exactly):

## THE MOVE
One decisive recommendation. State it plainly. What to do RIGHT NOW.

## BATTLEFIELD CLASSIFICATION
Classify as ATTACK, DEFENSE, or PATIENCE. Explain why.
- ATTACK: You have superabundance of strength. Seize initiative.
- DEFENSE: Insufficient strength. Position, prepare, gather force.
- PATIENCE: Conditions not ripe. The sage moves only when occasion requires.

## FIVE CONSTANT FACTORS ASSESSMENT
For each factor, assess the current state (strong/weak/neutral) with evidence:
1. **TAO (Moral Law)** — Alignment, moral authority, team harmony
2. **HEAVEN (Timing)** — Market cycles, environmental conditions, seasonal forces
3. **EARTH (Terrain)** — Landscape, positioning, competitive geography
4. **COMMANDER (Five Virtues)** — Leadership: wisdom, sincerity, benevolence, courage, strictness
5. **METHOD & DISCIPLINE** — Organization readiness, systems, training, accountability

## FORCE RATIO ANALYSIS
Honest assessment of relative strength vs opposition. Map to Sun Tzu's ratios:
- 10:1 → surround/dominate
- 5:1 → attack immediately
- 2:1 → divide and conquer
- Equal → fight only if highly capable
- Inferior → evade
- Greatly inferior → flee

## CHENG/CH'I ASSESSMENT
- Where is the DIRECT (expected) play?
- Where is the INDIRECT (surprise) play?
- Which should you use and WHY?
- Warning: any indirect move the enemy perceives becomes direct — losing its value.

## WARNINGS
What Sun Tzu would flag as dangers in THIS specific situation. Be direct. Be brutal.

## THE ART OF WAR CITATION
The specific principle or passage that governs this situation. Quote it.

TONE: Decisive, direct, no hedging. Sun Tzu did not equivocate. Neither do you.`,
    knowledge_source: 'knowledge/briefings/Knowledge/ArtOfWar.md',
    knowledge_chunks: 20,
    knowledge_chars: 308491
  };
}
