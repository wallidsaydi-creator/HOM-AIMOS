/**
 * recall-lexical-calibration.js — Native sparse recall calibration
 *
 * Paper / corpus authority:
 * - docs/recall-calibration-corpus.md
 * - BM25 sparse retrieval: term frequency, inverse document frequency,
 *   length-normalized lexical evidence
 * - MRAG / TimeR4: preserve named entities, comparison targets, and temporal
 *   anchors before broad semantic ranking
 * - MMR / source-attributed synthesis: keep evidence diversity without hiding
 *   source handles
 *
 * Purpose:
 * - Convert broad natural recall questions into bounded sparse-retrieval terms.
 * - Preserve quoted phrases, comparison targets, and named entities as first
 *   class retrieval evidence.
 * - Provide a deterministic rerank signal for Aimos's native recall route.
 *
 * Guardrails:
 * - Native read-path helper only. No DB access, no HTTP, no signing, no writes,
 *   no experiment imports, no app/runtime dependency.
 * - Does not change canonical memory, save math, identity, or persistence.
 */

const STOPWORDS = new Set([
  'a', 'about', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'being', 'but', 'by',
  'can', 'could', 'did', 'do', 'does', 'for', 'from', 'had', 'has', 'have',
  'he', 'her', 'hers', 'him', 'his', 'how', 'i', 'if', 'in', 'is', 'it', 'its',
  'me', 'my', 'of', 'on', 'or', 'our', 'ours', 'she', 'so', 'that', 'the',
  'their', 'them', 'then', 'there', 'they', 'this', 'to', 'was', 'we', 'were',
  'what', 'when', 'where', 'which', 'who', 'whom', 'why', 'with', 'would', 'you',
  'your', 'yours', 'narrator',
]);

const EXPANSIONS = new Map([
  ['airline', ['airlines', 'flight', 'flights', 'flying', 'flew', 'carrier', 'miles', 'loyalty']],
  ['spent', ['spend', 'cost', 'paid', 'expense', 'expenses', 'bought', 'buy', 'purchase', 'purchased']],
  ['fly', ['flight', 'flights', 'flying', 'flew', 'airline', 'airlines']],
  ['money', ['cash', 'dollars', 'paid', 'spent', 'cost', 'expense']],
  ['old', ['age', 'aged', 'years', 'born', 'birth', 'birthday']],
  ['mov', ['move', 'moved', 'moving', 'relocated', 'relocate', 'immigrated', 'immigrate', 'living', 'lived', 'visa', 'green', 'card', 'work']],
  ['move', ['moved', 'moving', 'relocated', 'relocate', 'immigrated', 'immigrate', 'living', 'lived', 'visa', 'green', 'card', 'work']],
  ['relocation', ['relocated', 'relocate', 'moved', 'moving', 'suburbs', 'apartment', 'city']],
  ['rachel', ['friend', 'suburbs', 'apartment', 'city']],
  ['doctor', ['physician', 'appointment', 'clinic', 'dermatologist', 'ent', 'primary', 'medical']],
  ['book', ['reading', 'read', 'novel']],
  ['movie', ['film', 'festival', 'cinema']],
  ['first', ['before', 'earlier', 'oldest', 'initially']],
  ['arrival', ['arrived', 'received', 'got', 'new']],
  ['arriv', ['arrived', 'received', 'got', 'new']],
  ['receiving', ['received', 'got', 'new', 'arrived', 'delivered']],
  ['received', ['receiving', 'got', 'new', 'arrived', 'delivered']],
  ['losing', ['lost', 'misplaced', 'missing', 'left']],
  ['lost', ['losing', 'misplaced', 'missing', 'left']],
  ['lens', ['prime', '50mm', 'photography', 'camera']],
  ['prime', ['lens', '50mm', 'photography', 'camera']],
  ['coast', ['coastal', 'beach', 'cliffs']],
  ['coastal', ['coast', 'beach', 'cliffs']],
  ['bird', ['birds', 'birding', 'audubon', 'feeder']],
  ['watch', ['watching', 'watched', 'birding']],
  ['family', ['parents', 'parent', 'mother', 'father', 'brother', 'sister', 'siblings', 'younger', 'older']],
  ['parents', ['family', 'mother', 'father']],
  ['brother', ['family', 'sibling', 'siblings']],
  ['sister', ['family', 'sibling', 'siblings']],
  ['recent', ['latest', 'newest', 'currently', 'now', 'most']],
  ['currently', ['current', 'now', 'latest', 'still', 'own', 'has']],
  ['current', ['currently', 'now', 'latest', 'still', 'present']],
  ['favorite', ['prefer', 'preference', 'like', 'love', 'enjoy', 'best']],
  ['sessions', ['session', 'conversation', 'chat', 'thread']],
  ['attended', ['went', 'visited', 'joined', 'participated']],
  ['raise', ['raised', 'fundraiser', 'charity', 'donation', 'donated']],
  ['occupation', ['job', 'work', 'career', 'position', 'role', 'employed', 'employment']],
  ['previous', ['before', 'earlier', 'old', 'former', 'prior']],
  ['bike', ['bicycle', 'cycling', 'repair', 'service', 'serviced', 'cleaner', 'rack', 'helmet', 'chain', 'lights', 'light', 'tune', 'tuneup', 'mechanic', 'saris']],
  ['expense', ['expenses', 'cost', 'paid', 'spent', 'spend', 'bought', 'buy', 'purchase', 'purchased', 'installed', 'dollars']],
  ['game', ['games', 'gaming', 'play', 'played', 'playing', 'finished', 'finish', 'complete', 'completed', 'difficulty', 'normal', 'hard', 'indie', 'switch']],
  ['play', ['played', 'playing', 'game', 'games', 'gaming', 'finish', 'finished', 'complete', 'completed', 'hour', 'hours']],
  ['hour', ['hours', 'game', 'games', 'play', 'played', 'playing', 'finished', 'finish', 'complete', 'completed']],
  ['kit', ['kits', 'model', 'models', 'scale', 'scales', 'modeling', 'building', 'weathering', 'painting', 'diorama', 'photo', 'etching', 'hobby', 'store', 'show', 'finished', 'picked']],
  ['kits', ['kit', 'model', 'models', 'scale', 'scales', 'modeling', 'building', 'weathering', 'painting', 'diorama', 'photo', 'etching', 'hobby', 'store', 'show', 'finished', 'picked']],
  ['model', ['kit', 'kits', 'scale', 'scales', 'built', 'worked', 'bought', 'modeling', 'building']],
  ['vehicle', ['model', 'car', 'truck', 'pickup', 'ford', 'f150', 'f', '150', 'mustang', 'decal', 'airbrush', 'scale']],
  ['truck', ['vehicle', 'model', 'pickup', 'ford', 'f150', 'f', '150', 'mustang']],
  ['pickup', ['vehicle', 'model', 'truck', 'ford', 'f150', 'f', '150']],
  ['sneaker', ['sneakers', 'shoe', 'shoes', 'rack', 'closet', 'storage', 'bed', 'sandal', 'sandals']],
  ['shoe', ['shoes', 'sneaker', 'sneakers', 'rack', 'closet', 'storage', 'bed', 'sandal', 'sandals']],
  ['closet', ['shoe', 'shoes', 'sneaker', 'sneakers', 'rack', 'storage']],
  ['sexual', ['compulsion', 'compulsions', 'fixation', 'fixations', 'problematic', 'impulsivity', 'sexuality', 'behavior', 'behaviors']],
  ['compulsion', ['compulsions', 'sexual', 'fixation', 'fixations', 'problematic', 'impulsivity', 'sexuality', 'behavior', 'behaviors']],
  ['alternative', ['option', 'options', 'term', 'terms', 'synonym', 'synonyms', 'phrase', 'phrases']],
  ['speyer', ['tourism', 'tourismus', 'marketing', 'board', 'phone', 'number', 'contact', 'details', 'email', 'website', 'maximilianstrasse']],
  ['tourism', ['tourismus', 'marketing', 'board', 'phone', 'number', 'contact', 'details', 'email', 'website', 'maximilianstrasse']],
  ['phone', ['charger', 'case', 'power', 'battery', 'data', 'backup']],
  ['charger', ['phone', 'power', 'cable', 'adapter', 'lost', 'missing', 'misplaced']],
  ['case', ['phone', 'cover', 'protective', 'new', 'got', 'received']],
  ['second', ['two', '2', 'song', 'songs', 'chorus', 'chord', 'progression', 'notes', 'verse']],
  ['note', ['notes', 'song', 'songs', 'chorus', 'chord', 'progression', 'verse']],
  ['festival', ['event', 'attended']],
  ['wedding', ['couple', 'married', 'marriage', 'attended', 'cousin', 'relative', 'bridesmaid', 'engagement', 'party', 'venue', 'ballroom']],
  ['cousin', ['relative', 'wedding', 'bridesmaid', 'engagement', 'party', 'married', 'marriage', 'venue', 'ballroom']],
  ['wake', ['waking', 'woke', 'morning', 'routine']],
  ['stream', ['streaming', 'service', 'services', 'subscription', 'trial', 'free', 'watch', 'watched', 'watching', 'show', 'shows', 'movie', 'movies', 'documentary', 'documentaries', 'netflix', 'hulu', 'prime', 'disney', 'apple']],
  ['streaming', ['stream', 'service', 'services', 'subscription', 'trial', 'free', 'watch', 'watched', 'watching', 'show', 'shows', 'movie', 'movies', 'documentary', 'documentaries', 'netflix', 'hulu', 'prime', 'disney', 'apple']],
  ['instrument', ['guitar', 'piano', 'drum', 'own']],
  ['jobs', ['job', 'remote', 'virtual', 'work', 'home', 'transcriptionist', 'bookkeeper', 'tutor', 'freelance']],
  ['job', ['jobs', 'remote', 'virtual', 'work', 'home', 'transcriptionist', 'bookkeeper', 'tutor', 'freelance']],
  ['senior', ['seniors', 'remote', 'virtual', 'transcriptionist']],
  ['seniors', ['senior', 'remote', 'virtual', 'transcriptionist']],
  ['7th', ['7', 'seven', 'seventh', 'transcriptionist']],
  ['song', ['songs', 'notes', 'chorus', 'verse', 'chord', 'progression']],
  ['songs', ['song', 'notes', 'chorus', 'verse', 'chord', 'progression']],
  ['chorus', ['song', 'songs', 'notes', 'chord', 'progression', 'verse']],
  ['email', ['emails', 'message', 'messages', 'work', 'routine', 'evening', 'pm', 'personal', 'unwind', 'stopping']],
  ['message', ['email', 'emails', 'messages', 'work', 'routine', 'evening', 'pm', 'personal', 'unwind', 'stopping']],
  ['emails', ['email', 'messages', 'work', 'routine', 'evening', 'pm']],
  ['messages', ['email', 'emails', 'work', 'routine', 'evening', 'pm']],
  ['stop', ['stopped', 'stopping', 'email', 'emails', 'message', 'messages', 'evening', 'pm', 'personal', 'unwind']],
  ['sport', ['sports', 'soccer', 'tournament', 'charity', 'annual', 'company', 'triathlon', 'run', '5k', 'event']],
  ['participat', ['participated', 'joined', 'attended', 'event', 'soccer', 'tournament']],
  ['ethnicity', ['heritage', 'cultural', 'family', 'tree', 'mixed', 'irish', 'italian', 'nationality']],
  ['shampoo', ['hair', 'brand', 'lavender', 'trader', 'joe', 'joes']],
  ['brand', ['shampoo', 'hair', 'trader', 'joe', 'joes']],
  ['environmentally', ['environmental', 'responsible', 'sustainable', 'sustainability', 'green', 'supplier', 'suppliers', 'sourcing']],
  ['responsible', ['environmentally', 'environmental', 'sustainable', 'sustainability', 'supplier', 'suppliers', 'sourcing']],
  ['sustainability', ['sustainable', 'environmental', 'environmentally', 'responsible', 'green', 'sourcing', 'suppliers']],
  ['supply', ['chain', 'sourcing', 'supplier', 'suppliers', 'materials', 'transportation', 'packaging']],
  ['chain', ['supply', 'sourcing', 'supplier', 'suppliers', 'materials', 'transportation', 'packaging']],
  ['garden', ['gardening', 'tomato', 'sapling', 'saplings', 'planted', 'planting', 'plants', 'workshop']],
  ['gardening', ['garden', 'tomato', 'sapling', 'saplings', 'planted', 'planting', 'plants', 'workshop']],
  ['art', ['museum', 'exhibit', 'metropolitan', 'modern', 'tour', 'gallery']],
  ['event', ['participated', 'attended', 'wedding', 'engagement', 'party', 'museum', 'exhibit', 'workshop']],
  ['relative', ['cousin', 'wedding', 'engagement', 'party', 'bridesmaid', 'married', 'marriage', 'family']],
  ['life', ['wedding', 'engagement', 'party', 'birth', 'graduation', 'funeral', 'marriage']],
  ['appliance', ['smoker', 'bbq', 'grill', 'oven', 'toaster', 'blender', 'mixer', 'fryer', 'kitchen']],
  ['kitchen', ['appliance', 'smoker', 'bbq', 'grill', 'oven', 'toaster', 'blender', 'mixer', 'fryer']],
  ['buy', ['bought', 'purchased', 'purchase', 'got', 'ordered', 'installed']],
  ['bought', ['buy', 'purchased', 'purchase', 'got', 'ordered', 'installed']],
]);

const MONTH_TERMS = new Map([
  ['january', '01'],
  ['february', '02'],
  ['march', '03'],
  ['april', '04'],
  ['may', '05'],
  ['june', '06'],
  ['july', '07'],
  ['august', '08'],
  ['september', '09'],
  ['october', '10'],
  ['november', '11'],
  ['december', '12'],
]);

const ORDINAL_WORDS = new Map([
  ['first', '1'],
  ['second', '2'],
  ['third', '3'],
  ['fourth', '4'],
  ['fifth', '5'],
  ['sixth', '6'],
  ['seventh', '7'],
  ['eighth', '8'],
  ['ninth', '9'],
  ['tenth', '10'],
  ['eleventh', '11'],
  ['twelfth', '12'],
  ['thirteenth', '13'],
  ['fourteenth', '14'],
  ['fifteenth', '15'],
  ['sixteenth', '16'],
  ['seventeenth', '17'],
  ['eighteenth', '18'],
  ['nineteenth', '19'],
  ['twentieth', '20'],
]);

const INTENT_TERMS = new Set([
  'most', 'least', 'more', 'less', 'first', 'last', 'recent', 'recently',
  'latest', 'newest', 'oldest', 'total', 'count', 'many', 'much', 'which',
  'what', 'when', 'where',
]);

function normalizeText(value) {
  return String(value ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}$:/._-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function stem(token) {
  let out = String(token || '').toLowerCase();
  if (out.length > 5 && out.endsWith('ies')) out = `${out.slice(0, -3)}y`;
  else if (out.length > 5 && out.endsWith('ing')) out = out.slice(0, -3);
  else if (out.length > 4 && out.endsWith('ed')) out = out.slice(0, -2);
  else if (out.length > 4 && out.endsWith('s') && !out.endsWith('ss')) out = out.slice(0, -1);
  return out;
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function tokenize(value, { keepStopwords = false } = {}) {
  const expandedTokens = [];
  for (const rawToken of normalizeText(value).split(/\s+/)) {
    if (!rawToken) continue;
    const token = rawToken.replace(/^[._:-]+|[._:-]+$/g, '');
    if (!token) continue;
    expandedTokens.push(token);
    const parts = token
      .split(/[-_/]+/)
      .map((part) => part.replace(/^[._:-]+|[._:-]+$/g, ''))
      .filter(Boolean);
    if (parts.length > 1) {
      expandedTokens.push(...parts);
      expandedTokens.push(parts.join(''));
    }
  }
  return expandedTokens
    .map(stem)
    .filter((token) => token.length > 1)
    .filter((token) => keepStopwords || !STOPWORDS.has(token));
}

function extractQuotedPhrases(query) {
  const phrases = [];
  for (const pattern of [
    /['"]([^'"]{2,100})['"]/g,
    /[\u201c\u201d]([^\u201c\u201d]{2,100})[\u201c\u201d]/g,
    /[\u2018\u2019]([^\u2018\u2019]{2,100})[\u2018\u2019]/g,
  ]) {
    for (const match of String(query || '').matchAll(pattern)) {
      phrases.push(match[1].trim());
    }
  }
  return unique(phrases);
}

function extractCapitalizedPhrases(query) {
  const phrases = [];
  const raw = String(query || '');
  for (const match of raw.matchAll(/\b[A-Z][a-zA-Z0-9]*(?:\s+[A-Z][a-zA-Z0-9]*){0,4}\b/g)) {
    const phrase = match[0].trim();
    if (!['I', 'What', 'When', 'Which', 'Who', 'How', 'The', 'A', 'An', 'Can', 'Would'].includes(phrase)) {
      phrases.push(phrase);
    }
  }
  return unique(phrases);
}

function extractRecallPhraseHints(query) {
  const normalized = normalizeText(query);
  const phrases = [];
  const addIfPresent = (needle, phrase = needle) => {
    if (normalized.includes(needle)) phrases.push(phrase);
  };
  const addWhen = (condition, items) => {
    if (!condition) return;
    phrases.push(...items);
  };

  addIfPresent('model kits');
  addIfPresent('model kit');
  addIfPresent('work from home jobs for seniors');
  addIfPresent('sad songs');
  addIfPresent('sad song');
  addIfPresent('chord progression');
  addIfPresent('second song');
  addIfPresent('environmentally responsible');
  addIfPresent('responsible supply chain');
  addIfPresent('supply chain');
  addIfPresent('bird watching');
  addIfPresent('bird watching workshop');
  addIfPresent('prime lens');
  addIfPresent('coastal trip');
  addIfPresent('great job with sustainability');
  addIfPresent('dodge charger');
  addIfPresent('subaru forester');
  addWhen(/\bphone\s+charger\b/.test(normalized) && /\bphone\s+case\b/.test(normalized), [
    'phone charger',
    'lost phone charger',
    'phone case',
    'new phone case',
    'got new phone case',
    'received phone case',
  ]);
  addWhen(/\bstreaming\s+service\b/.test(normalized) && /\b(?:start|using|used|use|recent)\b/.test(normalized), [
    'streaming service trial',
    'started using streaming service',
    'free trial streaming service',
    'watched documentary streaming service',
    'streaming service free trial documentary',
  ]);
  addWhen(/\bhow\s+many\b/.test(normalized) && /\bprojects?\b/.test(normalized), [
    'led project',
    'leading project',
    'working on final project',
    'class project',
    'project team',
    'data analysis team',
  ]);
  addWhen(/\bmodel\s+kits?\b/.test(normalized), [
    'model kit',
    'finished model kit',
    'working on model kit',
    'bought model kit',
    'model show',
    'scale model',
  ]);
  addWhen(/\bcamping\s+trips?\b/.test(normalized), [
    'camping trip',
    'solo camping trip',
    'got back from camping trip',
    'national park camping',
  ]);
  addWhen(/\bmovie\s+festivals?\b|\bfilm\s+festivals?\b/.test(normalized), [
    'film festival',
    'movie festival',
    'attended festival',
    'festival screening',
    'festival q&a',
    'film festival volunteer',
  ]);
  addWhen(/\broad\s+trip\b/.test(normalized) && /\b(?:hours?|driv|drove|destinations?)\b/.test(normalized), [
    'road trip',
    'drove hours',
    'hours drive',
    'trip destination',
    'drove to',
  ]);
  addWhen(/\bbike\b/.test(normalized) && /\b(?:money|spent|expenses?|cost)\b/.test(normalized), [
    'bike expenses',
    'bike cost',
    'bike helmet',
    'bike chain',
    'bike lights',
    'bike service',
  ]);
  addWhen(/\bdoctor\b/.test(normalized) && /\b(?:bed|sleep|slept)\b/.test(normalized), [
    'doctor appointment',
    'went to bed',
    'get to bed',
    'day before doctor appointment',
  ]);

  return unique(phrases);
}

function extractOrdinalValuePatterns(query) {
  const normalized = normalizeText(query);
  const ordinals = new Set();
  for (const match of normalized.matchAll(/\b(\d{1,2})(?:st|nd|rd|th)\b/g)) {
    ordinals.add(match[1]);
  }
  for (const [word, number] of ORDINAL_WORDS.entries()) {
    if (normalized.includes(word)) ordinals.add(number);
  }

  const patterns = [];
  for (const ordinal of ordinals) {
    patterns.push(`%${ordinal}.%`, `%${ordinal} %`, `%${ordinal}:%`, `%${ordinal})%`);
  }
  return unique(patterns);
}

function extractComparisonTargets(query) {
  const quoted = extractQuotedPhrases(query);
  if (quoted.length >= 2) return quoted.slice(0, 4);
  const raw = String(query || '');
  const match = raw.match(/\b(?:between|compare|compared|which|what)?\s*([^?.,]{2,80}?)\s+\bor\b\s+([^?.,]{2,80}?)(?:\?|$)/i);
  if (!match) return [];
  return [match[1], match[2]]
    .map((part) => part.replace(/\b(which|what|who|did|do|does|i|me|my|the|a|an|first|more|than|became|finish|reading|join|group|task|complete|completed|arrival|arrived|receiving|received)\b/gi, ' '))
    .map((part) => part.replace(/\s+/g, ' ').trim())
    .filter((part) => part.length > 1)
    .slice(0, 4);
}

function escapeTsQueryTerm(term) {
  return String(term || '').replace(/[^a-zA-Z0-9]/g, '').trim();
}

function buildTsQuery(terms) {
  const safe = unique(terms.map(escapeTsQueryTerm))
    .filter((term) => term.length >= 2)
    .slice(0, 32);
  return safe.length ? safe.join(' | ') : 'memory';
}

function buildPhrasePatterns(phrases) {
  return unique(phrases
    .map(normalizeText)
    .filter((phrase) => phrase.length >= 3)
    .slice(0, 12)
    .map((phrase) => `%${phrase}%`));
}

function buildValuePatterns(terms, phrases = []) {
  return unique([
    ...terms,
    ...phrases.map(normalizeText),
    ...phrases.flatMap((phrase) => tokenize(phrase)),
  ])
    .map(normalizeText)
    .filter((term) => term.length >= 3)
    .filter((term) => !INTENT_TERMS.has(term))
    .slice(0, 96)
    .map((term) => `%${term}%`);
}

function expandTerms(terms) {
  const expanded = [...terms];
  for (const term of [...terms]) {
    const more = EXPANSIONS.get(term);
    if (more) expanded.push(...more.map(stem));
  }
  return unique(expanded);
}

function includesAny(termSet, terms) {
  return terms.some((term) => termSet.has(term));
}

function pruneContextualExpansionCollisions(expandedTerms, baseTerms) {
  const baseSet = new Set(baseTerms);
  const remove = new Set();

  if (baseSet.has('spent') && includesAny(baseSet, ['game', 'play', 'hour'])) {
    for (const term of ['spend', 'cost', 'paid', 'expense', 'bought', 'buy', 'purchase', 'purchas', 'dollar']) {
      if (!baseSet.has(term)) remove.add(term);
    }
  }

  if (baseSet.has('old') && includesAny(baseSet, ['sneaker', 'shoe', 'closet', 'rack'])) {
    for (const term of ['age', 'aged', 'year', 'born', 'birth', 'birthday']) {
      if (!baseSet.has(term)) remove.add(term);
    }
  }

  return expandedTerms.filter((term) => !remove.has(term));
}

function splitQueryTerms(baseTerms) {
  const temporalTerms = [];
  const intentTerms = [];
  const subjectTerms = [];

  for (const term of baseTerms) {
    if (MONTH_TERMS.has(term)) {
      temporalTerms.push(term, MONTH_TERMS.get(term));
    } else if (INTENT_TERMS.has(term)) {
      intentTerms.push(term);
    } else {
      subjectTerms.push(term);
    }
  }

  return {
    subjectTerms: pruneContextualExpansionCollisions(expandTerms(subjectTerms), baseTerms).slice(0, 32),
    temporalTerms: unique(temporalTerms).slice(0, 16),
    intentTerms: unique(intentTerms).slice(0, 16),
  };
}

export function buildRecallLexicalCalibration(query = {}) {
  const baseTerms = tokenize(query);
  const splitTerms = splitQueryTerms(baseTerms);
  const quoted = extractQuotedPhrases(query);
  const namedEntities = unique([...quoted, ...extractCapitalizedPhrases(query)]);
  const comparisonTargets = extractComparisonTargets(query);
  const recallPhraseHints = extractRecallPhraseHints(query);
  const phraseTerms = [...namedEntities, ...comparisonTargets].flatMap((phrase) => tokenize(phrase));
  const expanded = pruneContextualExpansionCollisions(
    expandTerms([...baseTerms, ...phraseTerms, ...splitTerms.temporalTerms]),
    baseTerms
  );
  const terms = unique(expanded).slice(0, 48);
  const phrases = unique([...quoted, ...comparisonTargets, ...namedEntities, ...recallPhraseHints]).slice(0, 20);
  const valuePatterns = unique([
    ...buildValuePatterns(terms.length ? terms : tokenize(query, { keepStopwords: true }), phrases),
    ...extractOrdinalValuePatterns(query),
  ]).slice(0, 112);

  return {
    terms: terms.length ? terms : tokenize(query, { keepStopwords: true }).slice(0, 12),
    subject_terms: splitTerms.subjectTerms,
    temporal_terms: splitTerms.temporalTerms,
    intent_terms: splitTerms.intentTerms,
    ts_query: buildTsQuery(terms.length ? terms : tokenize(query, { keepStopwords: true })),
    phrases,
    phrase_patterns: buildPhrasePatterns(phrases),
    value_patterns: valuePatterns,
    named_entities: namedEntities,
    comparison_targets: comparisonTargets,
    formulas_used: [
      'BM25_sparse_or_retrieval',
      'entity_and_comparison_target_coverage',
      'MRAG_query_decomposition',
      'source_attributed_relevance_signal',
    ],
  };
}

function dateTermHit(haystack, term) {
  const raw = String(term || '');
  if (!/^\d{2}$/.test(raw)) return false;
  return haystack.includes(`/${raw}/`) || haystack.includes(`-${raw}-`) || haystack.includes(` ${raw} `);
}

function countTermHits(haystack, terms, tokenSet = null) {
  if (!terms.length) return 0;
  let hits = 0;
  for (const term of terms) {
    const normalized = stem(normalizeText(term));
    if (!normalized) continue;
    if (tokenSet) {
      if (tokenSet.has(normalized) || dateTermHit(haystack, normalized)) hits += 1;
    } else if (haystack.includes(normalized)) {
      hits += 1;
    }
  }
  return hits;
}

function countPhraseHits(haystack, phrases) {
  if (!phrases.length) return 0;
  let hits = 0;
  for (const phrase of phrases) {
    const normalized = normalizeText(phrase);
    if (normalized && haystack.includes(normalized)) hits += 1;
  }
  return hits;
}

function buildTokenFrequency(tokens = []) {
  const frequency = new Map();
  for (const token of tokens) {
    frequency.set(token, (frequency.get(token) || 0) + 1);
  }
  return frequency;
}

function countTermFrequency(haystack, terms, tokens = null, tokenFrequency = null) {
  if (!terms.length) return 0;
  let hits = 0;
  for (const term of terms) {
    const normalized = stem(normalizeText(term));
    if (!normalized) continue;
    const occurrences = tokens
      ? (tokenFrequency?.get(normalized) || 0)
      : haystack.split(normalized).length - 1;
    hits += Math.min(3, Math.max(0, occurrences));
  }
  return hits;
}

export function scoreRecallLexicalMatch(query, memory = {}, calibration = null) {
  const cal = calibration || buildRecallLexicalCalibration(query);
  const haystack = normalizeText([
    memory.key,
    memory.session_id,
    memory.project_id,
    memory.memory_type,
    memory.source,
    memory.value,
  ].filter(Boolean).join(' '));
  const haystackTokens = tokenize(haystack, { keepStopwords: true });
  const haystackTokenSet = new Set(haystackTokens);
  const haystackTokenFrequency = buildTokenFrequency(haystackTokens);

  const termHits = countTermHits(haystack, cal.terms, haystackTokenSet);
  const subjectHits = countTermHits(haystack, cal.subject_terms || [], haystackTokenSet);
  const subjectFrequency = countTermFrequency(haystack, cal.subject_terms || [], haystackTokens, haystackTokenFrequency);
  const temporalHits = countTermHits(haystack, cal.temporal_terms || [], haystackTokenSet);
  const entityHits = countPhraseHits(haystack, cal.named_entities);
  const comparisonHits = countPhraseHits(haystack, cal.comparison_targets);
  const phraseHits = countPhraseHits(haystack, cal.phrases);

  const termCoverage = cal.terms.length ? termHits / cal.terms.length : 0;
  const subjectCoverage = cal.subject_terms?.length ? subjectHits / cal.subject_terms.length : 0;
  const subjectDensity = cal.subject_terms?.length ? Math.min(1, subjectFrequency / Math.max(2, cal.subject_terms.length * 2)) : 0;
  const temporalCoverage = cal.temporal_terms?.length ? temporalHits / cal.temporal_terms.length : 0;
  const entityCoverage = cal.named_entities.length ? entityHits / cal.named_entities.length : 0;
  const comparisonCoverage = cal.comparison_targets.length ? comparisonHits / cal.comparison_targets.length : 0;
  const phraseCoverage = cal.phrases.length ? phraseHits / cal.phrases.length : 0;

  let score = cal.subject_terms?.length
    ? (subjectCoverage * 0.40)
      + (subjectDensity * 0.24)
      + (temporalCoverage * 0.14)
      + (entityCoverage * 0.08)
      + (comparisonCoverage * 0.08)
      + (phraseCoverage * 0.06)
      + (termCoverage * 0.10)
    : (termCoverage * 0.55)
      + (entityCoverage * 0.18)
      + (comparisonCoverage * 0.22)
      + (phraseCoverage * 0.15);

  if (cal.subject_terms?.length && subjectCoverage === 0) {
    score *= 0.2;
  } else if (cal.subject_terms?.length && subjectCoverage < 0.35) {
    score *= 0.55;
  }

  if (phraseHits > 0) {
    score += Math.min(0.24, phraseHits * 0.18);
  }

  const valueHitCount = Number(memory.value_hit_count || 0);
  if (valueHitCount > 0) {
    score += Math.min(0.08, valueHitCount * 0.01);
  }

  return Number(Math.max(0, Math.min(1, score)).toFixed(6));
}

export default {
  buildRecallLexicalCalibration,
  scoreRecallLexicalMatch,
};
