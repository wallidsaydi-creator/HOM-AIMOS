#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# fresh-ceremony.sh — the public-release gate.
#
# Performs the ENTIRE genesis ceremony on a machine that has never seen HOM,
# exactly as a stranger cloning the repository would experience it:
#
#   A2  database creation + agent_runtime role
#   A3  every migration in the deterministic migration order
#   A4  runtime architecture-authority generation
#   A5  housekeeper self-provisioning, Ed25519 keypair, self-signed
#       T1_SYSTEM_SELF cert, passphrase → keychain
#   A6  Guide/*.md ingestion through the REAL signed POST /aimos/save
#       (auth-gate active, no bypass)
#   ──  then, beyond the installer:
#       • recall returns the ingested Guide (the corpus is not blank)
#       • every memory carries a provenance row (the ledger has no orphans)
#       • credential save/read round-trips
#
# Assertions cover state, durable evidence, and non-empty outputs.
#
# SAFETY: refuses to run against protected legacy database names. Resolves the selected
# PostgreSQL 18 toolchain without assuming CPU architecture or patch version.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

DB="${1:-aimos_ceremony_$$}"
PORT="9100"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0
FAIL=0

find_pg18_bin() {
  local brew_bin="" prefix="" candidate=""
  if command -v brew >/dev/null 2>&1; then
    brew_bin="$(command -v brew)"
  elif [ -x /opt/homebrew/bin/brew ]; then
    brew_bin=/opt/homebrew/bin/brew
  elif [ -x /usr/local/bin/brew ]; then
    brew_bin=/usr/local/bin/brew
  fi
  if [ -n "$brew_bin" ]; then
    prefix="$("$brew_bin" --prefix postgresql@18 2>/dev/null || true)"
    candidate="$prefix/bin"
    if [ -x "$candidate/pg_config" ] && "$candidate/pg_config" --version | grep -q '^PostgreSQL 18\.'; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  candidate=/Applications/Postgres.app/Contents/Versions/18/bin
  if [ -x "$candidate/pg_config" ] && "$candidate/pg_config" --version | grep -q '^PostgreSQL 18\.'; then
    printf '%s\n' "$candidate"
    return 0
  fi
  if command -v pg_config >/dev/null 2>&1 && pg_config --version | grep -q '^PostgreSQL 18\.'; then
    dirname "$(command -v pg_config)"
    return 0
  fi
  return 1
}

PG18="$(find_pg18_bin || true)"

# ─── guardrails ──────────────────────────────────────────────────────────────
case "$DB" in
  oracle|aimos_dev)
    echo "REFUSING: '$DB' holds real data. This script creates and destroys a database." >&2
    exit 2 ;;
esac
[ -n "$PG18" ] && [ -x "$PG18/psql" ] \
  || { echo "PostgreSQL 18 binaries were not found in Homebrew, Postgres.app, or PATH" >&2; exit 2; }

ok()   { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n     got: %s\n' "$1" "${2:-<empty>}"; }
q()    { "$PG18/psql" -d "$DB" -tAc "$1" 2>/dev/null | tr -d ' '; }

# shellcheck disable=SC2329 # invoked indirectly by EXIT trap
cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
  "$PG18/dropdb" --if-exists "$DB" 2>/dev/null
  echo "  (dropped ephemeral pre-release test database $DB)"
}
trap cleanup EXIT

echo "═══ HOM fresh-install ceremony — database: $DB ═══"
echo

# ─── A1–A6: run the installer exactly as a new user would ───────────────────
echo "── Running scripts/genesis-install.mjs ──"
if node "$ROOT/scripts/genesis-install.mjs" --aimos-db "$DB" > /tmp/ceremony-$$.log 2>&1; then
  ok "genesis-install.mjs completed (exit 0)"
else
  bad "genesis-install.mjs FAILED (exit $?)" "$(tail -5 /tmp/ceremony-$$.log)"
  echo; echo "── installer log tail ──"; tail -25 /tmp/ceremony-$$.log
fi
echo

# ─── STATEFUL 1: every migration in the deterministic order applied ─────────
echo "── Stateful assertions ──"
EXPECT_MIGRATIONS=$(node "$ROOT/migrations/run.js" --print-order | awk -F, '{print NF}')
n_mig=$(q "SELECT count(*) FROM schema_migrations;")
if [ "$n_mig" = "$EXPECT_MIGRATIONS" ]; then
  ok "all $EXPECT_MIGRATIONS migrations applied"
else
  bad "schema_migrations should be $EXPECT_MIGRATIONS" "$n_mig"
fi

quantum=$(q "SELECT to_regclass('public.memory_quantum_states') IS NOT NULL;")
if [ "$quantum" = "t" ]; then
  ok "quantum-schema objects exist (formerly hand-applied only)"
else
  bad "memory_quantum_states missing" "$quantum"
fi

parent=$(q "SELECT count(*) FROM information_schema.columns WHERE table_name='aimos_events' AND column_name='parent_event_id';")
if [ "$parent" = "1" ]; then
  ok "aimos_events.parent_event_id exists"
else
  bad "parent_event_id missing" "$parent"
fi

# ─── STATEFUL 2: the housekeeper self-enrolled with a system role ───────────
hk=$(q "SELECT count(*) FROM agent_identity WHERE agent_id='housekeeper' AND is_system_role;")
if [ "$hk" = "1" ]; then
  ok "housekeeper self-enrolled, is_system_role=true"
else
  bad "housekeeper not enrolled as system role" "$hk"
fi

# ─── STATEFUL 3: exact manifest corpus, root-bound, fully attested ────────────
n_mem=$(q "SELECT count(*) FROM aimos_memories;")
manifest_files=$(node -e "const m=require('$ROOT/Guide/GENESIS-MANIFEST.json'); console.log(m.files.length)")
manifest_root=$(node -e "const m=require('$ROOT/Guide/GENESIS-MANIFEST.json'); console.log(m.corpus_root)")
manifest_version=$(node -e "const m=require('$ROOT/Guide/GENESIS-MANIFEST.json'); console.log(m.version)")
if [ -n "$n_mem" ] && [ "$n_mem" = "$manifest_files" ] 2>/dev/null; then
  ok "clean Genesis corpus contains exactly $manifest_files Guide memories"
else
  bad "expected exactly $manifest_files Guide seed memories before first boot" "$n_mem"
fi

bound=$(q "SELECT count(DISTINCT m.key)
             FROM aimos_memories m
             JOIN aimos_memory_provenance p ON p.memory_id = m.id
            WHERE m.company_id='hom'
              AND m.source='guide:genesis-install'
              AND p.body_json->>'genesis_corpus_root'='$manifest_root'
              AND p.body_json->>'genesis_manifest_version'='$manifest_version';")
if [ "$bound" = "$manifest_files" ]; then
  ok "all $manifest_files Guide memories commit to corpus_root=$manifest_root"
else
  bad "manifest-bound Guide provenance count should be $manifest_files" "$bound"
fi

# Guard against a VACUOUS pass: with 0 memories there are trivially 0 orphans.
# An assertion that cannot fail is not an assertion.
orphans=$(q "SELECT count(*) FROM aimos_memories m
             LEFT JOIN aimos_memory_provenance p ON p.memory_id = m.id
             WHERE p.memory_id IS NULL;")
if [ -z "$n_mem" ] || [ "$n_mem" = "0" ]; then
  bad "orphan check SKIPPED — corpus is empty, so this assertion is vacuous" "0 memories"
elif [ "$orphans" = "0" ]; then
  ok "all $n_mem memories carry a provenance row (ledger has no orphans)"
else
  bad "UNATTESTED MEMORIES — the genesis corpus is not fully ledgered; atomic memory and provenance persistence failed" "$orphans"
fi

# ─── DISK: the housekeeper's private key exists, 0600, owned by us ──────────
echo
echo "── Disk assertion ──"
KEY="$HOME/.aimos/agents/housekeeper.key"          # genesis-install.mjs:185
CERT="$HOME/.aimos/agents/housekeeper.cert-cache.json"  # genesis-install.mjs:186
if [ -f "$KEY" ]; then
  mode=$(stat -f '%Lp' "$KEY" 2>/dev/null || stat -c '%a' "$KEY" 2>/dev/null)
  if [ "$mode" = "600" ]; then
    ok "housekeeper privkey on disk with mode 0600"
  else
    bad "privkey mode must be 0600" "$mode"
  fi
else
  bad "housekeeper privkey not written to $KEY" "absent"
fi
if [ -f "$CERT" ]; then
  ok "self-signed T1_SYSTEM_SELF cert cached on disk"
else
  bad "cert cache missing" "$CERT absent"
fi
if node "$ROOT/scripts/verify-genesis-manifest.mjs" >/dev/null 2>&1; then
  ok "Guide/GENESIS-MANIFEST.json matches every shipped Guide byte"
else
  bad "Genesis manifest verification failed" "$ROOT/Guide/GENESIS-MANIFEST.json"
fi

# ─── NON-EMPTY FIELD: recall actually returns the Guide ─────────────────────
echo
echo "── Non-empty-field assertion (live recall) ──"
node "$ROOT/server.js" --aimos-db "$DB" > /tmp/ceremony-server-$$.log 2>&1 &
SERVER_PID=$!
for _ in {1..30}; do
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 1
done

if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
  ok "server booted against the freshly-installed database"
  # Recall is auth-gated. Sign a real envelope as the housekeeper.
  RECALL_BODY='{"query":"how do I save a memory","company_id":"hom","limit":10}'
  RECALL=$(printf '%s' "$RECALL_BODY" | node "$ROOT/aimos-sign-headers.js" \
             --aimos-db "$DB" --agent housekeeper --method POST --path '/aimos/recall' --body - \
             --exec "http://127.0.0.1:$PORT/aimos/recall" 2>/dev/null)
  n_results=$(printf '%s' "$RECALL" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);console.log((j.results||j.memories||[]).length)}catch{console.log(0)}})' 2>/dev/null)
  if [ -n "$n_results" ] && [ "$n_results" -gt 0 ] 2>/dev/null; then
    ok "recall returned $n_results memories — a non-empty field, signed end-to-end"
  else
    bad "recall returned no results (corpus blank, or envelope rejected)" "$n_results"
  fi
  live_orphans=$(q "SELECT count(*) FROM aimos_memories m
                     LEFT JOIN aimos_memory_provenance p ON p.memory_id = m.id
                     WHERE p.memory_id IS NULL;")
  if [ "$live_orphans" = "0" ]; then
    ok "post-boot writes remain fully attested (no orphaned memory rows)"
  else
    bad "post-boot orphan check failed" "$live_orphans"
  fi
  signal_rows=$(q "SELECT count(*) FROM aimos_memories
                    WHERE source IN ('signal-generators.js','sunday-signal-scan.js')
                       OR key LIKE 'signal_%';")
  if [ "$signal_rows" = "0" ]; then
    ok "public first boot adds no optional signal or Sunday personal corpus"
  else
    bad "first boot must not ingest optional signal memories" "$signal_rows"
  fi
else
  bad "server did not become healthy on :$PORT" "$(tail -5 /tmp/ceremony-server-$$.log)"
fi

# ─── PART B is NOT testable here, and that is correct ──────────────────────
# scripts/identity/passphrase.js:3-4 —
#   "there is NO env-var fallback — the passphrase is interactive-only.
#    If stdin is not a TTY, throw."
# Master enrollment and credential storage therefore CANNOT be automated, by
# design: secrets never pass through environment variables. genesis-install.mjs
# says the same ("No user master or agent enrollment happens here — that's the
# live Part B ceremony").
#
# Part B lives in tests/install/PART-B-CEREMONY.md and must be run by a human:
#     ! node scripts/identity/enroll-master.js
#     ! node scripts/identity/store-credential.js STORE --service=… --reason=…
echo
echo "── Part B (interactive) — NOT asserted here ──"
echo "  ⓘ master enrollment + credential save require a TTY passphrase by design."
echo "    Run tests/install/PART-B-CEREMONY.md manually. See passphrase.js:3-4."

# ─── IDEMPOTENCE: running genesis twice must not duplicate the corpus ──────
echo
echo "── Idempotence ──"
kill "$SERVER_PID" 2>/dev/null; unset SERVER_PID
before=$(q "SELECT count(*) FROM aimos_memories WHERE source = 'guide:genesis-install';")
node "$ROOT/scripts/genesis-install.mjs" --aimos-db "$DB" > /tmp/ceremony-2nd-$$.log 2>&1
after=$(q "SELECT count(*) FROM aimos_memories WHERE source = 'guide:genesis-install';")
if [ "$before" = "$after" ]; then
  ok "second genesis run leaves the Guide corpus unchanged ($after memories)"
else
  bad "genesis duplicated Guide memories" "$before → $after"
fi

# ─── verdict ────────────────────────────────────────────────────────────────
echo
echo "═══ Results ═══"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Installer log: /tmp/ceremony-$$.log"
[ "$FAIL" -gt 0 ] && exit 1
echo
echo "  Ceremony complete. A stranger cloning this repo can install it."
exit 0
