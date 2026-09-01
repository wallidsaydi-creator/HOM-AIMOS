#!/bin/bash

# HOM-AIMOS clean-macOS source installer.
#
# This script has no credential or runtime-policy authority. It discovers or
# provisions executable dependencies, installs the locked npm graph, hands
# control to native Genesis, then invokes generic first-launch onboarding.
# Secrets remain in Keychain; mutable AIMOS policy remains in signed ledgers.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
MODE="install"
ASSUME_YES=0
DATABASE="aimos"
PORT="9100"
INSTANCE="canonical"
POSTGRES_PORT="5432"
AGENT_ID=""
MODEL_PROVIDER=""
MODEL_ID=""
BREW=""
NODE_BIN=""
PG_CONFIG=""
MISSING=""

usage() {
  cat <<'EOF'
Usage: ./install-macos.sh [options]

  --check                 Inspect prerequisites without changing the machine.
  --dependencies-only     Provision/verify prerequisites, then stop.
  --aimos-db NAME         Genesis database name (default: aimos).
  --aimos-port PORT       AIMOS server port (default: 9100).
  --aimos-instance NAME   Application installation namespace (default: canonical).
  --postgres-port PORT    PostgreSQL server port (default: 5432).
  --agent-id ID           First ordinary agent identity (prompted when omitted).
  --model-provider ID     Optional provider selected during onboarding.
  --model ID              Optional model selected during onboarding.
  --yes                   Accept the displayed Homebrew/Genesis plan.
  --help                  Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --dependencies-only) MODE="dependencies"; shift ;;
    --aimos-db) DATABASE="${2:-}"; shift 2 ;;
    --aimos-port) PORT="${2:-}"; shift 2 ;;
    --aimos-instance) INSTANCE="${2:-}"; shift 2 ;;
    --postgres-port) POSTGRES_PORT="${2:-}"; shift 2 ;;
    --agent-id) AGENT_ID="${2:-}"; shift 2 ;;
    --model-provider) MODEL_PROVIDER="${2:-}"; shift 2 ;;
    --model) MODEL_ID="${2:-}"; shift 2 ;;
    --yes) ASSUME_YES=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

case "$DATABASE" in
  ''|*[!a-z0-9_]*|oracle|aimos_dev|postgres|template1)
    echo "Invalid or protected AIMOS database name: $DATABASE" >&2
    exit 64
    ;;
esac
if [ -n "$AGENT_ID" ]; then
  case "$AGENT_ID" in
    *[!a-zA-Z0-9_-]*|housekeeper|aimos_flag_signer) echo "Invalid or reserved AIMOS agent id: $AGENT_ID" >&2; exit 64 ;;
  esac
  [ "${#AGENT_ID}" -le 64 ] || { echo "AIMOS agent id is too long." >&2; exit 64; }
fi
if { [ -n "$MODEL_PROVIDER" ] && [ -z "$MODEL_ID" ]; } \
   || { [ -z "$MODEL_PROVIDER" ] && [ -n "$MODEL_ID" ]; }; then
  echo "--model-provider and --model must be supplied together." >&2
  exit 64
fi
case "$DATABASE" in
  [a-z]*) ;;
  *)
    echo "AIMOS database names must begin with a lowercase letter: $DATABASE" >&2
    exit 64
    ;;
esac
case "$PORT" in
  ''|*[!0-9]*) echo "Invalid AIMOS port: $PORT" >&2; exit 64 ;;
esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ] || [ "$PORT" -eq 9000 ] || [ "$PORT" -eq 9001 ]; then
  echo "Invalid or reserved AIMOS port: $PORT" >&2
  exit 64
fi
case "$INSTANCE" in
  ''|[!a-z]*|*[!a-z0-9_-]*) echo "Invalid AIMOS instance: $INSTANCE" >&2; exit 64 ;;
  *) [ "${#INSTANCE}" -le 32 ] || { echo "Invalid AIMOS instance: $INSTANCE" >&2; exit 64; } ;;
esac
case "$POSTGRES_PORT" in
  ''|*[!0-9]*) echo "Invalid PostgreSQL port: $POSTGRES_PORT" >&2; exit 64 ;;
esac
if [ "$POSTGRES_PORT" -lt 1024 ] || [ "$POSTGRES_PORT" -gt 65535 ] \
   || [ "$POSTGRES_PORT" -eq 9000 ] || [ "$POSTGRES_PORT" -eq 9001 ] \
   || [ "$POSTGRES_PORT" -eq 9100 ]; then
  echo "Invalid PostgreSQL port: $POSTGRES_PORT" >&2
  exit 64
fi

if [ "$(uname -s)" != "Darwin" ]; then
  echo "HOM-AIMOS 1.0 supports macOS only; this host is $(uname -s)." >&2
  exit 69
fi

MACOS_MAJOR="$(sw_vers -productVersion | awk -F. '{print $1}')"
if [ "$MACOS_MAJOR" -lt 14 ]; then
  echo "HOM-AIMOS 1.0 requires macOS 14 or later; found $(sw_vers -productVersion)." >&2
  exit 69
fi
case "$(uname -m)" in
  arm64|x86_64) ;;
  *) echo "Unsupported macOS architecture: $(uname -m)" >&2; exit 69 ;;
esac

find_brew() {
  if [ "$(uname -m)" = "arm64" ] && [ -x /opt/homebrew/bin/brew ]; then
    printf '%s\n' /opt/homebrew/bin/brew
  elif [ "$(uname -m)" = "x86_64" ] && [ -x /usr/local/bin/brew ]; then
    printf '%s\n' /usr/local/bin/brew
  elif command -v brew >/dev/null 2>&1; then
    command -v brew
  fi
}

find_node() {
  candidate=""
  # Prefer the architecture-native Homebrew Node 26 selected by the shipped
  # Brewfile before an ambient shell shim. This keeps clean installation and
  # reproducibility on the same concrete runtime while retaining 20/24 fallback
  # for already-provisioned supported hosts.
  if [ -n "$BREW" ] && "$BREW" --prefix node@26 >/dev/null 2>&1; then
    candidate="$("$BREW" --prefix node@26)/bin/node"
    major="$([ -x "$candidate" ] && "$candidate" -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || true)"
    [ "$major" = "26" ] && { printf '%s\n' "$candidate"; return; }
  fi
  if command -v node >/dev/null 2>&1; then candidate="$(command -v node)"; fi
  if [ -n "$candidate" ]; then
    major="$("$candidate" -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || true)"
    if [ "$major" = "26" ] || [ "$major" = "20" ] || [ "$major" = "24" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  fi
  if [ -n "$BREW" ] && "$BREW" --prefix node@24 >/dev/null 2>&1; then
    candidate="$("$BREW" --prefix node@24)/bin/node"
    major="$([ -x "$candidate" ] && "$candidate" -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || true)"
    [ "$major" = "24" ] && printf '%s\n' "$candidate"
  fi
}

find_pg_config() {
  if [ -n "$BREW" ] && "$BREW" --prefix postgresql@18 >/dev/null 2>&1; then
    candidate="$("$BREW" --prefix postgresql@18)/bin/pg_config"
    [ -x "$candidate" ] && { printf '%s\n' "$candidate"; return; }
  fi
  candidate="/Applications/Postgres.app/Contents/Versions/18/bin/pg_config"
  [ -x "$candidate" ] && { printf '%s\n' "$candidate"; return; }
  if command -v pg_config >/dev/null 2>&1; then
    candidate="$(command -v pg_config)"
    "$candidate" --version 2>/dev/null | grep -q '^PostgreSQL 18\.' && printf '%s\n' "$candidate"
  fi
}

add_missing() {
  if [ -z "$MISSING" ]; then MISSING="$1"; else MISSING="$MISSING, $1"; fi
}

inspect_dependencies() {
  MISSING=""
  BREW="$(find_brew || true)"
  NODE_BIN="$(find_node || true)"
  PG_CONFIG="$(find_pg_config || true)"

  xcode-select -p >/dev/null 2>&1 || add_missing "Apple Command Line Tools"
  [ -n "$NODE_BIN" ] || add_missing "Node.js 20, 24, or 26"
  [ -n "$PG_CONFIG" ] || add_missing "PostgreSQL 18"
  command -v curl >/dev/null 2>&1 || add_missing "curl"
  command -v make >/dev/null 2>&1 || add_missing "make"
  command -v pkg-config >/dev/null 2>&1 || add_missing "pkgconf/pkg-config"
  if command -v pkg-config >/dev/null 2>&1; then
    pkg-config --exists libsodium >/dev/null 2>&1 || add_missing "libsodium development files"
  fi
  if [ -n "$PG_CONFIG" ]; then
    vector_control="$("$PG_CONFIG" --sharedir)/extension/vector.control"
    [ -f "$vector_control" ] || add_missing "pgvector for PostgreSQL 18"
  fi
}

print_facts() {
  echo "HOM-AIMOS install preflight"
  echo "============================"
  echo "macOS:       $(sw_vers -productVersion) ($(uname -m))"
  echo "Homebrew:    ${BREW:-not installed (optional when dependencies already exist)}"
  echo "Node.js:     $([ -n "$NODE_BIN" ] && "$NODE_BIN" --version || echo missing)"
  echo "Instance:    $INSTANCE"
  echo "PG port:     $POSTGRES_PORT"
  echo "PostgreSQL:  $([ -n "$PG_CONFIG" ] && "$PG_CONFIG" --version || echo missing)"
  if [ -n "$PG_CONFIG" ] && [ -f "$("$PG_CONFIG" --sharedir)/extension/vector.control" ]; then
    echo "pgvector:    available to PostgreSQL 18"
  else
    echo "pgvector:    missing"
  fi
  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libsodium >/dev/null 2>&1; then
    echo "libsodium:   $(pkg-config --modversion libsodium)"
  else
    echo "libsodium:   missing"
  fi
  echo "pgsodium:    Genesis-owned, source/checksum locked at 3.1.11"
}

inspect_dependencies
print_facts

if [ "$MODE" = "check" ]; then
  if [ -n "$MISSING" ]; then
    echo "Missing: $MISSING" >&2
    exit 69
  fi
  echo "Preflight passed; no machine state changed."
  exit 0
fi

if [ -n "$MISSING" ]; then
  if ! xcode-select -p >/dev/null 2>&1; then
    echo >&2
    echo "Install Apple Command Line Tools, then rerun:" >&2
    echo "  xcode-select --install" >&2
    exit 69
  fi
  if [ -z "$BREW" ]; then
    echo >&2
    echo "Homebrew is not AIMOS authority, but it is the supported source-install provisioner." >&2
    echo "Install it from https://brew.sh, then rerun this script." >&2
    echo "Official informational command:" >&2
    echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"" >&2
    exit 69
  fi
  echo
  echo "Missing dependencies: $MISSING"
  echo "Provisioning plan: $BREW bundle --file $ROOT/Brewfile"
  if [ "$ASSUME_YES" -ne 1 ]; then
    printf 'Continue with Homebrew installation? [y/N] '
    read -r answer
    case "$answer" in y|Y|yes|YES) ;; *) echo "Cancelled."; exit 1 ;; esac
  fi
  "$BREW" bundle --file "$ROOT/Brewfile"
fi

BREW="$(find_brew || true)"
if [ "$POSTGRES_PORT" -eq 5432 ] && [ -n "$BREW" ] \
   && "$BREW" --prefix postgresql@18 >/dev/null 2>&1; then
  "$BREW" services start postgresql@18
fi

inspect_dependencies
print_facts
if [ -n "$MISSING" ]; then
  echo "Dependency provisioning incomplete: $MISSING" >&2
  exit 69
fi

PG_BINDIR="$("$PG_CONFIG" --bindir)"
NODE_BINDIR="$(dirname "$NODE_BIN")"
NPM_BIN="$NODE_BINDIR/npm"
[ -x "$NPM_BIN" ] || { echo "Selected Node.js runtime has no sibling npm: $NODE_BIN" >&2; exit 69; }
# This process-local PATH only selects verified installer executables. AIMOS
# never reads it as configuration, identity, credential, or policy authority.
PATH="$NODE_BINDIR:$PG_BINDIR:$PATH"
export PATH

if [ "$MODE" = "dependencies" ]; then
  echo "Dependencies are ready; Genesis was not run."
  exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  echo
  echo "Genesis will create database '$DATABASE', provision the Housekeeper, ingest the Guide, and reserve port $PORT."
  echo "Generic onboarding will then enroll the agent identity you choose and optionally record your model preference."
  printf 'Continue with native Genesis? [y/N] '
  read -r answer
  case "$answer" in y|Y|yes|YES) ;; *) echo "Cancelled."; exit 1 ;; esac
fi

cd "$ROOT"
"$NPM_BIN" ci
"$NODE_BIN" scripts/genesis-install.mjs \
  --aimos-db "$DATABASE" --aimos-port "$PORT" \
  --aimos-instance "$INSTANCE" --aimos-postgres-port "$POSTGRES_PORT"
ONBOARD_ARGS=(
  --aimos-db "$DATABASE"
  --aimos-port "$PORT"
  --aimos-instance "$INSTANCE"
  --aimos-postgres-port "$POSTGRES_PORT"
)
[ -n "$AGENT_ID" ] && ONBOARD_ARGS+=(--agent-id "$AGENT_ID")
if [ -n "$MODEL_PROVIDER" ]; then
  ONBOARD_ARGS+=(--model-provider "$MODEL_PROVIDER" --model "$MODEL_ID")
fi
"$NODE_BIN" scripts/identity/onboard-agent.mjs "${ONBOARD_ARGS[@]}"
"$NODE_BIN" scripts/service/manage-user-service.mjs install \
  --source-root "$ROOT" \
  --node "$NODE_BIN" \
  --database "$DATABASE" \
  --port "$PORT" \
  --instance "$INSTANCE" \
  --postgres-port "$POSTGRES_PORT"

echo
echo "Installation complete. AIMOS is installed as a persistent user service."
echo "Instance: $INSTANCE"
echo "Database: $DATABASE"
echo "AIMOS port: $PORT"
echo "Operator onboarding used one passphrase entry."
echo "Service status:"
printf '  %q scripts/service/manage-user-service.mjs status --instance %q\n' "$NODE_BIN" "$INSTANCE"
