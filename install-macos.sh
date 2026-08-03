#!/bin/bash

# HOM-AIMOS clean-macOS source installer.
#
# This script has no credential or runtime-policy authority. It discovers or
# provisions executable dependencies, installs the locked npm graph, and hands
# control to the native Genesis owner. Secrets remain in Keychain; mutable AIMOS
# policy remains in signed ledgers.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
MODE="install"
ASSUME_YES=0
DATABASE="aimos"
PORT="9100"
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
  if command -v brew >/dev/null 2>&1; then
    command -v brew
  elif [ -x /opt/homebrew/bin/brew ]; then
    printf '%s\n' /opt/homebrew/bin/brew
  elif [ -x /usr/local/bin/brew ]; then
    printf '%s\n' /usr/local/bin/brew
  fi
}

find_node() {
  candidate=""
  if command -v node >/dev/null 2>&1; then candidate="$(command -v node)"; fi
  if [ -n "$candidate" ]; then
    major="$("$candidate" -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || true)"
    if [ "$major" = "20" ] || [ "$major" = "24" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  fi
  if [ -n "$BREW" ] && "$BREW" --prefix node@24 >/dev/null 2>&1; then
    candidate="$("$BREW" --prefix node@24)/bin/node"
    [ -x "$candidate" ] && printf '%s\n' "$candidate"
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
  [ -n "$NODE_BIN" ] || add_missing "Node.js 20 or 24"
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
if [ -n "$BREW" ] && "$BREW" --prefix postgresql@18 >/dev/null 2>&1; then
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
  echo "Genesis will create database '$DATABASE', provision the housekeeper, ingest the Guide, and reserve port $PORT."
  printf 'Continue with native Genesis? [y/N] '
  read -r answer
  case "$answer" in y|Y|yes|YES) ;; *) echo "Cancelled."; exit 1 ;; esac
fi

cd "$ROOT"
npm ci
"$NODE_BIN" scripts/genesis-install.mjs --aimos-db "$DATABASE" --aimos-port "$PORT"

echo
echo "Installation complete. Start AIMOS with:"
printf '  %q server.js --aimos-db %q --aimos-port %q\n' "$NODE_BIN" "$DATABASE" "$PORT"
