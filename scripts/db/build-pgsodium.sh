#!/usr/bin/env bash
# Deterministic pgsodium source build for the PostgreSQL server selected by
# Genesis. The source URL, version, byte count, and SHA-256 are immutable inputs
# from pgsodium-lock.json. There is no branch/HEAD fallback and no ENV authority.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCK_FILE="$SCRIPT_DIR/pgsodium-lock.json"
PG_CONFIG=""
WORKDIR=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --pg-config)
      PG_CONFIG="${2:-}"
      shift 2
      ;;
    --lock)
      LOCK_FILE="${2:-}"
      shift 2
      ;;
    --workdir)
      WORKDIR="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 64
      ;;
  esac
done

# Build flags and compiler selection are explicit below. Ambient shell build
# flags cannot alter the resulting extension.
unset CC CXX CFLAGS CXXFLAGS CPPFLAGS LDFLAGS MAKEFLAGS MFLAGS PG_CPPFLAGS SHLIB_LINK
export LC_ALL=C

[ -n "$PG_CONFIG" ] || { echo "--pg-config is required" >&2; exit 64; }
[ -x "$PG_CONFIG" ] || { echo "pg_config is not executable: $PG_CONFIG" >&2; exit 69; }
[ -f "$LOCK_FILE" ] || { echo "dependency lock not found: $LOCK_FILE" >&2; exit 66; }

command -v node >/dev/null || { echo "Node.js is required to read the dependency lock" >&2; exit 69; }
command -v curl >/dev/null || { echo "curl is required to fetch the locked source" >&2; exit 69; }
command -v make >/dev/null || { echo "make is required to build pgsodium" >&2; exit 69; }
command -v pkg-config >/dev/null || { echo "pkg-config is required to locate libsodium" >&2; exit 69; }
pkg-config --exists libsodium || { echo "libsodium development files are required" >&2; exit 69; }

PKGLIBDIR="$($PG_CONFIG --pkglibdir)"
SHAREDIR="$($PG_CONFIG --sharedir)"
if [ ! -w "$PKGLIBDIR" ] || [ ! -w "$SHAREDIR/extension" ]; then
  echo "PostgreSQL extension directories are not writable by the invoking operator" >&2
  echo "Install the locked dependency with an administrator-controlled package lane, then rerun Genesis" >&2
  exit 77
fi

lock_value() {
  node -e 'const fs=require("fs"); const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); const v=x[process.argv[2]]; if(v===undefined) process.exit(65); process.stdout.write(String(v));' "$LOCK_FILE" "$1"
}

VERSION="$(lock_value version)"
SOURCE_URL="$(lock_value source_url)"
SOURCE_BYTES="$(lock_value source_bytes)"
SOURCE_SHA256="$(lock_value source_sha256)"

case "$SOURCE_URL" in
  https://codeload.github.com/michelp/pgsodium/*) ;;
  *) echo "locked pgsodium source host/path is not approved" >&2; exit 65 ;;
esac
[[ "$SOURCE_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "locked source SHA-256 is malformed" >&2; exit 65; }
[[ "$SOURCE_BYTES" =~ ^[0-9]+$ ]] || { echo "locked source byte count is malformed" >&2; exit 65; }

cleanup=0
if [ -z "$WORKDIR" ]; then
  WORKDIR="$(mktemp -d)"
  cleanup=1
else
  mkdir -p "$WORKDIR"
fi
if [ "$cleanup" -eq 1 ]; then trap 'rm -rf "$WORKDIR"' EXIT; fi

ARCHIVE="$WORKDIR/pgsodium-v$VERSION.tar.gz"
echo "[pgsodium] fetching locked v$VERSION source"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "$SOURCE_URL" -o "$ARCHIVE"

ACTUAL_BYTES="$(wc -c < "$ARCHIVE" | tr -d ' ')"
if command -v shasum >/dev/null; then
  ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
else
  ACTUAL_SHA256="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
fi
[ "$ACTUAL_BYTES" = "$SOURCE_BYTES" ] || { echo "pgsodium source byte count mismatch" >&2; exit 65; }
[ "$ACTUAL_SHA256" = "$SOURCE_SHA256" ] || { echo "pgsodium source SHA-256 mismatch" >&2; exit 65; }

tar -xzf "$ARCHIVE" -C "$WORKDIR"
SOURCE_DIR="$WORKDIR/pgsodium-$VERSION"
[ -f "$SOURCE_DIR/Makefile" ] || { echo "locked pgsodium archive layout is invalid" >&2; exit 65; }

SODIUM_CFLAGS="$(pkg-config --cflags libsodium)"
SODIUM_LIBS="$(pkg-config --libs libsodium)"
MAKE_ARGS=("PG_CONFIG=$PG_CONFIG" "PG_CPPFLAGS=$SODIUM_CFLAGS")

if [ "$(uname -s)" = "Darwin" ]; then
  command -v xcrun >/dev/null || { echo "xcrun is required on macOS" >&2; exit 69; }
  POSTGRES_BIN="$($PG_CONFIG --bindir)/postgres"
  PG_ARCH="$(file "$POSTGRES_BIN" | grep -o 'x86_64\|arm64' | head -1)"
  [ -n "$PG_ARCH" ] || { echo "unable to determine PostgreSQL binary architecture" >&2; exit 69; }
  SDK="$(xcrun --show-sdk-path)"
  CLANG="$(xcrun --find clang)"
  MAKE_ARGS+=(
    "CC=$CLANG"
    "PG_SYSROOT=$SDK"
    "PG_CPPFLAGS=-arch $PG_ARCH $SODIUM_CFLAGS"
    "SHLIB_LINK=-arch $PG_ARCH $SODIUM_LIBS -Wl,-undefined,dynamic_lookup"
  )
else
  SYSTEM_CC="$(command -v cc)"
  [ -n "$SYSTEM_CC" ] || { echo "C compiler is required" >&2; exit 69; }
  MAKE_ARGS+=("CC=$SYSTEM_CC")
fi

echo "[pgsodium] building v$VERSION for $($PG_CONFIG --version)"
cd "$SOURCE_DIR"
make clean >/dev/null 2>&1 || true
make "${MAKE_ARGS[@]}"

STAGE="$WORKDIR/stage"
rm -rf "$STAGE"
make install "DESTDIR=$STAGE" "${MAKE_ARGS[@]}"
[ -f "$STAGE$SHAREDIR/extension/pgsodium.control" ] || {
  echo "staged pgsodium control file missing" >&2
  exit 65
}
find "$STAGE$SHAREDIR/extension" -maxdepth 1 -name 'pgsodium--*.sql' -print -quit | grep -q . || {
  echo "staged pgsodium SQL files missing" >&2
  exit 65
}
find "$STAGE$PKGLIBDIR" -maxdepth 1 \( -name 'pgsodium.so' -o -name 'pgsodium.dylib' -o -name 'pgsodium.dll' \) -print -quit | grep -q . || {
  echo "staged pgsodium library missing" >&2
  exit 65
}

# The staged set is complete before any live extension file changes. PostgreSQL
# extension installs span multiple files, so Genesis re-hashes the complete live
# set immediately afterward and refuses A2 on any partial/mismatched result.
make install "${MAKE_ARGS[@]}"

hash_file() {
  if command -v shasum >/dev/null; then shasum -a 256 "$1" | awk '{print $1}';
  else sha256sum "$1" | awk '{print $1}'; fi
}

STAGED_LIBRARY="$(find "$STAGE$PKGLIBDIR" -maxdepth 1 \( -name 'pgsodium.so' -o -name 'pgsodium.dylib' -o -name 'pgsodium.dll' \) -print -quit)"
LIVE_LIBRARY="$PKGLIBDIR/$(basename "$STAGED_LIBRARY")"
[ -f "$LIVE_LIBRARY" ] || { echo "live pgsodium library missing after install" >&2; exit 65; }
[ "$(hash_file "$STAGED_LIBRARY")" = "$(hash_file "$LIVE_LIBRARY")" ] || {
  echo "live pgsodium library differs from the verified staged artifact" >&2
  exit 65
}

STAGED_SET="$WORKDIR/staged-extension.sha256"
LIVE_SET="$WORKDIR/live-extension.sha256"
(
  cd "$STAGE$SHAREDIR/extension"
  for file in pgsodium.control pgsodium--*.sql; do
    printf '%s  %s\n' "$(hash_file "$file")" "$file"
  done | sort
) > "$STAGED_SET"
(
  cd "$SHAREDIR/extension"
  for file in pgsodium.control pgsodium--*.sql; do
    printf '%s  %s\n' "$(hash_file "$file")" "$file"
  done | sort
) > "$LIVE_SET"
cmp -s "$STAGED_SET" "$LIVE_SET" || {
  echo "live pgsodium control/SQL set differs from the verified staged set" >&2
  exit 65
}

echo "[pgsodium] installed locked v$VERSION source_sha256=$SOURCE_SHA256"
