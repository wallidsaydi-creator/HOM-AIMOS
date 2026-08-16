#!/usr/bin/env bash
# Fetch the two canonical utility-benchmark datasets without redistributing
# their bytes in the AIMOS source repository. Upstream revisions and downloaded
# bytes are both pinned so a later upstream edit cannot silently change a run.

set -euo pipefail

DATA_DIR="$(cd "$(dirname "$0")" && pwd)"
LME_REVISION="98d7416c24c778c2fee6e6f3006e7a073259d48f"
LME_SHA256="821a2034d219ab45846873dd14c14f12cfe7776e73527a483f9dac095d38620c"
LME_FILE="official-longmemeval-oracle.json"
LME_URL="https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned/resolve/${LME_REVISION}/longmemeval_oracle.json"

LME_S_SHA256="d6f21ea9d60a0d56f34a05b609c79c88a451d2ae03597821ea3d5a9678c3a442"
LME_S_FILE="longmemeval_s_cleaned.json"
LME_S_URL="https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned/resolve/${LME_REVISION}/longmemeval_s_cleaned.json"

LOCOMO_REVISION="3eb6f2c585f5e1699204e3c3bdf7adc5c28cb376"
LOCOMO_SHA256="79fa87e90f04081343b8c8debecb80a9a6842b76a7aa537dc9fdf651ea698ff4"
LOCOMO_FILE="official-locomo10.json"
LOCOMO_URL="https://raw.githubusercontent.com/snap-research/locomo/${LOCOMO_REVISION}/data/locomo10.json"

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

fetch_verified() {
  local name="$1"
  local url="$2"
  local expected="$3"
  local target="${DATA_DIR}/${name}"
  local temporary="${target}.download"

  if [[ -f "$target" ]] && [[ "$(sha256_file "$target")" == "$expected" ]]; then
    printf 'verified existing %s\n' "$name"
    return
  fi

  rm -f "$temporary"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
    --output "$temporary" "$url"
  local actual
  actual="$(sha256_file "$temporary")"
  if [[ "$actual" != "$expected" ]]; then
    rm -f "$temporary"
    printf 'checksum mismatch for %s: expected %s, received %s\n' \
      "$name" "$expected" "$actual" >&2
    exit 1
  fi
  mv "$temporary" "$target"
  printf 'downloaded and verified %s\n' "$name"
}

printf '%s\n' 'AIMOS canonical benchmark dataset fetch'
printf 'LongMemEval revision: %s\n' "$LME_REVISION"
printf 'LoCoMo revision:      %s\n' "$LOCOMO_REVISION"

fetch_verified "$LME_FILE" "$LME_URL" "$LME_SHA256"
fetch_verified "$LME_S_FILE" "$LME_S_URL" "$LME_S_SHA256"
fetch_verified "$LOCOMO_FILE" "$LOCOMO_URL" "$LOCOMO_SHA256"

printf '%s\n' 'Dataset licenses remain upstream and apply to downloaded bytes:'
printf '%s\n' '  LongMemEval: https://github.com/xiaowu0162/LongMemEval/blob/main/LICENSE'
printf '%s\n' '  LoCoMo:      https://github.com/snap-research/locomo/blob/main/LICENSE.txt (CC BY-NC 4.0)'
