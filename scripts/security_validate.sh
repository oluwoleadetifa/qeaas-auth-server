#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
OVERSIZED_N="${OVERSIZED_N:-2097152}"

cd "$(dirname "$0")/../benchmark_client"

cargo run --release -- security-check \
  --base-url "$BASE_URL" \
  --oversized-n "$OVERSIZED_N"
