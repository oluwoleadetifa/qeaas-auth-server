#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
USERS_FILE="${USERS_FILE:-users.jsonl}"
ENTROPY_MODE="${ENTROPY_MODE:-direct_qrng}"
PAYLOADS="${PAYLOADS:-32,256,1024,4096}"
CONCURRENCY_LEVELS="${CONCURRENCY_LEVELS:-1,5,10,25}"
DURATION="${DURATION:-30}"
OUT_CSV="${OUT_CSV:-results/qeaas_matrix.csv}"
OUT_JSONL="${OUT_JSONL:-results/qeaas_matrix.jsonl}"
LABEL="${LABEL:-matrix}"

mkdir -p "$(dirname "$OUT_CSV")" "$(dirname "$OUT_JSONL")"

cd "$(dirname "$0")/../benchmark_client"

cargo run --release -- matrix \
  --base-url "$BASE_URL" \
  --entropy-mode "$ENTROPY_MODE" \
  --users "../$USERS_FILE" \
  --payloads "$PAYLOADS" \
  --concurrency-levels "$CONCURRENCY_LEVELS" \
  --duration "$DURATION" \
  --csv-out "../$OUT_CSV" \
  --jsonl-out "../$OUT_JSONL" \
  --label "$LABEL"
