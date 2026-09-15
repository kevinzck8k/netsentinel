#!/usr/bin/env bash
# Run the golden-case ablation against DeepSeek Chat.
#
# Usage:
#   export DEEPSEEK_API_KEY=sk-...
#   bash scripts/run_deepseek_eval.sh                 # 80-case stratified sample
#   EVAL_SAMPLE=258 bash scripts/run_deepseek_eval.sh # full set (4x the API cost)
#
# The sample is stratified per category and seeded, so the DeepSeek numbers stay
# comparable across runs. Four methods run per case, three of them LLM-backed.
#
# Runtime is dominated by ~10s DeepSeek round-trips, so cases are scored
# concurrently. Concurrency changes wall-clock only, never token cost; lower
# EVAL_WORKERS if the API starts returning rate-limit errors.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DEEPSEEK_API_KEY:?Set DEEPSEEK_API_KEY first}"
export LLM_PROVIDER=deepseek
export OPENAI_API_KEY="$DEEPSEEK_API_KEY"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.deepseek.com}"
# deepseek-chat / deepseek-v4-flash are retired aliases; V4.1 Flash is served
# as `deepseek-flash`. Thinking mode is ON by default upstream and would
# multiply output tokens, so DEEPSEEK_THINKING stays false.
export LLM_MODEL="${LLM_MODEL:-deepseek-flash}"
export DEEPSEEK_THINKING="${DEEPSEEK_THINKING:-false}"
export LLM_STRUCTURED_METHOD="${LLM_STRUCTURED_METHOD:-function_calling}"
export OFFLINE_MODE=false
export OTEL_ENABLED=false
export ALLOW_SIMULATED_TELEMETRY=true
python eval_runner.py \
  --ablation \
  --no-ingest \
  --sample "${EVAL_SAMPLE:-80}" \
  --seed "${EVAL_SEED:-7}" \
  --workers "${EVAL_WORKERS:-8}" \
  "$@"
