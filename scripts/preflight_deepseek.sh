#!/usr/bin/env bash
# One-case smoke test before spending money on the full ablation.
#
#   export DEEPSEEK_API_KEY=sk-...
#   bash scripts/preflight_deepseek.sh
#
# Costs a fraction of a cent. Read the "LLM calls" row of each scoreboard:
# single-agent must show ok=1, multi-agent ok=4. If it shows ok=0, the model
# name / key / structured-output method is wrong and every agent silently fell
# back to heuristics.
#
# The baselines intentionally exit non-zero (single-agent never passes the
# full-pipeline gate because it has no RAG and no telemetry), so the accuracy
# gate is ignored here on purpose.
set -uo pipefail
cd "$(dirname "$0")/.."
: "${DEEPSEEK_API_KEY:?Set DEEPSEEK_API_KEY first}"
export LLM_PROVIDER=deepseek
export OPENAI_API_KEY="$DEEPSEEK_API_KEY"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.deepseek.com}"
export LLM_MODEL="${LLM_MODEL:-deepseek-flash}"
export DEEPSEEK_THINKING="${DEEPSEEK_THINKING:-false}"
export LLM_STRUCTURED_METHOD="${LLM_STRUCTURED_METHOD:-function_calling}"
export OFFLINE_MODE=false
export OTEL_ENABLED=false
export ALLOW_SIMULATED_TELEMETRY=true

echo "== 1/2 single-agent: expect 'LLM calls ok=1' =="
python eval_runner.py --single-agent --limit 1 || true

echo
echo "== 2/2 multi-agent: expect 'LLM calls ok=4' =="
python eval_runner.py --limit 1 --ingest || true

echo
echo "Preflight done. If both scoreboards showed ok>0, run:"
echo "  EVAL_SAMPLE=258 bash scripts/run_deepseek_eval.sh"
