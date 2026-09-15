# Evaluation evidence

These are kept in the repo so the numbers in the top-level README can be
checked rather than taken on trust. Every file records `llm_calls`, because the
agents fall back to heuristics when a model call fails — a run showing
`{"ok": 0}` was scored by regex, not by the LLM, and proves nothing about model
behaviour.

| File | What it shows |
|------|---------------|
| `ablation_deepseek_20260915T004445Z.json` | Headline run: four methods over all 258 golden cases, DeepSeek `deepseek-flash`, 1,016 successful model calls. Source of the 97.7% vs 89.5% comparison. |
| `eval_20260915T010639Z.json` | `historical_bgp_anomaly` at 17/20, before the triage taxonomy was fixed. All three misses are route-leak cases classified as `route_withdrawal`. |
| `eval_20260915T011639Z.json` | Same 20 cases at 19/20 after the leak/churn boundary was spelled out in the triage prompt. |
| `eval_20260915T012137Z.json` | Same 20 cases at 20/20 after `bgp_flap` was defined as requiring repeated transitions. |

The three `eval_*` files are a 20-case subset, so they do not update the
headline 97.7%: that figure comes from the full-set ablation above and has not
been re-measured since the two prompt fixes.

Regenerate locally with:

```bash
OFFLINE_MODE=true python eval_runner.py --ablation --no-ingest --workers 8   # heuristics only
EVAL_SAMPLE=258 bash scripts/run_deepseek_eval.sh                            # needs DEEPSEEK_API_KEY
```
