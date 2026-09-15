#!/usr/bin/env python3
"""
Golden-case evaluation / scoring harness for the Telco AIOps pipeline.

Reads datasets/eval/golden_cases.jsonl, runs each case through LangGraph
(or triage-only for speed), and scores predictions against expected labels.

Usage:
  python eval_runner.py
  python eval_runner.py --triage-only
  python eval_runner.py --single-agent
  python eval_runner.py --rag-only
  python eval_runner.py --ablation --ingest
  python eval_runner.py --limit 5
"""

from __future__ import annotations

import json
import logging
import random
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

import typer
from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import PROJECT_ROOT, get_settings
from observability import init_observability

app = typer.Typer(add_completion=False, no_args_is_help=False)
console = Console()
logger = logging.getLogger(__name__)

DEFAULT_GOLDEN = PROJECT_ROOT / "datasets" / "eval" / "golden_cases.jsonl"
REPORT_DIR = PROJECT_ROOT / "lab" / "eval_reports"

# Weights for each evaluation mode (each set sums to 1.0).
TRIAGE_WEIGHTS = {
    "event_type": 0.50,
    "severity": 0.25,
    "nodes": 0.25,
}
FULL_WEIGHTS = {
    "event_type": 0.25,
    "severity": 0.10,
    "nodes": 0.10,
    "rag_documents": 0.15,
    "rca_contract": 0.15,
    "rca_keywords": 0.15,
    "telemetry_evidence": 0.10,
}


# ---------------------------------------------------------------------------
# Contracts
# ---------------------------------------------------------------------------


class GoldenCase(BaseModel):
    id: str
    category: str = "unknown"
    syslog: str
    expected_event_type: str
    expected_severity: str
    expected_nodes_contains: list[str] = Field(default_factory=list)
    expected_root_cause_keywords: list[str] = Field(default_factory=list)
    notes: str = ""
    source_dataset: Optional[str] = None


class FieldScore(BaseModel):
    field: str
    expected: Any
    actual: Any
    correct: bool
    weight: float
    detail: str = ""


class CaseScore(BaseModel):
    case_id: str
    category: str
    passed: bool
    score: float = Field(ge=0.0, le=1.0)
    field_scores: list[FieldScore]
    predicted_event_type: str = ""
    predicted_severity: str = ""
    predicted_nodes: list[str] = Field(default_factory=list)
    confidence_score: Optional[float] = None
    root_cause_preview: str = ""
    error: Optional[str] = None
    elapsed_ms: float = 0.0


class EvalReport(BaseModel):
    generated_at: str
    mode: Literal["full", "triage_only", "single_agent", "rag_only", "rule_only"]
    golden_path: str
    total: int
    passed: int
    failed: int
    accuracy: float
    mean_score: float
    field_accuracy: dict[str, float]
    category_accuracy: dict[str, float]
    llm_calls: dict[str, int] = Field(default_factory=dict)
    cases: list[CaseScore]


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def score_case(
    case: GoldenCase,
    *,
    triage: dict[str, Any],
    rca: dict[str, Any] | None = None,
    rag: dict[str, Any] | None = None,
    telemetry: dict[str, Any] | None = None,
) -> CaseScore:
    """Compare predictions to golden expectations and compute weighted score."""
    full_mode = rca is not None
    weights = FULL_WEIGHTS if full_mode else TRIAGE_WEIGHTS
    pred_event = _norm(triage.get("event_type"))
    pred_sev = _norm(triage.get("severity"))
    pred_device = _norm(triage.get("device_name"))

    rca_nodes = [_norm(n) for n in (rca or {}).get("affected_nodes") or []]
    # Prefer RCA nodes; fall back to triage device
    predicted_nodes = rca_nodes or ([pred_device] if pred_device else [])

    expected_nodes = [_norm(n) for n in case.expected_nodes_contains]
    nodes_ok = all(n in predicted_nodes for n in expected_nodes) if expected_nodes else True
    if not expected_nodes:
        nodes_detail = "no expected nodes"
    elif nodes_ok:
        nodes_detail = "all expected nodes present"
    else:
        missing = [n for n in expected_nodes if n not in predicted_nodes]
        nodes_detail = f"missing={missing}"

    fields = [
        FieldScore(
            field="event_type",
            expected=case.expected_event_type,
            actual=pred_event,
            correct=pred_event == _norm(case.expected_event_type),
            weight=weights["event_type"],
        ),
        FieldScore(
            field="severity",
            expected=case.expected_severity,
            actual=pred_sev,
            correct=pred_sev == _norm(case.expected_severity),
            weight=weights["severity"],
        ),
        FieldScore(
            field="nodes",
            expected=expected_nodes,
            actual=predicted_nodes,
            correct=nodes_ok,
            weight=weights["nodes"],
            detail=nodes_detail,
        ),
    ]

    if full_mode:
        documents = (rag or {}).get("documents") or []
        root_cause = str((rca or {}).get("root_cause") or "").strip()
        remediation = (rca or {}).get("remediation_steps") or []
        rca_ok = len(root_cause) >= 10 and bool(remediation)
        blob = " ".join(
            [root_cause]
            + [str(step.get("action", "") if isinstance(step, dict) else getattr(step, "action", ""))
               for step in remediation]
        ).lower()
        keywords = [_norm(k) for k in case.expected_root_cause_keywords]
        hits = [k for k in keywords if k in blob]
        keyword_ok = (not keywords) or (len(hits) / len(keywords) >= 0.4)
        fields.extend(
            [
                FieldScore(
                    field="rag_documents",
                    expected=">=1",
                    actual=len(documents),
                    correct=len(documents) >= 1,
                    weight=weights["rag_documents"],
                    detail="RAG must contribute at least one knowledge chunk",
                ),
                FieldScore(
                    field="rca_contract",
                    expected="root_cause + remediation_steps",
                    actual={
                        "root_cause_length": len(root_cause),
                        "remediation_steps": len(remediation),
                    },
                    correct=rca_ok,
                    weight=weights["rca_contract"],
                    detail="RCA must contain a concrete cause and remediation",
                ),
                FieldScore(
                    field="rca_keywords",
                    expected=keywords,
                    actual=hits,
                    correct=keyword_ok,
                    weight=weights["rca_keywords"],
                    detail=f"keyword recall {len(hits)}/{len(keywords) or 0}",
                ),
                FieldScore(
                    field="telemetry_evidence",
                    expected="live CLI bundle",
                    actual=bool(
                        (telemetry or {}).get("commands_executed")
                        or (telemetry or {}).get("bgp_summary")
                        or (telemetry or {}).get("interface_status")
                        or (telemetry or {}).get("raw_outputs")
                    ),
                    correct=bool(
                        (telemetry or {}).get("commands_executed")
                        or (telemetry or {}).get("bgp_summary")
                        or (telemetry or {}).get("interface_status")
                        or (telemetry or {}).get("raw_outputs")
                    ),
                    weight=weights["telemetry_evidence"],
                    detail="Telemetry Agent must collect device CLI evidence",
                ),
            ]
        )

    score = round(sum(f.weight for f in fields if f.correct), 4)
    # Full-pipeline PASS requires classification, usable RAG, valid RCA, and
    # a strong composite score. Triage-only retains classification semantics.
    passed = fields[0].correct
    if full_mode:
        passed = (
            passed
            and score >= 0.85
            and next(f.correct for f in fields if f.field == "rag_documents")
            and next(f.correct for f in fields if f.field == "rca_contract")
            and next(f.correct for f in fields if f.field == "rca_keywords")
        )

    root = str((rca or {}).get("root_cause") or "")[:120]
    conf = (rca or {}).get("confidence_score")
    conf_f = float(conf) if conf is not None else None

    return CaseScore(
        case_id=case.id,
        category=case.category,
        passed=passed,
        score=score,
        field_scores=fields,
        predicted_event_type=pred_event,
        predicted_severity=pred_sev,
        predicted_nodes=predicted_nodes,
        confidence_score=conf_f,
        root_cause_preview=root,
    )


def load_golden_cases(path: Path) -> list[GoldenCase]:
    if not path.exists():
        raise FileNotFoundError(
            f"Golden cases not found: {path}\n"
            "Run: python scripts/prepare_datasets.py"
        )
    cases: list[GoldenCase] = []
    with path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                cases.append(GoldenCase.model_validate(json.loads(line)))
            except Exception as exc:  # noqa: BLE001
                raise ValueError(f"Invalid golden case at line {line_no}: {exc}") from exc
    return cases


def _portable_path(path: Path) -> str:
    """Render a path relative to the repo root.

    Reports are committed as evidence, so they must not carry the absolute
    path of whoever ran them.
    """
    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return Path(path).name


def aggregate(cases: list[CaseScore], *, mode: str, golden_path: Path) -> EvalReport:
    total = len(cases)
    passed = sum(1 for c in cases if c.passed)
    failed = total - passed
    mean_score = round(sum(c.score for c in cases) / total, 4) if total else 0.0

    field_hits: dict[str, list[bool]] = {"event_type": [], "severity": [], "nodes": []}
    cat_hits: dict[str, list[bool]] = {}
    for c in cases:
        cat_hits.setdefault(c.category, []).append(c.passed)
        for f in c.field_scores:
            field_hits.setdefault(f.field, []).append(f.correct)

    def _acc(flags: list[bool]) -> float:
        return round(sum(flags) / len(flags), 4) if flags else 0.0

    return EvalReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        mode=mode,  # type: ignore[arg-type]
        golden_path=_portable_path(golden_path),
        total=total,
        passed=passed,
        failed=failed,
        accuracy=_acc([c.passed for c in cases]),
        mean_score=mean_score,
        field_accuracy={k: _acc(v) for k, v in field_hits.items()},
        category_accuracy={k: _acc(v) for k, v in sorted(cat_hits.items())},
        cases=cases,
    )


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def run_one(
    case: GoldenCase,
    *,
    method: str,
) -> CaseScore:
    import time

    t0 = time.perf_counter()
    try:
        if method in {"rule_only", "triage_only"}:
            from baseline import run_rule_only

            state = run_rule_only(case.syslog, incident_id=case.id)
            scored = score_case(case, triage=state.get("triage") or {}, rca=None)
        elif method == "single_agent":
            from baseline import run_single_agent

            final = run_single_agent(case.syslog, incident_id=case.id)
            scored = score_case(
                case,
                triage=final.get("triage") or {},
                rca=final.get("rca_report") or {},
                rag=final.get("rag") or {},
                telemetry=final.get("telemetry") or {},
            )
        elif method == "rag_only":
            from baseline import run_rag_only

            final = run_rag_only(case.syslog, incident_id=case.id)
            scored = score_case(
                case,
                triage=final.get("triage") or {},
                rca=final.get("rca_report") or {},
                rag=final.get("rag") or {},
                telemetry=final.get("telemetry") or {},
            )
        else:
            from graph import run_incident

            final = run_incident(
                raw_syslog=case.syslog,
                incident_id=case.id,
                thread_id=f"eval-{case.id}",
            )
            scored = score_case(
                case,
                triage=final.get("triage") or {},
                rca=final.get("rca_report") or {},
                rag=final.get("rag") or {},
                telemetry=final.get("telemetry") or {},
            )
        scored.elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        return scored
    except Exception as exc:  # noqa: BLE001
        logger.exception("Case %s failed", case.id)
        return CaseScore(
            case_id=case.id,
            category=case.category,
            passed=False,
            score=0.0,
            field_scores=[],
            error=str(exc),
            elapsed_ms=round((time.perf_counter() - t0) * 1000, 1),
        )


def render_report(report: EvalReport) -> None:
    summary = Table(title="AIOps Eval Scoreboard", show_lines=False)
    summary.add_column("Metric")
    summary.add_column("Value", justify="right")
    summary.add_row("Mode", report.mode)
    summary.add_row("Total cases", str(report.total))
    pass_label = (
        "Passed (pipeline)" if report.mode == "full" else "Passed (event_type)"
    )
    summary.add_row(pass_label, f"{report.passed}/{report.total}")
    summary.add_row("Accuracy", f"{report.accuracy * 100:.1f}%")
    summary.add_row("Mean weighted score", f"{report.mean_score * 100:.1f}%")
    for field, acc in report.field_accuracy.items():
        summary.add_row(f"  · {field}", f"{acc * 100:.1f}%")
    if report.llm_calls:
        ok = report.llm_calls.get("ok", 0)
        failed = report.llm_calls.get("failed", 0)
        colour = "green" if ok else "red"
        summary.add_row(
            "LLM calls",
            f"[{colour}]ok={ok}[/] fail={failed}",
        )
    console.print(summary)

    if report.category_accuracy:
        cat = Table(title="Accuracy by Category")
        cat.add_column("Category")
        cat.add_column("Accuracy", justify="right")
        for name, acc in report.category_accuracy.items():
            cat.add_row(name, f"{acc * 100:.1f}%")
        console.print(cat)

    detail = Table(title="Per-case Results", show_lines=True)
    detail.add_column("ID", style="cyan", max_width=28)
    detail.add_column("OK")
    detail.add_column("Score", justify="right")
    detail.add_column("Expected → Actual (event)")
    detail.add_column("Sev")
    detail.add_column("Nodes")
    detail.add_column("ms", justify="right")

    for c in report.cases:
        ok = "[green]PASS[/]" if c.passed else "[red]FAIL[/]"
        if c.error:
            ok = "[red]ERR[/]"
        exp_evt = next(
            (f.expected for f in c.field_scores if f.field == "event_type"), "?"
        )
        evt_cell = f"{exp_evt} → {c.predicted_event_type or '—'}"
        sev_ok = next(
            (f.correct for f in c.field_scores if f.field == "severity"), False
        )
        nodes_ok = next(
            (f.correct for f in c.field_scores if f.field == "nodes"), False
        )
        detail.add_row(
            c.case_id,
            ok,
            f"{c.score:.2f}",
            evt_cell,
            "[green]✓[/]" if sev_ok else "[red]✗[/]",
            "[green]✓[/]" if nodes_ok else "[red]✗[/]",
            f"{c.elapsed_ms:.0f}",
        )
    console.print(detail)

    grade = _letter_grade(report.accuracy)
    console.print(
        Panel.fit(
            f"[bold]Overall: {report.accuracy * 100:.1f}%[/]  "
            f"({report.passed}/{report.total} cases passed)  "
            f"Grade [bold]{grade}[/]",
            border_style="green" if report.accuracy >= 0.8 else "yellow",
        )
    )


def _letter_grade(accuracy: float) -> str:
    if accuracy >= 0.95:
        return "A+"
    if accuracy >= 0.90:
        return "A"
    if accuracy >= 0.80:
        return "B"
    if accuracy >= 0.70:
        return "C"
    if accuracy >= 0.60:
        return "D"
    return "F"


def save_report(report: EvalReport) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = REPORT_DIR / f"eval_{ts}.json"
    path.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )
    latest = REPORT_DIR / "latest.json"
    latest.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def stratified_sample(
    cases: list[GoldenCase], size: int, seed: int = 7
) -> list[GoldenCase]:
    """Proportional sample per category — keeps paid LLM runs affordable."""
    if size >= len(cases):
        return cases
    buckets: dict[str, list[GoldenCase]] = {}
    for case in cases:
        buckets.setdefault(case.category, []).append(case)

    rng = random.Random(seed)
    picked: list[GoldenCase] = []
    for category, bucket in sorted(buckets.items()):
        quota = max(1, round(size * len(bucket) / len(cases)))
        shuffled = bucket[:]
        rng.shuffle(shuffled)
        picked.extend(shuffled[:quota])

    rng.shuffle(picked)
    picked = picked[:size]
    order = {case.id: i for i, case in enumerate(cases)}
    return sorted(picked, key=lambda c: order[c.id])


def _score_cases(
    cases: list[GoldenCase],
    *,
    method: str,
    workers: int,
) -> list[CaseScore]:
    """Score every case, optionally on a thread pool.

    Each case is independent and the run is dominated by LLM latency (~10s per
    call), so a small pool turns a multi-hour paid run into minutes. Results
    are re-ordered to match the input so reports stay diffable across runs.
    """
    total = len(cases)

    def label(scored: CaseScore) -> str:
        mark = "PASS" if scored.passed else ("ERR" if scored.error else "FAIL")
        color = "green" if scored.passed else "red"
        return f"[{color}]{mark}[/{color}] score={scored.score:.2f}"

    if workers <= 1:
        results: list[CaseScore] = []
        for i, case in enumerate(cases, 1):
            console.print(f"  [{i}/{total}] {case.id} …", end=" ")
            scored = run_one(case, method=method)
            console.print(label(scored))
            results.append(scored)
        return results

    # Warm the lazily-built SOP index on the main thread so worker threads
    # never race to initialize it.
    if method not in {"rule_only", "triage_only"}:
        from vector_rag import get_rag_store

        get_rag_store().retrieve("bgp session down", top_k=1)

    ordered: list[Optional[CaseScore]] = [None] * total
    done = 0
    print_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(run_one, case, method=method): idx
            for idx, case in enumerate(cases)
        }
        for future in as_completed(futures):
            idx = futures[future]
            scored = future.result()
            ordered[idx] = scored
            with print_lock:
                done += 1
                console.print(
                    f"  [{done}/{total}] {cases[idx].id} … {label(scored)}"
                )

    return [scored for scored in ordered if scored is not None]


def run_evaluation(
    *,
    golden: Path = DEFAULT_GOLDEN,
    method: str = "multi_agent",
    limit: Optional[int] = None,
    category: Optional[str] = None,
    ingest: bool = False,
    persist: bool = True,
    sample: Optional[int] = None,
    seed: int = 7,
    workers: int = 1,
) -> EvalReport:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    init_observability()

    if ingest and method not in {"rule_only", "triage_only"}:
        try:
            from vector_rag import get_rag_store

            n = get_rag_store().ingest_directory()
            console.print(f"[dim]SOP ingest: {n} chunks[/]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]SOP ingest skipped:[/] {exc}")

    cases = load_golden_cases(golden)
    if category:
        cases = [c for c in cases if c.category == category]
    if limit is not None:
        cases = cases[:limit]
    if sample is not None:
        cases = stratified_sample(cases, sample, seed=seed)

    if not cases:
        raise RuntimeError("No golden cases to evaluate")

    mode_map = {
        "rule_only": "rule_only",
        "triage_only": "triage_only",
        "single_agent": "single_agent",
        "rag_only": "rag_only",
        "multi_agent": "full",
    }
    mode = mode_map.get(method, "full")
    console.print(
        f"[bold]Evaluating[/] {len(cases)} cases "
        f"(method={method}, offline={settings.is_offline()}, workers={workers})"
    )

    from agents import llm_call_stats, reset_llm_call_stats

    reset_llm_call_stats()
    results = _score_cases(cases, method=method, workers=workers)

    report = aggregate(
        results,
        mode=mode,
        golden_path=golden,
    )
    report.llm_calls = llm_call_stats()
    if method != "rule_only" and not settings.is_offline():
        if report.llm_calls.get("ok", 0) == 0:
            console.print(
                f"[bold red]WARNING[/] method={method} made 0 successful LLM "
                f"calls ({report.llm_calls.get('failed', 0)} failed) — these "
                "numbers come from the heuristic fallback, not the model."
            )
    render_report(report)
    if persist:
        path = save_report(report)
        console.print(f"[dim]Report saved → {path}[/]")
    return report


def _summarize(report: EvalReport) -> dict[str, Any]:
    return {
        "accuracy": report.accuracy,
        "mean_score": report.mean_score,
        "passed": report.passed,
        "total": report.total,
        "field_accuracy": report.field_accuracy,
        "category_accuracy": report.category_accuracy,
        "llm_calls": report.llm_calls,
        "mean_latency_ms": round(
            sum(c.elapsed_ms for c in report.cases) / max(len(report.cases), 1),
            1,
        ),
        # Keep the misses addressable: a paid ablation run is expensive to
        # repeat just to learn which cases regressed.
        "failed_cases": [
            {
                "case_id": c.case_id,
                "category": c.category,
                "score": round(c.score, 3),
                "error": c.error,
                "wrong_fields": [
                    {
                        "field": f.field,
                        "expected": f.expected,
                        "actual": f.actual,
                    }
                    for f in c.field_scores
                    if not f.correct
                ],
            }
            for c in report.cases
            if not c.passed
        ],
    }


def run_ablation(
    *,
    golden: Path = DEFAULT_GOLDEN,
    limit: Optional[int] = None,
    category: Optional[str] = None,
    ingest: bool = False,
    sample: Optional[int] = None,
    seed: int = 7,
    workers: int = 1,
) -> dict[str, Any]:
    """Compare literature-style baselines vs Multi-Agent on the same golden set."""
    settings = get_settings()
    methods = ("rule_only", "single_agent", "rag_only", "multi_agent")
    reports: dict[str, EvalReport] = {}
    for i, method in enumerate(methods):
        reports[method] = run_evaluation(
            golden=golden,
            method=method,
            limit=limit,
            category=category,
            ingest=ingest if method in {"rag_only", "multi_agent"} and i == 2 else False,
            persist=False,
            sample=sample,
            seed=seed,
            workers=workers,
        )

    comparison = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "literature": {
            "rule_only": "Drain/regex taxonomy (Loghub-style classical baseline)",
            "single_agent": "CoT syslog→RCA, no tools (Flow-of-Action CoT control)",
            "rag_only": "syslog + SOP RAG, no CLI (TeleOps LLM-RAG)",
            "multi_agent": "Triage + event-aware CLI + hybrid RAG + RCA",
        },
        "rule_only": _summarize(reports["rule_only"]),
        "single_agent": _summarize(reports["single_agent"]),
        "rag_only": _summarize(reports["rag_only"]),
        "multi_agent": _summarize(reports["multi_agent"]),
        "delta_vs_rag_only": {
            "accuracy": round(
                reports["multi_agent"].accuracy - reports["rag_only"].accuracy, 4
            ),
            "mean_score": round(
                reports["multi_agent"].mean_score - reports["rag_only"].mean_score, 4
            ),
        },
        "delta_vs_single_agent": {
            "accuracy": round(
                reports["multi_agent"].accuracy - reports["single_agent"].accuracy, 4
            ),
            "mean_score": round(
                reports["multi_agent"].mean_score - reports["single_agent"].mean_score, 4
            ),
        },
    }
    comparison["provenance"] = {
        "model": settings.resolved_llm_model(),
        "offline": settings.is_offline(),
        "structured_method": settings.llm_structured_method,
        "workers": workers,
        "sample": sample,
        "seed": seed,
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(comparison, indent=2, ensure_ascii=False)
    # Also keep an immutable timestamped copy: a cheap offline regression run
    # must never silently destroy the results of a paid provider run.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tag = "offline" if settings.is_offline() else settings.llm_provider.lower()
    archive = REPORT_DIR / f"ablation_{tag}_{stamp}.json"
    archive.write_text(payload, encoding="utf-8")
    path = REPORT_DIR / "ablation_latest.json"
    path.write_text(payload, encoding="utf-8")
    console.print(f"[dim]Ablation archived → {archive.name}[/]")

    def _line(name: str) -> str:
        block = comparison[name]
        label = "classif" if name == "rule_only" else "pass"
        if name == "rule_only":
            note = "  [classification only]"
        else:
            calls = block.get("llm_calls") or {}
            note = f"  llm ok={calls.get('ok', 0)} fail={calls.get('failed', 0)}"
        return (
            f"{name:14} {label} {block['passed']}/{block['total']} "
            f"({block['accuracy']*100:5.1f}%)  score {block['mean_score']*100:5.1f}%"
            f"{note}"
        )

    console.print(
        Panel.fit(
            "\n".join(_line(m) for m in methods),
            title="Ablation — literature baselines vs Multi-Agent",
            border_style="cyan",
        )
    )
    console.print(f"[dim]Ablation saved → {path}[/]")
    return comparison


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    golden: Path = typer.Option(DEFAULT_GOLDEN, "--golden", "-g"),
    triage_only: bool = typer.Option(
        False,
        "--triage-only",
        help="Score the regex/rule classifier only",
    ),
    limit: Optional[int] = typer.Option(None, "--limit", "-n"),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter e.g. synthetic_telco"
    ),
    ingest: bool = typer.Option(False, "--ingest/--no-ingest"),
    single_agent: bool = typer.Option(
        False,
        "--single-agent",
        help="CoT baseline: diagnose from syslog only, no tools / RAG",
    ),
    rag_only: bool = typer.Option(
        False,
        "--rag-only",
        help="TeleOps baseline: syslog + SOP retrieval, no live CLI",
    ),
    ablation: bool = typer.Option(
        False,
        "--ablation",
        help="Run rule / single-agent / RAG-only / Multi-Agent comparison",
    ),
    sample: Optional[int] = typer.Option(
        None,
        "--sample",
        help="Stratified sample of N cases (bounds paid LLM runs)",
    ),
    seed: int = typer.Option(7, "--seed", help="Sampling seed"),
    workers: int = typer.Option(
        1,
        "--workers",
        "-w",
        min=1,
        max=32,
        help="Score cases concurrently; LLM-bound runs scale near-linearly",
    ),
) -> None:
    """Run the golden-case scoreboard."""
    if ctx.invoked_subcommand is not None:
        return
    if ablation:
        compare = run_ablation(
            golden=golden,
            limit=limit,
            category=category,
            ingest=ingest,
            sample=sample,
            seed=seed,
            workers=workers,
        )
        if compare["multi_agent"]["accuracy"] < 0.70:
            raise typer.Exit(code=1)
        return
    method = "multi_agent"
    if triage_only:
        method = "rule_only"
    elif single_agent:
        method = "single_agent"
    elif rag_only:
        method = "rag_only"
    report = run_evaluation(
        golden=golden,
        method=method,
        limit=limit,
        category=category,
        ingest=ingest,
        sample=sample,
        seed=seed,
        workers=workers,
    )
    # Non-zero exit when accuracy below 70% — useful for CI
    if report.accuracy < 0.70:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
