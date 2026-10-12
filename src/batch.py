"""Batch triage runner: triage every .eml in a folder through the pipeline.

Reuses the existing LangGraph pipeline (`src.graph.run`) unchanged — no graph
construction is duplicated here. Each email is processed independently and
defensively: a single failing email is logged, recorded with verdict="error",
and never aborts the batch.

Results are written to a timestamped CSV under results/ and a summary is
pretty-printed to stdout.
"""

import argparse
import csv
import logging
import os
import statistics
import sys
import time
from datetime import datetime
from glob import glob

from src.agents.headers import deterministic_risk_floor, parse_email
from src.legacy_graph import run

logger = logging.getLogger(__name__)

CSV_FIELDS = [
    "filename",
    "risk_score",
    "floor",
    "verdict",
    "conflict",
    "latency_sec",
    "cost_usd",
    "summary",
]

# Aggregate schema for --repeat N runs (one row per email).
REPEAT_CSV_FIELDS = [
    "filename",
    "runs",
    "score_min",
    "score_max",
    "score_mean",
    "score_stdev",
    "label_stable",
    "labels",
]

CONFLICT_TAG = "[CONFLICT]"
_SUMMARY_MAX = 160


def find_eml_files(folder):
    """Return the .eml files in `folder`, sorted for deterministic ordering."""
    return sorted(glob(os.path.join(folder, "*.eml")))


def summarize_explanation(text):
    """Collapse an explanation to a single trimmed line for the CSV/summary.

    Drops a leading [CONFLICT] tag (it has its own column) and truncates.
    """
    if not text:
        return ""
    flat = " ".join(str(text).split())
    if flat.startswith(CONFLICT_TAG):
        flat = flat[len(CONFLICT_TAG):].strip()
    if len(flat) > _SUMMARY_MAX:
        flat = flat[: _SUMMARY_MAX - 1].rstrip() + "…"
    return flat


def _floor_only(raw_email):
    """Best-effort deterministic floor without the LLM (pure Python).

    Used on the error path so an LLM outage still yields the header-derived
    risk floor. Returns "" if even parsing fails.
    """
    try:
        state = parse_email({"raw_email": raw_email})
        return deterministic_risk_floor(state["parsed_headers"])[0]
    except Exception:  # pragma: no cover - defensive only
        return ""


def process_email(path):
    """Triage one .eml file, returning a CSV row dict. Never raises."""
    filename = os.path.basename(path)
    start = time.perf_counter()
    raw_email = None
    try:
        with open(path, encoding="utf-8") as f:
            raw_email = f.read()
        state = run(raw_email)
        latency = time.perf_counter() - start
        explanation = state.get("explanation", "")
        return {
            "filename": filename,
            "risk_score": state.get("risk_score", ""),
            "floor": state.get("risk_floor", ""),
            "verdict": state.get("verdict", "error"),
            "conflict": CONFLICT_TAG in str(explanation),
            "latency_sec": round(latency, 3),
            "cost_usd": state.get("total_cost_usd", ""),
            "summary": summarize_explanation(explanation),
        }
    except Exception as exc:
        latency = time.perf_counter() - start
        logger.error("batch: failed to triage %s: %s", filename, exc)
        return {
            "filename": filename,
            "risk_score": "",
            # Still record the deterministic floor if we managed to read the file.
            "floor": _floor_only(raw_email) if raw_email is not None else "",
            "verdict": "error",
            "conflict": False,
            "latency_sec": round(latency, 3),
            "cost_usd": "",
            "summary": f"ERROR: {exc}",
        }


def write_csv(rows, results_dir="results"):
    """Write rows to a timestamped CSV under results_dir; return its path."""
    os.makedirs(results_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(results_dir, f"batch_{stamp}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def summarize(rows):
    """Pure aggregation of rows -> counts and error list (for testability)."""
    counts = {"benign": 0, "spam": 0, "suspicious": 0, "malicious": 0, "error": 0}
    for row in rows:
        verdict = row.get("verdict", "error")
        counts[verdict] = counts.get(verdict, 0) + 1
    conflicts = sum(1 for row in rows if row.get("conflict"))
    errors = [row["filename"] for row in rows if row.get("verdict") == "error"]
    total_cost = sum(
        row["cost_usd"] for row in rows if isinstance(row.get("cost_usd"), (int, float))
    )
    return {
        "counts": counts,
        "conflicts": conflicts,
        "errors": errors,
        "total_cost_usd": round(total_cost, 6),
    }


def run_batch(folder, results_dir="results", progress=True):
    """Triage every .eml in `folder`; write a CSV and return (rows, path, secs)."""
    files = find_eml_files(folder)
    rows = []
    batch_start = time.perf_counter()
    for i, path in enumerate(files, 1):
        row = process_email(path)
        rows.append(row)
        if progress:
            print(
                f"[{i}/{len(files)}] {row['filename']} → "
                f"{row['verdict']} (score={row['risk_score']}, "
                f"floor={row['floor']}, {row['latency_sec']}s)"
            )
    elapsed = time.perf_counter() - batch_start
    csv_path = write_csv(rows, results_dir)
    return rows, csv_path, elapsed


def print_summary(rows, csv_path, elapsed):
    """Pretty-print the per-email table and aggregate summary to stdout."""
    # Per-email table.
    header = (
        f"{'FILE':<28} {'FLOOR':>5} {'SCORE':>5} {'VERDICT':<11} "
        f"{'CONFLICT':<8} {'LAT(s)':>7} {'COST($)':>9}"
    )
    print("\n" + header)
    print("-" * len(header))
    for row in rows:
        cost = row["cost_usd"]
        cost_str = f"{cost:.6f}" if isinstance(cost, (int, float)) else str(cost)
        print(
            f"{row['filename']:<28} {str(row['floor']):>5} {str(row['risk_score']):>5} "
            f"{row['verdict']:<11} {str(row['conflict']):<8} {str(row['latency_sec']):>7} "
            f"{cost_str:>9}"
        )

    agg = summarize(rows)
    counts = agg["counts"]
    print("\nSummary")
    print("-------")
    print(f"  total emails : {len(rows)}")
    print(
        f"  by verdict   : malicious={counts['malicious']} "
        f"suspicious={counts['suspicious']} spam={counts['spam']} "
        f"benign={counts['benign']} error={counts['error']}"
    )
    print(f"  conflicts    : {agg['conflicts']}")
    if agg["errors"]:
        print(f"  errored files: {', '.join(agg['errors'])}")
    print(f"  total cost   : ${agg['total_cost_usd']:.6f}")
    print(f"  total runtime: {elapsed:.2f}s")
    print(f"  results CSV  : {csv_path}")


# --- repeat / stability mode ------------------------------------------------


def aggregate_runs(filename, run_rows):
    """Collapse N single-run rows for one email into a stability row.

    Score stats are computed over numeric scores only (error runs, which carry
    a blank score, are excluded from the stats but still count toward label
    stability). `label_stable` is True iff every run produced the same verdict
    label; `labels` lists the distinct labels seen, sorted and `|`-joined.
    """
    scores = [r["risk_score"] for r in run_rows if isinstance(r["risk_score"], (int, float))]
    verdicts = [r["verdict"] for r in run_rows]
    costs = [r["cost_usd"] for r in run_rows if isinstance(r["cost_usd"], (int, float))]
    distinct_labels = sorted(set(verdicts))
    error_runs = sum(1 for v in verdicts if v == "error")

    if scores:
        score_min = min(scores)
        score_max = max(scores)
        score_mean = round(statistics.mean(scores), 2)
        score_stdev = round(statistics.stdev(scores), 2) if len(scores) >= 2 else 0.0
    else:
        score_min = score_max = score_mean = score_stdev = ""

    # A label is "stable" only if every run produced the SAME real label. An
    # "error" run never produced a label, so any error — including an all-error
    # email — makes the label NOT stable. Otherwise a total LLM/provider outage
    # would masquerade as a perfectly stable, all-clear run.
    label_stable = len(distinct_labels) == 1 and error_runs == 0

    return {
        "filename": filename,
        "runs": len(run_rows),
        "score_min": score_min,
        "score_max": score_max,
        "score_mean": score_mean,
        "score_stdev": score_stdev,
        "label_stable": label_stable,
        "labels": "|".join(distinct_labels),
        # Internal, not part of REPEAT_CSV_FIELDS.
        "_cost_usd": round(sum(costs), 6),
        "_error_runs": error_runs,
    }


def run_batch_repeated(folder, results_dir="results", repeat=3, progress=True):
    """Run each .eml `repeat` times; return (agg_rows, csv_path, elapsed)."""
    files = find_eml_files(folder)
    agg_rows = []
    batch_start = time.perf_counter()
    for i, path in enumerate(files, 1):
        filename = os.path.basename(path)
        run_rows = []
        for k in range(1, repeat + 1):
            row = process_email(path)
            run_rows.append(row)
            if progress:
                print(
                    f"[{i}/{len(files)} run {k}/{repeat}] {filename} → "
                    f"{row['verdict']} (score={row['risk_score']})"
                )
        agg_rows.append(aggregate_runs(filename, run_rows))
    elapsed = time.perf_counter() - batch_start
    csv_path = write_repeat_csv(agg_rows, results_dir)
    return agg_rows, csv_path, elapsed


def write_repeat_csv(agg_rows, results_dir="results"):
    """Write stability rows to a timestamped CSV; return its path."""
    os.makedirs(results_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(results_dir, f"batch_repeat_{stamp}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        # extrasaction="ignore" drops the internal _cost_usd key.
        writer = csv.DictWriter(f, fieldnames=REPEAT_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(agg_rows)
    return path


def summarize_repeat(agg_rows):
    """Corpus-level stability summary: unstable-label count and which files."""
    unstable = [r["filename"] for r in agg_rows if not r["label_stable"]]
    total_runs = sum(r["runs"] for r in agg_rows)
    total_cost = round(sum(r.get("_cost_usd", 0.0) or 0.0 for r in agg_rows), 6)
    error_runs = sum(r.get("_error_runs", 0) for r in agg_rows)
    return {
        "total": len(agg_rows),
        "unstable_count": len(unstable),
        "unstable_files": unstable,
        "total_runs": total_runs,
        "error_runs": error_runs,
        "total_cost_usd": total_cost,
    }


def print_repeat_summary(agg_rows, csv_path, elapsed, repeat):
    """Pretty-print the per-email stability table and corpus summary."""
    header = (
        f"{'FILE':<28} {'RUNS':>4} {'MIN':>4} {'MAX':>4} {'MEAN':>6} "
        f"{'STDEV':>6} {'STABLE':<7} {'LABELS'}"
    )
    print("\n" + header)
    print("-" * (len(header) + 8))
    for row in agg_rows:
        print(
            f"{row['filename']:<28} {row['runs']:>4} {str(row['score_min']):>4} "
            f"{str(row['score_max']):>4} {str(row['score_mean']):>6} "
            f"{str(row['score_stdev']):>6} {str(row['label_stable']):<7} {row['labels']}"
        )

    agg = summarize_repeat(agg_rows)
    print("\nStability summary")
    print("-----------------")
    print(f"  repeats/email : {repeat}")
    print(f"  total emails  : {agg['total']}")
    print(f"  total runs    : {agg['total_runs']}")
    print(
        f"  unstable labels: {agg['unstable_count']}"
        + (f" ({', '.join(agg['unstable_files'])})" if agg["unstable_files"] else "")
    )
    if agg["error_runs"]:
        print(f"  error runs    : {agg['error_runs']} (counted as unstable)")
    print(f"  total cost    : ${agg['total_cost_usd']:.6f}")
    print(f"  total runtime : {elapsed:.2f}s")
    print(f"  results CSV   : {csv_path}")


def main(argv=None):
    argv = sys.argv if argv is None else argv
    parser = argparse.ArgumentParser(
        prog="run_batch.py",
        description="Batch-triage every .eml in a folder through the pipeline.",
    )
    parser.add_argument("folder", help="folder containing .eml files")
    parser.add_argument(
        "--repeat",
        "-n",
        type=int,
        default=1,
        metavar="N",
        help="run each email N times and report score/label stability (default 1)",
    )
    args = parser.parse_args(argv[1:])

    if args.repeat < 1:
        print("error: --repeat must be >= 1", file=sys.stderr)
        return 2
    if not os.path.isdir(args.folder):
        print(f"error: not a directory: {args.folder}", file=sys.stderr)
        return 2
    if not find_eml_files(args.folder):
        print(f"no .eml files found in {args.folder}", file=sys.stderr)
        return 0

    if args.repeat == 1:
        rows, csv_path, elapsed = run_batch(args.folder)
        print_summary(rows, csv_path, elapsed)
    else:
        agg_rows, csv_path, elapsed = run_batch_repeated(args.folder, repeat=args.repeat)
        print_repeat_summary(agg_rows, csv_path, elapsed, args.repeat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
