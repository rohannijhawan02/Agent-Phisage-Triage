"""Local analyst CLI. `python triage.py --help` lists all workflows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

from src.pipeline import analyze
from src.training import compare, evaluate, evaluate_legacy, fit, read_jsonl, write_jsonl


def _json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def _inputs(path):
    path = Path(path)
    if path.is_file() and path.suffix.lower() == ".eml":
        return [path]
    if path.is_dir():
        return sorted(item for item in path.rglob("*.eml") if item.is_file())
    raise ValueError("input must be a .eml file or a folder containing .eml files")


def _scan_options(args):
    return {"model": args.llm_model,
            "auth_attestations": _json(args.auth_attestations) if args.auth_attestations else None,
            "protected_domains": set(args.protected_domain or []),
            "intel_file": args.intel_file, "memory_file": args.memory_file}


def _add_scan_options(parser):
    parser.add_argument("--llm-model", help="Hosted model identifier (or set TRIAGE_MODEL); omission produces review-only output")
    parser.add_argument("--auth-attestations", help="JSON sidecar with receiver-authenticated results keyed by email SHA-256")
    parser.add_argument("--protected-domain", action="append", default=[],
                        help="Domain to check for close lookalikes; repeatable")
    parser.add_argument("--intel-file", help="Read-only local JSON reputation snapshot")
    parser.add_argument("--memory-file", help="Read-only JSONL of analyst-confirmed cases")


def _cmd_analyze(args):
    artifact = _json(args.model_file) if args.model_file else None
    if args.repeat < 1:
        raise ValueError("--repeat must be at least 1")
    options = _scan_options(args)
    rows = []
    stability = []
    for path in _inputs(args.input):
        runs = []
        for number in range(1, args.repeat + 1):
            try:
                row = analyze(path, artifact=artifact, **options)
            except Exception as exc:
                row = {"file": str(path.resolve()), "verdict": "error", "error": f"{type(exc).__name__}: {exc}",
                       "risk_score": None, "explanation": "Analysis failed before a verdict could be produced.",
                       "phishing_probability_0_100": None, "threat_flags": {}, "findings": [],
                       "review_reasons": ["analysis_failed"], "cost_usd": 0, "elapsed_seconds": 0}
                row["report_markdown"] = ("# Email triage processing error\n\n"
                                          f"- Source: {path.resolve()}\n"
                                          f"- Error: {row['error']}\n\n"
                                          "No security verdict or risk score was produced.\n")
            row["run_number"] = number
            runs.append(row)
            rows.append(row)
        scores = [row["phishing_probability_0_100"] for row in runs if row["phishing_probability_0_100"] is not None]
        stability.append({"file": str(path.resolve()), "runs": len(runs),
                          "labels": sorted({row["verdict"] for row in runs}),
                          "label_stable": len({row["verdict"] for row in runs}) == 1 and all(row["verdict"] != "error" for row in runs),
                          "probability_min": min(scores) if scores else None,
                          "probability_max": max(scores) if scores else None})
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    reports = output / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    for row in rows:
        if row.get("report_markdown"):
            report_key = row.get("sha256") or hashlib.sha256(row["file"].encode("utf-8")).hexdigest()
            report_path = reports / f"{report_key}-run{row['run_number']}.md"
            report_path.write_text(row["report_markdown"], encoding="utf-8")
            row["report_file"] = str(report_path.resolve())
    write_jsonl(output / "results.jsonl", rows)
    if args.repeat > 1:
        _save(output / "stability.json", stability)
    fields = ("file", "risk_score", "verdict", "explanation", "probability_scope", "report_file", "review_reasons",
              "tokens", "cost_usd", "elapsed_seconds")
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: " | ".join(row.get(key, [])) if key == "review_reasons" else row.get(key)
                             for key in fields})
    print(json.dumps({"processed": len(stability), "runs": len(rows),
                      "errors": sum(row["verdict"] == "error" for row in rows),
                      "jsonl": str(output / "results.jsonl"), "csv": str(output / "summary.csv"),
                      "reports": str(reports)}, indent=2))
    return 1 if any(row["verdict"] == "error" for row in rows) else 0


def _cmd_prepare(args):
    manifest_path = Path(args.manifest).resolve()
    manifest = _json(manifest_path)
    if not manifest.get("dataset_name") or not manifest.get("dataset_version"):
        raise ValueError("manifest needs dataset_name and dataset_version")
    if not isinstance(manifest.get("emails"), list):
        raise ValueError("manifest needs emails array")
    rows = []
    options = _scan_options(args)
    for entry in manifest["emails"]:
        path = (manifest_path.parent / entry["path"]).resolve()
        if options["memory_file"] and not entry.get("date"):
            raise ValueError("manifest entries need a date when case memory is enabled")
        result = analyze(path, as_of=entry.get("date"), **options)
        rows.append({"sha256": result["sha256"], "path": str(path), "label": entry["label"],
                     "content_fingerprint": result["content_fingerprint"],
                     "dataset_name": manifest["dataset_name"], "dataset_version": manifest["dataset_version"],
                     "split": entry["split"], "source": entry["source"], "date": entry.get("date"),
                     "group": entry["group"], "slices": entry.get("slices", []),
                     "mime_complete": not any("truncated" in name or "body_missing" in name for name in result["unknown_signals"]),
                     "iocs": result["iocs"],
                     "features": result["features"], "model_version": result["model_version"],
                     "backend_identity": result["backend_identity"],
                     "baseline_verdict": result["baseline_verdict"],
                     "unknown_signals": result["unknown_signals"],
                     "proposed_verdict": result["rubric"]["proposed_verdict"],
                     "signal_config": result["signal_config"], "feature_version": result["feature_version"],
                     "rubric_version": result["rubric_version"], "rubric_prompt_hash": result["rubric_prompt_hash"],
                     "rubric_invalid_reasons": (result["rubric"]["invalid_reasons"] +
                                                [reason for agent in result["agents"].values()
                                                 for reason in agent["invalid_reasons"]] +
                                                [reason for turn in result["debate"]
                                                 for reason in turn["invalid_reasons"]]),
                     "cost_usd": result["cost_usd"], "elapsed_seconds": result["elapsed_seconds"]})
    write_jsonl(args.output, rows)
    print(f"Wrote {len(rows)} labeled feature records to {args.output}")
    return 0


def _cmd_fit(args):
    artifact = fit(read_jsonl(args.features), args.dataset_name, args.dataset_version)
    _save(args.output, artifact)
    report = evaluate(read_jsonl(args.features), artifact)
    _save(args.report, report)
    print(json.dumps({"artifact": args.output, "report": args.report,
                      "threshold_status": artifact["thresholds"]["status"]}, indent=2))
    return 0


def _cmd_evaluate(args):
    _save(args.output, evaluate(read_jsonl(args.features), _json(args.model_file)))
    print(f"Wrote evaluation to {args.output}")
    return 0


def _cmd_evaluate_legacy(args):
    _save(args.output, evaluate_legacy(read_jsonl(args.features)))
    print(f"Wrote upstream comparison to {args.output}")
    return 0


def _cmd_compare(args):
    report = compare(read_jsonl(args.incumbent_features), read_jsonl(args.candidate_features),
                     _json(args.incumbent_model), _json(args.candidate_model))
    _save(args.output, report)
    print(json.dumps({"promote": report["promote"], "checks": report["checks"],
                      "score_crossings": report["decision_threshold_crossings"]}, indent=2))
    return 0 if report["promote"] else 2


def _cmd_feedback(args):
    if args.verdict not in {"benign", "spam", "suspicious", "malicious", "needs_review"}:
        raise ValueError("invalid corrected verdict")
    row = {"sha256": args.sha256, "corrected_verdict": args.verdict, "analyst": args.analyst,
           "reason": args.reason}
    with Path(args.output).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline MIME extraction and evidence-backed email triage")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze_parser = sub.add_parser("analyze", help="Analyze an .eml file or folder")
    analyze_parser.add_argument("input")
    analyze_parser.add_argument("--output", default="results")
    analyze_parser.add_argument("--model-file", help="Calibrated model JSON from fit")
    analyze_parser.add_argument("--repeat", type=int, default=1, help="Repeat each analysis and write stability.json")
    _add_scan_options(analyze_parser)
    analyze_parser.set_defaults(func=_cmd_analyze)
    prepare_parser = sub.add_parser("prepare", help="Extract features from a labeled manifest")
    prepare_parser.add_argument("manifest")
    prepare_parser.add_argument("--output", required=True)
    _add_scan_options(prepare_parser)
    prepare_parser.set_defaults(func=_cmd_prepare)
    fit_parser = sub.add_parser("fit", help="Train and calibrate from prepared records")
    fit_parser.add_argument("features")
    fit_parser.add_argument("--dataset-name", required=True)
    fit_parser.add_argument("--dataset-version", required=True)
    fit_parser.add_argument("--output", required=True)
    fit_parser.add_argument("--report", required=True)
    fit_parser.set_defaults(func=_cmd_fit)
    evaluation = sub.add_parser("evaluate", help="Evaluate on the locked test partition")
    evaluation.add_argument("features")
    evaluation.add_argument("--model-file", required=True)
    evaluation.add_argument("--output", required=True)
    evaluation.set_defaults(func=_cmd_evaluate)
    legacy = sub.add_parser("evaluate-legacy", help="Optionally run copied upstream graph on locked test emails")
    legacy.add_argument("features")
    legacy.add_argument("--output", required=True)
    legacy.set_defaults(func=_cmd_evaluate_legacy)
    comparison = sub.add_parser("compare", help="Compare candidate and incumbent on paired locked emails")
    for name in ("incumbent-features", "candidate-features", "incumbent-model", "candidate-model"):
        comparison.add_argument(f"--{name}", required=True)
    comparison.add_argument("--output", required=True)
    comparison.set_defaults(func=_cmd_compare)
    feedback = sub.add_parser("feedback", help="Append a corrected analyst verdict")
    feedback.add_argument("--sha256", required=True)
    feedback.add_argument("--verdict", required=True)
    feedback.add_argument("--analyst", required=True)
    feedback.add_argument("--reason", required=True)
    feedback.add_argument("--output", default="feedback.jsonl")
    feedback.set_defaults(func=_cmd_feedback)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
