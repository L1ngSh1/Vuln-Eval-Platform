"""VEP Evaluation: Metrics output utilities.

Phase 2B: Enhanced metrics output with extended fields and detail CSV support.
Convert EvalResult to dict and write metrics JSON + detail CSVs.
"""

import csv
import json
from pathlib import Path

from vep.core.models import EvalResult, EvaluationDetails


def eval_result_to_dict(result: EvalResult) -> dict:
    """Convert EvalResult to dictionary for JSON serialization.

    Output format compatible with existing metrics.json files,
    with Phase 2B extended fields.

    Args:
        result: EvalResult object

    Returns:
        Dictionary ready for JSON serialization
    """
    metrics = {
        "cwe": result.cwe,
        "tool": result.tool,
        "fp_mode": result.fp_mode,
        "raw_findings": result.total_findings,
        "total_findings": result.total_findings,
        "dedup_findings": result.dedup_findings,
        "ground_truth_total": result.total_expected_vulnerable,
        "total_expected_vulnerable": result.total_expected_vulnerable,
        "in_scope_findings": result.in_scope_findings,
        "outside_scope_findings": result.outside_scope_findings,
        "outside_scope_ratio": result.outside_scope_ratio,
        "tp": result.tp,
        "fp": result.fp,
        "fp_in_scope": result.fp_in_scope,
        "fp_all_non_gt": result.fp_all_non_gt,
        "fn": result.fn,
        "precision": result.precision,
        "recall": result.recall,
        "fnr": result.fnr,
        "fpr": result.fpr,
        "fdr": result.fdr,
        "f1": result.f1,
        "schema_version": result.schema_version,
    }

    # Optional fields
    if result.tn is not None:
        metrics["tn"] = result.tn
    if result.total_expected_cases is not None:
        metrics["cwe_scope_total"] = result.total_expected_cases
        metrics["total_expected_cases"] = result.total_expected_cases

    return metrics


def write_metrics_json(result: EvalResult, path: Path) -> None:
    """Write evaluation metrics to JSON file.

    Creates parent directories if needed.
    Output format: UTF-8, 2-space indent.

    Args:
        result: EvalResult to serialize
        path: Output file path

    Raises:
        IOError: If file cannot be written
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    metrics = eval_result_to_dict(result)

    with path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
        f.write("\n")  # Trailing newline


def write_detail_csv(rows: list, path: Path, fieldnames: list) -> None:
    """Write detail CSV file.

    Args:
        rows: List of dicts containing row data
        path: Output CSV path
        fieldnames: CSV column names

    Note:
        Writes header even if rows is empty.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_evaluation_details(details: EvaluationDetails, out_dir: Path) -> None:
    """Write detailed CSV files (tp.csv, fp.csv, fn.csv, outside_scope.csv).

    Args:
        details: EvaluationDetails object
        out_dir: Output directory for CSV files
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Standard fieldnames (compatible with old evaluator)
    fieldnames = ["testcase", "testcaseId", "sinkFile", "line", "ruleId", "findingCount"]

    # Write TP
    write_detail_csv(details.tp_rows, out_dir / "tp.csv", fieldnames)

    # Write FP
    write_detail_csv(details.fp_rows, out_dir / "fp.csv", fieldnames)

    # Write FN
    write_detail_csv(details.fn_rows, out_dir / "fn.csv", fieldnames)

    # Write outside_scope
    write_detail_csv(details.outside_scope_rows, out_dir / "outside_scope.csv", fieldnames)
