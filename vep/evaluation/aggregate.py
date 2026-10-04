"""VEP Evaluation: Aggregate multiple CWE metrics.

Phase 2D: Multi-CWE Aggregator
Aggregate multiple v2 metrics.json files into overall summary.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from vep.core.normalization import normalize_cwe_id
from vep.evaluation.contract import CUSTOM_FPR, METRIC_CONTRACT, STANDARD_FPR, UNIT, metric_modes, standard_fpr


def load_metrics_json(path: Path) -> dict:
    """Load metrics JSON file.

    Args:
        path: Path to metrics.json

    Returns:
        Metrics dictionary
    """
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def aggregate_metrics(
    metrics_list: List[dict],
    tool: Optional[str] = None,
    strict: bool = False
) -> dict:
    """Aggregate multiple CWE metrics into overall summary.

    Args:
        metrics_list: List of metrics dictionaries
        tool: Expected tool name (optional, for validation)
        strict: If True, fail on inconsistencies

    Returns:
        Aggregated metrics dictionary

    Note:
        Overall metrics calculated from sum of TP/FP/FN/TN,
        NOT by averaging individual precision/recall/f1.
    """
    if not metrics_list:
        raise ValueError("No metrics to aggregate")

    # Collect metadata
    fp_modes_seen = set()
    tools_seen = set()
    schema_versions_seen = set()
    cwes_aggregated = {}

    # Accumulate totals
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_tn = 0
    has_tn = False

    for metrics in metrics_list:
        # Track metadata
        cwe = normalize_cwe_id(metrics.get("cwe", "unknown"))
        if cwe in cwes_aggregated:
            raise ValueError(f"Duplicate CWE metrics: {cwe}")
        fp_mode = metrics.get("fp_mode", "unknown")
        metrics_tool = metrics.get("tool", "unknown")
        schema_version = metrics.get("schema_version")

        fp_modes_seen.add(fp_mode)
        tools_seen.add(metrics_tool)
        if schema_version:
            schema_versions_seen.add(schema_version)

        # Accumulate metrics
        tp = metrics.get("tp", 0)
        fp = metrics.get("fp", 0)
        fn = metrics.get("fn", 0)
        tn = metrics.get("tn")

        total_tp += tp
        total_fp += fp
        total_fn += fn

        if tn is not None:
            total_tn += tn
            has_tn = True

        # Store per-CWE metrics
        cwes_aggregated[cwe] = metrics

    # These contracts are correctness requirements, not optional strict checks.
    if len(fp_modes_seen) > 1:
        raise ValueError(f"Mixed FP modes: {fp_modes_seen}")
    if len(tools_seen) > 1:
        raise ValueError(f"Mixed tools: {tools_seen}")
    if tool and tool not in tools_seen:
        raise ValueError(f"Expected tool {tool}, found {tools_seen}")
    contracts = {m.get("metric_contract") for m in metrics_list}
    scopes = [m.get("sample_scope") or {} for m in metrics_list]
    if len(contracts) > 1:
        raise ValueError("Mixed metric contracts")
    if len({s.get("dataset_sha256") for s in scopes}) > 1:
        raise ValueError("Mixed ground truth datasets/sample sets")
    if len({s.get("unit") for s in scopes}) > 1:
        raise ValueError("Mixed statistic units")
    if strict and any(not s.get("verified", False) for s in scopes):
        raise ValueError("Strict aggregation requires verified sample identities")
    complete_tn = all(m.get("tn") is not None for m in metrics_list)
    has_tn = complete_tn
    def sum_known(name):
        return sum(m[name] for m in metrics_list) if all(m.get(name) is not None for m in metrics_list) else None
    fp_in_scope = sum_known("fp_in_scope")
    fp_all_non_gt = sum_known("fp_all_non_gt")

    # Determine aggregated metadata
    if len(tools_seen) == 1:
        agg_tool = list(tools_seen)[0]
    elif tool:
        agg_tool = tool
    else:
        agg_tool = "mixed"

    if len(fp_modes_seen) == 1:
        agg_fp_mode = list(fp_modes_seen)[0]
    else:
        agg_fp_mode = "mixed"

    # Calculate overall metrics
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    overall_f1 = (2 * overall_precision * overall_recall) / (overall_precision + overall_recall) \
        if (overall_precision + overall_recall) > 0 else 0.0

    overall_fnr = total_fn / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    overall_fpr = total_fp / (total_fp + total_tn) if has_tn and (total_fp + total_tn) > 0 else 0.0
    overall_fdr = total_fp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0

    # Round to 4 decimal places
    overall_precision = round(overall_precision, 4)
    overall_recall = round(overall_recall, 4)
    overall_f1 = round(overall_f1, 4)
    overall_fnr = round(overall_fnr, 4)
    overall_fpr = round(overall_fpr, 4)
    overall_fdr = round(overall_fdr, 4)

    # Build aggregated result
    result = {
        "schema_version": "vep.aggregate.v2",
        "tool": agg_tool,
        "fp_mode": agg_fp_mode,
        "metric_contract": next(iter(contracts)) or "legacy_unverified",
        "sample_scope": {
            "unit": scopes[0].get("unit", "unknown"),
            "dataset_sha256": scopes[0].get("dataset_sha256"),
            "cwes": {cwe: m.get("sample_scope") or {} for cwe, m in cwes_aggregated.items()},
            "verified": all(s.get("verified", False) for s in scopes),
        },
        "metric_modes": metric_modes(total_tp, fp_in_scope, fp_all_non_gt, total_fn, total_tn if complete_tn else None),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "included_count": len(metrics_list),
        "cwes": cwes_aggregated,
        "overall": {
            "tp": total_tp,
            "fp": total_fp,
            "fn": total_fn,
            "precision": overall_precision,
            "recall": overall_recall,
            "f1": overall_f1,
            "fnr": overall_fnr,
            "fpr": overall_fpr,
            "fdr": overall_fdr,
            "fp_in_scope": fp_in_scope,
            "fp_all_non_gt": fp_all_non_gt,
            "outside_scope_findings": sum_known("outside_scope_findings"),
            "in_scope_findings": sum_known("in_scope_findings"),
            "dedup_findings": sum_known("dedup_findings"),
            "raw_findings": sum_known("raw_findings"),
            "cwe_scope_total": sum_known("cwe_scope_total"),
            "fpr_in_scope": standard_fpr(fp_in_scope, total_tn if complete_tn else None),
            "fpr_definition": (CUSTOM_FPR if agg_fp_mode == "all_non_gt" else STANDARD_FPR
                               if agg_fp_mode == "in_scope" else "legacy/unknown; standard FPR unverified"),
        },
        "metadata": {
            "fp_modes_seen": sorted(fp_modes_seen),
            "tools_seen": sorted(tools_seen),
            "schema_versions_seen": sorted(schema_versions_seen) if schema_versions_seen else ["unknown"],
        }
    }

    # Add TN if available
    if has_tn:
        result["overall"]["tn"] = total_tn

    return result


def write_aggregate_json(aggregate: dict, path: Path) -> None:
    """Write aggregate metrics to JSON file.

    Args:
        aggregate: Aggregate metrics dictionary
        path: Output file path
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(aggregate, f, indent=2)
        f.write("\n")
