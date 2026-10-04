"""VEP Evaluation: Aggregate multiple CWE metrics.

Phase 2D: Multi-CWE Aggregator
Aggregate multiple v2 metrics.json files into overall summary.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


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
        cwe = metrics.get("cwe", "unknown")
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

    # Validate consistency if strict
    if strict:
        if len(fp_modes_seen) > 1:
            raise ValueError(f"Mixed FP modes in strict mode: {fp_modes_seen}")
        if tool and len(tools_seen) > 1:
            raise ValueError(f"Mixed tools in strict mode: {tools_seen}")
        if tool and tool not in tools_seen:
            raise ValueError(f"Expected tool {tool}, found {tools_seen}")

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
