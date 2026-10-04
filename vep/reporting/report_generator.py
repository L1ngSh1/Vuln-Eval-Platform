"""VEP Reporting: Schema detection and data normalization.

Phase 2F: Load metrics JSON (legacy or v2), normalize into a unified
ReportData structure for downstream plot and text report generation.

Supported schemas:
- "legacy": produced by aggregate_results.py
    {CWE-XX: {tools: {codeql: {...}, codefuse: {...}}}, OVERALL: ...}
- "vep.aggregate.v2": produced by aggregate_v2.py
    {schema_version: "vep.aggregate.v2", tool: "...", cwes: {...}, overall: {...}}
- "vep.eval.v2": single-CWE metrics produced by eval_findings.py
    {schema_version: "vep.eval.v2", cwe: "CWE-022", tool: "codefuse", ...}
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


TOOL_DISPLAY_NAMES = {
    "codefuse": "CodeFuse-Query",
    "codeql": "CodeQL",
}


def tool_display_name(tool: str) -> str:
    """Return a user-facing label without changing the machine tool ID."""
    return TOOL_DISPLAY_NAMES.get(tool, tool)


@dataclass
class ToolMetrics:
    """Normalized metrics for a single tool on a single CWE (or overall)."""
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    fnr: float = 0.0
    fpr: float = 0.0
    fdr: float = 0.0
    tn: Optional[int] = None
    fp_mode: str = "unknown"
    outside_scope_findings: Optional[int] = None
    fpr_in_scope: Optional[float] = None
    fpr_definition: str = "legacy/unknown; standard in-scope FPR unavailable"
    metric_modes: dict = field(default_factory=dict)
    sample_scope: dict = field(default_factory=dict)


@dataclass
class CWEEntry:
    """Per-CWE data containing metrics keyed by tool name."""
    cwe: str
    benchmark_total: Optional[int] = None
    real_positive: Optional[int] = None
    tools: Dict[str, ToolMetrics] = field(default_factory=dict)


@dataclass
class ReportData:
    """Unified report data structure produced by load_metrics()."""
    schema: str                                  # "legacy" | "vep.aggregate.v2" | ...
    tools: List[str] = field(default_factory=list)   # discovered tool names (sorted)
    cwes: Dict[str, CWEEntry] = field(default_factory=dict)  # keyed by normalized CWE
    overall: Dict[str, ToolMetrics] = field(default_factory=dict)  # keyed by tool name
    fp_mode: str = "unknown"
    metric_contract: str = "legacy_unverified"
    sample_scope: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_cwe_key(key: str) -> str:
    """Normalize CWE key to 'CWE-NNN' format for display consistency.

    Examples:
        'CWE-22'  -> 'CWE-022'
        'CWE-089' -> 'CWE-089'
        'CWE-328' -> 'CWE-328'
    """
    m = re.search(r"(\d+)", key)
    if m:
        num = m.group(1).zfill(3)
        return f"CWE-{num}"
    return key


def _dict_to_tool_metrics(d: dict) -> ToolMetrics:
    """Convert a raw metrics dict to ToolMetrics."""
    return ToolMetrics(
        tp=d.get("tp", 0),
        fp=d.get("fp", 0),
        fn=d.get("fn", 0),
        precision=d.get("precision", 0.0),
        recall=d.get("recall", 0.0),
        f1=d.get("f1", 0.0),
        fnr=d.get("fnr", 0.0),
        fpr=d.get("fpr", 0.0),
        fdr=d.get("fdr", 0.0),
        tn=d.get("tn"),
        fp_mode=d.get("fp_mode", "unknown"),
        outside_scope_findings=d.get("outside_scope_findings"),
        fpr_in_scope=d.get("fpr_in_scope"),
        fpr_definition=d.get("fpr_definition", "legacy/unknown; standard in-scope FPR unavailable"),
        metric_modes=d.get("metric_modes") or {},
        sample_scope=d.get("sample_scope") or {},
    )


# ---------------------------------------------------------------------------
# Schema detection
# ---------------------------------------------------------------------------

def detect_schema(data: dict) -> str:
    """Auto-detect metrics JSON schema version.

    Returns:
        One of "legacy", "vep.aggregate.v2", "vep.eval.v2", or the raw
        schema_version string for unknown v2 schemas.

    Raises:
        ValueError: If the schema cannot be determined.
    """
    sv = data.get("schema_version")
    if sv:
        return sv
    if "OVERALL" in data and isinstance(data["OVERALL"], dict):
        return "legacy"
    raise ValueError(
        "Unknown metrics schema: no 'schema_version' and no 'OVERALL' key found."
    )


# ---------------------------------------------------------------------------
# Loaders (one per schema)
# ---------------------------------------------------------------------------

def _load_legacy(data: dict) -> ReportData:
    """Load legacy aggregate_results.py format."""
    tools_set: set = set()
    cwes: Dict[str, CWEEntry] = {}
    overall: Dict[str, ToolMetrics] = {}

    for key, val in data.items():
        if key == "OVERALL":
            for tool_name, metrics in val.get("tools", {}).items():
                overall[tool_name] = _dict_to_tool_metrics(metrics)
                tools_set.add(tool_name)
            continue

        cwe_norm = _normalize_cwe_key(key)
        entry = CWEEntry(
            cwe=cwe_norm,
            benchmark_total=val.get("benchmark_total"),
            real_positive=val.get("real_positive"),
        )
        for tool_name, metrics in val.get("tools", {}).items():
            entry.tools[tool_name] = _dict_to_tool_metrics(metrics)
            tools_set.add(tool_name)
        cwes[cwe_norm] = entry

    return ReportData(
        schema="legacy",
        tools=sorted(tools_set),
        cwes=cwes,
        overall=overall,
    )


def _load_aggregate_v2(data: dict) -> ReportData:
    """Load vep.aggregate.v2 format (single-tool aggregate)."""
    tool_name = data.get("tool", "unknown")
    tools_set = {tool_name}
    cwes: Dict[str, CWEEntry] = {}
    overall: Dict[str, ToolMetrics] = {}

    # Per-CWE
    for cwe_key, cwe_data in data.get("cwes", {}).items():
        cwe_norm = _normalize_cwe_key(cwe_key)
        if cwe_data.get("fp_mode", data.get("fp_mode", "unknown")) != data.get("fp_mode", "unknown"):
            raise ValueError("Per-CWE FP mode differs from aggregate")
        entry = CWEEntry(cwe=cwe_norm)
        entry.tools[tool_name] = _dict_to_tool_metrics(dict(cwe_data, fp_mode=data.get("fp_mode", "unknown")))
        cwes[cwe_norm] = entry

    # Overall
    overall_data = data.get("overall", {})
    if overall_data:
        overall[tool_name] = _dict_to_tool_metrics(dict(overall_data, fp_mode=data.get("fp_mode", "unknown"),
                                                    metric_modes=data.get("metric_modes") or {}))

    return ReportData(
        schema="vep.aggregate.v2",
        tools=sorted(tools_set),
        cwes=cwes,
        overall=overall,
        fp_mode=data.get("fp_mode", "unknown"),
        metric_contract=data.get("metric_contract", "legacy_unverified"),
        sample_scope=data.get("sample_scope") or {"unit": "unknown", "dataset_sha256": None,
                                                 "cwes": {cwe: {} for cwe in cwes}, "verified": False},
    )


def _load_eval_v2(data: dict) -> ReportData:
    """Load vep.eval.v2 format (single-CWE, single-tool)."""
    tool_name = data.get("tool", "unknown")
    cwe_raw = data.get("cwe", "unknown")
    cwe_norm = _normalize_cwe_key(cwe_raw)

    entry = CWEEntry(cwe=cwe_norm)
    entry.tools[tool_name] = _dict_to_tool_metrics(data)

    # For single-CWE, overall == the only CWE
    overall = {tool_name: _dict_to_tool_metrics(data)}

    return ReportData(
        schema="vep.eval.v2",
        tools=[tool_name],
        cwes={cwe_norm: entry},
        overall=overall,
        fp_mode=data.get("fp_mode", "unknown"),
        metric_contract=data.get("metric_contract", "legacy_unverified"),
        sample_scope={"unit": (data.get("sample_scope") or {}).get("unit", "unknown"),
                      "dataset_sha256": (data.get("sample_scope") or {}).get("dataset_sha256"),
                      "verified": (data.get("sample_scope") or {}).get("verified", False),
                      "cwes": {cwe_norm: data.get("sample_scope") or {}}},
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_metrics(path: Path) -> ReportData:
    """Load a metrics JSON file and return normalized ReportData.

    Automatically detects schema version and parses accordingly.

    Args:
        path: Path to a metrics JSON file.

    Returns:
        ReportData with unified structure.
    """
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    schema = detect_schema(data)

    if schema == "legacy":
        return _load_legacy(data)
    elif schema == "vep.aggregate.v2":
        return _load_aggregate_v2(data)
    elif schema == "vep.eval.v2":
        return _load_eval_v2(data)
    else:
        # Try aggregate v2 as fallback for future schemas
        if "cwes" in data and "overall" in data:
            return _load_aggregate_v2(data)
        raise ValueError(f"Unsupported metrics schema: {schema}")


def merge_report_data(reports: List[ReportData]) -> ReportData:
    """Merge multiple ReportData objects (e.g. different tools) into one.

    This enables loading separate CodeQL and CodeFuse aggregate files
    and combining them into a single dual-tool ReportData.

    Args:
        reports: List of ReportData objects to merge.

    Returns:
        Merged ReportData with all tools combined.
    """
    if not reports:
        raise ValueError("No ReportData to merge")
    if len(reports) == 1:
        return reports[0]

    first = reports[0]
    for report in reports[1:]:
        if report.fp_mode != first.fp_mode:
            raise ValueError("Mixed FP modes in report merge")
        if set(report.cwes) != set(first.cwes):
            raise ValueError("Different CWE sample scopes in report merge")
        if report.sample_scope != first.sample_scope:
            raise ValueError("Different sample populations/datasets in report merge")
        if report.metric_contract != first.metric_contract:
            raise ValueError("Different metric contracts in report merge")

    tools_set: set = set()
    merged_cwes: Dict[str, CWEEntry] = {}
    merged_overall: Dict[str, ToolMetrics] = {}

    for rd in reports:
        if tools_set.intersection(rd.tools):
            raise ValueError("Duplicate tool would overwrite report metrics; aggregate first")
        tools_set.update(rd.tools)

        # Merge per-CWE
        for cwe_key, entry in rd.cwes.items():
            if cwe_key not in merged_cwes:
                merged_cwes[cwe_key] = CWEEntry(
                    cwe=entry.cwe,
                    benchmark_total=entry.benchmark_total,
                    real_positive=entry.real_positive,
                )
            for tool_name, tm in entry.tools.items():
                merged_cwes[cwe_key].tools[tool_name] = tm

        # Merge overall
        for tool_name, tm in rd.overall.items():
            merged_overall[tool_name] = tm

    if not first.sample_scope.get("verified", False):
        raise ValueError("Unverified sample identities; replay inputs before dual-tool comparison")

    return ReportData(
        schema="merged",
        tools=sorted(tools_set),
        cwes=merged_cwes,
        overall=merged_overall,
        fp_mode=first.fp_mode,
        metric_contract=first.metric_contract,
        sample_scope=first.sample_scope,
    )
