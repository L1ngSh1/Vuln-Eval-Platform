"""Unit tests for vep.evaluation.aggregate (Phase 4 / M4.2)."""

import json

import pytest

from vep.evaluation.aggregate import (
    aggregate_metrics,
    write_aggregate_json,
)


def metrics(cwe, tp, fp, fn, tn, fp_mode="all_non_gt", tool="codefuse"):
    return {
        "cwe": cwe,
        "tool": tool,
        "fp_mode": fp_mode,
        "schema_version": "vep.eval.v2",
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


class TestAggregateMetrics:
    def test_overall_is_sum_not_average(self):
        agg = aggregate_metrics([
            metrics("CWE-A", tp=10, fp=5, fn=2, tn=20),
            metrics("CWE-B", tp=5, fp=10, fn=3, tn=30),
        ])
        overall = agg["overall"]
        assert overall["tp"] == 15
        assert overall["fp"] == 15
        assert overall["fn"] == 5
        assert overall["tn"] == 50
        assert overall["precision"] == 0.5
        assert overall["recall"] == 0.75
        assert overall["f1"] == 0.6
        assert overall["fnr"] == 0.25
        assert overall["fdr"] == 0.5

    def test_schema_and_metadata(self):
        agg = aggregate_metrics([
            metrics("CWE-A", 1, 1, 1, 1),
            metrics("CWE-B", 1, 1, 1, 1),
        ])
        assert agg["schema_version"] == "vep.aggregate.v2"
        assert agg["included_count"] == 2
        assert set(agg["cwes"].keys()) == {"CWE-A", "CWE-B"}
        assert agg["tool"] == "codefuse"
        assert agg["fp_mode"] == "all_non_gt"

    def test_empty_metrics_raises(self):
        with pytest.raises(ValueError, match="No metrics"):
            aggregate_metrics([])

    def test_strict_mixed_fp_mode_raises(self):
        with pytest.raises(ValueError, match="Mixed FP modes"):
            aggregate_metrics([
                metrics("CWE-A", 1, 1, 1, 1, fp_mode="all_non_gt"),
                metrics("CWE-B", 1, 1, 1, 1, fp_mode="in_scope"),
            ], strict=True)

    def test_strict_tool_mismatch_raises(self):
        # The tool consistency check requires passing the expected tool.
        with pytest.raises(ValueError, match="Mixed tools"):
            aggregate_metrics([
                metrics("CWE-A", 1, 1, 1, 1, tool="codefuse"),
                metrics("CWE-B", 1, 1, 1, 1, tool="codeql"),
            ], tool="codefuse", strict=True)

    def test_non_strict_mixed_fp_mode_reports_mixed(self):
        agg = aggregate_metrics([
            metrics("CWE-A", 1, 1, 1, 1, fp_mode="all_non_gt"),
            metrics("CWE-B", 1, 1, 1, 1, fp_mode="in_scope"),
        ])
        assert agg["fp_mode"] == "mixed"
        assert agg["metadata"]["fp_modes_seen"] == ["all_non_gt", "in_scope"]


class TestWriteAggregateJson:
    def test_roundtrip(self, tmp_path):
        out = tmp_path / "nested" / "aggregate.json"
        agg = aggregate_metrics([metrics("CWE-A", 1, 1, 1, 1)])
        write_aggregate_json(agg, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["overall"]["tp"] == 1
        assert data["schema_version"] == "vep.aggregate.v2"
