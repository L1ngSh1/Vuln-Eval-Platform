"""Closeout regressions: cache identity, completeness and unique CWE totals."""

import json
from dataclasses import replace

import pytest

from tests.python.test_pipeline_golden import REPO_ROOT, build_workspace
from vep.core.manifest import load_manifest
from vep.evaluation.aggregate import aggregate_metrics
from vep.pipeline import PipelineOptions, _aggregate_name, run_pipeline

# Stage 1 records failures without making the baseline commit's suite red.
pytestmark = pytest.mark.xfail(reason="Stage 2 pending", strict=True)


def setup_eval(tmp_path):
    ws = build_workspace(tmp_path)
    options = PipelineOptions(
        tool="codefuse", cwe_tokens=["901"], stages=["evaluate", "aggregate"],
        manifest_file=ws / "manifest.yml", aggregate_out_root=tmp_path / "out",
    )
    assert run_pipeline(options, REPO_ROOT) == 0
    directory = ws / "experiments/cwe-901/eval/codefuse_eval_v2"
    return ws, options, directory


@pytest.mark.parametrize("change", ["mode", "findings", "ground_truth"])
def test_cache_invalidates_changed_inputs(tmp_path, change):
    ws, options, directory = setup_eval(tmp_path)
    if change == "mode":
        options = replace(options, fp_mode="in_scope")
    elif change == "findings":
        csv = ws / "experiments/cwe-901/results/codefuse-query/cwe901_codefuse.csv"
        csv.write_text(csv.read_text() + "BenchmarkTest99998,CWE-901,new.java,1\n")
    else:
        gt = ws / "ground_truth.csv"
        gt.write_text(gt.read_text() + "BenchmarkTest99997,other,true,901\n")
    assert run_pipeline(options, REPO_ROOT) == 0
    cached = json.loads((directory / "metrics.json").read_text())
    assert run_pipeline(replace(options, skip_existing=False), REPO_ROOT) == 0
    fresh = json.loads((directory / "metrics.json").read_text())
    assert cached == fresh


@pytest.mark.parametrize("damage", ["bad_json", "wrong_shape", "tampered_metrics",
                                   "missing_detail", "tampered_detail", "legacy"])
def test_incomplete_or_corrupt_cache_recomputes(tmp_path, damage):
    _, options, directory = setup_eval(tmp_path)
    metrics = directory / "metrics.json"
    if damage == "bad_json":
        metrics.write_text("{")
    elif damage == "wrong_shape":
        metrics.write_text("[]")
    elif damage == "tampered_metrics":
        data = json.loads(metrics.read_text())
        data["tp"] = 999
        metrics.write_text(json.dumps(data))
    elif damage == "missing_detail":
        (directory / "fp.csv").unlink()
    elif damage == "tampered_detail":
        (directory / "tp.csv").write_text("partial")
    else:
        marker = directory / "evaluation-cache.json"
        if marker.exists():
            marker.unlink()
        metrics.write_text('{"tp":999}')
    assert run_pipeline(options, REPO_ROOT) == 0
    assert json.loads(metrics.read_text())["tp"] == 1
    assert (directory / "tp.csv").read_text().startswith("testcase,")
    assert (directory / "fp.csv").is_file()


def test_manifest_resolves_aliases_once_in_input_order(tmp_path):
    ws = build_workspace(tmp_path)
    manifest = load_manifest(ws / "manifest.yml", REPO_ROOT)
    assert [e.name for e in manifest.resolve(["901", "328", "CWE-901", "cwe328"])] == [
        "CWE-901", "CWE-328",
    ]


@pytest.mark.parametrize("strict", [False, True])
def test_aggregator_rejects_duplicate_cwe_aliases(strict):
    a = {"cwe": "CWE-328", "tool": "codefuse", "tp": 2, "fp": 1, "fn": 0}
    with pytest.raises(ValueError, match="Duplicate CWE"):
        aggregate_metrics([a, dict(a, cwe="328")], tool="codefuse", strict=strict)


def test_duplicate_selection_matches_unique_totals(tmp_path):
    ws = build_workspace(tmp_path)
    options = PipelineOptions(
        tool="codefuse", cwe_tokens=["328", "CWE-328"],
        stages=["evaluate", "aggregate"], manifest_file=ws / "manifest.yml",
        aggregate_out_root=tmp_path / "out",
    )
    assert run_pipeline(options, REPO_ROOT) == 0
    output = tmp_path / "out/metrics_v2_codefuse_subset.json"
    assert output.exists()
    data = json.loads(output.read_text())
    assert data["included_count"] == len(data["cwes"]) == 1
    for count in ("tp", "fp", "fn", "tn"):
        assert data["overall"][count] == sum(m[count] for m in data["cwes"].values())


def test_full_set_name_uses_members_not_list_length(tmp_path):
    ws = build_workspace(tmp_path)
    manifest = load_manifest(ws / "manifest.yml", REPO_ROOT)
    entry = manifest.cwes[0]
    assert _aggregate_name("codefuse", [entry, entry], manifest, PipelineOptions("codefuse")) == (
        "metrics_v2_codefuse_subset.json"
    )
