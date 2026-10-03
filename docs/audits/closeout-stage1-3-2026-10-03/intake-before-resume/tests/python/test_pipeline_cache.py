"""Closeout regressions: cache identity, completeness and unique CWE totals."""

import json
from dataclasses import replace

import pytest

from tests.python.test_pipeline_golden import REPO_ROOT, build_workspace
from vep.core.manifest import load_manifest
from vep.evaluation.aggregate import aggregate_metrics
from vep.pipeline import PipelineOptions, _aggregate_name, run_pipeline

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


def test_unchanged_cache_preserves_all_artifacts(tmp_path):
    _, options, directory = setup_eval(tmp_path)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
    assert run_pipeline(options, REPO_ROOT) == 0
    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
    assert before == after


def test_interrupted_evaluation_has_no_completion_marker(tmp_path, monkeypatch):
    _, options, directory = setup_eval(tmp_path)

    def broken_writer(details, staging):
        (staging / "tp.csv").write_text("incomplete")
        raise OSError("simulated disk failure")

    with monkeypatch.context() as patch:
        patch.setattr("vep.pipeline.write_evaluation_details", broken_writer)
        assert run_pipeline(replace(options, skip_existing=False), REPO_ROOT) == 1
    assert not (directory / "evaluation-cache.json").exists()
    assert not list(directory.parent.glob(".vep-eval-*"))
    assert run_pipeline(options, REPO_ROOT) == 0
    assert (directory / "evaluation-cache.json").is_file()


@pytest.mark.parametrize("damage", ["bad_json", "wrong_shape", "missing_identity"])
def test_corrupt_completion_marker_recomputes(tmp_path, damage):
    _, options, directory = setup_eval(tmp_path)
    marker = directory / "evaluation-cache.json"
    marker.write_text({"bad_json": "{", "wrong_shape": "[]", "missing_identity": "{}"}[damage])
    assert run_pipeline(options, REPO_ROOT) == 0
    assert json.loads(marker.read_text())["schema"] == "vep.pipeline-cache.v1"


def setup_run(tmp_path, tool_name, monkeypatch):
    """Use real adapters with tiny versioned executables, never real analyzers."""
    import yaml
    from vep.tools.codefuse import CodeFuseTool
    from vep.tools.codeql import CodeQLTool
    from vep.tools.config import ToolsConfig

    ws = build_workspace(tmp_path)
    db = ws / "database"
    db.mkdir()
    (db / "source.txt").write_text("original database")
    rule = ws / "rule"
    rule.mkdir()
    (rule / "query.ql").write_text("original rule")
    local = ws / "rules/codefuse-query/lib"
    local.mkdir(parents=True)
    (local / "local.gdl").write_text("local library")
    official = ws / "official"
    official.mkdir()
    (official / "official.gdl").write_text("official library")
    converter = ws / "scripts/converters/codefuse_json_to_csv.py"
    converter.parent.mkdir(parents=True)
    converter.write_bytes((REPO_ROOT / "scripts/converters/codefuse_json_to_csv.py").read_bytes())
    binary = ws / "analyzer"
    version = ws / "version.txt"
    version.write_text("fixture version 1")
    calls = ws / "run-calls.txt"
    binary.write_text(f'''#!/bin/bash
if [ "$1" = version ]; then cat "{version}"; exit 0; fi
echo run >> "{calls}"
out=""; prev=""
for arg in "$@"; do
    case "$arg" in --output=*) out="${{arg#--output=}}";; esac
    if [ "$prev" = --output-json ]; then out="$arg"; fi
    prev="$arg"
done
if [ "{tool_name}" = codeql ]; then
    printf '%s' '{{"version":"2.1.0","runs":[{{"results":[]}}]}}' > "$out"
else
    printf '%s' '[]' > "$out"
fi
''')
    binary.chmod(0o755)
    manifest = yaml.safe_load((ws / "manifest.yml").read_text())
    for entry in manifest["cwes"]:
        entry["codeql"] = {"rule_directory": str(rule)}
        entry["codefuse"] = {"rule_file": str(rule / "query.ql")}
    (ws / "manifest.yml").write_text(yaml.safe_dump(manifest))
    config = ToolsConfig()
    config.env_checks.codefuse_java_env = False
    tool = (CodeQLTool(config, ws, bin_path=str(binary)) if tool_name == "codeql" else
            CodeFuseTool(config, ws, home=str(ws), godel_bin=str(binary), official_lib=str(official)))
    monkeypatch.setattr("vep.pipeline._build_tool", lambda *args: tool)
    options = PipelineOptions(
        tool=tool_name, cwe_tokens=["901"], stages=["run", "evaluate"],
        manifest_file=ws / "manifest.yml", db_overrides={tool_name: db},
    )
    return ws, tool, options, calls


@pytest.mark.parametrize("tool_name", ["codeql", "codefuse"])
@pytest.mark.parametrize("change", ["rules", "database", "version", "binary", "raw",
                                   "normalized", "run_marker", "libraries"])
def test_run_cache_binds_effective_inputs(tmp_path, monkeypatch, tool_name, change):
    ws, _, options, calls = setup_run(tmp_path, tool_name, monkeypatch)
    assert run_pipeline(options, ws) == 0
    assert calls.read_text().splitlines() == ["run"]
    assert run_pipeline(options, ws) == 0
    assert calls.read_text().splitlines() == ["run"]
    if change == "rules":
        (ws / "rule/query.ql").write_text("changed rule")
    elif change == "database":
        (ws / "database/source.txt").write_text("changed database")
    elif change == "version":
        (ws / "version.txt").write_text("fixture version 2")
    elif change == "binary":
        binary = ws / "analyzer"
        binary.write_text(binary.read_text() + "\n# new binary revision\n")
    elif change == "libraries":
        if tool_name == "codefuse":
            (ws / "official/official.gdl").write_text("changed official lib")
        else:
            (ws / "rule/qlpack.yml").write_text("name: fixture/test\nversion: 1.0.0\n")
    else:
        output = ws / "experiments/cwe-901/results" / (
            "codeql" if tool_name == "codeql" else "codefuse-query")
        name = {"raw": ("cwe901.sarif" if tool_name == "codeql" else "checker901.json"),
                "normalized": ("cwe901.csv" if tool_name == "codeql" else "cwe901_codefuse.csv"),
                "run_marker": "run-cache.json"}[change]
        (output / name).write_text("damaged")
    assert run_pipeline(options, ws) == 0
    assert calls.read_text().splitlines() == ["run", "run"]


def test_run_only_resume_is_independent_of_metrics(tmp_path, monkeypatch):
    ws, _, options, calls = setup_run(tmp_path, "codeql", monkeypatch)
    options = replace(options, stages=["run"])
    assert run_pipeline(options, ws) == 0
    assert run_pipeline(options, ws) == 0
    assert calls.read_text().splitlines() == ["run"]
    assert not list(ws.glob("experiments/*/eval/*/metrics.json"))


def test_run_version_failure_disables_cache_not_analysis(tmp_path, monkeypatch):
    ws, _, options, calls = setup_run(tmp_path, "codeql", monkeypatch)
    binary = ws / "analyzer"
    binary.write_text(binary.read_text().replace('then cat', 'then exit 19; cat'))
    assert run_pipeline(options, ws) == 0
    assert run_pipeline(options, ws) == 0
    assert calls.read_text().splitlines() == ["run", "run"]
    assert not list(ws.glob("experiments/*/results/*/run-cache.json"))


def test_rule_pack_lock_change_invalidates_cache(tmp_path, monkeypatch):
    ws, _, options, calls = setup_run(tmp_path, "codeql", monkeypatch)
    (ws / "rule/qlpack.yml").write_text("name: fixture/test\nversion: 1.0.0\n")
    lock = ws / "rule/codeql-pack.lock.yml"
    lock.write_text("lockVersion: 1\n")
    assert run_pipeline(options, ws) == 0
    lock.write_text("lockVersion: 2\n")
    assert run_pipeline(options, ws) == 0
    assert calls.read_text().splitlines() == ["run", "run"]


def test_refreshed_run_requires_evaluation_before_aggregation(tmp_path, monkeypatch):
    ws, _, options, _ = setup_run(tmp_path, "codeql", monkeypatch)
    assert run_pipeline(options, ws) == 0
    output = ws / "experiments/cwe-901/results/codeql/cwe901.csv"
    output.write_text("changed input")
    # An unchanged tool emits the same normalized findings, so this is valid.
    assert run_pipeline(replace(options, stages=["run", "aggregate"],
                                aggregate_out_root=ws / "out"), ws) == 0
    metrics = ws / "experiments/cwe-901/eval/codeql_eval_v2/evaluation-cache.json"
    metrics.unlink()
    assert run_pipeline(replace(options, stages=["run", "aggregate"],
                                aggregate_out_root=ws / "out"), ws) == 1


def test_success_without_new_raw_output_does_not_reuse_old_output(tmp_path, monkeypatch):
    ws, _, options, _ = setup_run(tmp_path, "codeql", monkeypatch)
    assert run_pipeline(options, ws) == 0
    (ws / "analyzer").write_text('#!/bin/bash\nif [ "$1" = version ]; then echo fixture; fi\nexit 0\n')
    assert run_pipeline(options, ws) == 1
    assert not list(ws.glob("experiments/*/results/*/run-cache.json"))
    assert not list(ws.glob("experiments/*/results/*/.vep-run-*"))


def test_failed_run_invalidates_completion_and_preserves_old_findings(tmp_path, monkeypatch):
    ws, _, options, _ = setup_run(tmp_path, "codeql", monkeypatch)
    assert run_pipeline(options, ws) == 0
    output = ws / "experiments/cwe-901/results/codeql/cwe901.csv"
    before = output.read_bytes()
    (ws / "analyzer").write_text('#!/bin/bash\nif [ "$1" = version ]; then echo fixture; exit 0; fi\nexit 29\n')
    assert run_pipeline(options, ws) == 1
    assert output.read_bytes() == before
    assert not list(ws.glob("experiments/*/results/*/run-cache.json"))
