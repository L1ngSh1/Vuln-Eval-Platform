"""Pipeline golden integration tests (Phase 4 / M4.4).

Runs the real pipeline (evaluate + aggregate stages) over a committed mini
benchmark fixture and compares against golden metric JSONs. No analysis tools,
databases, or network access required.

The CWE-328 fixture mirrors the real ground truth special case: the "328S"
row (BenchmarkTest00003) must count as a vulnerable CWE-328 case. Semantics
fixed by docs/audits/PARITY_M34_CODEFUSE_PIPELINE.md — do not "fix" the
fixture when this test fails; the scope mapping regressed instead.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from vep.pipeline import PipelineOptions, run_pipeline

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures" / "mini_benchmark"
PIPELINE_CLI = REPO_ROOT / "scripts" / "evaluation" / "run_pipeline.py"


def build_workspace(tmp_path):
    """Copy fixtures into a tmp workspace and write a manifest with absolute paths."""
    ws = tmp_path / "ws"
    ws.mkdir()
    shutil.copy(FIXTURES / "ground_truth.csv", ws / "ground_truth.csv")
    shutil.copytree(FIXTURES / "experiments", ws / "experiments")

    manifest = {
        "version": "test",
        "ground_truth": {"file": str(ws / "ground_truth.csv")},
        "databases": {"codefuse": str(ws / "unused-db"), "codeql": str(ws / "unused-db")},
        "cwes": [
            {
                "id": "328", "name": "CWE-328", "slug": "cwe-328", "slug_compact": "cwe328",
                "codefuse": {"rule_file": str(ws / "unused.gdl")},
                "experiments": {"directory": str(ws / "experiments" / "cwe-328")},
            },
            {
                "id": "901", "name": "CWE-901", "slug": "cwe-901", "slug_compact": "cwe901",
                "codefuse": {"rule_file": str(ws / "unused.gdl")},
                "experiments": {"directory": str(ws / "experiments" / "cwe-901")},
            },
        ],
    }
    (ws / "manifest.yml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return ws


def run_evaluate_aggregate(ws, out_root, skip_existing=True):
    options = PipelineOptions(
        tool="codefuse",
        cwe_tokens=["all"],
        stages=["evaluate", "aggregate"],
        manifest_file=ws / "manifest.yml",
        aggregate_out_root=out_root,
        skip_existing=skip_existing,
    )
    assert run_pipeline(options, REPO_ROOT) == 0


def assert_matches_golden(actual: dict, golden_path: Path):
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    subset = {key: actual[key] for key in golden if key in actual}
    assert subset == golden, f"mismatch vs {golden_path.name}"


class TestGoldenEvaluation:
    def test_metrics_match_golden(self, tmp_path):
        ws = build_workspace(tmp_path)
        out_root = tmp_path / "out"
        run_evaluate_aggregate(ws, out_root)

        for cwe_id, golden_name in (("328", "cwe328_metrics.json"),
                                    ("901", "cwe901_metrics.json")):
            metrics_path = (ws / "experiments" / f"cwe-{cwe_id}" / "eval"
                            / "codefuse_eval_v2" / "metrics.json")
            assert metrics_path.is_file(), metrics_path
            assert_matches_golden(json.loads(metrics_path.read_text(encoding="utf-8")),
                                  FIXTURES / "golden" / golden_name)

    def test_aggregate_matches_golden(self, tmp_path):
        ws = build_workspace(tmp_path)
        out_root = tmp_path / "out"
        run_evaluate_aggregate(ws, out_root)

        aggregate_path = out_root / "metrics_v2_codefuse_all.json"
        assert aggregate_path.is_file()
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
        assert_matches_golden(aggregate, FIXTURES / "golden" / "aggregate.json")

    def test_328s_scope_guard(self, tmp_path):
        """BenchmarkTest00003 (ground truth row '328S') must be a TP for CWE-328."""
        ws = build_workspace(tmp_path)
        run_evaluate_aggregate(ws, tmp_path / "out")

        eval_dir = ws / "experiments" / "cwe-328" / "eval" / "codefuse_eval_v2"
        metrics = json.loads((eval_dir / "metrics.json").read_text(encoding="utf-8"))
        assert metrics["tp"] == 2 and metrics["fn"] == 0

        tp_rows = (eval_dir / "tp.csv").read_text(encoding="utf-8")
        assert "BenchmarkTest00003" in tp_rows


class TestSkipExisting:
    def test_second_run_skips_and_preserves_metrics(self, tmp_path):
        ws = build_workspace(tmp_path)
        run_evaluate_aggregate(ws, tmp_path / "out")

        metrics_path = (ws / "experiments" / "cwe-328" / "eval"
                        / "codefuse_eval_v2" / "metrics.json")
        marker = json.loads(metrics_path.read_text(encoding="utf-8"))
        marker["__marker__"] = "do-not-overwrite"
        metrics_path.write_text(json.dumps(marker), encoding="utf-8")

        run_evaluate_aggregate(ws, tmp_path / "out", skip_existing=True)
        preserved = json.loads(metrics_path.read_text(encoding="utf-8"))
        assert preserved["__marker__"] == "do-not-overwrite"

    def test_no_skip_existing_reevaluates(self, tmp_path):
        ws = build_workspace(tmp_path)
        run_evaluate_aggregate(ws, tmp_path / "out")

        metrics_path = (ws / "experiments" / "cwe-328" / "eval"
                        / "codefuse_eval_v2" / "metrics.json")
        marker = json.loads(metrics_path.read_text(encoding="utf-8"))
        marker["__marker__"] = "do-not-overwrite"
        metrics_path.write_text(json.dumps(marker), encoding="utf-8")

        run_evaluate_aggregate(ws, tmp_path / "out", skip_existing=False)
        fresh = json.loads(metrics_path.read_text(encoding="utf-8"))
        assert "__marker__" not in fresh
        assert_matches_golden(fresh, FIXTURES / "golden" / "cwe328_metrics.json")


class TestCliErrorPaths:
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(PIPELINE_CLI), *args],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )

    def test_unknown_cwe_token_exits_2(self):
        proc = self.run_cli("--tool", "codefuse", "--cwe", "999", "--stages", "evaluate")
        assert proc.returncode == 2
        assert "Unknown CWE token" in (proc.stdout + proc.stderr)

    def test_invalid_stage_exits_2(self):
        proc = self.run_cli("--tool", "codefuse", "--cwe", "022", "--stages", "nonsense")
        assert proc.returncode == 2
        assert "Unknown stages" in (proc.stdout + proc.stderr)

    def test_db_with_both_tools_exits_2(self):
        proc = self.run_cli("--tool", "both", "--cwe", "all", "--db", "dataset/x")
        assert proc.returncode == 2
        assert "both" in (proc.stdout + proc.stderr)

    def test_aggregate_name_with_both_tools_exits_2(self):
        proc = self.run_cli(
            "--tool", "both", "--cwe", "all",
            "--stages", "aggregate", "--aggregate-name", "combined.json",
        )
        assert proc.returncode == 2
        assert "--aggregate-name" in (proc.stdout + proc.stderr)

    def test_report_without_aggregate_exits_1(self, tmp_path):
        ws = build_workspace(tmp_path)
        proc = self.run_cli(
            "--tool", "codefuse", "--cwe", "all",
            "--stages", "evaluate,report",
            "--manifest", str(ws / "manifest.yml"),
            "--out-root", str(tmp_path / "out"),
        )
        assert proc.returncode == 1
        assert "report requires the aggregate stage" in (proc.stdout + proc.stderr)
