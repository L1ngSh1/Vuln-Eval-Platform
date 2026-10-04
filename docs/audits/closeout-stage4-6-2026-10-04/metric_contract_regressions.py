"""Closeout contract: standard in-scope FPR, explicit populations and merges."""

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from vep.core.models import ExpectedCase, Finding
from vep.evaluation.aggregate import aggregate_metrics
from vep.evaluation.evaluator import evaluate_findings
from vep.evaluation.ground_truth import load_expected_cases
from vep.evaluation.metrics import eval_result_to_dict
from vep.reporting.report_generator import load_metrics, merge_report_data
from vep.reporting.text_report import generate_chinese_report, generate_english_report


def result(mode="all_non_gt", include_tn=True, tool="codeql", cwe="CWE-901"):
    expected = [ExpectedCase("BenchmarkTest00001", cwe, True),
                ExpectedCase("BenchmarkTest00002", cwe, False),
                ExpectedCase("BenchmarkTest00003", cwe, False)]
    findings = [Finding("BenchmarkTest00001", cwe, "a.java"),
                Finding("BenchmarkTest99999", cwe, "outside.java")]
    return evaluate_findings(findings, expected, tool, cwe, include_tn, mode)


def report_file(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return load_metrics(p)


def test_standard_fpr_excludes_outside_scope_without_changing_legacy():
    value = result()
    assert value.fpr == 0.3333
    assert value.fpr_in_scope == 0.0


@pytest.mark.parametrize("tn", [False, True])
def test_undefined_standard_fpr_is_null(tn):
    expected = [ExpectedCase("BenchmarkTest00001", "CWE-901", True)]
    value = evaluate_findings([], expected, "codeql", "CWE-901", include_tn=tn)
    assert eval_result_to_dict(value)["fpr_in_scope"] is None


def test_missing_tn_does_not_become_zero_fpr():
    assert eval_result_to_dict(result(include_tn=False))["fpr_in_scope"] is None


@pytest.mark.parametrize("mode", ["all_non_gt", "in_scope"])
def test_serializer_publishes_both_modes_and_population(mode):
    data = eval_result_to_dict(result(mode))
    assert data["metric_contract"] == "vep.metrics.v1"
    assert data["fp_mode"] == mode
    assert data["metric_modes"]["all_non_gt"]["fp"] == 1
    assert data["metric_modes"]["in_scope"]["fp"] == 0
    assert data["outside_scope_findings"] == 1
    assert data["sample_scope"]["unit"] == "testcase_per_cwe"
    assert data["sample_scope"]["positive"] == 1
    assert data["sample_scope"]["negative"] == 2
    assert "custom" in data["fpr_definition"] if mode == "all_non_gt" else "FP_in_scope" in data["fpr_definition"]


def test_ground_truth_fingerprint_distinguishes_equal_size_populations(tmp_path):
    a = tmp_path / "a.csv"
    b = tmp_path / "b.csv"
    a.write_text("BenchmarkTest00001,other,true,901\nBenchmarkTest00002,other,false,901\n")
    b.write_text("BenchmarkTest00001,other,true,901\nBenchmarkTest00003,other,false,901\n")
    def metrics(path):
        return eval_result_to_dict(evaluate_findings([], load_expected_cases(path, "901"), "codeql", "CWE-901"))
    x, y = metrics(a), metrics(b)
    assert x["sample_scope"]["dataset_sha256"] != y["sample_scope"]["dataset_sha256"]
    assert x["sample_scope"]["scope_sha256"] != y["sample_scope"]["scope_sha256"]


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("difference", ["fp_mode", "dataset", "tool"])
def test_aggregate_rejects_incompatible_inputs_even_non_strict(strict, difference):
    a = eval_result_to_dict(result(cwe="CWE-901"))
    b = eval_result_to_dict(result(cwe="CWE-902"))
    if difference == "fp_mode":
        b["fp_mode"] = "in_scope"
    elif difference == "dataset":
        a["sample_scope"]["dataset_sha256"] = "dataset-a"
        b["sample_scope"]["dataset_sha256"] = "dataset-b"
    else:
        b["tool"] = "codefuse"
    with pytest.raises(ValueError):
        aggregate_metrics([a, b], strict=strict)


def test_aggregate_retains_scope_counts_and_dual_metrics():
    data = aggregate_metrics([eval_result_to_dict(result(cwe="CWE-901")),
                              eval_result_to_dict(result(cwe="CWE-902"))])
    assert data["overall"]["fp_in_scope"] == 0
    assert data["overall"]["outside_scope_findings"] == 2
    assert data["overall"]["fpr_in_scope"] == 0
    assert data["metric_modes"]["all_non_gt"]["fp"] == 2
    assert data["metric_modes"]["in_scope"]["fp"] == 0
    assert len(data["sample_scope"]["cwes"]) == 2


def test_partial_tn_cannot_support_standard_fpr():
    a = eval_result_to_dict(result(cwe="CWE-901"))
    b = eval_result_to_dict(result(cwe="CWE-902", include_tn=False))
    data = aggregate_metrics([a, b])
    assert data["overall"]["fpr_in_scope"] is None
    assert "tn" not in data["overall"]


@pytest.mark.parametrize("difference", ["fp_mode", "dataset", "scope", "cwes", "duplicate_tool"])
def test_report_merge_rejects_incompatible_or_overwriting_inputs(tmp_path, difference):
    a = eval_result_to_dict(result(tool="codeql"))
    b = eval_result_to_dict(result(tool="codefuse"))
    if difference == "fp_mode":
        b["fp_mode"] = "in_scope"
    elif difference == "dataset":
        a["sample_scope"]["dataset_sha256"] = "a"
        b["sample_scope"]["dataset_sha256"] = "b"
    elif difference == "scope":
        b["sample_scope"]["scope_sha256"] = "different population"
    elif difference == "cwes":
        b["cwe"] = "CWE-902"
    else:
        b["tool"] = "codeql"
    with pytest.raises(ValueError):
        merge_report_data([report_file(tmp_path, "a.json", a), report_file(tmp_path, "b.json", b)])


def test_report_retains_contract_in_both_languages(tmp_path):
    data = eval_result_to_dict(result())
    report = report_file(tmp_path, "metrics.json", data)
    assert report.fp_mode == "all_non_gt"
    assert report.overall["codeql"].outside_scope_findings == 1
    assert report.overall["codeql"].fpr_in_scope == 0.0
    assert report.sample_scope["cwes"]["CWE-901"] == data["sample_scope"]
    for text in (generate_chinese_report(report), generate_english_report(report)):
        for token in ("all_non_gt", "in_scope", "outside_scope_findings", "fpr_in_scope", "sample_scope"):
            assert token in text


def test_charts_disclose_selected_mode_and_population(tmp_path, monkeypatch):
    from matplotlib.axes import Axes
    from vep.reporting.plot_generator import generate_all_plots

    titles = []
    original = Axes.set_title
    def capture(self, label, *args, **kwargs):
        titles.append(label)
        return original(self, label, *args, **kwargs)
    monkeypatch.setattr(Axes, "set_title", capture)
    report = report_file(tmp_path, "metrics.json", eval_result_to_dict(result()))
    plots = generate_all_plots(report, tmp_path / "figs")
    assert plots
    assert any("all_non_gt" in title and "scope=" in title for title in titles)
    assert (tmp_path / "figs/metric_modes_comparison.png").is_file()


def test_real_report_cli_creates_json_and_bilingual_reports_in_new_directory(tmp_path):
    metrics = tmp_path / "metrics.json"
    metrics.write_text(json.dumps(eval_result_to_dict(result())))
    root = Path(__file__).resolve().parents[2]
    out = tmp_path / "new-report"
    process = subprocess.run([sys.executable, str(root / "scripts/reporting/generate_report_v2.py"),
                              "--metrics", str(metrics), "--out-dir", str(out), "--no-plots"],
                             text=True, capture_output=True)
    assert process.returncode == 0, process.stdout + process.stderr
    serialized = json.loads((out / "report_data.json").read_text())
    assert serialized["fp_mode"] == "all_non_gt"
    assert serialized["overall"]["codeql"]["fpr_in_scope"] == 0
    for name in ("report.md", "report_zh.md"):
        assert "in_scope" in (out / name).read_text()


def test_verified_same_population_merges_both_tools(tmp_path):
    gt = tmp_path / "gt.csv"
    gt.write_text("BenchmarkTest00001,other,true,901\nBenchmarkTest00002,other,false,901\n")
    reports = []
    for tool in ("codeql", "codefuse"):
        data = eval_result_to_dict(evaluate_findings([], load_expected_cases(gt, "901"), tool, "CWE-901"))
        reports.append(report_file(tmp_path, f"{tool}.json", data))
    merged = merge_report_data(reports)
    assert merged.tools == ["codefuse", "codeql"]
    assert merged.sample_scope["verified"] is True


def test_unknown_population_cannot_be_assumed_equal(tmp_path):
    reports = [report_file(tmp_path, f"{tool}.json", eval_result_to_dict(result(tool=tool)))
               for tool in ("codeql", "codefuse")]
    with pytest.raises(ValueError, match="Unverified"):
        merge_report_data(reports)
