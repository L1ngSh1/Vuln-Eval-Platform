"""VEP Pipeline: unified experiment orchestrator (Phase 3 / M3.3).

One entry point for: tool execution -> normalization -> v2 evaluation ->
multi-CWE aggregation -> v2 reporting. Manifest-driven; stage selection lets
machines without the analysis tools still evaluate existing findings.

Does not delete or bypass the legacy scripts; the switchover of run_eval.sh /
eval_checker.sh happens in M3.4 after the parity gate.
"""

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vep.core.manifest import CweEntry, Manifest, load_manifest
from vep.evaluation.aggregate import (
    aggregate_metrics,
    load_metrics_json,
    write_aggregate_json,
)
from vep.evaluation.evaluator import evaluate_findings_with_details
from vep.evaluation.findings import load_findings_csv
from vep.evaluation.ground_truth import load_expected_cases
from vep.evaluation.metrics import write_evaluation_details, write_metrics_json
from vep.tools.base import Tool, WARN_MARKER
from vep.tools.codefuse import CodeFuseTool
from vep.tools.codeql import CodeQLTool
from vep.tools.config import load_tools_config, ToolsConfig

STAGES = ("run", "evaluate", "aggregate", "report")

RESULTS_SUBDIR = {"codefuse": "results/codefuse-query", "codeql": "results/codeql"}
FINDINGS_CSV_NAME = {
    "codefuse": lambda entry: f"cwe{entry.id}_codefuse.csv",
    "codeql": lambda entry: f"cwe{entry.id}.csv",
}
DEFAULT_EVAL_DIR_NAME = {"codefuse": "codefuse_eval_v2", "codeql": "codeql_eval_v2"}


@dataclass
class PipelineOptions:
    """Arguments for run_pipeline()."""
    tool: str                                    # codefuse | codeql | both
    cwe_tokens: List[str] = field(default_factory=lambda: ["all"])
    stages: List[str] = field(default_factory=lambda: ["run", "evaluate", "aggregate"])
    manifest_file: Optional[Path] = None
    tools_config_file: Optional[Path] = None
    db_overrides: Dict[str, Optional[Path]] = field(default_factory=dict)
    fp_mode: str = "all_non_gt"
    eval_dir_names: Dict[str, str] = field(default_factory=dict)
    aggregate_out_root: Path = Path("reports/data")
    aggregate_name: Optional[str] = None
    report_out_dir: Path = Path("reports")
    keep_going: bool = False
    skip_existing: bool = True
    run_timeout_seconds: int = 3600


@dataclass
class ToolPipelineResult:
    """Outcome of one tool branch, including its aggregate artifact."""

    tool: str
    failures: List[str] = field(default_factory=list)
    aggregate_path: Optional[Path] = None


def run_pipeline(options: PipelineOptions, project_root: Path) -> int:
    """Execute the selected stages. Returns 0 on success, 1 on failures."""
    if options.tool == "both" and options.aggregate_name:
        raise ValueError(
            "--aggregate-name 不能与 --tool both 同用；"
            "请使用默认的分工具聚合文件名。"
        )
    if "report" in options.stages and "aggregate" not in options.stages:
        print("❌ report requires the aggregate stage")
        return 1

    manifest = load_manifest(options.manifest_file, project_root)
    tools_config = load_tools_config(options.tools_config_file, project_root)
    entries = manifest.resolve(options.cwe_tokens)
    tool_names = ["codefuse", "codeql"] if options.tool == "both" else [options.tool]

    print("=" * 60)
    print(f"VEP Pipeline | tool={options.tool} | cwes={len(entries)}"
          f" | stages={'+'.join(options.stages)}")
    print("=" * 60)

    failures: List[str] = []
    tool_results: Dict[str, ToolPipelineResult] = {}
    for tool_name in tool_names:
        result = _run_single_tool(
            tool_name, options, manifest, tools_config, entries, project_root
        )
        tool_results[tool_name] = result
        failures.extend(result.failures)

    if "report" in options.stages:
        failures.extend(_generate_reports(tool_names, tool_results, options, project_root))

    if failures:
        print(f"\n❌ Pipeline finished with {len(failures)} failure(s):")
        for failure in failures:
            print(f"   - {failure}")
        return 1
    print("\n✅ Pipeline finished successfully.")
    return 0


def _run_single_tool(
    tool_name: str,
    options: PipelineOptions,
    manifest: Manifest,
    tools_config: ToolsConfig,
    entries: List[CweEntry],
    project_root: Path,
) -> ToolPipelineResult:
    failures: List[str] = []
    result = ToolPipelineResult(tool=tool_name, failures=failures)
    print(f"\n########## {tool_name} ##########")

    tool = _build_tool(tool_name, options, tools_config, project_root)
    db_path = options.db_overrides.get(tool_name) or getattr(tools_config.databases, tool_name)

    if "run" in options.stages:
        fatal = _check_environment(tool)
        if fatal:
            failures.append(f"{tool_name}: environment check failed")
            return result

    evaluated: List[CweEntry] = []
    for index, entry in enumerate(entries, start=1):
        tag = f"[{tool_name} {index}/{len(entries)}] {entry.name}"
        if entry.experiments_directory is None:
            print(f"{tag} ❌ manifest 缺少 experiments.directory")
            failures.append(f"{tool_name} {entry.name}: no experiments.directory")
            continue

        metrics_path = _eval_dir(entry, tool_name, options) / "metrics.json"
        findings_csv = _findings_csv(entry, tool_name)

        if options.skip_existing and metrics_path.is_file() \
                and ("evaluate" in options.stages or "run" in options.stages):
            print(f"{tag} ⏭️  metrics 已存在，跳过: {metrics_path}")
            evaluated.append(entry)
            continue

        if "run" in options.stages:
            if not _run_tool(tool, entry, db_path, findings_csv, tag):
                failures.append(f"{tool_name} {entry.name}: run/standardize failed")
                if not options.keep_going:
                    return result
                continue

        if "evaluate" in options.stages:
            if not _evaluate(tool_name, entry, findings_csv, manifest, options, tag):
                failures.append(f"{tool_name} {entry.name}: evaluation failed")
                if not options.keep_going:
                    return result
                continue
        evaluated.append(entry)

    if "aggregate" in options.stages:
        if not evaluated:
            failures.append(f"{tool_name}: nothing to aggregate")
        else:
            result.aggregate_path = _aggregate(
                tool_name, evaluated, manifest, options, project_root
            )
    return result


def _build_tool(
    tool_name: str,
    options: PipelineOptions,
    tools_config: ToolsConfig,
    project_root: Path,
) -> Tool:
    if tool_name == "codefuse":
        return CodeFuseTool(
            tools_config,
            project_root,
            run_timeout_seconds=options.run_timeout_seconds,
        )
    if tool_name == "codeql":
        return CodeQLTool(
            tools_config,
            project_root,
            run_timeout_seconds=options.run_timeout_seconds,
        )
    raise ValueError(f"Unknown tool: {tool_name}")


def _check_environment(tool: Tool) -> List[str]:
    problems = tool.check_environment()
    if problems:
        print(f"[{tool.name}] 环境检查发现问题:")
        for problem in problems:
            print(f"   {problem}")
    fatal = [p for p in problems if not p.startswith(WARN_MARKER)]
    if not fatal:
        print(f"[{tool.name}] ✅ 环境检查通过")
    return fatal


def _run_tool(
    tool: Tool,
    entry: CweEntry,
    db_path: Path,
    findings_csv: Path,
    tag: str,
) -> bool:
    out_dir = findings_csv.parent
    print(f"{tag} ▶️  运行工具 (db={db_path}) ...")
    try:
        result = tool.run(entry, db_path, out_dir)
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"{tag} ❌ {exc}")
        return False
    if result.returncode != 0 or result.raw_output is None:
        print(f"{tag} ❌ 工具退出码 {result.returncode}，日志: {result.log_file}")
        return False
    try:
        written = tool.standardize(result, findings_csv)
    except (RuntimeError, FileNotFoundError) as exc:
        print(f"{tag} ❌ 标准化失败: {exc}")
        return False
    print(f"{tag} ✅ 工具完成，标准化输出: {written}")
    return True


def _evaluate(
    tool_name: str,
    entry: CweEntry,
    findings_csv: Path,
    manifest: Manifest,
    options: PipelineOptions,
    tag: str,
) -> bool:
    if not findings_csv.is_file():
        print(f"{tag} ❌ findings CSV 不存在: {findings_csv}")
        return False
    eval_dir = _eval_dir(entry, tool_name, options)
    metrics_path = eval_dir / "metrics.json"
    try:
        findings = load_findings_csv(findings_csv, tool=tool_name, cwe=entry.name)
        expected_cases = load_expected_cases(manifest.ground_truth_file, cwe=entry.name)
        result, details = evaluate_findings_with_details(
            findings=findings,
            expected_cases=expected_cases,
            tool=tool_name,
            cwe=entry.name,
            include_tn=True,
            fp_mode=options.fp_mode,
        )
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        write_metrics_json(result, metrics_path)
        write_evaluation_details(details, eval_dir)
    except (OSError, ValueError) as exc:
        print(f"{tag} ❌ 评估失败: {exc}")
        return False
    print(f"{tag} ✅ TP={result.tp} FP={result.fp} FN={result.fn}"
          f" P={result.precision:.4f} R={result.recall:.4f} F1={result.f1:.4f}"
          f" → {metrics_path}")
    return True


def _aggregate(
    tool_name: str,
    entries: List[CweEntry],
    manifest: Manifest,
    options: PipelineOptions,
    project_root: Path,
) -> Path:
    metrics_list = []
    for entry in entries:
        metrics_path = _eval_dir(entry, tool_name, options) / "metrics.json"
        metrics_list.append(load_metrics_json(metrics_path))
    aggregate = aggregate_metrics(metrics_list, tool=tool_name, strict=False)
    out_root = options.aggregate_out_root
    if not out_root.is_absolute():
        out_root = project_root / out_root
    name = options.aggregate_name or _aggregate_name(tool_name, entries, manifest, options)
    out_path = out_root / name
    write_aggregate_json(aggregate, out_path)
    overall = aggregate["overall"]
    print(f"\n[{tool_name}] 聚合 {aggregate['included_count']} 个 CWE → {out_path}")
    print(f"[{tool_name}] Overall: TP={overall['tp']} FP={overall['fp']} FN={overall['fn']}"
          f" P={overall['precision']:.4f} R={overall['recall']:.4f} F1={overall['f1']:.4f}")
    return out_path


def _generate_reports(
    tool_names: List[str],
    tool_results: Dict[str, ToolPipelineResult],
    options: PipelineOptions,
    project_root: Path,
) -> List[str]:
    """Generate compatible single-tool reports or a dual-tool report set."""
    failures: List[str] = []
    report_dir = options.report_out_dir
    if not report_dir.is_absolute():
        report_dir = project_root / report_dir

    available = {
        name: result.aggregate_path
        for name, result in tool_results.items()
        if result.aggregate_path is not None
    }

    if len(tool_names) == 1:
        tool_name = tool_names[0]
        aggregate_path = available.get(tool_name)
        if aggregate_path is None:
            return [f"{tool_name}: report skipped because aggregate output is unavailable"]
        failure = _run_report([aggregate_path], report_dir, project_root)
        return [failure] if failure else []

    # In dual-tool mode, keep standalone reports for every successful branch.
    for tool_name in tool_names:
        aggregate_path = available.get(tool_name)
        if aggregate_path is None:
            continue
        failure = _run_report([aggregate_path], report_dir / tool_name, project_root)
        if failure:
            failures.append(failure)

    missing = [name for name in tool_names if name not in available]
    if missing:
        failures.append(
            "combined report not generated; missing aggregate output for: "
            + ", ".join(missing)
        )
        return failures

    combined_paths = [available[name] for name in tool_names]
    failure = _run_report(combined_paths, report_dir, project_root)
    if failure:
        failures.append(failure)
    return failures


def _run_report(
    aggregate_paths: List[Path],
    report_dir: Path,
    project_root: Path,
) -> Optional[str]:
    cmd = [
        sys.executable,
        str(project_root / "scripts/reporting/generate_report_v2.py"),
        "--metrics", *(str(path) for path in aggregate_paths),
        "--out-dir", str(report_dir),
    ]
    print(f"[report] 生成报告: {' '.join(cmd[1:])}")
    try:
        proc = subprocess.run(cmd, check=False)
    except OSError as exc:
        return f"report generation failed for {report_dir}: {exc}"
    if proc.returncode != 0:
        return (
            f"report generation failed for {report_dir} "
            f"(returncode={proc.returncode})"
        )
    return None


def _eval_dir(entry: CweEntry, tool_name: str, options: PipelineOptions) -> Path:
    eval_dir_name = options.eval_dir_names.get(tool_name) or DEFAULT_EVAL_DIR_NAME[tool_name]
    return entry.experiments_directory / "eval" / eval_dir_name


def _findings_csv(entry: CweEntry, tool_name: str) -> Path:
    return entry.experiments_directory / RESULTS_SUBDIR[tool_name] / FINDINGS_CSV_NAME[tool_name](entry)


def _aggregate_name(
    tool_name: str,
    entries: List[CweEntry],
    manifest: Manifest,
    options: PipelineOptions,
) -> str:
    # 全量（与 manifest 条目数一致）使用 _all 命名，其余子集使用 _subset
    suffix = "all" if len(entries) == len(manifest.cwes) else "subset"
    return f"metrics_v2_{tool_name}_{suffix}.json"
