"""VEP Reporting: Bilingual Markdown report generation.

Phase 2F: Generate English and Chinese evaluation reports supporting
dual-tool comparison.  Reports are self-contained Markdown files that
reference chart images in a relative ``figs/`` directory.
"""

from datetime import date
from pathlib import Path
from typing import List, Optional

from vep.reporting.report_generator import ReportData, ToolMetrics, tool_display_name


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt(v: float, digits: int = 4) -> str:
    """Format a float to fixed decimal places."""
    return f"{v:.{digits}f}"


def _pct(v: float) -> str:
    """Format a float as percentage string e.g. '72.70%'."""
    return f"{v * 100:.2f}%"


def _contract_section(report: ReportData, chinese=False) -> str:
    """Use serialized mode metrics, never silently recompute a different scope."""
    scope = report.sample_scope
    title = "指标口径与样本范围" if chinese else "Metric contract and sample population"
    note = ("范围外告警保留；旧 fpr 是自定义口径。fpr_in_scope 分母缺失或为零时为 N/A。"
            if chinese else "Outside-scope findings are retained. Legacy fpr is custom. fpr_in_scope is N/A when its denominator is missing or zero.")
    text = (f"\n## {title}\n\n"
            f"- fp_mode: `{report.fp_mode}`; metric_contract: `{report.metric_contract}`\n"
            f"- sample_scope: unit=`{scope.get('unit', 'unknown')}`; "
            f"dataset_sha256=`{scope.get('dataset_sha256') or 'unknown'}`; verified=`{scope.get('verified', False)}`\n"
            f"- {note}\n"
            "- fpr_in_scope = FP_in_scope / (FP_in_scope + TN_in_scope).\n"
            "- all_non_gt includes outside-scope findings; in_scope uses labelled cases only.\n\n"
            "| Tool | fp_mode | TP | FP | FN | Precision | Recall | F1 | outside_scope_findings | fpr_in_scope |\n"
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
    for tool in report.tools:
        tm = report.overall.get(tool)
        if tm is None:
            continue
        for mode in ("all_non_gt", "in_scope"):
            values = tm.metric_modes.get(mode)
            if values is None:
                text += f"| {tool_display_name(tool)} | {mode} | N/A | N/A | N/A | N/A | N/A | N/A | {tm.outside_scope_findings if tm.outside_scope_findings is not None else 'unknown'} | N/A |\n"
                continue
            fpr = values.get("fpr_in_scope")
            text += (f"| {tool_display_name(tool)} | {mode} | {values['tp']} | {values['fp']} | {values['fn']} | "
                     f"{_fmt(values['precision'])} | {_fmt(values['recall'])} | {_fmt(values['f1'])} | "
                     f"{tm.outside_scope_findings} | {_fmt(fpr) if fpr is not None else 'N/A'} |\n")
    text += "\nCWE sample_scope fingerprints:\n"
    for cwe, population in sorted(scope.get("cwes", {}).items()):
        text += (f"- {cwe}: scope_sha256=`{population.get('scope_sha256', 'unknown')}`; "
                 f"positive={population.get('positive', 'unknown')}; negative={population.get('negative', 'unknown')}.\n")
    return text + "\n"


def _tool_overall_block_en(tool: str, tm: ToolMetrics) -> str:
    return (
        f"### {tool_display_name(tool)}\n\n"
        f"| Metric | Value |\n"
        f"|---|---|\n"
        f"| Precision | {_fmt(tm.precision)} ({_pct(tm.precision)}) |\n"
        f"| Recall | {_fmt(tm.recall)} ({_pct(tm.recall)}) |\n"
        f"| F1 | {_fmt(tm.f1)} ({_pct(tm.f1)}) |\n"
        f"| TP | {tm.tp} |\n"
        f"| FP | {tm.fp} |\n"
        f"| FN | {tm.fn} |\n"
        f"| fp_mode | {tm.fp_mode} |\n"
        f"| outside_scope_findings | {tm.outside_scope_findings if tm.outside_scope_findings is not None else 'unknown'} |\n"
        f"| fpr_in_scope | {_fmt(tm.fpr_in_scope) if tm.fpr_in_scope is not None else 'N/A'} |\n"
        f"| Legacy fpr | {_fmt(tm.fpr)} — {tm.fpr_definition} |\n"
    )


def _tool_overall_block_zh(tool: str, tm: ToolMetrics) -> str:
    return (
        f"### {tool_display_name(tool)}\n\n"
        f"| 指标 | 值 |\n"
        f"|---|---|\n"
        f"| 准确率（Precision） | {_fmt(tm.precision)} ({_pct(tm.precision)}) |\n"
        f"| 召回率（Recall） | {_fmt(tm.recall)} ({_pct(tm.recall)}) |\n"
        f"| F1 分数 | {_fmt(tm.f1)} ({_pct(tm.f1)}) |\n"
        f"| 真阳性（TP） | {tm.tp} |\n"
        f"| 误报（FP） | {tm.fp} |\n"
        f"| 漏报（FN） | {tm.fn} |\n"
        f"| fp_mode | {tm.fp_mode} |\n"
        f"| outside_scope_findings | {tm.outside_scope_findings if tm.outside_scope_findings is not None else 'unknown'} |\n"
        f"| fpr_in_scope | {_fmt(tm.fpr_in_scope) if tm.fpr_in_scope is not None else 'N/A'} |\n"
        f"| 历史 fpr | {_fmt(tm.fpr)} — {tm.fpr_definition} |\n"
    )


def _cwe_comparison_table(report: ReportData) -> str:
    """Build a Markdown table comparing all tools across all CWEs."""
    import re

    def sort_key(cwe: str):
        m = re.search(r"(\d+)", cwe)
        return int(m.group(1)) if m else 0

    cwes = sorted(report.cwes.keys(), key=sort_key)
    tools = report.tools

    # Header
    header = "| CWE |"
    sep = "|---|"
    for tool in tools:
        label = tool_display_name(tool)
        header += f" {label} P | {label} R | {label} F1 |"
        sep += "---|---|---|"
    header += "\n"
    sep += "\n"

    rows = ""
    for cwe in cwes:
        entry = report.cwes[cwe]
        row = f"| {cwe} |"
        for tool in tools:
            tm = entry.tools.get(tool)
            if tm:
                row += f" {_fmt(tm.precision)} | {_fmt(tm.recall)} | {_fmt(tm.f1)} |"
            else:
                row += " — | — | — |"
        rows += row + "\n"

    return header + sep + rows


def _best_worst_analysis(report: ReportData) -> dict:
    """Find best/worst precision CWE per tool."""
    import re

    result = {}
    for tool in report.tools:
        precisions = []
        for cwe, entry in report.cwes.items():
            tm = entry.tools.get(tool)
            if tm:
                precisions.append((cwe, tm.precision))
        if not precisions:
            continue
        precisions.sort(key=lambda x: x[1])
        result[tool] = {
            "best": [(c, p) for c, p in precisions if abs(p - precisions[-1][1]) < 1e-9],
            "worst": [(c, p) for c, p in precisions if abs(p - precisions[0][1]) < 1e-9],
        }
    return result


# ---------------------------------------------------------------------------
# English report
# ---------------------------------------------------------------------------

def generate_english_report(report: ReportData) -> str:
    """Generate English Markdown evaluation report."""
    today = date.today().isoformat()
    tools = report.tools
    n_cwes = len(report.cwes)
    tool_list = ", ".join(tool_display_name(tool) for tool in tools)

    sections: List[str] = []

    # Title
    sections.append(f"# Static Analysis Evaluation Report\n")
    sections.append(f"> **Tools evaluated:** {tool_list}  \n")
    sections.append(f"> **CWEs covered:** {n_cwes}  \n")
    sections.append(f"> **Generated:** {today}\n")
    sections.append(_contract_section(report))

    # Overall Performance
    sections.append("\n---\n\n## Overall Performance\n")
    for tool in tools:
        tm = report.overall.get(tool)
        if tm:
            sections.append(_tool_overall_block_en(tool, tm))

    # Best / Worst
    bw = _best_worst_analysis(report)
    if bw:
        sections.append("\n---\n\n## CWE-level Analysis\n")
        for tool, info in bw.items():
            best_str = ", ".join(f"{c} ({_fmt(p)})" for c, p in info["best"])
            worst_str = ", ".join(f"{c} ({_fmt(p)})" for c, p in info["worst"])
            sections.append(f"**{tool_display_name(tool)}:**\n")
            sections.append(f"- Best precision: {best_str}\n")
            sections.append(f"- Lowest precision: {worst_str}\n\n")

    # Comparison table
    sections.append("\n---\n\n## Detailed Comparison\n\n")
    sections.append(_cwe_comparison_table(report))

    # Figures
    sections.append("\n---\n\n## Figures\n\n")
    sections.append("### Overall Performance\n![Overall](figs/overall_metrics.png)\n\n")
    sections.append("### Performance by CWE\n![Metrics](figs/metrics_by_cwe.png)\n\n")
    sections.append("### Detection Counts\n![Counts](figs/counts_by_cwe.png)\n\n")
    if len(tools) >= 2:
        sections.append("### Precision Comparison\n![Precision](figs/precision_comparison.png)\n\n")

    if any(tm.metric_modes for tm in report.overall.values()):
        sections.append("### Both FP Definitions\n![FP modes](figs/metric_modes_comparison.png)\n\n")

    # Technical interpretation
    sections.append("\n---\n\n## Technical Interpretation\n\n")
    sections.append(
        "This report evaluates the detection capabilities of static analysis tools "
        "on the OWASP Benchmark dataset.\n\n"
    )
    for tool in tools:
        tm = report.overall.get(tool)
        if tm:
            sections.append(
                f"**{tool_display_name(tool)}** achieved a recall of **{_fmt(tm.recall)}** "
                f"with a precision of **{_fmt(tm.precision)}** "
                f"(F1 = {_fmt(tm.f1)}).\n\n"
            )

    if len(tools) >= 2:
        sections.append(
            "The dual-tool comparison provides insights into the trade-offs between "
            "precision and recall across different vulnerability categories.\n\n"
        )

    # Reproducibility
    sections.append("\n---\n\n## Reproducibility\n\n")
    sections.append("All results are automatically generated from the VEP evaluation pipeline.\n\n")

    # Author
    sections.append(f"\n---\n\n**L1ngSh1**  \nGenerated on: {today}\n")

    return "".join(sections)


# ---------------------------------------------------------------------------
# Chinese report
# ---------------------------------------------------------------------------

def generate_chinese_report(report: ReportData) -> str:
    """Generate Chinese Markdown evaluation report."""
    today = date.today().isoformat()
    tools = report.tools
    n_cwes = len(report.cwes)
    tool_list = ", ".join(tool_display_name(tool) for tool in tools)

    sections: List[str] = []

    # Title
    sections.append(f"# 静态分析工具漏洞检测评估报告\n")
    sections.append(f"> **评估工具：** {tool_list}  \n")
    sections.append(f"> **覆盖 CWE：** {n_cwes} 种  \n")
    sections.append(f"> **生成日期：** {today}\n")
    sections.append(_contract_section(report, chinese=True))

    # Overall
    sections.append("\n---\n\n## 总体表现\n")
    for tool in tools:
        tm = report.overall.get(tool)
        if tm:
            sections.append(_tool_overall_block_zh(tool, tm))

    # Best / Worst
    bw = _best_worst_analysis(report)
    if bw:
        sections.append("\n---\n\n## 各 CWE 类型分析\n")
        for tool, info in bw.items():
            best_str = ", ".join(f"{c}（{_fmt(p)}）" for c, p in info["best"])
            worst_str = ", ".join(f"{c}（{_fmt(p)}）" for c, p in info["worst"])
            sections.append(f"**{tool_display_name(tool)}：**\n")
            sections.append(f"- 准确率最高：{best_str}\n")
            sections.append(f"- 准确率最低：{worst_str}\n\n")

    # Comparison table
    sections.append("\n---\n\n## 详细对比\n\n")
    sections.append(_cwe_comparison_table(report))

    # Figures
    sections.append("\n---\n\n## 图表展示\n\n")
    sections.append("### 总体表现\n![Overall](figs/overall_metrics.png)\n\n")
    sections.append("### 各 CWE 指标对比\n![Metrics](figs/metrics_by_cwe.png)\n\n")
    sections.append("### 检测数量统计\n![Counts](figs/counts_by_cwe.png)\n\n")
    if len(tools) >= 2:
        sections.append("### 准确率工具对比\n![Precision](figs/precision_comparison.png)\n\n")

    if any(tm.metric_modes for tm in report.overall.values()):
        sections.append("### 两种 FP 口径\n![FP modes](figs/metric_modes_comparison.png)\n\n")

    # Technical interpretation
    sections.append("\n---\n\n## 技术分析与总结\n\n")
    sections.append(
        "本报告评估了静态分析工具在 OWASP Benchmark 数据集上的漏洞检测能力。\n\n"
    )
    for tool in tools:
        tm = report.overall.get(tool)
        if tm:
            sections.append(
                f"**{tool_display_name(tool)}** 达到了 **{_fmt(tm.recall)}** 的召回率，"
                f"准确率为 **{_fmt(tm.precision)}**"
                f"（F1 = {_fmt(tm.f1)}）。\n\n"
            )

    if len(tools) >= 2:
        sections.append(
            "双工具对比有助于深入理解不同漏洞类型上准确率与召回率之间的权衡关系。\n\n"
        )

    sections.append(
        "这些指标仅描述本报告记录的 Benchmark 样本范围，不证明真实工程零漏报或工具的普遍优劣。\n\n"
    )

    # Reproducibility
    sections.append("\n---\n\n## 可复现性说明\n\n")
    sections.append("所有结果均由 VEP 自动化评估流程生成。\n\n")

    # Author
    sections.append(f"\n---\n\n**L1ngSh1**  \n生成日期：{today}\n")

    return "".join(sections)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_reports(
    report: ReportData,
    out_dir: Path,
    en_filename: str = "report.md",
    zh_filename: str = "report_zh.md",
) -> List[Path]:
    """Generate and write bilingual Markdown reports.

    Args:
        report: Unified ReportData.
        out_dir: Output directory.
        en_filename: English report filename.
        zh_filename: Chinese report filename.

    Returns:
        List of paths to generated report files.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    generated: List[Path] = []

    en_path = out_dir / en_filename
    en_content = generate_english_report(report)
    en_path.write_text(en_content, encoding="utf-8")
    generated.append(en_path)

    zh_path = out_dir / zh_filename
    zh_content = generate_chinese_report(report)
    zh_path.write_text(zh_content, encoding="utf-8")
    generated.append(zh_path)

    return generated
