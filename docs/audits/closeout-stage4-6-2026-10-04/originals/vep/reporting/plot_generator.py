"""VEP Reporting: Dual-tool comparison chart generation.

Phase 2F: Generate matplotlib/seaborn charts that compare multiple tools
side-by-side for each CWE and overall.

Charts produced:
1. metrics_by_cwe.png  — Precision/Recall/F1 per CWE, grouped by tool
2. counts_by_cwe.png   — TP/FP/FN per CWE, grouped by tool
3. overall_metrics.png — Overall Precision/Recall/F1, dual-tool bars
4. precision_comparison.png — Precision per CWE, tool comparison line chart
"""

from pathlib import Path
from typing import List

import numpy as np

from vep.reporting.report_generator import ReportData, tool_display_name

# Tool color palette — harmonious, distinct, accessible
TOOL_COLORS = {
    "codeql":   {"primary": "#4C72B0", "accent": "#7BA3D9"},
    "codefuse": {"primary": "#DD8452", "accent": "#EDAB82"},
}
DEFAULT_COLOR = {"primary": "#55A868", "accent": "#88C89A"}

METRIC_COLORS = {
    "Precision": "#4C72B0",
    "Recall":    "#DD8452",
    "F1":        "#55A868",
}

COUNT_COLORS = {
    "TP": "#4C72B0",
    "FP": "#C44E52",
    "FN": "#8172B3",
}


def _get_tool_color(tool: str) -> dict:
    return TOOL_COLORS.get(tool, DEFAULT_COLOR)


def _sorted_cwes(report: ReportData) -> List[str]:
    """Return CWE keys sorted numerically."""
    import re

    def sort_key(cwe: str):
        m = re.search(r"(\d+)", cwe)
        return int(m.group(1)) if m else 0

    return sorted(report.cwes.keys(), key=sort_key)


def generate_all_plots(report: ReportData, out_dir: Path) -> List[Path]:
    """Generate all report charts.

    Args:
        report: Unified ReportData.
        out_dir: Directory to write PNG files.

    Returns:
        List of paths to generated chart files.
    """
    # Lazy import so the module can be imported without matplotlib
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend
    import matplotlib.pyplot as plt
    import seaborn as sns

    sns.set_theme(style="whitegrid")
    plt.rcParams["figure.dpi"] = 120
    plt.rcParams["font.size"] = 10

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    generated: List[Path] = []

    cwes = _sorted_cwes(report)
    tools = report.tools

    if not cwes:
        return generated

    # ---------------------------------------------------------------
    # Chart 1: Metrics by CWE (Precision / Recall / F1 per tool)
    # ---------------------------------------------------------------
    fig, axes = plt.subplots(1, 3, figsize=(18, 6), sharey=True)
    metric_names = ["precision", "recall", "f1"]
    metric_labels = ["Precision", "Recall", "F1"]

    x = np.arange(len(cwes))
    n_tools = len(tools)
    width = 0.7 / max(n_tools, 1)

    for ax, metric_name, metric_label in zip(axes, metric_names, metric_labels):
        for i, tool in enumerate(tools):
            values = []
            for cwe in cwes:
                entry = report.cwes[cwe]
                tm = entry.tools.get(tool)
                values.append(getattr(tm, metric_name, 0.0) if tm else 0.0)

            offset = (i - (n_tools - 1) / 2) * width
            color = _get_tool_color(tool)["primary"]
            bars = ax.bar(
                x + offset, values, width, label=tool_display_name(tool), color=color
            )

            for bar in bars:
                h = bar.get_height()
                if h > 0:
                    ax.annotate(
                        f"{h:.2f}",
                        xy=(bar.get_x() + bar.get_width() / 2, h),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha="center", va="bottom", fontsize=7,
                    )

        ax.set_xticks(x)
        ax.set_xticklabels(cwes, rotation=45, ha="right")
        ax.set_ylim(0, 1.12)
        ax.set_title(metric_label, fontsize=13, weight="bold")
        ax.legend(fontsize=9)

    fig.suptitle("Performance by CWE", fontsize=15, weight="bold", y=1.02)
    plt.tight_layout()
    p = out_dir / "metrics_by_cwe.png"
    fig.savefig(p, bbox_inches="tight")
    plt.close(fig)
    generated.append(p)

    # ---------------------------------------------------------------
    # Chart 2: Detection counts by CWE (TP / FP / FN per tool)
    # ---------------------------------------------------------------
    fig, axes_row = plt.subplots(1, max(n_tools, 1), figsize=(8 * max(n_tools, 1), 6), sharey=True)
    if n_tools == 1:
        axes_row = [axes_row]

    count_fields = ["tp", "fp", "fn"]
    count_labels = ["TP", "FP", "FN"]
    count_colors = [COUNT_COLORS["TP"], COUNT_COLORS["FP"], COUNT_COLORS["FN"]]

    bar_width = 0.25

    for ax, tool in zip(axes_row, tools):
        for j, (cf, cl, cc) in enumerate(zip(count_fields, count_labels, count_colors)):
            values = []
            for cwe in cwes:
                entry = report.cwes[cwe]
                tm = entry.tools.get(tool)
                values.append(getattr(tm, cf, 0) if tm else 0)
            offset = (j - 1) * bar_width
            ax.bar(x + offset, values, bar_width, label=cl, color=cc)

        ax.set_xticks(x)
        ax.set_xticklabels(cwes, rotation=45, ha="right")
        ax.set_title(
            f"Detection Counts — {tool_display_name(tool)}",
            fontsize=13,
            weight="bold",
        )
        ax.legend()

    fig.suptitle("Detection Counts by CWE", fontsize=15, weight="bold", y=1.02)
    plt.tight_layout()
    p = out_dir / "counts_by_cwe.png"
    fig.savefig(p, bbox_inches="tight")
    plt.close(fig)
    generated.append(p)

    # ---------------------------------------------------------------
    # Chart 3: Overall metrics (dual-tool side-by-side)
    # ---------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(max(7, 3 * n_tools), 5))

    metric_keys = ["precision", "recall", "f1"]
    group_labels = ["Precision", "Recall", "F1"]
    x_overall = np.arange(len(group_labels))
    width_overall = 0.7 / max(n_tools, 1)

    for i, tool in enumerate(tools):
        tm = report.overall.get(tool)
        values = [getattr(tm, mk, 0.0) if tm else 0.0 for mk in metric_keys]
        offset = (i - (n_tools - 1) / 2) * width_overall
        color = _get_tool_color(tool)["primary"]
        bars = ax.bar(
            x_overall + offset,
            values,
            width_overall,
            label=tool_display_name(tool),
            color=color,
        )

        for bar in bars:
            h = bar.get_height()
            ax.annotate(
                f"{h:.2f}",
                xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 6),
                textcoords="offset points",
                ha="center", va="bottom", fontsize=12, weight="bold",
            )

    ax.set_xticks(x_overall)
    ax.set_xticklabels(group_labels)
    ax.set_ylim(0, 1.12)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_title("Overall Performance", fontsize=15, weight="bold", pad=15)
    ax.legend(fontsize=11)

    plt.tight_layout()
    p = out_dir / "overall_metrics.png"
    fig.savefig(p, bbox_inches="tight")
    plt.close(fig)
    generated.append(p)

    # ---------------------------------------------------------------
    # Chart 4: Precision comparison line chart
    # ---------------------------------------------------------------
    if n_tools >= 2:
        fig, ax = plt.subplots(figsize=(14, 5))

        for tool in tools:
            values = []
            for cwe in cwes:
                entry = report.cwes[cwe]
                tm = entry.tools.get(tool)
                values.append(tm.precision if tm else 0.0)
            color = _get_tool_color(tool)["primary"]
            ax.plot(
                cwes,
                values,
                marker="o",
                linewidth=2,
                label=tool_display_name(tool),
                color=color,
            )

            for xi, (cwe, v) in enumerate(zip(cwes, values)):
                ax.annotate(
                    f"{v:.2f}",
                    xy=(xi, v),
                    xytext=(0, 8),
                    textcoords="offset points",
                    ha="center", fontsize=8,
                )

        ax.set_ylim(0, 1.12)
        ax.set_title("Precision Comparison by CWE", fontsize=14, weight="bold")
        ax.legend(fontsize=11)
        ax.grid(True, alpha=0.3)
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        p = out_dir / "precision_comparison.png"
        fig.savefig(p, bbox_inches="tight")
        plt.close(fig)
        generated.append(p)

    return generated
