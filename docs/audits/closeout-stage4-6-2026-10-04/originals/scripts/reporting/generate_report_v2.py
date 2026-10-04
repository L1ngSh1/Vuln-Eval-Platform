#!/usr/bin/env python3
"""VEP Report Generator v2 CLI — Phase 2F Entry Point.

Generate dual-tool comparison reports with charts and bilingual markdown.
Supports both legacy and v2 metrics schemas via auto-detection.

Usage:
    # Single metrics file (auto-detect schema)
    python scripts/reporting/generate_report_v2.py \\
        --metrics reports/data/metrics.json \\
        --out-dir reports

    # Multiple metrics files (merge for dual-tool comparison)
    python scripts/reporting/generate_report_v2.py \\
        --metrics reports/data/metrics_v2_codeql.json \\
                  reports/data/metrics_v2_codefuse.json \\
        --out-dir reports

    # Filter specific tools
    python scripts/reporting/generate_report_v2.py \\
        --metrics reports/data/metrics.json \\
        --tools codeql codefuse \\
        --out-dir reports

Phase 2F: Does NOT replace existing generate_report.py / plots_metrics.py.
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vep.reporting.report_generator import (
    load_metrics,
    merge_report_data,
    ReportData,
    tool_display_name,
)
from vep.reporting.plot_generator import generate_all_plots
from vep.reporting.text_report import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate dual-tool comparison reports (Phase 2F)."
    )
    parser.add_argument(
        "--metrics",
        nargs="+",
        required=True,
        help="One or more metrics JSON files (legacy or v2 format).",
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Output directory for reports and figures.",
    )
    parser.add_argument(
        "--tools",
        nargs="+",
        help="Filter to specific tools (e.g., codeql codefuse).",
    )
    parser.add_argument(
        "--figs-dir",
        help="Figures output subdirectory name (default: figs).",
        default="figs",
    )
    parser.add_argument(
        "--en-filename",
        default="report.md",
        help="English report filename (default: report.md).",
    )
    parser.add_argument(
        "--zh-filename",
        default="report_zh.md",
        help="Chinese report filename (default: report_zh.md).",
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        help="Skip chart generation (text reports only).",
    )
    parser.add_argument(
        "--no-reports",
        action="store_true",
        help="Skip text report generation (charts only).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output.",
    )
    return parser


def filter_tools(report: ReportData, tools: list) -> ReportData:
    """Filter ReportData to only include specified tools."""
    from vep.reporting.report_generator import CWEEntry

    filtered_tools = [t for t in report.tools if t in tools]
    filtered_cwes = {}
    for cwe_key, entry in report.cwes.items():
        new_entry = CWEEntry(
            cwe=entry.cwe,
            benchmark_total=entry.benchmark_total,
            real_positive=entry.real_positive,
        )
        for tool in filtered_tools:
            if tool in entry.tools:
                new_entry.tools[tool] = entry.tools[tool]
        if new_entry.tools:
            filtered_cwes[cwe_key] = new_entry

    filtered_overall = {t: m for t, m in report.overall.items() if t in filtered_tools}

    return ReportData(
        schema=report.schema,
        tools=filtered_tools,
        cwes=filtered_cwes,
        overall=filtered_overall,
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    figs_dir = out_dir / args.figs_dir

    # ------------------------------------------------------------------
    # 1. Load metrics
    # ------------------------------------------------------------------
    reports = []
    for metrics_path in args.metrics:
        metrics_path = Path(metrics_path).resolve()
        if not metrics_path.exists():
            print(f"❌ Error: Metrics file not found: {metrics_path}", file=sys.stderr)
            return 1
        try:
            rd = load_metrics(metrics_path)
            reports.append(rd)
            if args.verbose:
                print(f"  ✅ Loaded {metrics_path}")
                print(f"     Schema: {rd.schema}")
                print(f"     Tools:  {rd.tools}")
                print(f"     CWEs:   {len(rd.cwes)}")
        except Exception as e:
            print(f"❌ Error loading {metrics_path}: {e}", file=sys.stderr)
            return 1

    # ------------------------------------------------------------------
    # 2. Merge if multiple files
    # ------------------------------------------------------------------
    if len(reports) > 1:
        report = merge_report_data(reports)
        if args.verbose:
            print(f"\n  🔗 Merged {len(reports)} reports")
            print(f"     Tools: {report.tools}")
            print(f"     CWEs:  {len(report.cwes)}")
    else:
        report = reports[0]

    # ------------------------------------------------------------------
    # 3. Filter tools if specified
    # ------------------------------------------------------------------
    if args.tools:
        report = filter_tools(report, args.tools)
        if args.verbose:
            print(f"  🔍 Filtered to tools: {report.tools}")

    if not report.tools:
        print("❌ Error: No tools found in metrics data", file=sys.stderr)
        return 1

    # ------------------------------------------------------------------
    # 4. Generate charts
    # ------------------------------------------------------------------
    if not args.no_plots:
        try:
            plot_paths = generate_all_plots(report, figs_dir)
            print(f"\n📊 Generated {len(plot_paths)} charts:")
            for p in plot_paths:
                print(f"   {p}")
        except ImportError as e:
            print(f"⚠️  Warning: Could not generate charts (missing dependency): {e}")
            print("   Install matplotlib and seaborn: pip install matplotlib seaborn")
        except Exception as e:
            print(f"❌ Error generating charts: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    # ------------------------------------------------------------------
    # 5. Generate text reports
    # ------------------------------------------------------------------
    if not args.no_reports:
        try:
            report_paths = write_reports(
                report, out_dir,
                en_filename=args.en_filename,
                zh_filename=args.zh_filename,
            )
            print(f"\n📝 Generated {len(report_paths)} reports:")
            for p in report_paths:
                print(f"   {p}")
        except Exception as e:
            print(f"❌ Error generating reports: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("VEP Report Generator v2 — Phase 2F")
    print("=" * 60)
    print(f"Tools:   {', '.join(tool_display_name(tool) for tool in report.tools)}")
    print(f"CWEs:    {len(report.cwes)}")
    print(f"Output:  {out_dir}")
    for tool in report.tools:
        tm = report.overall.get(tool)
        if tm:
            print(f"\n  {tool_display_name(tool)}:")
            print(f"    Precision: {tm.precision:.4f}")
            print(f"    Recall:    {tm.recall:.4f}")
            print(f"    F1:        {tm.f1:.4f}")
    print("=" * 60)
    print("✅ Report generation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
