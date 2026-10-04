#!/usr/bin/env bash
set -e

# ==============================================================================
# Legacy entry point — Phase 3 / M3.4 起为统一 pipeline 的兼容 wrapper。
# 评估/聚合/报告逻辑已迁移到 scripts/evaluation/run_pipeline.py
# （v2 评估核心 + vep.aggregate.v2 聚合 + generate_report_v2 报告）。
# 本脚本保留 SARIF 存在性预检查，行为对齐旧版 run_eval.sh。
# ==============================================================================

echo "========================================="
echo "   CodeQL Evaluation Framework"
echo "========================================="

if [ ! -d "experiments" ]; then
    echo "❌ experiments/ directory not found."
    exit 1
fi

echo "[+] Checking SARIF files..."

missing=0

for dir in experiments/*/; do
    cwe=$(basename "$dir")

    # 查找 results 子目录里的 sarif
    sarif_file=$(find "$dir/results" -name "*.sarif" 2>/dev/null || true)

    if [ -z "$sarif_file" ]; then
        echo "❌ Missing SARIF file for $cwe"
        missing=1
    else
        echo "✔ Found SARIF for $cwe"
    fi
done

if [ "$missing" -eq 1 ]; then
    echo ""
    echo "⚠ Some SARIF files are missing."
    echo "Please run CodeQL analysis before evaluation."
    exit 1
fi

echo ""
echo "[+] All SARIF files detected."
echo ""

# 激活虚拟环境
if [ -d ".venv" ]; then
    echo "[+] Activating virtual environment"
    source .venv/bin/activate
fi

echo "[+] Delegating to unified pipeline (evaluate, aggregate, report)..."
python3 scripts/evaluation/run_pipeline.py \
    --tool codeql \
    --cwe all \
    --stages evaluate,aggregate,report \
    --no-skip-existing

echo ""
echo "========================================="
echo "   Evaluation Completed Successfully"
echo "========================================="
echo ""
echo "Reports generated in reports/"
echo "Open reports/report.md to view results."
