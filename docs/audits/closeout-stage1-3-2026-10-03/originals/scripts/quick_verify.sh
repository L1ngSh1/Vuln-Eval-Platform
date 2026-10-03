#!/bin/bash
set -e

echo "=============================="
echo "VEP Phase 2 快速验证"
echo "=============================="

# 激活虚拟环境
source .venv/bin/activate

# Phase 1 验证
echo ""
echo "[1/5] Phase 1 验证..."
python scripts/verify_manifest.py | tail -3

# 编译检查
echo ""
echo "[2/5] 编译检查..."
python -m compileall vep/ scripts/evaluation/ 2>&1 | grep -E "(Compiling|Error)" | tail -5 || echo "✅ 编译通过"

# CodeFuse 评估
echo ""
echo "[3/5] CodeFuse 评估 (CWE-022)..."
python scripts/evaluation/eval_findings.py \
  --findings experiments/cwe-022/results/codefuse-query/cwe022_codefuse.csv \
  --ground-truth expectedresults-1.2.csv \
  --tool codefuse \
  --cwe CWE-022 \
  --out /tmp/vep_verify_metrics.json \
  --no-details 2>&1 | grep -E "(TP|FP|FN|Precision|Recall|F1)" | head -8

# CodeQL 评估
echo ""
echo "[4/5] CodeQL 评估 (CWE-079)..."
python scripts/evaluation/eval_sarif_findings.py \
  --sarif experiments/cwe-079/results/codeql/cwe079.sarif \
  --ground-truth expectedresults-1.2.csv \
  --tool codeql \
  --cwe CWE-079 \
  --out /tmp/vep_verify_codeql.json \
  --no-details 2>&1 | grep -E "(TP|FP|FN|Precision|Recall|F1)" | head -8

# 聚合
echo ""
echo "[5/5] 聚合验证..."
python scripts/evaluation/aggregate_v2.py \
  --metrics experiments/cwe-022/eval/codefuse_eval_v2b/metrics.json \
            experiments/cwe-089/eval/codefuse_eval_v2b/metrics.json \
  --out /tmp/vep_verify_aggregate.json 2>&1 | grep -E "(TP|FP|FN|Precision|Recall|F1)" | head -8

echo ""
echo "=============================="
echo "✅ Phase 2 验证完成"
echo "=============================="
