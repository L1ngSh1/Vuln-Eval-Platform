#!/bin/bash
set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi
PYTHON="${PYTHON:-python3}"

umask 077
VERIFY_TMP="$(mktemp -d "${TMPDIR:-/tmp}/vep-verify.XXXXXX")"
trap 'rm -rf -- "$VERIFY_TMP"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Capture first, then display: filtering stdout must not hide a child's status.
run_logged() {
    local log="$1"
    shift
    if "$@" >"$log" 2>&1; then
        cat "$log"
    else
        local status=$?
        cat "$log" >&2
        return "$status"
    fi
}

echo "=============================="
echo "VEP Phase 2 快速验证"
echo "=============================="

# Phase 1 验证
echo ""
echo "[1/5] Phase 1 验证..."
run_logged "$VERIFY_TMP/manifest.log" "$PYTHON" scripts/verify_manifest.py

# 编译检查
echo ""
echo "[2/5] 编译检查..."
run_logged "$VERIFY_TMP/compile.log" "$PYTHON" -m compileall vep/ scripts/evaluation/

# CodeFuse 评估
echo ""
echo "[3/5] CodeFuse 评估 (CWE-022)..."
run_logged "$VERIFY_TMP/codefuse.log" "$PYTHON" scripts/evaluation/eval_findings.py \
  --findings experiments/cwe-022/results/codefuse-query/cwe022_codefuse.csv \
  --ground-truth expectedresults-1.2.csv \
  --tool codefuse \
  --cwe CWE-022 \
  --out "$VERIFY_TMP/codefuse.json" \
  --no-details

# CodeQL 评估
echo ""
echo "[4/5] CodeQL 评估 (CWE-079)..."
run_logged "$VERIFY_TMP/codeql.log" "$PYTHON" scripts/evaluation/eval_sarif_findings.py \
  --sarif experiments/cwe-079/results/codeql/cwe079.sarif \
  --ground-truth expectedresults-1.2.csv \
  --tool codeql \
  --cwe CWE-079 \
  --out "$VERIFY_TMP/codeql.json" \
  --csv-out "$VERIFY_TMP/codeql-findings.csv" \
  --no-details

# 聚合
echo ""
echo "[5/5] 聚合验证..."
run_logged "$VERIFY_TMP/aggregate.log" "$PYTHON" scripts/evaluation/aggregate_v2.py \
  --metrics experiments/cwe-022/eval/codefuse_eval_v2b/metrics.json \
            experiments/cwe-089/eval/codefuse_eval_v2b/metrics.json \
  --out "$VERIFY_TMP/aggregate.json"

echo ""
echo "=============================="
echo "✅ Phase 2 验证完成"
echo "=============================="
