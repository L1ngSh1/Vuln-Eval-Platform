#!/bin/bash
# ==============================================================================
# 通用规则一键评测脚本 (CodeFuse-Query)
# Phase 3 / M3.4 起为兼容 wrapper：实际逻辑已迁移到
# scripts/evaluation/run_pipeline.py（v2 评估核心，产物为 codefuse_eval_v2）。
# 用法: ./scripts/evaluation/eval_checker.sh <CWE编号>
# 示例: ./scripts/evaluation/eval_checker.sh 078
#       ./scripts/evaluation/eval_checker.sh 022
# 可用环境变量: DB_DIR（覆盖数据库路径）、CODEFUSE_HOME（覆盖工具路径）
# ==============================================================================
set -e

CWE_ID=$1
if [ -z "$CWE_ID" ]; then
    echo "❌ 错误: 缺少 CWE 编号参数。"
    echo "用法: $0 <CWE编号> (例如: 078, 022)"
    exit 1
fi

# 获取脚本所在目录的绝对路径
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# 确定项目根目录 (scripts/evaluation 的上两级)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"

# 切换到项目根目录执行
cd "${PROJECT_ROOT}"

# 激活虚拟环境 (如果存在)
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

DB_ARGS=()
if [ -n "${DB_DIR:-}" ]; then
    DB_ARGS=(--db "${DB_DIR}")
fi

exec python3 scripts/evaluation/run_pipeline.py \
    --tool codefuse \
    --cwe "${CWE_ID}" \
    --stages run,evaluate \
    --no-skip-existing \
    ${DB_ARGS+"${DB_ARGS[@]}"}
