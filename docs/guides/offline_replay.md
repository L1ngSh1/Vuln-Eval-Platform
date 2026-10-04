# 最终归档结果的离线重放

## 承诺与输入

`repro/archive-v3.0.1/` 固化两个工具、11 个 CWE 的规范化 CSV、OWASP Benchmark 1.2 GT、原 all_non_gt 汇总、双口径预期结果、版本与 SHA256 清单。原 `reports/data/` 证据不变。CodeQL CSV 来自原 SARIF 转换；所有源 SARIF 内嵌 CodeQL **2.25.3**。CodeFuse CSV 未记录可证明的分析器版本，清单保留 null/unknown；其他日期的环境快照不作为这些输出的版本证明。

规则清单保存当前源树的哈希和 CodeQL pack lock；它不声称当前规则就是历史分析时的精确版本。原输入路径／哈希记录转换来源，离线运行仅读取包内 CSV，不读取原 SARIF、ignored 文件或数据库。

## 运行

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python scripts/evaluation/reproduce_archived_results.py \
  --out-dir /tmp/vep-replay --plots
```

依赖安装需要包源或预先准备的 wheelhouse；**装好依赖后的重放不需要网络、CodeQL、Godel、Java、Maven或分析数据库**。文本／JSON 重放可省略 `--plots`。Python 3.9 与 3.11 的最终 CI 各自安装固定版本并执行完整测试和重放；锁文件记录本地验证环境 Python 3.9.6 的确切依赖版本，不承诺任意 Python 版本。

标准输出成功时为：

```text
REPLAY PASS: 2 tools x 11 CWEs x 2 FP modes; historical counts unchanged
```

退出码为 0；校验、输入、预期指标或运行失败返回非零。输出目录必须在输入包之外，所有校验完成后才写出报告。校验清单保证与 Git 中固定的包一致，不作为数字签名或抗恶意修改的信任根。

## 输出与验收

- `all_non_gt/` 与 `in_scope/`：各工具总指标 JSON、每个 CWE 的 `metrics.json`、`tp.csv`、`fp.csv`、`fn.csv`、`outside_scope.csv`。
- 每种口径的 `report_data.json`、`report.md`、`report_zh.md`；`--plots` 生成 `figs/`，包含双口径并列图。
- `replay-verification.json`：包清单哈希、校验数量、工具／CWE／口径、历史计数保持不变及 `analyzers_executed: false`。
- 原 all_non_gt 每 CWE 六项计数、汇总全部旧字段必须保持一致；新结果全部指标／样本指纹必须与预期 JSON 一致。
- 文本中的生成日期是运行日期；数值、样本身份与机器 JSON 可重复，PNG 字节不承诺跨平台一致。

| 工具 | all_non_gt TP / FP / FN / TN | in_scope FP | 范围外唯一 testcase（按 CWE 求和） | fpr_in_scope |
|---|---|---:|---:|---:|
| CodeFuse-Query | 1415 / 552 / 0 / 773 | 552 | 0 | 0.4166 |
| CodeQL | 1415 / 2236 / 0 / 794 | 531 | 1705 | 0.4008 |

范围外 1705 不是全项目去重告警数，而是各 CWE 规范化 testcase 集大小之和；两工具分别保留自己的输入，不做为降低 FP 的静默过滤。标准 FPR 使用 `FP_in_scope / (FP_in_scope + TN_in_scope)`；旧 all_non_gt 的 fpr 是自定义口径，参见 [指标契约](metric_contract.md)。

## 真实工具限制

本次收尾验收的是**真实历史分析结果的离线重新评估**，不是重新执行规则。固定版本重建数据库、重新运行分析器和跨平台规则回归均未在此次收尾补验；旧建库／分析命令保留为历史参考，不作为最终版保证。尤其 CodeFuse 历史分析器版本和历史规则提交不完整，不能从 Python 测试推出真实工具兼容性。
