# VEP 收尾阶段 4–6

## 阶段 4：指标契约（已本地验收）

- 历史 all_non_gt 和 reports/data 证据保持字节不变；旧 fpr 保留且明确标注为自定义指标。
- 新增 fp_mode、双口径 metric_modes、GT SHA256 与逐 CWE 样本指纹、范围外计数、标准 fpr_in_scope；分母缺失或为零时返回 null。
- 聚合与报告合并拒绝不同工具（聚合）、口径、CWE 集、统计单位、GT／样本集，以及身份不明的多报告比较。
- JSON、英文／中文报告、图表共享同一指标对象并显示口径／样本身份。

## 回归证据

- 原完整测试：215 passed，exit 0（BASELINE_suite.json）。
- 首批指标契约用例在旧代码：21 failed, 1 passed，exit 1（BASELINE_contract.json）。
- 扩充后针对性测试：68 passed，exit 0（STAGE4_targeted.json）。
- 扩充后完整测试：240 passed，exit 0（STAGE4_suite.json）。
- 报告绘图产生 14 条第三方 PyparsingDeprecationWarning，不影响测试结果。

## 阶段 5 待验收

双工具 11 CWE 的原始输入与历史六项计数共 22 组逐项一致（REPLAY_input_probe.json）。下一步将固化规范化 CSV、GT、版本及哈希，并验证干净检出离线重放。CodeQL SARIF 内嵌版本为 2.25.3；CodeFuse 所选 CSV 未包含可证明的运行版本，保持 unknown，不将其他日期的环境快照冒充本次运行版本。

## 阶段 6 门槛

阶段 4–5 验收后才发布。完整 CI、许可证、依赖、证据包、已知限制与最终 release 必须齐备；GitHub 只读归档作为用户单独确认的最后动作。
