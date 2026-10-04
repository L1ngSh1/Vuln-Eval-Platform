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

## 阶段 5：归档重放（已验收）

双工具 11 CWE 的原始输入与历史六项计数共 22 组逐项一致（REPLAY_input_probe.json）。下一步将固化规范化 CSV、GT、版本及哈希，并验证干净检出离线重放。CodeQL SARIF 内嵌版本为 2.25.3；CodeFuse 所选 CSV 未包含可证明的运行版本，保持 unknown，不将其他日期的环境快照冒充本次运行版本。

## 阶段 6 门槛

阶段 4–5 验收后才发布。完整 CI、许可证、依赖、证据包、已知限制与最终 release 必须齐备；GitHub 只读归档作为用户单独确认的最后动作。

## 阶段 5 补充结果

- 提交 abf664e：22 份规范化输入、GT、历史汇总、新双口径预期、30 项初始文件哈希、规则／pack／依赖版本清单。
- 首批异常路径用例在实现前为 15 failed, 1 passed（BASELINE_replay.json）；扩充后 17 passed（STAGE5_targeted.json）。
- 全集 257 passed；干净 git archive 源码新装 requirements.lock，网络禁用探针命中；空 PATH、无 ignored 输入／数据库，重放并绘图成功，全测试 257 passed（STAGE5_clean.json）。
- 默认 Python 3.14 不在锁文件验证范围，误用该解释器的安装已终止（exit 143）；改用已验证 3.9.6 的独立 venv，安装成功（exit 0），不将未完成安装记成成功。

## 阶段 6：最终发布准备

- 明确 v3.0.1、自有 MIT 与 Benchmark GPL-2.0／CodeQL MIT／Benchmark Web 素材各自 MIT，保留原头部并附上游许可证哈希；外部 CodeFuse 引擎仅作引用，不打包分析器。
- 修正文档 FPR、未来扩展、跨平台承诺和报告中“高召回保证真实工程无遗漏”的含义。
- 四项产物和分离副本回滚已验证：旧指标契约 24 failed, 1 passed；修改后 25 passed；回滚恢复原失败并通过原 215 测试。见 VERIFICATION.txt。
- 最终本地完整测试 257 passed，compile、manifest 和双工具完整离线重放均 exit 0（FINAL_*.json）。217 份历史证据保持字节不变。
- 上游 GPL 许可证保留精确原始字节（含末尾空行）；diff 空白检查只为这三份相同许可证作明确豁免。
- 最终 CI 与资产下载／重放校验在最终提交后执行，作为独立 release 证据保存。GitHub 归档仍需单独确认。
