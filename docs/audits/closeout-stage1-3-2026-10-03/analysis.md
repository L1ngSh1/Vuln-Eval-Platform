# VEP 阶段 1–3 中间验收记录

## 阶段 1：审计基线

- 基线提交：`34b28feb1c98c64f5d277e8a2bedf6afb675a38d`。
- 原有测试：156 passed，exit 0。
- 新增回归在原业务代码上：19 failed，exit 1；逐条输出见 `BASELINE_regressions.json`。
- 阶段 1 完整测试：156 passed, 19 xfailed，exit 0。xfail 仅用于封存已复现缺陷，阶段 2/3 分别移除。
- 源码原文、模式与 SHA-256，以及当前指标、mini fixture、GT、配置和已有审计材料的哈希见 `baseline-manifest.json`。
- 文件系统大小写不敏感，基线测试记录与输入清单使用不同语义文件名，避免覆盖。
- 历史 all_non_gt 证据原样保留；未执行分析器、发布或远端操作。

## 根因与补丁边界

- A01：缓存只按 metrics 文件存在判断，未绑定输入、口径或产物完整性。
- A04：CWE 别名重复进入累计，而字典覆盖明细；全量文件名只比较列表长度。
- A06/A07：shell 管道掩盖失败；旧 CodeQL wrapper 未标准化 SARIF；固定共享临时文件。
- FPR/报告契约属于阶段 4，离线发布材料属于阶段 5/6，本次保持原状。

## 阶段 2：执行正确性

- 在隔离的 `34b28fe` 副本重新执行封存回归：19 failed，exit 1；原有完整测试加 strict xfail：156 passed, 19 xfailed，exit 0。
- 续接时先保存未提交补丁及哈希到 `intake-before-resume/`；未覆盖已有审计材料。
- 评估缓存绑定工具、CWE、FP 口径、findings/GT 内容哈希和评估器代码；五项指标/明细产物均通过哈希校验后才复用。
- 运行缓存绑定实际可执行文件、版本、规则/查询包、锁文件、共享库和数据库内容；版本探测失败时执行分析但不复用缓存。
- 工具输出和评估结果先在私有目录生成；明细先于指标发布，完成记录原子写入；失败运行不发布旧结果为新结果。
- CWE 别名按输入顺序去重；聚合层拒绝重复 CWE；全量/子集文件名按实际成员判定。
- 重新验证：相关测试 98 passed，exit 0；完整测试 197 passed, 5 xfailed，exit 0。剩余五项 strict xfail 全部属于阶段 3。
- 结果保存在 `BASELINE_revalidated.json`、`STAGE1_revalidated.json`、`STAGE2_revalidated_targeted.json` 和 `STAGE2_revalidated_suite.json`；所有历史输入、指标及审计哈希通过复核。

## 后续验收

阶段 3 后补充完整验证、历史哈希核验、可执行回滚和干净副本测试。运行缓存对数据库进行内容哈希，首次校验成本随数据库大小增长；本轮不优化为仅比较时间戳。
