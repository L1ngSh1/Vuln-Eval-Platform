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

## 阶段 3：旧入口（2026-10-04 完成中间验收）

- `quick_verify.sh` 移除掩盖子命令状态的过滤管道；通过捕获日志后展示保留真实退出码。临时产物位于每次运行独立的 0700 目录，正常结束及失败均清理，SARIF 转换显式指定私有 CSV 路径。
- `run_eval.sh` 按 manifest 预检全部标准 SARIF 路径，再用统一 SARIF 解析器转换并原子发布 CSV；缺输入或转换异常时停止，旧 CSV 不掩盖转换失败。CWE-022 非空正样本验证 TP=1、FP=0、FN=正样本数减一。
- 三个旧入口从自身路径定位项目根目录，支持显式 PYTHON；CodeFuse wrapper 保留 exec 和带空格数据库参数。
- 注入子命令退出码 23、37、41、43、47、53、59 的测试全部通过；并行 quick_verify 输出目录互不覆盖，退出后全部删除。

### 夹具校准与历史证据

- 封存的 legacy 测试曾以 `dict(..., PYTHON=..., **env)` 合并环境。env 同时提供 PYTHON 时触发 TypeError，原 19 项失败记录中的三个 legacy 用例未真正运行到脚本。历史记录和封存夹具保持原样，不把这三个夹具错误作为业务缺陷证据。
- 当前夹具改为字典展开合并。有效的扩展旧入口基线为 12 failed, 5 passed, 1 deselected；排除真实成功用例以避免旧脚本写共享 /tmp。
- `verify.py` 在三个独立副本中使用同一组 19 项封存回归，仅修正上述 env 合并。三次 fixtures_sha256 完全相同，得到 BASELINE 19 failed / MODIFIED 19 passed / ROLLBACK 19 failed。此次记录提供有效的旧代码复现证据。

## 中间验收结论

- 旧入口相关测试：18 passed，exit 0。
- 当前完整测试：215 passed，exit 0；无 skip、xfail。
- 从 `34b28fe` 的仅跟踪文件副本应用 `DIFF_FILE.patch`：产品/测试哈希完全一致，完整测试 215 passed，exit 0。
- Bash 语法和 git diff --check：exit 0。
- 回滚脚本只作用于显式指定的非 Git 副本，预检目标/原始哈希后恢复七个原始文件的内容与模式，移除新增缓存模块并恢复阶段 1 夹具；操作 exit 0。
- 回滚副本恢复旧缺陷（19 项回归 exit 1）；正常测试为 156 passed, 19 xfailed，exit 0。当前工作树保持修复状态。
- 全部历史输入、指标、原始文件和旧审计材料的哈希保持不变。
- `MODIFIED_FILE` 是修复后 run_eval.sh 的逐字节快照；`DIFF_FILE.patch` 包含业务与回归代码；`VERIFICATION.txt` 记录精确命令、输入、输出和状态；`ROLLBACK.sh` 可执行。

## 剩余工作与限制

- 按用户要求止于阶段 3，未进行发布、远端归档或阶段 4–6 的修改。
- 指标/FPR 契约、报告合并兼容性、双工具真实归档结果的离线重放、版本/许可证和发布材料仍待后续阶段。
- 真实分析器未执行；适配器缓存测试使用版本化假执行器，不将其作为真实规则回归或跨平台可复现实验的证明。
- 干净副本测试依赖已有 Python 测试环境，不代表离线依赖安装或真实归档结果重放已完成。
- 运行缓存对数据库进行内容哈希，成本随数据库大小增长；数据库内部分析产物变化也可能保守失效。本轮不优化为仅比较时间戳。
- quick_verify 仍需要原有实验输入和历史评估文件；缺失时现已如实失败，归档可用输入的补齐属于阶段 5。
