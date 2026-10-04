# VEP 指标契约（vep.metrics.v1）

历史 `vep.eval.v2` / `vep.aggregate.v2` 文件保持原样。新输出以 additive 字段
`metric_contract=vep.metrics.v1` 记录定义，不重写历史 all_non_gt 计数。

## 匹配与样本范围

- 统计单位：`testcase_per_cwe`，即规范化后的 testcase/CWE 对；同一 testcase 的重复告警只计一次。
- GT 按目标 CWE 选择，保留既有 CWE-328S → CWE-328 映射。
- `sample_scope` 保留 GT 文件 SHA-256、所选规范化 testcase/标签集合的指纹、正负样本数量和统计单位。
- 空或冲突的 GT 标签身份报错。手动构造且没有 GT 来源的样本标为未验证；旧输入的范围缺失标为 unknown，不声称已证明同样本可比。
- 既有告警匹配语义不变：没有有效 testcase 身份的告警仍保留在 raw_findings，但未计入 testcase 去重计数；本次不新增降低 FP 的过滤器。

## 两种 FP 口径

| fp_mode | FP 定义 | 范围外告警 |
|---|---|---|
| all_non_gt | FP_in_scope + outside_scope_findings | 保留并作为历史惩罚项计入 FP |
| in_scope | 被命中的范围内阴性样本 | 单独保留，不加入该 FP |

`metric_modes` 始终并列保存两种口径的 TP/FP/FN/TN、Precision、Recall 和 F1。
选定 `fp_mode` 决定旧顶层 fp/precision/f1 字段，不影响原始告警的保留。
`outside_scope_findings` 指不在所选 GT 总体中的唯一 testcase/CWE 对，不是原始告警行数。

## FPR

- `fpr_in_scope = FP_in_scope / (FP_in_scope + TN_in_scope)`，只对应有明确标签的阴性总体。
- 未计算 TN、阴性分母为零或聚合输入缺少完整 TN 时，`fpr_in_scope=null`，文本显示 N/A。
- 旧 `fpr` 数值保留。all_non_gt 时明确标注为自定义 `FP_all_non_gt/(FP_all_non_gt+TN_in_scope)`，不作为标准 FPR。
- 例如 1 正、2 负、命中正例且产生 1 个范围外 testcase：历史自定义 fpr=0.3333；fpr_in_scope=0；范围外数量=1。

## 聚合、合并与报告

- 聚合总计来自唯一 CWE 明细之和，不能平均单 CWE 的比率。
- 不同工具、fp_mode、指标契约、GT 指纹或统计单位的输入始终报错；`strict=False` 不关闭这些正确性检查。
- strict 聚合额外要求样本身份已验证。旧缺元数据输入可以单独展示，但报告必须明确 unknown/unverified。
- 双工具报告要求相同 CWE 集合、相同 sample_scope 和 fp_mode；相同工具重复输入报错，避免静默覆盖 overall。
- 样本身份未知或未验证时，不合并为双工具比较；先从带 GT 指纹的输入重放。旧报告仍可单独呈现。
- JSON `report_data.json`、中英文正文、两种口径比较表和图表使用同一对象。图表标明选定口径、单位及样本指纹；双口径图不删减范围外结果。
- `fpr_in_scope` 和 FP 数量反映当前 GT 与规则组合，不自动构成显著性或 Benchmark 外泛化结论。
