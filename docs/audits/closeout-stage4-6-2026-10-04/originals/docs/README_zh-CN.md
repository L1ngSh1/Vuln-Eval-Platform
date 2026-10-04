# Vuln-Eval-Platform 🔐
### Security Evaluation Lab for Static Analysis Tools

[👉 Click here to view the English Version](../README.md)

![License](https://img.shields.io/badge/license-MIT-green)
![OWASP](https://img.shields.io/badge/OWASP-Benchmark-important)
![Created by L1ngSh1](https://img.shields.io/badge/Created%20by-L1ngSh1-purple)

---

## 📌 项目简介

**Vuln-Eval-Platform** 是一个面向安全研究的静态分析评测框架，
用于统一评估不同漏洞检测工具在 **OWASP Benchmark 数据集** 上的检测能力。

本项目支持：

- CodeQL 静态分析工具评测
- CodeFuse-Query 静态分析工具评测
- 多 CWE 漏洞检测对比
- 自动化评测指标统计
- 可复现实验流程设计

该框架旨在解决不同安全工具之间缺乏统一评测标准的问题，
提供工程化、可扩展的漏洞检测评测平台。

⚠ 本项目主要用于安全研究与工具评测实验。

---

## 🆕 版本说明

### v3.0.0（当前版本）

- CodeFuse-Query 与 CodeQL 统一使用 `scripts/evaluation/run_pipeline.py`。
- 新增工具自动发现和 CodeFuse `JAVA_HOME` 环境门禁。
- 新增断点续跑、156 个测试、golden fixtures 和 Python 3.9/3.11 CI。
- 支持双工具联合报告，以及 CodeFuse-Query、CodeQL 独立报告。

### v2.0

- 完成 11 个 CodeFuse-Query / GodelScript Java SAST checker。
- 建立 `source / helper / taint / sink / sanitizer` 模块化规则框架。
- 新增统一评测入口：`scripts/evaluation/eval_checker.sh <CWE>`。
- 当前 11 个 checker 在 OWASP Benchmark 上均达到 `Recall = 1.0000`。
- 项目进入 regression、packaging 与 precision research 阶段。

### v1.1

- 完善早期自动化评测流程。
- 新增 `run_eval.sh`、结果转换、指标汇总与基础报告生成。

### v1.0

- 接入 OWASP Benchmark。
- 完成静态分析工具评测平台的基础架构。
- 支持 CodeQL / CodeFuse 结果归一化与单 CWE 评测。

---

## 🧩 系统架构

```
OWASP Benchmark Source Code
│
▼
Static Analysis Database
│
▼
Detection Rules Execution
(CodeQL / CodeFuse Query)
│
▼
Detection Result Export
(CodeQL SARIF / CodeFuse JSON)
│
▼
Result Normalization
(SARIF → CSV / JSON → CSV)
│
▼
Ground Truth Comparison
│
▼
Evaluation Metrics Output
```

---

## 🎯 项目目标

- 构建统一漏洞检测评测框架  
- 对比不同静态分析工具检测能力  
- 提供自动化评测流程  
- 支持安全研究实验复现  
- 提供可扩展规则管理体系  

---

## 📂 项目结构

```
Vuln-Eval-Lab
│
├── dataset                    # 数据集与分析数据库
│   ├── benchmark              # OWASP Benchmark 源码
│   │   ├── data
│   │   ├── src
│   │   └── target
│   ├── codeql-db              # CodeQL 数据库与结果
│   │      
│   └── codefuse-db            # CodeFuse 数据库目录
│
├── rules                      # 检测规则
│   ├── codeql-query           # CodeQL 各 CWE 规则
│   └── codefuse-query         # CodeFuse 各 CWE 规则
│
├── experiments                # 实验目录
│   ├── cwe-022 ~ cwe-643      # 各 CWE 实验
│   │   ├── eval
│   │   ├── logs
│   │   └──结果
│   └── examples               # 示例实验
│
├── scripts                    # 脚本目录（按功能分类）
│   ├── converters             # 结果格式转换
│   ├── evaluation             # 指标评测与计算
│   └── reporting              # 图表与报告生成
├── reports                    # 结果输出
│   ├── data
│   └── figs
│
├── run_eval.sh                # 一键评估入口
├── requirements.txt
├── expectedresults-1.2.csv    # 基准期望结果
├── LICENSE
└── README.md
```

更多实验流程说明请参考[统一评估流程](guides/evaluation_workflow.md)。

---

## 🔧 安装 CodeQL

参考官方发布地址：

[https://github.com/github/codeql-cli-binaries/releases](https://github.com/github/codeql-cli-binaries/releases)

---

## 🔧 安装 CodeFuse / Sparrow

[https://github.com/codefuse-ai/CodeFuse-Query](https://github.com/codefuse-ai/CodeFuse-Query)

---

# ⚡ Quick Start

### 获取代码

```bash
git clone https://github.com/L1ngSh1/Vuln-Eval-Platform.git
cd Vuln-Eval-Platform
```

### macOS

使用 Homebrew 安装 OpenJDK 17，再通过 `brew --prefix` 获取真实 JDK Bundle
路径；该写法同时兼容 Apple Silicon 和 Intel Mac。

```bash
brew install openjdk@17
export JAVA_HOME="$(brew --prefix openjdk@17)/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
export DB_CODEFUSE="dataset/codefuse-db-mac-fixed"
python3 scripts/check_codefuse_java_env.py
```

### Linux

需要安装完整 JDK，而不是只有 JRE。Debian/Ubuntu 示例：

```bash
sudo apt-get update
sudo apt-get install -y python3-venv openjdk-17-jdk

export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
export PATH="$JAVA_HOME/bin:$PATH"
export DB_CODEFUSE="dataset/codefuse-db-linux"
python3 scripts/check_codefuse_java_env.py
```

其他 Linux 发行版安装对应的 OpenJDK 17 development package 后，可以沿用
同一条 `JAVA_HOME` 自动解析命令。

以上数据库目录是按平台给出的本机示例；如果数据库位于其他位置，请将
`DB_CODEFUSE` 设置为对应绝对路径。

### Python 环境

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 运行评估

设置 `DB_CODEFUSE` 后，以下命令在 macOS 和 Linux 上完全一致。

```bash
# CodeFuse 全量新鲜回归：执行、评估、聚合、报告
python3 scripts/evaluation/run_pipeline.py --tool codefuse --cwe all \
  --db "$DB_CODEFUSE" \
  --stages run,evaluate,aggregate,report \
  --no-skip-existing --keep-going

# 聚合已有 metrics，生成联合报告和两份独立报告
python3 scripts/evaluation/run_pipeline.py --tool both --cwe all \
  --stages aggregate,report

# 旧入口继续作为兼容 wrapper
./run_eval.sh
bash scripts/evaluation/eval_checker.sh 022
```

---

## ⚡ 统一评估 Pipeline（v3.0.0 推荐）

`scripts/evaluation/run_pipeline.py` 统一完成：

* 工具环境检查和路径发现
* CodeFuse-Query / CodeQL 执行
* JSON / SARIF 标准化
* v2 评估与多 CWE 聚合
* 中英文联合报告和单工具报告

结果输出位置：

```
reports/data/metrics_v2_codefuse_all.json
reports/data/metrics_v2_codeql_all.json
reports/figs/
reports/report.md
reports/report_zh.md
reports/codefuse/                         # CodeFuse-Query 独立报告
reports/codeql/                           # CodeQL 独立报告
```

evaluate-only 模式读取的是 normalized CSV，而不是只有 SARIF 就能直接评估。
已有 SARIF 可使用 `scripts/evaluation/eval_sarif_findings.py` 转换和评估。

当前 `all_non_gt` 基线：

| 工具 | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| CodeFuse-Query | 1415 | 552 | 0 | 0.7194 | 1.0000 | 0.8368 |
| CodeQL | 1415 | 2236 | 0 | 0.3876 | 1.0000 | 0.5586 |

---

# 🧪 实验流程

每个 CWE 实验统一遵循以下流程：

1. 构建静态分析数据库
2. 执行漏洞检测规则
3. 导出检测结果（CodeQL: SARIF，CodeFuse: JSON）
4. 结果归一化为 CSV
5. Ground Truth 对比
6. 统计评测指标

---

# 📊 评测指标

本项目采用标准漏洞检测评测指标体系：

| 指标      | 含义             |
| --------- | ---------------- |
| TP        | 真实检测漏洞数量 |
| FP        | 误报数量         |
| FN        | 漏报数量         |
| Precision | 检测准确率       |
| Recall    | 漏洞召回率       |
| FNR       | 漏报率           |
| FPR       | 误报率           |
| FDR       | 误检率           |

---

# 📌 当前支持 CWE 类型

* CWE-022
* CWE-078
* CWE-079
* CWE-089
* CWE-090
* CWE-327
* CWE-328
* CWE-330
* CWE-501
* CWE-614
* CWE-643

---

# 📈 项目特点

* 工程化漏洞评测框架
* 支持多工具统一评测
* 支持自动指标统计
* 支持实验复现
* 支持规则模块化管理
* 支持 manifest 驱动的统一评估 pipeline（v3.0.0）
* 支持自动生成中英双语报告
* 支持性能可视化分析

---

# ✅ 测试与 CI

```bash
python -m compileall vep/ scripts/evaluation/ scripts/reporting/ scripts/converters/
python scripts/verify_manifest.py
python -m pytest
```

当前共有 156 个测试。GitHub Actions 在 Python 3.9/3.11 上执行编译、manifest
验证和 pytest；golden fixtures 保护 CWE-328 的 `328S` ground-truth 语义。

---

# 🚧 未来规划

* 在保持当前零 FN 基线的前提下降低 FP
* 扩展更多 CWE checker 和静态分析工具 adapter
* 在 Linux 上补充 CodeFuse 全链路复现
* 研究 path、field 和 context sensitivity 等精度能力

---

# 📄 许可证

本项目基于 MIT 开源许可证发布
您可以在遵守许可证条款的前提下自由使用、修改和分发本项目
完整许可证内容请参见 [LICENSE](../LICENSE) 文件

---

## 👨‍💻 作者

L1ngSh1

---

## ✍️ 作者的碎碎念

本项目最初源于作者在安全研究实习期间，对不同静态分析工具评测方式缺乏统一标准的思考。

Vuln-Eval-Platform 的目标是构建一个结构化、可扩展、可复现的漏洞检测评测框架，使研究者能够更加系统地分析静态分析工具在真实漏洞数据集上的检测表现。

该项目既是一个研究实验平台，也记录了作者在安全研究与工程实践中的探索过程。

项目目前仍在持续演进中，欢迎对静态分析与漏洞检测感兴趣的研究者参与改进、提出建议或贡献规则。

如果本项目能够在安全研究或教学中提供帮助，将是作者非常欣慰的事情。
