# Vuln-Eval-Platform 🔐
### Security Evaluation Lab for Static Analysis Tools

[👉 点击这里查看中文版本 (Chinese Version)](docs/README_zh-CN.md)

![License](https://img.shields.io/badge/license-MIT-green)
![OWASP](https://img.shields.io/badge/OWASP-Benchmark-important)
![Created by L1ngSh1](https://img.shields.io/badge/Created%20by-L1ngSh1-purple)

---

## 📌 Project Introduction

**Vuln-Eval-Platform** is a static analysis evaluation framework oriented towards security research.
It is used to uniformly evaluate the detection capabilities of different vulnerability detection tools on the **OWASP Benchmark dataset**.

This project supports:

- Evaluation of the CodeQL static analysis tool
- Evaluation of the CodeFuse-Query static analysis tool
- Comparison of multi-CWE vulnerability detection
- Automated statistical analysis of evaluation metrics
- Reproducible experimental process design

This framework aims to solve the problem of lacking a unified evaluation standard among different security tools,
providing an engineered, scalable platform for vulnerability detection evaluation.

⚠ This project is primarily used for security research and tool evaluation experiments.

---

## 🆕 Release Notes

### v3.0.0 (Current Version)

- Unified CodeFuse-Query and CodeQL execution under `scripts/evaluation/run_pipeline.py`.
- Added automatic tool discovery and the CodeFuse `JAVA_HOME` environment gate.
- Added resumable multi-CWE runs, 156 tests, golden fixtures, and Python 3.9/3.11 CI.
- Added combined CodeFuse-Query/CodeQL reports plus standalone reports for each tool.

### v2.0

- Completed 11 CodeFuse-Query / GodelScript Java SAST checkers.
- Established a modular rule framework for `source / helper / taint / sink / sanitizer`.
- Added a unified manifest-driven pipeline: `scripts/evaluation/run_pipeline.py` (Phase 3).
- The current 11 checkers have all achieved `Recall = 1.0000` on the OWASP Benchmark.
- The project has entered the regression, packaging, and precision research stages.

### v1.1

- Refined the early automated evaluation process.
- Added `run_eval.sh`, result conversion, metrics aggregation, and basic report generation.

### v1.0

- Integrated the OWASP Benchmark.
- Completed the basic architecture of the static analysis tool evaluation platform.
- Supported CodeQL / CodeFuse result normalization and single-CWE evaluation.

---

## 🧩 System Architecture

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

## 🎯 Project Goals

- Build a unified vulnerability detection evaluation framework
- Compare the detection capabilities of different static analysis tools
- Provide automated evaluation workflows
- Support the reproduction of security research experiments
- Provide an extensible rule management system

---

## 📂 Project Structure

```
Vuln-Eval-Lab
│
├── dataset                    # Datasets and Analysis Databases
│   ├── benchmark              # OWASP Benchmark source code
│   │   ├── data
│   │   ├── src
│   │   └── target
│   ├── codeql-db              # CodeQL databases and results
│   │      
│   └── codefuse-db            # CodeFuse database directory
│
├── rules                      # Detection Rules
│   ├── codeql-query           # CodeQL rules for each CWE
│   └── codefuse-query         # CodeFuse rules for each CWE
│
├── experiments                # Experiment Directory
│   ├── cwe-022 ~ cwe-643      # Experiments for each CWE
│   │   ├── eval
│   │   ├── logs
│   │   └── results
│   └── examples               # Example experiments
│
├── scripts                    # Scripts Directory (grouped by function)
│   ├── converters             # Result format conversion
│   ├── evaluation             # Metric evaluation and calculation
│   └── reporting              # Chart and report generation
├── reports                    # Output Results
│   ├── data
│   └── figs
│
├── run_eval.sh                # Legacy CodeQL entry (wrapper around the pipeline)
├── requirements.txt
├── expectedresults-1.2.csv    # Benchmark expected results
├── LICENSE
└── README.md
```

For more details, see the [evaluation workflow](docs/guides/evaluation_workflow.md).

---

## 🔧 Install CodeQL

Refer to the official release page:

[https://github.com/github/codeql-cli-binaries/releases](https://github.com/github/codeql-cli-binaries/releases)

---

## 🔧 Install CodeFuse / Sparrow

[https://github.com/codefuse-ai/CodeFuse-Query](https://github.com/codefuse-ai/CodeFuse-Query)

---

# ⚡ Quick Start

### Get the source

```bash
git clone https://github.com/L1ngSh1/Vuln-Eval-Platform.git
cd Vuln-Eval-Platform
```

### macOS

Install OpenJDK 17 with Homebrew, then resolve the real JDK bundle path. Using
`brew --prefix` works on both Apple Silicon and Intel Homebrew installations.

```bash
brew install openjdk@17
export JAVA_HOME="$(brew --prefix openjdk@17)/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
export DB_CODEFUSE="dataset/codefuse-db-mac-fixed"
python3 scripts/check_codefuse_java_env.py
```

### Linux

Install a full JDK rather than a JRE. For Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y python3-venv openjdk-17-jdk

export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
export PATH="$JAVA_HOME/bin:$PATH"
export DB_CODEFUSE="dataset/codefuse-db-linux"
python3 scripts/check_codefuse_java_env.py
```

For other Linux distributions, install their OpenJDK 17 development package
and keep the same `JAVA_HOME` discovery command.

The database directories above are machine-specific examples. If your database
is elsewhere, set `DB_CODEFUSE` to its absolute path.

### Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Run the evaluation

The commands below are identical on macOS and Linux after `DB_CODEFUSE` is set.

```bash
# Fresh CodeFuse regression: run -> evaluate -> aggregate -> report
python3 scripts/evaluation/run_pipeline.py --tool codefuse --cwe all \
  --db "$DB_CODEFUSE" \
  --stages run,evaluate,aggregate,report \
  --no-skip-existing --keep-going

# Aggregate existing metrics and generate comparison + standalone reports
python3 scripts/evaluation/run_pipeline.py --tool both --cwe all \
  --stages aggregate,report

# Legacy wrappers (still forward to the pipeline)
./run_eval.sh                                # CodeQL: SARIF precheck + evaluate/aggregate/report
bash scripts/evaluation/eval_checker.sh 022  # CodeFuse single CWE
```

---

## ⚡ Unified Pipeline (Recommended in v3.0.0)

`scripts/evaluation/run_pipeline.py` is the manifest-driven main entry. It will:

* Check the tool environment (including the CodeFuse `JAVA_HOME`/JDK gate)
* Run the selected tool(s), or evaluate existing normalized findings CSV files
* Evaluate with the v2 core (`vep.eval.v2` metrics + tp/fp/fn/outside-scope CSVs)
* Aggregate multi-CWE overall metrics (`vep.aggregate.v2`)
* Output English evaluation report
* Output Chinese evaluation report

Result output locations:

```
reports/data/metrics_v2_codefuse_all.json   # CodeFuse aggregate (vep.aggregate.v2)
reports/data/metrics_v2_codeql_all.json     # CodeQL aggregate
experiments/cwe-<ID>/eval/codefuse_eval_v2/ # per-CWE metrics + tp/fp/fn CSVs
reports/figs/
reports/report.md
reports/report_zh.md
reports/codefuse/                          # standalone CodeFuse-Query report
reports/codeql/                            # standalone CodeQL report
```

Evaluate-only mode reads normalized CSV files, not raw SARIF alone. Existing
SARIF can be converted with `scripts/evaluation/eval_sarif_findings.py`.

Current `all_non_gt` baseline:

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| CodeFuse-Query | 1415 | 552 | 0 | 0.7194 | 1.0000 | 0.8368 |
| CodeQL | 1415 | 2236 | 0 | 0.3876 | 1.0000 | 0.5586 |

---

# 🧪 Experimental Workflow

Each CWE experiment uniformly follows these steps:

1. Build static analysis database
2. Execute vulnerability detection rules
3. Export detection results (CodeQL: SARIF, CodeFuse: JSON)
4. Normalize results to CSV
5. Ground Truth comparison
6. Calculate evaluation metrics

---

# 📊 Evaluation Metrics

This project uses a standard vulnerability detection evaluation metric system:

| Metric    | Meaning                                  |
| --------- | ---------------------------------------- |
| TP        | True Positive (detected vulnerabilities) |
| FP        | False Positive (false alarms)            |
| FN        | False Negative (missed vulnerabilities)  |
| Precision | Detection Precision                      |
| Recall    | Vulnerability Recall                     |
| FNR       | False Negative Rate                      |
| FPR       | False Positive Rate                      |
| FDR       | False Discovery Rate                     |

---

# 📌 Currently Supported CWE Types

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

# 📈 Project Features

* Engineered vulnerability evaluation framework
* Supports unified evaluation of multiple tools
* Supports automatic metric calculation
* Supports experimental reproduction
* Supports modular rule management
* Supports a manifest-driven unified evaluation pipeline (v3.0.0)
* Supports automatic generation of bilingual reports (English/Chinese)
* Supports performance visualization analysis

---

# ✅ Tests and CI

```bash
python -m compileall vep/ scripts/evaluation/ scripts/reporting/ scripts/converters/
python scripts/verify_manifest.py
python -m pytest
```

The current suite contains 156 tests. GitHub Actions runs compile, manifest,
and pytest checks on Python 3.9 and 3.11. Golden fixtures protect the CWE-328
`328S` ground-truth behavior.

---

# 🚧 Future Plans

* Reduce false positives while preserving the current zero-FN baseline
* Add more CWE checkers and static analysis tool adapters
* Validate the full CodeFuse workflow on Linux
* Explore path-, field-, and context-sensitive precision improvements

---

# 📄 License

This project is released under the MIT Open Source License.
You are free to use, modify, and distribute this project under the terms of the license.
Please see the [LICENSE](LICENSE) file for complete license contents.

---

## 👨‍💻 Author

L1ngSh1

---

## ✍️ Author's Notes

This project originally stemmed from the author's thoughts during a security research internship regarding the lack of standardized evaluation methods for different static analysis tools.

The goal of Vuln-Eval-Platform is to build a structured, extensible, and reproducible vulnerability detection evaluation framework, allowing researchers to more systematically analyze the detection performance of static analysis tools on real vulnerability datasets.

This project is both a platform for research experiments and a record of the author's exploration in security research and engineering practices.

The project is still continuously evolving. Researchers interested in static analysis and vulnerability detection are welcome to participate in improving it, proposing suggestions, or contributing rules.

It would be a great comfort to the author if this project could be helpful in security research or teaching.
