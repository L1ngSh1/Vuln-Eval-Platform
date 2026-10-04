# Changelog

All notable changes to Vuln-Eval-Platform are documented here.

## [Unreleased]

- Precision research for high-FP CWE checkers is planned for the V3.x series.

## [3.0.0] - 2026-09-01

### Added

- Manifest-driven `run_pipeline.py` entry for CodeFuse-Query, CodeQL, or both tools.
- Automatic tool/database discovery with CLI, environment, config, PATH, and fallback precedence.
- CodeFuse JAVA_HOME/JDK type-model gate.
- V2 normalized evaluation, multi-CWE aggregation, bilingual reports, and charts.
- Combined CodeFuse-Query/CodeQL comparison reports plus standalone tool reports.
- 149+ pytest tests, golden pipeline fixtures, CWE-328 `328S` guard, and Python 3.9/3.11 CI.

### Changed

- `run_eval.sh` and `eval_checker.sh` are compatibility wrappers around the unified pipeline.
- CodeFuse evaluation output uses `codefuse_eval_v2` and aggregate schema `vep.aggregate.v2`.
- Reports use user-facing `CodeFuse-Query` and `CodeQL` labels while machine IDs remain stable.

### Fixed

- Prevented the CodeQL report from overwriting the CodeFuse-Query report in `--tool both` runs.
- Propagated report-generation failures through the pipeline exit status.
- Rejected ambiguous `--tool both --aggregate-name` invocations.
- Corrected CWE-328 ground-truth handling for the OWASP `328S` variant.

### Compatibility

- Existing metrics schemas and normalized CSV formats are unchanged.
- Legacy entry scripts remain available for one release cycle.
