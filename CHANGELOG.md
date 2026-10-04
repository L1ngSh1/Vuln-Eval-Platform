# Changelog

All notable changes to Vuln-Eval-Platform are documented here.

## [3.0.1] - 2026-10-04

### Fixed

- Cache identities now bind inputs, metric mode, evaluator/rules/tool/database context; corrupt or incomplete entries recompute.
- Ordered CWE deduplication and aggregation guards prevent duplicate totals.
- Legacy entries propagate real exit codes, normalize SARIF before evaluation, and use private cleaned temporary directories.
- Metric/report merges reject incompatible FP modes and sample populations instead of silently mixing them.

### Added

- Explicit sample hashes, dual FP-mode metrics, outside-scope counts and standard `fpr_in_scope`; historical all_non_gt and custom `fpr` values remain unchanged.
- Checksummed normalized inputs for both tools across 11 CWEs, GT, historical metrics, version records, locked dependencies and offline archive replay.
- 257-test closeout suite, clean-checkout replay acceptance, bilingual reports and FP-mode-aware charts.
- Complete platform MIT text, third-party notices/licenses, known limits and separate archive gates.

### Compatibility and closeout

- Existing metric schemas remain readable; additive contract fields describe new results. Identity-unknown historical reports can render singly but are not silently combined.
- The final guarantee is archived-result replay after dependency installation. Fixed-version analyzer rebuilding/execution and cross-platform rule regression were not revalidated.
- CodeFuse historical run version and original imported source revisions remain explicitly unknown.
- This is the final feature closeout. Publishing does not make the repository read-only; archival requires a separate explicit final confirmation.

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
