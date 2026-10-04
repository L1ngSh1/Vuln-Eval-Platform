"""VEP Evaluation: Unified evaluator for vulnerability findings.

Phase 2B: Enhanced evaluator with detailed outputs and FP mode support.
Core evaluation logic compatible with eval_codefuse_results.py.
"""

from typing import List, Tuple

from vep.core.models import Finding, ExpectedCase, EvalResult, EvaluationDetails
from vep.core.normalization import normalize_testcase_id


def evaluate_findings(
    findings: List[Finding],
    expected_cases: List[ExpectedCase],
    tool: str,
    cwe: str,
    include_tn: bool = True,
    fp_mode: str = "all_non_gt",
) -> EvalResult:
    """Evaluate findings against ground truth (simple version for backward compatibility).

    Args:
        findings: List of Finding objects
        expected_cases: List of ExpectedCase objects
        tool: Tool name
        cwe: CWE identifier
        include_tn: Whether to calculate true negatives
        fp_mode: FP calculation mode ("all_non_gt" or "in_scope")

    Returns:
        EvalResult with metrics (without details)
    """
    result, _ = evaluate_findings_with_details(
        findings, expected_cases, tool, cwe, include_tn, fp_mode
    )
    return result


def evaluate_findings_with_details(
    findings: List[Finding],
    expected_cases: List[ExpectedCase],
    tool: str,
    cwe: str,
    include_tn: bool = True,
    fp_mode: str = "all_non_gt",
) -> Tuple[EvalResult, EvaluationDetails]:
    """Evaluate findings with detailed row-level results.

    Matching strategy:
        - Match by testcase identifier (deduplicate multiple findings per testcase)
        - TP: finding matches vulnerable expected case
        - FP: depends on fp_mode
          - all_non_gt: finding does NOT match vulnerable case (includes out-of-scope)
          - in_scope: finding matches non-vulnerable case (excludes out-of-scope)
        - FN: vulnerable expected case with no finding
        - TN: non-vulnerable expected case with no finding (if include_tn=True)

    Args:
        findings: List of Finding objects
        expected_cases: List of ExpectedCase objects
        tool: Tool name for result metadata
        cwe: CWE identifier for result metadata
        include_tn: Whether to calculate true negatives
        fp_mode: "all_non_gt" or "in_scope"

    Returns:
        Tuple of (EvalResult, EvaluationDetails)
    """
    # Deduplicate findings by testcase (keep first occurrence)
    testcase_to_finding = {}
    for finding in findings:
        tc = normalize_testcase_id(finding.testcase)
        if tc and tc not in testcase_to_finding:
            testcase_to_finding[tc] = finding

    detected_testcases = set(testcase_to_finding.keys())

    # Build ground truth sets
    vulnerable_cases = set()
    non_vulnerable_cases = set()
    all_expected_cases = set()

    for expected in expected_cases:
        tc = normalize_testcase_id(expected.testcase)
        all_expected_cases.add(tc)
        if expected.is_vulnerable:
            vulnerable_cases.add(tc)
        else:
            non_vulnerable_cases.add(tc)

    # Calculate sets
    tp_cases = detected_testcases & vulnerable_cases
    fp_in_scope_cases = detected_testcases & non_vulnerable_cases
    fp_out_scope_cases = detected_testcases - all_expected_cases
    fn_cases = vulnerable_cases - detected_testcases
    tn_cases = non_vulnerable_cases - detected_testcases
    in_scope_cases = detected_testcases & all_expected_cases
    outside_scope_cases = fp_out_scope_cases

    # Metrics
    tp = len(tp_cases)
    fp_in_scope = len(fp_in_scope_cases)
    fp_all_non_gt = len(fp_in_scope_cases) + len(fp_out_scope_cases)
    fn = len(fn_cases)
    tn = len(tn_cases) if include_tn else None

    # FP based on mode
    if fp_mode == "in_scope":
        fp = fp_in_scope
    else:  # all_non_gt (default)
        fp = fp_all_non_gt

    # Calculate rates
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (tn is not None and (fp + tn) > 0) else 0.0
    fdr = fp / (tp + fp) if (tp + fp) > 0 else 0.0

    dedup_findings = len(detected_testcases)
    in_scope_findings = len(in_scope_cases)
    outside_scope_findings = len(outside_scope_cases)
    outside_scope_ratio = outside_scope_findings / dedup_findings if dedup_findings > 0 else 0.0

    # Round metrics (4 decimal places)
    precision = round(precision, 4)
    recall = round(recall, 4)
    f1 = round(f1, 4)
    fnr = round(fnr, 4)
    fpr = round(fpr, 4)
    fdr = round(fdr, 4)
    outside_scope_ratio = round(outside_scope_ratio, 4)

    # Build detailed rows
    tp_rows = []
    fp_rows = []
    fn_rows = []
    outside_scope_rows = []

    # TP rows
    for tc in sorted(tp_cases):
        finding = testcase_to_finding.get(tc)
        if finding:
            tp_rows.append({
                "testcase": finding.testcase,
                "testcaseId": tc.replace("BenchmarkTest", "") if "BenchmarkTest" in tc else "",
                "sinkFile": finding.file,
                "line": finding.line if finding.line else "",
                "ruleId": finding.rule_id,
                "findingCount": 1,
            })

    # FP rows (in-scope)
    for tc in sorted(fp_in_scope_cases):
        finding = testcase_to_finding.get(tc)
        if finding:
            fp_rows.append({
                "testcase": finding.testcase,
                "testcaseId": tc.replace("BenchmarkTest", "") if "BenchmarkTest" in tc else "",
                "sinkFile": finding.file,
                "line": finding.line if finding.line else "",
                "ruleId": finding.rule_id,
                "findingCount": 1,
            })

    # Outside-scope rows
    for tc in sorted(outside_scope_cases):
        finding = testcase_to_finding.get(tc)
        if finding:
            outside_scope_rows.append({
                "testcase": finding.testcase,
                "testcaseId": tc.replace("BenchmarkTest", "") if "BenchmarkTest" in tc else "",
                "sinkFile": finding.file,
                "line": finding.line if finding.line else "",
                "ruleId": finding.rule_id,
                "findingCount": 1,
            })

    # FN rows
    for tc in sorted(fn_cases):
        fn_rows.append({
            "testcase": tc,
            "testcaseId": tc.replace("BenchmarkTest", "") if "BenchmarkTest" in tc else "",
            "sinkFile": "",
            "line": "",
            "ruleId": "",
            "findingCount": 0,
        })

    # Create result
    result = EvalResult(
        tool=tool,
        cwe=cwe,
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=precision,
        recall=recall,
        f1=f1,
        fnr=fnr,
        fpr=fpr,
        fdr=fdr,
        total_findings=len(findings),
        dedup_findings=dedup_findings,
        total_expected_vulnerable=len(vulnerable_cases),
        total_expected_cases=len(all_expected_cases),
        in_scope_findings=in_scope_findings,
        outside_scope_findings=outside_scope_findings,
        outside_scope_ratio=outside_scope_ratio,
        fp_in_scope=fp_in_scope,
        fp_all_non_gt=fp_all_non_gt,
        fp_mode=fp_mode,
        schema_version="vep.eval.v2"
    )

    details = EvaluationDetails(
        tp_rows=tp_rows,
        fp_rows=fp_rows,
        fn_rows=fn_rows,
        outside_scope_rows=outside_scope_rows
    )

    return result, details
