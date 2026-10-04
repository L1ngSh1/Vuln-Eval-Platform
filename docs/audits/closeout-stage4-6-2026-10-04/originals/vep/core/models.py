"""VEP Core: Data models for unified evaluation.

Phase 2: Unified Evaluation Core
Standard library dataclasses for findings, expected cases, and evaluation results.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """Represents a single vulnerability finding from a static analysis tool.

    Attributes:
        testcase: Benchmark test case identifier (e.g., "BenchmarkTest00001")
        rule_id: Rule or CWE identifier (e.g., "CWE-022")
        file: Source file path
        line: Line number (optional)
        tool: Tool name (e.g., "codefuse", "codeql")
        cwe: CWE identifier (optional, may differ from rule_id)
        message: Finding message or reason (optional)
        raw: Original data for extension fields
    """
    testcase: str
    rule_id: str
    file: str
    line: Optional[int] = None
    tool: Optional[str] = None
    cwe: Optional[str] = None
    message: Optional[str] = None
    raw: dict = field(default_factory=dict)


@dataclass
class ExpectedCase:
    """Represents a ground truth test case from OWASP Benchmark.

    Attributes:
        testcase: Test case identifier
        cwe: CWE identifier
        is_vulnerable: True if this is a true positive case
        category: Vulnerability category (optional)
        raw: Original data for extension fields
    """
    testcase: str
    cwe: str
    is_vulnerable: bool
    category: Optional[str] = None
    raw: dict = field(default_factory=dict)


@dataclass
class EvalResult:
    """Represents evaluation metrics for a tool on a specific CWE.

    Attributes:
        tool: Tool name
        cwe: CWE identifier
        tp: True positives
        fp: False positives
        fn: False negatives
        tn: True negatives (optional)
        precision: TP / (TP + FP)
        recall: TP / (TP + FN)
        f1: F1 score
        fnr: False negative rate (FN / (TP + FN))
        fpr: False positive rate (FP / (FP + TN))
        fdr: False discovery rate (FP / (TP + FP))
        total_findings: Total number of findings (before deduplication)
        dedup_findings: Unique testcases detected
        total_expected_vulnerable: Total vulnerable cases in ground truth
        total_expected_cases: Total cases in ground truth (optional)
        in_scope_findings: Findings within CWE scope
        outside_scope_findings: Findings outside CWE scope
        outside_scope_ratio: Ratio of outside-scope findings
        fp_in_scope: False positives (in-scope only)
        fp_all_non_gt: False positives (all non-ground-truth)
        fp_mode: FP calculation mode ("all_non_gt" or "in_scope")
        schema_version: Schema version identifier
    """
    tool: str
    cwe: str
    tp: int
    fp: int
    fn: int
    tn: Optional[int]
    precision: float
    recall: float
    f1: float
    fnr: float
    fpr: float
    fdr: float
    total_findings: int
    dedup_findings: int
    total_expected_vulnerable: int
    total_expected_cases: Optional[int]
    in_scope_findings: int
    outside_scope_findings: int
    outside_scope_ratio: float
    fp_in_scope: int
    fp_all_non_gt: int
    fp_mode: str = "all_non_gt"
    schema_version: str = "vep.eval.v2"


@dataclass
class EvaluationDetails:
    """Detailed evaluation results for CSV output.

    Attributes:
        tp_rows: True positive details
        fp_rows: False positive details
        fn_rows: False negative details
        outside_scope_rows: Outside-scope finding details
    """
    tp_rows: list
    fp_rows: list
    fn_rows: list
    outside_scope_rows: list
