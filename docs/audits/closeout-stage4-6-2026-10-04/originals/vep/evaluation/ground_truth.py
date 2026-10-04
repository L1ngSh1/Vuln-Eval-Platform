"""VEP Evaluation: Load ground truth (expected cases) from OWASP Benchmark.

Phase 2: Unified Evaluation Core
"""

import csv
from pathlib import Path
from typing import List, Optional

from vep.core.models import ExpectedCase
from vep.core.normalization import normalize_cwe_id, normalize_testcase_id, normalize_truth_value


def load_expected_cases(
    path: Path,
    cwe: Optional[str] = None
) -> List[ExpectedCase]:
    """Load expected test cases from OWASP Benchmark ground truth CSV.

    Expected CSV format (flexible header matching):
        - testcase / test name / name
        - category
        - real vulnerability / vulnerable / expected
        - cwe / cweid

    Args:
        path: Path to expectedresults CSV file
        cwe: Optional CWE filter (e.g., "CWE-022", "022", "cwe-022")

    Returns:
        List of ExpectedCase objects

    Note:
        Supports flexible field name matching for ground truth CSV variants.
        CWE matching handles suffixes (e.g., "328S" matches CWE-328).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Ground truth file not found: {path}")

    # Normalize target CWE if provided
    target_cwe_normalized = normalize_cwe_id(cwe) if cwe else None

    expected_cases = []

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)

        for row in reader:
            # Skip empty rows and comments
            if not row or str(row[0]).strip().startswith("#"):
                continue

            # Expected format: testcase, category, real_vulnerability, cwe
            if len(row) < 4:
                continue

            testcase_raw = row[0].strip()
            category = row[1].strip()
            vulnerable_raw = row[2].strip()
            cwe_raw = row[3].strip()

            # Normalize
            testcase = normalize_testcase_id(testcase_raw)
            is_vulnerable = normalize_truth_value(vulnerable_raw)

            # Handle CWE normalization (support suffix like "328S")
            case_cwe_normalized = normalize_cwe_id(cwe_raw)

            # Special handling for CWE-328S -> CWE-328
            # Ground truth may have "328S", we normalize to "CWE-328"
            if cwe_raw.upper() == "328S":
                case_cwe_normalized = "CWE-328"

            # Skip if truth value ambiguous
            if is_vulnerable is None:
                continue

            # Filter by CWE if specified
            if target_cwe_normalized:
                if case_cwe_normalized != target_cwe_normalized:
                    # Also check raw CWE for suffix variants
                    if not (target_cwe_normalized == "CWE-328" and cwe_raw.upper() == "328S"):
                        continue

            expected_case = ExpectedCase(
                testcase=testcase,
                cwe=case_cwe_normalized,
                is_vulnerable=is_vulnerable,
                category=category,
                raw={
                    "testcase_raw": testcase_raw,
                    "cwe_raw": cwe_raw,
                    "vulnerable_raw": vulnerable_raw
                }
            )

            expected_cases.append(expected_case)

    return expected_cases
