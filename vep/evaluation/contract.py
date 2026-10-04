"""Small, explicit metric/population contract for archived VEP results."""

import hashlib
import json

from vep.core.normalization import normalize_cwe_id, normalize_testcase_id

METRIC_CONTRACT = "vep.metrics.v1"
UNIT = "testcase_per_cwe"
STANDARD_FPR = "FP_in_scope / (FP_in_scope + TN_in_scope)"
CUSTOM_FPR = "custom: FP_all_non_gt / (FP_all_non_gt + TN_in_scope); not standard FPR"


def standard_fpr(fp_in_scope, tn):
    if fp_in_scope is None or tn is None or fp_in_scope + tn == 0:
        return None
    return round(fp_in_scope / (fp_in_scope + tn), 4)


def metric_modes(tp, fp_in_scope, fp_all_non_gt, fn, tn):
    def metrics(fp, mode):
        if fp is None:
            return None
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
                "fpr_in_scope": standard_fpr(fp_in_scope, tn),
                "fpr_definition": STANDARD_FPR if mode == "in_scope" else CUSTOM_FPR,
                "fpr_custom": standard_fpr(fp, tn) if mode == "all_non_gt" else None}
    return {"all_non_gt": metrics(fp_all_non_gt, "all_non_gt"),
            "in_scope": metrics(fp_in_scope, "in_scope")}


def sample_scope(expected_cases, cwe):
    labels = {}
    dataset_ids = set()
    for case in expected_cases:
        tc = normalize_testcase_id(case.testcase)
        if not tc:
            raise ValueError("Ground truth contains an empty testcase identity")
        if tc in labels and labels[tc] != case.is_vulnerable:
            raise ValueError(f"Conflicting ground truth labels: {tc}")
        labels[tc] = case.is_vulnerable
        dataset_ids.add(case.raw.get("dataset_sha256"))
    if len(dataset_ids) > 1:
        raise ValueError("Mixed ground truth datasets")
    dataset_id = next(iter(dataset_ids), None)
    identity = {"unit": UNIT, "cwe": normalize_cwe_id(cwe), "labels": sorted(labels.items())}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"unit": UNIT, "cwe": normalize_cwe_id(cwe), "scope_sha256": digest,
            "dataset_sha256": dataset_id, "total": len(labels),
            "positive": sum(labels.values()), "negative": len(labels) - sum(labels.values()),
            "verified": dataset_id is not None}
