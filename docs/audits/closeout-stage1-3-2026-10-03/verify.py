#!/usr/bin/env python3
"""Reproduce stage 1--3 evidence in disposable tracked-file snapshots."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

AUDIT = Path(__file__).resolve().parent
ROOT = AUDIT.parents[2]
PRODUCT_FILES = (
    "vep/core/manifest.py", "vep/evaluation/aggregate.py", "vep/pipeline.py",
    "vep/pipeline_cache.py", "run_eval.sh", "scripts/quick_verify.sh",
    "scripts/evaluation/eval_checker.sh", "tests/python/test_pipeline_cache.py",
    "tests/python/test_pipeline_golden.py", "tests/python/test_legacy_entrypoints.py",
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def preserved():
    baseline = json.loads((AUDIT / "baseline-manifest.json").read_text())
    for name, digest in baseline["preserved_evidence"].items():
        assert sha(ROOT / name) == digest, f"Historical evidence changed: {name}"
    for name, meta in baseline["original_files"].items():
        assert sha(AUDIT / "originals" / name) == meta["sha256"], name
    return baseline


def snapshot(destination):
    process = subprocess.Popen(["git", "archive", "HEAD"], cwd=ROOT, stdout=subprocess.PIPE)
    with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
        archive.extractall(destination)
    assert process.wait() == 0
    # Include only named patches, never ignored analyzer databases or results.
    for name in PRODUCT_FILES:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)


def frozen_regressions(destination):
    """Use identical 19 fixtures, correcting the frozen fixture's env merge."""
    for source in sorted((AUDIT / "baseline-tests").glob("*.py")):
        content = source.read_text()
        if source.name == "test_legacy_entrypoints.py":
            content = content.replace(
                "env=dict(os.environ, PYTHON=sys.executable, **(env or {}))",
                'env={**os.environ, "PYTHON": sys.executable, **(env or {})}',
            )
        (destination / "tests/python" / source.name).write_text(content)
    return {p.name: sha(p) for p in sorted((destination / "tests/python").glob("test_*.py"))
            if p.name in ("test_pipeline_cache.py", "test_legacy_entrypoints.py")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("baseline", "modified", "rollback"), required=True)
    mode = parser.parse_args().mode
    baseline = preserved()
    restored = None
    action = None
    with tempfile.TemporaryDirectory(prefix=f"vep-closeout-{mode}-", dir=ROOT.parent) as temp:
        workspace = Path(temp)
        snapshot(workspace)
        if mode == "baseline":
            for name in baseline["original_files"]:
                shutil.copy2(AUDIT / "originals" / name, workspace / name)
            (workspace / "vep/pipeline_cache.py").unlink()
        elif mode == "rollback":
            command = [str(AUDIT / "ROLLBACK.sh"), str(workspace)]
            result = subprocess.run(command, text=True, capture_output=True,
                                    env={**os.environ, "PYTHON": sys.executable})
            action = {"command": command, "exit_status": result.returncode,
                      "stdout": result.stdout, "stderr": result.stderr}
            assert result.returncode == 0, result.stdout + result.stderr
            restored = all(sha(workspace / name) == meta["sha256"]
                           for name, meta in baseline["original_files"].items())
            restored = restored and not (workspace / "vep/pipeline_cache.py").exists()
            assert restored
        fixtures = frozen_regressions(workspace)
        command = [sys.executable, "-m", "pytest", "tests/python/test_pipeline_cache.py",
                   "tests/python/test_legacy_entrypoints.py", "--runxfail"]
        result = subprocess.run(command, cwd=workspace, text=True, capture_output=True)
        summary = result.stdout.strip().splitlines()[-1].split(" in ")[0]
        expected = 0 if mode == "modified" else 1
        assert result.returncode == expected, result.stdout + result.stderr
        assert summary == ("19 passed" if expected == 0 else "19 failed"), summary
        assert "dict() got multiple values" not in result.stdout
        assert "TypeError: dict(" not in result.stdout
        literal = f"{mode.upper()}: {summary}; pytest exit={result.returncode}"
        if mode == "rollback":
            literal += "; restored=PASS"
        record = {"command": command, "cwd": str(workspace), "input": "same 19 frozen mini regressions; corrected env merge",
                  "fixtures_sha256": fixtures, "exit_status": result.returncode,
                  "stdout": result.stdout, "stderr": result.stderr, "literal_output": literal,
                  "rollback_action": action, "restored": restored}
        if mode == "rollback":
            suite = subprocess.run([sys.executable, "-m", "pytest"], cwd=workspace,
                                   text=True, capture_output=True)
            record["restored_suite"] = {"command": [sys.executable, "-m", "pytest"],
                                       "exit_status": suite.returncode, "stdout": suite.stdout, "stderr": suite.stderr}
            assert suite.returncode == 0, suite.stdout + suite.stderr
            assert "156 passed, 19 xfailed" in suite.stdout
        (AUDIT / f"{mode.upper()}_verified.json").write_text(json.dumps(record, indent=2) + "\n")
    print(literal)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
