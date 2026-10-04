"""Real shell wrappers over disposable inputs; no analysis tool or network."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.xfail(reason="Stage 3 pending", strict=True)


def workspace(tmp_path):
    ws = tmp_path / "legacy"
    ws.mkdir()
    for directory in ("vep", "scripts", "configs"):
        shutil.copytree(ROOT / directory, ws / directory,
                        ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(ROOT / "run_eval.sh", ws)
    shutil.copy(ROOT / "expectedresults-1.2.csv", ws)
    activate = ws / ".venv/bin/activate"
    activate.parent.mkdir(parents=True)
    activate.write_text(f'export PATH="{Path(sys.executable).parent}:$PATH"\n')
    return ws


def shell(ws, path, env=None):
    return subprocess.run(["bash", path], cwd=ws, text=True, capture_output=True,
                          env=dict(os.environ, PYTHON=sys.executable, **(env or {})))


def fake_python(ws, failure="", code=0):
    """Log invocations without touching the old script's fixed /tmp paths."""
    binary = ws / "fake-bin"
    binary.mkdir()
    program = f'''#!{sys.executable}
import json, os, pathlib, sys
args = sys.argv[1:]
paths = [args[i+1] for i, a in enumerate(args[:-1]) if a in ("--out", "--csv-out")]
record = {{"args": args, "paths": paths,
          "modes": [pathlib.Path(p).parent.stat().st_mode & 0o777 for p in paths]}}
with open(os.environ["CALL_LOG"], "a") as handle:
    handle.write(json.dumps(record) + "\\n")
print("TP FP FN Precision Recall F1")
sys.exit({code} if {failure!r} and {failure!r} in " ".join(args) else 0)
'''
    for name in ("python", "python3"):
        p = binary / name
        p.write_text(program)
        p.chmod(0o755)
    (ws / ".venv/bin/activate").write_text(f'export PATH="{binary}:$PATH"\n')
    return {"PATH": f"{binary}:{os.environ['PATH']}", "PYTHON": str(binary / "python"),
            "CALL_LOG": str(ws / "calls.jsonl")}


def test_quick_verify_missing_inputs_is_nonzero(tmp_path):
    ws = workspace(tmp_path)
    result = shell(ws, "scripts/quick_verify.sh")
    assert result.returncode != 0
    assert "Phase 2 验证完成" not in result.stdout


@pytest.mark.parametrize("failure,code", [("verify_manifest.py", 23), ("compileall", 37)])
def test_quick_verify_preserves_child_exit(tmp_path, failure, code):
    ws = workspace(tmp_path)
    result = shell(ws, "scripts/quick_verify.sh", fake_python(ws, failure, code))
    assert result.returncode == code
    assert "Phase 2 验证完成" not in result.stdout


def test_quick_verify_parallel_private_outputs_and_cleanup(tmp_path):
    ws = workspace(tmp_path)
    env = dict(os.environ, **fake_python(ws))
    jobs = [subprocess.Popen(["bash", "scripts/quick_verify.sh"], cwd=ws, env=env,
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for _ in range(2)]
    for job in jobs:
        stdout, stderr = job.communicate(timeout=30)
        assert job.returncode == 0, stdout + stderr
    records = [json.loads(line) for line in (ws / "calls.jsonl").read_text().splitlines()]
    outputs = [(p, m) for r in records for p, m in zip(r["paths"], r["modes"])]
    assert outputs
    assert all(mode == 0o700 for _, mode in outputs)
    parents = {str(Path(path).parent) for path, _ in outputs}
    assert len(parents) == 2
    assert all(not Path(parent).exists() for parent in parents)
    sarif_calls = [r for r in records if any("eval_sarif_findings.py" in a for a in r["args"])]
    assert all("--csv-out" in r["args"] for r in sarif_calls)


def test_run_eval_sarif_only_normalizes_then_evaluates(tmp_path):
    import yaml

    ws = workspace(tmp_path)
    manifest = yaml.safe_load((ws / "configs/cwe_manifest.yml").read_text())
    for entry in manifest["cwes"]:
        directory = ws / entry["experiments"]["directory"] / "results/codeql"
        directory.mkdir(parents=True)
        (directory / f'cwe{entry["id"]}.sarif').write_text(json.dumps({
            "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}},
                                           "results": []}],
        }))
    result = shell(ws, "run_eval.sh", {"MPLBACKEND": "Agg", "MPLCONFIGDIR": str(ws / "mpl")})
    assert result.returncode == 0, result.stdout + result.stderr
    for entry in manifest["cwes"]:
        directory = ws / entry["experiments"]["directory"]
        assert (directory / f'results/codeql/cwe{entry["id"]}.csv').is_file()
        assert (directory / "eval/codeql_eval_v2/metrics.json").is_file()
