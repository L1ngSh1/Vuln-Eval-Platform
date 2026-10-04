"""Real shell wrappers over disposable inputs; no analysis tool or network."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


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
                          env={**os.environ, "PYTHON": sys.executable, **(env or {})})


def fake_python(ws, failure="", code=0):
    """Log invocations without touching the old script's fixed /tmp paths."""
    binary = ws / "fake-bin"
    binary.mkdir()
    program = f'''#!{sys.executable}
import json, os, pathlib, sys
args = sys.argv[1:]
paths = [args[i+1] for i, a in enumerate(args[:-1]) if a in ("--out", "--csv-out")]
record = {{"args": args, "paths": paths, "cwd": os.getcwd(),
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


@pytest.mark.parametrize("failure,code", [
    ("verify_manifest.py", 23), ("compileall", 37),
    ("eval_findings.py", 41), ("eval_sarif_findings.py", 43), ("aggregate_v2.py", 47),
])
def test_quick_verify_preserves_child_exit(tmp_path, failure, code):
    ws = workspace(tmp_path)
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    env = dict(fake_python(ws, failure, code), TMPDIR=str(temporary))
    result = shell(ws, "scripts/quick_verify.sh", env)
    assert result.returncode == code
    assert "Phase 2 验证完成" not in result.stdout
    assert not list(temporary.iterdir())


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


def prepare_sarif(ws):
    import yaml

    manifest = yaml.safe_load((ws / "configs/cwe_manifest.yml").read_text())
    for entry in manifest["cwes"]:
        directory = ws / entry["experiments"]["directory"] / "results/codeql"
        directory.mkdir(parents=True)
        (directory / f'cwe{entry["id"]}.sarif').write_text(json.dumps({
            "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}},
                                           "results": []}],
        }))
    return manifest


def test_run_eval_sarif_only_normalizes_then_evaluates(tmp_path):
    from vep.evaluation.ground_truth import load_expected_cases

    ws = workspace(tmp_path)
    manifest = prepare_sarif(ws)
    first = manifest["cwes"][0]
    expected = load_expected_cases(ws / "expectedresults-1.2.csv", cwe=first["name"])
    positive = next(case for case in expected if case.is_vulnerable)
    sarif = ws / first["experiments"]["directory"] / f'results/codeql/cwe{first["id"]}.sarif'
    payload = json.loads(sarif.read_text())
    payload["runs"][0]["results"] = [{
        "ruleId": "fixture/positive", "message": {"text": "known positive"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f"src/{positive.testcase}.java"},
            "region": {"startLine": 9},
        }}],
    }]
    sarif.write_text(json.dumps(payload))
    result = shell(ws, "run_eval.sh", {"MPLBACKEND": "Agg", "MPLCONFIGDIR": str(ws / "mpl")})
    assert result.returncode == 0, result.stdout + result.stderr
    for entry in manifest["cwes"]:
        directory = ws / entry["experiments"]["directory"]
        assert (directory / f'results/codeql/cwe{entry["id"]}.csv').is_file()
        assert (directory / "eval/codeql_eval_v2/metrics.json").is_file()
    directory = ws / first["experiments"]["directory"]
    metrics = json.loads((directory / "eval/codeql_eval_v2/metrics.json").read_text())
    assert metrics["tp"] == 1 and metrics["fp"] == 0
    assert metrics["fn"] == sum(case.is_vulnerable for case in expected) - 1
    normalized = (directory / f'results/codeql/cwe{first["id"]}.csv').read_text()
    assert positive.testcase in normalized and "fixture/positive" in normalized


@pytest.mark.parametrize("damage", ["missing", "bad_json", "wrong_shape"])
def test_run_eval_invalid_sarif_stops_before_evaluation(tmp_path, damage):
    ws = workspace(tmp_path)
    manifest = prepare_sarif(ws)
    # An old CSV must never conceal a failing conversion.
    for entry in manifest["cwes"]:
        directory = ws / entry["experiments"]["directory"] / "results/codeql"
        (directory / f'cwe{entry["id"]}.csv').write_text("testcase,ruleId,file,line\n")
    first = manifest["cwes"][0]
    directory = ws / first["experiments"]["directory"] / "results/codeql"
    sarif = directory / f'cwe{first["id"]}.sarif'
    original = (directory / f'cwe{first["id"]}.csv').read_bytes()
    if damage == "missing":
        sarif.unlink()
    else:
        sarif.write_text("{" if damage == "bad_json" else "[]")
    result = shell(ws, "run_eval.sh", {"MPLBACKEND": "Agg", "MPLCONFIGDIR": str(ws / "mpl")})
    assert result.returncode != 0
    assert "Evaluation Completed Successfully" not in result.stdout
    assert not list(ws.glob("experiments/*/eval/*/metrics.json"))
    assert (directory / f'cwe{first["id"]}.csv').read_bytes() == original
    assert not list(ws.glob("experiments/*/results/codeql/.vep-sarif-*"))


def test_run_eval_pipeline_failure_preserves_exit(tmp_path):
    ws = workspace(tmp_path)
    prepare_sarif(ws)
    result = shell(ws, "run_eval.sh", fake_python(ws, "run_pipeline.py", 53))
    assert result.returncode == 53
    assert "Evaluation Completed Successfully" not in result.stdout


def test_eval_checker_missing_argument_is_nonzero(tmp_path):
    ws = workspace(tmp_path)
    assert shell(ws, "scripts/evaluation/eval_checker.sh").returncode != 0


def test_eval_checker_preserves_exit_and_spaced_database(tmp_path):
    ws = workspace(tmp_path)
    env = dict(os.environ, **fake_python(ws, "run_pipeline.py", 59), DB_DIR="database with spaces")
    result = subprocess.run(["bash", "scripts/evaluation/eval_checker.sh", "022"],
                            cwd=ws, env=env, text=True, capture_output=True)
    assert result.returncode == 59
    call = json.loads((ws / "calls.jsonl").read_text().splitlines()[0])
    assert call["args"][call["args"].index("--db") + 1] == "database with spaces"


@pytest.mark.parametrize("script,args", [
    ("run_eval.sh", []), ("scripts/quick_verify.sh", []),
    ("scripts/evaluation/eval_checker.sh", ["022"]),
])
def test_legacy_entrypoint_resolves_own_root(tmp_path, script, args):
    ws = workspace(tmp_path)
    prepare_sarif(ws)
    env = dict(os.environ, **fake_python(ws))
    result = subprocess.run(["bash", str(ws / script), *args], cwd=tmp_path,
                            env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [json.loads(line) for line in (ws / "calls.jsonl").read_text().splitlines()]
    assert calls and all(call["cwd"] == str(ws) for call in calls)


def test_quick_verify_real_cli_success_cleans_private_outputs(tmp_path):
    from vep.evaluation.evaluator import evaluate_findings_with_details
    from vep.evaluation.ground_truth import load_expected_cases
    from vep.evaluation.metrics import write_metrics_json

    ws = workspace(tmp_path)
    prepare_sarif(ws)
    csv = ws / "experiments/cwe-022/results/codefuse-query/cwe022_codefuse.csv"
    csv.parent.mkdir(parents=True)
    csv.write_text("testcase,ruleId,file,line\n")
    for cwe in ("022", "089"):
        result, _ = evaluate_findings_with_details(
            findings=[], expected_cases=load_expected_cases(ws / "expectedresults-1.2.csv", cwe=f"CWE-{cwe}"),
            tool="codefuse", cwe=f"CWE-{cwe}", include_tn=True,
        )
        write_metrics_json(result, ws / f"experiments/cwe-{cwe}/eval/codefuse_eval_v2b/metrics.json")
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    result = shell(ws, "scripts/quick_verify.sh", {"TMPDIR": str(temporary)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Phase 2 验证完成" in result.stdout
    assert not list(temporary.iterdir())
    assert not (ws / "findings.csv").exists()
