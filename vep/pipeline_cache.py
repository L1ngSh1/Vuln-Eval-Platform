"""Small, pipeline-specific completion records, not a general cache framework.

An evaluation or run is reusable only when its identity and every published
artifact hash match. Legacy metrics without a completion record are rebuilt.
"""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from vep.tools.config import discover_codefuse, discover_codeql

CACHE_SCHEMA = "vep.pipeline-cache.v1"
EVALUATION_FILES = ("metrics.json", "tp.csv", "fp.csv", "fn.csv", "outside_scope.csv")


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def path_identity(path):
    """Content identity, including directory membership (not just its path)."""
    path = Path(path).resolve()
    if path.is_file():
        return {"path": str(path), "sha256": file_hash(path)}
    if not path.is_dir():
        raise FileNotFoundError(path)
    files = []
    visited = set()
    for directory, dirs, names in os.walk(path, followlinks=True):
        real = Path(directory).resolve()
        if real in visited:
            raise ValueError(f"Ambiguous/cyclic directory identity: {path}")
        visited.add(real)
        dirs.sort()
        relative = str(Path(directory).relative_to(path))
        files.append((relative + "/", None))
        for name in sorted(names):
            p = Path(directory) / name
            files.append((str(p.relative_to(path)), file_hash(p)))
    encoded = json.dumps(files, separators=(",", ":")).encode()
    return {"path": str(path), "sha256": hashlib.sha256(encoded).hexdigest()}


def evaluation_identity(tool, entry, findings_csv, ground_truth):
    root = Path(__file__).resolve().parent
    contract = [root / "core" / name for name in ("models.py", "normalization.py")]
    contract += [root / "evaluation" / name for name in (
        "evaluator.py", "findings.py", "ground_truth.py", "metrics.py", "contract.py",
    )]
    contract.append(Path(__file__))
    return {
        "schema": CACHE_SCHEMA, "stage": "evaluate", "tool": tool,
        "cwe": entry.name, "findings": path_identity(findings_csv),
        "ground_truth": path_identity(ground_truth),
        "evaluator": {p.name: file_hash(p) for p in contract},
    }


def run_context(tool, db_path, project_root):
    """Bind the effective executable/version, database and shared libraries.

    A failed version probe disables reuse; it never invents a version. Database
    content is hashed once per tool invocation, with no stat-only shortcut.
    """
    if tool.name == "codeql":
        binary, _ = discover_codeql(tool.config, project_root, tool.bin_override)
        libraries = []
    else:
        paths, _ = discover_codefuse(
            tool.config, project_root, tool.home_override,
            tool.godel_bin_override, tool.official_lib_override,
        )
        if paths is None:
            raise ValueError("CodeFuse installation identity missing")
        binary = paths.godel_bin
        libraries = [path_identity(paths.official_lib), path_identity(paths.local_lib)]
    if binary is None:
        raise ValueError("Tool executable identity missing")
    version = subprocess.run(
        [str(binary), "version"], capture_output=True, text=True,
        timeout=15, check=False, cwd=project_root,
    )
    if version.returncode != 0 or not version.stdout.strip():
        raise ValueError("Tool version probe failed; run cache disabled")
    db_path = Path(db_path)
    if not db_path.is_absolute():
        db_path = project_root / db_path
    return {
        "executable": path_identity(binary), "version": version.stdout.strip(),
        "database": path_identity(db_path), "libraries": libraries,
        "java_home": os.environ.get("JAVA_HOME"),
        "codeql_search_path": os.environ.get("CODEQL_SEARCH_PATH"),
    }


def run_identity(tool, entry, context):
    rule = entry.codeql_rule_directory if tool.name == "codeql" else entry.codefuse_rule_file
    rule = Path(rule)
    if tool.name == "codeql":
        # Include the containing query pack and lock, not just one CWE folder.
        for parent in (rule, *rule.parents):
            if (parent / "qlpack.yml").is_file():
                rule = parent
                break
    root = Path(__file__).resolve().parent
    standardizer = root / ("evaluation/sarif.py" if tool.name == "codeql"
                           else "../scripts/converters/codefuse_json_to_csv.py")
    return {
        "schema": CACHE_SCHEMA, "stage": "run", "tool": tool.name,
        "cwe": entry.name, "context": context, "rules": path_identity(rule),
        "adapter": file_hash(root / "tools" / (tool.name + ".py")),
        "standardizer": file_hash(standardizer),
        "timeout_seconds": tool.run_timeout_seconds,
    }


def cache_valid(marker, identity, required_files):
    if identity is None:
        return False
    try:
        record = json.loads(Path(marker).read_text(encoding="utf-8"))
        if record["schema"] != CACHE_SCHEMA or record["identity"] != identity:
            return False
        expected = {Path(p).name: file_hash(p) for p in required_files}
        return record["artifacts"] == expected
    except (OSError, ValueError, KeyError, TypeError):
        return False


def write_completion(marker, identity, artifacts):
    record = {"schema": CACHE_SCHEMA, "identity": identity,
              "artifacts": {Path(p).name: file_hash(p) for p in artifacts}}
    marker = Path(marker)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=marker.parent,
                                     prefix=".completion-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            json.dump(record, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
