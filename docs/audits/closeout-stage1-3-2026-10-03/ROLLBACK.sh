#!/usr/bin/env bash
set -eo pipefail
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 TARGET_COPY" >&2
    exit 2
fi
AUDIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${PYTHON:-python3}" - "$AUDIT" "$1" <<'PY'
import hashlib
import json
import shutil
import stat
import sys
from pathlib import Path

audit = Path(sys.argv[1]).resolve()
target = Path(sys.argv[2]).resolve()
root = audit.parents[2]
if not target.is_dir() or target == root or (target / ".git").exists():
    raise SystemExit("TARGET_COPY must be a separate non-Git checkout copy")
baseline = json.loads((audit / "baseline-manifest.json").read_text())
modified = json.loads((audit / "modified-manifest.json").read_text())
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
# Check every input before changing any target file.
for name, meta in baseline["original_files"].items():
    if sha(audit / "originals" / name) != meta["sha256"]:
        raise SystemExit(f"Original hash mismatch: {name}")
for name, meta in modified["files"].items():
    if not (target / name).is_file() or sha(target / name) != meta["sha256"]:
        raise SystemExit(f"Target differs from verified patch: {name}")
for name, meta in baseline["original_files"].items():
    shutil.copy2(audit / "originals" / name, target / name)
    (target / name).chmod(meta["mode"])
for source in (audit / "baseline-tests").glob("*.py"):
    shutil.copy2(source, target / "tests/python" / source.name)
(target / "vep/pipeline_cache.py").unlink()
for name, meta in baseline["original_files"].items():
    assert sha(target / name) == meta["sha256"]
    assert stat.S_IMODE((target / name).stat().st_mode) == meta["mode"]
print("ROLLBACK_ACTION: original hashes/modes restored; pipeline_cache.py removed; exit=0")
PY
