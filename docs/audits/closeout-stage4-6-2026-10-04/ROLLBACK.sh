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
from pathlib import Path
import shutil
import stat
import sys

audit, target = (Path(p).resolve() for p in sys.argv[1:])
root = audit.parents[2]
if not target.is_dir() or target == root or (target / '.git').exists():
    raise SystemExit('TARGET_COPY must be a separate non-Git checkout copy')
baseline = json.loads((audit / 'baseline-manifest.json').read_text())
modified = json.loads((audit / 'modified-manifest.json').read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
for name, meta in baseline['original_files'].items():
    if sha(audit / 'originals' / name) != meta['sha256']:
        raise SystemExit(f'Original hash mismatch: {name}')
for name, meta in modified['files'].items():
    p = target / name
    if not p.is_file() or sha(p) != meta['sha256']:
        raise SystemExit(f'Target differs from verified patch: {name}')
for name, meta in modified['files'].items():
    p = target / name
    if name in baseline['original_files']:
        old = baseline['original_files'][name]
        shutil.copy2(audit / 'originals' / name, p)
        p.chmod(old['mode'])
        assert sha(p) == old['sha256'] and stat.S_IMODE(p.stat().st_mode) == old['mode']
    else:
        p.unlink()
        assert not p.exists()
print('ROLLBACK_ACTION: original hashes/modes restored; new stage4-6 product files removed; exit=0')
PY
