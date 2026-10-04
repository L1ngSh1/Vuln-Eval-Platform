#!/usr/bin/env python3
"""Run frozen metric regressions against separate baseline/patch/rollback copies."""
import argparse
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

AUDIT = Path(__file__).resolve().parent
ROOT = AUDIT.parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['baseline', 'modified', 'rollback'], required=True)
    mode = parser.parse_args().mode
    baseline = json.loads((AUDIT / 'baseline-manifest.json').read_text())
    target = Path(tempfile.mkdtemp(prefix=f'vep-stage4-6-{mode}-', dir=ROOT.parent))
    raw = subprocess.check_output(['git', 'archive', baseline['commit']], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        tar.extractall(target)
    actions = []
    if mode != 'baseline':
        p = subprocess.run(['git', 'apply', str(AUDIT / 'DIFF_FILE.patch')], cwd=target,
                           capture_output=True, text=True)
        actions.append({'command':p.args,'stdout':p.stdout,'stderr':p.stderr,'exit_status':p.returncode})
        if p.returncode: raise RuntimeError(p.stderr)
    if mode == 'rollback':
        p = subprocess.run([str(AUDIT / 'ROLLBACK.sh'), str(target)], capture_output=True, text=True,
                           env=dict(__import__('os').environ, PYTHON=sys.executable))
        actions.append({'command':p.args,'stdout':p.stdout,'stderr':p.stderr,'exit_status':p.returncode})
        if p.returncode: raise RuntimeError(p.stderr)
    # Exactly the same frozen regression input, even after rollback removes new tests.
    shutil.copy2(AUDIT / 'metric_contract_regressions.py', target / 'tests/python/test_metric_contract.py')
    command = [sys.executable, '-m', 'pytest', 'tests/python/test_metric_contract.py']
    result = subprocess.run(command, cwd=target, capture_output=True, text=True)
    summary = result.stdout.strip().splitlines()[-1]
    concise = re.sub(r' in [0-9.]+s$', '', summary)
    literal = f'{mode.upper()}: {concise}; pytest exit={result.returncode}'
    record = {'command':[sys.executable,str(Path(__file__).resolve()),'--mode',mode],
              'input':'same 25 frozen metric contract regressions + committed mini fixtures',
              'inner_command':command, 'cwd':str(target),'stdout':result.stdout,'stderr':result.stderr,
              'literal_output':literal,'exit_status':result.returncode,'actions':actions}
    if mode == 'rollback':
        (target / 'tests/python/test_metric_contract.py').unlink()
        full = subprocess.run([sys.executable,'-m','pytest'],cwd=target,capture_output=True,text=True)
        record['restored_suite']={'command':full.args,'stdout':full.stdout,'stderr':full.stderr,'exit_status':full.returncode}
        record['restored_status']='PASS' if full.returncode==0 else 'FAIL'
        literal += f'; restored={record["restored_status"]}'
        record['literal_output']=literal
    (AUDIT / f'{mode.upper()}_verified.json').write_text(json.dumps(record,indent=2)+'\n')
    print(literal)
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
