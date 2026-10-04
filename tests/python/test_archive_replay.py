"""Archive replay acceptance and failure paths (no analyzer subprocesses)."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/evaluation/reproduce_archived_results.py'
ARCHIVE = ROOT / 'repro/archive-v3.0.1'


def run(archive, out):
    return subprocess.run([sys.executable, str(SCRIPT), '--archive', str(archive),
                           '--out-dir', str(out)], capture_output=True, text=True)


def test_real_dual_tool_replay(tmp_path):
    result = run(ARCHIVE, tmp_path / 'out')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'REPLAY PASS: 2 tools x 11 CWEs x 2 FP modes; historical counts unchanged'
    for tool, fp_all, fp_scope, tn in [('codefuse', 552, 552, 773), ('codeql', 2236, 531, 794)]:
        for mode, fp in [('all_non_gt', fp_all), ('in_scope', fp_scope)]:
            data = json.loads((tmp_path / 'out' / mode / f'{tool}.json').read_text())
            assert data['overall']['tp'] == 1415
            assert data['overall']['fp'] == fp
            assert data['overall']['tn'] == tn
            assert data['overall']['fn'] == 0
            assert data['overall']['outside_scope_findings'] == fp_all - fp_scope
            assert data['sample_scope']['verified']
            assert len(data['cwes']) == 11
            for cwe, m in data['cwes'].items():
                folder = tmp_path / 'out' / mode / tool / cwe
                assert all((folder / f'{f}.csv').exists() for f in ['tp', 'fp', 'fn', 'outside_scope'])
        assert data['overall']['fpr_in_scope'] == round(fp_scope / (fp_scope + tn), 4)
    for mode in ['all_non_gt', 'in_scope']:
        report = json.loads((tmp_path / 'out' / mode / 'report_data.json').read_text())
        assert report['fp_mode'] == mode
        assert set(report['tools']) == {'codefuse', 'codeql'}
        for name in ['report.md', 'report_zh.md']:
            text = (tmp_path / 'out' / mode / name).read_text()
            assert mode in text and '94d19209baf53a' in text
            assert '](figs/' not in text


@pytest.mark.parametrize('mutation', ['tamper_findings', 'missing_findings', 'tamper_gt',
    'duplicate_input', 'missing_input', 'unknown_tool', 'wrong_cwe', 'unknown_version',
    'escape_path', 'absolute_path', 'bad_schema', 'wrong_expected', 'tamper_expected', 'missing_lock_checksum'])
def test_replay_rejects_incomplete_or_corrupt_archive(tmp_path, mutation):
    archive = tmp_path / 'archive'
    shutil.copytree(ARCHIVE, archive)
    manifest_path = archive / 'manifest.json'
    m = json.loads(manifest_path.read_text())
    entry = m['inputs'][0]
    p = archive / entry['path']
    if mutation == 'tamper_findings': p.write_text(p.read_text() + '\nchanged\n')
    elif mutation == 'missing_findings': p.unlink()
    elif mutation == 'tamper_gt': (archive / m['ground_truth']).write_text('broken')
    elif mutation == 'duplicate_input': m['inputs'].append(entry)
    elif mutation == 'missing_input': m['inputs'].pop()
    elif mutation == 'unknown_tool': entry['tool'] = 'other'
    elif mutation == 'wrong_cwe': entry['cwe'] = 'CWE-999'
    elif mutation == 'unknown_version': m['tools']['codeql'].pop('version')
    elif mutation == 'escape_path': entry['path'] = '../outside.csv'
    elif mutation == 'absolute_path': entry['path'] = '/etc/passwd'
    elif mutation == 'bad_schema': m['schema_version'] = 'unsupported'
    elif mutation == 'missing_lock_checksum': m['files'].pop('requirements.lock')
    elif mutation in ['wrong_expected', 'tamper_expected']:
        e = archive / m['expected']
        d = json.loads(e.read_text()); d['codeql']['all_non_gt']['overall']['tp'] += 1
        e.write_text(json.dumps(d))
        if mutation == 'wrong_expected':
            import hashlib
            m['files'][m['expected']] = hashlib.sha256(e.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(m))
    result = run(archive, tmp_path / 'out')
    assert result.returncode != 0
    assert 'REPLAY ERROR:' in result.stderr
    assert not (tmp_path / 'out').exists()


def test_replay_rejects_output_in_archive(tmp_path):
    archive = tmp_path / 'archive'
    shutil.copytree(ARCHIVE, archive)
    result = run(archive, archive / 'output')
    assert result.returncode != 0
    assert not (archive / 'output').exists()


def test_replay_is_semantically_repeatable(tmp_path):
    for name in ['a', 'b']:
        result = run(ARCHIVE, tmp_path / name)
        assert result.returncode == 0, result.stderr
    a = tmp_path / 'a'
    for p in a.rglob('*'):
        if p.is_file():
            assert p.read_bytes() == (tmp_path / 'b' / p.relative_to(a)).read_bytes()
