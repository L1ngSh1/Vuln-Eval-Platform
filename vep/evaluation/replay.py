"""Replay a fixed, checksummed archive using only normalized CSVs and GT."""
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from vep.evaluation.aggregate import aggregate_metrics
from vep.evaluation.evaluator import evaluate_findings_with_details
from vep.evaluation.findings import load_findings_csv
from vep.evaluation.ground_truth import load_expected_cases
from vep.evaluation.metrics import eval_result_to_dict, write_evaluation_details

CWES = tuple('CWE-' + n for n in ('022', '078', '079', '089', '090', '327', '328', '330', '501', '614', '643'))
TOOLS = ('codefuse', 'codeql')
MODES = ('all_non_gt', 'in_scope')
COMPARABLE = ('overall', 'cwes', 'sample_scope', 'metric_modes', 'fp_mode', 'metric_contract', 'included_count')


def _path(root, relative):
    p = Path(relative)
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise ValueError(f'Invalid archive path: {relative}')
    resolved = (root / p).resolve()
    if root not in resolved.parents:
        raise ValueError(f'Archive path escapes root: {relative}')
    return resolved


def _dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def replay_archive(archive, out_dir, plots=False):
    archive, out_dir = Path(archive).resolve(), Path(out_dir).resolve()
    if out_dir == archive or archive in out_dir.parents:
        raise ValueError('Output must be separate from immutable archive inputs')
    manifest = json.loads((archive / 'manifest.json').read_text(encoding='utf-8'))
    if manifest['schema_version'] != 'vep.archive.v1':
        raise ValueError('Unsupported archive schema')
    if tuple(manifest['cwes']) != CWES or set(manifest['tools']) != set(TOOLS):
        raise ValueError('Archive must cover the fixed 11 CWEs and both tools')
    for tool in TOOLS:
        if 'version' not in manifest['tools'][tool] or not manifest['tools'][tool].get('evidence'):
            raise ValueError(f'Missing version/provenance record: {tool}')
    inputs = manifest['inputs']
    keys = [(e['tool'], e['cwe']) for e in inputs]
    required_keys = {(t, c) for t in TOOLS for c in CWES}
    if len(keys) != len(required_keys) or set(keys) != required_keys:
        raise ValueError('Duplicate, missing or unknown tool/CWE input')
    paths = [e['path'] for e in inputs]
    if len(set(paths)) != len(paths):
        raise ValueError('Duplicate input path')
    required_files = set(paths + [manifest['ground_truth'], manifest['expected']])
    required_files.update(f'historical/{t}.json' for t in TOOLS)
    required_files.update(('requirements.lock', 'codeql-pack.lock.yml', 'qlpack.yml', 'rule-inventory.json'))
    if not required_files.issubset(manifest['files']):
        raise ValueError('Incomplete input checksum inventory')
    for relative, expected_hash in manifest['files'].items():
        p = _path(archive, relative)
        if hashlib.sha256(p.read_bytes()).hexdigest() != expected_hash:
            raise ValueError(f'Checksum mismatch: {relative}')
    # Path validation applies even to a malicious replacement entry.
    for relative in required_files:
        _path(archive, relative)
    gt = _path(archive, manifest['ground_truth'])
    expected = json.loads(_path(archive, manifest['expected']).read_text(encoding='utf-8'))
    results, details = {}, {}
    for tool in TOOLS:
        historical = json.loads((archive / 'historical' / f'{tool}.json').read_text(encoding='utf-8'))
        per_mode = {mode: [] for mode in MODES}
        for cwe in CWES:
            entry = next(e for e in inputs if e['tool'] == tool and e['cwe'] == cwe)
            findings = load_findings_csv(_path(archive, entry['path']), tool, cwe)
            if len(findings) != entry['raw_findings']:
                raise ValueError(f'Raw finding count mismatch: {tool}/{cwe}')
            population = load_expected_cases(gt, cwe)
            if not population:
                raise ValueError(f'Missing GT population: {cwe}')
            for mode in MODES:
                result, detail = evaluate_findings_with_details(findings, population, tool, cwe, True, mode)
                metrics = eval_result_to_dict(result)
                if mode == 'all_non_gt':
                    for field in ('tp', 'fp', 'fn', 'tn', 'fp_in_scope', 'outside_scope_findings'):
                        if metrics[field] != historical['cwes'][cwe][field]:
                            raise ValueError(f'Historical count changed: {tool}/{cwe}/{field}')
                per_mode[mode].append(metrics)
                details[(tool, cwe, mode)] = detail
        for mode in MODES:
            agg = aggregate_metrics(per_mode[mode], tool=tool, strict=True)
            agg['generated_at'] = manifest['as_of']
            if mode == 'all_non_gt':
                for field, value in historical['overall'].items():
                    if agg['overall'].get(field) != value:
                        raise ValueError(f'Historical total changed: {tool}/{field}')
            if {k: agg[k] for k in COMPARABLE} != expected[tool][mode]:
                raise ValueError(f'Expected archive metrics mismatch: {tool}/{mode}')
            results[(tool, mode)] = agg
    # No output is created until every checksum, population and metric check passed.
    from vep.reporting.report_generator import load_metrics, merge_report_data
    from vep.reporting.text_report import write_reports
    for mode in MODES:
        folder = out_dir / mode
        metric_paths = []
        for tool in TOOLS:
            agg = results[(tool, mode)]
            target = folder / f'{tool}.json'
            _dump(target, agg)
            metric_paths.append(target)
            for cwe, metrics in agg['cwes'].items():
                detail_dir = folder / tool / cwe
                _dump(detail_dir / 'metrics.json', metrics)
                write_evaluation_details(details[(tool, cwe, mode)], detail_dir)
        report = merge_report_data([load_metrics(p) for p in metric_paths])
        _dump(folder / 'report_data.json', asdict(report))
        written = write_reports(report, folder)
        if not plots:
            # Text-only replay must not emit links to nonexistent PNGs.
            import re
            for path in written:
                text = path.read_text(encoding='utf-8')
                text = re.sub(r'!\[[^\]]*\]\(figs/[^)]+\)\n?', '', text)
                path.write_text(text, encoding='utf-8')
        if plots:
            from vep.reporting.plot_generator import generate_all_plots
            generate_all_plots(report, folder / 'figs')
    _dump(out_dir / 'replay-verification.json', {
        'status': 'PASS', 'archive_id': manifest['archive_id'],
        'manifest_sha256': hashlib.sha256((archive / 'manifest.json').read_bytes()).hexdigest(),
        'tools': list(TOOLS), 'cwes': list(CWES), 'fp_modes': list(MODES),
        'checksummed_files': len(manifest['files']), 'historical_counts_unchanged': True,
        'analyzers_executed': False,
    })
    return results
