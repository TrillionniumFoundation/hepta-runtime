#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind the real completed R25 qualification and the already published R24."""
import hashlib
import importlib.util
import json
from pathlib import Path
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r25')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')


def identity(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest}


def main():
    path = ROOT / 'qualification-02/report.json'
    deadline = time.monotonic() + 5400
    while True:
        report = json.loads(path.read_text())
        if report.get('finished_utc'):
            break
        if time.monotonic() >= deadline:
            raise TimeoutError('qualification did not finish; campaign receipt not created')
        time.sleep(3)
    assert report['qualified'] is True, report.get('error')
    assert report['source_tested'] == report['source_after']
    assert all(type(s['returncode']) is int and s['returncode'] == 0 for s in report['stages'])
    for relative, expected in report['source_after'].items():
        assert identity(ROOT / 'source-02' / relative)['sha256'] == expected, relative
    inputs = json.loads((ROOT / 'campaign-inputs-02.example.json').read_text())
    publication_path = BASE / 'final-publication-readback.json'
    publication = json.loads(publication_path.read_text())
    inputs['baseline']['publication_readback'] = dict(identity(publication_path), commit=publication['commit'])
    assert publication['commit'] == 'baab4def80be7af015b2e7a594cb302f66c4130e'
    assert identity(publication_path)['sha256'] == '38866c01fac54133c8a88e25bee90ea4a551e7273614f493bf44522a8273d3ca'
    spec = importlib.util.spec_from_file_location('r25_campaign', ROOT / 'campaign-tools-02/r25_campaign.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    campaign = json.loads((BASE / 'campaign-01/report.json').read_text())
    for value in inputs['baseline']['binaries'].values():
        assert identity(Path(value['path'])) == value
    module.verify_baseline_enablement(campaign, publication, inputs['baseline']['binaries'],
                                     publication['commit'], identity(BASE / 'campaign-01/report.json')['sha256'])
    for name, value in report['binaries'].items():
        actual = identity(Path(value['path']))
        assert actual['sha256'] == value['sha256'] and Path(value['path']).parent == ROOT / 'qualification-02'
        inputs['candidate_binaries'][name] = {k: actual[k] for k in ('bytes', 'sha256')}
    inputs['qualification_reports'] = [dict(identity(path), success_field='qualified')]
    assert inputs['launcher_sha256'] == identity(ROOT / 'campaign-tools-02/r25_campaign.py')['sha256']
    assert inputs['summary_sha256'] == identity(ROOT / 'campaign-tools-02/summarize_r25_campaign.py')['sha256']
    with (ROOT / 'campaign-inputs-02.json').open('x') as stream:
        stream.write(json.dumps(inputs, indent=2) + '\n')
    tests = json.loads((ROOT / 'qualification-02/isolated-tests/summary.json').read_text())
    audit = json.loads((ROOT / 'qualification-02/isolated-tests.audit.json').read_text())
    compact = {'schema': 'hepta-r25-qualification-compact/v1', 'qualified': report['qualified'],
               'qualification_report': identity(path), 'source_files': len(report['source_after']),
               'source_unchanged': report['source_after'] == report['source_tested'],
               'source_map': identity(ROOT / 'qualification-02/source-map.json'),
               'stages': [{k: s[k] for k in ('name', 'returncode', 'seconds')} for s in report['stages']],
               'tests': {k: tests.get(k) for k in ('passed', 'failed', 'ignored', 'selected', 'retries', 'success', 'elapsed_seconds')},
               'audit_errors': audit.get('errors'), 'binaries': inputs['candidate_binaries'],
               'baseline_commit': publication['commit'], 'campaign_inputs': identity(ROOT / 'campaign-inputs-02.json')}
    (ROOT / 'qualification-compact-02.json').write_text(json.dumps(compact, indent=2) + '\n')
    print(json.dumps(compact), flush=True)


if __name__ == '__main__':
    main()
