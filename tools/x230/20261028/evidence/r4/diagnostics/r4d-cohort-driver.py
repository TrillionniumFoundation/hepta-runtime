#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path

ROOT = Path('/home/qian/hepta-runtime-optimization-20261028')
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

diagnostic = ROOT / 'diagnostic-r4d-release'
report_path = diagnostic / 'report.json'
report = json.loads(report_path.read_bytes())
assert report['built'] is True and report['qualified'] is False and not report.get('error')
assert report['source'] == str(ROOT / 'source-r4d')
assert report['source_built'] == report['source_after']
assert report['harness_before'] == report['harness_after']
assert [row['name'] for row in report['stages']] == ['format', 'fmt-check', 'release']
assert all(row['returncode'] == 0 and row['original_child_reaped'] and not row['timed_out'] for row in report['stages'])
binary = diagnostic / 'hepta-runtime'
source_map = diagnostic / 'source-map.json'
assert report['binary']['path'] == str(binary)
assert sha(binary) == report['binary']['sha256']
assert sha(source_map) == report['source_map_sha256']
assert json.loads(source_map.read_bytes()) == report['source_built']
runner = ROOT / 'source-r4d/tools/x230/20261028/run_registry_cohort_abba.py'
assert sha(runner) == '637f5ef973ff58c3dbad62ef14a3fce27d75337e090811992e38b5b57d489cea'
command = ['/usr/bin/python3', '-B', '-u', str(runner),
    '--baseline', str(ROOT / 'qualification-r3/hepta-runtime'),
    '--baseline-sha256', '5e670e58d1c8067df594fcc256a2b88bd52cb60a443cadb36e2a7dc0f49effa7',
    '--baseline-source', str(ROOT / 'source-r3'),
    '--baseline-source-manifest', str(ROOT / 'qualification-r3/source-map.json'),
    '--baseline-source-manifest-sha256', '68d411fd95d517801cb189ff641065fe4540fcf6c95e59cdf7af2bc74ca33e65',
    '--candidate', str(binary), '--candidate-sha256', report['binary']['sha256'],
    '--candidate-source', str(ROOT / 'source-r4d'),
    '--candidate-source-manifest', str(source_map),
    '--candidate-source-manifest-sha256', report['source_map_sha256'],
    '--recovery-report', '/home/qian/hepta-runtime-optimization-20261023/a62-native-cf8e1d8fae61ab15e23c011c-six-running/report.json',
    '--recovery-report-sha256', '7b583ee5f48eb30616e420a4471c1c69247efd48a01d117bed26a5334b106c99',
    '--out', str(ROOT / 'cohort-r4d-abba-r01')]
provenance = {'schema': 'hepta-r4d-release-cohort-provenance/v1',
    'qualification_claim': False, 'scope': 'Early performance diagnosis before full R4d qualification.',
    'diagnostic_report': {'path': str(report_path), 'sha256': sha(report_path)},
    'diagnostic_runtime': report['binary'],
    'source_map': {'path': str(source_map), 'sha256': sha(source_map)},
    'baseline_qualification_report': {'path': str(ROOT / 'qualification-r3/report.json'),
        'sha256': sha(ROOT / 'qualification-r3/report.json')},
    'runner_sha256': sha(runner), 'command': command, 'automatic_retries': 0}
assert provenance['baseline_qualification_report']['sha256'] == '736ce6511462f0bef63ed8e2d0741dd74e9a740f5bf95974d52da0cefdd481c5'
assert not (ROOT / 'cohort-r4d-abba-r01').exists()
with (ROOT / 'cohort-r4d-provenance.json').open('x') as stream:
    json.dump(provenance, stream, indent=2)
    stream.write('\n')
print(json.dumps(provenance), flush=True)
os.execv('/usr/bin/python3', command)
