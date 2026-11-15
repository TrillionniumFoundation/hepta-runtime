#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Verify already completed native screen receipts and summarize existing samples."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r23')
FRONTIER = ROOT / 'remaining-frontier'
ATTEMPT = FRONTIER / 'attempt-01'

def identity(path):
    path = Path(path)
    assert path.is_absolute() and path.is_file() and not path.is_symlink()
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest}

def create(name, value):
    with (ATTEMPT / name).open('x') as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + '\n')

assert identity(FRONTIER / 'exec_screen_stage.py')['sha256'] == 'fe38b0ae912ab780bcd7f739dd75b8e13e3dee9efea60cf06635b311d840bbf2'
rows = {}
for phase in ('compile', 'run'):
    receipt = json.loads((ATTEMPT / (phase + '-receipt.json')).read_text())
    status, start = receipt['native_status'], receipt['native_start']
    assert status['state'] == 'succeeded' and status['exit_code'] == 0
    assert status['cancelled'] is False and status['timed_out'] is False and status['automatic_retry'] is False
    assert status['output_complete'] is True and status['output_durable'] is True
    job = start['job']
    assert status['job_id'] == job['id'] and job['host'] == 'x230'
    assert job['executable'] == '/usr/bin/python3'
    assert job['args'] == ['-B', str(FRONTIER / 'exec_screen_stage.py'), phase]
    driver = json.loads((ATTEMPT / (phase + '-driver.json')).read_text())
    assert driver['stage'] == phase and driver['automatic_retries'] == 0
    for expected in driver['inputs'].values():
        assert identity(expected['path']) == expected
    assert identity(ATTEMPT / 'component') == receipt['binary']
    rows[phase] = {'receipt': identity(ATTEMPT / (phase + '-receipt.json')),
                   'driver': identity(ATTEMPT / (phase + '-driver.json')),
                   'stdout': identity(ATTEMPT / (phase + '.stdout')),
                   'stderr': identity(ATTEMPT / (phase + '.stderr')),
                   'job_id': job['id']}
helper = ROOT / 'campaign-tools/r23_campaign.py'
assert identity(helper)['sha256'] == '1c5b978752ff96034337ff80b8fd1906d55ccbfa355e379746b4d115d39d0f71'
spec = importlib.util.spec_from_file_location('_screen_postflight_snapshot', helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
machine = module.machine_snapshot()
create('machine-after.json', machine)
summary = subprocess.run(['/usr/bin/python3', '-B', str(FRONTIER / 'buffer_screen.py'),
                          'summarize', '--stdout', str(ATTEMPT / 'run.stdout'),
                          '--output', str(ATTEMPT / 'summary.json')],
                         capture_output=True, timeout=20)
(ATTEMPT / 'summary.stdout').write_bytes(summary.stdout)
(ATTEMPT / 'summary.stderr').write_bytes(summary.stderr)
assert summary.returncode == 0
value = json.loads((ATTEMPT / 'summary.json').read_text())
assert value['component_records_valid'] is True and value['candidate_adopted'] is False
result = {'schema': 'hepta-public-reference-buffer-screen-postflight/v1',
          'passed': True, 'finished_unix': time.time(), 'native_stages': rows,
          'all_recorded_source_dependency_and_binary_identities_unchanged': True,
          'summary': identity(ATTEMPT / 'summary.json'),
          'mechanism_gate_passed': value['mechanism_gate_passed'],
          'candidate_adopted': False, 'new_workload_executed': False,
          'scope': 'Completed native job receipts and component sample arithmetic; no RPC or lifecycle acceptance.'}
create('postflight.json', result)
print(json.dumps(result))
