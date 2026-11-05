#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Record real native terminal receipts; never executes or repeats a workload."""
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r23/remaining-frontier')
ATTEMPT = ROOT / 'attempt-02'
value = json.load(sys.stdin)
phase = value['phase']
assert phase in ('compile', 'run')
status = json.loads(value['native_status_json'])
start = json.loads(value['native_start_json'])
info = json.loads(value['binary_info_json'])
assert status['state'] == 'succeeded' and status['exit_code'] == 0
assert status['automatic_retry'] is False and status['cancelled'] is False and status['timed_out'] is False
assert status['output_complete'] is True and status['output_durable'] is True
assert status['terminal_publication_confirmed'] is True
job = start['job']
assert start['reused'] is False and status['job_id'] == job['id'] and job['host'] == 'x230'
assert job['executable'] == '/usr/bin/python3'
assert job['args'] == ['-B', str(ROOT / 'tooling-fix-02/exec_screen_stage.py'), phase]
p = ATTEMPT / 'component'
assert p.is_file() and not p.is_symlink()
with p.open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
assert info['path'] == str(p) and info['size'] == p.stat().st_size and info['sha256'] == digest
receipt = {'native_status': status, 'native_start': start,
           'binary': {'path': str(p), 'bytes': info['size'], 'sha256': digest},
           'observed_terminal_unix_seconds': time.time(),
           'scope': 'Actual native receipts and current compiled binary identity; no workload executed.'}
path = ATTEMPT / (phase + '-receipt.json')
with path.open('x') as stream:
    json.dump(receipt, stream, sort_keys=True, indent=2)
    stream.write('\n')
raw = path.read_bytes()
print(json.dumps({'receipt': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                  'job_id': job['id'], 'recorded_terminal_unix_seconds': receipt['observed_terminal_unix_seconds']}))
