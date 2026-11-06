#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Record the single authorized pure-local C1 archive source seal."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess

BASE = Path('/tmp/hepta-runtime-recovery-20261106')
PREP = BASE / 'd1-c1-archive-preparation-01'
ORIGINALS = BASE / 'd1-c1-actual-originals-01'
OUTPUT = BASE / 'd1-c1-archive-sealed-01'
EXECUTION = BASE / 'd1-c1-archive-seal-execution-01'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

template = (PREP / 'archive_d1_c1.py').read_bytes()
sealer = (PREP / 'seal_c1_archive.py').read_bytes()
assert sha(template) == '5018c7bc509e965fc96206f10a2e582309193d93366be079c1b9681bba6cfd98'
assert sha(sealer) == 'd0186849e1eabd7dc244fb8c0d7bffb9eb774b9844e1fe4132896481973c7d50'
assert not os.path.lexists(OUTPUT)
assert not os.path.lexists(EXECUTION)
tree = ast.parse(template)
core = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'CORE_PATHS' for t in n.targets))
pins = {}
for name in [*core, 'c1-holder-native-read-01-000.json']:
    path = ORIGINALS / name
    if not os.path.lexists(path):
        pins[name] = None
    else:
        raw = path.read_bytes()
        pins[name] = {'bytes': len(raw), 'sha256': sha(raw)}
assert pins['c1-campaign-01/summary.json'] is None
assert pins['c1-observation-01/independent-summary.json'] is None
EXECUTION.mkdir(mode=0o700)
argv = ['/usr/bin/python3', '-B', str(PREP / 'seal_c1_archive.py'),
        '--template', str(PREP / 'archive_d1_c1.py'),
        '--originals', str(ORIGINALS),
        '--holder-job-id', '1a1b0849a11-fc05-7119',
        '--output', str(OUTPUT)]
result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
create(EXECUTION / 'stdout.log', result.stdout)
create(EXECUTION / 'stderr.log', result.stderr)
receipt = {'schema': 'hepta-d1-c1-archive-local-seal-execution/v1',
    'argv': argv, 'returncode': result.returncode, 'automatic_retries': 0,
    'original_holder_job_id': '1a1b0849a11-fc05-7119',
    'template': {'bytes': len(template), 'sha256': sha(template)},
    'sealer': {'bytes': len(sealer), 'sha256': sha(sealer)},
    'local_originals': pins,
    'stdout': {'bytes': len(result.stdout), 'sha256': sha(result.stdout)},
    'stderr': {'bytes': len(result.stderr), 'sha256': sha(result.stderr)},
    'collector_executed': False, 'original_parser_or_auditor_executed': False,
    'compiler_test_runtime_or_host_executed': False, 'pure_local_source_sealer_executions': 1}
create(EXECUTION / 'receipt.json', (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode())
print(json.dumps({'returncode': result.returncode, 'stdout': receipt['stdout'], 'stderr': receipt['stderr'],
                  'output': str(OUTPUT), 'execution': str(EXECUTION)}, sort_keys=True))
if result.returncode:
    raise SystemExit(result.returncode)
