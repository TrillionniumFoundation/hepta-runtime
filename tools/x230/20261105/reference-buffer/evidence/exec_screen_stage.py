#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind and exec one screen stage inside the existing native job supervisor."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r23')
FRONTIER = ROOT / 'remaining-frontier'
ATTEMPT = FRONTIER / 'attempt-01'

def identity(path):
    path = Path(path)
    assert path.is_absolute() and path.is_file() and not path.is_symlink()
    with path.open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha}

def write(name, value):
    with (ATTEMPT / name).open('x') as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + '\n')

assert len(sys.argv) == 2 and sys.argv[1] in ('compile', 'run')
stage = sys.argv[1]
plan = json.loads((ATTEMPT / 'build-plan.json').read_text())
qualification = json.loads((ROOT / 'qualification-01/report.json').read_text())
accepted_root = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
campaign = json.loads((accepted_root / 'campaign-01/report.json').read_text())
assert identity(accepted_root / 'source/src/mcp/runtime/ssh_observation_profile.rs')['sha256'] == 'a62169343c2a08c38d69925f33fdc7551cf4be7b4b7f50cf89683f652a8f853a'
assert qualification['qualified'] is True and qualification.get('finished_utc')
assert campaign['passed'] is True and campaign['adoption_passed'] is True and campaign.get('finished_utc')
assert campaign['source_inputs_unchanged'] is True and campaign['inputs_unchanged'] is True
assert identity(plan['qualification_report']['path'])['sha256'] == plan['qualification_report']['sha256']
inputs = {}
for name, expected in plan['dependencies'].items():
    actual = identity(expected['path'])
    assert all(actual[key] == expected[key] for key in ('path', 'bytes', 'sha256'))
    inputs[name] = actual
actual = identity(plan['component']['path'])
assert actual['sha256'] == plan['component']['sha256']
inputs['component_source'] = actual
helper = ROOT / 'campaign-tools/r23_campaign.py'
assert identity(helper)['sha256'] == '1c5b978752ff96034337ff80b8fd1906d55ccbfa355e379746b4d115d39d0f71'
spec = importlib.util.spec_from_file_location('_screen_machine_snapshot', helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
environment = os.environ.copy()
environment.update(plan['environment'])
assert plan['environment'] == {'RUSTUP_AUTO_INSTALL': '0', 'MALLOC_ARENA_MAX': '1'}
if stage == 'compile':
    version = subprocess.run([plan['rustc_argv'][0], '+1.95.0', '-vV'],
                             capture_output=True, timeout=10, env=environment)
    (ATTEMPT / 'rustc-vV.stdout').write_bytes(version.stdout)
    (ATTEMPT / 'rustc-vV.stderr').write_bytes(version.stderr)
    assert version.returncode == 0 and b'release: 1.95.0\n' in version.stdout
    argv = plan['rustc_argv']
else:
    receipt = json.loads((ATTEMPT / 'compile-receipt.json').read_text())
    assert receipt['native_status']['state'] == 'succeeded' and receipt['native_status']['exit_code'] == 0
    assert time.time() - receipt['observed_terminal_unix_seconds'] >= 30
    actual = identity(ATTEMPT / 'component')
    assert actual == receipt['binary']
    inputs['component_binary'] = actual
    argv = plan['run_argv']
write(stage + '-driver.json', {'schema': 'hepta-r23-buffer-screen-exec-driver/v1',
      'stage': stage, 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'start_monotonic_ns': time.monotonic_ns(), 'argv': argv, 'inputs': inputs,
      'environment_overrides': plan['environment'], 'machine_before': module.machine_snapshot(),
      'supervisor': 'existing native process_start process-group supervisor; no new runner',
      'automatic_retries': 0})
with (ATTEMPT / (stage + '.stdout')).open('xb') as stdout, (ATTEMPT / (stage + '.stderr')).open('xb') as stderr:
    os.dup2(stdout.fileno(), 1)
    os.dup2(stderr.fileno(), 2)
    os.execve(argv[0], argv, environment)
