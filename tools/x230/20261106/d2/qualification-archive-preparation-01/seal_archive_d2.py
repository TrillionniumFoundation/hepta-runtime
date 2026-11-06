#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bind the completed first D2 qualification without running archived programs."""
import hashlib
import json
import os
from pathlib import Path
import tarfile

HERE = Path(__file__).resolve().parent
ACTUAL_ROOT = HERE.parent / 'd2-qualification-actual-originals-01'
OUT = HERE / 'sealed-01'
names = ['preparation.json', 'qualification-terminal-status-01.json',
         'qualification-native-read-01.json', 'qualification-01/report.json',
         'qualification-01/source-map.json', 'qualification-01/isolated-tests/summary.json',
         'qualification-01/isolated-tests.audit.json']
raw = {name: (ACTUAL_ROOT / name).read_bytes() for name in names}
parsed = {name: json.loads(value) for name, value in raw.items()}
terminal = parsed['qualification-terminal-status-01.json']
report = parsed['qualification-01/report.json']
tests = parsed['qualification-01/isolated-tests/summary.json']
audit = parsed['qualification-01/isolated-tests.audit.json']
prep = parsed['preparation.json']
assert terminal['job_id'] == '1a1b0cc0f51-fc05-7301'
assert terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
assert report['qualified'] is True and prep['passed'] is True
assert tests['success'] is True and audit['success'] is True
counts = {name: tests[name] for name in ['passed', 'failed', 'ignored', 'selected', 'retries']}
assert counts['failed'] == counts['retries'] == 0
assert all(audit[name] == counts[name] for name in ['passed', 'failed', 'ignored', 'selected'])
assert counts['selected'] == counts['passed'] + counts['ignored']
actual = {'schema': 'hepta-d2-qualification-archive-actual-pins/v1', 'sealed': True,
          'qualification_job_id': terminal['job_id'], 'outcome': 'passed',
          'files': {name: {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
                    for name, value in raw.items()}, 'counts': counts,
          'qualified_binary_sha256': {name: row['sha256'] for name, row in report['binaries'].items()}}
source = (HERE / 'archive_d2_qualification.py').read_text()
assert hashlib.sha256(source.encode()).hexdigest() == '3e150f1a3d9c1640a1c89932d2c9fc994e8b149113b524bbc8c86a3a52fd2ce4'
assert source.count('ACTUAL = None') == 1
sealed = source.replace('ACTUAL = None', 'ACTUAL = ' + repr(actual), 1).encode()
namespace = {'__name__': 'd2_archive_preexecution_binding', '__file__': str(OUT / 'archive_d2_qualification.py')}
exec(compile(sealed, namespace['__file__'], 'exec'), namespace)
namespace['require_sealed']()
namespace['native_terminal'](terminal, terminal['job_id'], 'succeeded', 0)
streams = namespace['original_streams'](parsed['qualification-native-read-01.json'], terminal)
assert len(streams['stdout']) == 1111 and streams['stderr'] == b''
payloads = dict(raw)
with tarfile.open(HERE / 'd2-deployment.tar.gz', 'r:gz') as archive:
    for entry in archive:
        assert entry.isfile()
        payloads[entry.name] = archive.extractfile(entry).read()
for name in ['installation-start-01.json', 'installation-native-01.json',
             'installation-read-01.json', 'qualification-start-01.json',
             'install_qualification.py', 'launch-command.json']:
    payloads['archive-inputs-01/' + name] = (HERE / 'archive-local-inputs' / name).read_bytes()
payloads['archive-inputs-01/deployment.tar.gz'] = (HERE / 'd2-deployment.tar.gz').read_bytes()
payloads['installation-01.json'] = (HERE / 'archive-local-inputs/installation-01.json').read_bytes()
for name, expected in namespace['PINNED'].items():
    value = payloads[name]
    assert expected == {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
installation = namespace['installation_summary'](payloads)
assert len(report['source_tested']) == len(report['source_input']) == 222
assert report['source_tested'] == report['source_after'] == prep['source_after_qualification'] == parsed['qualification-01/source-map.json']
assert report['source_input'] == prep['source_before_qualification']
assert len(report['harness_after']) == 19 and report['harness_after'] == report['harness_before']
assert [row['name'] for row in report['stages']] == namespace['STAGES']
assert all(row['returncode'] == 0 for row in report['stages'])
OUT.mkdir(mode=0o700)


def save(name, data):
    fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


save('archive_d2_qualification.py', sealed)
save('actual-original-pins.json', (json.dumps(actual, indent=2, sort_keys=True) + '\n').encode())
binding = {'schema': 'hepta-d2-qualification-archive-local-binding/v1',
           'source_bytes': len(sealed), 'source_sha256': hashlib.sha256(sealed).hexdigest(),
           'sealed_from_original_job': terminal['job_id'], 'actual_counts': counts,
           'original_installation_checked': installation,
           'frozen_static_pins_checked': len(namespace['PINNED']),
           'source_maps_reconciled': True, 'collector_executed': False,
           'full_case_logs_verified_here': False, 'tests_or_auditors_reexecuted': False}
save('local-binding.json', (json.dumps(binding, indent=2, sort_keys=True) + '\n').encode())
print(json.dumps(binding, sort_keys=True))
