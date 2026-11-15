#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Package existing x230 pidfd component receipts, without running any fixture."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

ROOT = Path('/home/qian/hepta-runtime-pidfd-component-20261105-01')
MAX_TOTAL = 16 * 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_FILES = 2048

def digest(data):
    return hashlib.sha256(data).hexdigest()

def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()

def stamp(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def main():
    assert ROOT.resolve() == ROOT
    outputs = [ROOT / ('component-evidence-01' + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    assert not any(os.path.lexists(p) for p in outputs)
    paths = [ROOT / name for name in ('benchmark_cancel_wait.py', 'candidate-jobs.rs', 'component-input-freeze.json', 'component-native-terminal-01.json')]
    for p in sorted((ROOT / 'run-01').rglob('*')):
        assert not p.is_symlink()
        if p.is_file(): paths.append(p)
        else: assert p.is_dir()
    assert len(paths) <= MAX_FILES
    data, identities = {}, {}
    for path in paths:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_FILE
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as f:
            assert stamp(info) == stamp(os.fstat(f.fileno()))
            raw = f.read(MAX_FILE + 1)
            assert len(raw) == info.st_size and stamp(info) == stamp(os.fstat(f.fileno())) == stamp(path.lstat())
        assert not raw.startswith(b'\x7fELF') and b'PRIVATE KEY-----' not in raw and b'openssh-key-v1\x00' not in raw
        relative = path.relative_to(ROOT).as_posix()
        data[relative], identities[path] = raw, stamp(info)
    assert sum(map(len, data.values())) <= MAX_TOTAL
    assert all(stamp(p.lstat()) == expected for p, expected in identities.items())
    assert digest(data['benchmark_cancel_wait.py']) == '77ab26a406490f05c036ba31d02c7cf5d72a02032916acabb8262addd18f4fe4'
    assert digest(data['candidate-jobs.rs']) == 'd92b1dba53b2495a0146f242ad6455d6f2d87def19f01c1d831d2488a28eedaa'
    assert digest(data['component-input-freeze.json']) == '9121b8fab4ded1a40923de0a7787fc295c764846ffb4f8eeb564b54c03617886'
    native = json.loads(data['component-native-terminal-01.json'])
    assert native['job_id'] == '1a1adfb2959-fc05-5c58' and native['state'] == 'succeeded' and native['exit_code'] == 0
    assert native['output_complete'] and native['output_durable'] and not native['automatic_retry']
    summary = json.loads(data['run-01/summary.json'])
    rows = [json.loads(line) for line in data['run-01/raw-samples.jsonl'].splitlines()]
    assert summary['passed'] and summary['samples_completed'] == summary['samples_planned'] == len(rows) == 62
    assert all(row['passed'] for row in rows) and sum(row['phase'] == 'measured' for row in rows) == summary['measured_samples'] == 48
    assert summary['all_owned_children_reaped'] and summary['cleanup_kills'] == 0
    assert summary['lost_ack_controls'] == [True, True] and len(summary['already_exited_controls']) == 2
    assert all(row['passed'] and row['cancel_receipt_unchanged'] for row in summary['already_exited_controls'])
    compact = {'schema': 'hepta-r31-pidfd-component-archive-summary/v1', 'execution_host': 'x230',
        'original_job_id': native['job_id'], 'source_root': str(ROOT), 'summary': summary,
        'original_scope_text_preserved': True,
        'scope_clarification': 'Executed on x230, but only the Python helper and owned synthetic supervisor fixtures were measured; no whole-runtime, SSH, six-host, or saturated-cancellation performance acceptance is implied.',
        'tests_or_benchmarks_reexecuted': False}
    manifest = {'schema': 'hepta-r31-pidfd-component-archive/v1', 'selected_bytes': sum(map(len, data.values())),
        'tool_sha256': digest(Path(__file__).read_bytes()), 'summary': compact,
        'files': {n: {'bytes': len(b), 'sha256': digest(b)} for n,b in sorted(data.items())}}
    manifest_raw = encode(manifest)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in [('manifest.json', manifest_raw), *sorted(data.items())]:
                entry = tarfile.TarInfo(name); entry.size = len(raw); entry.mode = 0o600; entry.mtime = 0
                archive.addfile(entry, io.BytesIO(raw))
    archive_raw = buffer.getvalue()
    for path, raw in zip(outputs, (archive_raw, manifest_raw, encode(compact))):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
    print(json.dumps({'archive': str(outputs[0]), 'bytes': len(archive_raw), 'sha256': digest(archive_raw),
        'manifest_sha256': digest(manifest_raw), 'selected_files': len(data), 'selected_bytes': manifest['selected_bytes'],
        'passed': summary['passed'], 'samples': len(rows), 'measured_samples': summary['measured_samples'], 'no_benchmark_rerun': True}))

if __name__ == '__main__':
    main()
