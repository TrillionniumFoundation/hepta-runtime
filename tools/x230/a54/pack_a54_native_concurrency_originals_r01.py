#!/usr/bin/env python3
"""Capture six fixed, completed A54 evidence files; never start or signal work."""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
ROOT = BASE / 'a54-native-concurrency-r01'
OUTPUT = BASE / 'a54-native-concurrency-r01-detail-evidence.json.gz'
REPORT_SHA = '8ef92163507cb553704262a46afd6d5d3b4bb568234442bed4a7b07759c83ebb'
REPORT_BYTES = 340637
NAMES = (
    'report.json',
    'helper-bindings.stdout.original',
    'helper-snapshot.stdout.original',
    'business-requests.original.json',
    'rpc-mixed-status-and-read.json',
    'rpc-terminal-same-keys.json',
)
LIMIT = 2 * 1024 * 1024


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(st):
    # Reading may update atime; atime is intentionally absent from this fence.
    return [st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def report_identity(receipt):
    value = receipt['stat9']
    return value[:3] + value[4:]


def read_fixed(root_fd, name):
    need(name in NAMES, 'unplanned evidence file')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                 dir_fd=root_fd)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.getuid() and not before.st_mode & 0o077
             and 0 <= before.st_size <= LIMIT, 'unsafe or oversized evidence: ' + name)
        raw = bytearray()
        while True:
            part = os.read(fd, min(65536, LIMIT + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            need(len(raw) <= LIMIT, 'evidence grew beyond bound: ' + name)
        need(len(raw) == before.st_size
             and stamp(before) == stamp(os.fstat(fd))
             == stamp(os.stat(name, dir_fd=root_fd, follow_symlinks=False)),
             'evidence changed during read: ' + name)
        raw = bytes(raw)
        return raw, {'path': str(ROOT / name), 'bytes': len(raw),
                     'sha256': sha(raw), 'stat9': stamp(before)}
    finally:
        os.close(fd)


def match_report_receipt(actual, expected):
    need(actual['path'] == expected['path'] and actual['bytes'] == expected['bytes']
         and actual['sha256'] == expected['sha256']
         and report_identity(actual) == expected['identity'],
         'evidence no longer matches the completed report: ' + actual['path'])


def tool(reply):
    need('error' not in reply and isinstance(reply.get('result'), dict)
         and not reply['result'].get('isError'), 'RPC response contains an error')
    blocks = [part['text'] for part in reply['result'].get('content', [])
              if part.get('type') == 'text']
    need(len(blocks) == 1, 'RPC result text count differs')
    value = json.loads(blocks[0])
    need(value.get('audit_recorded') is True and 'audit_warning' not in value,
         'RPC audit acknowledgement absent')
    return value


def create(base_fd, raw):
    fd = os.open(OUTPUT.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=base_fd)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            need(count > 0, 'zero-length evidence output write')
            at += count
        os.fsync(fd)
        receipt = {'path': str(OUTPUT), 'bytes': len(raw), 'sha256': sha(raw),
                   'stat9': stamp(os.fstat(fd))}
    finally:
        os.close(fd)
    os.fsync(base_fd)
    return receipt


def main():
    need(isinstance(REPORT_SHA, str) and len(REPORT_SHA) == 64
         and all(c in "0123456789abcdef" for c in REPORT_SHA)
         and type(REPORT_BYTES) is int and 0 < REPORT_BYTES <= LIMIT,
         "actual completed report identity required before reading or writing")
    os.umask(0o077)
    need(BASE.resolve(strict=True) == BASE and ROOT.resolve(strict=True) == ROOT,
         'evidence path contains a symlink')
    base_fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root_stat = os.fstat(root_fd)
        need(root_stat.st_uid == os.getuid() and not root_stat.st_mode & 0o077,
             'evidence directory is not private and owned')
        need(os.fstat(base_fd).st_uid == os.getuid(), 'output parent owner differs')
        captured = {name: read_fixed(root_fd, name) for name in NAMES}
        need(sum(len(raw) for raw, _ in captured.values()) <= 8 * 1024 * 1024,
             'total evidence exceeds bound')
        raw_report, _ = captured['report.json']
        need(len(raw_report) == REPORT_BYTES and sha(raw_report) == REPORT_SHA,
             'original report identity differs')
        report = json.loads(raw_report)
        need(report['passed'] is True and report['errors'] == []
             and report['native_phase_complete'] is True
             and report['frozen_inputs_unchanged'] is True
             and report['automatic_retries'] == 0
             and report['planned_jobs'] == 8, 'completed attempt is not successful')
        for name in ('helper-bindings.stdout.original', 'helper-snapshot.stdout.original'):
            expected = [row['stdout_receipt'] for row in report['ssh_helpers']
                        if row['stdout_receipt']['path'] == str(ROOT / name)]
            need(len(expected) == 1, 'helper original receipt absent or duplicated')
            match_report_receipt(captured[name][1], expected[0])
        expected = [row for row in report['inputs']
                    if row['path'] == str(ROOT / 'business-requests.original.json')]
        need(len(expected) == 1, 'business request receipt absent or duplicated')
        match_report_receipt(captured['business-requests.original.json'][1], expected[0])
        mixed = json.loads(captured['rpc-mixed-status-and-read.json'][0])
        same = json.loads(captured['rpc-terminal-same-keys.json'][0])
        batches = {row['label']: row for row in report['rpc_batches']}
        need(len(mixed) == 16 and [row['id'] for row in mixed]
             == batches['mixed-status-and-read']['ids'], 'mixed raw RPC identities differ')
        need(len(same) == 8 and [row['id'] for row in same]
             == batches['terminal-same-keys']['ids'], 'final same-key raw RPC identities differ')
        for slot in range(8):
            need(tool(mixed[2 * slot]) == report['outputs'][7 - slot]
                 and tool(mixed[2 * slot + 1]) == report['terminal_statuses'][slot],
                 'mixed raw reply differs from report')
            need(tool(same[slot]) == report['terminal_same_keys'][slot],
                 'final same-key raw reply differs from report')
        for name, (raw, receipt) in captured.items():
            again, after = read_fixed(root_fd, name)
            need(again == raw and after == receipt, 'final source fence changed: ' + name)
        need(stamp(root_stat) == stamp(os.fstat(root_fd)) == stamp(ROOT.lstat()),
             'evidence directory changed during capture')
        bundle = {
            'schema': 'hepta-a54-native-concurrency-r01-evidence/v1',
            'root': str(ROOT),
            'report_sha256': REPORT_SHA,
            'automatic_retry': False,
            'capture_scope': 'six fixed completed files; no process or remote operation',
            'files': {name: {**receipt, 'base64': base64.b64encode(raw).decode('ascii')}
                      for name, (raw, receipt) in captured.items()},
        }
        expanded = (json.dumps(bundle, sort_keys=True, separators=(',', ':')) + '\n').encode()
        packed = gzip.compress(expanded, mtime=0)
        output_receipt = create(base_fd, packed)
        print(json.dumps({'captured': True, 'files': len(captured), 'evidence': output_receipt,
                          'source_bytes': sum(len(raw) for raw, _ in captured.values()),
                          'expanded_bytes': len(expanded), 'expanded_sha256': sha(expanded),
                          'business_launches': 0, 'signals': 0,
                          'independent_raw_reconciliation': 'performed after download'},
                         sort_keys=True), flush=True)
    finally:
        os.close(root_fd)
        os.close(base_fd)


if __name__ == '__main__':
    main()
