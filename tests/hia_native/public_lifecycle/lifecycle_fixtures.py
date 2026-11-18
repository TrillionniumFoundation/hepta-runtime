# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Verify, then retire completed owned fixtures without losing their captures.

Captured device/inode identities remain part of semantic reconstruction. They
describe the completed runtime, not the filesystem used to restore CI artifacts.
"""
from pathlib import Path, PurePosixPath
import json, os, stat
from lifecycle_inputs import pin
from lifecycle_success_projection import capture_tree, H, SORTED

RECEIPT = 'fixture-retirement.json'
SCHEMA = 'hepta.public-lifecycle.finite-fixture-retirement.v1'


def _read(path):
    pin(path)
    value = json.loads(Path(path).read_bytes())
    assert type(value) is dict
    return value


def _plan(folder, domain):
    final = _read(folder / 'eof-filesystem.json')
    captures = {'eof-filesystem.json': pin(folder / 'eof-filesystem.json')}
    if domain == 'preflight':
        state = {'': dict(kind='directory', **final['root_stat'])}
        for name, row in final['full'].items():
            assert name
            state[name] = dict(row)
            if row['kind'] == 'file':
                state[name]['stable'] = True
    else:
        assert domain in ('success', 'pending')
        state = final['filesystem']
    trees = {'final-state': state}
    if domain != 'preflight':
        before = _read(folder / 'fence-before.json')
        assert _read(folder / 'fence-after.json') == before
        assert set(before) <= {'fence', 'predecessor', 'other-state'}
        if domain == 'pending':
            assert set(before) == {'fence'}
        for name, rows in before.items():
            trees['final-' + name] = rows
        for name in ('fence-before.json', 'fence-after.json'):
            captures[name] = pin(folder / name)
    for name, rows in trees.items():
        assert type(rows) is dict and rows['']['kind'] == 'directory'
        for key, row in rows.items():
            path = PurePosixPath(key)
            assert not path.is_absolute() and '..' not in path.parts
            assert key == '' or path.as_posix() == key
            assert row['kind'] in ('file', 'directory', 'symlink')
            assert all(type(row[k]) is int for k in
                       ('mode', 'device', 'inode', 'uid', 'gid', 'nlink'))
            if row['kind'] == 'file':
                raw = bytes.fromhex(row['hex'])
                assert row['stable'] is True
                assert len(raw) == row['bytes'] and H(raw) == row['sha256']
    return trees, captures


def _receipt(folder, domain, process, trees, captures):
    expected_status = 'CAPTURED_NOT_QUALIFIED' if domain == 'pending' else 'PASS'
    assert process['status'] == expected_status and process['exit_code'] == 0
    if domain == 'pending':
        assert process['full_capture'] is True and process['qualification'] is False
    assert process['reaped'] is True and type(process['pid']) is int and process['pid'] > 0
    streams = {name: pin(folder / name, process[name])
               for name in ('input.bin', 'stdout.bin', 'stderr')}
    return dict(schema=SCHEMA, status='RETIRED_AFTER_VERIFICATION', domain=domain,
        verifier_source=pin(Path(__file__)), captures=captures, streams=streams,
        process=dict(pid=process['pid'], side=process['side'], exit_code=0, reaped=True),
        trees={name: dict(entries=len(rows),
            regular_files=sum(r['kind'] == 'file' for r in rows.values()),
            complete_snapshot_sha256=H(SORTED(rows))) for name, rows in trees.items()},
        source='complete actual EOF and fence observations after process reaping')


def admit(folder, domain, process, *, require_retired=False):
    """Require complete live equality, or the exact bound retirement receipt."""
    folder = Path(folder)
    trees, captures = _plan(folder, domain)
    expected = _receipt(folder, domain, process, trees, captures)
    live = {p.name for p in folder.iterdir() if p.name.startswith('final-')}
    if os.path.lexists(folder / RECEIPT):
        assert _read(folder / RECEIPT) == expected
        assert not live, 'retired fixture unexpectedly exists'
        return True
    assert not require_retired, 'fixture retirement receipt is missing'
    assert live == set(trees), 'owned final fixture set changed'
    for name, rows in trees.items():
        root = folder / name
        assert root.is_dir() and not root.is_symlink()
        assert capture_tree(root, True) == rows, ('actual completed fixture changed', name)
    return False


def retire(folder, domain, process):
    """Called only after the full case semantic checker has succeeded."""
    folder = Path(folder)
    assert admit(folder, domain, process) is False
    trees, captures = _plan(folder, domain)
    receipt = _receipt(folder, domain, process, trees, captures)
    for name, rows in trees.items():
        root = folder / name
        for key in sorted(rows, key=lambda s: (len(PurePosixPath(s).parts), s), reverse=True):
            path = root / key
            before = path.lstat()
            row = rows[key]
            assert (before.st_dev, before.st_ino) == (row['device'], row['inode'])
            if row['kind'] == 'directory':
                assert stat.S_ISDIR(before.st_mode)
                path.rmdir()
            else:
                assert (stat.S_ISREG(before.st_mode) if row['kind'] == 'file'
                        else stat.S_ISLNK(before.st_mode))
                path.unlink()
    with (folder / RECEIPT).open('xb') as stream:
        stream.write(SORTED(receipt) + b'\n')
    assert admit(folder, domain, process, require_retired=True)
