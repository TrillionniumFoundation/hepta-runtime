"""Retain the complete owned guard tree across native and fresh-original jobs."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

import hia_native_runtime_mcp_fixtures as archive
from hia_native_config_span_qualification import (GUARD_SOURCE_PINS, canonical, file_pin,
    inside, load, need, same, sha, strict_json)

ROOTS = ('config-span/native/guard/fixtures',)
RECEIPT = 'config-span/retired-fixtures.json'
ARCHIVE = 'config-span/retired-fixtures.bin.gz'
RESTORE = 'config-span/original-fixture-restore.json'


def factory(root):
    path = Path(root) / 'tests/hia_native/config_span/guard_original/cases.py'
    same(file_pin(path), GUARD_SOURCE_PINS['cases.py'], 'fixture factory source')
    return load(path, '_config_span_fixture_factory')


def captured_before(output):
    return strict_json(inside(output, 'config-span/native/guard/filesystem-before.json').read_bytes())


def verify_entries(entries, before, cases):
    """Verify the entire traversable archive, including the formerly denied child."""
    archive.validate_entries(entries, ROOTS)
    nodes = [dict(kind='directory', path=b'', mode=0o700), *cases.fixture_nodes()]
    expected = {(ROOTS[0].encode() + (b'/' + row['path'] if row['path'] else b'')).hex(): row
                for row in nodes}
    same(sorted(row['path_hex'] for row in entries), sorted(expected), 'complete guard fixture paths')
    snapshots = {row['relative_hex']: row for row in before}
    same(sorted(snapshots), sorted(row['path'].hex() for row in nodes), 'complete original fixture snapshot')
    owner = snapshots['']
    for row in entries:
        node = expected[row['path_hex']]
        previous = snapshots[node['path'].hex()]
        same(row['kind'], node['kind'], 'guard fixture object kind')
        same([row['uid'], row['gid']], [owner['uid'], owner['gid']], 'guard fixture object owner')
        same(row['mode'], 0o777 if node['kind'] == 'symlink' else node['mode'], 'archived guard fixture mode')
        same(row['xattrs'], {}, 'guard fixture has undeclared attributes')
        if node['path'] != b'denied/child':
            same([row['source_device'], row['source_inode'], row['nlink']],
                 [previous['device'], previous['inode'], previous['links']], 'same fixture identities before retirement')
        else:
            same(previous, dict(relative_hex=node['path'].hex(), errno=13), 'actual denied child observation')
        if node['kind'] == 'file':
            same([row['bytes'], row['sha256'], row['link_group'], row['nlink']],
                 [len(node['data']), sha(node['data']), row['path_hex'], 1], 'complete archived guard file')
        elif node['kind'] == 'symlink':
            same(row['target_hex'], node['target'].hex(), 'complete archived guard link')


def permission(output, before, source_mode, target_mode):
    expected = next(row for row in before if row['relative_hex'] == b'denied'.hex())
    with archive.parent_fd(output, ROOTS[0] + '/denied') as (fd, name):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        same([info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode],
             [expected['device'], expected['inode'], os.getuid(), expected['gid'], stat.S_IFDIR | source_mode],
             'only the same owned denied directory may change mode')
        os.chmod(name, target_mode, dir_fd=fd, follow_symlinks=False)
        after = os.stat(name, dir_fd=fd, follow_symlinks=False)
        same([after.st_dev, after.st_ino, after.st_mode],
             [info.st_dev, info.st_ino, stat.S_IFDIR | target_mode], 'owned denied mode transition')


def retirement(root, output, binding, origin, *, create=False):
    output = archive.root_path(output)
    expected = dict(schema='hepta.runtime.config-span-fixture-retirement.v1', status='PASS',
                    execution_output_root=str(origin), fixture_directories=list(ROOTS),
                    native_evidence_sha256=sha(canonical(binding)), source_inodes_recreated=False,
                    denied_mode_in_execution=0, denied_mode_in_archive=0o700,
                    semantic_invocations_added=0)
    need(Path(origin).is_absolute() and '..' not in Path(origin).parts, 'guard fixture origin')
    before, cases = captured_before(output), factory(root)
    receipt = output / RECEIPT
    if not receipt.exists():
        need(create and not receipt.is_symlink(), 'guard retirement receipt missing')
        same(str(output), str(origin), 'native fixture retirement requires its actual origin')
        same(cases.snapshot(output / ROOTS[0]), before, 'complete native fixture state before retirement')
        permission(output, before, 0, 0o700)
        entries = archive.snapshot(output, ROOTS)
        verify_entries(entries, before, cases)
        archive.create_archive(output, ROOTS, entries, ARCHIVE)
        pin = file_pin(inside(output, ARCHIVE))
        archive.read_archive(output, entries, ROOTS, ARCHIVE, pin)
        same(archive.snapshot(output, ROOTS), entries, 'full guard fixture stable before removal')
        archive.remove_roots(output, ROOTS, entries)
        archive.absent(output, ROOTS)
        archive.dump_new(output, RECEIPT, dict(expected, entries=entries, archive=pin))
    value = strict_json(inside(output, RECEIPT).read_bytes())
    same(sorted(value), sorted([*expected, 'entries', 'archive']), 'guard retirement fields')
    same({key:value[key] for key in expected}, expected, 'guard retirement scope and binding')
    verify_entries(value['entries'], before, cases)
    counts = archive.read_archive(output, value['entries'], ROOTS, ARCHIVE, value['archive'])
    return dict(expected, **counts, artifact_sha256={name:file_pin(inside(output, name))['sha256']
                                                    for name in (RECEIPT, ARCHIVE)})


@contextmanager
def restored(root, output, binding, admitted, origin):
    """Normal fresh-original execution only; retained readers never enter here."""
    output = archive.root_path(output)
    same(str(output), str(origin), 'original replay requires the actual native origin')
    same(retirement(root, output, binding, origin), admitted, 'admitted native retirement')
    archive.absent(output, ROOTS)
    need(not (output / RESTORE).exists() and not (output / RESTORE).is_symlink(), 'guard restoration already used')
    source = strict_json(inside(output, RECEIPT).read_bytes())
    cases = factory(root)
    created = []
    archive.populate(output, source['entries'], ARCHIVE, source['archive'], created, roots=ROOTS)
    reconstructed = archive.snapshot(output, ROOTS)
    same(archive.logical(reconstructed), archive.logical(source['entries']), 'complete reconstructed guard tree')
    unlocked = cases.snapshot(output / ROOTS[0])
    permission(output, unlocked, 0o700, 0)
    before = cases.snapshot(output / ROOTS[0])
    problem = None
    try:
        yield output / ROOTS[0]
    except BaseException as error:
        problem = error
        raise
    finally:
        after = cases.snapshot(output / ROOTS[0])
        same(after, before, 'fresh original changed the reconstructed guard tree')
        permission(output, after, 0, 0o700)
        final_entries = archive.snapshot(output, ROOTS)
        same(final_entries, reconstructed, 'same reconstructed inode and complete bytes after original')
        archive.remove_roots(output, ROOTS, final_entries)
        archive.absent(output, ROOTS)
        archive.dump_new(output, RESTORE, dict(
            schema='hepta.runtime.config-span-original-fixture-reconstruction.v1',
            status='PASS' if problem is None else 'FAIL', execution_output_root=str(origin),
            source_retirement_sha256=sha(canonical(admitted)), source_inodes_recreated=False,
            fresh_before_after_same_inodes=True, reconstruction_retired=True,
            reconstructed_entries=reconstructed, before=before, after=after,
            error=None if problem is None else dict(type=type(problem).__name__, message=str(problem))))


def retained_reconstruction(root, output, admitted, origin):
    value = strict_json(inside(output, RESTORE).read_bytes())
    expected = dict(schema='hepta.runtime.config-span-original-fixture-reconstruction.v1',
                    status='PASS', execution_output_root=str(origin),
                    source_retirement_sha256=sha(canonical(admitted)), source_inodes_recreated=False,
                    fresh_before_after_same_inodes=True, reconstruction_retired=True, error=None)
    same(sorted(value), sorted([*expected, 'reconstructed_entries', 'before', 'after']), 'guard reconstruction fields')
    same({key:value[key] for key in expected}, expected, 'guard reconstruction scope')
    same(value['before'], value['after'], 'retained reconstruction changed')
    verify_entries(value['reconstructed_entries'], value['before'], factory(root))
    original = strict_json(inside(output, RECEIPT).read_bytes())
    same(archive.logical(value['reconstructed_entries']), archive.logical(original['entries']),
         'complete retained reconstruction matches native archive')
    return dict(expected, artifact_sha256={RESTORE:file_pin(inside(output, RESTORE))['sha256']})
