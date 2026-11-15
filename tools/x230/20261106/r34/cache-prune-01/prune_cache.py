#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One attempt: unlink exactly two closed, rebuildable R33 cache files.

No recursive deletion, subprocess, build, benchmark, retry or cache rename.
The independent retained test executable and all source/results are preserved.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import types

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r34')
OWNER = Path('/home/qian/hepta-runtime-optimization-20261106-r33')
CACHE = OWNER / 'target-build'
TOOL = ROOT / 'cache-prune-tools-01/prune_cache.py'
PLAN = ROOT / 'cache-prune-tools-01/plan.json'
OUTPUT = ROOT / 'cache-prune-01'
MINIMUM_FREE = 3 * 1024**3
MAX_ENTRIES = 65536
MAX_INVENTORY_BYTES = 64 * 1024**2
HELPER = {'path': str(ROOT / 'prepare_qualify.py'), 'bytes': 29912,
          'sha256': '6f50859c6155ecc1c0eea78a027ae94508d6de9dee0545cef00bde8fee0bf67f'}
QUALIFICATION_INPUT = {'path': str(ROOT / 'qualification-input.json'), 'bytes': 3707,
                       'sha256': '7065ad29178dbec61a1ed78fa24c9697cd6b6d3fed1ca9d5bb6cb7335b097e1e'}
OWNER_CLOSURE = {'path': str(ROOT / 'cache-owner-closure-inputs.json'), 'bytes': 4503,
                 'sha256': '94b2649e0a8b66711b122638432848a41af37f06a10973f81e7be21d5705ebb9'}
# The plan must equal this fixed two-file allowlist. It cannot add paths.
CANDIDATES = (
    {'path': 'debug/deps/hepta_runtime-1b8b761b89392e3b',
     'stat': {'dev': 2053, 'ino': 2948723, 'size': 541152032,
              'mtime_ns': 1793930603038937300, 'nlink': 1, 'allocated_bytes': 541147136},
     'expected_sha256': 'e2096aa99096233152ffbd11fd1d42aa145cbfa1ef9f4fa81b8191e9055ad3b1',
     'retained_copy': str(OWNER / 'qualification-01/test-binaries/hepta_runtime-1b8b761b89392e3b')},
    {'path': 'debug/deps/libhepta_runtime-564505b54e9d81cd.rlib',
     'stat': {'dev': 2053, 'ino': 3173052, 'size': 388308656,
              'mtime_ns': 1793930262097573600, 'nlink': 1, 'allocated_bytes': 388313088},
     'expected_sha256': None, 'retained_copy': None},
)
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def need(value, message):
    if not value:
        raise RuntimeError(message)


def snapshot(value):
    return {'dev': value.st_dev, 'ino': value.st_ino, 'mode': value.st_mode,
            'uid': value.st_uid, 'gid': value.st_gid, 'nlink': value.st_nlink,
            'size': value.st_size, 'mtime_ns': value.st_mtime_ns,
            'ctime_ns': value.st_ctime_ns, 'allocated_bytes': value.st_blocks * 512}


def raw_identity(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def small_original(binding):
    path = Path(binding['path'])
    need(path.is_absolute() and path.resolve() == path, 'noncanonical original path')
    fd = os.open(path, FILE_FLAGS)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1, 'original must be a regular single-link file')
        need(first.st_size == binding['bytes'] and first.st_size <= 1024**2, 'small-original size differs')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(1024**2 + 1)
        need(snapshot(first) == snapshot(os.fstat(fd)) == snapshot(path.lstat()), 'original changed while read')
        need(raw_identity(path, raw) == binding, 'original bytes/hash differs')
        return raw
    finally:
        os.close(fd)


def write_new(name, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    need(len(raw) <= MAX_INVENTORY_BYTES, 'receipt size limit exceeded')
    path = OUTPUT / name
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(OUTPUT, DIR_FLAGS)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return raw_identity(path, raw)


def unstarted_r34():
    for name in ('preparation.json', 'preparation.json.next', 'source', 'target-build', 'qualification-01'):
        need(not os.path.lexists(ROOT / name), 'R34 preparation already claimed or started: ' + name)


def cache_inventory():
    need(CACHE.resolve() == CACHE, 'cache path changed or became a symlink')
    root_fd = os.open(CACHE, DIR_FLAGS)
    rows = {'': {'kind': 'directory', 'stat': snapshot(os.fstat(root_fd))}}
    stack = [('', root_fd)]
    try:
        while stack:
            relative, directory = stack.pop()
            try:
                names = sorted(os.listdir(directory))
                for name in names:
                    path = name if not relative else relative + '/' + name
                    need(path not in rows and len(rows) < MAX_ENTRIES, 'cache inventory duplicate or entry limit')
                    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    kind = ('directory' if stat.S_ISDIR(current.st_mode) else
                            'file' if stat.S_ISREG(current.st_mode) else
                            'symlink' if stat.S_ISLNK(current.st_mode) else 'other')
                    row = {'kind': kind, 'stat': snapshot(current)}
                    if kind == 'symlink':
                        row['target'] = os.readlink(name, dir_fd=directory)
                    rows[path] = row
                    if kind == 'directory':
                        child = os.open(name, DIR_FLAGS, dir_fd=directory)
                        try:
                            need(snapshot(os.fstat(child)) == snapshot(current), 'directory changed during inventory')
                        except BaseException:
                            os.close(child)
                            raise
                        stack.append((path, child))
            finally:
                os.close(directory)
        need(snapshot(CACHE.lstat()) == rows['']['stat'], 'cache root changed during inventory')
        return rows
    finally:
        for _, directory in stack:
            os.close(directory)


def open_parent():
    root_fd = os.open(CACHE, DIR_FLAGS)
    try:
        need(snapshot(os.fstat(root_fd)) == snapshot(CACHE.lstat()), 'cache root identity differs')
        debug_fd = os.open('debug', DIR_FLAGS, dir_fd=root_fd)
        try:
            deps_fd = os.open('deps', DIR_FLAGS, dir_fd=debug_fd)
        finally:
            os.close(debug_fd)
        return deps_fd
    finally:
        os.close(root_fd)


def hash_open_file(fd, maximum):
    os.lseek(fd, 0, os.SEEK_SET)
    total, digest = 0, hashlib.sha256()
    while True:
        block = os.read(fd, 1024**2)
        if not block:
            break
        total += len(block)
        need(total <= maximum, 'candidate grew during hashing')
        digest.update(block)
    need(total == maximum, 'candidate size changed during hashing')
    return digest.hexdigest()


def checked_candidate(parent_fd, candidate, expected_digest=None):
    name = Path(candidate['path']).name
    fd = os.open(name, FILE_FLAGS, dir_fd=parent_fd)
    try:
        first = os.fstat(fd)
        current = snapshot(first)
        need(stat.S_ISREG(first.st_mode) and first.st_uid == 1000, 'candidate type/owner differs')
        need(all(current[key] == value for key, value in candidate['stat'].items()), 'candidate fixed stat differs: ' + name)
        digest = hash_open_file(fd, first.st_size)
        need(current == snapshot(os.fstat(fd)) == snapshot(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)),
             'candidate changed while hashing: ' + name)
        for required in (candidate['expected_sha256'], expected_digest):
            need(required is None or digest == required, 'candidate SHA differs: ' + name)
        return fd, {'path': str(CACHE / candidate['path']), 'stat': current, 'sha256': digest}
    except BaseException:
        os.close(fd)
        raise


def check_retained_test(candidate, cache_stat, retained):
    path = Path(candidate['retained_copy'])
    digest = candidate['expected_sha256']
    need(retained.get(str(path)) == digest, 'retained ELF differs from frozen original test SHA')
    need(path.resolve() == path, 'retained path is not canonical')
    fd = os.open(path, FILE_FLAGS)
    try:
        first = os.fstat(fd)
        current = snapshot(first)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == candidate['stat']['size'],
             'retained ELF must be a separate regular single-link complete file')
        need((first.st_dev, first.st_ino) != (cache_stat['dev'], cache_stat['ino']), 'retained ELF is the candidate inode')
        need(hash_open_file(fd, first.st_size) == digest, 'retained stable SHA differs')
        need(current == snapshot(os.fstat(fd)) == snapshot(path.lstat()), 'retained ELF changed during hashing')
        return {'path': str(path), 'stat': current, 'sha256': digest}
    finally:
        os.close(fd)


def quiet(module):
    # Call only with all cache inventory/candidate descriptors closed; the
    # unchanged helper therefore needs no special exemption for this process.
    unstarted_r34()
    result = module.inspect_processes(CACHE)
    need(result['matched_processes'] == [] and result['compiler_processes'] == [], 'cache owner or compiler remains active')
    return result


def compare_inventory(before, after, removed):
    need(set(after) == set(before) - set(removed), 'an unexpected cache path appeared or disappeared')
    mutable_parent_fields = {'size', 'mtime_ns', 'ctime_ns', 'allocated_bytes'}
    for path in after:
        if path == 'debug/deps' and removed:
            need(before[path]['kind'] == after[path]['kind'] == 'directory', 'candidate parent is no longer a directory')
            left = {k: v for k, v in before[path]['stat'].items() if k not in mutable_parent_fields}
            right = {k: v for k, v in after[path]['stat'].items() if k not in mutable_parent_fields}
            need(left == right, 'candidate parent identity/ownership changed')
        else:
            need(before[path] == after[path], 'unselected cache entry changed: ' + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    need(sys.platform == 'linux' and os.getuid() == 1000, 'fixed Linux owner required')
    need(Path(__file__).resolve() == TOOL and ROOT.resolve() == ROOT, 'fixed installed tool/root required')
    unstarted_r34()
    need(len(args.plan_sha256) == 64 and all(c in '0123456789abcdef' for c in args.plan_sha256), 'invalid plan SHA')
    plan_binding = {'path': str(PLAN), 'bytes': PLAN.lstat().st_size, 'sha256': args.plan_sha256}
    plan = json.loads(small_original(plan_binding))
    need(plan['schema'] == 'hepta-r34-two-file-cache-prune-plan/v1' and plan['sealed'] is True, 'sealed fixed plan required')
    need(plan['candidates'] == list(CANDIDATES), 'plan changes the fixed two-file allowlist')
    need(plan['cache_owner'] == str(OWNER) and plan['cache_path'] == str(CACHE), 'cache path differs')
    need(plan['output'] == str(OUTPUT) and plan['minimum_free_bytes'] == MINIMUM_FREE, 'output or free-space gate differs')
    need(plan['helper_launcher'] == HELPER and plan['qualification_input'] == QUALIFICATION_INPUT and plan['owner_closure'] == OWNER_CLOSURE,
         'sealed R34 bindings differ')
    need(plan['tool']['path'] == str(TOOL), 'tool path differs')
    small_original(plan['tool'])
    OUTPUT.mkdir(mode=0o700)
    report = {'schema': 'hepta-r34-two-file-cache-prune/v1', 'passed': False, 'started_utc': now(),
              'plan': plan_binding, 'tool': plan['tool'], 'helper_launcher': HELPER,
              'automatic_retries': 0, 'source_or_threshold_modified': False,
              'directories_deleted': 0, 'cache_renamed': False, 'subprocesses_started': 0,
              'deletions': [], 'receipts': {}, 'postcheck_errors': []}
    before, module, retained_before = None, None, None
    try:
        report['receipts']['claim'] = write_new('claim.json', report)
        helper_raw = small_original(HELPER)
        module = types.ModuleType('bound_r34_preparation_for_cache_prune')
        module.__file__ = HELPER['path']
        # Execute the already reviewed, hash-bound module definitions only.
        # Its __main__ branch is false; no preparer or qualifier is invoked.
        exec(compile(helper_raw, HELPER['path'], 'exec', optimize=0), module.__dict__)
        need(module.ROOT == ROOT and module.CACHE_OWNER == OWNER, 'helper roots differ')
        config = json.loads(module.read_bound(QUALIFICATION_INPUT))
        closure = json.loads(module.read_bound(OWNER_CLOSURE))
        need(config['sealed'] is True and config['owner_closure_input_sha256'] == OWNER_CLOSURE['sha256'], 'sealed closure differs')
        module.frozen_candidate(config)
        harness = {p.name: module.sha(p) for p in sorted((module.BASE / 'source/tools/x230/20261028').glob('*.py'))}
        need(len(harness) == 19 and harness == config['qualification_harness_sha256'], 'accepted harness differs')
        owner_closed = module.cache_owner_closed(closure, harness)
        retained_before = module.retained_programs(OWNER)
        first_processes = quiet(module)
        report['receipts']['owner_before'] = write_new('owner-before.json', {
            'owner_closure': owner_closed, 'retained_programs': retained_before, 'process_check': first_processes})
        before = cache_inventory()
        need(set(name for name in before if name and '/' not in name) == {'debug', 'release', '.rustc_info.json'}, 'unexpected cache root entries')
        report['receipts']['cache_before'] = write_new('cache-before.json', {
            'scope': 'complete cache entry metadata, no followed symlinks, access times excluded', 'entries': before})
        candidate_rows = []
        parent_fd = open_parent()
        try:
            for candidate in CANDIDATES:
                fd, row = checked_candidate(parent_fd, candidate)
                os.close(fd)
                need(row['stat'] == before[candidate['path']]['stat'], 'candidate differs from before inventory')
                if candidate['retained_copy']:
                    row['independent_retained_copy'] = check_retained_test(candidate, row['stat'], retained_before)
                candidate_rows.append(row)
        finally:
            os.close(parent_fd)
        report['receipts']['candidates_before'] = write_new('candidates-before.json', candidate_rows)
        final_processes = quiet(module)
        report['free_bytes_before'] = shutil.disk_usage(ROOT).free
        report['receipts']['deletion_intent'] = write_new('deletion-intent.json', {
            'at_utc': now(), 'all_candidates_verified_before_any_unlink': True,
            'free_bytes_before': report['free_bytes_before'], 'minimum_free_bytes': MINIMUM_FREE,
            'process_check': final_processes, 'candidates': candidate_rows,
            'rlib_digest_binding': 'original fixed-stat object was stably hashed; the same full SHA is required again immediately before unlink'})
        for index, (candidate, original) in enumerate(zip(CANDIDATES, candidate_rows), 1):
            quiet(module)
            parent_fd = open_parent()
            fd = None
            try:
                fd, current = checked_candidate(parent_fd, candidate, original['sha256'])
                need(current['stat'] == original['stat'], 'candidate metadata changed after intent')
                if candidate['retained_copy']:
                    current['independent_retained_copy'] = check_retained_test(candidate, current['stat'], retained_before)
                report['receipts']['delete_%02d_intent' % index] = write_new('delete-%02d-intent.json' % index, current)
                name = Path(candidate['path']).name
                need(snapshot(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == current['stat'], 'candidate changed before unlink')
                os.unlink(name, dir_fd=parent_fd)
                # Record the successful unlink immediately, before later fsync
                # or custody checks can fail. Never hide a partial deletion.
                deleted = {'path': candidate['path'], 'at_utc': now(), 'sha256': current['sha256'],
                           'original_stat': current['stat'], 'unlinked': True,
                           'parent_synced': False, 'opened_inode_unlinked': False,
                           'path_absent': False}
                report['deletions'].append(deleted)
                os.fsync(parent_fd)
                deleted['parent_synced'] = True
                need(os.fstat(fd).st_nlink == 0, 'the opened candidate was not unlinked')
                deleted['opened_inode_unlinked'] = True
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RuntimeError('candidate path still exists after unlink')
                deleted['path_absent'] = True
                report['receipts']['delete_%02d_result' % index] = write_new('delete-%02d-result.json' % index, deleted)
            finally:
                if fd is not None:
                    os.close(fd)
                os.close(parent_fd)
        report['two_requested_files_unlinked'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            after = cache_inventory()
            report['receipts']['cache_after'] = write_new('cache-after.json', {
                'scope': 'complete cache entry metadata, no followed symlinks, access times excluded', 'entries': after})
            report['observed_absent_allowed_candidates'] = [
                candidate['path'] for candidate in CANDIDATES if candidate['path'] not in after]
            if before is not None:
                removed = [row['path'] for row in report['deletions']]
                compare_inventory(before, after, removed)
                report['unselected_cache_entries_unchanged'] = True
        except BaseException as error:
            report['postcheck_errors'].append('inventory: ' + type(error).__name__ + ': ' + str(error))
        if module is not None and retained_before is not None:
            try:
                owner_after = module.cache_owner_closed(closure, harness)
                retained_after = module.retained_programs(OWNER)
                need(retained_before == retained_after, 'retained programs changed')
                report['receipts']['owner_after'] = write_new('owner-after.json', {
                    'owner_closure': owner_after, 'retained_programs': retained_after, 'process_check': quiet(module)})
                report['independent_retained_programs_unchanged'] = True
            except BaseException as error:
                report['postcheck_errors'].append('owner: ' + type(error).__name__ + ': ' + str(error))
        report['free_bytes_after'] = shutil.disk_usage(ROOT).free
        report['minimum_free_bytes'] = MINIMUM_FREE
        report['free_space_gate_met'] = report['free_bytes_after'] >= MINIMUM_FREE
        report['passed'] = (len(report['deletions']) == 2 and 'error' not in report
                            and not report['postcheck_errors'] and report['free_space_gate_met'])
        report['finished_utc'] = now()
        final = write_new('report.json', report)
        print(json.dumps({'passed': report['passed'], 'deleted': len(report['deletions']),
                          'free_bytes_before': report.get('free_bytes_before'),
                          'free_bytes_after': report['free_bytes_after'], 'free_space_gate_met': report['free_space_gate_met'],
                          'error': report.get('error'), 'postcheck_errors': report['postcheck_errors'], 'report': final}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
