# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exercise complete owned filesystem domains and replay a fresh original later.

The native phase executes only the static HIA executable. Its complete responses,
observed filesystem projections, descriptor custody, fault receipts and source
identities are retained. The independent original phase runs the complete same
case definitions and compares every response byte and projected observation.
No retained native execution is counted as a new original or native process.
"""
from pathlib import Path
import argparse
import hashlib
import importlib
import json
import os
import stat
import struct
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
DOMAINS = {
    'record_io': ('result_fs_record_io', 'result_record_io_cases', 239, 577, 239, 0),
    'record_io_faults': ('result_fs_record_io_faults', 'result_record_io_fault_cases', 40, 89, 43, 3),
    'directory': ('result_fs_directory', 'result_directory_cases', 121, 347, 121, 0),
    'archive_metadata': ('result_fs_archive_metadata', 'result_archive_metadata_cases', 1649, 3504, 1649, 0),
    'archive_metadata_faults': ('result_fs_archive_metadata_faults', 'result_archive_metadata_fault_cases', 23, 46, 23, 0),
    'archive_publish': ('result_fs_archive_publish', 'result_archive_publish_cases', 1644, 3295, 1644, 0),
    'archive_publish_faults': ('result_fs_archive_publish_faults', 'result_archive_publish_fault_cases', 45, 83, 50, 5),
    'archive_store': ('result_fs_archive_store', 'result_archive_store_cases', 123, 1235, 123, 0),
    'archive_store_faults': ('result_fs_archive_store', 'result_archive_store_fault_cases', 37, 220, 37, 0),
}
SCOPE = {name: False for name in ('whole_runtime_replaced', 'production_activated',
    'old_stack_removal_qualified', 'result_storage_closed', 'public_request_dispatch_qualified',
    'audit_storage_closed', 'archive_anchoring_closed', 'caller_root_path_reopening_qualified',
    'initialization_mutex_contention_qualified', 'initialization_mutex_poisoning_qualified')}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pin(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'not an owned regular observation: ' + str(path))
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': SHA(raw), 'mode': stat.S_IMODE(path.stat().st_mode)}


def source_files():
    names = {Path(__file__).name, 'result_storage_json_cases.py', 'result_record_io_cases.py',
        'result_record_io_fault_cases.py', 'result_record_io_supervisor.py'}
    names.update(path.name for path in HERE.glob('result_fs_*.py'))
    names.update(path.name for path in HERE.glob('result_archive_*.py'))
    names.add('result_directory_cases.py')
    return {name: pin(HERE / name) for name in sorted(names)}


def inventory(folder):
    result = {}
    for path in sorted(Path(folder).rglob('*')):
        require(not path.is_symlink(), 'observation contains a symlink')
        if path.is_file():
            result[str(path.relative_to(folder))] = pin(path)
        else:
            require(path.is_dir(), 'observation contains a special file')
    return result


def retire_fixture(root):
    """Retire only this completed case's fixture, after all observations exist.

    Component-relative operations also cover the original >PATH_MAX cases.
    Final permissions are observed before any cleanup-only chmod. No symlink is
    followed, and every leaf's identity is rechecked immediately before unlink.
    """
    root = Path(root)
    require(root.name == 'fixture' and not root.is_symlink() and root.is_dir(), 'unexpected fixture retirement')
    manifest = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def descend(fd, prefix):
        for name in sorted(os.listdir(fd)):
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            relative = prefix + name
            row = {'path': relative, 'mode': before.st_mode, 'uid': before.st_uid, 'gid': before.st_gid,
                'device': before.st_dev, 'inode': before.st_ino, 'links': before.st_nlink, 'bytes': before.st_size}
            manifest.append(row)
            if stat.S_ISDIR(before.st_mode):
                if stat.S_IMODE(before.st_mode) & 0o700 != 0o700:
                    os.chmod(name, stat.S_IMODE(before.st_mode) | 0o700, dir_fd=fd, follow_symlinks=False)
                    row['cleanup_only_mode'] = stat.S_IMODE(before.st_mode) | 0o700
                child = os.open(name, flags, dir_fd=fd)
                try:
                    actual = os.fstat(child)
                    require((actual.st_dev, actual.st_ino) == (before.st_dev, before.st_ino), 'fixture directory changed')
                    descend(child, relative + '/')
                finally:
                    os.close(child)
                actual = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require((actual.st_dev, actual.st_ino) == (before.st_dev, before.st_ino), 'fixture directory rebound')
                os.rmdir(name, dir_fd=fd)
            else:
                actual = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require((actual.st_dev, actual.st_ino, actual.st_mode) ==
                    (before.st_dev, before.st_ino, before.st_mode), 'fixture leaf changed')
                os.unlink(name, dir_fd=fd)

    before = root.stat()
    if stat.S_IMODE(before.st_mode) & 0o700 != 0o700:
        root.chmod(stat.S_IMODE(before.st_mode) | 0o700)
    fd = os.open(root, flags)
    try:
        actual = os.fstat(fd)
        require((actual.st_dev, actual.st_ino) == (before.st_dev, before.st_ino), 'fixture root changed')
        descend(fd, '')
        require(not os.listdir(fd), 'fixture retirement incomplete')
    finally:
        os.close(fd)
    root.rmdir()
    return {'retired_after_complete_observation': True, 'fixture_root_before':
        {'mode': before.st_mode, 'device': before.st_dev, 'inode': before.st_ino},
        'nodes': manifest, 'remaining_fixture': root.exists()}


def execute(domain, executable, definition, folder):
    module = importlib.import_module(DOMAINS[domain][0])
    if domain == 'record_io':
        wire = b''.join(struct.pack('<Q', len(bytes.fromhex(raw))) + bytes.fromhex(raw)
            for raw in definition['operations'])
        observed, outputs = module.run_one(executable, folder / 'fixture', folder, definition, wire)
        (folder / 'stdin.bin').write_bytes(wire)
        comparison = {key: observed[key] for key in ('before', 'after', 'replies')}
    else:
        returned = module.run(executable, definition, folder)
        observed, outputs = returned[:2]
        if domain in ('record_io_faults', 'archive_publish_faults', 'archive_metadata_faults'):
            fields = ['before', 'after', 'responses']
            if 'recovery' in definition:
                fields += ['recovery_after', 'recovery_responses']
            comparison = {key: observed[key] for key in fields}
        else:
            comparison = observed
        if domain == 'archive_store_faults':
            response = comparison['observations'][definition['expected_response_index']]['response']
            require(response['diagnostic'] == definition['expected_first_diagnostic'], 'specified store error differs')
    if isinstance(outputs, bytes):
        outputs = [outputs]
    framed = b''.join(struct.pack('<Q', len(raw)) + raw for raw in outputs)
    semantic = ENCODE(comparison)
    (folder / 'semantic-comparison.json').write_bytes(semantic)
    (folder / 'complete-projected-output.bin').write_bytes(framed)
    retirement = retire_fixture(folder / 'fixture')
    (folder / 'fixture-retirement.json').write_bytes(ENCODE(retirement))
    require(not retirement['remaining_fixture'], 'owned fixture remains')
    return semantic, framed


def definitions(domain):
    result = list(importlib.import_module(DOMAINS[domain][1]).cases())
    require(len({row['name'] for row in result}) == len(result), 'case names repeat')
    requests = 0
    for row in result:
        actions = row['actions'] if domain == 'directory' else row['operations']
        requests += sum(isinstance(action, str) or 'request' in action for action in actions)
        requests += len(row.get('recovery', []))
    count, expected_requests, processes, killed = DOMAINS[domain][2:]
    require(len(result) == count and requests == expected_requests
        and len(result) + sum('recovery' in row for row in result) == processes
        and sum('recovery' in row for row in result) == killed, 'complete fixed domain changed')
    return result


def admit_capture(folder, domain):
    folder = Path(folder)
    report = json.loads((folder / 'result.json').read_bytes())
    require(report['status'] == 'PASS' and report['phase'] == 'native' and report['domain'] == domain
        and report['new_original_processes'] == 0 and report['source_files'] == source_files(),
        'native capture is incomplete or has different inputs')
    require(report['definitions'] == pin(folder / 'definitions.json'), 'case definitions changed')
    rows = definitions(domain)
    require((folder / 'definitions.json').read_bytes() == ENCODE(rows), 'complete case definitions differ')
    require(len(report['cases']) == len(rows), 'native cases are missing')
    for index, (record, row) in enumerate(zip(report['cases'], rows, strict=True)):
        require(record['index'] == index and record['name'] == row['name'] and record['completed'] is True,
            'native case ordering changed')
        case = folder / f'{index:04d}'
        require(record['artifacts'] == inventory(case), 'native observations changed')
        require(record['semantic'] == pin(case / 'semantic-comparison.json')
            and record['complete_output'] == pin(case / 'complete-projected-output.bin'), 'native projection changed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True, choices=tuple(DOMAINS))
    parser.add_argument('--phase', required=True, choices=('native', 'original'))
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-capture', type=Path)
    args = parser.parse_args()
    out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    executable = args.executable.resolve(strict=True)
    sources = source_files();image = pin(executable);start = time.monotonic()
    report = {'schema': 'hepta.result-storage.filesystem-execution.v1', 'status': 'RUNNING',
        'phase': args.phase, 'domain': args.domain, 'source_files': sources, 'executable': image,
        'cases': [], 'new_original_processes': 0, 'new_native_processes': 0,
        'semantic_reference_comparison_complete': False, **SCOPE}
    save = lambda: (out / 'result.json').write_bytes(ENCODE(report))
    save()
    try:
        require((args.phase == 'original') == (args.native_capture is not None), 'original phase needs current native capture')
        native = admit_capture(args.native_capture, args.domain) if args.native_capture else None
        rows = definitions(args.domain)
        (out / 'definitions.json').write_bytes(ENCODE(rows));report['definitions'] = pin(out / 'definitions.json')
        for index, definition in enumerate(rows):
            case = out / f'{index:04d}'
            semantic, complete = execute(args.domain, executable, definition, case)
            if native:
                captured = args.native_capture / f'{index:04d}'
                require(semantic == (captured / 'semantic-comparison.json').read_bytes(),
                    'full original/native filesystem comparison differs: ' + definition['name'])
                require(complete == (captured / 'complete-projected-output.bin').read_bytes(),
                    'complete original/native response bytes differ: ' + definition['name'])
            report['cases'].append({'index': index, 'name': definition['name'], 'completed': True,
                'semantic': pin(case / 'semantic-comparison.json'),
                'complete_output': pin(case / 'complete-projected-output.bin'), 'artifacts': inventory(case)})
            if index % 32 == 0:
                save()
        require(source_files() == sources and pin(executable) == image, 'actual execution sources changed')
        if native:
            require(native == admit_capture(args.native_capture, args.domain), 'native capture changed during original replay')
        count, requests, processes, killed = DOMAINS[args.domain][2:]
        report.update(status='PASS', case_count=count, requests=requests, processes=processes,
            deliberately_killed_requests=killed, new_original_processes=processes if native else 0,
            new_native_processes=0 if native else processes, source_unchanged=True,
            semantic_reference_comparison_complete=bool(native), elapsed_seconds=time.monotonic() - start)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), elapsed_seconds=time.monotonic() - start)
        (out / 'failure.txt').write_text(traceback.format_exc())
        raise
    finally:
        save()
    print(json.dumps({key: report[key] for key in ('schema', 'status', 'phase', 'domain', 'case_count',
        'requests', 'processes', 'deliberately_killed_requests', 'new_original_processes',
        'new_native_processes', 'semantic_reference_comparison_complete', 'elapsed_seconds')}, sort_keys=True))


if __name__ == '__main__':
    main()
