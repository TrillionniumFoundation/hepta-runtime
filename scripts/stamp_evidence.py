# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Recheck complete real Stamp captures without executing either owner."""
from pathlib import Path
import importlib.util
import json
import struct
import sys

from audit_stamp_registry import HARNESS, encoded, regular, require, sha
from hia_native_result_storage_qualification import object_at, pin

COUNTS = {'stamp': (36, 117, 0), 'stamp_kernel': (34, 102, 53),
    'cache_stamp': (38, 183, 0), 'cache_stamp_kernel': (18, 105, 24)}


def harness(root, name):
    directory = Path(root) / HARNESS;path = directory / (name + '.py')
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location('_stamp_' + name + '_' + sha(regular(path)), path)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def selected(root, domain):
    owner = domain.removesuffix('_kernel')
    require(owner in ('stamp', 'cache_stamp'), 'unknown Stamp domain')
    module = harness(root, 'audit_stamp_cases' if owner == 'stamp' else 'cache_stamp_cases')
    rows = list(module.fault_cases() if domain.endswith('_kernel') else module.cases())
    count, requests, controls = COUNTS[domain]
    require(len(rows) == len({row['name'] for row in rows}) == count
        and sum(sum('mutation' not in step for step in row['steps']) for row in rows) == requests
        and sum(len(row.get('supervisor', {}).get('faults', [])) for row in rows) == controls,
        'complete frozen Stamp scenario domain changed')
    return module, rows


def descriptors(value):
    require(type(value) is dict and set(value) == {'files', 'event_streams'}, 'held descriptor schema differs')
    require(value['files'] == sorted(value['files'], key=encoded)
        and value['event_streams'] == sorted(value['event_streams'], key=encoded),
        'held descriptor observations are unordered')
    for row in value['files']:
        require(set(row) == {'device', 'inode', 'mode', 'position', 'flags'}
            and all(type(item) is int and item >= 0 for item in row.values()) and row['position'] == 0,
            'held file descriptor or preserved cursor differs')
    for stream in value['event_streams']:
        require(stream == sorted(stream, key=encoded), 'inotify watch observations are unordered')
        for row in stream:
            require(set(row) == {'wd', 'ino', 'sdev', 'mask', 'ignored_mask'}
                and all(type(item) is int and item >= 0 for item in row.values()),
                'complete inotify watch observation differs')


def kernel_evidence(folder, config, command):
    report = object_at(folder / 'kernel.json')
    require(report.get('schema') == 'hepta.namespace-owned-kernel-observer.v1'
        and report.get('status') == 'PASS' and report.get('command') == command
        and report.get('configuration') == config == object_at(folder / 'kernel-config.json')
        and report.get('direct_owned_child_only') is True and report.get('semantic_emulation') is False
        and report.get('all_selected_faults_reached') is True and report.get('child_reaped') is True
        and report.get('exit_code') == 0 and type(report.get('pid')) is int and report['pid'] > 0
        and int(regular(folder / 'kernel.pid')) == report['pid'], 'actual owned syscall observer differs')
    counts = {};fired = set()
    for event in report['events']:
        kind = event['kind'];counts[kind] = counts.get(kind, 0) + 1
        require(event['ordinal'] == counts[kind] and type(event['actual_kernel_result']) is int
            and type(event['delivered_result']) is int and type(event['held_files']) is list,
            'actual kernel event ordinal or completion missing')
        matches = [(i, row) for i, row in enumerate(config['faults'])
            if row['kind'] == kind and row.get('ordinal', 1) == counts[kind]]
        require(len(matches) <= 1, 'overlapping owned kernel faults')
        if not matches:
            require(event['completion'] == 'kernel_continue'
                and event['actual_kernel_result'] == event['delivered_result'],
                'unselected syscall was changed')
            continue
        index, fault = matches[0];require(index not in fired, 'kernel fault applied twice');fired.add(index)
        if 'errno' in fault:
            expected = ('actual_kernel_close_then_injected_errno' if kind.endswith('_close')
                else 'injected_errno_before_kernel_effect')
            require(event['completion'] == expected and event['delivered_result'] == -fault['errno'],
                'selected errno completion differs')
            if kind.endswith('_close'):
                require(event['actual_kernel_result'] == 0, 'failed injected close did not retire its descriptor')
        elif 'short_limit' in fault:
            require(event['completion'] == 'bounded_actual_kernel_read'
                and event['actual_request_bytes'] == fault['short_limit']
                and -4095 <= event['actual_kernel_result'] <= fault['short_limit']
                and event['actual_kernel_result'] == event['delivered_result'], 'actual bounded read differs')
        else:
            require(fault.get('zero') is True and event['completion'] == 'injected_eof_without_file_bytes'
                and event['delivered_result'] == 0, 'selected EOF completion differs')
    require(fired == set(range(len(config['faults']))) and counts == report['counts'],
        'not every declared kernel control actually completed')
    return {'counts': counts, 'events': len(report['events']), 'sha256': sha(regular(folder / 'kernel.json'))}


def stamp_response(size, body, step, case):
    require(size == step.get('status', 48 if step.get('diagnostic', case.get('diagnostic', 0)) else 160),
        'Stamp diagnostic status differs')
    if not body:
        return
    diagnostic, error, missing, value, zero = struct.unpack_from('<5Q', body, 8)
    require(body[:8] == b'HRACC001' and diagnostic in (0, 16, 23) and zero == 0
        and (diagnostic, error) == (step.get('diagnostic', case.get('diagnostic', 0)), step.get('error', 0))
        and missing == (int(error == 2) if diagnostic == 23 else 0)
        and size == (48 if diagnostic else 160) and value == (0 if diagnostic else 112),
        'complete Stamp result envelope differs')
    if not diagnostic:
        require(body[48:56] == b'HRAST001' and struct.unpack_from('<Q', body, 104)[0] in (1, 2),
            'complete actual Stamp projection differs')


def cache_response(size, body, step, stamps, module):
    if 'status' in step:
        require(size == step['status'], 'cache private-wire status differs')
        return
    require(body[:8] == b'HRACR001' and 64 <= size <= 266432, 'cache result framing differs')
    diagnostic, error, missing, value, count_records, count_cache, initialized = struct.unpack_from('<7Q', body, 8)
    require(diagnostic in (0, 16, 23, 43) and count_cache <= 16 and initialized <= 1
        and (diagnostic, error) == (step.get('diagnostic', 0), step.get('error', 0))
        and missing == (int(error == 2) if diagnostic == 23 else 0)
        and (not diagnostic or size == 64), 'complete cache diagnostic envelope differs')
    for name, actual in (('value', value), ('cache_count', count_cache), ('initialized', initialized)):
        require(name not in step or step[name] == actual, 'cache state projection differs')
    if step.get('save'):
        require(size >= 176 and value == 112 and body[64:72] == b'HRAST001', 'saved actual Stamp is absent')
        stamps[step['save']] = body[64:176]
    if 'expected_records' in step:
        require(size >= 176 and count_records == len(step['expected_records'])
            and body[176:] == module.records_wire(step['expected_records']), 'complete cached Record vector differs')


def frames(folder, case, owner, module, observations):
    incoming, outgoing = regular(folder / 'stdin.bin'), regular(folder / 'stdout.bin')
    left = 0;right = 0;stamps = {};calls = 0;count = 0
    require(len(observations) == len(case['steps']), 'Stamp observation domain is incomplete')
    for index, (step, observed) in enumerate(zip(case['steps'], observations, strict=True)):
        require(observed.get('step') == index, 'Stamp observation order changed')
        if 'mutation' in step:
            require(set(observed) == {'step', 'mutation', 'filesystem'} and observed['mutation'] == step
                and type(observed['filesystem']) is dict, 'actual fixture mutation differs')
            continue
        raw = ((bytes.fromhex(step['raw']) if 'raw' in step else module.REQUEST)
            if owner == 'stamp' else module.wire(step, stamps))
        wire = struct.pack('<Q', len(raw)) + raw
        require(incoming[left:left + len(wire)] == wire, 'full retained Stamp input differs from its scenario')
        left += len(wire);count += 1
        if owner == 'stamp' and raw == module.REQUEST:
            calls += 1
        require(right + 4 <= len(outgoing), 'partial Stamp response length')
        size = struct.unpack_from('<I', outgoing, right)[0]
        limit = 160 if owner == 'stamp' else 266432
        allowed = (48, 160, 0xffffffff) if owner == 'stamp' else (0xffffffff, 0xfffffffe, 0xfffffff9)
        require(size in allowed or owner == 'cache_stamp' and 64 <= size <= limit,
            'unexpected Stamp response status')
        length = 4 + (size if size <= limit else 0)
        require(right + length <= len(outgoing), 'partial Stamp response body')
        response = outgoing[right:right + length];right += length;body = response[4:]
        require(set(observed) == {'step', 'result_hex', 'descriptors', 'filesystem_unchanged'}
            and observed['result_hex'] == response.hex() and observed['filesystem_unchanged'] is True,
            'observed result differs from complete actual output')
        descriptors(observed['descriptors'])
        if owner == 'stamp':
            stamp_response(size, body, step, case)
        else:
            cache_response(size, body, step, stamps, module)
    require(left == len(incoming) and right == len(outgoing), 'extra or missing complete Stamp frames')
    return incoming, outgoing, count, calls


def process_capture(root, folder, case, owner, module, observations, executable, original):
    incoming, outgoing, count, calls = frames(folder, case, owner, module, observations)
    row = object_at(folder / 'result.json');stderr = regular(folder / 'stderr.log')
    case_folder = folder.parent;fixture = case_folder / 'fixture'
    paths = ([fixture] if owner == 'stamp' else [fixture / ('d%03d' % case.get('aliases', {}).get(str(i), i))
        for i in range(1, 18)])
    inner = [str(executable), *map(str, paths)];command = inner
    name = 'test_audit_stamp' if owner == 'stamp' else 'test_cache_stamp'
    expected_files = {'result.json', 'stdin.bin', 'stdout.bin', 'stderr.log'}
    if 'supervisor' in case:
        supervisor = 'audit_stamp_supervisor.py' if owner == 'stamp' else 'cache_stamp_supervisor.py'
        command = [sys.executable, '-I', '-B', str(Path(root) / HARNESS / supervisor),
            '--fixture', str(fixture), '--config', str(folder / 'kernel-config.json'),
            '--log', str(folder / 'kernel.json'), '--', *inner]
        require(row.get('kernel') == kernel_evidence(folder, case['supervisor'], inner),
            'process kernel receipt differs from complete trace')
        expected_files.update(('kernel-config.json', 'kernel.json', 'kernel.pid'))
    else:
        require('kernel' not in row, 'unexpected synthetic kernel receipt')
    require({path.name for path in folder.iterdir()} == expected_files, 'unexpected process capture member')
    expected = {'command': command, 'cwd': str(root), 'environment': {'PATH': ''},
        'source_harness_sha256': sha(regular(Path(root) / HARNESS / (name + '.py'))),
        'frames': count, 'valid_requests': calls, 'exit_code': 0, 'child_reaped': True,
        'stdin_bytes': len(incoming), 'stdin_sha256': sha(incoming),
        'stdout_bytes': len(outgoing), 'stdout_sha256': sha(outgoing),
        'stderr_bytes': len(stderr), 'stderr_sha256': sha(stderr)}
    require(all(row.get(key) == value for key, value in expected.items())
        and type(row.get('pid')) is int and row['pid'] > 0
        and type(row.get('elapsed_seconds')) in (int, float) and 0 <= row['elapsed_seconds'] <= 180,
        'complete actual Stamp process receipt differs')
    if original:
        observed = json.loads(stderr)
        require(type(observed) is dict and observed.get('status') == 'PASS' and observed.get('frames') == count
            and observed.get('full_original_namespace_module') is True and row.get('original') == observed,
            'actual original Stamp observer is incomplete')
        if owner == 'stamp':
            require(observed.get('original_archive_stamp_calls') == calls
                and observed.get('borrowed_file_released') is True, 'original Stamp calls or release differs')
        else:
            require(observed.get('borrowed_files_released') is True
                and observed.get('real_filesystem_effects') is True and observed.get('child_contracts_scripted') is False
                and len(observed.get('calls', [])) == 7 and sum(observed['calls']) <= count,
                'original real-cache calls or release differs')
    else:
        require(not stderr and row.get('original') is None, 'native process has an original observer')
    return row, incoming, outgoing


def capture_files(folder):
    folder = Path(folder);result = {}
    for path in sorted(folder.rglob('*')):
        parts = path.relative_to(folder).parts
        if len(parts) >= 2 and parts[1] in ('fixture', 'held'):
            continue
        if path.name == 'retired-fixtures.json':
            continue
        require(not path.is_symlink(), 'Stamp capture contains a symlink')
        if path.is_file():
            result[str(path.relative_to(folder))] = pin(path)
        else:
            require(path.is_dir(), 'Stamp capture contains a special file')
    return result


def capture(root, folder, domain, executables, *, retirement=True):
    root, folder = Path(root), Path(folder);owner = domain.removesuffix('_kernel')
    module, cases = selected(root, domain);report = object_at(folder / 'result.json')
    require(set(executables) in ({'native'}, {'native', 'original'}), 'Stamp implementation set differs')
    paired = 'original' in executables;count, requests, controls = COUNTS[domain]
    expected = {'status': 'PASS', 'native_sha256': pin(executables['native'])['sha256'],
        'original_sha256': pin(executables['original'])['sha256'] if paired else None,
        'original_executed': paired, 'full_original_namespace_module': paired,
        'real_filesystem_effects': True, 'kernel_controls': domain.endswith('_kernel'),
        'full_wire_comparison': paired, 'production_activated': False, 'whole_runtime_replaced': False,
        'paired_processes': count if paired else 0, 'native_processes': count,
        'requests_per_side': requests, 'selected_controls_per_side': controls}
    require(all(report.get(key) == value for key, value in expected.items()) and len(report.get('cases', [])) == count,
        'complete actual Stamp comparison scope or count differs')
    if owner == 'cache_stamp':
        require(report.get('child_contracts_scripted') is False and report.get('cold_snapshot_admitted') is False,
            'cache scope expanded beyond the actual three-method graph')
    paths = []
    for index, (case, row) in enumerate(zip(cases, report['cases'], strict=True)):
        directory = folder / ('case-%03d' % index)
        require(object_at(directory / 'case.json') == case and object_at(directory / 'result.json') == row
            and row.get('name') == case['name'] and row.get('status') == 'PASS'
            and row.get('requests') == sum('mutation' not in step for step in case['steps'])
            and row.get('exact_wire_bytes_compared') is paired and row.get('original_executed') is paired
            and type(row.get('initial_filesystem')) is dict and type(row.get('final_filesystem')) is dict,
            'complete retained Stamp case differs')
        labels = ['original', 'native'] if paired else ['native'];observed = [];streams = []
        for label in labels:
            process, incoming, outgoing = process_capture(root, directory / label, case, owner, module,
                row['observations'], executables[label], label == 'original')
            observed.append(process);streams.append((incoming, outgoing))
        require(row.get('processes') == observed and all(item == streams[0] for item in streams),
            'complete paired Stamp input/output bytes differ')
        allowed = {'case.json', 'result.json', *labels, 'fixture', 'held'}
        require({path.name for path in directory.iterdir()} <= allowed, 'unexpected Stamp case artifact')
        paths.extend(str((directory / name).relative_to(folder)) for name in ('fixture', 'held'))
    allowed = {'result.json', 'retired-fixtures.json', *('case-%03d' % i for i in range(count))}
    require({path.name for path in folder.iterdir()} <= allowed, 'unexpected Stamp domain artifact')
    if retirement:
        expected_retirement = {'schema': 'hepta.audit-stamp.fixture-retirement.v1', 'status': 'PASS',
            'fixture_paths': paths, 'complete_evidence_sha256': sha(encoded(capture_files(folder))),
            'all_processes_reaped_before_retirement': True, 'semantic_invocations_added': 0}
        require(object_at(folder / 'retired-fixtures.json') == expected_retirement
            and not any((folder / name).exists() or (folder / name).is_symlink() for name in paths),
            'completed fixture retirement differs')
    return report
