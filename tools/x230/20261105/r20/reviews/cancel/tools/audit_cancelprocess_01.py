#!/usr/bin/env python3
"""Independently audit a closed, full R20 CANCEL mechanism experiment.

Read only: never imports or executes the producer, saved helpers, target program,
or production source. Diagnostic templates are literal data from the pinned
producer. All fixtures, ordering, semantic oracles and statistics are rebuilt.
The mechanism screen is reported separately from evidence integrity.
"""
import argparse
import ast
import datetime
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import statistics
import sys
import traceback

A_SHA = '2f751c09a9a29bebb0cda0a9bd2bb522d145ee8183740ed1442d77666ee44aa7'
B_SHA = '1f1f086e3bc0fc62184ed51949964e1f82e337b87d330225097ae38722e4ac8c'
PROBE_SHA = 'ae5d82307c4ab36ff6b37e76deeaf0b71259f8c852ac4a2e8ae333a111731daa'
PLAN_SHA = 'a44c750c4b0efc67123b02085194628062884be72d40c0830e6fe85e201c8c96'
CONSTANTS = ('PRIVATE_DIRECTORY_CODE', 'BOUND_OBSERVATION_CODE', 'START_CODE', 'STATUS_CODE', 'READ_CODE', 'CANCEL_CODE')
SCENES = ('cancel_already_exited', 'cancel_linux_owned_pidfd', 'read_control')
SPECS = [
    ('already_exited_native', SCENES[0], 'native', None),
    ('pidfd_owned_native', SCENES[1], 'native', None),
    ('read_control_native', SCENES[2], 'native', None),
    ('pidfd_mock_success', SCENES[1], 'mock', None),
    ('pidfd_unavailable', SCENES[1], 'mock', 'pidfd_unavailable'),
    ('pidfd_open_failure', SCENES[1], 'mock', 'pidfd_open_failure'),
    ('pidfd_signal_failure', SCENES[1], 'mock', 'pidfd_signal_failure'),
    ('missing_owner', SCENES[1], 'mock', 'missing_owner'),
    ('invalid_owner', SCENES[1], 'mock', 'invalid_owner'),
    ('identity_mismatch', SCENES[1], 'mock', 'identity_mismatch'),
    ('uid_mismatch', SCENES[1], 'mock', 'uid_mismatch'),
    ('publication_failure', SCENES[1], 'mock', 'publication_failure'),
    ('nonlinux_success', SCENES[1], 'mock', 'nonlinux_success'),
    ('nonlinux_ps_failure', SCENES[1], 'mock', 'nonlinux_ps_failure'),
    ('nonlinux_revalidate_identity', SCENES[1], 'mock', 'nonlinux_revalidate_identity'),
    ('nonlinux_revalidate_uid', SCENES[1], 'mock', 'nonlinux_revalidate_uid'),
    ('binding_mismatch', SCENES[1], 'mock', 'binding_mismatch')]
USAGE = ('ru_utime', 'ru_stime', 'ru_maxrss', 'ru_ixrss', 'ru_idrss', 'ru_isrss', 'ru_minflt',
         'ru_majflt', 'ru_nswap', 'ru_inblock', 'ru_oublock', 'ru_msgsnd', 'ru_msgrcv',
         'ru_nsignals', 'ru_nvcsw', 'ru_nivcsw')
MARKER = 'R20_CANCEL_METADATA '
FAKE_PID = 424242
FAKE_BOOT = '00000000-0000-4000-8000-000000000020'
FAKE_TICKS = 1234567
PS_START = 'Wed Nov  4 12:34:56 2026'
READ_BYTES = b'R20 cancel read control\n'
LIMITS = {'each_native_cancel_aggregate_B_over_A_cpu_max': 0.95,
          'each_native_cancel_each_adjacent_pair_B_over_A_cpu_max': 1.0,
          'byte_identical_read_control_aggregate_B_over_A_cpu_max': 1.1,
          'all_semantics_and_measurement_correctness_required': True,
          'all_owned_child_scope_checks_required': True, 'complete_fixed_matrix_required': True}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_pairs(items):
    value = {}
    for key, item in items:
        need(key not in value, 'duplicate JSON key: ' + key)
        value[key] = item
    return value


def decode(raw):
    def nonfinite(value):
        raise ValueError('nonfinite JSON: ' + value)
    return json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=nonfinite)


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def stamp(value):
    return tuple(getattr(value, field) for field in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class Inputs:
    def __init__(self):
        self.files = {}

    def read(self, path, expected=None):
        path = Path(path).absolute()
        need(path.resolve() == path, 'noncanonical or linked input: ' + str(path))
        if path not in self.files:
            before = path.lstat()
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'not a single-link regular input: ' + str(path))
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                need(stamp(before) == stamp(os.fstat(fd)), 'input changed before open: ' + str(path))
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    raw = stream.read(before.st_size + 1)
                need(stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
                     and len(raw) == before.st_size, 'input changed while reading: ' + str(path))
            finally:
                os.close(fd)
            self.files[path] = (stamp(before), raw)
        raw = self.files[path][1]
        if expected is not None:
            need(sha(raw) == expected, 'input SHA256 mismatch: ' + str(path))
        return raw

    def binding(self, path):
        raw = self.read(path)
        return {'path': str(Path(path).absolute()), 'bytes': len(raw), 'sha256': sha(raw)}

    def stable(self):
        for path, (before, raw) in self.files.items():
            need(path.resolve() == path and stamp(path.lstat()) == before and path.read_bytes() == raw,
                 'input changed during audit: ' + str(path))


def safe_relative(value):
    need(isinstance(value, str) and value and '\\' not in value and '\x00' not in value, 'invalid relative path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix() == value
         and all(part not in ('', '.', '..') for part in path.parts), 'relative path escape: ' + value)
    return path


def file_set(root):
    found = set()
    for path in root.rglob('*'):
        mode = path.lstat().st_mode
        need(not stat.S_ISLNK(mode), 'link in evidence tree: ' + str(path))
        if stat.S_ISREG(mode):
            found.add(path.relative_to(root).as_posix())
        else:
            need(stat.S_ISDIR(mode), 'special file in evidence tree: ' + str(path))
    return found


def extract(raw):
    constants = {}
    for name in CONSTANTS:
        found = re.findall(r'const ' + name + r': &str = r#"(.*?)"#;', raw.decode(), re.S)
        need(len(found) == 1, 'Rust constant not unique: ' + name)
        ast.parse(found[0]); constants[name] = found[0]
    return constants


class RemoveImports(ast.NodeTransformer):
    def visit_Import(self, node):
        return None

    def visit_ImportFrom(self, node):
        return None


def producer_literals(raw):
    wanted = {'DIAGNOSTICS', 'BLOCK_IMPORT', 'TARGET_CODE'}
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in wanted:
                need(name not in values and isinstance(node.value, ast.Constant)
                     and type(node.value.value) is str, 'producer literal is not unique immutable text')
                values[name] = node.value.value
    need(set(values) == wanted, 'producer literal coverage')
    return values


def production(constants, scene):
    return ('REMOTE_DIRECTORY_SOURCE = ' + json.dumps(constants['PRIVATE_DIRECTORY_CODE'], ensure_ascii=False)
            + '\nexec(REMOTE_DIRECTORY_SOURCE)\n' + constants['BOUND_OBSERVATION_CODE'] + '\n'
            + constants['READ_CODE' if scene == 'read_control' else 'CANCEL_CODE'])


def saved_script(constants, spec, phase, pid, uid, templates):
    _, scene, mode, fault = spec
    body = production(constants, scene)
    if phase == 'benchmark':
        return body.encode()
    config = {'mode': mode, 'fault': fault, 'pid': pid, 'uid': uid, 'ticks': FAKE_TICKS,
              'boot': FAKE_BOOT, 'ps_start': PS_START, 'nonlinux': bool(fault and fault.startswith('nonlinux')),
              'inprocess': False}
    return ('_r20_cfg = ' + repr(config) + '\n' + templates['DIAGNOSTICS']
            + (templates['BLOCK_IMPORT'] if phase == 'environment-boundary' else '') + body).encode()


def expected_order():
    rows = [('semantics', spec, variant, None, None) for spec in SPECS for variant in 'AB']
    rows.extend(('environment-boundary', SPECS[0], variant, None, None) for variant in 'AB')
    rows.extend(('benchmark', (scene, scene, 'native', None), variant, rnd, call)
                for scene in SCENES for rnd, variant in enumerate('ABBA') for call in range(16))
    return rows


def fixture_inputs(origin, spec, phase, sequence, variant, uid, target):
    name, scene, _, fault = spec
    job = origin / 'fixtures' / phase / (str(sequence).zfill(5) + '-' + variant) / 'state' / 'jobs' / name
    owner = {'supervisor_pid': FAKE_PID, 'supervisor_uid': uid,
             'supervisor_identity': {'kind': 'proc_start_ticks', 'value': FAKE_BOOT + ':' + str(FAKE_TICKS)}}
    if target is not None:
        owner = {'supervisor_pid': target['pid'], 'supervisor_uid': target['guard']['uid'],
                 'supervisor_identity': target['guard']['identity']}
    owner.update(job_id=name, launch_nonce='e' * 32, invocation_id='f' * 32)
    if fault and fault.startswith('nonlinux'):
        owner['supervisor_identity'] = {'kind': 'ps_lstart', 'value': PS_START}
    query = {'job_id': name, 'job_dir': str(job), 'unit': 'hepta-r20-cancel-' + name,
             'request_digest': 'd' * 64, 'grace_seconds': 0, 'stdout_offset': 0, 'stderr_offset': 0, 'limit': 16384}
    docs = {'request.json': {**query, 'launch_nonce': 'e' * 32, 'terminal_publication_protocol': 1},
            'launch.json': {'backend': 'detached'}}
    if scene in ('cancel_already_exited', 'read_control'):
        docs['exit.json'] = {'job_id': name, 'launch_nonce': 'e' * 32, 'exit_code': 0, 'output_complete': True,
                            'output_durable': True, 'cancelled': False, 'timed_out': False, 'terminal_publication_protocol': 1}
    elif fault != 'missing_owner':
        docs['started.json'] = dict(owner, launch_nonce='a' * 32) if fault == 'invalid_owner' else owner
    if fault == 'binding_mismatch':
        query['request_digest'] = 'b' * 64
    files = {name: encode(value) for name, value in docs.items()}
    files.update({'stdout.log': READ_BYTES, 'stderr.log': b''})
    if fault == 'publication_failure':
        files['cancel-request.json.tmp'] = b'R20 preexisting owned temporary file\n'
    return job, owner, query, files


def expected_publication(spec):
    return spec[1] == 'cancel_linux_owned_pidfd' and spec[3] in (
        None, 'nonlinux_success', 'pidfd_signal_failure', 'nonlinux_revalidate_identity', 'nonlinux_revalidate_uid')


def parse_streams(stdout, stderr):
    metadata, lines = None, []
    for line in stderr.decode('utf-8', errors='replace').splitlines():
        if line.startswith(MARKER):
            need(metadata is None, 'duplicate diagnostic metadata')
            metadata = decode(line[len(MARKER):])
        else:
            lines.append(line)
    try:
        response = decode(stdout)
    except (ValueError, UnicodeError):
        response = None
    return {'response': response, 'metadata': metadata, 'application_stderr_lines': lines,
            'exception_tail': lines[-1] if lines else None}


def expected_response(spec, pid):
    name, scene, _, fault = spec
    if fault is not None and fault != 'nonlinux_success':
        return None
    if scene == 'cancel_already_exited':
        return {'job_id': name, 'result': 'already_exited'}
    if scene == 'read_control':
        def part(data):
            return {'offset': 0, 'next_offset': len(data), 'size': len(data), 'eof': True,
                    'text': data.decode(), 'bytes_hex': data.hex()}
        return {'job_id': name, 'stdout': part(READ_BYTES), 'stderr': part(b'')}
    return {'job_id': name, 'result': 'term_sent', 'atomic_identity': fault != 'nonlinux_success',
            'supervisor_pid': pid, 'termination_confirmed': False, 'reconcile_via': 'process_status'}


def semantic_check(row, spec, streams, pid, phase):
    fault = spec[3]
    blocked_a = phase == 'environment-boundary' and row['variant'] == 'A'
    response = None if blocked_a else expected_response(spec, pid)
    if response is not None:
        need(row['returncode'] == 0 and row['response'] == response and not row['application_stderr_lines'],
             'success response/exit/error differs at row ' + str(row['sequence']))
        need(streams['stdout'] == (json.dumps(response, sort_keys=True) + '\n').encode(), 'success stdout bytes differ')
    else:
        errors = {
            'missing_owner': 'frozen supervisor binding unavailable; no cancellation submitted',
            'invalid_owner': 'frozen supervisor binding unavailable; no cancellation submitted',
            'identity_mismatch': 'frozen supervisor identity or UID changed; no cancellation submitted',
            'uid_mismatch': 'frozen supervisor identity or UID changed; no cancellation submitted',
            'nonlinux_ps_failure': 'frozen supervisor identity or UID changed; no cancellation submitted',
            'nonlinux_revalidate_identity': 'supervisor changed before best-effort signal',
            'nonlinux_revalidate_uid': 'supervisor changed before best-effort signal',
            'pidfd_unavailable': 'atomic supervisor signalling unavailable; no cancellation submitted',
            'binding_mismatch': 'remote job request binding missing or mismatched',
            'pidfd_open_failure': 'PermissionError: [Errno 1] R20 deliberate pidfd-open failure',
            'pidfd_signal_failure': 'PermissionError: [Errno 1] R20 deliberate pidfd-signal failure'}
        need(row['returncode'] == 1 and row['response'] is None and streams['stdout'] == b'', 'negative case not fail-closed')
        if blocked_a:
            need(row['exception_tail'] == 'ImportError: R20 deliberate unavailable subprocess', 'blocked import boundary error')
        elif fault == 'publication_failure':
            need(row['exception_tail'].startswith('FileExistsError:') and "'cancel-request.json.tmp'" in row['exception_tail'],
                 'publication failure exception differs')
        else:
            need(row['exception_tail'] == errors[fault], 'semantic error tail differs: ' + str(fault))


def expected_events(spec, pid, opened):
    _, scene, mode, fault = spec
    if scene != 'cancel_linux_owned_pidfd' or fault in ('missing_owner', 'invalid_owner', 'pidfd_unavailable', 'binding_mismatch'):
        return []
    if fault == 'pidfd_open_failure':
        return [{'kind': 'pidfd_open_failed', 'pid': pid}]
    if fault and fault.startswith('nonlinux'):
        keys = {'nonlinux_success': ['lstart=', 'uid=', 'lstart=', 'uid='],
                'nonlinux_ps_failure': ['lstart='],
                'nonlinux_revalidate_identity': ['lstart=', 'uid=', 'lstart='],
                'nonlinux_revalidate_uid': ['lstart=', 'uid=', 'lstart=', 'uid=']}[fault]
        counts, result = {'lstart=': 0, 'uid=': 0}, []
        for key in keys:
            counts[key] += 1
            result.append({'kind': 'ps', 'argv': ['ps', '-p', str(pid), '-o', key], 'call': counts[key]})
        if fault == 'nonlinux_success':
            result.append({'kind': 'os_kill', 'pid': pid, 'signal': 15, 'mock': True})
        return result
    need(len(opened) == 1, 'missing tracked pidfd for diagnostic event oracle')
    fd = opened[0]
    result = [{'kind': 'pidfd_open', 'pid': pid, 'fd': fd}]
    if mode == 'mock':
        result.append({'kind': 'proc_identity'})
        if fault != 'identity_mismatch':
            result.append({'kind': 'proc_uid'})
    if fault is None or fault == 'pidfd_signal_failure':
        result.append({'kind': 'pidfd_send_signal', 'fd': fd, 'signal': 15,
                       'returned': fault != 'pidfd_signal_failure', 'mock': mode == 'mock'})
    result.append({'kind': 'pidfd_close', 'fd': fd})
    return result


def diagnostic_check(row, spec, pid):
    phase, variant = row['phase'], row['variant']
    metadata = row['metadata']
    if phase == 'benchmark':
        need(metadata is None, 'diagnostics included in timed native benchmark')
        return
    need(isinstance(metadata, dict) and set(metadata) == {'mode', 'events', 'opened', 'closed', 'still_open',
         'ps_counts', 'subprocess_loaded', 'initial_subprocess_loaded'}, 'diagnostic shape')
    _, scene, mode, fault = spec
    nonlinux = bool(fault and fault.startswith('nonlinux'))
    should_open = (scene == 'cancel_linux_owned_pidfd' and not nonlinux and fault not in
                   ('missing_owner', 'invalid_owner', 'pidfd_unavailable', 'pidfd_open_failure', 'binding_mismatch'))
    need(metadata['mode'] == mode and metadata['initial_subprocess_loaded'] is False, 'diagnostic mode/initial import differs')
    loaded = nonlinux or (variant == 'A' and scene != 'read_control' and phase != 'environment-boundary')
    need(metadata['subprocess_loaded'] is loaded, 'subprocess import mechanism differs')
    need(metadata['opened'] == metadata['closed'] and metadata['still_open'] == []
         and len(metadata['opened']) == int(should_open)
         and all(type(fd) is int and fd >= 0 for fd in metadata['opened']), 'pidfd lifetime/closedness differs')
    expected = expected_events(spec, pid, metadata['opened'])
    need(metadata['events'] == expected, 'exact diagnostic signal/revalidation event ordering differs at row ' + str(row['sequence']))
    counts = {key: sum(event['kind'] == 'ps' and event['argv'][4] == key for event in expected) for key in ('lstart=', 'uid=')}
    need(metadata['ps_counts'] == counts, 'ps count derivation differs')


def usage_pair(before, after):
    need(set(before) == set(after) == set(USAGE), 'RUSAGE fields differ')
    for key in USAGE:
        need(all(type(obj[key]) in (int, float) and math.isfinite(obj[key]) and obj[key] >= 0 for obj in (before, after))
             and after[key] >= before[key], 'RUSAGE counter invalid or decreases: ' + key)
    return after['ru_utime'] + after['ru_stime'] - before['ru_utime'] - before['ru_stime']


def guard_check(guard, pid, uid, argv):
    need(set(guard) == {'pid', 'uid', 'identity', 'cmdline_sha256', 'direct_popen_child'}
         and guard['pid'] == pid and guard['uid'] == uid and guard['direct_popen_child'] is True,
         'owned direct child guard binding differs')
    identity = guard['identity']
    need(set(identity) == {'kind', 'value'} and identity['kind'] == 'proc_start_ticks'
         and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}:[1-9][0-9]*', identity['value']),
         'Linux boot/start identity is malformed')
    need(guard['cmdline_sha256'] == sha(b'\0'.join(arg.encode() for arg in argv) + b'\0'),
         'actual child argv hash differs from reconstructed command')
    return (pid, identity['value'])


def audit(args, report):
    files, checks = Inputs(), report['checks']
    root = args.root.absolute()
    package = root.parent
    need(root.resolve() == root and root.is_dir(), 'evidence root is not canonical directory')
    need(not args.output.absolute().is_relative_to(package), 'audit output overlaps archived evidence')
    bindings = {'baseline': (args.baseline, A_SHA), 'candidate': (args.candidate, B_SHA),
                'probe': (args.probe, PROBE_SHA), 'plan': (args.plan, PLAN_SHA)}
    raw_inputs = {name: files.read(path, pin) for name, (path, pin) in bindings.items()}
    need(all(path.absolute().parent == package for path, _ in bindings.values()), 'four frozen inputs must be package siblings of probe root')
    report['inputs'] = {name: files.binding(path) for name, (path, _) in bindings.items()}
    constants = {v: extract(raw_inputs[n]) for v, n in [('A', 'baseline'), ('B', 'candidate')]}
    need(all(constants['A'][key] == constants['B'][key] for key in CONSTANTS if key != 'CANCEL_CODE'), 'non-CANCEL constant changed')
    need(ast.dump(RemoveImports().visit(ast.parse(constants['A']['CANCEL_CODE']))) ==
         ast.dump(RemoveImports().visit(ast.parse(constants['B']['CANCEL_CODE']))), 'non-import CANCEL AST changed')
    templates, plan = producer_literals(raw_inputs['probe']), decode(raw_inputs['plan'])
    need(plan['schema'] == 'hepta-r20-cancel-mechanism-plan/v1' and plan['screen'] == LIMITS
         and plan['calls_per_cell'] == 16 and plan['order'] == 'ABBA' and plan['scenes'] == list(SCENES)
         and plan['semantic_cases'] == [s[0] for s in SPECS] and plan['maximum_full_run_helper_processes'] == 228
         and plan['maximum_full_run_owned_targets'] == 66, 'fixed plan differs')
    need(files.read(root / 'plan.frozen.json') == raw_inputs['plan'], 'frozen plan differs from explicit input')
    checks['source_tool_plan_pins_and_six_constant_scope'] = True

    docs = {}
    for name, pin, schema in [('semantics', args.expected_semantics_sha256, 'hepta-r20-cancel-mechanism-semantics/v1'),
                              ('abba', args.expected_abba_sha256, 'hepta-r20-cancel-mechanism-abba/v1'),
                              ('screen', args.expected_screen_sha256, 'hepta-r20-cancel-mechanism-screen/v1')]:
        raw = files.read(root / (name + '.json'), pin)
        doc = decode(raw)
        need(doc['schema'] == schema and encode(doc) == raw, 'original report schema/bytes')
        docs[name] = doc
    sem, bench, screen = docs['semantics'], docs['abba'], docs['screen']
    common = {'baseline_source_sha256': A_SHA, 'candidate_source_sha256': B_SHA,
              'probe_tool_sha256': PROBE_SHA, 'plan_sha256': PLAN_SHA, 'mode': 'full',
              'source_stable': True, 'remote_calls': 0, 'automatic_retries': 0, 'existing_services_changed': False,
              'actual_helper_records': 228, 'actual_owned_target_records': 66,
              'actual_fresh_helper_processes': 228, 'real_targets_created': 66, 'error': None}
    for doc in docs.values():
        need(all(doc.get(key) == value for key, value in common.items()), 'report full-mode/identity/count/lifecycle differs')
        need(doc['python'] == sem['python'] and doc['driver_python_version'] == sem['driver_python_version']
             and doc['driver_uname'] == sem['driver_uname'] and sem['driver_uname'][0] == 'Linux', 'runtime/platform binding differs')
    need(sem['passed'] is True and sem['complete_required_coverage'] is True
         and bench['completed'] is True and bench['benchmark_performed'] is True
         and bench['order'] == 'ABBA' and bench['calls_per_cell'] == 16 and bench['timing_scope'] == plan['timing_scope']
         and screen['assessed'] is True and screen['adoption_assessed'] is False and screen['limits'] == LIMITS,
         'closed protocol completion/interpretation differs')
    origin = PurePosixPath(sem['raw_processes']['path']).parent
    need(origin.is_absolute() and '..' not in origin.parts and origin.as_posix() == str(origin), 'original root path invalid')
    expected_files = {'semantics.json', 'abba.json', 'screen.json', 'raw-processes.jsonl', 'plan.frozen.json', 'progress.json'}

    def artifact(rel, record):
        rel = safe_relative(rel).as_posix()
        raw = files.read(root / rel)
        need(record == {'path': str(origin / rel), 'bytes': len(raw), 'sha256': sha(raw)}, 'artifact path/size/hash: ' + rel)
        expected_files.add(rel)
        return raw

    raw_rows = files.read(root / 'raw-processes.jsonl')
    for doc in docs.values():
        artifact('raw-processes.jsonl', doc['raw_processes'])
    lines = raw_rows.splitlines()
    need(raw_rows.endswith(b'\n') and len(lines) == 228, 'full raw-row denominator differs')
    rows = [decode(line) for line in lines]
    need(all(line == encode(row).replace(b'\n', b'') for row, line in zip(rows, lines)), 'raw JSONL encoding differs')
    progress_raw = files.read(root / 'progress.json'); progress = decode(progress_raw)
    need(progress['current_stage'] == 'completed' and progress['helper_records'] == 228 and progress['owned_target_records'] == 66
         and progress['screen_assessed'] is True and progress['screen_passed'] is screen['passed']
         and progress_raw == encode(progress), 'terminal progress differs')
    report['source_report_bindings'] = {name: files.binding(root / name)
                                      for name in ('semantics.json', 'abba.json', 'screen.json', 'raw-processes.jsonl', 'progress.json')}
    checks['closed_reports_and_full_228_helper_66_target_denominators'] = True

    uid = rows[0]['helper_guard']['uid']
    need(type(uid) is int and uid >= 0, 'remote owner UID invalid')
    identities, target_sequences, target_artifacts = set(), [], []
    native_scripts, script_records, publications = set(), {}, []
    target_deltas, helper_deltas, row_summaries = [], [], []
    previous_end, previous_usage = None, None
    for index, (row, (phase, spec, variant, rnd, call)) in enumerate(zip(rows, expected_order())):
        name, scene, mode, fault = spec
        need((row['sequence'], row['phase'], row['case'], row['scene'], row['variant'], row['round'], row['call']) ==
             (index, phase, name, scene, variant, rnd, call), 'row classification/order differs at ' + str(index))
        need(row['branch_mock'] is (mode == 'mock') and row['correct'] is True and 'validation_error' not in row,
             'row mock/correctness classification differs')
        need(row['fresh_interpreter'] is True and row['reaped'] is True and row['timed_out'] is False
             and row['automatic_retry'] is False and row['ownership_error'] is None
             and row['query_sent_after_helper_identity_confirmed'] is True
             and type(row['pid']) is int and row['pid'] > 1 and type(row['returncode']) is int,
             'helper owned lifecycle failure at row ' + str(index))
        target = row['target']
        need((target is not None) is (scene == 'cancel_linux_owned_pidfd' and mode == 'native'), 'target scope/classification differs')
        job, owner, query, before_files = fixture_inputs(origin, spec, phase, index, variant, uid, target)
        need(row['input_json'] == query and row['input_sha256'] == sha(json.dumps(query, sort_keys=True).encode()), 'query content/hash differs')
        script_rel = 'scripts/' + name + '-' + variant + ('-blocked' if phase == 'environment-boundary' else '') + '-' + phase + '.py'
        source = artifact(script_rel, row['script'])
        need(source == saved_script(constants[variant], spec, phase, owner['supervisor_pid'], uid, templates), 'saved script reconstruction differs: ' + script_rel)
        script_records[script_rel] = {'bytes': len(source), 'sha256': sha(source)}
        need(row['argv_shape'] == [sem['python'], '-B', '-c', {'script_file': str(origin / script_rel), 'sha256': sha(source)}], 'helper argv shape differs')
        identity = guard_check(row['helper_guard'], row['pid'], uid, [sem['python'], '-B', '-c', source.decode()])
        need(identity not in identities, 'helper/target owned PID+start identity reused'); identities.add(identity)
        if phase == 'benchmark':
            need(source == production(constants[variant], scene).encode() and MARKER.encode() not in source
                 and row['native_exact_production_script'] is True, 'timed benchmark is not exact uninstrumented production')
            native_scripts.add(script_rel)
        streams = {stream: artifact('processes/' + str(index).zfill(5) + '.' + stream, row[stream]) for stream in ('stdout', 'stderr')}
        derived = parse_streams(streams['stdout'], streams['stderr'])
        need(all(row[key] == value for key, value in derived.items()), 'stream-derived JSON/metadata/error differs')
        semantic_check(row, spec, streams, owner['supervisor_pid'], phase)
        diagnostic_check(row, spec, owner['supervisor_pid'])
        if phase == 'benchmark':
            need(streams['stderr'] == b'', 'native benchmark stderr not empty')

        fixture = row['fixture']; job_rel = job.relative_to(origin)
        need(fixture['path'] == str(job) and fixture['preexisting_unchanged'] is True, 'fixture path/unchanged flag differs')
        before = {filename: {'bytes': len(raw), 'mode': 0o600, 'sha256': sha(raw)} for filename, raw in before_files.items()}
        after = dict(before)
        for filename, raw in before_files.items():
            rel = (job_rel / filename).as_posix()
            need(files.read(root / rel) == raw, 'fixture preexisting bytes differ: ' + rel); expected_files.add(rel)
        published = fixture['published']
        need((published is not None) is expected_publication(spec), 'cancel publication ordering/outcome differs')
        if published is not None:
            need(set(published) == {'at_unix_ms', 'job_id', 'launch_nonce'} and type(published['at_unix_ms']) is int
                 and published['at_unix_ms'] > 0 and published['job_id'] == name and published['launch_nonce'] == 'e' * 32,
                 'cancel publication binding differs')
            raw = (json.dumps(published, sort_keys=True) + '\n').encode()
            rel = (job_rel / 'cancel-request.json').as_posix()
            need(files.read(root / rel) == raw, 'published cancel request bytes differ'); expected_files.add(rel)
            after['cancel-request.json'] = {'bytes': len(raw), 'mode': 0o600, 'sha256': sha(raw)}
            publications.append(index)
        need(fixture['before'] == before and fixture['after'] == after, 'fixture snapshots differ from rebuilt bytes')

        before_usage, after_usage, clock = row['rusage_children_before'], row['rusage_children_after'], row['clock']
        cpu = usage_pair(before_usage, after_usage)
        need(set(clock) == {'start_monotonic_ns', 'spawned_monotonic_ns', 'end_monotonic_ns', 'start_realtime_ns', 'end_realtime_ns'}
             and all(type(value) is int and value > 0 for value in clock.values())
             and clock['start_monotonic_ns'] <= clock['spawned_monotonic_ns'] <= clock['end_monotonic_ns'], 'helper clock shape/order differs')
        wall = (clock['end_monotonic_ns'] - clock['start_monotonic_ns']) / 1e9
        need(cpu >= 0 and wall > 0 and row['child_cpu_seconds'] == cpu and row['wall_seconds'] == wall, 'helper CPU/wall arithmetic differs')
        if previous_usage is not None:
            need(before_usage == previous_usage and clock['start_monotonic_ns'] >= previous_end, 'cross-row counter/clock continuity differs')
        helper_deltas.append(cpu)
        last_end = clock['end_monotonic_ns']
        if target is not None:
            target_sequences.append(index)
            target_rel = 'targets/' + str(index).zfill(5) + '.json'
            target_raw = files.read(root / target_rel)
            need(target_raw == encode(target) and decode(target_raw) == target, 'target sidecar/nested row mismatch')
            expected_files.add(target_rel)
            target_artifacts.append({'path': str(origin / target_rel), 'bytes': len(target_raw), 'sha256': sha(target_raw)})
            ready = target['ready']
            need(set(ready) == {'pid', 'uid', 'nonce', 'identity'} and ready['pid'] == target['pid']
                 and ready['uid'] == uid and ready['identity'] == target['guard']['identity']
                 and re.fullmatch(r'[0-9a-f]{32}', ready['nonce']) and target['pid'] != row['pid'], 'target readiness/owner binding differs')
            target_identity = guard_check(target['guard'], target['pid'], uid,
                                          [sem['python'], '-B', '-u', '-c', templates['TARGET_CODE'], ready['nonce']])
            need(target_identity not in identities, 'target/helper PID+start identity reused'); identities.add(target_identity)
            need(target['setup_failure'] is False and target['not_reaped_before_helper_after_rusage'] is True
                 and target['rusage_after_helper_matches_before_reap'] is True and target['cleanup_error'] is None
                 and target['returncode'] == -15 and target['reaped'] is True and target['cleanup_signal'] is None,
                 'target identity/signal/reap/scope/cleanup differs')
            clocks = [target[key] for key in ('setup_start_monotonic_ns', 'setup_end_monotonic_ns',
                                             'cleanup_start_monotonic_ns', 'cleanup_end_monotonic_ns')]
            need(all(type(value) is int and value > 0 for value in clocks)
                 and clocks[0] <= clocks[1] <= clock['start_monotonic_ns'] <= clock['end_monotonic_ns'] <= clocks[2] <= clocks[3],
                 'target setup/helper/cleanup temporal ordering differs')
            if previous_end is not None:
                need(clocks[0] >= previous_end, 'target setup overlaps previous helper/cleanup')
            need(target['rusage_before_reap'] == after_usage, 'target was reaped before helper after-sample')
            target_cpu = usage_pair(target['rusage_before_reap'], target['rusage_after_reap'])
            need(target['target_cpu_seconds_excluded_from_helper'] == target_cpu
                 and row['rusage_after_cleanup'] == target['rusage_after_reap'], 'target excluded CPU arithmetic/chain differs')
            target_deltas.append(target_cpu)
            target_stdout = artifact('targets/' + str(index).zfill(5) + '.stdout', target['stdout'])
            target_stderr = artifact('targets/' + str(index).zfill(5) + '.stderr', target['stderr'])
            need(target_stdout == (json.dumps(ready, sort_keys=True) + '\n').encode() and target_stderr == b'', 'target readiness/exit streams differ')
            last_end = clocks[3]
        else:
            need(row['rusage_after_cleanup'] == after_usage, 'non-target cleanup adds child accounting')
        previous_usage, previous_end = row['rusage_after_cleanup'], last_end
        row_summaries.append({'sequence': index, 'phase': phase, 'scene': scene, 'variant': variant,
                              'helper_cpu_seconds': cpu, 'helper_wall_seconds': wall,
                              'target_cpu_seconds_excluded': target_deltas[-1] if target is not None else None,
                              'returncode': row['returncode'], 'correct': True})

    need(target_sequences == [2, 3] + list(range(100, 164)) and len(target_deltas) == 66
         and len(script_records) == 42 and len(native_scripts) == 6, 'target/script denominator or sequence differs')
    need(production(constants['A'], 'read_control') == production(constants['B'], 'read_control'), 'READ control differs')
    for doc in docs.values():
        need(doc['target_metadata_files'] == target_artifacts, 'target manifest ordering/hash differs')
    total_cpu = usage_pair(rows[0]['rusage_children_before'], rows[-1]['rusage_after_cleanup'])
    helper_cpu, target_cpu = math.fsum(helper_deltas), math.fsum(target_deltas)
    need(math.isclose(helper_cpu + target_cpu, total_cpu, rel_tol=1e-12, abs_tol=1e-10), 'helper plus excluded target CPU does not reconcile with cumulative total')
    checks.update(all_228_fresh_owned_helpers_reaped_without_timeout_or_retry=True,
                  all_42_scripts_reconstructed_and_192_native_benchmarks_without_diagnostics=True,
                  exact_stdout_stderr_metadata_and_response_derivations=True,
                  all_fixture_inputs_unchanged_and_publication_outcomes_bound=True,
                  exact_mock_signal_pidfd_close_and_ps_revalidation_order=True,
                  all_66_targets_bound_to_pid_uid_boot_start_nonce_and_argv=True,
                  all_66_target_sigterm_exits_reaped_after_helper_sampling_without_cleanup_signals=True,
                  helper_target_rusage_chains_and_monotonic_scope_reconciled=True)

    cases = []
    for index, spec in enumerate(SPECS):
        def normalized(row):
            response = row['response']
            if row['target'] is not None and response is not None and 'supervisor_pid' in response:
                response = dict(response, supervisor_pid='<verified-owned-child>')
            return row['returncode'], response, row['exception_tail']
        need(normalized(rows[2 * index]) == normalized(rows[2 * index + 1]), 'A/B semantic difference: ' + spec[0])
        cases.append({'name': spec[0], 'scene': spec[1], 'mode': spec[2], 'passed': True,
                      'baseline_sequence': 2 * index, 'candidate_sequence': 2 * index + 1,
                      'normalization': 'Only the individually verified owned target PID differs between native success runs.'})
    need(sem['cases'] == cases and sem['environment_boundary'] == {
        'documented': True, 'intentionally_different': True, 'baseline_sequence': 34, 'candidate_sequence': 35,
        'meaning': plan['interpretation']['environment_boundary']}, 'semantic/boundary aggregate differs')
    checks['seventeen_semantic_pairs_and_separate_blocked_import_boundary'] = True

    cells, summaries = [], {}
    for scene in SCENES:
        group = []
        for rnd, variant in enumerate('ABBA'):
            chosen = [row for row in rows if row['phase'] == 'benchmark' and row['scene'] == scene and row['round'] == rnd]
            need(len(chosen) == 16 and all(row['variant'] == variant for row in chosen), 'cell denominator/order differs')
            cell = {'scene': scene, 'round': rnd, 'variant': variant, 'calls': 16, 'sequences': [row['sequence'] for row in chosen],
                    'helper_cpu_seconds': math.fsum(row['child_cpu_seconds'] for row in chosen),
                    'helper_wall_seconds': math.fsum(row['wall_seconds'] for row in chosen),
                    'helper_cpu_ms_per_call': 1000 * statistics.mean(row['child_cpu_seconds'] for row in chosen),
                    'helper_wall_ms_per_call': 1000 * statistics.mean(row['wall_seconds'] for row in chosen)}
            cells.append(cell); group.append(cell)
        arms = {}
        for variant in 'AB':
            selected = [cell for cell in group if cell['variant'] == variant]
            arm = {'calls': 32, 'helper_cpu_seconds': math.fsum(cell['helper_cpu_seconds'] for cell in selected),
                   'helper_wall_seconds': math.fsum(cell['helper_wall_seconds'] for cell in selected)}
            arm.update(helper_cpu_ms_per_call=1000 * arm['helper_cpu_seconds'] / 32,
                       helper_wall_ms_per_call=1000 * arm['helper_wall_seconds'] / 32)
            arms[variant] = arm
        summaries[scene] = {'arms': arms,
            'aggregate_B_over_A_cpu': arms['B']['helper_cpu_seconds'] / arms['A']['helper_cpu_seconds'],
            'aggregate_B_over_A_wall': arms['B']['helper_wall_seconds'] / arms['A']['helper_wall_seconds'],
            'pair_B_over_A_cpu': [group[b]['helper_cpu_ms_per_call'] / group[a]['helper_cpu_ms_per_call'] for a, b in [(0, 1), (3, 2)]],
            'pair_B_over_A_wall': [group[b]['helper_wall_ms_per_call'] / group[a]['helper_wall_ms_per_call'] for a, b in [(0, 1), (3, 2)]]}
    need(bench['cells'] == cells and bench['summaries'] == summaries, 'original/recomputed cells/arms/ratios differ')
    decisions = {}
    for scene in SCENES[:2]:
        decisions[scene + '_aggregate_cpu_at_most_0_95'] = summaries[scene]['aggregate_B_over_A_cpu'] <= 0.95
        for index, ratio in enumerate(summaries[scene]['pair_B_over_A_cpu']):
            decisions[scene + '_pair_' + str(index + 1) + '_cpu_at_most_1_00'] = ratio <= 1.0
    decisions.update(unchanged_read_aggregate_cpu_at_most_1_10=summaries['read_control']['aggregate_B_over_A_cpu'] <= 1.1,
                     all_semantics_and_measurement_correctness=True,
                     all_owned_targets_unreaped_until_after_helper_sample=True, complete_fixed_matrix=True)
    need(screen['checks'] == decisions and screen['passed'] is all(decisions.values()), 'fixed screen recomputation differs')
    checks['all_twelve_cells_six_arms_six_cpu_pairs_six_wall_pairs_equal_original'] = True
    checks['fixed_screen_exactly_recomputed_separately_from_audit_pass'] = True

    actual_files = file_set(root)
    need(actual_files == expected_files, 'closed probe file set differs: ' + repr(sorted(actual_files ^ expected_files)))
    manifest_raw = files.read(args.manifest, args.expected_manifest_sha256)
    manifest = decode(manifest_raw)
    need(manifest['schema'] == 'hepta-r20-cancel-export/v1' and manifest['expected_report_sha256'] == {
        'semantics.json': args.expected_semantics_sha256, 'abba.json': args.expected_abba_sha256,
        'screen.json': args.expected_screen_sha256}, 'export manifest schema/report pins differ')
    need(files.read(package / '_export-manifest.json') == manifest_raw,
         'embedded manifest differs from the explicitly pinned original manifest bytes')
    manifest_rows = {}
    for record in manifest['files']:
        rel = safe_relative(record['path']).as_posix()
        need(rel not in manifest_rows and set(record) == {'path', 'original_path', 'size', 'sha256', 'mode'}, 'manifest duplicate/shape differs')
        manifest_rows[rel] = record
    packaged = {root.name + '/' + rel for rel in expected_files} | {path.name for path, _ in bindings.values()}
    need(set(manifest_rows) == packaged and file_set(package) == packaged | {'_export-manifest.json'},
         'exact external manifest/package set differs')
    for rel, record in manifest_rows.items():
        raw = files.read(package / rel)
        need(record['size'] == len(raw) and record['sha256'] == sha(raw) and record['mode'] == 0o600,
             'external manifest byte/size/hash/private-mode differs: ' + rel)
        original = PurePosixPath(record['original_path'])
        need(original.is_absolute() and '..' not in original.parts, 'manifest original path invalid')
        if rel.startswith(root.name + '/'):
            need(str(original) == str(origin / rel[len(root.name) + 1:]), 'manifest original probe path differs')
    checks['complete_external_manifest_and_exact_file_set_all_bytes_sizes_hashes_modes'] = True
    files.stable(); checks['all_audited_inputs_stable'] = True
    report.update(passed=True, original_root=str(origin), source_sha256={'baseline': A_SHA, 'candidate': B_SHA},
        manifest=files.binding(args.manifest), original_screen_passed=screen['passed'], recomputed_screen_checks=decisions,
        counts={'helper_processes': 228, 'semantic_cases': 17, 'semantic_helpers': 34, 'native_semantic_helpers': 6,
                'mock_semantic_helpers': 28, 'blocked_import_boundary_helpers': 2, 'measured_native_helpers': 192,
                'measured_native_cancel_helpers': 128, 'measured_identical_read_helpers': 64,
                'owned_target_processes': 66, 'semantic_targets': 2, 'measured_targets': 64,
                'cells': 12, 'calls_per_cell': 16, 'calls_per_scene_arm': 32, 'script_files': 42,
                'helper_stream_files': 456, 'target_sidecars_and_stream_files': 198,
                'probe_files': len(expected_files), 'packaged_files': len(packaged),
                'embedded_manifest_files': 1, 'archive_members': len(packaged) + 1,
                'distinct_owned_pid_start_identities': len(identities), 'cancel_publications': len(publications)},
        semantic_cases=cases, target_sequences=target_sequences, publication_sequences=publications,
        cells=cells, native_summaries=summaries, row_derivations=row_summaries,
        cpu_scope={'helper_cpu_seconds_all_228': helper_cpu, 'excluded_target_cpu_seconds_all_66': target_cpu,
                   'cumulative_children_cpu_seconds': total_cpu, 'reconciliation_abs_error': abs(helper_cpu + target_cpu - total_cpu),
                   'continuity': 'Every next helper before-sample equals the previous after-cleanup sample; every target before-reap equals its helper after-sample.',
                   'limits': 'Offline verification binds records and exact frozen program bytes. It does not perform an independent live /proc observation.'},
        memory={'scope': 'Cumulative Linux RUSAGE_CHILDREN ru_maxrss across reaped helpers and targets; neither per-helper RSS nor traced allocation.',
                'first_before_kib': rows[0]['rusage_children_before']['ru_maxrss'],
                'last_after_cleanup_kib': rows[-1]['rusage_after_cleanup']['ru_maxrss'],
                'maximum_observed_kib': max(row['rusage_after_cleanup']['ru_maxrss'] for row in rows),
                'memory_adoption_assessed': False},
        interpretation={'control': 'READ source and timed scripts are byte-identical. READ movement is control variation, not an optimization gain.',
                        'attribution': 'Native CANCEL ratios include candidate effects and process/run variation; do not attribute the entire measured difference to lazy import.',
                        'mock': 'All 28 mock helpers are branch semantics only. No mock record enters performance statistics.',
                        'environment_boundary': plan['interpretation']['environment_boundary'],
                        'scope': 'A component CPU mechanism screen, not runtime adoption, SSH throughput, multi-host capacity or memory improvement.'},
        verified_probe_files={rel: {'bytes': len(files.read(root / rel)), 'sha256': sha(files.read(root / rel))} for rel in sorted(expected_files)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'baseline', 'candidate', 'probe', 'plan', 'manifest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('manifest', 'semantics', 'abba', 'screen'):
        parser.add_argument('--expected-' + name + '-sha256', required=True)
    args = parser.parse_args()
    need(not os.path.lexists(args.output), 'output must be fresh; prior failures are never overwritten')
    report = {'schema': 'hepta-r20-cancelprocess-offline-audit/v1', 'passed': False, 'checks': {},
              'audit_tool_sha256': sha(Path(__file__).read_bytes()), 'probe_tool_sha256': PROBE_SHA,
              'workloads_started': False, 'remote_calls': 0, 'executed_producer_or_saved_scripts': False}
    try:
        audit(args, report)
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with args.output.open('xb') as stream:
        stream.write(encode(report))
    print(json.dumps({'passed': report['passed'], 'original_screen_passed': report.get('original_screen_passed'),
                      'output': str(args.output.absolute()), 'sha256': sha(args.output.read_bytes()),
                      'checks': len(report['checks']), 'error': report.get('error')}, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
