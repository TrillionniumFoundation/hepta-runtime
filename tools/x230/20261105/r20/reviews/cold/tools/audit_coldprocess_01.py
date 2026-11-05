#!/usr/bin/env python3
"""Read-only, independent reconstruction of a closed R20 coldprocess probe.

Never imports/executes the producer, saved scripts, or production source. The two
mock/blocked-import literal templates are read as data from the SHA-pinned tool;
all fixtures, production bodies, ordering, timing and statistics are rebuilt here.
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

BASELINE_SHA = 'c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9'
CANDIDATE_SHA = '2f751c09a9a29bebb0cda0a9bd2bb522d145ee8183740ed1442d77666ee44aa7'
PROBE_SHA = '8ccb6bd17032792be189a87386dabaefe4fdd2251b582834734c717a9e63b79a'
CONSTANTS = ('PRIVATE_DIRECTORY_CODE', 'BOUND_OBSERVATION_CODE', 'START_CODE', 'STATUS_CODE', 'READ_CODE', 'CANCEL_CODE')
SCENES = ('status_completed', 'read_completed', 'detached_live', 'systemd_mock', 'nonlinux_ps_mock')
SPECS = [(s, s, None) for s in SCENES] + [
    ('binding_mismatch', 'status_completed', 'binding_mismatch'),
    ('corrupt_launch', 'status_completed', 'corrupt_launch'),
    ('corrupt_exit', 'status_completed', 'corrupt_exit'),
    ('bad_witness', 'status_completed', 'bad_witness'),
    ('missing_witness', 'status_completed', 'missing_witness'),
    ('missing_owner', 'detached_live', 'missing_owner'),
    ('unsafe_owner', 'detached_live', 'unsafe_owner'),
    ('malformed_owner', 'detached_live', 'malformed_owner'),
    ('systemd_wrong_invocation', 'systemd_mock', 'systemd_wrong_invocation'),
    ('nonlinux_systemd_uid_error', 'systemd_mock', 'nonlinux_systemd_uid_error')]
USAGE = ('ru_utime', 'ru_stime', 'ru_maxrss', 'ru_ixrss', 'ru_idrss', 'ru_isrss', 'ru_minflt',
         'ru_majflt', 'ru_nswap', 'ru_inblock', 'ru_oublock', 'ru_msgsnd', 'ru_msgrcv',
         'ru_nsignals', 'ru_nvcsw', 'ru_nivcsw')
MARKER = 'R20_PROBE_METADATA '


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON: ' + value)))


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def stamp(path):
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode), 'not a regular input file: ' + str(path))
    return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


class Inputs:
    def __init__(self):
        self.files = {}

    def read(self, path, expected=None):
        path = Path(path).absolute()
        need(path.resolve() == path, 'symlink or noncanonical input: ' + str(path))
        if path not in self.files:
            before = stamp(path)
            data = path.read_bytes()
            need(before == stamp(path) and len(data) == before[3], 'input changed during read: ' + str(path))
            self.files[path] = (before, data)
        data = self.files[path][1]
        if expected is not None:
            need(sha(data) == expected, 'input SHA256 mismatch: ' + str(path))
        return data

    def binding(self, path):
        data = self.read(path)
        return {'path': str(Path(path).absolute()), 'bytes': len(data), 'sha256': sha(data)}

    def stable(self):
        return all(stamp(p) == before and p.read_bytes() == data for p, (before, data) in self.files.items())


def extract(raw):
    text = raw.decode()
    result = {}
    for name in CONSTANTS:
        matches = re.findall(r'const ' + name + r': &str = r#"(.*?)"#;', text, re.S)
        need(len(matches) == 1, 'source constant not unique: ' + name)
        ast.parse(matches[0])
        result[name] = matches[0]
    return result


class RemoveImports(ast.NodeTransformer):
    def visit_Import(self, node):
        return None

    def visit_ImportFrom(self, node):
        return None


def production(constants, scene):
    return ('REMOTE_DIRECTORY_SOURCE = ' + json.dumps(constants['PRIVATE_DIRECTORY_CODE'], ensure_ascii=False)
            + '\nexec(REMOTE_DIRECTORY_SOURCE)\n' + constants['BOUND_OBSERVATION_CODE'] + '\n'
            + constants['READ_CODE' if scene == 'read_completed' else 'STATUS_CODE'])


def saved_script(constants, spec, phase, owner, templates):
    name, scene, fault = spec
    diagnostic = phase != 'benchmark'
    nonlinux = scene == 'nonlinux_ps_mock' or fault == 'nonlinux_systemd_uid_error'
    systemd = scene == 'systemd_mock'
    prefix = 'import sys\n_r20_initial_modules = set(sys.modules)\n_r20_mock_calls = []\n_r20_extra = {}\n' if diagnostic else ''
    if systemd or nonlinux:
        if not diagnostic:
            prefix = 'import sys\n_r20_mock_calls = []\n'
        settings = {'pid': owner['supervisor_pid'], 'nonlinux': nonlinux, 'systemd': systemd,
                    'invocation': 'f' * 32, 'ps_value': 'Wed Nov  4 12:34:56 2026', 'fault': fault}
        settings.update(uid=owner['supervisor_uid'], unit='hepta-r20-probe-' + name, job_id=name, nonce='e' * 32)
        prefix += 'import subprocess as _r20_subprocess\n_r20_settings = ' + repr(settings) + '\n' + templates['mock']
    if phase == 'environment-boundary':
        prefix += templates['blocked']
    footer = '\n' if diagnostic else ''
    if diagnostic and scene == 'nonlinux_ps_mock':
        footer += '_r20_extra["process_uid_helper"] = process_uid(' + str(owner['supervisor_pid']) + ')\n'
    if diagnostic:
        footer += ('print(' + repr(MARKER) + ' + json.dumps({"subprocess_loaded": "subprocess" in sys.modules, '
                   '"initial_subprocess_loaded": "subprocess" in _r20_initial_modules, '
                   '"new_modules": sorted(set(sys.modules) - _r20_initial_modules), '
                   '"mock_calls": _r20_mock_calls, "extra": _r20_extra}, sort_keys=True), file=sys.stderr)\n')
    return (prefix + production(constants, scene) + footer).encode()


def expected_query(origin, spec):
    name, _, fault = spec
    return {'job_id': name, 'job_dir': str(origin / 'fixtures' / name / 'state' / 'jobs' / name),
            'unit': 'hepta-r20-probe-' + name, 'request_digest': ('b' if fault == 'binding_mismatch' else 'd') * 64,
            'wait_seconds': 0, 'stdout_offset': 0, 'stderr_offset': 0, 'limit': 16384}


def fixture_bytes(origin, spec, owner):
    name, scene, fault = spec
    query = expected_query(origin, spec)
    request = {**query, 'request_digest': 'd' * 64, 'launch_nonce': 'e' * 32, 'terminal_publication_protocol': 1}
    started = {**owner, 'job_id': name}
    if scene == 'nonlinux_ps_mock' or fault == 'nonlinux_systemd_uid_error':
        started['supervisor_identity'] = {'kind': 'ps_lstart', 'value': 'Wed Nov  4 12:34:56 2026'}
    documents = {'request.json': request, 'launch.json': {'backend': 'systemd' if scene == 'systemd_mock' else 'detached'},
                 'started.json': started}
    if scene in SCENES[:2]:
        terminal = {'job_id': name, 'launch_nonce': 'e' * 32, 'terminal_publication_protocol': 1,
                    'exit_code': 0, 'output_complete': True, 'output_durable': True, 'timed_out': False, 'cancelled': False}
        documents['exit.json'] = terminal
        documents['exit.witness.json'] = {'job_id': name, 'launch_nonce': 'e' * 32,
            'terminal_publication_protocol': 1, 'exit_sha256': '0' * 64 if fault == 'bad_witness' else sha(encode(terminal))}
    if fault == 'missing_witness':
        del documents['exit.witness.json']
    if fault == 'missing_owner':
        del documents['started.json']
    result = {k: encode(v) for k, v in documents.items()}
    for target, reason in [('launch.json', 'corrupt_launch'), ('exit.json', 'corrupt_exit'), ('started.json', 'malformed_owner')]:
        if fault == reason:
            result[target] = b'{'
    result.update({'stdout.log': b'R20 read-only output\n', 'stderr.log': b''})
    return result


def expected_response(spec, row):
    name, scene, fault = spec
    failures = {'binding_mismatch': 'remote job request binding missing or mismatched',
                'corrupt_launch': 'corrupt remote job file launch.json', 'corrupt_exit': 'corrupt remote job file exit.json',
                'unsafe_owner': 'ValueError: unsafe terminal publication file'}
    if fault in failures:
        return row['returncode'] != 0 and row['response'] is None and row['exception_tail'] == failures[fault]
    if row['returncode'] != 0 or not isinstance(row['response'], dict):
        return False
    response = row['response']
    if scene == 'read_completed':
        return (response['job_id'] == name and response['stdout']['bytes_hex'] == b'R20 read-only output\n'.hex()
                and response['stdout']['eof'] is True and response['stderr']['bytes_hex'] == '')
    state = 'succeeded' if scene == 'status_completed' else 'running'
    if fault in ('bad_witness', 'missing_witness'):
        state = 'finalizing'
    if fault in ('missing_owner', 'malformed_owner', 'systemd_wrong_invocation', 'nonlinux_systemd_uid_error'):
        state = 'owner_unknown'
    return response.get('state') == state and response.get('job_id') == name


def audit(args, report):
    files = Inputs()
    root = args.cold_dir.absolute()
    need(root.resolve() == root and root.is_dir(), 'cold directory must be canonical and complete')
    need(not args.output.absolute().is_relative_to(root), 'audit output must not alter cold input directory')
    sem = decode(files.read(root / 'semantics.json', args.expected_semantics_sha256))
    bench = decode(files.read(root / 'cold-abba.json', args.expected_benchmark_sha256))
    constants = {v: extract(files.read(p, expected)) for v, p, expected in
                 [('A', args.baseline, BASELINE_SHA), ('B', args.candidate, CANDIDATE_SHA)]}
    probe_tree = ast.parse(files.read(args.probe_tool, PROBE_SHA))
    literals = [n.value for n in ast.walk(probe_tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    templates = {}
    for key, prefix in [('mock', 'def _r20_check_output(argv,'), ('blocked', 'import builtins as _r20_builtins\n')]:
        values = [v for v in literals if v.startswith(prefix)]
        need(len(values) == 1, 'producer literal not unique: ' + key)
        templates[key] = values[0]
    checks = report['checks']
    need(all(constants['A'][k] == constants['B'][k] for k in CONSTANTS if k != 'STATUS_CODE'), 'nonstatus source change')
    need(ast.dump(RemoveImports().visit(ast.parse(constants['A']['STATUS_CODE']))) ==
         ast.dump(RemoveImports().visit(ast.parse(constants['B']['STATUS_CODE']))), 'nonimport status source change')
    checks['source_and_tool_identity_and_only_status_import_change'] = True
    need(sem['schema'] == 'hepta-r20-coldprocess-semantics/v1' and bench['schema'] == 'hepta-r20-coldprocess-abba/v1', 'report schema')
    for obj in (sem, bench):
        need(obj['passed'] is True and obj['source_stable'] is True and obj['baseline_source_sha256'] == BASELINE_SHA
             and obj['candidate_source_sha256'] == CANDIDATE_SHA and obj['probe_tool_sha256'] == PROBE_SHA
             and obj['scenes'] == list(SCENES) and obj['automatic_retries'] == 0 and obj['remote_calls'] == 0
             and obj['workloads_started'] is False, 'producer identity/success fields')
    need(sem['python'] == bench['python'] and bench['order'] == 'ABBA' and bench['calls_per_cell'] == args.calls_per_cell, 'protocol differs')
    need(all(v is True for v in sem['checks'].values()) and set(sem['checks']) == {
        'all_nonstatus_constants_identical', 'status_nonimport_ast_identical', 'all_differential_cases_passed',
        'unused_module_environment_boundary_documented', 'fixtures_unchanged', 'sources_and_tool_unchanged'}, 'producer checks')
    raw = files.read(root / 'raw-processes.jsonl')
    need(raw.endswith(b'\n'), 'truncated raw JSONL')
    rows = [decode(line) for line in raw.splitlines()]
    origin = PurePosixPath(sem['raw_processes']['path']).parent
    need(origin.is_absolute() and '..' not in origin.parts, 'invalid original root')
    raw_binding = {'path': str(origin / 'raw-processes.jsonl'), 'bytes': len(raw), 'sha256': sha(raw)}
    need(sem['raw_processes'] == bench['raw_processes'] == raw_binding, 'raw binding differs')
    expected_order = [('semantics', spec, v, None, None) for spec in SPECS for v in 'AB']
    expected_order += [('environment-boundary', SPECS[0], v, None, None) for v in 'AB']
    expected_order += [('benchmark', (s, s, None), v, rnd, call)
                       for s in SCENES for rnd, v in enumerate('ABBA') for call in range(args.calls_per_cell)]
    need(len(rows) == len(expected_order) == sem['fresh_process_count'] == bench['fresh_process_count'], 'process denominator')
    checks['exact_phase_order_and_denominators'] = True
    expected_files = {'semantics.json', 'cold-abba.json', 'raw-processes.jsonl'}
    owner = decode(files.read(root / 'fixtures/status_completed/state/jobs/status_completed/started.json'))
    need(set(owner) == {'job_id', 'launch_nonce', 'supervisor_uid', 'supervisor_pid', 'supervisor_identity', 'invocation_id'}
         and owner['job_id'] == 'status_completed' and owner['launch_nonce'] == 'e' * 32 and owner['invocation_id'] == 'f' * 32,
         'fixture owner schema')
    need(type(owner['supervisor_pid']) is int and owner['supervisor_pid'] > 0
         and type(owner['supervisor_uid']) is int and owner['supervisor_uid'] >= 0, 'fixture PID/UID')
    need(owner['supervisor_identity']['kind'] == 'proc_start_ticks', 'Linux owner identity')
    for spec in SPECS:
        folder = Path('fixtures') / spec[0] / 'state' / 'jobs' / spec[0]
        for name, data in fixture_bytes(origin, spec, owner).items():
            rel = (folder / name).as_posix(); expected_files.add(rel)
            need(files.read(root / rel) == data, 'fixture bytes differ: ' + rel)
    checks['every_fixture_rebuilt_from_fixed_contract'] = True
    native_scripts = set()
    script_records = {}
    for index, (row, (phase, spec, variant, rnd, call)) in enumerate(zip(rows, expected_order)):
        need((row['sequence'], row['phase'], row['case'], row['scene'], row['variant'], row['round'], row['call']) ==
             (index, phase, spec[0], spec[1], variant, rnd, call), 'row classification/order at ' + str(index))
        need(row['fresh_interpreter'] is True and row['reaped'] is True and row['timed_out'] is False
             and row['automatic_retry'] is False and type(row['returncode']) is int
             and type(row['pid']) is int and row['pid'] > 0, 'process lifecycle at ' + str(index))
        query = expected_query(origin, spec)
        need(row['input_json'] == query and row['input_sha256'] == sha(json.dumps(query, sort_keys=True).encode()), 'query bytes')
        rel = 'scripts/' + spec[0] + '-' + variant + ('-blocked' if phase == 'environment-boundary' else '') + '-' + phase + '.py'
        expected_files.add(rel)
        source = files.read(root / rel)
        need(source == saved_script(constants[variant], spec, phase, owner, templates), 'saved script differs: ' + rel)
        need(row['argv_shape'] == [sem['python'], '-B', '-c', {'script_file': str(origin / rel), 'sha256': sha(source)}], 'argv/script hash')
        script_records[rel] = {'bytes': len(source), 'sha256': sha(source)}
        if phase == 'benchmark' and spec[1] in SCENES[:3]:
            need(source == production(constants[variant], spec[1]).encode() and MARKER.encode() not in source,
                 'native benchmark has instrumentation')
            native_scripts.add(rel)
        streams = {}
        for stream in ('stdout', 'stderr'):
            rel_stream = 'processes/' + str(index).zfill(5) + '.' + stream
            expected_files.add(rel_stream)
            data = files.read(root / rel_stream); streams[stream] = data
            need(row[stream] == {'path': str(origin / rel_stream), 'bytes': len(data), 'sha256': sha(data)}, 'stream byte/hash binding')
        metadata, app_lines = None, []
        for line in streams['stderr'].decode('utf-8', errors='replace').splitlines():
            if line.startswith(MARKER):
                need(metadata is None, 'duplicate metadata')
                metadata = decode(line[len(MARKER):])
            else:
                app_lines.append(line)
        try:
            response = decode(streams['stdout'])
        except (ValueError, UnicodeError):
            response = None
        need((row['response'], row['metadata'], row['application_stderr_lines'], row['exception_tail']) ==
             (response, metadata, app_lines, app_lines[-1] if app_lines else None), 'raw response/error derivation')
        if phase == 'benchmark':
            need(metadata is None and not streams['stderr'] and expected_response(spec, row), 'benchmark output/correctness')
        before, after, clock = row['rusage_children_before'], row['rusage_children_after'], row['clock']
        need(set(before) == set(after) == set(USAGE), 'RUSAGE fields')
        for key in USAGE:
            need(all(type(obj[key]) in (int, float) and math.isfinite(obj[key]) and obj[key] >= 0 for obj in (before, after))
                 and after[key] >= before[key], 'RUSAGE counter validity')
        need(set(clock) == {'start_monotonic_ns', 'spawned_monotonic_ns', 'end_monotonic_ns', 'start_realtime_ns', 'end_realtime_ns'}
             and all(type(v) is int and v > 0 for v in clock.values()), 'clock fields')
        need(clock['start_monotonic_ns'] <= clock['spawned_monotonic_ns'] <= clock['end_monotonic_ns'], 'monotonic interval')
        cpu = after['ru_utime'] + after['ru_stime'] - before['ru_utime'] - before['ru_stime']
        wall = (clock['end_monotonic_ns'] - clock['start_monotonic_ns']) / 1e9
        need(cpu >= 0 and wall > 0 and row['child_cpu_seconds'] == cpu and row['wall_seconds'] == wall, 'CPU/wall arithmetic')
        if index:
            need(before == rows[index - 1]['rusage_children_after'] and
                 clock['start_monotonic_ns'] >= rows[index - 1]['clock']['end_monotonic_ns'], 'cross-row counter/clock continuity')
    need(len(native_scripts) == 6 and len(script_records) == 42, 'script coverage')
    checks.update(all_scripts_rebuilt_and_hashed=True, native_benchmarks_exact_production_without_diagnostics=True,
                  stdout_stderr_and_derived_fields_exact=True, every_process_reaped_without_retry_or_timeout=True,
                  rusage_and_monotonic_arithmetic_exact=True, cumulative_counters_contiguous=True)
    cases = []
    for idx, spec in enumerate(SPECS):
        a, b = rows[2 * idx:2 * idx + 2]
        same = (a['returncode'], a['response'], a['exception_tail']) == (b['returncode'], b['response'], b['exception_tail'])
        need(same and expected_response(spec, a) and expected_response(spec, b), 'semantic equivalence: ' + spec[0])
        if spec[2] is None:
            for r in (a, b):
                m = r['metadata']; need(isinstance(m, dict) and m['initial_subprocess_loaded'] is False, 'semantic metadata')
                need(m['new_modules'] == sorted(set(m['new_modules'])) and
                     m['subprocess_loaded'] == ('subprocess' in m['new_modules']), 'module inventory consistency')
            if spec[1] in ('status_completed', 'detached_live'):
                need(a['metadata']['subprocess_loaded'] is True and b['metadata']['subprocess_loaded'] is False, 'lazy import absent')
            elif spec[1] == 'read_completed':
                need(a['metadata']['subprocess_loaded'] is b['metadata']['subprocess_loaded'] is False, 'read control import')
            elif spec[1] == 'systemd_mock':
                need(all(len(r['metadata']['mock_calls']) == 1 for r in (a, b)), 'systemd mock coverage')
            elif spec[1] == 'nonlinux_ps_mock':
                need(all(len(r['metadata']['mock_calls']) == 2 and r['metadata']['extra']['process_uid_helper'] == owner['supervisor_uid']
                         for r in (a, b)), 'nonlinux mock coverage')
        cases.append({'name': spec[0], 'scene': spec[1], 'fault': spec[2], 'passed': True,
                      'baseline_sequence': 2 * idx, 'candidate_sequence': 2 * idx + 1, 'equivalent_exit_response_error_tail': True})
    need(sem['cases'] == cases and sem['semantic_cases'] == {'total': 15, 'passed': 15, 'failed': 0, 'names': [s[0] for s in SPECS]}, 'semantic aggregate')
    need(rows[30]['returncode'] != 0 and rows[30]['exception_tail'] == 'ImportError: R20 deliberate unavailable subprocess'
         and expected_response(SPECS[0], rows[31]), 'documented unavailable-module boundary')
    need(sem['environment_boundary'] == {
        'assumption': 'Supported Python has intact standard-library modules. A missing or deliberately blocked unused subprocess import no longer fails completed status.',
        'intentionally_different': True, 'verified_as_documented': True, 'baseline_sequence': 30, 'candidate_sequence': 31}, 'boundary report')
    checks['fifteen_semantic_cases_and_separate_environment_boundary_exact'] = True
    cells, summaries, extra_pairs = [], {}, {}
    for scene in SCENES:
        group = []
        for rnd, variant in enumerate('ABBA'):
            chosen = [r for r in rows if r['phase'] == 'benchmark' and r['scene'] == scene and r['round'] == rnd]
            need(len(chosen) == args.calls_per_cell, 'cell denominator')
            cell = {'scene': scene, 'variant': variant, 'round': rnd, 'calls': len(chosen), 'sequences': [r['sequence'] for r in chosen],
                    'child_cpu_seconds': math.fsum(r['child_cpu_seconds'] for r in chosen),
                    'wall_seconds': math.fsum(r['wall_seconds'] for r in chosen),
                    'child_cpu_ms_per_call': 1000 * statistics.mean(r['child_cpu_seconds'] for r in chosen),
                    'wall_ms_per_call': 1000 * statistics.mean(r['wall_seconds'] for r in chosen),
                    'native_linux_path': scene in SCENES[:3], 'mock_diagnostic_only': scene in SCENES[3:]}
            cells.append(cell); group.append(cell)
        arms = {}
        for variant in 'AB':
            chosen = [c for c in group if c['variant'] == variant]
            arm = {'calls': sum(c['calls'] for c in chosen), 'child_cpu_seconds': math.fsum(c['child_cpu_seconds'] for c in chosen),
                   'wall_seconds': math.fsum(c['wall_seconds'] for c in chosen)}
            arm.update(child_cpu_ms_per_call=1000 * arm['child_cpu_seconds'] / arm['calls'], wall_ms_per_call=1000 * arm['wall_seconds'] / arm['calls'])
            arms[variant] = arm
        summaries[scene] = {'arms': arms, 'aggregate_B_over_A_cpu': arms['B']['child_cpu_ms_per_call'] / arms['A']['child_cpu_ms_per_call'],
            'aggregate_B_over_A_wall': arms['B']['wall_ms_per_call'] / arms['A']['wall_ms_per_call'],
            'pair_B_over_A_cpu': [group[b]['child_cpu_ms_per_call'] / group[a]['child_cpu_ms_per_call'] for a, b in [(0, 1), (3, 2)]],
            'mock_diagnostic_only': scene in SCENES[3:]}
        extra_pairs[scene] = {'pair_B_over_A_wall': [group[b]['wall_ms_per_call'] / group[a]['wall_ms_per_call'] for a, b in [(0, 1), (3, 2)]],
            'pair_rounds': [{'baseline': a, 'candidate': b} for a, b in [(0, 1), (3, 2)]]}
    need(bench['cells'] == cells and bench['summaries'] == summaries, 'original/recomputed cell, arm or pair statistics differ')
    checks['all_twenty_cells_ten_arms_and_ten_cpu_pairs_equal_original'] = True
    actual_files = set()
    for p in root.rglob('*'):
        need(not p.is_symlink(), 'link in cold archive')
        if p.is_file():
            actual_files.add(p.relative_to(root).as_posix())
        else:
            need(p.is_dir(), 'special file in cold archive')
    need(actual_files == expected_files, 'cold file set differs: ' + repr(sorted(actual_files ^ expected_files)))
    checks['exact_complete_file_set_and_all_file_hashes'] = True
    need(files.stable(), 'input changed during audit')
    checks['all_inputs_stable'] = True
    checks['mock_and_native_results_kept_separate'] = True
    report.update(passed=True, original_root=str(origin), source_sha256={'baseline': BASELINE_SHA, 'candidate': CANDIDATE_SHA},
        source_report_bindings={name: files.binding(root / name) for name in ('semantics.json', 'cold-abba.json', 'raw-processes.jsonl')},
        counts={'fresh_processes': len(rows), 'semantic_cases': 15, 'semantic_processes': 30, 'environment_boundary_processes': 2,
                'measured_processes': 20 * args.calls_per_cell, 'native_measured_processes': 12 * args.calls_per_cell,
                'mock_diagnostic_processes': 8 * args.calls_per_cell, 'calls_per_cell': args.calls_per_cell,
                'calls_per_scene_arm': 2 * args.calls_per_cell, 'cells': 20, 'script_files': 42,
                'stream_files': 2 * len(rows), 'cold_files': len(expected_files), 'distinct_recorded_child_pids': len({r['pid'] for r in rows})},
        native_summaries={s: {**summaries[s], **extra_pairs[s]} for s in SCENES[:3]},
        mock_diagnostics={s: {**summaries[s], **extra_pairs[s]} for s in SCENES[3:]},
        module_inventory_differences={s: {'baseline_only': sorted(set(rows[2 * i]['metadata']['new_modules']) - set(rows[2 * i + 1]['metadata']['new_modules'])),
                                          'candidate_only': sorted(set(rows[2 * i + 1]['metadata']['new_modules']) - set(rows[2 * i]['metadata']['new_modules']))}
                                      for i, s in enumerate(SCENES[:3])},
        memory={'scope': 'Cumulative RUSAGE_CHILDREN ru_maxrss observation; neither per-child RSS nor traced allocation.',
                'first_before': rows[0]['rusage_children_before']['ru_maxrss'],
                'last_after': rows[-1]['rusage_children_after']['ru_maxrss'],
                'maximum_observed': max(r['rusage_children_after']['ru_maxrss'] for r in rows), 'linux_unit': 'KiB'},
        interpretation={'control': 'READ source/scripts are byte-identical between arms; its observed ratio is control variation, not an optimization gain.',
                        'attribution': 'STATUS changes include both the candidate effect and uncontrolled process/run variation. Do not attribute the entire observed ratio to lazy import.',
                        'mock': 'Systemd and non-Linux mocks provide branch diagnostics only, not real service or OS performance.',
                        'scope': 'Fresh interpreter component measurements exclude SSH, runtime throughput, concurrency and application end-to-end claims.'},
        verified_cold_files={rel: {'bytes': len(files.read(root / rel)), 'sha256': sha(files.read(root / rel))} for rel in sorted(expected_files)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cold-dir', 'baseline', 'candidate', 'probe-tool', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-semantics-sha256', required=True)
    parser.add_argument('--expected-benchmark-sha256', required=True)
    parser.add_argument('--calls-per-cell', type=int, choices=(1, 16), default=16)
    args = parser.parse_args()
    need(not os.path.lexists(args.output), 'output must be fresh')
    report = {'schema': 'hepta-r20-coldprocess-offline-audit/v1', 'passed': False, 'checks': {},
              'audit_tool_sha256': sha(Path(__file__).read_bytes()), 'probe_tool_sha256': PROBE_SHA,
              'workloads_started': False, 'remote_calls': 0, 'executed_producer_or_saved_scripts': False}
    try:
        audit(args, report)
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with args.output.open('xb') as stream:
        stream.write(encode(report))
    print(json.dumps({'passed': report['passed'], 'output': str(args.output.absolute()),
                      'sha256': sha(args.output.read_bytes()), 'checks': len(report['checks']), 'error': report.get('error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
