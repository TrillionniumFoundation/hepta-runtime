#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One explicitly composed A42 release completion; never rerun the five prior stages."""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import types

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
SOURCE = BASE / 'source-a42-fresh-cohort-r03'
OUT = BASE / 'qualification-a42-release-completion-r02'
PREP = BASE / 'a42-release-completion-entry-r02'
ENTRY = BASE / 'tools/complete_a42_release_r02.py'
OLD_OUT = BASE / 'qualification-a42-fresh-cohort-r03'
OLD_PREP = BASE / 'a42-qualification-entry-r03'
CORE = BASE / 'tools/prepare_qualify_a42_fresh_cohort_r03.py'
CORE_SHA = '3667eef725327df895ce26d4c898d19cabc4774146577ca08726cd2d4602d5a0'
OBSERVER = BASE / 'tools/observe_release_window_a44_r01.py'
OBSERVER_SHA = '8f63b89004a5bc51ee920bab99dcd7da6bd89d3e072dec8e45df2aa4f83ef88f'
PROTOCOL = BASE / 'tools/a44-a42-release-completion-protocol-r01.json'
PROTOCOL_SHA = 'fec0268cc2563a32baa75c7466b1d528356269f2048d2f573c544b133a19a9f9'
NATIVE = BASE / 'tools/run_a41_native_validation_r07.py'
NATIVE_SHA = '6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9'
WINDOW = BASE / 'a44-release-window-r01/report.json'
FINAL_BINDINGS_READY = True
WINDOW_SHA = 'e9071a2ad570c11a11252111e984ea8f436f981df52b94209d1b894588bad396'
WINDOW_BYTES = 7611
SNAPSHOT_SHA = 'd47b08231fc69f5f833fa9be8ff92012a71e624da58d2f4eab8ca7d48a7a2306'
SNAPSHOT_BYTES = 58793
SOURCE_MAP_SHA = 'c1ae8a69901aee16e03871e920a6a7e321672c9b30b3a6e75d3560390b8c2e11'
PREFORMAT_MAP_SHA = '02edd61645f84ae6cbe3dd3d8977fe85b1c66a2ba813fb0a80a7c026a0a5ef86'
RELEASE_ARGV = ['/home/qian/.cargo/bin/cargo', '+1.95.0', 'build', '--offline', '--locked',
                '--all-features', '--release', '--bins', '--message-format=json-render-diagnostics']
RELEASE_SECONDS = 1800
WORKER_SECONDS = 1900
OUTER_SECONDS = 2100
MEM_MIN_KIB = 2097152
DISK_MIN_BYTES = 2147483648
BUSY_NAMES = ('cargo', 'cargo-clippy', 'clippy-driver', 'rustc', 'heptabao_server')
OLD_NAMES = ('format', 'fmt-check', 'clean-package', 'clippy', 'test')
FIXED = {
    'qualification_r03': (OLD_OUT / 'report.json', 40283, 'b7374df702c477f394b5f3ba2ed94337daa23f8dde54fb38370df6b2d5172b6d'),
    'worker_r03': (OLD_PREP / 'worker-report.json', 7701, '27324028a7e49f165e3862f77df7a8c061414628a3b7355fa49ea423ee3d2cb9'),
    'guardian_r03': (OLD_PREP / 'entry-report.json', 284896, 'fcda21f276b6858341a80347c9e537423100195c1b4672a39e8f50153d72949f'),
    'terminal_r03': (BASE / 'tools/qualification-r03-terminal-status.raw.json', 474, '74819c91616c19885dd3671ac68f8fa55db7709b1701f08ae9eb48b478946816'),
    'r03_entry_script': (CORE, 57997, CORE_SHA),
    'release_completion_protocol': (PROTOCOL, 6129, PROTOCOL_SHA),
    'host_load_driver': (NATIVE, 51497, NATIVE_SHA),
    'observer': (OBSERVER, 22723, OBSERVER_SHA),
    'previous_no_clear_window': (BASE / 'a43-release-window-r01/report.json', 53711, '98f85fd00baa4335349c8d54fec1b74537a4e0249a6b21eee37773a922872329'),
}


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute direct directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def bootstrap_bytes(path, expected, size):
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == size,
                 'fixed helper type or length differs')
            blocks, count = [], 0
            while count <= size:
                raw = os.read(fd, min(65536, size + 1 - count))
                if not raw:
                    break
                blocks.append(raw)
                count += len(raw)
            raw = b''.join(blocks)
            need(count == size and sha(raw) == expected and stamp(before) == stamp(os.fstat(fd))
                 == stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                 'fixed helper bytes or identity changed')
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def loaded(name, path, raw):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def support():
    # Loading definitions never calls either historical main/worker/observer.
    core = loaded('a42_release_original_custody', CORE, bootstrap_bytes(CORE, CORE_SHA, 57997))
    observer = loaded('a42_release_original_proof', OBSERVER,
                      bootstrap_bytes(OBSERVER, OBSERVER_SHA, 22723))
    core.PREP, core.OUT, core.DEST = PREP, OUT, SOURCE
    core.WORKER_SECONDS, core.OUTER_OPERATOR_SECONDS = WORKER_SECONDS, OUTER_SECONDS
    need(core.TERM_SECONDS == core.KILL_SECONDS == 30, 'original cleanup budgets differ')
    return core, observer


def receipt_only(value):
    return {key: value[key] for key in ('path', 'bytes', 'sha256', 'identity')}


def same_proof(value):
    return {key: item for key, item in value.items() if key != 'observed_utc'}


def deduplicated(values):
    result = {}
    for value in values:
        value = receipt_only(value)
        prior = result.get(value['path'])
        need(prior is None or prior == value, 'conflicting original receipt: ' + value['path'])
        result[value['path']] = value
    return [result[path] for path in sorted(result)]


def verify_protocol(value):
    need(value.get('schema') == 'hepta-a44-a42-release-completion-protocol/v1'
         and value.get('maximum_new_release_attempts_after_clear') == 1
         and value.get('window_seconds') == 600 and value.get('interval_seconds') == 30
         and value.get('source') == str(SOURCE) and value.get('source_files') == 168
         and value.get('tested_source_map_compact_sha256') == SOURCE_MAP_SHA
         and value.get('preformat_source_map_compact_sha256') == PREFORMAT_MAP_SHA
         and value.get('completion_output') == str(OUT)
         and value.get('completion_entry_output') == str(PREP)
         and value.get('observer_out') == str(WINDOW.parent)
         and value.get('release_argv') == RELEASE_ARGV
         and value.get('release_budget_seconds') == RELEASE_SECONDS
         and value.get('completion_worker_budget_seconds') == WORKER_SECONDS
         and value.get('completion_outer_budget_seconds') == OUTER_SECONDS
         and value.get('cleanup_term_kill_seconds') == [30, 30]
         and value.get('previous_successful_stages') == list(OLD_NAMES)
         and value.get('original_r03_remains_failed') is True
         and value.get('original_release_executions') == 0
         and value.get('no_clean_format_or_test_reexecution') is True
         and value.get('fresh_release_artifact_required') is True
         and value.get('reuse_if_fresh_true_forbidden') is True
         and value.get('mem_available_kib_min') == MEM_MIN_KIB
         and value.get('disk_available_bytes_min') == DISK_MIN_BYTES
         and value.get('busy_process_names') == list(BUSY_NAMES)
         and value.get('originals_immutable') is True
         and value.get('automatic_cargo_launch') is False
         and value.get('automatic_benchmark_launch') is False
         and value.get('automatic_retries') is False
         and value.get('scheduling_tranche') == 'a44-new-user-continuation-r01'
         and value.get('previous_window_not_reused_for_admission') is True
         and value.get('previous_failed_tranche_unchanged') is True
         and value.get('previous_no_clear_window', {}).get('path')
             == str(BASE / 'a43-release-window-r01/report.json')
         and value['previous_no_clear_window'].get('sha256')
             == '98f85fd00baa4335349c8d54fec1b74537a4e0249a6b21eee37773a922872329'
         and value['previous_no_clear_window'].get('bytes') == 53711,
         'fresh release-only protocol differs')


def verify_snapshot(value):
    snapshot = value.get('snapshot', {})
    need(value.get('schema') == 'hepta-a44-release-window-snapshot/v1'
         and snapshot.get('required_fields_present') is True and snapshot.get('errors') == []
         and type(snapshot.get('processes')) is list,
         'resource snapshot is incomplete')
    busy = [row for row in snapshot['processes']
            if row['comm'] in BUSY_NAMES and row['state'] not in ('Z', 'X', 'x')]
    memory = re.findall(r'^MemAvailable:\s+(\d+)\s+kB\s*$', snapshot['meminfo'], flags=re.MULTILINE)
    need(len(memory) == 1 and type(value.get('mem_available_kib')) is int
         and value['mem_available_kib'] == int(memory[0])
         and value.get('matching_live_processes') == busy,
         'snapshot resource projection differs')
    need(value.get('clear') is True and value.get('within_window') is True
         and not busy and value.get('resource_errors') == []
         and value['mem_available_kib'] >= MEM_MIN_KIB
         and type(value.get('disk_available_bytes')) is int
         and value['disk_available_bytes'] >= DISK_MIN_BYTES
         and value.get('resource_thresholds') == {
             'mem_available_kib_min': MEM_MIN_KIB, 'disk_available_bytes_min': DISK_MIN_BYTES},
         'first clear snapshot did not meet the fixed resource gate')
    elapsed = value.get('observed_seconds_since_start')
    need(type(elapsed) in (float, int) and math.isfinite(elapsed) and 0 <= elapsed < 600,
         'clear snapshot is outside the original window')


def verify_inputs(core, observer):
    need(FINAL_BINDINGS_READY is True, 'release-completion bindings are disabled')
    for digest, size in ((WINDOW_SHA, WINDOW_BYTES), (SNAPSHOT_SHA, SNAPSHOT_BYTES)):
        need(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)
             and type(size) is int and 0 < size <= 1024 * 1024, 'missing actual clear-window pin')
    originals, receipts = {}, {}
    for key, (path, size, digest) in FIXED.items():
        raw, receipt = core.original(path, digest)
        need(len(raw) == size, 'fixed continuation original length differs: ' + key)
        originals[key], receipts[key] = raw, receipt
    verify_protocol(json.loads(originals['release_completion_protocol']))
    previous = json.loads(originals['previous_no_clear_window'])
    need(previous.get('schema') == 'hepta-a43-release-window-observation/v1'
         and previous.get('status') == 'no_clear_observed'
         and previous.get('passed') is False and previous.get('clear_observed') is False
         and previous.get('snapshot_calls') == 40 and previous.get('window_seconds') == 1200
         and previous.get('interval_seconds') == 30 and previous.get('originals_unchanged') is True
         and previous.get('errors') == [], 'retained previous failed scheduling window differs')
    q = json.loads(originals['qualification_r03'])
    worker = json.loads(originals['worker_r03'])
    guardian = json.loads(originals['guardian_r03'])
    need(core.map_sha(q['source_input']) == PREFORMAT_MAP_SHA and len(q['source_input']) == 168,
         'original preformat source map differs')
    need(guardian['qualification_report'] == receipts['qualification_r03']
         and guardian['guarded_worker_report'] == receipts['worker_r03']
         and guardian['entry'] == receipts['r03_entry_script'], 'original guardian references differ')
    for index, (name, tail) in enumerate(core.STAGES):
        row = worker['stages'][index]
        need(row['name'] == name and row['argv'] == [core.CARGO, '+1.95.0'] + tail
             and row['timeout_seconds'] == RELEASE_SECONDS, 'original guarded stage argv/budget differs')
        if index < 5:
            need(q['stages'][index]['command'] == row['argv'], 'original qualification command differs')
        gate = row['host_gate']
        need(Path(gate['path']) == OLD_PREP / ('stage-%d-%s.host-gate.json' % (index, name)),
             'original host gate path differs')
        raw, current = core.original(Path(gate['path']), gate['sha256'])
        need(current == gate, 'original stage gate changed')
        value = json.loads(raw)
        need(value.get('clear') is (index < 5), 'original stage gate outcome differs')
        originals['r03_gate_' + name], receipts['r03_gate_' + name] = raw, current
    raw, receipt = core.original(WINDOW, WINDOW_SHA)
    need(len(raw) == WINDOW_BYTES, 'actual window report length differs')
    window = json.loads(raw)
    need(window.get('schema') == 'hepta-a44-release-window-observation/v1'
         and window.get('status') == 'clear_observed' and window.get('passed') is True
         and window.get('clear_observed') is True and window.get('originals_unchanged') is True
         and window.get('errors') == [] and window.get('window_seconds') == 600
         and window.get('interval_seconds') == 30 and window.get('helper_invocations') == 1
         and window.get('automatic_cargo_launch') is False
         and window.get('automatic_native_query') is False
         and window.get('quiet_host_continuously_proved') is False
         and window.get('scheduling_tranche') == 'a44-new-user-continuation-r01'
         and window.get('previous_failed_tranche_unchanged') is True
         and window.get('previous_window_not_reused_for_admission') is True
         and all(window.get(key) == 0 for key in ('agent_requests', 'foreign_signals',
                 'foreign_priority_changes', 'automatic_retries')),
         'new resource window is not a successful read-only terminal observation')
    need(window.get('bindings') == {key: receipts[key] for key in FIXED},
         'resource window did not bind these exact original inputs')
    originals['window_report'], receipts['window_report'] = raw, receipt
    rows, calls = window.get('observations'), window.get('snapshot_calls')
    need(type(rows) is list and type(calls) is int and 1 <= calls <= 20 and len(rows) == calls
         and [row['index'] for row in rows] == list(range(calls))
         and rows[-1]['clear'] is True and all(row['clear'] is False for row in rows[:-1])
         and rows[-1]['receipt'] == window.get('successful_snapshot'),
         'window must end at its first clear snapshot')
    for row in rows:
        expected = row['receipt']
        path = WINDOW.parent / ('snapshot-%02d.json' % row['index'])
        need(expected['path'] == str(path), 'window snapshot path differs')
        data, current = core.original(path, expected['sha256'])
        need(current == expected, 'window snapshot original changed')
        value = json.loads(data)
        need(value['index'] == row['index'] and value['clear'] is row['clear']
             and value['observed_seconds_since_start'] == row['elapsed_seconds']
             and value['mem_available_kib'] == row['mem_available_kib']
             and value['disk_available_bytes'] == row['disk_available_bytes']
             and value['matching_live_processes'] == row['matching_live_processes'],
             'window snapshot/report projection differs')
        key = 'window_snapshot_%02d' % row['index']
        originals[key], receipts[key] = data, current
        if row is rows[-1]:
            need(len(data) == SNAPSHOT_BYTES and current['sha256'] == SNAPSHOT_SHA,
                 'actual first-clear snapshot pin differs')
            verify_snapshot(value)
            receipts['window_snapshot'] = current
    observed_proofs = []
    for key, filename in (('tested_source_proof', 'tested-source-current-proof.json'),
                          ('tested_source_proof_after', 'tested-source-current-proof-after.json')):
        expected = window[key]
        need(expected['path'] == str(WINDOW.parent / filename), 'window source proof path differs')
        data, current = core.original(Path(expected['path']), expected['sha256'])
        need(current == expected, 'window source proof changed')
        observed_proofs.append(json.loads(data))
        originals[key], receipts[key] = data, current
    proof = observer.tested_source_proof(originals)
    need(all(same_proof(value) == same_proof(proof) for value in observed_proofs),
         'current tested source or artifact differs from the successful new observation')
    need(proof['source_map'] == q['source_tested'] and proof['source_files'] == 168
         and proof['source_map_sha256_compact'] == SOURCE_MAP_SHA,
         'current formatted source is not the originally tested source')
    for name, expected in proof['logs'].items():
        raw, current = core.original(Path(expected['path']), expected['sha256'])
        need(current == expected, 'old log changed during source proof')
        originals['r03_log_' + name], receipts['r03_log_' + name] = raw, current
    expected = proof['original_empty_release_log']
    raw, current = core.original(Path(expected['path']), expected['sha256'])
    need(current == expected and raw == b'', 'old refused release log changed')
    originals['r03_log_release'], receipts['r03_log_release'] = raw, current
    receipts['old_test_binary'] = receipt_only(proof['original_copied_test_binary'])
    for name in ('qualifier-worker.stdout', 'qualifier-worker.stderr'):
        raw, current = core.original(OLD_PREP / name)
        originals['r03_' + name], receipts['r03_' + name] = raw, current
    entry_raw, entry_receipt = core.original(ENTRY)
    originals['completion_entry'], receipts['completion_entry'] = entry_raw, entry_receipt
    # The helper is source-bound by the parent bootstrap in a worker. The final
    # parent compares this exact script receipt again after completion.
    return {'q': q, 'worker': worker, 'guardian': guardian, 'window': window, 'proof': proof,
            'originals': originals, 'receipts': receipts}


def host_gate(native):
    snapshot = native.host_load()
    busy = [row for row in snapshot['processes']
            if row['comm'] in BUSY_NAMES and row['state'] not in ('Z', 'X', 'x')]
    mem = disk = None
    errors = []
    try:
        memory = re.findall(r'^MemAvailable:\s+(\d+)\s+kB\s*$', snapshot['meminfo'], flags=re.MULTILINE)
        need(len(memory) == 1, 'MemAvailable unavailable or ambiguous')
        mem = int(memory[0])
        filesystem = os.statvfs(BASE)
        disk = filesystem.f_bavail * filesystem.f_frsize
    except (OSError, ValueError, KeyError, IndexError, RuntimeError) as error:
        errors.append(type(error).__name__ + ': ' + str(error))
    return {'clear': bool(snapshot['required_fields_present'] and not snapshot['errors']
                         and not busy and not errors and mem >= MEM_MIN_KIB and disk >= DISK_MIN_BYTES),
            'snapshot': snapshot, 'matching_live_processes': busy,
            'mem_available_kib': mem, 'disk_available_bytes': disk, 'resource_errors': errors,
            'resource_thresholds': {'mem_available_kib_min': MEM_MIN_KIB,
                                    'disk_available_bytes_min': DISK_MIN_BYTES},
            'scope': 'point-in-time admission; no exclusive or continuous host lease'}


def copy_executable(core, observer, source, destination):
    # The shared target may change in a later build. Only the new durable copy
    # enters the stable qualification provenance; this source receipt is history.
    parent = directory(source.parent)
    destination_parent = directory(destination.parent)
    fd = target = None
    try:
        fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        # Cargo may hard-link its release executable to release/deps. Record
        # that real link count and require stable bytes/identity, not nlink=1.
        # The independently created OUT copy remains strictly single-link.
        need(stat.S_ISREG(before.st_mode) and before.st_nlink >= 1
             and 0 < before.st_size <= 512 * 1024 * 1024, 'bounded regular compiled artifact required')
        target = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o700, dir_fd=destination_parent)
        digest, size = hashlib.sha256(), 0
        while True:
            raw = os.read(fd, 65536)
            if not raw:
                break
            size += len(raw)
            need(size <= before.st_size, 'compiled artifact grew during copy')
            digest.update(raw)
            view = memoryview(raw)
            while view:
                wrote = os.write(target, view)
                need(wrote > 0, 'artifact copy made no progress')
                view = view[wrote:]
        need(size == before.st_size and stamp(before) == stamp(os.fstat(fd))
             == stamp(os.stat(source.name, dir_fd=parent, follow_symlinks=False)),
             'compiled artifact changed during copy')
        os.fsync(target)
        os.close(target)
        target = None
        os.fsync(destination_parent)
        receipt = receipt_only(observer.stream_original(destination, digest.hexdigest()))
        need(receipt['bytes'] == size, 'durable executable copy differs')
        return receipt, {'source_target_receipt': {'path': str(source), 'bytes': size,
            'sha256': digest.hexdigest(), 'identity': stamp(before)}, 'copy_receipt': receipt,
            'scope': 'historical stable-descriptor copy only; shared target may be rebuilt later'}
    finally:
        for handle in (fd, target, parent, destination_parent):
            if handle is not None:
                os.close(handle)


def worker(args, core, observer):
    need(args.permit_fd is not None and args.expected_entry_sha is not None, 'new worker permit required')
    try:
        need(os.read(args.permit_fd, 2) == b'G', 'original parent did not authorize this worker')
    finally:
        os.close(args.permit_fd)
    core.original(Path(__file__).absolute(), args.expected_entry_sha)
    need(os.getpgrp() == os.getpid() and os.getsid(0) == os.getpid(), 'new worker session differs')
    inputs = verify_inputs(core, observer)
    need(inputs['receipts']['completion_entry']['sha256'] == args.expected_entry_sha,
         'uploaded completion entry differs from original worker bootstrap')
    env, environment = core.clean_environment()
    need(env == dict(os.environ), 'new worker inherited environment was not cleaned')
    need(environment['fixed_values'] == inputs['worker']['environment']['fixed_values'],
         'new fixed build environment differs from original tested configuration')
    report = {'schema': 'hepta-a42-release-completion-worker/v1', 'started_utc': utc(),
              'passed': False, 'errors': [], 'stages': [], 'source': str(SOURCE),
              'source_unchanged': False, 'originals_unchanged': False,
              'source_identity_before': inputs['proof']['source_receipts'],
              'source_tested': inputs['q']['source_tested'], 'input_receipts': inputs['receipts'],
              'environment': environment,
              'environment_scope': 'Same fixed values and same cleaning helper; no claim of an unavailable old full inherited environment hash.',
              'release_budget_seconds': RELEASE_SECONDS, 'automatic_retry': False,
              'format_clean_test_executions': 0, 'agent_accesses': 0, 'service_changes': False}
    core.checkpoint(PREP / 'worker-report.json', report)
    result = 1
    try:
        native = loaded('a42_release_native_host_load', NATIVE, inputs['originals']['host_load_driver'])
        log_path = OUT / 'release.log'
        log_receipt = core.create(log_path, b'')
        fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(stamp(os.fstat(fd)) == log_receipt['identity'], 'new release log identity changed')
        with os.fdopen(fd, 'ab', buffering=0) as log:
            gate = host_gate(native)
            gate_receipt = core.create(PREP / 'stage-0-release.host-gate.json', core.canonical(gate))
            row = {'name': 'release', 'argv': RELEASE_ARGV, 'timeout_seconds': RELEASE_SECONDS,
                   'executed': False, 'execution_count': 0, 'host_gate': gate_receipt,
                   'gate_clear': gate['clear']}
            report['stages'].append(row)
            core.checkpoint(PREP / 'worker-report.json', report)
            need(gate['clear'], 'new release refused before Cargo: busy/incomplete/resource-floor gate')
            row.update(executed=True, execution_count=1, started_utc=utc())
            core.checkpoint(PREP / 'worker-report.json', report)
            started = time.monotonic()
            try:
                completed = subprocess.run(RELEASE_ARGV, cwd=SOURCE, env=env, stdout=log,
                                           stderr=subprocess.STDOUT, timeout=RELEASE_SECONDS)
                row['returncode'] = completed.returncode
            finally:
                row['seconds'] = time.monotonic() - started
                row['finished_utc'] = utc()
                log.flush()
                os.fsync(log.fileno())
                core.checkpoint(PREP / 'worker-report.json', report)
        log_raw, log_receipt = core.original(log_path)
        row['log'] = log_receipt
        need(row.get('returncode') == 0, 'new release build failed')
        events = []
        for line in log_raw.splitlines():
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if (isinstance(event, dict) and event.get('reason') == 'compiler-artifact'
                    and event.get('target', {}).get('name') == 'hepta-runtime'
                    and event.get('profile', {}).get('test') is False):
                events.append(event)
        need(len(events) == 1 and events[0].get('fresh') is False
             and events[0].get('manifest_path') == str(SOURCE / 'Cargo.toml')
             and events[0]['target'].get('src_path') == str(SOURCE / 'src/main.rs'),
             'new release needs one original fresh=false/source-bound compiler artifact; no clean/retry')
        compiled = Path(events[0]['executable'])
        need(compiled == core.TARGET / 'release/hepta-runtime', 'compiled release path differs')
        copied, observation = copy_executable(core, observer, compiled, OUT / 'hepta-runtime')
        report['binary'] = {**copied, 'cached': False, 'compiler_source': str(SOURCE / 'src/main.rs')}
        report['binary_copy_observation'] = observation
        report['compiler_artifact'] = events[0]
        result = 0
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        try:
            after = verify_inputs(core, observer)
            need(after['receipts'] == inputs['receipts']
                 and same_proof(after['proof']) == same_proof(inputs['proof']),
                 'original stage evidence or original tested source changed during new release')
            report.update(originals_unchanged=True, source_unchanged=True,
                          source_identity_after=after['proof']['source_receipts'],
                          source_after=after['q']['source_tested'])
        except BaseException as error:
            result = 1
            report['errors'].append('final input check: ' + type(error).__name__ + ': ' + str(error))
        if (OUT / 'release.log').exists():
            try:
                _, receipt = core.original(OUT / 'release.log')
                report['release_log'] = receipt
                if report['stages']:
                    report['stages'][0]['log'] = receipt
            except BaseException as error:
                result = 1
                report['errors'].append('release log check: ' + type(error).__name__ + ': ' + str(error))
        report['passed'] = result == 0 and not report['errors']
        report['finished_utc'] = utc()
        core.checkpoint(PREP / 'worker-report.json', report)
    return 0 if report['passed'] else 1


def bootstrap(script_raw, script_receipt):
    worker_path = str(PREP / 'entry.original.py')
    code = ("import os,stat,hashlib,sys\nfrom pathlib import Path\n"
        + "p=Path(" + repr(worker_path) + ")\n"
        + "def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)\n"
        + "d=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)\n"
        + "for part in p.parts[1:-1]:\n c=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d);os.close(d);d=c\n"
        + "f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=d)\n"
        + "try:\n s=os.fstat(f);parts=[];n=0\n"
        + " while n<" + str(len(script_raw) + 1) + ":\n  b=os.read(f," + str(len(script_raw) + 1) + "-n)\n  if not b:break\n  parts.append(b);n+=len(b)\n"
        + " raw=b''.join(parts)\n"
        + " if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or n!=" + str(len(script_raw))
        + " or hashlib.sha256(raw).hexdigest()!=" + repr(script_receipt['sha256'])
        + " or identity(os.fstat(f))!=identity(s) or identity(os.stat(p.name,dir_fd=d,follow_symlinks=False))!=identity(s):raise RuntimeError('new worker script binding differs')\n"
        + "finally:os.close(f);os.close(d)\n"
        + "sys.argv=[str(p),'--worker','--expected-entry-sha'," + repr(script_receipt['sha256']) + "]+sys.argv[1:]\n"
        + "exec(compile(raw,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})\n")
    return [sys.executable, '-B', '-s', '-c', code]


def successful_custody(row):
    return (row.get('executed') is True and row.get('execution_count') == 1
        and row.get('original_child_reaped') is True and row.get('pidfd_opened') is True
        and row.get('actual_waitpid') == row.get('pid') and type(row.get('pid')) is int
        and row['pid'] > 1 and row.get('raw_wait_status') == 0 and row.get('returncode') == 0
        and row.get('custody_known') is True and row.get('custody_retained_until_reap') is True
        and row.get('group_quiet_before_reap') is True and row.get('signals') == []
        and row.get('outer_work_budget_exceeded') is False
        and not row.get('normal_worker_exit_left_live_group_or_observation_errors')
        and not row.get('error') and not row.get('cleanup_errors')
        and row.get('terminal_group_snapshot', {}).get('live') == []
        and row.get('terminal_group_snapshot', {}).get('errors') == [])


def composed(core, inputs, worker_result, worker_receipt, entry_receipt):
    receipts = inputs['receipts']
    prior = {'qualification': receipts['qualification_r03'], 'worker': receipts['worker_r03'],
             'entry': receipts['guardian_r03'], 'qualified': False, 'release_executed': False,
             'host_gates': {name: receipts['r03_gate_' + name] for name in (*OLD_NAMES, 'release')},
             'release_log': receipts['r03_log_release']}
    release_row = worker_result['stages'][0]
    completion = {'worker': worker_receipt, 'entry': entry_receipt,
                  'release_log': release_row['log'], 'host_gate': release_row['host_gate'],
                  'protocol': receipts['release_completion_protocol'],
                  'window_report': receipts['window_report'], 'window_snapshot': receipts['window_snapshot'],
                  'original_entry_helper': receipts['r03_entry_script'],
                  'entry_helper': receipts['completion_entry']}
    stages = [{**row, 'origin': 'r03', 'log': receipts['r03_log_' + row['name']]}
              for row in inputs['q']['stages']]
    stages.append({'name': 'release', 'origin': 'release_completion', 'command': RELEASE_ARGV,
                   'returncode': 0, 'seconds': release_row['seconds'],
                   'log_sha256': release_row['log']['sha256'], 'log': release_row['log']})
    test_binary = {**inputs['q']['test_binary'], **receipts['old_test_binary']}
    stable = list(receipts.values()) + [worker_receipt, entry_receipt, release_row['log'],
              release_row['host_gate'], worker_result['binary']]
    for name in ('qualifier-worker.stdout', 'qualifier-worker.stderr'):
        _, receipt = core.original(PREP / name)
        stable.append(receipt)
    return {'schema': 'hepta-runtime-composed-qualification/v1',
            'composition_kind': 'a42-r03-five-stages-plus-release/v1',
            'qualified': True, 'source': str(SOURCE), 'source_tested': inputs['q']['source_tested'],
            'source_after': worker_result['source_after'],
            'source_identity_before': inputs['proof']['source_receipts'],
            'source_identity_after': worker_result['source_identity_after'],
            'prior_attempt': prior, 'release_completion': completion, 'stages': stages,
            'test_binary': test_binary, 'binary': worker_result['binary'],
            'provenance': deduplicated(stable), 'completed_utc': utc(),
            'original_r03_remains_failed': True, 'original_source_after_was_not_written_or_invented': True,
            'previous_tests_are_not_reexecuted': True, 'new_release_executions': 1,
            'environment_equivalence_scope': worker_result['environment_scope'],
            'scope': 'Explicit composition of five original passing stages and one new release; no native behavior or performance acceptance.'}


def main(core, observer):
    inputs = verify_inputs(core, observer)
    need(Path(__file__).absolute() == ENTRY, 'parent must run the new uploaded entry itself')
    os.umask(0o077)
    for path in (PREP, OUT):
        core.fresh(path)
    core.mkdir_new(PREP)
    core.mkdir_new(OUT)
    report = {'schema': 'hepta-a42-release-completion-entry/v1', 'started_utc': utc(),
              'passed': False, 'release_custody_verified': False, 'errors': [],
              'source': str(SOURCE), 'source_unchanged': False, 'originals_unchanged': False,
              'source_identity_before': inputs['proof']['source_receipts'],
              'input_receipts': inputs['receipts'], 'original_r03_remains_failed': True,
              'format_clean_test_executions': 0, 'automatic_retry': False, 'service_changes': False,
              'budgets': {'worker_seconds': WORKER_SECONDS, 'release_seconds': RELEASE_SECONDS,
                          'outer_seconds': OUTER_SECONDS, 'term_seconds': 30, 'kill_seconds': 30},
              'worker_custody': {'executed': False, 'execution_count': 0, 'original_child_reaped': False,
                                 'signals': [], 'outer_work_budget_exceeded': False},
              'scope': 'Actual original-worker custody and source binding; composition publication follows this immutable receipt.'}
    core.checkpoint(PREP / 'entry-report.json', report)
    result = 1
    worker_result = worker_receipt = None
    try:
        core.mkdir_new(PREP / 'inputs')
        for key, raw in inputs['originals'].items():
            core.create(PREP / 'inputs' / (key + '.original'), raw)
        script_raw = inputs['originals']['completion_entry']
        script_receipt = inputs['receipts']['completion_entry']
        core.create(PREP / 'entry.original.py', script_raw)
        core.create(PREP / 'prior-tested-source-current-proof.json', core.canonical(inputs['proof']))
        env, report['environment'] = core.clean_environment()
        code = core.own_worker(bootstrap(script_raw, script_receipt), env, report)
        raw, worker_receipt = core.original(PREP / 'worker-report.json')
        worker_result = json.loads(raw)
        report['worker'] = worker_receipt
        need(code == 0 and successful_custody(report['worker_custody']), 'new original worker did not close with successful custody')
        need(worker_result.get('schema') == 'hepta-a42-release-completion-worker/v1'
             and worker_result.get('passed') is True and worker_result.get('errors') == []
             and worker_result.get('source_unchanged') is True and worker_result.get('originals_unchanged') is True
             and worker_result.get('input_receipts') == inputs['receipts']
             and worker_result.get('source_identity_before') == inputs['proof']['source_receipts']
             and worker_result.get('source_identity_after') == inputs['proof']['source_receipts']
             and worker_result.get('source_tested') == worker_result.get('source_after') == inputs['q']['source_tested'],
             'new release worker lacks complete original input/source binding')
        stages = worker_result['stages']
        need(len(stages) == 1 and stages[0]['name'] == 'release' and stages[0]['argv'] == RELEASE_ARGV
             and stages[0]['timeout_seconds'] == RELEASE_SECONDS and stages[0]['executed'] is True
             and stages[0]['execution_count'] == 1 and stages[0]['returncode'] == 0
             and stages[0]['gate_clear'] is True, 'new worker did not run exactly one successful release')
        artifact = worker_result['binary']
        current = receipt_only(observer.stream_original(Path(artifact['path']), artifact['sha256']))
        need(current == receipt_only(artifact) and artifact.get('cached') is False,
             'new copied release changed before guardian completion')
        report['release_custody_verified'] = True
        report['binary'] = artifact
        result = 0
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        try:
            after = verify_inputs(core, observer)
            need(after['receipts'] == inputs['receipts']
                 and same_proof(after['proof']) == same_proof(inputs['proof']),
                 'original source or evidence changed during guarded completion')
            report.update(source_unchanged=True, originals_unchanged=True,
                          source_identity_after=after['proof']['source_receipts'])
        except BaseException as error:
            result = 1
            report['errors'].append('final original check: ' + type(error).__name__ + ': ' + str(error))
        report['passed'] = result == 0 and not report['errors']
        report['finished_utc'] = utc()
        core.checkpoint(PREP / 'entry-report.json', report)
    if not report['passed']:
        print(json.dumps({'entry_report': str(PREP / 'entry-report.json'), 'release_completion_passed': False,
                          'original_r03_remains_failed': True, 'errors': report['errors']}), flush=True)
        return 1
    _, entry_receipt = core.original(PREP / 'entry-report.json')
    value = composed(core, inputs, worker_result, worker_receipt, entry_receipt)
    publication = core.create(OUT / 'report.json', core.canonical(value))
    # Presence of a valid witness proves the preceding report barriers returned;
    # it does not assert its own future survival after host power loss.
    witness = {'schema': 'hepta-runtime-composed-qualification-witness/v1',
               'report_path': publication['path'], 'report_sha256': publication['sha256'],
               'report_bytes': publication['bytes'], 'report_file_fsync_completed': True,
               'report_directory_fsync_completed': True}
    core.create(OUT / 'composition.witness.json', core.canonical(witness))
    print(json.dumps({'report': publication, 'qualified_by_explicit_composition': True,
                      'original_r03_remains_failed': True, 'new_release_executions': 1}), flush=True)
    return 0


if __name__ == '__main__':
    need(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(os, 'WNOWAIT'),
         'native Linux original-child custody required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--permit-fd', type=int)
    parser.add_argument('--expected-entry-sha')
    args = parser.parse_args()
    core, observer = support()
    signal.signal(signal.SIGTERM, core.termination_handler)
    signal.signal(signal.SIGINT, core.termination_handler)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    if args.worker:
        raise SystemExit(worker(args, core, observer))
    need(args.permit_fd is None and args.expected_entry_sha is None, 'worker-only arguments refused')
    raise SystemExit(main(core, observer))
