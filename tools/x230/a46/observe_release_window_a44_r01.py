#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fresh bounded scheduling and current-source proof before a release-only completion.

Never launches Cargo, a benchmark, SSH or an agent request. Does not signal or
reprioritize another process. A clear sample is a point observation only; every
later qualification or benchmark must pass its own immediate unchanged gate.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
import types

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
OUT = BASE / 'a44-release-window-r01'
NATIVE = BASE / 'tools/run_a41_native_validation_r07.py'
NATIVE_SHA = '6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9'
QUAL = BASE / 'qualification-a42-fresh-cohort-r03/report.json'
QUAL_SHA = 'b7374df702c477f394b5f3ba2ed94337daa23f8dde54fb38370df6b2d5172b6d'
WORKER = BASE / 'a42-qualification-entry-r03/worker-report.json'
WORKER_SHA = '27324028a7e49f165e3862f77df7a8c061414628a3b7355fa49ea423ee3d2cb9'
AMENDMENT = BASE / 'tools/a44-a42-release-completion-protocol-r01.json'
AMENDMENT_SHA = 'fec0268cc2563a32baa75c7466b1d528356269f2048d2f573c544b133a19a9f9'
BUSY_NAMES = ('cargo', 'cargo-clippy', 'clippy-driver', 'rustc', 'heptabao_server')
WINDOW_SECONDS = 600
INTERVAL_SECONDS = 30
MEM_MIN_KIB = 2097152
DISK_MIN_BYTES = 2147483648
MAX_BYTES = 1024 * 1024
PUBLISHED = None
GUARDIAN = BASE / 'a42-qualification-entry-r03/entry-report.json'
GUARDIAN_SHA = 'fcda21f276b6858341a80347c9e537423100195c1b4672a39e8f50153d72949f'
ORIGINAL_ENTRY = BASE / 'tools/prepare_qualify_a42_fresh_cohort_r03.py'
ORIGINAL_ENTRY_SHA = '3667eef725327df895ce26d4c898d19cabc4774146577ca08726cd2d4602d5a0'
TERMINAL = BASE / 'tools/qualification-r03-terminal-status.raw.json'
TERMINAL_SHA = '74819c91616c19885dd3671ac68f8fa55db7709b1701f08ae9eb48b478946816'
PREVIOUS_WINDOW = BASE / 'a43-release-window-r01/report.json'
PREVIOUS_WINDOW_SHA = '98f85fd00baa4335349c8d54fec1b74537a4e0249a6b21eee37773a922872329'


def need(value, message):
    if not value:
        raise RuntimeError(message)


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
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def original(path, expected=None):
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size <= MAX_BYTES, 'bounded single-link original required')
            raw = bytearray()
            while len(raw) <= MAX_BYTES:
                block = os.read(fd, min(65536, MAX_BYTES + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            raw = bytes(raw)
            need(len(raw) == before.st_size and len(raw) <= MAX_BYTES
                 and stamp(before) == stamp(os.fstat(fd))
                 == stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                 'original changed during read')
            digest = hashlib.sha256(raw).hexdigest()
            need(expected is None or digest == expected, 'original SHA differs: ' + str(path))
            return raw, {'path': str(path), 'bytes': len(raw), 'sha256': digest,
                         'identity': stamp(before)}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def create(path, raw):
    need(len(raw) <= MAX_BYTES, 'bounded observation output exceeded')
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)
    check, receipt = original(path)
    need(check == raw, 'new observation readback differs')
    return receipt


def checkpoint(value):
    global PUBLISHED
    path = OUT / 'report.json'
    raw = canonical(value)
    if PUBLISHED is None:
        PUBLISHED = create(path, raw)
        return
    _, current = original(path)
    need(current == PUBLISHED, 'owned observation report changed externally')
    temporary = OUT / ('report.next-' + str(time.monotonic_ns()))
    create(temporary, raw)
    parent = directory(OUT)
    try:
        need(stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == current['identity'],
             'owned report identity changed before publication')
        os.replace(temporary.name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    check, PUBLISHED = original(path)
    need(check == raw, 'owned report readback differs')


def stream_original(path, expected):
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size <= 512 * 1024 * 1024, 'bounded copied artifact required')
            digest, size = hashlib.sha256(), 0
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                size += len(block)
                need(size <= before.st_size, 'copied artifact grew during read')
                digest.update(block)
            need(size == before.st_size and stamp(before) == stamp(os.fstat(fd))
                 == stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                 'copied artifact changed during read')
            need(digest.hexdigest() == expected and os.access(path, os.X_OK),
                 'copied test artifact identity or executable access differs')
            return {'path': str(path), 'bytes': size, 'sha256': digest.hexdigest(),
                    'identity': stamp(before), 'body_sha256_verified': True}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def tested_source_proof(retained):
    q = json.loads(retained['qualification_r03'])
    worker = json.loads(retained['worker_r03'])
    guardian = json.loads(retained['guardian_r03'])
    terminal = json.loads(retained['terminal_r03'])
    need(q['qualified'] is False and q['current_stage'] == 'release'
         and q['error'] == 'A42 r03 cargo stage refused: busy/incomplete/resource-floor host gate; cargo not started'
         and 'source_after' not in q, 'original failed qualification state differs')
    names = ['format', 'fmt-check', 'clean-package', 'clippy', 'test']
    need([row['name'] for row in q['stages']] == names
         and all(row['returncode'] == 0 for row in q['stages']), 'original five stages did not pass')
    need([row['name'] for row in worker['stages']] == names + ['release']
         and all(row['executed'] is True and row['execution_count'] == 1
                 and row['returncode'] == 0 and row['gate_clear'] is True for row in worker['stages'][:5])
         and worker['stages'][5]['executed'] is False
         and worker['stages'][5]['execution_count'] == 0
         and worker['stages'][5]['gate_clear'] is False, 'original release was not an unexecuted refusal')
    custody = guardian['worker_custody']
    need(custody['original_child_reaped'] is True and custody['custody_known'] is True
         and custody['custody_retained_until_reap'] is True and custody['group_quiet_before_reap'] is True
         and custody['pid'] == custody['actual_waitpid'] == 2318650
         and custody['raw_wait_status'] == 256 and custody['returncode'] == 1
         and custody['outer_work_budget_exceeded'] is False and custody['signals'] == []
         and custody['terminal_group_snapshot']['errors'] == []
         and custody['terminal_group_snapshot']['live'] == []
         and guardian['parent_unchanged_after_attempt'] is True, 'original worker custody did not close normally')
    need(terminal['job_id'] == '1a1758aea3b-96a-697' and terminal['state'] == 'failed'
         and terminal['exit_code'] == 1 and terminal['timed_out'] is False
         and terminal['cancelled'] is False and terminal['output_complete'] is True,
         'original operator terminal receipt differs')
    entry = types.ModuleType('a43_release_window_source_reader')
    entry.__file__ = str(ORIGINAL_ENTRY)
    exec(compile(retained['r03_entry_script'], str(ORIGINAL_ENTRY), 'exec'), entry.__dict__)
    source = BASE / 'source-a42-fresh-cohort-r03'
    mapping, receipts, _ = entry.source(source)
    need(q['source'] == str(source) and mapping == q['source_tested'] and len(mapping) == 168
         and entry.map_sha(mapping) == 'c1ae8a69901aee16e03871e920a6a7e321672c9b30b3a6e75d3560390b8c2e11',
         'current complete source does not match the actually tested source')
    test_start = datetime.datetime.fromisoformat(worker['stages'][4]['started_utc'])
    delta = test_start - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    start_ns = (delta.days * 86400 + delta.seconds) * 1000000000 + delta.microseconds * 1000
    late = [name for name, row in receipts.items()
            if row['identity'][7] > start_ns or row['identity'][8] > start_ns]
    need(not late, 'source has visible modification/change timestamp after original test start')
    logs = {}
    test_raw = None
    for row in q['stages']:
        raw, receipt = original(QUAL.parent / (row['name'] + '.log'), row['log_sha256'])
        logs[row['name']] = receipt
        if row['name'] == 'test':
            test_raw = raw
    empty, release_log = original(QUAL.parent / 'release.log')
    need(empty == b'', 'original unexecuted release log is not empty')
    artifact = q['test_binary']
    need(artifact['cached'] is False
         and artifact['path'] == str(QUAL.parent / 'hepta-runtime-tests')
         and artifact['sha256'] == 'bf4f3fecfda0fb78cebaac83c7f154c3410371dee1f25172ebf92596aa33275a'
         and artifact['compiler_source'] == str(source / 'src/main.rs'), 'original copied test artifact binding differs')
    events = []
    for line in test_raw.splitlines():
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if (isinstance(value, dict) and value.get('reason') == 'compiler-artifact'
                and value.get('target', {}).get('name') == 'hepta-runtime'
                and value.get('profile', {}).get('test') is True):
            events.append(value)
    need(len(events) == 1 and events[0]['fresh'] is False
         and events[0]['manifest_path'] == str(source / 'Cargo.toml')
         and events[0]['target']['src_path'] == artifact['compiler_source'],
         'original test compiler event is not source-bound fresh=false')
    binary = stream_original(Path(artifact['path']), artifact['sha256'])
    again, again_receipts, _ = entry.source(source)
    need(again == mapping and again_receipts == receipts, 'source changed during new proof collection')
    return {'schema': 'hepta-a42-r03-tested-source-current-proof/v1', 'observed_utc': utc(),
            'passed': True, 'candidate_qualified': False, 'release_executions': 0,
            'source': str(source), 'source_map': mapping, 'source_receipts': receipts,
            'source_map_sha256_compact': entry.map_sha(mapping), 'source_files': len(mapping),
            'all_current_source_times_no_later_than_test_start': True,
            'original_test_start_unix_ns': start_ns, 'logs': logs,
            'original_empty_release_log': release_log, 'original_copied_test_binary': binary,
            'original_test_compiler_event': events[0],
            'scope': 'New present source/artifact observation; not original source_after, release qualification or a continuous history proof.'}


def main():
    need(sys.platform == 'linux' and len(AMENDMENT_SHA) == 64, 'observer is not finally bound')
    os.umask(0o077)
    parent = directory(OUT.parent)
    try:
        os.mkdir(OUT.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    report = {'schema': 'hepta-a44-release-window-observation/v1', 'started_utc': utc(),
              'passed': False, 'clear_observed': False, 'status': 'preflight',
              'helper_invocations': 1,
              'helper_invocations_scope': 'one observer process; snapshot_calls counts host_load calls',
              'snapshot_calls': 0, 'window_seconds': WINDOW_SECONDS,
              'interval_seconds': INTERVAL_SECONDS, 'automatic_cargo_launch': False,
              'automatic_native_query': False, 'agent_requests': 0, 'foreign_signals': 0,
              'foreign_priority_changes': 0, 'automatic_retries': 0,
              'bindings': {}, 'observations': [], 'errors': [],
              'quiet_host_continuously_proved': False,
              'limits': ['Only discrete local observations; no continuous or remote-host clearance.',
                         'Qualification and measurement retain their own immediate gates.',
                         'The 600-second observation window never extends a product or test deadline.',
                         'No observed clear sample does not prove every instant was busy.']}
    checkpoint(report)
    result = 1
    try:
        retained = {}
        for key, path, expected in (
                ('qualification_r03', QUAL, QUAL_SHA), ('worker_r03', WORKER, WORKER_SHA),
                ('guardian_r03', GUARDIAN, GUARDIAN_SHA), ('terminal_r03', TERMINAL, TERMINAL_SHA),
                ('r03_entry_script', ORIGINAL_ENTRY, ORIGINAL_ENTRY_SHA),
                ('release_completion_protocol', AMENDMENT, AMENDMENT_SHA),
                ('previous_no_clear_window', PREVIOUS_WINDOW, PREVIOUS_WINDOW_SHA),
                ('host_load_driver', NATIVE, NATIVE_SHA),
                ('observer', Path(__file__).absolute(), None)):
            raw, receipt = original(path, expected)
            retained[key] = raw
            report['bindings'][key] = receipt
            create(OUT / (key + '.original'), raw)
        amendment = json.loads(retained['release_completion_protocol'])
        need(amendment['schema'] == 'hepta-a44-a42-release-completion-protocol/v1'
             and amendment['maximum_new_release_attempts_after_clear'] == 1
             and amendment['window_seconds'] == WINDOW_SECONDS
             and amendment['interval_seconds'] == INTERVAL_SECONDS
             and amendment['mem_available_kib_min'] == MEM_MIN_KIB
             and amendment['disk_available_bytes_min'] == DISK_MIN_BYTES
             and amendment['original_r03_remains_failed'] is True,
             'prospective release completion protocol differs')
        previous = json.loads(retained['previous_no_clear_window'])
        need(len(retained['previous_no_clear_window']) == 53711
             and previous.get('schema') == 'hepta-a43-release-window-observation/v1'
             and previous.get('status') == 'no_clear_observed'
             and previous.get('passed') is False and previous.get('clear_observed') is False
             and previous.get('snapshot_calls') == 40 and previous.get('window_seconds') == 1200
             and previous.get('interval_seconds') == 30 and previous.get('originals_unchanged') is True
             and previous.get('errors') == [], 'previous failed scheduling window differs')
        need(amendment.get('scheduling_tranche') == 'a44-new-user-continuation-r01'
             and amendment.get('previous_window_not_reused_for_admission') is True
             and amendment.get('previous_failed_tranche_unchanged') is True
             and amendment.get('observer_out') == str(OUT)
             and amendment.get('previous_no_clear_window', {}).get('path') == str(PREVIOUS_WINDOW)
             and amendment['previous_no_clear_window'].get('sha256') == PREVIOUS_WINDOW_SHA
             and amendment['previous_no_clear_window'].get('bytes') == 53711,
             'new scheduling tranche does not bind the retained failed window')
        report['scheduling_tranche'] = amendment['scheduling_tranche']
        report['previous_failed_tranche_unchanged'] = True
        report['previous_window_not_reused_for_admission'] = True
        proof = tested_source_proof(retained)
        report['tested_source_proof'] = create(OUT / 'tested-source-current-proof.json', canonical(proof))
        report['proof_scope'] = proof['scope']
        native = types.ModuleType('a42_build_window_frozen_host_load')
        native.__file__ = str(NATIVE)
        exec(compile(retained['host_load_driver'], str(NATIVE), 'exec'), native.__dict__)
        started = time.monotonic()
        deadline = started + WINDOW_SECONDS
        report.update(status='observing', observation_started_utc=utc())
        checkpoint(report)
        index = 0
        while time.monotonic() < deadline:
            snapshot = native.host_load()
            report['snapshot_calls'] += 1
            busy = [row for row in snapshot['processes']
                    if row['comm'] in BUSY_NAMES and row['state'] not in ('Z', 'X', 'x')]
            mem = disk = None
            resource_errors = []
            try:
                matches = [line.split()[1:] for line in snapshot['meminfo'].splitlines()
                           if line.startswith('MemAvailable:')]
                need(len(matches) == 1 and matches[0][1] == 'kB', 'MemAvailable unavailable')
                mem = int(matches[0][0])
                fs = os.statvfs(BASE)
                disk = fs.f_bavail * fs.f_frsize
            except (OSError, ValueError, KeyError, IndexError, RuntimeError) as error:
                resource_errors.append(type(error).__name__ + ': ' + str(error))
            clear = bool(snapshot['required_fields_present'] and not snapshot['errors']
                         and not busy and not resource_errors and mem >= MEM_MIN_KIB
                         and disk >= DISK_MIN_BYTES)
            elapsed = time.monotonic() - started
            # A sample that finishes outside the declared window cannot admit
            # a new attempt, even when its /proc contents happened to be clear.
            within = time.monotonic() < deadline
            value = {'schema': 'hepta-a44-release-window-snapshot/v1', 'index': index,
                     'clear': clear and within, 'snapshot': snapshot,
                     'matching_live_processes': busy, 'mem_available_kib': mem,
                     'disk_available_bytes': disk, 'resource_errors': resource_errors,
                     'resource_thresholds': {'mem_available_kib_min': MEM_MIN_KIB,
                                             'disk_available_bytes_min': DISK_MIN_BYTES},
                     'observed_seconds_since_start': elapsed, 'within_window': within}
            receipt = create(OUT / ('snapshot-%02d.json' % index), canonical(value))
            report['observations'].append({'index': index, 'elapsed_seconds': elapsed,
                'clear': value['clear'], 'matching_live_processes': busy,
                'mem_available_kib': mem, 'disk_available_bytes': disk, 'receipt': receipt})
            checkpoint(report)
            if value['clear']:
                report.update(status='clear_observed', passed=True, clear_observed=True,
                              successful_snapshot=receipt)
                result = 0
                break
            index += 1
            due = min(started + index * INTERVAL_SECONDS, deadline)
            # Skipped schedule points are not backfilled as successful samples.
            if time.monotonic() >= due and due < deadline:
                due = min(time.monotonic() + INTERVAL_SECONDS, deadline)
            time.sleep(max(0.0, min(INTERVAL_SECONDS, due - time.monotonic())))
        if not report['clear_observed']:
            report['status'] = 'no_clear_observed'
            result = 2
        for key, receipt in report['bindings'].items():
            raw, now = original(Path(receipt['path']), receipt['sha256'])
            need(raw == retained[key] and now == receipt, 'observer input changed: ' + key)
        for row in report['observations']:
            receipt = row['receipt']
            _, now = original(Path(receipt['path']), receipt['sha256'])
            need(now == receipt, 'snapshot original changed')
        after_proof = tested_source_proof(retained)
        need({k: v for k, v in after_proof.items() if k != 'observed_utc'}
             == {k: v for k, v in proof.items() if k != 'observed_utc'},
             'tested source/artifact originals changed during observation window')
        report['tested_source_proof_after'] = create(OUT / 'tested-source-current-proof-after.json', canonical(after_proof))
        report['originals_unchanged'] = True
    except BaseException as error:
        report.update(passed=False, clear_observed=False, status='observation_failed')
        report['errors'].append(type(error).__name__ + ': ' + str(error))
        result = 1
    finally:
        report['finished_utc'] = utc()
        checkpoint(report)
        print(json.dumps({'report': str(OUT / 'report.json'), 'status': report['status'],
                          'passed': report['passed'], 'snapshot_calls': report['snapshot_calls'],
                          'automatic_cargo_launch': False}), flush=True)
    return result


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt('observer received ' + signal.Signals(signum).name)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())
