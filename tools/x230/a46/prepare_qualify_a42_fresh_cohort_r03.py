#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One fresh A42 qualification attempt under guarded cargo-stage admission.

The original remote qualifier bytes and its argv/1800-second stage timeouts are
unchanged. Only that loaded module's subprocess reference receives a narrow
facade. Every original cargo stage requires a new complete frozen-r07 host-load
snapshot and the new 2 GiB memory/disk floors immediately before every stage,
including package-clean. This is a point-in-time
observation, not an exclusive host lease. A separately-sessioned worker contains
the qualifier; its original parent owns pidfd/waitid/raw-waitpid custody. No
foreign process, agent, SSH key, service, old source or old report is modified.
"""
import argparse
import base64
import datetime
import hashlib
import json
import math
import re
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import types
import zlib

DEV_ROOT = Path('/home/qian/hepta-runtime-optimization-20261023')
BASE = DEV_ROOT / 'a41-phase-timing-20261025-r01'
PARENT = BASE / 'source-r07-recovery-only'
PARENT_Q = BASE / 'qualification-r07-recovery-only/report.json'
DEST = BASE / 'source-a42-fresh-cohort-r03'
OUT = BASE / 'qualification-a42-fresh-cohort-r03'
PREP = BASE / 'a42-qualification-entry-r03'
BUNDLE = BASE / 'tools/a42-source-bundle-r01.json.gz'
QUALIFIER = BASE / 'tools/qualify_runtime_candidate.py'
NATIVE = BASE / 'tools/run_a41_native_validation_r07.py'
TARGET = BASE / 'target'
CARGO = '/home/qian/.cargo/bin/cargo'
BUNDLE_SHA = 'c10e03b5d2f2b29317f79c8020f0f8f59795d19175c577b6def5b2e6bbf1841c'
BUNDLE_BYTES = 289444
COMPRESSED_SHA = 'e0bffbd7635ea0919cb551ce08661c4999e7f2aa1e79b96665cdc7075b9ed73d'
COMPRESSED_BYTES = 94105
PARENT_Q_SHA = 'ab3481a57c69177d20f4d4feff31543dbc0a32b6f07892a0553879035b928cc9'
PARENT_MAP_SHA = '4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d'
CANDIDATE_MAP_SHA = '02edd61645f84ae6cbe3dd3d8977fe85b1c66a2ba813fb0a80a7c026a0a5ef86'
QUALIFIER_SHA = '64efa0da0d22e2ad8d10eb6f8a91ab158a234b331383bbd595e65fc9bd47d1d2'
NATIVE_SHA = '6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9'
CHANGED = frozenset(('src/mcp/runtime/request_audit.rs', 'src/mcp/runtime/request_archive_index.rs',
    'src/mcp/runtime/request_archive_batch.rs', 'src/mcp/runtime/request_archive_batch_tests.rs',
    'src/mcp/runtime/request_archive_page_batch_tests.rs'))
BUSY_NAMES = ('cargo', 'cargo-clippy', 'clippy-driver', 'rustc', 'heptabao_server')
STAGES = (
    ('format', ['fmt', '--all']),
    ('fmt-check', ['fmt', '--all', '--', '--check']),
    ('clean-package', ['clean', '--offline', '--locked', '--package', 'hepta-runtime']),
    ('clippy', ['clippy', '--offline', '--locked', '--all-features', '--all-targets', '--', '-D', 'warnings']),
    ('test', ['test', '--offline', '--locked', '--all-features', '--message-format=json-render-diagnostics']),
    ('release', ['build', '--offline', '--locked', '--all-features', '--release', '--bins', '--message-format=json-render-diagnostics']),
)
WORKER_SECONDS = 6600
TERM_SECONDS = 30
KILL_SECONDS = 30
OUTER_OPERATOR_SECONDS = 7000
MAX_FILE = 16 * 1024 * 1024
MAX_READ = 128 * 1024 * 1024
READ_BYTES = 0
PUBLISHED = {}

# This is the fresh A43 scheduling protocol for unchanged A42 source. The
# completed A42 window remains a historical failure; its r02 draft stays disabled.
# Root binds the actual terminal clear report/snapshot before the sole launch.
FINAL_BINDINGS_READY = True
AWAIT_CLEAR_REPORT = BASE / 'a43-resource-window-r01/report.json'
AWAIT_CLEAR_REPORT_SHA = '1d7bc4828dcfc30ec8caa987398e913b3f4b08b2c2c5d8ec000c128e44639148'
AWAIT_CLEAR_REPORT_BYTES = 4551
AWAIT_CLEAR_SNAPSHOT_SHA = 'e82f2d7bcbdc5165a67aacb586208379fa62eb3ba2b1d4422f248d2b5cda7c9b'
AWAIT_CLEAR_SNAPSHOT_BYTES = 58560
CONTINUATION_PROTOCOL = BASE / 'tools/a43-continuation-protocol-r01.json'
CONTINUATION_PROTOCOL_SHA = 'a3f02df5ad6290fc100ff7329fd5ab4509899779328bf2aa7f860ed621dfa9b4'
CONTINUATION_PROTOCOL_BYTES = 3259
AWAIT_OBSERVER = BASE / 'tools/observe_resource_window_a43_r01.py'
AWAIT_OBSERVER_SHA = '26c5d1a00d5195451e6f03d86cf454a1d4ac2edf53bb5367ad130c31533e83a8'
AWAIT_OBSERVER_BYTES = 13043
R01_QUALIFICATION = BASE / 'qualification-a42-fresh-cohort-r01/report.json'
R01_QUALIFICATION_SHA = 'f462b4fa50a312c8eead082bb24a1717a6b09e75d13077bef95a09fe9da45244'
R01_WORKER = BASE / 'a42-qualification-entry-r01/worker-report.json'
R01_WORKER_SHA = 'ec7d42317aca94b537a508dfb3c07ffcfddd21314bacfe5e03cc6323d0c5556e'
R01_ENTRY = BASE / 'tools/prepare_qualify_a42_fresh_cohort_r01.py'
R01_ENTRY_SHA = 'd9acd96c491a77ddb49825a57d5a27f3a0cf58e064b07780a3e1b9ec2cef7a23'
PRIOR_WINDOW = BASE / 'a42-build-window-r01/report.json'
PRIOR_WINDOW_SHA = '581f4a30e2a0ac1a369541cc9b282f2885701f60ac7304fd79e24d58732859f0'
MEM_MIN_KIB = 2097152
DISK_MIN_BYTES = 2147483648
CONTINUATION_BINDING = None


def need(value, message):
    if not value:
        raise RuntimeError(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def map_sha(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and '.' not in path.parts,
         'direct absolute directory required: ' + str(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def original(path, expected=None, cap=MAX_FILE):
    global READ_BYTES
    path = Path(path)
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap,
                 'bounded single-link regular original required: ' + str(path))
            chunks, size = [], 0
            while True:
                raw = os.read(fd, min(1024 * 1024, cap + 1 - size))
                if not raw:
                    break
                size += len(raw)
                READ_BYTES += len(raw)
                need(size <= cap and READ_BYTES <= MAX_READ, 'bounded read budget exceeded')
                chunks.append(raw)
            data = b''.join(chunks)
            after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            need(size == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(after),
                 'original changed during read: ' + str(path))
            need(expected is None or sha(data) == expected, 'original SHA differs: ' + str(path))
            return data, {'path': str(path), 'bytes': size, 'sha256': sha(data), 'identity': stamp(before)}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def fresh(path):
    parent = directory(path.parent)
    try:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise RuntimeError('fresh path required: ' + str(path))
    finally:
        os.close(parent)


def mkdir_new(path):
    parent = directory(path.parent)
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def create(path, raw):
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            need(os.fstat(stream.fileno()).st_nlink == 1, 'new file link count changed')
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)
    checked, receipt = original(path)
    need(checked == raw, 'new file readback differs: ' + str(path))
    return receipt


def checkpoint(path, value):
    # Only this process's own previously published report may be replaced.
    raw = canonical(value)
    if str(path) not in PUBLISHED:
        PUBLISHED[str(path)] = create(path, raw)
        return
    before_raw, before = original(path)
    need(before == PUBLISHED[str(path)], 'owned report was changed externally')
    temporary = path.with_name(path.name + '.next-' + str(time.monotonic_ns()))
    create(temporary, raw)
    parent = directory(path.parent)
    try:
        need(stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == before['identity'],
             'owned report changed before publication')
        os.replace(temporary.name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    after_raw, after = original(path)
    need(after_raw == raw, 'owned report publication differs')
    PUBLISHED[str(path)] = after


def source(root, keep_bytes=False):
    mapping, receipts, contents = {}, {}, {}
    pending, entries = [root], 0
    while pending:
        path = pending.pop()
        fd = directory(path)
        try:
            with os.scandir(fd) as scan:
                names = sorted(entry.name for entry in scan)
            for name in names:
                entries += 1
                need(entries <= 1024, 'source inventory limit exceeded')
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                child = path / name
                if stat.S_ISDIR(info.st_mode):
                    pending.append(child)
                elif stat.S_ISREG(info.st_mode):
                    raw, receipt = original(child)
                    relative = str(child.relative_to(root))
                    mapping[relative] = receipt['sha256']
                    receipts[relative] = receipt
                    if keep_bytes:
                        contents[relative] = raw
                else:
                    raise RuntimeError('source link/special file refused: ' + str(child))
        finally:
            os.close(fd)
    return mapping, receipts, contents


def load_bundle(path, compressed=False):
    raw, receipt = original(path, COMPRESSED_SHA if compressed else BUNDLE_SHA, 1024 * 1024)
    if compressed:
        need(len(raw) == COMPRESSED_BYTES, 'compressed bundle length differs')
        decoder = zlib.decompressobj(31)
        decoded = decoder.decompress(raw, BUNDLE_BYTES + 1)
        need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
             and len(decoded) == BUNDLE_BYTES and sha(decoded) == BUNDLE_SHA,
             'bounded single-member bundle decode differs')
        raw = decoded
    need(len(raw) == BUNDLE_BYTES, 'bundle length differs')
    value = json.loads(raw)
    need(value['schema'] == 'hepta-a42-fresh-page-source-bundle/v1'
         and value['parent_source'] == str(PARENT)
         and len(value['parent_source_map']) == 165
         and map_sha(value['parent_source_map']) == PARENT_MAP_SHA
         and len(value['candidate_source_map']) == 168
         and map_sha(value['candidate_source_map']) == CANDIDATE_MAP_SHA
         and set(value['changed_files']) == CHANGED, 'bundle binding differs')
    expected = dict(value['parent_source_map'])
    contents = {}
    for name, item in value['changed_files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,
             'unsafe source member')
        data = base64.b64decode(item['data_base64'], validate=True)
        need(len(data) == item['bytes'] and sha(data) == item['sha256']
             and item['parent_sha256'] == expected.get(name), 'source member differs')
        expected[name] = item['sha256']
        contents[name] = data
    need(expected == value['candidate_source_map'], 'candidate delta coverage differs')
    return value, contents, raw, receipt


def parent_qualification(mapping):
    raw, receipt = original(PARENT_Q, PARENT_Q_SHA)
    value = json.loads(raw)
    need(value.get('schema') == 'runtime-candidate-qualification/v1'
         and value.get('qualified') is True and value.get('current_stage') == 'complete'
         and not value.get('error') and value.get('source') == str(PARENT)
         and value['source_input'] == value['source_tested'] == value['source_after'] == mapping,
         'qualified parent source binding differs')
    return raw, receipt


def clean_environment():
    env = dict(os.environ)
    exact = {'PYTHONPATH', 'PYTHONHOME', 'RUST_LOG', 'RUST_TEST_NOCAPTURE', 'RUSTFLAGS',
             'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
             'HEPTA_ARCHIVE_INDEX_TRACE', 'HEPTA_REQUEST_AUDIT_TRACE', 'HEPTA_OBSERVATION_TRACE',
             'HEPTA_TEST_ARCHIVE_PAGE_SELECTOR_CHILD', 'HEPTA_A41_ARCHIVE_ROOT', 'GIT_SSH', 'GIT_SSH_COMMAND'}
    removed = sorted(key for key in env if key in exact or key.startswith('SSH_'))
    for key in removed:
        env.pop(key, None)
    fixed = {'PATH': '/home/qian/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'CARGO_HOME': str(DEV_ROOT / 'cargo-home-a32-a33-r02'),
             'CARGO_TARGET_DIR': str(TARGET), 'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0',
             'TOKIO_WORKER_THREADS': '2', 'RUST_TEST_THREADS': '2',
             'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
    env.update(fixed)
    return env, {'removed_names_only': removed, 'fixed_values': fixed, 'agent_accesses': 0}


def module(name, path, raw):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


class GuardedSubprocess:
    STDOUT = subprocess.STDOUT

    def __init__(self, native, report, expected_env):
        self.native, self.report, self.expected_env = native, report, expected_env
        self.next_stage = 0

    def run(self, argv, **kwargs):
        need(self.next_stage < len(STAGES), 'unexpected additional qualifier subprocess')
        name, tail = STAGES[self.next_stage]
        need(argv == [CARGO, '+1.95.0'] + tail, 'qualifier stage sequence or argv differs')
        need(set(kwargs) == {'cwd', 'env', 'stdout', 'stderr', 'timeout'}
             and Path(kwargs['cwd']) == DEST and kwargs['env'] == self.expected_env
             and kwargs['stderr'] == subprocess.STDOUT and kwargs['timeout'] == 1800,
             'qualifier subprocess options differ')
        log = kwargs['stdout']
        need(Path(log.name) == OUT / (name + '.log') and stat.S_ISREG(os.fstat(log.fileno()).st_mode)
             and os.fstat(log.fileno()).st_nlink == 1, 'original qualifier log differs')
        snapshot = self.native.host_load()
        matching = [row for row in snapshot['processes']
                    if row['comm'] in BUSY_NAMES and row['state'] not in ('Z', 'X', 'x')]
        mem = disk = None
        resource_errors = []
        try:
            memory = re.findall(r'^MemAvailable:\s+(\d+)\s+kB\s*$',
                                snapshot['meminfo'], flags=re.MULTILINE)
            need(len(memory) == 1, 'MemAvailable unavailable or ambiguous')
            mem = int(memory[0])
            filesystem = os.statvfs(BASE)
            disk = filesystem.f_bavail * filesystem.f_frsize
        except (OSError, ValueError, KeyError, IndexError, RuntimeError) as error:
            resource_errors.append(type(error).__name__ + ': ' + str(error))
        gate = {'clear': bool(snapshot['required_fields_present'] and not snapshot['errors']
                             and not matching and not resource_errors
                             and mem >= MEM_MIN_KIB and disk >= DISK_MIN_BYTES),
                'matching_live_processes': matching, 'snapshot': snapshot,
                'mem_available_kib': mem, 'disk_available_bytes': disk,
                'resource_errors': resource_errors,
                'resource_thresholds': {'mem_available_kib_min': MEM_MIN_KIB,
                                        'disk_available_bytes_min': DISK_MIN_BYTES},
                'scope': 'point-in-time local admission only; no continuous lock or remote-host guarantee'}
        receipt = create(PREP / ('stage-%d-%s.host-gate.json' % (self.next_stage, name)), canonical(gate))
        row = {'name': name, 'argv': argv, 'timeout_seconds': 1800, 'host_gate': receipt,
               'gate_clear': gate['clear'], 'executed': False, 'execution_count': 0}
        self.report['stages'].append(row)
        checkpoint(PREP / 'worker-report.json', self.report)
        need(gate['clear'], 'A42 r03 cargo stage refused: busy/incomplete/resource-floor host gate; cargo not started')
        # No source scan, sleep, retry or package operation lies between this
        # newly retained gate and the original subprocess call.
        row.update(executed=True, execution_count=1, started_utc=utc())
        checkpoint(PREP / 'worker-report.json', self.report)
        try:
            result = subprocess.run(argv, **kwargs)
            row['returncode'] = result.returncode
            self.next_stage += 1
            return result
        except BaseException as error:
            row['error'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            row['finished_utc'] = utc()
            checkpoint(PREP / 'worker-report.json', self.report)


def worker(args):
    # Parent writes GO only after the unreaped original child has a pidfd and
    # a verified new session/group identity. No cargo may run before that.
    need(args.permit_fd is not None and args.expected_entry_sha is not None, 'worker permit required')
    try:
        need(os.read(args.permit_fd, 2) == b'G', 'parent worker permit unavailable')
    finally:
        os.close(args.permit_fd)
    raw, _ = original(Path(__file__).absolute(), args.expected_entry_sha)
    del raw
    need(os.getpgrp() == os.getpid() and os.getsid(0) == os.getpid(), 'worker session identity differs')
    fresh(OUT)
    bundle, _, _, _ = load_bundle(PREP / 'source-bundle.original.json')
    mapping, _, _ = source(DEST)
    need(mapping == bundle['candidate_source_map'], 'prepared source changed before qualifier')
    qraw, qreceipt = original(QUALIFIER, QUALIFIER_SHA)
    nraw, nreceipt = original(NATIVE, NATIVE_SHA)
    need(len(qraw) == 5915 and len(nraw) == 51497, 'fixed helper length differs')
    native = module('a42_frozen_r07_host_load', NATIVE, nraw)
    qualifier = module('a42_guarded_fixed_qualifier', QUALIFIER, qraw)
    env, environment = clean_environment()
    # The parent's exec environment is already this exact cleaned environment.
    need(env == dict(os.environ), 'worker inherited environment was not the frozen cleaned environment')
    report = {'schema': 'hepta-a42-guarded-qualifier-worker/v1', 'started_utc': utc(),
              'passed': False, 'qualifier': qreceipt, 'host_load_driver': nreceipt,
              'execution_description': 'unchanged qualifier bytes under A42 guarded subprocess facade',
              'environment': environment, 'stages': [], 'automatic_retry': False,
              'service_changes': False, 'agent_accesses': 0, 'ssh_calls': 0}
    checkpoint(PREP / 'worker-report.json', report)
    facade = GuardedSubprocess(native, report, env)
    qualifier.subprocess = facade
    prior_argv = sys.argv
    sys.argv = [str(QUALIFIER), '--source', str(DEST), '--output', str(OUT), '--target-dir', str(TARGET),
                '--cargo', CARGO, '--toolchain', '1.95.0', '--jobs', '2']
    try:
        qualifier.main()
        need(facade.next_stage == len(STAGES), 'original qualifier stage coverage differs')
        result_raw, receipt = original(OUT / 'report.json')
        result = json.loads(result_raw)
        need(result.get('qualified') is True and result.get('current_stage') == 'complete'
             and not result.get('error') and result['source_input'] == bundle['candidate_source_map']
             and result['source_tested'] == result['source_after'], 'original qualifier did not qualify')
        need(set(result['source_after']) == set(bundle['candidate_source_map'])
             and all(value == bundle['candidate_source_map'][name]
                     for name, value in result['source_after'].items() if name not in CHANGED),
             'format changed candidate inventory or an unrelated parent file')
        report.update(passed=True, qualifier_report=receipt)
        return 0
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        return 1
    finally:
        sys.argv = prior_argv
        report['finished_utc'] = utc()
        checkpoint(PREP / 'worker-report.json', report)


def proc_identity(pid):
    text = Path('/proc', str(pid), 'stat').read_text()
    closing = text.rfind(') ')
    fields = text[closing + 2:].split()
    return {'pid': pid, 'comm': text[text.find('(') + 1:closing], 'state': fields[0],
            'ppid': int(fields[1]), 'pgrp': int(fields[2]), 'session': int(fields[3]),
            'start_ticks': int(fields[19])}


def group_snapshot(pgid):
    members, errors = [], []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            row = proc_identity(int(path.name))
            if row['pgrp'] == pgid:
                members.append(row)
        except (FileNotFoundError, ProcessLookupError):
            pass
        except (OSError, ValueError, IndexError) as error:
            errors.append({'pid': int(path.name), 'error': type(error).__name__ + ': ' + str(error)})
    members.sort(key=lambda row: row['pid'])
    return {'utc': utc(), 'members': members, 'errors': errors,
            'live': [row for row in members if row['state'] not in ('Z', 'X', 'x')]}


def own_worker(argv, env, report):
    row = report['worker_custody']
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    child = handle = None
    custody = True
    initial = None
    stdout = stderr = None
    started = time.monotonic()
    term_at = kill_at = cleanup_started = None
    deadline = started + WORKER_SECONDS

    def save():
        checkpoint(PREP / 'entry-report.json', report)

    def waitid_original():
        nonlocal custody
        try:
            result = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result is not None and result.si_pid != child.pid:
                custody = False
                raise RuntimeError('unexpected original worker waitid identity')
            return result
        except ChildProcessError as error:
            custody = False
            row['custody_unknown'] = True
            raise RuntimeError('original worker ECHILD; no signal or invented exit') from error

    def observe():
        nonlocal custody
        result = waitid_original()
        try:
            current = proc_identity(child.pid)
            if not (current['start_ticks'] == initial['start_ticks']
                    and current['pgrp'] == child.pid and current['session'] == child.pid):
                raise RuntimeError('original unreaped worker identity changed')
        except (OSError, ValueError, IndexError, RuntimeError) as error:
            custody = False
            row['custody_unknown'] = True
            raise RuntimeError('original worker identity unavailable; no further signal') from error
        return result

    def reap(observed, group, quiet):
        nonlocal custody
        need(custody and observed is not None and observed.si_pid == child.pid,
             'reap lacks observed original child')
        try:
            waited, status = os.waitpid(child.pid, os.WNOHANG)
        except ChildProcessError as error:
            custody = False
            row['custody_unknown'] = True
            raise RuntimeError('original worker ECHILD at reap; no invented exit') from error
        need(waited == child.pid, 'raw waitpid did not reap original observed worker')
        child.returncode = os.waitstatus_to_exitcode(status)
        row.update(original_child_reaped=True, actual_waitpid=waited,
            raw_wait_status=status, returncode=child.returncode,
            custody_retained_until_reap=True, group_quiet_before_reap=quiet,
            terminal_group_snapshot=group)

    def signal_group(signum):
        need(custody and not row['original_child_reaped'], 'signal lacks original child custody')
        observe()
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass
        row['signals'].append({'signal': signal.Signals(signum).name,
            'target': 'this_attempt_original_unreaped_worker_process_group',
            'pgid': child.pid, 'at_seconds': time.monotonic() - started})
        save()

    def cleanup_step(now):
        nonlocal term_at, kill_at, cleanup_started
        # One absolute 60-second cleanup window, shared by normal/error paths.
        # An exception during cleanup cannot renew either signal deadline.
        if cleanup_started is None:
            cleanup_started = now
            row['cleanup_started_at_seconds'] = now - started
            row['cleanup_deadline_at_seconds'] = now - started + TERM_SECONDS + KILL_SECONDS
        if now >= cleanup_started + TERM_SECONDS + KILL_SECONDS:
            return False
        if term_at is None:
            term_at = now
            signal_group(signal.SIGTERM)
        elif kill_at is None and now >= cleanup_started + TERM_SECONDS:
            kill_at = now
            signal_group(signal.SIGKILL)
        return True

    def open_log(path):
        receipt = create(path, b'')
        parent = directory(path.parent)
        try:
            fd = os.open(path.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
            try:
                need(stamp(os.fstat(fd)) == receipt['identity'], 'fresh worker log identity changed')
                return os.fdopen(fd, 'ab', buffering=0)
            except BaseException:
                os.close(fd)
                raise
        finally:
            os.close(parent)

    try:
        stdout = open_log(PREP / 'qualifier-worker.stdout')
        stderr = open_log(PREP / 'qualifier-worker.stderr')
        row['argv'] = argv + ['--permit-fd', str(read_fd)]
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            child = subprocess.Popen(row['argv'], env=env, cwd=PREP,
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, pass_fds=(read_fd,), start_new_session=True)
        finally:
            # An interrupt can now see the assigned original Popen child. The
            # worker unblocks these two signals at its own controlled entry.
            signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
        os.close(read_fd)
        read_fd = None
        row.update(executed=True, execution_count=1, pid=child.pid, started_utc=utc())
        initial = proc_identity(child.pid)
        need(initial['pgrp'] == child.pid and initial['session'] == child.pid, 'new worker group differs')
        handle = os.pidfd_open(child.pid, 0)
        row.update(pidfd_opened=True, original_identity=initial)
        save()
        row['worker_permit_send_attempted'] = True
        row['worker_permit_may_have_been_sent'] = True
        need(os.write(write_fd, b'G') == 1, 'worker permit was not written completely')
        row['worker_permit_sent'] = True
        os.close(write_fd)
        write_fd = None
        save()
        while True:
            observed = observe()
            now = time.monotonic()
            if observed is not None:
                group = group_snapshot(child.pid)
                row['terminal_group_snapshot'] = group
                if not group['errors'] and not group['live']:
                    reap(observed, group, True)
                    break
                if cleanup_started is None:
                    row['normal_worker_exit_left_live_group_or_observation_errors'] = True
            if cleanup_started is not None or now >= deadline or observed is not None:
                if now >= deadline:
                    row['outer_work_budget_exceeded'] = True
                if not cleanup_step(now):
                    # Even a known terminal leader can be reaped only after the
                    # bounded cleanup boundary; no further group signal follows.
                    if observed is not None:
                        reap(observed, group_snapshot(child.pid), False)
                    raise RuntimeError('owned worker group did not settle within original bounded cleanup')
            time.sleep(.1)
    except BaseException as error:
        row['error'] = type(error).__name__ + ': ' + str(error)
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None
        if child is not None and custody and not row['original_child_reaped']:
            if not row.get('worker_permit_may_have_been_sent'):
                # Closing GO is sufficient to make this exact worker fail before
                # any qualifier/cargo launch. A missing group identity never
                # authorizes a signal. Still explicitly observe/raw-reap it.
                until = min(time.monotonic() + TERM_SECONDS, started + WORKER_SECONDS + TERM_SECONDS + KILL_SECONDS)
                try:
                    while time.monotonic() < until:
                        observed = waitid_original()
                        if observed is not None:
                            reap(observed, {'scope': 'GO never sent; no qualifier launch'}, False)
                            row['unstarted_worker_reaped'] = True
                            break
                        time.sleep(.1)
                except BaseException as cleanup:
                    row.setdefault('cleanup_errors', []).append(type(cleanup).__name__ + ': ' + str(cleanup))
            elif initial is not None:
                try:
                    while not row['original_child_reaped']:
                        observed = observe()
                        group = group_snapshot(child.pid)
                        if observed is not None and not group['errors'] and not group['live']:
                            reap(observed, group, True)
                            break
                        if not cleanup_step(time.monotonic()):
                            if observed is not None:
                                reap(observed, group, False)
                            break
                        time.sleep(.1)
                except BaseException as cleanup:
                    row.setdefault('cleanup_errors', []).append(type(cleanup).__name__ + ': ' + str(cleanup))
        raise
    finally:
        for fd in (read_fd, write_fd, handle):
            if fd is not None:
                os.close(fd)
        for stream in (stdout, stderr):
            if stream is not None:
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
        row['elapsed_seconds'] = time.monotonic() - started
        row['finished_utc'] = utc()
        row['custody_known'] = custody
        save()
    return row['returncode']


def verify_continuation_binding():
    """The fresh A43 bounded observation admits only this one new A42 r03 attempt.

    It never substitutes for the unchanged new per-stage host snapshots. Missing
    prospective pins refuse before creating any new source/preparation/output.
    """
    need(FINAL_BINDINGS_READY is True, 'A42 r03 continuation bindings are not ready')
    for label, digest, size in (
        ('await report', AWAIT_CLEAR_REPORT_SHA, AWAIT_CLEAR_REPORT_BYTES),
        ('successful snapshot', AWAIT_CLEAR_SNAPSHOT_SHA, AWAIT_CLEAR_SNAPSHOT_BYTES),
    ):
        need(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)
             and type(size) is int and 0 < size <= MAX_FILE,
             'missing exact ' + label + ' pin')
    need(isinstance(CONTINUATION_PROTOCOL_SHA, str)
         and re.fullmatch(r'[0-9a-f]{64}', CONTINUATION_PROTOCOL_SHA),
         'missing continuation protocol pin')
    qraw, qreceipt = original(R01_QUALIFICATION, R01_QUALIFICATION_SHA)
    wraw, wreceipt = original(R01_WORKER, R01_WORKER_SHA)
    eraw, ereceipt = original(R01_ENTRY, R01_ENTRY_SHA)
    need(len(qraw) == 18952 and len(wraw) == 2701 and len(eraw) == 41236,
         'original r01 failure/entry lengths differ')
    qualification, worker_result = json.loads(qraw), json.loads(wraw)
    need(qualification.get('schema') == 'runtime-candidate-qualification/v1'
         and qualification.get('qualified') is False and qualification.get('current_stage') == 'format'
         and qualification.get('stages') == []
         and qualification.get('error') == 'A42 cargo stage refused: busy/incomplete host snapshot; cargo not started'
         and qualification.get('source') == str(BASE / 'source-a42-fresh-cohort-r01')
         and len(qualification['source_input']) == 168
         and map_sha(qualification['source_input']) == CANDIDATE_MAP_SHA,
         'r01 is not the preserved zero-cargo format-gate failure')
    stages = worker_result.get('stages')
    need(worker_result.get('schema') == 'hepta-a42-guarded-qualifier-worker/v1'
         and worker_result.get('passed') is False and type(stages) is list and len(stages) == 1,
         'original r01 worker failure differs')
    stage = stages[0]
    need(stage.get('name') == 'format' and stage.get('argv') == [CARGO, '+1.95.0', 'fmt', '--all']
         and stage.get('executed') is False and stage.get('execution_count') == 0
         and stage.get('gate_clear') is False and stage.get('timeout_seconds') == 1800,
         'original r01 must retain zero cargo executions')
    prior_raw, prior_receipt = original(PRIOR_WINDOW, PRIOR_WINDOW_SHA)
    prior = json.loads(prior_raw)
    need(len(prior_raw) == 27077
         and prior.get('schema') == 'hepta-a42-build-window-observation/v1'
         and prior.get('status') == 'no_clear_observed' and prior.get('passed') is False
         and prior.get('clear_observed') is False and prior.get('snapshot_calls') == 20
         and prior.get('originals_unchanged') is True and prior.get('errors') == [],
         'completed prior A42 no-clear window must remain unchanged and ineligible')
    await_raw, await_receipt = original(AWAIT_CLEAR_REPORT, AWAIT_CLEAR_REPORT_SHA)
    need(len(await_raw) == AWAIT_CLEAR_REPORT_BYTES, 'await report byte length differs')
    awaited = json.loads(await_raw)
    need(awaited.get('schema') == 'hepta-a43-resource-window-observation/v1'
         and awaited.get('status') == 'clear_observed' and awaited.get('passed') is True
         and awaited.get('clear_observed') is True
         and awaited.get('automatic_cargo_launch') is False
         and awaited.get('automatic_native_query') is False
         and awaited.get('originals_unchanged') is True and awaited.get('errors') == []
         and type(awaited.get('window_seconds')) is int and awaited['window_seconds'] == 600
         and type(awaited.get('interval_seconds')) is int and awaited['interval_seconds'] == 30
         and awaited.get('agent_requests') == 0 and awaited.get('foreign_signals') == 0
         and awaited.get('foreign_priority_changes') == 0 and awaited.get('automatic_retries') == 0
         and awaited.get('quiet_host_continuously_proved') is False
         and isinstance(awaited.get('finished_utc'), str) and bool(awaited['finished_utc'])
         and type(awaited.get('helper_invocations')) is int and awaited['helper_invocations'] == 1,
         'await report is not a successful read-only bounded observation')
    bindings = awaited.get('bindings', {})
    need(bindings.get('qualification_r01') == qreceipt and bindings.get('worker_r01') == wreceipt,
         'await observation does not retain these original r01 failures')
    originals = {
        'r01-qualification.original.json': qraw,
        'r01-worker.original.json': wraw,
        'r01-entry.original.py': eraw,
        'await-clear-report.original.json': await_raw,
        'prior-a42-window.original.json': prior_raw,
    }
    receipts = {'qualification_r01': qreceipt, 'worker_r01': wreceipt,
                'entry_r01': ereceipt, 'await_clear_report': await_receipt,
                'prior_a42_window': prior_receipt}
    for key, expected, size, filename in (
        ('continuation_protocol', CONTINUATION_PROTOCOL_SHA, CONTINUATION_PROTOCOL_BYTES, 'continuation-protocol.original.json'),
        ('host_load_driver', NATIVE_SHA, 51497, 'await-host-load-driver.original.py'),
        ('observer', AWAIT_OBSERVER_SHA, AWAIT_OBSERVER_BYTES, 'await-observer.original.py'),
    ):
        binding = bindings.get(key)
        need(type(binding) is dict and isinstance(binding.get('path'), str),
             'await binding absent: ' + key)
        path = Path(binding['path'])
        need(path.is_absolute() and path.is_relative_to(BASE) and '..' not in path.parts,
             'await binding is outside the isolated preparation root')
        need(binding.get('sha256') == expected and binding.get('bytes') == size,
             'await binding SHA or length differs: ' + key)
        if key == 'host_load_driver':
            need(path == NATIVE, 'await host-load driver path differs')
        elif key == 'continuation_protocol':
            need(path == CONTINUATION_PROTOCOL, 'continuation protocol path differs')
        elif key == 'observer':
            need(path == AWAIT_OBSERVER, 'new resource observer path differs')
        data, current = original(path, binding.get('sha256'))
        need(current == binding, 'await bound original changed: ' + key)
        if key == 'continuation_protocol':
            amendment = json.loads(data)
            need(amendment.get('schema') == 'hepta-a43-a42-continuation/v1'
                 and amendment.get('maximum_new_qualification_attempts_after_clear') == 1
                 and amendment.get('window_seconds') == 600 and amendment.get('interval_seconds') == 30
                 and amendment.get('previous_r02_remains_ineligible') is True
                 and amendment.get('source_map_sha256') == CANDIDATE_MAP_SHA
                 and amendment.get('busy_process_names') == list(BUSY_NAMES)
                 and amendment.get('new_restrictive_resource_checks') == {
                     'mem_available_kib_min': MEM_MIN_KIB, 'disk_available_bytes_min': DISK_MIN_BYTES}
                 and amendment.get('qualification_source') == str(DEST)
                 and amendment.get('qualification_out') == str(OUT)
                 and amendment.get('qualification_entry_out') == str(PREP)
                 and amendment.get('observer_out') == str(AWAIT_CLEAR_REPORT.parent)
                 and amendment.get('qualification_stages') == [name for name, _ in STAGES]
                 and amendment.get('qualification_stage_budget_seconds') == 1800
                 and amendment.get('qualification_worker_seconds') == WORKER_SECONDS
                 and amendment.get('qualification_cleanup_term_kill_seconds') == [TERM_SECONDS, KILL_SECONDS]
                 and amendment.get('qualification_outer_operator_seconds') == OUTER_OPERATOR_SECONDS
                 and amendment.get('no_foreign_process_signal_or_priority_change') is True
                 and amendment.get('no_installed_services_mutation') is True
                 and amendment.get('no_git_add_commit_push_merge') is True
                 and amendment.get('old_originals_immutable') is True
                 and amendment.get('automatic_cargo_launch') is False
                 and amendment.get('automatic_benchmark_launch') is False,
                 'fresh A43 continuation protocol differs')
        originals[filename] = data
        receipts[key] = current
    declared = awaited.get('successful_snapshot')
    need(type(declared) is dict and declared.get('sha256') == AWAIT_CLEAR_SNAPSHOT_SHA
         and declared.get('bytes') == AWAIT_CLEAR_SNAPSHOT_BYTES,
         'successful snapshot exact pin differs')
    snapshot_path = Path(declared['path'])
    need(snapshot_path.is_absolute() and snapshot_path.is_relative_to(AWAIT_CLEAR_REPORT.parent)
         and snapshot_path != AWAIT_CLEAR_REPORT and '..' not in snapshot_path.parts,
         'successful snapshot path is outside its fixed observation directory')
    snapshot_raw, snapshot_receipt = original(snapshot_path, AWAIT_CLEAR_SNAPSHOT_SHA)
    need(snapshot_receipt == declared and len(snapshot_raw) == AWAIT_CLEAR_SNAPSHOT_BYTES,
         'successful snapshot original changed')
    value = json.loads(snapshot_raw)
    snapshot = value.get('snapshot', {})
    need(value.get('schema') == 'hepta-a43-resource-window-snapshot/v1'
         and value.get('clear') is True and value.get('within_window') is True
         and type(value.get('index')) is int
         and value['index'] >= 0 and snapshot.get('required_fields_present') is True
         and snapshot.get('errors') == []
         and all(type(snapshot.get(name)) is str and bool(snapshot[name])
                 for name in ('loadavg', 'stat', 'meminfo', 'uptime'))
         and type(snapshot.get('processes')) is list,
         'successful host snapshot is incomplete')
    live = [row for row in snapshot['processes']
            if row['comm'] in BUSY_NAMES and row['state'] not in ('Z', 'X', 'x')]
    need(not live and value.get('matching_live_processes') == [] and value.get('resource_errors') == [],
         'successful snapshot contains busy work or observation errors')
    memory = re.findall(r'^MemAvailable:\s+(\d+)\s+kB\s*$', snapshot['meminfo'], flags=re.MULTILINE)
    need(len(memory) == 1 and type(value.get('mem_available_kib')) is int
         and int(memory[0]) == value['mem_available_kib'] and value['mem_available_kib'] >= 2097152
         and type(value.get('disk_available_bytes')) is int and value['disk_available_bytes'] >= 2147483648
         and value.get('resource_thresholds') == {
             'mem_available_kib_min': 2097152, 'disk_available_bytes_min': 2147483648},
         'successful snapshot resource floor differs or was not met')
    elapsed = value.get('observed_seconds_since_start')
    need(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed < 600,
         'successful snapshot lies outside the bounded observation window')
    observations = awaited.get('observations')
    calls = awaited.get('snapshot_calls')
    need(type(observations) is list and type(calls) is int and 1 <= calls <= 20
         and len(observations) == calls and observations[-1].get('receipt') == declared
         and observations[-1].get('index') == value['index'] and observations[-1].get('clear') is True
         and [row.get('index') for row in observations] == list(range(calls))
         and observations[-1].get('elapsed_seconds') == elapsed
         and observations[-1].get('matching_live_processes') == []
         and observations[-1].get('mem_available_kib') == value['mem_available_kib']
         and observations[-1].get('disk_available_bytes') == value['disk_available_bytes']
         and all(row.get('clear') is False for row in observations[:-1]),
         'successful snapshot is not the first clear terminal observation')
    # Bind the source observation receipt once more after its dependent original
    # reads. These immutable records must also survive qualification unchanged.
    repeated_raw, repeated_receipt = original(AWAIT_CLEAR_REPORT, AWAIT_CLEAR_REPORT_SHA)
    need(repeated_raw == await_raw and repeated_receipt == await_receipt,
         'await report changed while verifying its dependent originals')
    originals['await-clear-snapshot.original.json'] = snapshot_raw
    receipts['successful_snapshot'] = snapshot_receipt
    return {'receipts': receipts, 'originals': originals,
            'scope': 'one fresh r03 after a newly observed clear point; all original stage gates still required',
            'previous_cargo_executions': 0, 'previous_tests': 0, 'previous_benchmarks': 0,
            'previous_counts_scope': 'A42 r01 only; earlier qualified r07 results are separate',
            'snapshot_calls': calls, 'workloads_automatically_launched_by_observer': 0,
            'prior_failure_retained': True, 'prior_a42_window_ineligible': True,
            'old_r02_draft_used_or_enabled': False, 'continuous_quiet_host_claim': False}


def main(args):
    need(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(os, 'WNOWAIT'),
         'native x230 Linux pidfd/waitid support required')
    os.umask(0o077)
    for path in (DEST, OUT, PREP):
        fresh(path)
    need(not DEST.is_relative_to(PARENT) and not PARENT.is_relative_to(DEST), 'source paths overlap')
    mkdir_new(PREP)
    report = {'schema': 'hepta-a42-qualification-entry/v1', 'started_utc': utc(), 'passed': False,
        'qualified': False, 'execution_description': 'unchanged qualifier bytes under A42 guarded subprocess facade',
        'source': str(DEST), 'output': str(OUT), 'parent_source': str(PARENT),
        'budgets': {'operator_outer_seconds': OUTER_OPERATOR_SECONDS, 'worker_seconds': WORKER_SECONDS,
                    'original_each_qualifier_stage_seconds': 1800, 'term_seconds': TERM_SECONDS,
                    'kill_seconds': KILL_SECONDS},
        'automatic_retry': False, 'agent_accesses': 0, 'ssh_calls': 0, 'service_changes': False,
        'foreign_process_signals': 0, 'benchmark_executions': 0, 'errors': [],
        'worker_custody': {'executed': False, 'execution_count': 0, 'original_child_reaped': False,
                           'signals': [], 'outer_work_budget_exceeded': False},
        'prior_busy_host_gate_unchanged': 'a42-host-gate-r01 is retained separately and is not this admission gate',
        'group_scope_limit': 'Only this new session/process group is covered; escaped descendants or host reboot are not proved.'}
    need(CONTINUATION_BINDING is not None, 'r03 main lacks the verified continuation binding')
    report['continuation'] = {key: value for key, value in CONTINUATION_BINDING.items() if key != 'originals'}
    checkpoint(PREP / 'entry-report.json', report)
    parent_mapping = parent_receipts = parent_raw = parent_receipt = None
    result = 1
    try:
        for name, raw in CONTINUATION_BINDING['originals'].items():
            create(PREP / name, raw)
        bundle, changes, bundle_raw, bundle_receipt = load_bundle(BUNDLE, compressed=True)
        report['bundle'] = bundle_receipt
        report['bundle_decoded'] = {'bytes': len(bundle_raw), 'sha256': sha(bundle_raw)}
        compressed_raw, _ = original(BUNDLE, COMPRESSED_SHA, 1024 * 1024)
        create(PREP / 'source-bundle.original.json.gz', compressed_raw)
        create(PREP / 'source-bundle.original.json', bundle_raw)
        parent_mapping, parent_receipts, parent_bytes = source(PARENT, keep_bytes=True)
        need(parent_mapping == bundle['parent_source_map'], 'complete parent source map differs')
        parent_raw, parent_receipt = parent_qualification(parent_mapping)
        report['parent_qualification'] = parent_receipt
        report['parent_source_before'] = parent_receipts
        create(PREP / 'r07-qualification.original.json', parent_raw)
        create(PREP / 'parent-source-map.original.json', canonical(parent_mapping))
        qraw, qreceipt = original(QUALIFIER, QUALIFIER_SHA)
        nraw, nreceipt = original(NATIVE, NATIVE_SHA)
        need(len(qraw) == 5915 and len(nraw) == 51497, 'actual frozen helper length differs')
        report['qualifier'] = qreceipt
        report['host_load_driver'] = nreceipt
        create(PREP / 'qualifier.original.py', qraw)
        create(PREP / 'r07-native-driver.original.py', nraw)
        script_raw, script_receipt = original(Path(__file__).absolute())
        report['entry'] = script_receipt
        create(PREP / 'entry.original.py', script_raw)
        report['local_qualifier_copy_caveat'] = '5915-byte actual remote 64efa qualifier retained; older local 5916-byte copy has one extra final LF and was not substituted.'
        for path in (TARGET, DEV_ROOT / 'cargo-home-a32-a33-r02'):
            fd = directory(path)
            os.close(fd)
        mkdir_new(DEST)
        contents = dict(parent_bytes)
        contents.update(changes)
        for name in sorted({str(Path(name).parent) for name in contents}, key=lambda name: (len(Path(name).parts), name)):
            current = DEST
            for part in Path(name).parts:
                if part == '.':
                    continue
                current = current / part
                try:
                    fd = directory(current)
                    os.close(fd)
                except FileNotFoundError:
                    mkdir_new(current)
        for name, raw in sorted(contents.items()):
            create(DEST / name, raw)
        prepared, receipts, _ = source(DEST)
        need(prepared == bundle['candidate_source_map'], 'prepared candidate complete map differs')
        report.update(source_preformat=prepared, source_preformat_map_sha256_compact=map_sha(prepared),
                      source_file_count=len(prepared), source_preformat_receipts=receipts)
        env, environment = clean_environment()
        report['environment'] = environment
        # Recheck immutable parents and tools before permitting the worker.
        rechecked, rechecked_receipts, _ = source(PARENT)
        rechecked_q, rechecked_q_receipt = parent_qualification(rechecked)
        need(rechecked == parent_mapping and rechecked_receipts == parent_receipts
             and rechecked_q == parent_raw and rechecked_q_receipt == parent_receipt,
             'parent changed during preparation')
        original(BUNDLE, COMPRESSED_SHA, 1024 * 1024)
        original(QUALIFIER, QUALIFIER_SHA)
        original(NATIVE, NATIVE_SHA)
        checkpoint(PREP / 'entry-report.json', report)
        # The child compiles bytes from the same descriptor it verified, never
        # executes a later pathname read before checking its script digest.
        worker_path = str(PREP / 'entry.original.py')
        bootstrap = ("import os,stat,hashlib,sys\nfrom pathlib import Path\n"
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
            + " or identity(os.fstat(f))!=identity(s) or identity(os.stat(p.name,dir_fd=d,follow_symlinks=False))!=identity(s):raise RuntimeError('worker script binding differs')\n"
            + "finally:os.close(f);os.close(d)\n"
            + "sys.argv=[str(p),'--worker','--expected-entry-sha'," + repr(script_receipt['sha256']) + "]+sys.argv[1:]\n"
            + "exec(compile(raw,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})\n")
        argv = [sys.executable, '-B', '-s', '-c', bootstrap]
        code = own_worker(argv, env, report)
        worker_raw, worker_receipt = original(PREP / 'worker-report.json')
        worker_report = json.loads(worker_raw)
        report['guarded_worker_report'] = worker_receipt
        qraw, qreceipt = original(OUT / 'report.json')
        qualification = json.loads(qraw)
        report['qualification_report'] = qreceipt
        row = report['worker_custody']
        need(code == 0 and worker_report.get('passed') is True
             and row['original_child_reaped'] and row['custody_retained_until_reap']
             and row.get('group_quiet_before_reap') is True and not row.get('outer_work_budget_exceeded')
             and not row.get('normal_worker_exit_left_live_group_or_observation_errors')
             and not row.get('error') and qualification.get('qualified') is True
             and qualification.get('current_stage') == 'complete' and not qualification.get('error'),
             'qualification result or original worker custody failed')
        after, _, _ = source(DEST)
        need(qualification['source_input'] == bundle['candidate_source_map']
             and qualification['source_tested'] == qualification['source_after'] == after,
             'qualified candidate source binding differs')
        need(set(after) == set(bundle['candidate_source_map'])
             and all(value == bundle['candidate_source_map'][name]
                     for name, value in after.items() if name not in CHANGED),
             'qualified candidate changed inventory or unrelated parent files')
        report['source_after'] = after
        report['guarded_qualification_complete'] = True
        result = 0
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        try:
            if parent_mapping is not None and parent_raw is not None:
                after, after_receipts, _ = source(PARENT)
                after_raw, after_receipt = parent_qualification(after)
                unchanged = after == parent_mapping and after_receipts == parent_receipts \
                    and after_raw == parent_raw and after_receipt == parent_receipt
                report['parent_source_after'] = after_receipts
                report['parent_qualification_after'] = after_receipt
                report['parent_unchanged_after_attempt'] = unchanged
                need(unchanged, 'frozen parent changed during qualification attempt')
            else:
                report['parent_unchanged_after_attempt'] = False
                need(False, 'parent verification did not reach a complete starting binding')
        except BaseException as error:
            result = 1
            report['errors'].append('final parent check: ' + type(error).__name__ + ': ' + str(error))
        try:
            fixed_after = {}
            for key, path, expected in (
                ('bundle', BUNDLE, COMPRESSED_SHA), ('qualifier', QUALIFIER, QUALIFIER_SHA),
                ('host_load_driver', NATIVE, NATIVE_SHA),
                ('entry', Path(__file__).absolute(), report.get('entry', {}).get('sha256')),
            ):
                if key not in report:
                    continue
                _, after = original(path, expected)
                need(after == report[key], 'fixed qualification input changed: ' + key)
                fixed_after[key] = after
            report['fixed_inputs_after'] = fixed_after
        except BaseException as error:
            result = 1
            report['errors'].append('final fixed-input check: ' + type(error).__name__ + ': ' + str(error))
        try:
            continued = verify_continuation_binding()
            need(continued['receipts'] == CONTINUATION_BINDING['receipts'], 'continuation originals changed during r03')
            report['continuation_receipts_after'] = continued['receipts']
        except BaseException as error:
            result = 1
            report['errors'].append('final continuation check: ' + type(error).__name__ + ': ' + str(error))
        report['qualified'] = report['passed'] = result == 0 and not report['errors']
        report['finished_utc'] = utc()
        checkpoint(PREP / 'entry-report.json', report)
        print(json.dumps({'report': str(PREP / 'entry-report.json'), 'qualified': report['qualified'],
                          'worker_reaped': report['worker_custody']['original_child_reaped'],
                          'qualification_output': str(OUT), 'errors': report['errors']}), flush=True)
    return 0 if report['qualified'] else 1


TERMINATION_REQUESTED = False


def termination_handler(signum, _frame):
    global TERMINATION_REQUESTED
    if not TERMINATION_REQUESTED:
        TERMINATION_REQUESTED = True
        raise KeyboardInterrupt('received ' + signal.Signals(signum).name)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, termination_handler)
    signal.signal(signal.SIGINT, termination_handler)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--permit-fd', type=int)
    parser.add_argument('--expected-entry-sha')
    arguments = parser.parse_args()
    CONTINUATION_BINDING = verify_continuation_binding()
    if arguments.worker:
        raise SystemExit(worker(arguments))
    need(arguments.permit_fd is None and arguments.expected_entry_sha is None, 'worker-only arguments refused')
    raise SystemExit(main(arguments))
