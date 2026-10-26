#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One A44 owner-barrier qualification; disabled until the actual fresh window is bound.

The original remote qualifier bytes and its argv/1800-second stage timeouts are
unchanged. Only that loaded module's subprocess reference receives a narrow
facade. Every original cargo stage requires a new complete frozen-r07 host-load
snapshot and 2 GiB memory/disk floors, including format and package-clean.
This is a point-in-time
observation, not an exclusive host lease. A separately-sessioned worker contains
the qualifier; its original parent owns pidfd/waitid/raw-waitpid custody. No
foreign process, agent, SSH key, service, old source or old report is modified.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
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
DEST = BASE / 'source-a44-owner-barrier-r01'
OUT = BASE / 'qualification-a44-owner-barrier-r01'
PREP = BASE / 'a44-owner-barrier-entry-r01'
BUNDLE = BASE / 'tools/a44-owner-barrier-source-r01.json.gz'
QUALIFIER = BASE / 'tools/qualify_runtime_candidate.py'
NATIVE = BASE / 'tools/run_a41_native_validation_r07.py'
TARGET = BASE / 'target'
CARGO = '/home/qian/.cargo/bin/cargo'
BUNDLE_SHA = '985af78d0a1b64069e4ca5d46da9c3afa0ad5007ee074cfa01a92d7e48595312'
BUNDLE_BYTES = 362744
COMPRESSED_SHA = '94eb25f2d7003d3372edaf540de7d6143a431bcdbeff6aa0acb245af58b6a05c'
COMPRESSED_BYTES = 112029
PARENT_Q_SHA = 'ab3481a57c69177d20f4d4feff31543dbc0a32b6f07892a0553879035b928cc9'
PARENT_MAP_SHA = '4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d'
CANDIDATE_MAP_SHA = '80a73b1f41c886c8b7d3d08d8cc6f99356729f979a707bf943bf675592222b6f'
QUALIFIER_SHA = '64efa0da0d22e2ad8d10eb6f8a91ab158a234b331383bbd595e65fc9bd47d1d2'
NATIVE_SHA = '6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9'
CHANGED = frozenset(('src/mcp/runtime/jobs.rs', 'src/mcp/runtime/jobs_output_durability_tests.rs',
    'src/mcp/runtime/jobs_owner_publication_tests.rs'))
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

# Fresh independent qualification quota. No old observer/failed-report binding
# supplies admission. Root must finish its A42 work before separately launching.
FINAL_BINDINGS_READY = True
PROTOCOL = BASE / 'tools/a44-owner-barrier-qualification-r01.protocol.json'
PROTOCOL_SHA = '45185065cf0540296ea722bdfd4f000940338e466a6c936dfd34ca7cdbc5d50b'
PROTOCOL_BYTES = 8615
MEM_MIN_KIB = 2097152
DISK_MIN_BYTES = 2147483648



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
    need(value['schema'] == 'hepta-a43-owner-barrier-source-bundle/v1'
         and value['parent_source'] == str(PARENT)
         and len(value['parent_source_map']) == 165
         and map_sha(value['parent_source_map']) == PARENT_MAP_SHA
         and len(value['candidate_source_map']) == 166
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
        need(gate['clear'], 'A43 owner-barrier cargo stage refused: busy/incomplete/resource-floor host gate; cargo not started')
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
    native = module('a43_owner_barrier_frozen_r07_host_load', NATIVE, nraw)
    qualifier = module('a43_owner_barrier_guarded_fixed_qualifier', QUALIFIER, qraw)
    env, environment = clean_environment()
    # The parent's exec environment is already this exact cleaned environment.
    need(env == dict(os.environ), 'worker inherited environment was not the frozen cleaned environment')
    report = {'schema': 'hepta-a44-owner-barrier-guarded-qualifier-worker/v1', 'started_utc': utc(),
              'passed': False, 'qualifier': qreceipt, 'host_load_driver': nreceipt,
              'execution_description': 'unchanged qualifier bytes under A43 owner-barrier guarded subprocess facade',
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


def verify_protocol_binding():
    # Disabled drafts fail before any directory/file publication or worker.
    need(FINAL_BINDINGS_READY, 'owner-barrier candidate/protocol identities pending; no attempt started')
    for value in (BUNDLE_SHA, COMPRESSED_SHA, CANDIDATE_MAP_SHA, PROTOCOL_SHA):
        need(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value), 'final SHA binding missing')
    need(type(BUNDLE_BYTES) is int and 0 < BUNDLE_BYTES <= 1024 * 1024
         and type(COMPRESSED_BYTES) is int and 0 < COMPRESSED_BYTES <= 1024 * 1024
         and type(PROTOCOL_BYTES) is int and 0 < PROTOCOL_BYTES <= 65536,
         'final bounded input lengths missing')
    raw, receipt = original(PROTOCOL, PROTOCOL_SHA, 65536)
    need(len(raw) == PROTOCOL_BYTES, 'independent qualification protocol length differs')
    value = json.loads(raw)
    need(value.get('schema') == 'hepta-a44-owner-barrier-qualification-protocol/v1'
         and value.get('bindings_ready') is True and value.get('independent_attempt') is True
         and value.get('maximum_attempts') == 1 and value.get('automatic_retry') is False,
         'fresh independent qualification policy differs')
    need(value.get('paths') == {'source': str(DEST), 'qualification': str(OUT), 'entry': str(PREP),
             'target': str(TARGET), 'bundle': str(BUNDLE), 'protocol': str(PROTOCOL)}
         and value.get('parent') == {'source': str(PARENT), 'source_files': 165,
             'source_map_compact_sha256': PARENT_MAP_SHA,
             'qualification_path': str(PARENT_Q), 'qualification_sha256': PARENT_Q_SHA},
         'independent source/parent/output path binding differs')
    need(value.get('candidate') == {'source_files': 166, 'source_map_compact_sha256': CANDIDATE_MAP_SHA,
             'bundle_schema': 'hepta-a43-owner-barrier-source-bundle/v1',
             'changed_files': sorted(CHANGED), 'bundle_json_bytes': BUNDLE_BYTES,
             'bundle_json_sha256': BUNDLE_SHA, 'bundle_gzip_bytes': COMPRESSED_BYTES,
             'bundle_gzip_sha256': COMPRESSED_SHA}, 'candidate bundle binding differs')
    need(value.get('helpers') == {'qualifier_path': str(QUALIFIER), 'qualifier_bytes': 5915,
             'qualifier_sha256': QUALIFIER_SHA, 'host_load_path': str(NATIVE),
             'host_load_bytes': 51497, 'host_load_sha256': NATIVE_SHA}, 'frozen helper binding differs')
    need(value.get('stages') == [{'name': name, 'argv': [CARGO, '+1.95.0'] + tail,
             'timeout_seconds': 1800} for name, tail in STAGES]
         and value.get('budgets') == {'worker_seconds': WORKER_SECONDS,
             'term_seconds': TERM_SECONDS, 'kill_seconds': KILL_SECONDS,
             'operator_outer_seconds': OUTER_OPERATOR_SECONDS}
         and value.get('build_jobs') == 2 and value.get('incremental') == 0,
         'fixed qualifier stage/argv/budget policy differs')
    need(value.get('resource_gate') == {'before_every_stage_including_format_and_clean': True,
             'required_fields_complete': True, 'observation_errors_empty': True,
             'busy_process_names': list(BUSY_NAMES), 'mem_available_kib_min': MEM_MIN_KIB,
             'disk_available_bytes_min': DISK_MIN_BYTES, 'wait_or_retry_when_busy': False}
         and value.get('root_must_finish_a42_work_before_launch') is True
         and value.get('old_r02_reenabled') is False and value.get('reuse_a42_admission_quota') is False,
         'independent scheduling/resource policy differs')
    return raw, receipt


def verify_scheduling_window():
    protocol_raw, _ = original(PROTOCOL, PROTOCOL_SHA, 65536)
    policy = json.loads(protocol_raw)
    binding = policy.get('scheduling_window', {})
    window = BASE / 'a44-release-window-r01/report.json'
    need(policy.get('scheduling_tranche') == 'a44-new-user-continuation-r01'
         and policy.get('previous_window_not_reused_for_admission') is True
         and binding.get('path') == str(window)
         and type(binding.get('sha256')) is str and re.fullmatch(r'[0-9a-f]{64}', binding['sha256'])
         and type(binding.get('bytes')) is int and 0 < binding['bytes'] <= 1024 * 1024,
         'actual A44 scheduling-window binding is missing')
    raw, receipt = original(window, binding['sha256'], 1024 * 1024)
    need(len(raw) == binding['bytes'], 'A44 scheduling-window length differs')
    value = json.loads(raw)
    need(value.get('schema') == 'hepta-a44-release-window-observation/v1'
         and value.get('status') == 'clear_observed' and value.get('passed') is True
         and value.get('clear_observed') is True and value.get('originals_unchanged') is True
         and value.get('errors') == [] and value.get('window_seconds') == 600
         and value.get('interval_seconds') == 30 and value.get('helper_invocations') == 1
         and value.get('scheduling_tranche') == 'a44-new-user-continuation-r01'
         and value.get('previous_failed_tranche_unchanged') is True
         and value.get('previous_window_not_reused_for_admission') is True
         and value.get('automatic_cargo_launch') is False and value.get('automatic_native_query') is False
         and all(value.get(name) == 0 for name in ('agent_requests', 'foreign_signals',
             'foreign_priority_changes', 'automatic_retries')),
         'A44 scheduling window was not a successful read-only terminal observation')
    rows, count = value.get('observations'), value.get('snapshot_calls')
    need(type(rows) is list and type(count) is int and 1 <= count <= 20 and len(rows) == count
         and [row['index'] for row in rows] == list(range(count))
         and rows[-1]['clear'] is True and all(row['clear'] is False for row in rows[:-1])
         and rows[-1]['receipt'] == value.get('successful_snapshot'),
         'A44 scheduling window does not end at its first clear observation')
    return raw, receipt


def main(args):
    protocol_raw, protocol_receipt = verify_protocol_binding()
    window_raw, window_receipt = verify_scheduling_window()
    need(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(os, 'WNOWAIT'),
         'native x230 Linux pidfd/waitid support required')
    os.umask(0o077)
    for path in (DEST, OUT, PREP):
        fresh(path)
    need(not DEST.is_relative_to(PARENT) and not PARENT.is_relative_to(DEST), 'source paths overlap')
    mkdir_new(PREP)
    report = {'schema': 'hepta-a44-owner-barrier-qualification-entry/v1', 'started_utc': utc(), 'passed': False,
        'qualified': False, 'execution_description': 'unchanged qualifier bytes under A43 owner-barrier guarded subprocess facade',
        'source': str(DEST), 'output': str(OUT), 'parent_source': str(PARENT),
        'protocol': protocol_receipt, 'scheduling_window': window_receipt, 'independent_attempt': True,
        'budgets': {'operator_outer_seconds': OUTER_OPERATOR_SECONDS, 'worker_seconds': WORKER_SECONDS,
                    'original_each_qualifier_stage_seconds': 1800, 'term_seconds': TERM_SECONDS,
                    'kill_seconds': KILL_SECONDS},
        'automatic_retry': False, 'agent_accesses': 0, 'ssh_calls': 0, 'service_changes': False,
        'foreign_process_signals': 0, 'benchmark_executions': 0, 'errors': [],
        'worker_custody': {'executed': False, 'execution_count': 0, 'original_child_reaped': False,
                           'signals': [], 'outer_work_budget_exceeded': False},
        'scheduling_scope': 'independent owner-barrier attempt; does not revive old r02 or reuse A42 admission quota',
        'group_scope_limit': 'Only this new session/process group is covered; escaped descendants or host reboot are not proved.'}
    checkpoint(PREP / 'entry-report.json', report)
    parent_mapping = parent_receipts = parent_raw = parent_receipt = None
    result = 1
    try:
        create(PREP / 'protocol.original.json', protocol_raw)
        create(PREP / 'scheduling-window.original.json', window_raw)
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
        original(PROTOCOL, PROTOCOL_SHA, 65536)
        current_window, current_window_receipt = verify_scheduling_window()
        need(current_window == window_raw and current_window_receipt == window_receipt,
             'A44 scheduling window changed before worker permit')
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
                ('protocol', PROTOCOL, PROTOCOL_SHA),
                ('scheduling_window', Path(window_receipt['path']), window_receipt['sha256']),
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
    need(FINAL_BINDINGS_READY, 'disabled owner-barrier qualification draft; no worker or Cargo launch')
    signal.signal(signal.SIGTERM, termination_handler)
    signal.signal(signal.SIGINT, termination_handler)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--permit-fd', type=int)
    parser.add_argument('--expected-entry-sha')
    arguments = parser.parse_args()
    if arguments.worker:
        raise SystemExit(worker(arguments))
    need(arguments.permit_fd is None and arguments.expected_entry_sha is None, 'worker-only arguments refused')
    raise SystemExit(main(arguments))
