#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Frozen Linux-only r07/A43 original-runner business/crash/ABBA experiment.

Requires both complete successful qualifications and the A46 guardian's success.
Only synthetic jobs beneath a fresh output directory are created. Extracted
production Python bodies are preserved verbatim. Perf runs have no fault hooks.
Crash hooks finish the original close/fsync, announce the cut, and block until
the original parent kills that exact unreaped supervisor through its pidfd.
This is not native MCP/SSH acceptance, host reboot, or power-loss evidence.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import statistics
import subprocess
import sys
import time
import types

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
NATIVE = BASE / 'tools/run_a41_native_validation_r07.py'
NATIVE_SHA = '6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9'
R07_Q = BASE / 'qualification-r07-recovery-only/report.json'
A43_Q = BASE / 'qualification-a46-owner-barrier-r01/report.json'
A46_ENTRY = BASE / 'a46-owner-barrier-entry-r01/entry-report.json'
R07_MAP = '4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d'
A43_INPUT_MAP = '80a73b1f41c886c8b7d3d08d8cc6f99356729f979a707bf943bf675592222b6f'
ORDER = ('r07', 'a43', 'a43', 'r07')
CONCURRENCY = (1, 4)
JOBS_PER_CELL = 16
JOB_SECONDS = 10
CLIENT_SECONDS = 10
TERM_SECONDS = KILL_SECONDS = 30
CORRECTNESS_SECONDS = 400
PERFORMANCE_SECONDS = 300
CUTS = ('after_owner-intent.json_close', 'after_started.json_close', 'after_final_owner_directory_fsync')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
BUSY = ('cargo', 'cargo-clippy', 'clippy-driver', 'rustc', 'heptabao_server')

# A real fixture effect is an exclusive durable file create. The first stdout
# event precedes that create, so an accidental second business attempt remains
# visible even if O_EXCL prevents a second successful effect.
BUSINESS = r'''
import hashlib,json,os,pathlib,resource,sys,time
job=pathlib.Path(sys.argv[1]); code=int(sys.argv[2]); token=sys.argv[3]
started=time.monotonic_ns()
print(json.dumps({'event':'business_start','pid':os.getpid(),'token':token,'monotonic_ns':started}),flush=True)
effect={'token':token,'pid':os.getpid(),'start_monotonic_ns':started,
        'payload_sha256':hashlib.sha256(b'hepta-a47-real-business-effect').hexdigest()}
fd=os.open(job/'effect.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
with os.fdopen(fd,'w') as stream:
    json.dump(effect,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
directory=os.open(job,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:os.fsync(directory)
finally:os.close(directory)
usage=resource.getrusage(resource.RUSAGE_SELF)
print(json.dumps({'event':'business_complete','pid':os.getpid(),'token':token,
    'monotonic_ns':time.monotonic_ns(),'exit_code':code,
    'self_rusage':{'utime_seconds':usage.ru_utime,'stime_seconds':usage.ru_stime,'maxrss_kib':usage.ru_maxrss}}),flush=True)
sys.exit(code)
'''

# Every arm uses this same startup gate. execv keeps the original child's PID
# and Linux start identity; the extra fixed Python startup is included in all
# reported task/cell measurements. This is not a fault hook in performance runs.
# If parent binding fails, closing the write end produces EOF before any target
# script runs. The child inherits blocked termination signals only until GO.
START_GATE = r'''
import json,os,signal,sys
permit_fd=int(sys.argv[1])
try:permit=os.read(permit_fd,2)
finally:os.close(permit_fd)
if permit!=b'G':raise SystemExit(126)
signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
argv=json.loads(sys.argv[2])
if not isinstance(argv,list) or len(argv)<4 or argv[:3]!=[sys.executable,'-I','-S']:
    raise SystemExit('invalid bound Python target')
os.execv(argv[0],argv)
'''


def need(value, message):
    if not value:
        raise RuntimeError(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def compact_map(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_file(path, cap=16 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'direct file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap,
             'bounded single-link regular file required: ' + str(path))
        parts, size = [], 0
        while size <= cap:
            raw = os.read(fd, min(1024 * 1024, cap + 1 - size))
            if not raw:
                break
            parts.append(raw)
            size += len(raw)
        need(size == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'file changed during read: ' + str(path))
        raw = b''.join(parts)
        return raw, {'path': str(path), 'bytes': size, 'sha256': digest(raw), 'identity': list(stamp(before))}
    finally:
        os.close(fd)


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)


def save(path, value):
    temporary = path.with_name(path.name + '.next')
    create(temporary, canonical(value))
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)


def native_module():
    raw, receipt = read_file(NATIVE)
    need(len(raw) == 51497 and digest(raw) == NATIVE_SHA, 'original native helper differs')
    module = types.ModuleType('a47_original_qualification_and_host_observer')
    module.__file__ = str(NATIVE)
    exec(compile(raw, str(NATIVE), 'exec'), module.__dict__)
    return module, receipt


def rust_string(source, name):
    prefix = 'const ' + name + ': &str = r#"'
    need(source.count(prefix) == 1, 'ambiguous production source constant: ' + name)
    tail = source.split(prefix, 1)[1]
    need('"#;' in tail, 'missing raw-string boundary: ' + name)
    return tail.split('"#;', 1)[0]


def extract(bundle, out):
    source = Path(bundle['source']) / 'src/mcp/runtime/jobs.rs'
    raw, receipt = read_file(source)
    need(receipt['sha256'] == bundle['source_map']['src/mcp/runtime/jobs.rs'], 'jobs source binding differs')
    text = raw.decode('utf-8')
    private, start, status = (rust_string(text, key) for key in ('PRIVATE_DIRECTORY_CODE', 'START_CODE', 'STATUS_CODE'))
    beginning, ending = "runner = r'''", "\n'''\nrunner_path"
    need(start.count(beginning) == 1 and start.count(ending) == 1, 'runner extraction boundaries differ')
    runner = start.split(beginning, 1)[1].split(ending, 1)[0]
    bodies = {'private': private, 'start': start, 'status': status, 'runner_body': runner}
    paths = {}
    for name, body in (('runner', private + '\n' + runner + '\n'),
                       ('launcher', 'REMOTE_DIRECTORY_SOURCE = ' + json.dumps(private) + '\nexec(REMOTE_DIRECTORY_SOURCE)\n' + start),
                       ('status', private + '\n' + status)):
        path = out / (bundle['label'] + '-' + name + '.py')
        create(path, body.encode())
        paths[name] = {'path': str(path), 'sha256': digest(body.encode())}
    return {'jobs_source': receipt, 'body_sha256': {k: digest(v.encode()) for k, v in bodies.items()},
            'paths': paths, 'bodies': bodies}


def host_gate(native, out, name):
    snapshot = native.host_load()
    matching = [row for row in snapshot['processes'] if row['comm'] in BUSY and row['state'] not in ('Z', 'X', 'x')]
    values = re.findall(r'^MemAvailable:\s+(\d+)\s+kB\s*$', snapshot['meminfo'], re.MULTILINE)
    mem = int(values[0]) if len(values) == 1 else -1
    fs = os.statvfs(out)
    disk = fs.f_bavail * fs.f_frsize
    gate = {'snapshot': snapshot, 'matching_live_processes': matching, 'mem_available_kib': mem,
            'disk_available_bytes': disk, 'thresholds': {'mem_available_kib': 2097152, 'disk_available_bytes': 2147483648}}
    gate['clear'] = bool(snapshot['required_fields_present'] and not snapshot['errors'] and not matching
                         and mem >= 2097152 and disk >= 2147483648)
    create(out / (name + '.host-gate.json'), canonical(gate))
    need(gate['clear'], 'fresh complete host/resource gate refused: ' + name)


def process_info(pid):
    text = Path('/proc', str(pid), 'stat').read_text()
    closing = text.rfind(') ')
    fields = text[closing + 2:].split()
    return {'pid': pid, 'ppid': int(fields[1]), 'state': fields[0], 'birth_ticks': int(fields[19]),
            'cpu_ticks': int(fields[11]) + int(fields[12]),
            'rss_kib': int(fields[21]) * os.sysconf('SC_PAGE_SIZE') // 1024}


def tree_sample(task):
    owner = process_info(task['child'].pid)
    need(owner['birth_ticks'] == task['birth'], 'original supervisor identity changed')
    rows, vanished = [owner], 0
    try:
        children = Path('/proc', str(owner['pid']), 'task', str(owner['pid']), 'children').read_text().split()
    except FileNotFoundError:
        children = []
    need(len(children) <= 16, 'unexpected fixture child count')
    for pid in children:
        try:
            row = process_info(int(pid))
            if row['ppid'] == owner['pid']:
                rows.append(row)
        except (FileNotFoundError, ProcessLookupError):
            vanished += 1
    return {'monotonic_ns': time.monotonic_ns(), 'processes': rows,
            'sum_rss_kib': sum(row['rss_kib'] for row in rows), 'vanished_during_observation': vanished}


class TaskStartError(RuntimeError):
    def __init__(self, task, error):
        self.task = task
        super().__init__(type(error).__name__ + ': ' + str(error))


def new_task(argv, directory, name, input_path=None, cut=None):
    task = {'row': {'argv': list(argv), 'name': name, 'started_monotonic_ns': time.monotonic_ns(),
                    'signals': [], 'reaped': False, 'timed_out': False, 'sampled_tree_peak_rss_kib': 0,
                    'tree_samples': [], 'cut': cut, 'go_may_have_been_sent': False,
                    'go_sent': False, 'startup_gate_sha256': digest(START_GATE.encode()),
                    'startup_gate_overhead_included': True},
            'output': None, 'error': None, 'event_fd': None, 'event_bytes': b'',
            'child': None, 'handle': None, 'birth': None, 'deadline': time.monotonic() + CLIENT_SECONDS,
            'cleanup_started': None, 'kill_sent': False, 'next_sample': 0}
    parent_fds, incoming = {}, None
    try:
        try:
            task['output'] = open(directory / (name + '.stdout'), 'xb', buffering=0)
            task['error'] = open(directory / (name + '.stderr'), 'xb', buffering=0)
            incoming = open(input_path, 'rb') if input_path else None
            permit_read, permit_write = os.pipe2(os.O_CLOEXEC)
            parent_fds.update(permit_read=permit_read, permit_write=permit_write)
            inherited = [permit_read]
            if cut:
                read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
                task['event_fd'] = read_fd
                parent_fds['event_write'] = write_fd
                inherited.append(write_fd)
                task['row']['argv'] = list(argv) + ['--event-fd', str(write_fd)]
            spawn_argv = [sys.executable, '-I', '-S', '-c', START_GATE,
                          str(permit_read), json.dumps(task['row']['argv'])]
            task['row']['spawn_argv'] = spawn_argv
            prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
            try:
                child = subprocess.Popen(spawn_argv, cwd=directory, env=ENV,
                    stdin=incoming if incoming is not None else subprocess.DEVNULL,
                    stdout=task['output'], stderr=task['error'], pass_fds=tuple(inherited), start_new_session=True)
                task['child'] = child
                task['row']['pid'] = child.pid
                task['handle'] = os.pidfd_open(child.pid, 0)
                task['birth'] = process_info(child.pid)['birth_ticks']
                task['row'].update(birth_ticks=task['birth'], pidfd_opened=True,
                                   original_identity_bound_before_go=True)
            finally:
                # A pending signal delivered during mask restoration is caught
                # by the outer try with the original child already registered.
                signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
            task['row']['go_may_have_been_sent'] = True
            need(os.write(permit_write, b'G') == 1, 'incomplete original-child GO write')
            task['row'].update(go_sent=True, go_sent_monotonic_ns=time.monotonic_ns())
        finally:
            setup_errors = []
            # Closing GO without a write makes the same new Python child exit;
            # it can never reach a paused fault fixture without parent custody.
            for key, fd in list(parent_fds.items()):
                del parent_fds[key]
                try: os.close(fd)
                except BaseException as error:
                    setup_errors.append(key + ': ' + type(error).__name__ + ': ' + str(error))
            if incoming is not None:
                try: incoming.close()
                except BaseException as error:
                    setup_errors.append('stdin: ' + type(error).__name__ + ': ' + str(error))
            if setup_errors:
                task['row']['setup_close_errors'] = setup_errors
                raise RuntimeError('parent-side startup descriptor cleanup failed')
        return task
    except BaseException as error:
        task['row']['launch_error'] = type(error).__name__ + ': ' + str(error)
        raise TaskStartError(task, error) from error


def signal_original(task, signum, reason):
    child, row = task['child'], task['row']
    need(not row['reaped'] and task['handle'] is not None, 'original pidfd custody missing')
    observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if observed is not None:
        need(observed.si_pid == child.pid, 'unexpected waitid identity before signal')
        return False
    need(process_info(child.pid)['birth_ticks'] == task['birth'], 'original identity changed before signal')
    signal.pidfd_send_signal(task['handle'], signum)
    row['signals'].append({'signal': signal.Signals(signum).name, 'reason': reason,
                           'target': 'original_unreaped_fixture_supervisor_pidfd', 'monotonic_ns': time.monotonic_ns()})
    return True


def reap_if_exited(task):
    child, row = task['child'], task['row']
    need(not row['reaped'], 'original child was already reaped')
    observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if observed is not None:
        need(observed.si_pid == child.pid, 'unexpected original-child waitid identity')
        waited, status, usage = os.wait4(child.pid, os.WNOHANG)
        need(waited == child.pid, 'raw wait4 did not reap the observed original child')
        child.returncode = os.waitstatus_to_exitcode(status)
        row.update(reaped=True, actual_wait4_pid=waited, raw_wait_status=status, returncode=child.returncode,
                   finished_monotonic_ns=time.monotonic_ns(),
                   wait4_rusage={key: getattr(usage, key) for key in
                        ('ru_utime', 'ru_stime', 'ru_maxrss', 'ru_minflt', 'ru_majflt', 'ru_inblock', 'ru_oublock', 'ru_nvcsw', 'ru_nivcsw')})
        row['elapsed_ms'] = (row['finished_monotonic_ns'] - row['started_monotonic_ns']) / 1e6
        return True
    return False


def collect(task, now):
    child, row = task['child'], task['row']
    if task['event_fd'] is not None and not row.get('cut_observation'):
        try: task['event_bytes'] += os.read(task['event_fd'], 4096)
        except BlockingIOError: pass
        need(len(task['event_bytes']) <= 4096, 'fault observation exceeded bound')
        if b'\n' in task['event_bytes']:
            event = json.loads(task['event_bytes'])
            need(event['pid'] == child.pid and event['birth_ticks'] == task['birth']
                 and event['cut'] == row['cut'], 'cut is not from this original supervisor')
            row['cut_observation'] = event
            row['cut_sigkill_sent'] = signal_original(task, signal.SIGKILL, 'declared_prebusiness_cut')
    if reap_if_exited(task):
        return True
    if now >= task['next_sample'] and len(row['tree_samples']) < 1024:
        sample = tree_sample(task)
        row['tree_samples'].append(sample)
        row['sampled_tree_peak_rss_kib'] = max(row['sampled_tree_peak_rss_kib'], sample['sum_rss_kib'])
        task['next_sample'] = now + .02
    if now >= task['deadline'] and task['cleanup_started'] is None:
        row['timed_out'] = True
        task['cleanup_started'] = now
        signal_original(task, signal.SIGTERM, 'fixed_client_deadline')
    if task['cleanup_started'] is not None:
        elapsed = now - task['cleanup_started']
        if elapsed >= TERM_SECONDS and not task['kill_sent']:
            task['kill_sent'] = signal_original(task, signal.SIGKILL, 'bounded_cleanup')
        need(elapsed < TERM_SECONDS + KILL_SECONDS, 'original child not reaped within fixed cleanup window')
    return False


def close_task(task):
    errors = []
    for key in ('output', 'error'):
        stream = task.get(key)
        if stream is None:
            continue
        if stream.closed:
            task[key] = None
            continue
        for operation, action in (('flush', stream.flush), ('fsync', lambda: os.fsync(stream.fileno()))):
            try: action()
            except BaseException as error:
                errors.append({'resource': key, 'operation': operation,
                               'error': type(error).__name__ + ': ' + str(error)})
        try: stream.close()
        except BaseException as error:
            errors.append({'resource': key, 'operation': 'close',
                           'error': type(error).__name__ + ': ' + str(error)})
        if stream.closed:
            task[key] = None
    for key in ('handle', 'event_fd'):
        fd = task.get(key)
        if fd is None:
            continue
        # Never retry a close by descriptor number: Linux may have already
        # released it even when close reported an error.
        task[key] = None
        try: os.close(fd)
        except BaseException as error:
            errors.append({'resource': key, 'operation': 'close',
                           'error': type(error).__name__ + ': ' + str(error)})
    if errors:
        task['row'].setdefault('close_errors', []).extend(errors)
    return errors


def run_tasks(factories, concurrency, phase_deadline):
    pending, results, live = list(factories), [], []
    failed = None
    try:
        while pending or live:
            need(time.monotonic() < phase_deadline, 'fixed phase deadline exceeded')
            while pending and len(live) < concurrency:
                live.append(pending.pop(0)())
            for task in list(live):
                if collect(task, time.monotonic()):
                    live.remove(task)
                    results.append(task['row'])
                    closing = close_task(task)
                    need(not closing, 'fixture log synchronization/descriptor close failed')
                    if task['row']['timed_out']:
                        raise RuntimeError('fixed client deadline failed; comparison stops without retry')
            if live: time.sleep(.002)
    except BaseException as error:
        failed = type(error).__name__ + ': ' + str(error)
        if isinstance(error, TaskStartError):
            if error.task['child'] is None:
                results.append(error.task['row']); close_task(error.task)
            else:
                live.append(error.task)
        # Only original pidfd-held children are signalled. No enumerated PID or
        # foreign group is adopted. ECHILD is never converted to exit zero.
        for task in live:
            try:
                if task['cleanup_started'] is None:
                    task['cleanup_started'] = time.monotonic()
                    if task['row'].get('go_may_have_been_sent'):
                        signal_original(task, signal.SIGTERM, 'harness_failure')
                    else:
                        task['row']['cleanup_method'] = 'GO pipe EOF; original target script never admitted'
            except BaseException as cleanup:
                task['row']['custody_error'] = type(cleanup).__name__ + ': ' + str(cleanup)
        for task in live:
            try:
                if not task['row'].get('go_may_have_been_sent'):
                    until = task['cleanup_started'] + TERM_SECONDS
                    while not reap_if_exited(task):
                        need(time.monotonic() < until, 'unadmitted original child did not exit after GO EOF')
                        time.sleep(.01)
                    task['row']['unadmitted_child_reaped_without_signal'] = True
                elif task['row'].get('custody_error'):
                    # Still observe an already terminal direct child. Unknown
                    # pidfd/start custody never authorizes a substitute signal.
                    reap_if_exited(task)
                else:
                    while not collect(task, time.monotonic()): time.sleep(.01)
            except BaseException as cleanup:
                task['row']['cleanup_error'] = type(cleanup).__name__ + ': ' + str(cleanup)
            finally:
                results.append(task['row']); close_task(task)
    return {'passed': failed is None, 'error': failed, 'tasks': results, 'unexecuted': len(pending)}


def fixture(root, name, arm, exit_code):
    directory = root / name
    directory.mkdir(mode=0o700)
    state = directory / 'state'; jobs = state / 'jobs'; job = jobs / 'job'
    for path in (state, jobs, job): path.mkdir(mode=0o700)
    token = hashlib.sha256(str(directory).encode()).hexdigest()
    req = {'job_id': 'job', 'job_dir': str(job), 'launch_nonce': token[:32],
           'request_fingerprint': token, 'terminal_publication_protocol': 1,
           'executable': sys.executable, 'args': ['-I', '-S', '-c', BUSINESS, str(job), str(exit_code), token],
           'execution_mode': 'operator', 'timeout_seconds': JOB_SECONDS, 'env': {},
           'unit': 'hepta-a47-' + token[:16], 'default_cwd': str(directory)}
    create(job / 'request.json', canonical(req))
    info = job.stat()
    binding = {'device': info.st_dev, 'inode': info.st_ino, 'job_id': req['job_id'],
               'launch_nonce': req['launch_nonce'], 'request_fingerprint': req['request_fingerprint']}
    return {'directory': directory, 'job': job, 'req': req, 'binding': binding,
            'arm': arm, 'expected_exit': exit_code, 'token': token}


def runner_factory(fx, script, name='original', cut=None):
    def launch():
        argv = [sys.executable, '-I', '-S', script['paths']['runner']['path'], str(fx['job']),
                json.dumps(fx['binding']), 'detached']
        if cut:
            argv = [sys.executable, '-I', '-S', str(Path(__file__).absolute()), '--hooked-runner',
                    '--runner', script['paths']['runner']['path'], '--runner-sha', script['paths']['runner']['sha256'],
                    '--job', str(fx['job']), '--binding', json.dumps(fx['binding']), '--cut', cut,
                    '--owner-directory-sync-count', '2' if fx['arm'] == 'r07' else '1']
        return new_task(argv, fx['directory'], name, cut=cut)
    return launch


def observe_result(fx, task):
    files = {}
    for name in ('request.json', 'owner-intent.json', 'started.json', 'child.json', 'exit.json',
                 'exit.witness.json', 'stdout.log', 'stderr.log', 'effect.json'):
        path = fx['job'] / name
        if path.exists():
            raw, receipt = read_file(path)
            files[name] = {'receipt': receipt, 'text': raw.decode('utf-8')}
    events = [json.loads(line) for line in files.get('stdout.log', {}).get('text', '').splitlines()]
    starts = [row for row in events if row.get('event') == 'business_start']
    ends = [row for row in events if row.get('event') == 'business_complete']
    terminal = json.loads(files['exit.json']['text']) if 'exit.json' in files else None
    witness = json.loads(files['exit.witness.json']['text']) if 'exit.witness.json' in files else None
    row = {'files': files, 'business_starts': starts, 'business_completions': ends,
           'effect_exists': 'effect.json' in files, 'terminal': terminal, 'witness': witness}
    if starts:
        row['submit_to_business_start_ms'] = (starts[0]['monotonic_ns'] - task['started_monotonic_ns']) / 1e6
    if ends:
        row['submit_to_business_completion_ms'] = (ends[0]['monotonic_ns'] - task['started_monotonic_ns']) / 1e6
    if not task['cut']:
        row['passed'] = bool(task['reaped'] and not task['timed_out'] and not task.get('close_errors')
            and task['returncode'] == fx['expected_exit']
            and len(starts) == len(ends) == 1 and starts[0]['token'] == ends[0]['token'] == fx['token']
            and ends[0]['exit_code'] == fx['expected_exit'] and row['effect_exists']
            and terminal is not None and terminal.get('exit_code') == fx['expected_exit']
            and terminal.get('output_complete') is True and terminal.get('output_durable') is True
            and witness is not None and witness.get('exit_sha256') == files['exit.json']['receipt']['sha256'])
    else:
        row['passed'] = bool(task['reaped'] and not task['timed_out'] and not task.get('close_errors')
            and task['returncode'] == -signal.SIGKILL
            and task.get('cut_sigkill_sent') is True and task.get('cut_observation')
            and not starts and not ends and not row['effect_exists'] and terminal is None)
    return row


def correctness_case(fx, script, cut, deadline, row):
    original = run_tasks([runner_factory(fx, script, cut=cut)], 1, deadline)
    row['original'] = original
    need(original['passed'] and len(original['tasks']) == 1, 'original fixture supervisor failed')
    observed = observe_result(fx, original['tasks'][0])
    row['observed_original'] = observed
    need(observed['passed'], 'actual business/kill evidence failed')
    replay = run_tasks([runner_factory(fx, script, name='restart')], 1, deadline)
    row['restart'] = replay
    need(replay['passed'] and len(replay['tasks']) == 1 and replay['tasks'][0]['returncode'] != 0,
         'original job runner restart did not refuse')
    restart_error = (fx['directory'] / 'restart.stderr').read_text()
    need('workload must not be replayed' in restart_error, 'restart refusal is not the original owner fence')
    create(fx['directory'] / 'launcher-input.json', canonical(fx['req']))
    launcher = run_tasks([lambda: new_task([sys.executable, '-I', '-S', script['paths']['launcher']['path']],
                         fx['directory'], 'same-key', fx['directory'] / 'launcher-input.json')], 1, deadline)
    row['same_key'] = launcher
    need(launcher['passed'] and len(launcher['tasks']) == 1, 'same-key reconciliation observation failed')
    if cut:
        need(launcher['tasks'][0]['returncode'] != 0 and 'ambiguous prior launch' in
             (fx['directory'] / 'same-key.stderr').read_text(), 'uncertain same-key launch did not refuse')
    else:
        reused = json.loads((fx['directory'] / 'same-key.stdout').read_text())
        need(launcher['tasks'][0]['returncode'] == 0 and reused.get('reused_remote') is True,
             'completed original key was not reconciled')
    status_input = {key: fx['req'][key] for key in ('job_id', 'job_dir', 'unit')}
    status_input['wait_seconds'] = 0
    create(fx['directory'] / 'status-input.json', canonical(status_input))
    status_run = run_tasks([lambda: new_task([sys.executable, '-I', '-S', script['paths']['status']['path']],
                           fx['directory'], 'status', fx['directory'] / 'status-input.json')], 1, deadline)
    row['status_run'] = status_run
    need(status_run['passed'] and len(status_run['tasks']) == 1, 'status observer custody failed')
    if status_run['tasks'][0]['returncode'] != 0:
        row['status_observation_error'] = (fx['directory'] / 'status.stderr').read_text()
        row['attribution_limit'] = 'An original status parser failure is retained, not silently treated as a new A43 regression or a successful Unknown result.'
        raise RuntimeError('original status script returned an error; original evidence retained')
    status_value = json.loads((fx['directory'] / 'status.stdout').read_text())
    row['status'] = status_value
    if cut:
        need(status_value.get('state') in ('owner_unknown', 'finalizing', 'lost')
             and status_value.get('automatic_retry') is False, 'crash status is not conservative')
    else:
        need(status_value.get('exit_code') == fx['expected_exit']
             and status_value.get('state') == ('succeeded' if fx['expected_exit'] == 0 else 'failed')
             and status_value.get('terminal_publication_confirmed') is True, 'native terminal/status exit differs')
    after = observe_result(fx, original['tasks'][0])
    need(after['passed'] and after['files'] == observed['files'], 'same original job changed or business replayed')
    row.update(passed=True, original_job_files_unchanged=True)
    return row


def hook_child(args):
    raw, _ = read_file(Path(args.runner))
    need(digest(raw) == args.runner_sha, 'fault runner source changed')
    job = Path(args.job)
    info = job.stat(); identity = (info.st_dev, info.st_ino)
    real_open, real_fdopen, real_sync = os.open, os.fdopen, os.fsync
    real_popen = subprocess.Popen
    owners = {}
    directory_syncs = 0
    popen_calls = []

    def stop_at(cut):
        if cut != args.cut: return
        need(not popen_calls, 'declared cut occurred after a process launch; no kill notification')
        row = {'cut': cut, 'pid': os.getpid(), 'birth_ticks': process_info(os.getpid())['birth_ticks'],
               'monotonic_ns': time.monotonic_ns(), 'observed_popen_calls_before_cut': len(popen_calls),
               'completed_owner_directory_syncs': directory_syncs}
        encoded = json.dumps(row).encode() + b'\n'
        need(os.write(args.event_fd, encoded) == len(encoded), 'partial fault notification')
        while True: signal.pause()

    def opened(path, flags, *values, **kwargs):
        fd = real_open(path, flags, *values, **kwargs)
        owners.pop(fd, None)
        if Path(path).name in ('owner-intent.json', 'started.json') and flags & os.O_EXCL and flags & os.O_CREAT:
            owners[fd] = Path(path).name
        return fd

    class OwnerStream:
        def __init__(self, stream, name): self.stream, self.name = stream, name
        def __getattr__(self, name): return getattr(self.stream, name)
        def __enter__(self): return self
        def __exit__(self, *_):
            self.stream.close()
            stop_at('after_' + self.name + '_close')
            return False

    def fdopened(fd, *values, **kwargs):
        stream = real_fdopen(fd, *values, **kwargs)
        return OwnerStream(stream, owners[fd]) if fd in owners else stream

    def synced(fd):
        nonlocal directory_syncs
        before = os.fstat(fd)
        result = real_sync(fd)
        if stat.S_ISDIR(before.st_mode) and (before.st_dev, before.st_ino) == identity:
            directory_syncs += 1
            if directory_syncs == args.owner_directory_sync_count:
                stop_at('after_final_owner_directory_fsync')
        return result

    def popen(*values, **kwargs):
        popen_calls.append({'monotonic_ns': time.monotonic_ns()})
        return real_popen(*values, **kwargs)

    os.open, os.fdopen, os.fsync = opened, fdopened, synced
    subprocess.Popen = popen
    sys.argv = [args.runner, args.job, args.binding, 'detached']
    exec(compile(raw, args.runner, 'exec'), {'__name__': '__main__', '__file__': args.runner})


def main(args):
    need(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(os, 'wait4')
         and hasattr(signal, 'pidfd_send_signal'), 'Linux original-owner pidfd/raw wait4 support required')
    os.umask(0o077)
    capability = os.pidfd_open(os.getpid(), 0)
    os.close(capability)
    out = args.out
    need(out.is_absolute() and out.parent == BASE and out.name.startswith('a47-owner-')
         and out.parent.resolve(strict=True) == out.parent and not os.path.lexists(out), 'fresh A47 output required')
    native, helper = native_module()
    out.mkdir(mode=0o700)
    report = {'schema': 'hepta-a47-original-owner-lifecycle/v1', 'started_utc': utc(), 'passed': False,
              'helper': helper, 'scope': 'Linux extracted original supervisor/launcher/status and synthetic local effects; not native MCP, SSH, multi-host, production adoption, reboot or power loss',
              'plan': {'order': list(ORDER), 'concurrency': list(CONCURRENCY), 'jobs_per_cell': JOBS_PER_CELL,
                       'measured_jobs': 128, 'job_timeout_seconds': JOB_SECONDS, 'client_wait_seconds': CLIENT_SECONDS,
                       'correctness_seconds': CORRECTNESS_SECONDS, 'performance_seconds': PERFORMANCE_SECONDS,
                       'cleanup_term_seconds': TERM_SECONDS, 'cleanup_kill_seconds': KILL_SECONDS,
                       'startup_gate': {'sha256': digest(START_GATE.encode()),
                                        'same_pid_exec_after_parent_identity_binding': True,
                                        'eof_before_go_exits_without_target_execution': True,
                                        'fixed_extra_startup_included_in_both_arms': True,
                                        'performance_fault_hooks': False},
                       'correctness_cases_per_arm': ['exit-0', 'exit-7', *CUTS]},
              'automatic_retries': 0, 'service_changes': 0, 'foreign_signals': 0,
              'correctness': [], 'performance': [], 'errors': [], 'planned_measured': 128,
              'attempted_measured': 0, 'successful_measured': 0, 'failed_measured': 0}
    bundles, scripts = {}, {}
    save(out / 'report.json', report)
    try:
        entry_raw, entry_receipt = read_file(A46_ENTRY)
        entry = json.loads(entry_raw)
        need(entry.get('schema') == 'hepta-a46-owner-barrier-qualification-entry/v1'
             and entry.get('qualified') is True and entry.get('passed') is True
             and entry.get('guarded_qualification_complete') is True
             and entry.get('parent_unchanged_after_attempt') is True and not entry.get('errors'),
             'A43 A46 qualification is not complete; no business fixture admitted')
        bundles = {label: native.load_qualification(path, label, out) for label, path in (('r07', R07_Q), ('a43', A43_Q))}
        need(compact_map(bundles['r07']['source_map']) == R07_MAP, 'r07 source differs')
        candidate_q = json.loads(read_file(A43_Q)[0])
        need(compact_map(candidate_q['source_input']) == A43_INPUT_MAP
             and entry['source_after'] == bundles['a43']['source_map'], 'qualified candidate is not original A43')
        scripts = {label: extract(bundle, out) for label, bundle in bundles.items()}
        need(scripts['r07']['bodies']['private'] == scripts['a43']['bodies']['private']
             and scripts['r07']['bodies']['status'] == scripts['a43']['bodies']['status'], 'non-owner helper bodies differ')
        report['inputs'] = bundles
        report['a46_entry'] = entry_receipt
        report['script'] = read_file(Path(__file__).absolute())[1]
        report['extracted_sources'] = {label: {k: v for k, v in value.items() if k != 'bodies'} for label, value in scripts.items()}
        create(out / 'frozen-plan.json', canonical({'plan': report['plan'], 'inputs': bundles,
               'a46_entry': entry_receipt, 'extracted_sources': report['extracted_sources'], 'script': report['script']}))
        cases = out / 'cases'; cases.mkdir(mode=0o700)
        correct_deadline = time.monotonic() + CORRECTNESS_SECONDS
        for arm in ('r07', 'a43'):
            host_gate(native, out, 'correctness-' + arm)
            for index, (code, cut) in enumerate(((0, None), (7, None), *((0, item) for item in CUTS))):
                fx = fixture(cases, arm + '-correctness-' + str(index), arm, code)
                result = {'arm': arm, 'case': cut or ('exit-' + str(code)), 'passed': False,
                          'fixture': str(fx['directory'])}
                try:
                    correctness_case(fx, scripts[arm], cut, correct_deadline, result)
                except BaseException as error:
                    result['error'] = type(error).__name__ + ': ' + str(error)
                create(fx['directory'] / 'case-report.json', canonical(result))
                report['correctness'].append(result); save(out / 'report.json', report)
                need(result['passed'], 'correctness failed; no subsequent comparison starts')
        perf_deadline = time.monotonic() + PERFORMANCE_SECONDS
        for round_index, arm in enumerate(ORDER):
            for concurrency in CONCURRENCY:
                name = 'round-' + str(round_index) + '-' + arm + '-c' + str(concurrency)
                host_gate(native, out, name)
                group = out / name; group.mkdir(mode=0o700)
                fixtures = [fixture(group, 'job-' + str(index), arm, 0) for index in range(JOBS_PER_CELL)]
                parent_before = resource.getrusage(resource.RUSAGE_SELF)
                started = time.monotonic_ns()
                execution = run_tasks([runner_factory(fx, scripts[arm]) for fx in fixtures], concurrency, perf_deadline)
                completed = time.monotonic_ns()
                parent_after = resource.getrusage(resource.RUSAGE_SELF)
                create(group / 'execution.original.json', canonical(execution))
                rows = []
                for task in execution['tasks']:
                    # The original runner argv binds its exact job directory.
                    job = Path(task['argv'][4])
                    fx = next(item for item in fixtures if item['job'] == job)
                    try:
                        observed = observe_result(fx, task)
                    except BaseException as error:
                        observed = {'passed': False, 'error': type(error).__name__ + ': ' + str(error),
                                    'fixture': str(fx['directory'])}
                    row = {'task': task, 'observed': observed}
                    rows.append(row)
                successes = sum(row['observed']['passed'] for row in rows)
                failures = len(rows) - successes
                cell = {'round': round_index, 'arm': arm, 'concurrency': concurrency,
                        'planned': JOBS_PER_CELL, 'attempted': len(rows), 'successes': successes,
                        'failures': failures, 'unexecuted': JOBS_PER_CELL - len(rows),
                        'seconds': (completed - started) / 1e9, 'execution': execution, 'jobs': rows}
                cell['jobs_per_second'] = successes / cell['seconds']
                cell['harness_cpu_seconds'] = (parent_after.ru_utime + parent_after.ru_stime
                                               - parent_before.ru_utime - parent_before.ru_stime)
                cell['wait4_cpu_seconds'] = sum(row['task'].get('wait4_rusage', {}).get('ru_utime', 0)
                    + row['task'].get('wait4_rusage', {}).get('ru_stime', 0) for row in rows)
                cell['wait4_maxrss_kib'] = max((row['task'].get('wait4_rusage', {}).get('ru_maxrss', 0) for row in rows), default=0)
                cell['sampled_tree_peak_rss_kib'] = max((row['task']['sampled_tree_peak_rss_kib'] for row in rows), default=0)
                cell['resource_scope'] = 'Original supervisor raw wait4 rusage, separately recorded parent harness CPU, business self-rusage in original output, and bounded sampled owner/direct-child RSS; peak RSS is not a continuously observed concurrent-group maximum. Cell wall time includes task launch/collection and harness stdout/stderr synchronization; fixture preparation and report serialization are outside it.'
                report['performance'].append(cell)
                report['attempted_measured'] += len(rows); report['successful_measured'] += successes; report['failed_measured'] += failures
                save(out / 'report.json', report)
                need(execution['passed'] and successes == JOBS_PER_CELL and failures == 0,
                     'fixed complete comparison failed; no retry or best-run selection')
        report['comparison'] = {}
        for concurrency in CONCURRENCY:
            arms = {}
            for arm in ('r07', 'a43'):
                cells = [row for row in report['performance'] if row['arm'] == arm and row['concurrency'] == concurrency]
                all_jobs = [job for cell in cells for job in cell['jobs']]
                arms[arm] = {'jobs': sum(cell['successes'] for cell in cells),
                             'pooled_jobs_per_second': sum(cell['successes'] for cell in cells) / sum(cell['seconds'] for cell in cells),
                             'whole_lifecycle_wait4_cpu_seconds': sum(cell['wait4_cpu_seconds'] for cell in cells),
                             'harness_cpu_seconds': sum(cell['harness_cpu_seconds'] for cell in cells),
                             'max_wait4_ru_maxrss_kib': max(cell['wait4_maxrss_kib'] for cell in cells),
                             'median_submit_to_start_ms': statistics.median(job['observed']['submit_to_business_start_ms'] for job in all_jobs),
                             'median_submit_to_complete_ms': statistics.median(job['observed']['submit_to_business_completion_ms'] for job in all_jobs),
                             'median_submit_to_supervisor_reap_ms': statistics.median(job['task']['elapsed_ms'] for job in all_jobs)}
            report['comparison'][str(concurrency)] = arms
        report['passed'] = report['comparison_valid'] = report['successful_measured'] == report['attempted_measured'] == 128
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
        report['passed'] = report['comparison_valid'] = False
    finally:
        try:
            for bundle in bundles.values(): native.assert_bundle_unchanged(bundle)
            for value in scripts.values():
                for item in value['paths'].values():
                    need(read_file(Path(item['path']))[1]['sha256'] == item['sha256'], 'extracted executable body changed')
            if 'script' in report: need(read_file(Path(__file__).absolute())[1] == report['script'], 'harness changed')
            if 'a46_entry' in report: need(read_file(A46_ENTRY)[1] == report['a46_entry'], 'A46 entry changed')
            report['inputs_unchanged'] = True
        except BaseException as error:
            report['errors'].append('final input check: ' + type(error).__name__ + ': ' + str(error))
            report['passed'] = report['comparison_valid'] = False
        report['unexecuted_measured'] = 128 - report['attempted_measured']
        report['finished_utc'] = utc(); save(out / 'report.json', report)
        print(json.dumps({'report': str(out / 'report.json'), 'passed': report['passed'],
                          'attempted_measured': report['attempted_measured'], 'errors': report['errors']}), flush=True)
    return 0 if report['passed'] else 1


STOP_REQUESTED = False


def request_stop(signum, _frame):
    global STOP_REQUESTED
    if not STOP_REQUESTED:
        STOP_REQUESTED = True
        raise KeyboardInterrupt('received ' + signal.Signals(signum).name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--hooked-runner', action='store_true')
    parser.add_argument('--runner'); parser.add_argument('--runner-sha'); parser.add_argument('--job')
    parser.add_argument('--binding'); parser.add_argument('--cut', choices=CUTS)
    parser.add_argument('--owner-directory-sync-count', type=int, choices=(1, 2))
    parser.add_argument('--event-fd', type=int)
    arguments = parser.parse_args()
    if arguments.hooked_runner:
        need(all(getattr(arguments, key) is not None for key in
                 ('runner', 'runner_sha', 'job', 'binding', 'cut', 'owner_directory_sync_count', 'event_fd')),
             'complete internal hook binding required')
        hook_child(arguments)
    else:
        need(arguments.out is not None and all(getattr(arguments, key) is None for key in
             ('runner', 'runner_sha', 'job', 'binding', 'cut', 'owner_directory_sync_count', 'event_fd')),
             'public mode requires only a fresh output path')
        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        raise SystemExit(main(arguments))
