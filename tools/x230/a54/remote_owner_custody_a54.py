#!/usr/bin/python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Restricted AI395 fixture observer. This program never launches a process."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import stat
import sys
import time

PARENT = Path('/home/qq/hepta-runtime-native-owner-a54-r01')
CASES = ('controller-loss', 'reply-loss', 'owner-loss')
CHILD_SHA = '3daba9e7d256125490c215edb035279bd1943c672356b634629abd993db7d87d'
INPUT_SHA = '929b11f47a02202e710632002203f7ea8dd3c1bc51ef818e59b6a3cd1dc2d5dc'
RELEASE = b'RELEASE\n'
IMMUTABLE = ('request.json', 'owner-intent.json', 'started.json', 'child.json', 'runner.py', 'stdin.bin', 'launch.json')
OPTIONAL = ('exit.json', 'exit.witness.json', 'stdout.log', 'stderr.log')
MAX_LINE = 1024 * 1024
FINAL_BINDINGS_READY = True
ACTUAL_QUALIFICATION_SHA256 = '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'
ACTUAL_RELEASE_SHA256 = 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'
ACTUAL_TESTED_MAP_COMPACT_SHA256 = '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def directory(path, private=True):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and str(path) == str(path.absolute()), 'absolute direct directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        need(not private or (info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700), 'private owned directory required')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_at(fd, name, optional=False, limit=128 * 1024):
    need(type(name) is str and re.fullmatch(r'[a-zA-Z0-9_.-]{1,128}', name), 'one fixed filename required')
    try:
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        if optional:
            return None
        raise
    try:
        before = os.fstat(handle)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and not before.st_mode & 0o077 and before.st_size <= limit, 'unsafe/big fixture file: ' + name)
        chunks, size = [], 0
        while True:
            block = os.read(handle, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block); size += len(block)
            need(size <= limit, 'fixture file grew beyond bound')
        need(size == before.st_size and stamp(before) == stamp(os.fstat(handle))
             == stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'fixture file changed during read')
        raw = b''.join(chunks)
        return raw, {'name': name, 'bytes': len(raw), 'sha256': sha(raw), 'identity': stamp(before)}
    finally:
        os.close(handle)


def create_at(fd, name, raw):
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    with os.fdopen(handle, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.fsync(fd)


def actual_identity():
    return {'uid': os.geteuid(), 'username': pwd.getpwuid(os.geteuid()).pw_name,
            'home': pwd.getpwuid(os.geteuid()).pw_dir, 'hostname': socket.gethostname(),
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'machine_id': Path('/etc/machine-id').read_text().strip(), 'machine': os.uname().machine,
            'python_realpath': str(Path(sys.executable).resolve())}


def process_identity(pid):
    need(type(pid) is int and 1 < pid < 2147483648, 'bounded original process ID required')
    fields = Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()
    return {'pid': pid, 'birth_ticks': int(fields[19]), 'ppid': int(fields[1]),
            'pgid': int(fields[2]), 'sid': int(fields[3]), 'state': fields[0],
            'uid': Path('/proc', str(pid)).stat().st_uid,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def same_process(identity):
    try:
        now = process_identity(identity['pid'])
        return all(now[key] == identity[key] for key in ('pid', 'birth_ticks', 'uid', 'boot_id'))
    except (FileNotFoundError, ProcessLookupError):
        return False


def bound_pidfd(identity):
    need(same_process(identity), 'original process changed before pidfd open')
    fd = os.pidfd_open(identity['pid'], 0)
    try:
        need(same_process(identity), 'original process changed after pidfd open')
        return fd
    except BaseException:
        os.close(fd)
        raise


def exited(fd):
    return bool(select.select([fd], [], [], 0)[0])


def proc_argv(identity):
    need(same_process(identity), 'process changed before argv check')
    with open('/proc/%d/cmdline' % identity['pid'], 'rb', buffering=0) as stream:
        raw = stream.read(MAX_LINE + 1)
    need(len(raw) <= MAX_LINE and raw.endswith(b'\0') and same_process(identity), 'original argv unavailable/changed')
    return [part.decode() for part in raw[:-1].split(b'\0')], sha(raw)


def validate_command(value, sequence, case, nonce):
    need(type(value) is dict and value.get('seq') == sequence and type(value.get('seq')) is int
         and value.get('case') == case and value.get('case_nonce') == nonce, 'command sequence/case binding differs')
    op = value.get('op')
    need(op in ('bind', 'observe', 'release', 'kill_owner', 'finish'), 'unsupported restricted operation')
    fields = {'seq', 'case', 'case_nonce', 'op'} | ({'job_id', 'request_digest'} if op == 'bind' else set())
    need(set(value) == fields, 'unexpected command fields; no caller path/PID is accepted')
    if op == 'bind':
        need(type(value['job_id']) is str and re.fullmatch(r'[0-9a-f]{1,32}-[0-9a-f]{1,16}-[0-9a-f]{1,16}', value['job_id'])
             and type(value['request_digest']) is str and re.fullmatch(r'[0-9a-f]{64}', value['request_digest']), 'native job binding malformed')
    return op


class Session:
    def __init__(self, plan, plan_sha, case, parent_fd):
        self.plan, self.plan_sha, self.case, self.parent_fd = plan, plan_sha, case, parent_fd
        self.remote_identity = actual_identity()
        self.case_nonce = sha((plan['attempt_nonce'] + '/' + case).encode())
        self.root = PARENT / case
        self.owner_fd = self.child_fd = self.job_fd = None
        self.owner = self.child = self.job = self.binding = None
        self.kill_attempted = False
        self.started = time.monotonic(); self.deadline = self.started + 150
        self.events = []; self.immutable = {}
        os.mkdir(case, mode=0o700, dir_fd=parent_fd); os.fsync(parent_fd)
        self.root_fd = directory(self.root)
        os.mkdir('target-state', mode=0o700, dir_fd=self.root_fd); os.fsync(self.root_fd)
        self.root_identity = stamp(os.fstat(self.root_fd))[:5]
        create_at(self.root_fd, 'custody-owner.json', canonical({'schema': 'hepta-remote-owner-helper-binding/v1',
                  'plan_sha256': plan_sha, 'case': case, 'case_nonce': self.case_nonce,
                  'helper_identity': process_identity(os.getpid()), 'remote_identity': actual_identity()}))

    def release(self):
        try:
            create_at(self.root_fd, 'release', RELEASE)
        except FileExistsError:
            need(read_at(self.root_fd, 'release')[0] == RELEASE, 'release marker differs')
        return read_at(self.root_fd, 'release')[1]

    def check_directories(self):
        fd = directory(self.root)
        try:
            need(stamp(os.fstat(fd))[:5] == self.root_identity, 'original case directory changed')
        finally:
            os.close(fd)
        if self.job_fd is not None:
            fd = directory(self.job)
            try:
                need(stamp(os.fstat(fd))[:5] == self.job_identity, 'original job directory changed')
            finally:
                os.close(fd)

    def immutable_files(self):
        return {name: read_at(self.job_fd, name)[1] for name in IMMUTABLE}

    def bind(self, job_id, request_digest):
        need(self.binding is None and self.job_fd is None, 'one bind attempt per fresh case')
        self.job = self.root / 'target-state/jobs' / job_id
        until = min(self.deadline, time.monotonic() + 20)
        while True:
            try:
                fd = directory(self.job)
                try:
                    present = set(os.listdir(fd))
                finally:
                    os.close(fd)
                ready = read_at(self.root_fd, 'effect.ready', optional=True)
                if ready is not None and set(IMMUTABLE) <= present:
                    need(ready[0] == b'READY\n', 'business readiness differs')
                    break
            except FileNotFoundError:
                pass
            need(time.monotonic() < until, 'original native effect/job readiness absent')
            time.sleep(.05)
        self.job_fd = directory(self.job)
        self.job_identity = stamp(os.fstat(self.job_fd))[:5]
        originals = {name: read_at(self.job_fd, name) for name in IMMUTABLE}
        raw = {name: item[0] for name, item in originals.items()}
        initial_immutable = {name: item[1] for name, item in originals.items()}
        req, intent, started, child, launch = (json.loads(raw[name]) for name in
            ('request.json', 'owner-intent.json', 'started.json', 'child.json', 'launch.json'))
        need(all(type(value) is dict for value in (req, intent, started, child, launch)), 'original job metadata object required')
        expected_args = ['-I', '-S', '-u', '-c', self.plan['business_code'],
                         str(self.root / 'effect'), INPUT_SHA, str(self.root / 'release')]
        need(req.get('job_id') == job_id and req.get('job_dir') == str(self.job)
             and req.get('request_fingerprint') == request_digest and req.get('terminal_publication_protocol') == 1
             and req.get('executable') == '/usr/bin/python3' and req.get('args') == expected_args
             and req.get('cwd') == str(self.root) and req.get('env') == {} and req.get('timeout_seconds') == 90
             and req.get('execution_mode') == 'operator' and req.get('allow_detached_fallback') is False
             and req.get('unit') == 'hepta-runtime-job-' + job_id
             and re.fullmatch(r'[0-9a-f]{32}', req.get('launch_nonce', '')), 'original native request differs from fixed business')
        need(intent == started and intent.get('job_id') == job_id and intent.get('launch_nonce') == req['launch_nonce']
             and type(intent.get('invocation_id')) is str and re.fullmatch(r'[0-9a-f]{32}', intent['invocation_id'])
             and launch.get('backend') == 'systemd' and launch.get('unit') == req['unit'], 'original systemd owner publication differs')
        need(len(raw['stdin.bin']) == 4096 and sha(raw['stdin.bin']) == INPUT_SHA
             and read_at(self.root_fd, 'effect')[0] == b'EXECUTED\n', 'original input/effect differs')
        owner = process_identity(started['supervisor_pid'])
        need(owner['uid'] == os.geteuid() == started.get('supervisor_uid')
             and started.get('supervisor_identity') == {'kind': 'proc_start_ticks', 'value': owner['boot_id'] + ':' + str(owner['birth_ticks'])},
             'original owner identity differs')
        owner_argv, owner_argv_sha = proc_argv(owner)
        need(len(owner_argv) == 8 and owner_argv[1:4] == ['-I', '-S', '-c']
             and str(Path(owner_argv[0]).resolve()) == self.remote_identity['python_realpath']
             and owner_argv[4] == raw['runner.py'].decode()
             and owner_argv[-1] == 'systemd' and owner_argv[-3] == str(self.job),
             'owner argv is not the retained original native supervisor bytes')
        expected_binding = {'device': os.fstat(self.job_fd).st_dev, 'inode': os.fstat(self.job_fd).st_ino,
                            'job_id': job_id, 'launch_nonce': req['launch_nonce'], 'request_fingerprint': request_digest}
        need(json.loads(owner_argv[-2]) == expected_binding, 'owner argv inode/request binding differs')
        self.owner = owner; self.owner_fd = bound_pidfd(owner)
        business = process_identity(child['pid'])
        need(business['uid'] == owner['uid'] and business['ppid'] == owner['pid']
             and child.get('identity') == {'kind': 'proc_start_ticks', 'value': business['boot_id'] + ':' + str(business['birth_ticks'])},
             'original business identity/parent differs')
        child_argv, child_argv_sha = proc_argv(business)
        need(child_argv == ['/usr/bin/python3', *expected_args], 'original business argv differs')
        self.child = business; self.child_fd = bound_pidfd(business)
        need(not exited(self.owner_fd) and not exited(self.child_fd), 'original owner/business already exited before bind')
        need(self.immutable_files() == initial_immutable, 'original metadata changed during bind')
        self.immutable = initial_immutable
        self.binding = {'job_id': job_id, 'request_digest': request_digest, 'launch_nonce': req['launch_nonce'],
                        'owner': owner, 'business': business, 'owner_argv_sha256': owner_argv_sha,
                        'business_argv_sha256': child_argv_sha, 'job_directory_identity': self.job_identity}
        return self.observe()

    def observe(self):
        need(self.binding is not None, 'original job is not bound')
        self.check_directories()
        need(self.immutable_files() == self.immutable, 'original owner/job metadata changed')
        files = {}
        for name in (*IMMUTABLE, *OPTIONAL):
            item = read_at(self.job_fd, name, optional=name in OPTIONAL)
            if item is not None:
                raw, receipt = item
                files[name] = {'receipt': receipt}
                if name != 'runner.py':
                    files[name]['base64'] = base64.b64encode(raw).decode()
        for name in ('effect', 'effect.ready', 'release'):
            item = read_at(self.root_fd, name, optional=True)
            if item is not None:
                raw, receipt = item
                files[name] = {'receipt': receipt, 'base64': base64.b64encode(raw).decode()}
        need(read_at(self.root_fd, 'effect')[0] == b'EXECUTED\n', 'synthetic effect repeated/changed')
        return {'binding': self.binding, 'immutable': self.immutable, 'files': files,
                'owner_exited': exited(self.owner_fd), 'business_exited': exited(self.child_fd),
                'owner_same_incarnation': same_process(self.owner), 'business_same_incarnation': same_process(self.child)}

    def kill_owner(self):
        need(self.case == 'owner-loss' and not self.kill_attempted and self.binding is not None,
             'one owner kill only in the bound owner-loss case')
        before = self.observe()
        need(not before['owner_exited'] and not before['business_exited']
             and before['owner_same_incarnation'] and before['business_same_incarnation'], 'original processes are not both live')
        self.kill_attempted = True
        signal.pidfd_send_signal(self.owner_fd, signal.SIGKILL)
        self.events.append({'owner_signal': 'SIGKILL', 'owner_identity': self.owner, 'via_original_pidfd': True,
                            'submitted_monotonic_ns': time.monotonic_ns(), 'business_was_live': True})
        until = min(self.deadline, time.monotonic() + 15)
        while not (exited(self.owner_fd) and exited(self.child_fd)) and time.monotonic() < until:
            time.sleep(.05)
        result = self.observe()
        need(result['owner_exited'] and result['business_exited'], 'existing systemd unit did not stop original owner/business')
        need('exit.witness.json' not in result['files'], 'unexpected confirmed witness after owner kill')
        return result

    def finish(self, errors):
        # One cleanup boundary; neither failed release nor failed collection
        # renews it. Remote processes are not our children and are never reaped.
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        until = time.monotonic() + 20
        result = {'schema': 'hepta-remote-owner-helper-final/v1', 'case': self.case, 'case_nonce': self.case_nonce,
                  'plan_sha256': self.plan_sha, 'remote_identity': self.remote_identity, 'errors': list(errors),
                  'business_launches': 0, 'business_signals': 0, 'remote_wait4_claimed': False,
                  'owner_kill_attempted': self.kill_attempted, 'events': self.events}
        try:
            result['release'] = self.release()
        except BaseException as error:
            result['errors'].append('release: ' + type(error).__name__ + ': ' + str(error))
        for name, fd in (('owner', self.owner_fd), ('business', self.child_fd)):
            if fd is not None:
                try:
                    while not exited(fd) and time.monotonic() < until - 2:
                        time.sleep(.05)
                    result[name + '_pidfd_exited'] = exited(fd)
                    need(result[name + '_pidfd_exited'], 'original ' + name + ' did not exit during bounded cleanup')
                except BaseException as error:
                    result['errors'].append(name + ': ' + type(error).__name__ + ': ' + str(error))
        try:
            if self.binding is not None:
                result['final_observation'] = self.observe()
        except BaseException as error:
            result['errors'].append('final observation: ' + type(error).__name__ + ': ' + str(error))
        result['elapsed_seconds'] = time.monotonic() - self.started
        result['job_bound'] = self.binding is not None
        result['cleanup_complete'] = bool(not result['errors'] and result['job_bound']
                                           and result.get('owner_pidfd_exited')
                                           and result.get('business_pidfd_exited'))
        create_at(self.root_fd, 'custody-report.json', canonical(result))
        raw, receipt = read_at(self.root_fd, 'custody-report.json', limit=MAX_LINE)
        return {'report': result, 'receipt': receipt, 'base64': base64.b64encode(raw).decode()}, until

    def close(self):
        for fd in (self.owner_fd, self.child_fd, self.job_fd, self.root_fd):
            if fd is not None:
                os.close(fd)


def emit(value, deadline):
    raw = canonical(value)
    need(len(raw) <= MAX_LINE, 'bounded helper response required')
    offset = 0
    while offset < len(raw):
        need(time.monotonic() < deadline, 'helper response deadline expired')
        if select.select([], [sys.stdout.fileno()], [], min(.1, deadline - time.monotonic()))[1]:
            try:
                offset += os.write(sys.stdout.fileno(), raw[offset:])
            except BlockingIOError:
                pass


def require_bindings():
    need(FINAL_BINDINGS_READY is True, 'actual A54 qualification bindings pending; no fixture or child admitted')
    for value in (ACTUAL_QUALIFICATION_SHA256, ACTUAL_RELEASE_SHA256, ACTUAL_TESTED_MAP_COMPACT_SHA256):
        need(type(value) is str and len(value) == 64 and all(character in '0123456789abcdef' for character in value),
             'actual A54 qualification/release/tested-source SHA missing')


def main(args):
    require_bindings()
    os.umask(0o077)
    need(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'Linux pidfds required')
    need(args.case in CASES and args.plan == PARENT / 'plan.json'
         and re.fullmatch(r'[0-9a-f]{64}', args.plan_sha256), 'fixed reviewed plan required')
    parent = directory(PARENT)
    session = None
    try:
        raw, _ = read_at(parent, 'plan.json', limit=MAX_LINE)
        need(sha(raw) == args.plan_sha256, 'frozen plan SHA differs')
        plan = json.loads(raw)
        helper, _ = read_at(parent, 'remote_owner_custody.py')
        need(plan['schema'] == 'hepta-native-remote-owner-plan/v1' and plan['ready'] is True
             and plan['remote_parent'] == str(PARENT) and plan['cases'] == list(CASES)
             and plan['helper_sha256'] == sha(helper) and Path(__file__).absolute() == PARENT / 'remote_owner_custody.py'
             and sha(plan['business_code'].encode()) == plan['business_code_sha256'] == CHILD_SHA
             and plan['input_sha256'] == INPUT_SHA and re.fullmatch(r'[0-9a-f]{64}', plan['attempt_nonce'])
             and re.fullmatch(r'[0-9a-f]{64}', plan['independent_admission']['sha256'])
             and re.fullmatch(r'[0-9a-f]{64}', plan['qualification']['release_sha256'])
             and re.fullmatch(r'[0-9a-f]{64}', plan['qualification']['sha256']), 'frozen plan bindings incomplete')
        qualification = plan['qualification']
        need(qualification['sha256'] == ACTUAL_QUALIFICATION_SHA256
             and qualification['release_sha256'] == ACTUAL_RELEASE_SHA256
             and qualification['source_files'] == 175
             and qualification['tested_map_compact_sha256'] == ACTUAL_TESTED_MAP_COMPACT_SHA256,
             'frozen A54 qualification/release/tested-source plan differs')
        need(actual_identity() == plan['remote_identity'], 'independently admitted AI395 identity differs')
        session = Session(plan, args.plan_sha256, args.case, parent)
        os.set_blocking(sys.stdin.fileno(), False); os.set_blocking(sys.stdout.fileno(), False)
        def response(seq, okay, result):
            return {'seq': seq, 'case': args.case, 'case_nonce': session.case_nonce, 'ok': okay, 'result': result}
        errors, pending, sequence, buffer = [], None, 1, bytearray()
        try:
            emit(response(0, True, {'kind': 'hello', 'remote_identity': actual_identity(),
                 'helper_identity': process_identity(os.getpid()), 'remote_root': str(session.root),
                 'plan_sha256': args.plan_sha256}), min(session.deadline, time.monotonic() + 10))
            while True:
                need(sequence <= 32 and time.monotonic() < session.deadline, 'bounded helper session exhausted')
                if b'\n' not in buffer:
                    if not select.select([sys.stdin.fileno()], [], [], min(.1, session.deadline - time.monotonic()))[0]:
                        continue
                    block = os.read(sys.stdin.fileno(), 65536)
                    if not block:
                        need(not buffer, 'partial protocol request at EOF')
                        errors.append('controller custody channel EOF before finish'); break
                    buffer.extend(block); need(len(buffer) <= MAX_LINE, 'helper command exceeds bound')
                    continue
                line, _, rest = buffer.partition(b'\n'); buffer = bytearray(rest)
                value = json.loads(line)
                op = validate_command(value, sequence, args.case, session.case_nonce)
                pending = sequence; sequence += 1
                session.events.append({'request': value, 'at_monotonic_ns': time.monotonic_ns()})
                if op == 'finish':
                    break
                if op == 'bind':
                    result = session.bind(value['job_id'], value['request_digest'])
                elif op == 'observe':
                    result = session.observe()
                elif op == 'release':
                    result = {'release': session.release()}
                else:
                    result = session.kill_owner()
                message = response(pending, True, result)
                emit(message, min(session.deadline, time.monotonic() + 10))
                session.events.append({'response_seq': pending, 'sha256': sha(canonical(message))})
                pending = None
        except BaseException as error:
            errors.append(type(error).__name__ + ': ' + str(error))
        finally:
            final, until = session.finish(errors)
            try:
                emit(response(pending, not final['report']['errors'], final), until)
            except (BrokenPipeError, RuntimeError, OSError):
                pass  # The independently retained remote final receipt remains authoritative.
        return 0 if not final['report']['errors'] else 1
    finally:
        if session is not None:
            session.close()
        os.close(parent)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--case', required=True, choices=CASES)
    args = parser.parse_args()
    def interrupted(signum, _frame):
        raise InterruptedError('custody helper interrupted: ' + signal.Signals(signum).name)
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, interrupted)
    raise SystemExit(main(args))
