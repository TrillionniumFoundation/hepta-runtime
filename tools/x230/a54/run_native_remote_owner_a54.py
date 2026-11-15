#!/usr/bin/python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Explicit qualified X230 Rust MCP -> AI395 original-owner recovery fixtures."""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import time
import types

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
OUT = BASE / 'a54-native-owner-remote-r01'
BASE_HARNESS = BASE / 'tools/native_owner_recovery_frozen.py'
BASE_SHA = '8ed769c4ca6a44cfd4c38ab31a6b378025f4e84ab13f77e564bbd70a1e594f7a'
REMOTE = Path('/home/qq/hepta-runtime-native-owner-a54-r01')
PROFILE = BASE / 'a52-native-ssh-profile-r01'
ADMISSION_SHA = '464d503f925044f7dd4f13288c31f7735ea427ee9f863531ecbb55a52238237b'
SSH_CONFIG_SHA = '00dd6f7168ec9ecd892100dd667a79da00173d1348373a717ae269b88ad3e117'
KNOWN_HOSTS_SHA = '2bc880a7949593d946e5d77ee22381ddffecabc5db76594f3245698e4de0343e'
PUBLIC_KEY_SHA = '978911353de7277875419f48b8e180babc1f735a0dca426738075e95af14c8de'
CASES = ('controller-loss', 'reply-loss', 'owner-loss')
MAX_MESSAGE = 1024 * 1024
FINAL_BINDINGS_READY = True
ACTUAL_QUALIFICATION_SHA256 = '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'
ACTUAL_RELEASE_SHA256 = 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'
ACTUAL_TESTED_MAP_COMPACT_SHA256 = '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def require_bindings():
    need(FINAL_BINDINGS_READY is True, 'actual A54 qualification bindings pending; no fixture or child admitted')
    for value in (ACTUAL_QUALIFICATION_SHA256, ACTUAL_RELEASE_SHA256, ACTUAL_TESTED_MAP_COMPACT_SHA256):
        need(type(value) is str and len(value) == 64 and all(character in '0123456789abcdef' for character in value),
             'actual A54 qualification/release/tested-source SHA missing')


def load_base():
    need(BASE_HARNESS.resolve(strict=True) == BASE_HARNESS, 'direct frozen base harness required')
    raw = BASE_HARNESS.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == BASE_SHA and len(raw) == 43478, 'original controller harness differs')
    module = types.ModuleType('frozen_native_owner_recovery')
    module.__file__ = str(BASE_HARNESS)
    exec(compile(raw, str(BASE_HARNESS), 'exec'), module.__dict__)
    return module


class SSHChannel:
    """Own exactly one local SSH Popen; remote PIDs are never local signal targets."""
    def __init__(self, base, argv, root, case, nonce, exclusions):
        self.base, self.root, self.case, self.nonce, self.exclusions = base, root, case, nonce, exclusions
        root.mkdir(mode=0o700)
        self.raw = (root / 'stdout.original.jsonl').open('xb', buffering=0)
        self.err = (root / 'stderr.original.log').open('xb', buffering=0)
        self.requests = (root / 'requests.original.jsonl').open('xb', buffering=0)
        self.child = self.pidfd = self.identity = None
        self.buffer = bytearray(); self.eof = False; self.reaped = False
        self.failed = False; self.finished = False; self.final_reply_received = False; self.sequence = 0
        self.cleanup_deadline = None; self.cleanup_complete = False
        self.result = {'argv': argv, 'scope': 'original local custody SSH child only',
                       'signals': [], 'cleanup_errors': [], 'original_wait4': None}
        try:
            need(len(list(Path('/proc/self/task').iterdir())) == 1, 'single-threaded SSH owner required')
            prior = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
            try:
                self.child = subprocess.Popen(argv, cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=self.err, start_new_session=True,
                    preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, prior))
                # Retain the original Popen even if constructor cleanup fails
                # before the caller can receive this object.
                self.exclusions[self.child.pid] = self
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, prior)
            self.pidfd = os.pidfd_open(self.child.pid, 0)
            self.identity = base.process_identity(self.child.pid)
            need(base.same_process(self.identity), 'original custody SSH identity changed')
            self.exclusions[self.child.pid] = self
            self.result['identity'] = self.identity
            os.set_blocking(self.child.stdout.fileno(), False)
            os.set_blocking(self.child.stdin.fileno(), False)
            self.hello = self.response(0, 20)
        except BaseException:
            self.failed = True
            self.close()
            raise

    def pump(self, seconds):
        if self.eof or self.child.stdout.closed:
            return
        if select.select([self.child.stdout], [], [], max(0, seconds))[0]:
            block = os.read(self.child.stdout.fileno(), 65536)
            if not block:
                self.eof = True
            else:
                self.raw.write(block); self.buffer.extend(block)
                need(len(self.buffer) <= MAX_MESSAGE, 'bounded custody reply exceeded')

    def response(self, sequence, seconds):
        until = time.monotonic() + seconds
        while True:
            if b'\n' in self.buffer:
                line, _, tail = self.buffer.partition(b'\n'); self.buffer = bytearray(tail)
                value = json.loads(line)
                need(value.get('seq') == sequence and value.get('case') == self.case
                     and value.get('case_nonce') == self.nonce, 'custody response correlation differs')
                need(value.get('ok') is True, 'remote helper failed: ' + json.dumps(value))
                return value['result']
            need(not self.eof and time.monotonic() < until, 'custody response unavailable')
            self.pump(min(.1, until - time.monotonic()))

    def call(self, operation, **fields):
        need(not self.failed and not self.finished and not self.reaped, 'custody protocol is no longer writable; no retries')
        self.sequence += 1
        value = {'seq': self.sequence, 'case': self.case, 'case_nonce': self.nonce, 'op': operation, **fields}
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        need(len(raw) <= MAX_MESSAGE, 'bounded custody request required')
        self.requests.write(raw); os.fsync(self.requests.fileno())
        if operation == 'finish':
            self.finished = True
        try:
            until, offset = time.monotonic() + 10, 0
            while offset < len(raw):
                need(time.monotonic() < until, 'custody request write timeout')
                if select.select([], [self.child.stdin], [], .1)[1]:
                    try:
                        offset += os.write(self.child.stdin.fileno(), raw[offset:])
                    except BlockingIOError:
                        pass
            result = self.response(self.sequence, 30)
            if operation == 'finish':
                final_raw = base64.b64decode(result['base64'], validate=True)
                need(self.base.digest(final_raw) == result['receipt']['sha256']
                     and len(final_raw) == result['receipt']['bytes'] and json.loads(final_raw) == result['report']
                     and result['report']['case'] == self.case and result['report']['case_nonce'] == self.nonce
                     and result['report']['plan_sha256'] == self.hello['plan_sha256']
                     and result['report']['cleanup_complete'] is True, 'final remote receipt not complete or bound')
                self.final_reply_received = True
            return result
        except BaseException:
            self.failed = True
            raise

    def close(self):
        # Finish one bounded cleanup before delivering a second interrupt.
        # Restoring the mask may raise, after the original evidence is saved.
        prior = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            return self._close()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, prior)

    def _close(self):
        if self.cleanup_complete:
            return self.result
        if self.cleanup_deadline is None:
            self.cleanup_deadline = time.monotonic() + 40
        errors = self.result['cleanup_errors']
        def error(scope, value):
            errors.append(scope + ': ' + type(value).__name__ + ': ' + str(value))
        def pump_safely():
            if self.child.stdout.closed:
                time.sleep(.05)
                return
            try:
                self.pump(.05)
            except BaseException as failure:
                error('stdout capture', failure); self.buffer.clear()
                try:
                    if not self.child.stdout.closed and select.select([self.child.stdout], [], [], .05)[0]:
                        if not os.read(self.child.stdout.fileno(), 65536):
                            self.eof = True
                except BaseException as failure:
                    error('stdout drain', failure)
        if self.child is not None and not self.reaped:
            try:
                if not self.child.stdin.closed:
                    self.child.stdin.close()
            except BaseException as failure:
                error('stdin EOF', failure)
            # EOF lets the remote helper release and finish its shared 20s
            # cleanup. No local SSH signal is described as a remote-owner kill.
            deadline = min(self.cleanup_deadline - 10, time.monotonic() + (2 if self.final_reply_received else 25))
            while self.pidfd is not None and not self.base.pidfd_exited(self.pidfd) and time.monotonic() < deadline:
                pump_safely()
            for number in (signal.SIGTERM, signal.SIGKILL):
                if time.monotonic() >= self.cleanup_deadline or self.result.get('custody_unknown'):
                    break
                if self.pidfd is not None and self.base.pidfd_exited(self.pidfd):
                    break
                try:
                    if self.pidfd is not None:
                        signal.pidfd_send_signal(self.pidfd, number)
                    else:
                        # Original Popen remains unreaped; there is no PID reuse.
                        os.kill(self.child.pid, number)
                    self.result['signals'].append({'signal': signal.Signals(number).name,
                        'target': 'original_local_custody_ssh_pidfd' if self.pidfd is not None else 'original_unreaped_local_ssh'})
                except ProcessLookupError:
                    pass
                except BaseException as failure:
                    error('original SSH signal', failure)
                until = min(self.cleanup_deadline, time.monotonic() + 5)
                if self.pidfd is not None:
                    while not self.base.pidfd_exited(self.pidfd) and time.monotonic() < until:
                        pump_safely()
            try:
                while True:
                    waited, status, usage = os.wait4(self.child.pid, os.WNOHANG)
                    if waited == self.child.pid:
                        self.child.returncode = os.waitstatus_to_exitcode(status)
                        self.reaped = True
                        self.result['original_wait4'] = {'pid': waited, 'raw_status': status,
                            'exit_code': self.child.returncode, 'user_seconds': usage.ru_utime,
                            'system_seconds': usage.ru_stime, 'maxrss_kib': usage.ru_maxrss}
                        self.exclusions.pop(self.child.pid, None)
                        break
                    need(waited == 0 and time.monotonic() < self.cleanup_deadline, 'original SSH wait4 did not complete')
                    time.sleep(.02)
            except ChildProcessError as failure:
                self.result['custody_unknown'] = True
                error('original SSH wait4', failure)
            except BaseException as failure:
                error('original SSH wait4', failure)
        if self.child is not None:
            until = min(self.cleanup_deadline, time.monotonic() + 2)
            while not self.eof and not self.child.stdout.closed and time.monotonic() < until:
                pump_safely()
        self.result['stdout_eof'] = self.eof
        self.result['unconsumed_reply_bytes'] = len(self.buffer)
        streams = [self.raw, self.err, self.requests]
        if self.child is not None:
            streams.append(self.child.stdout)
        for stream in streams:
            if stream.closed:
                continue
            try:
                stream.flush()
                if stream in (self.raw, self.err, self.requests):
                    os.fsync(stream.fileno())
            except BaseException as failure:
                error('stream sync', failure)
            finally:
                try:
                    stream.close()
                except BaseException as failure:
                    error('stream close', failure)
        if self.reaped and self.pidfd is not None:
            os.close(self.pidfd); self.pidfd = None
        self.cleanup_complete = self.reaped and self.eof
        self.result['cleanup_complete'] = self.cleanup_complete
        self.base.save(self.root / 'ssh-receipt.json', self.result)
        return self.result


def exclude_custody_children(base, registry):
    original = base.own_child_pids
    def only_controller_children():
        result = []
        for pid in original():
            owner = registry.get(pid)
            if owner is None:
                result.append(pid)
                continue
            need(owner.child.pid == pid and not owner.reaped and owner.pidfd is not None
                 and owner.identity is not None and owner.identity['ppid'] == os.getpid()
                 and base.same_process(owner.identity), 'separately owned custody SSH identity unavailable')
        return result
    base.own_child_pids = only_controller_children
    return original


def snapshot_bytes(snapshot, name):
    value = snapshot['files'][name]
    raw = base64.b64decode(value['base64'], validate=True)
    need(len(raw) == value['receipt']['bytes'] and hashlib.sha256(raw).hexdigest() == value['receipt']['sha256'],
         'remote original byte receipt differs: ' + name)
    return raw


def case(base, plan, plan_sha, name, binary, wrapper_dir, command, registry, report):
    root = OUT / name; root.mkdir(mode=0o700)
    (root / 'state').mkdir(mode=0o700); (root / 'state/jobs').mkdir(mode=0o700)
    remote = REMOTE / name
    nonce = base.digest((plan['attempt_nonce'] + '/' + name).encode())
    cfg = {'state_dir': str(root / 'state'), 'controller_workspace_roots': [], 'hosts': {'ai395': {
        'ssh_target': 'native-ai395', 'platform': 'linux', 'execution_mode': 'operator',
        'remote_state_dir': str(remote / 'target-state'), 'allow_execute': True, 'allow_pty': False,
        'allow_write': False, 'allow_job_network': True, 'allow_detached_fallback': False, 'privileged_actions': {}}}}
    base.create(root / 'runtime.json', base.canonical(cfg))
    request = {'host': 'ai395', 'executable': '/usr/bin/python3', 'args': ['-I', '-S', '-u', '-c', base.CHILD,
        str(remote / 'effect'), base.digest(base.INPUT), str(remote / 'release')], 'cwd': str(remote),
        'env': {}, 'stdin': base.INPUT.decode(), 'timeout_seconds': 90, 'idempotency_key': 'native-remote-owner-' + nonce[:24]}
    base.create(root / 'request.original.json', base.canonical(request))
    report.update(name=name, passed=False, calls=[], start_requests=0, case_nonce=nonce, remote_root=str(remote))
    channel = controller = None
    try:
        remote_command = shlex.join(['/usr/bin/python3', '-I', '-S', '-u', str(REMOTE / 'remote_owner_custody.py'),
                                    '--plan', str(REMOTE / 'plan.json'), '--plan-sha256', plan_sha, '--case', name])
        channel = SSHChannel(base, [*command, '-T', 'native-ai395', remote_command], root / 'custody-ssh', name, nonce, registry)
        need(channel.hello.get('kind') == 'hello' and channel.hello['remote_identity'] == plan['remote_identity']
             and channel.hello['remote_root'] == str(remote) and channel.hello['plan_sha256'] == plan_sha,
             'new profile/helper does not match independent AI395 identity and frozen plan')
        report['actual_remote_hello'] = channel.hello
        controller = base.Controller(binary, root / 'runtime.json', root / 'controller-0', wrapper_dir)
        report['start_requests'] += 1
        if name == 'reply-loss':
            report['unconsumed_launch_rpc_id'] = controller.send('tools/call', {'name': 'process_start', 'arguments': request})
            report['launch_reply_consumed_before_controller_kill'] = False
        else:
            first = controller.call('process_start', request); report['first_launch'] = first
            need(first.get('reused') is False and first.get('launch', {}).get('backend') == 'systemd', 'first native launch is not systemd/new')
        def launched_record():
            found = [json.loads(base.read(path)) for path in (root / 'state/jobs').glob('*.json')]
            found = [row for row in found if row.get('idempotency_key') == request['idempotency_key']]
            need(len(found) <= 1, 'ambiguous original native job')
            return found[0] if found and found[0].get('launch_state') == 'launched' else None
        record = base.until(launched_record, 20, 'durable original launched controller record absent')
        need(record['host'] == 'ai395' and record['ssh_target'] == 'native-ai395'
             and record['execution_mode'] == 'operator' and record['system_jobctl'] is False
             and record['executable'] == request['executable'] and record['args'] == request['args']
             and record['cwd'] == request['cwd'] and record['remote_job_dir'] == str(remote / 'target-state/jobs' / record['id']),
             'original local job does not bind this AI395 fixture')
        report['original_record'] = record
        bound = channel.call('bind', job_id=record['id'], request_digest=record['request_digest'])
        report['original_remote_binding'] = bound
        need(bound['binding']['job_id'] == record['id'] and not bound['owner_exited'] and not bound['business_exited'],
             'helper did not retain original live owner/business')
        reference = {'host': 'ai395', 'job_id': record['id']}
        if name == 'owner-loss':
            report['owner_loss'] = channel.call('kill_owner')
            need(report['owner_loss']['owner_exited'] and report['owner_loss']['business_exited'], 'systemd original-group cleanup incomplete')
        else:
            report['controller_crash'] = controller.stop(crash=True)
            crash = report['controller_crash']
            need(crash['original_wait4']['exit_code'] == -signal.SIGKILL and crash['cleanup_complete']
                 and crash['stdout_eof'] and not crash['cleanup_errors'], 'original controller SIGKILL/wait4 incomplete')
            controller = None
            survived = channel.call('observe'); report['survived_controller_loss'] = survived
            need(not survived['owner_exited'] and not survived['business_exited']
                 and survived['owner_same_incarnation'] and survived['business_same_incarnation'], 'original remote owner/business did not survive')
            controller = base.Controller(binary, root / 'runtime.json', root / 'controller-1', wrapper_dir)
        status = controller.call('process_status', reference); report['first_recovered_status'] = status
        need(status.get('job_id') == record['id'], 'recovered native status job differs')
        if name == 'owner-loss':
            need(status.get('state') in ('owner_unknown', 'finalizing') and status.get('automatic_retry') is False
                 and status.get('status_authoritative') is False and status.get('terminal_publication_confirmed') is not True,
                 'owner loss gained invented certainty')
        else:
            need(status.get('state') == 'running', 'native recovered status did not retain original running job')
        local_before = base.file_receipt(root / 'state/jobs' / (record['id'] + '.json'))
        remote_before = channel.call('observe')
        report['start_requests'] += 1
        reused = controller.call('process_start', request); report['same_key_reuse'] = reused
        need(reused.get('reused') is True and reused.get('retried_launch') is False and reused.get('launch') is None
             and reused.get('job', {}).get('id') == record['id'] and reused.get('status', {}).get('job_id') == record['id'],
             'same key relaunched or changed original native identity')
        remote_after = channel.call('observe')
        need(remote_after['immutable'] == remote_before['immutable'] == bound['immutable']
             and base.file_receipt(root / 'state/jobs' / (record['id'] + '.json')) == local_before,
             'same-key reconciliation changed original local/remote identity files')
        need(snapshot_bytes(remote_after, 'effect') == base.EFFECT, 'same-key synthetic effect repeated')
        report.update(before_same_key_remote=remote_before, after_same_key_remote=remote_after, local_record_receipt=local_before)
        if name == 'owner-loss':
            need(reused['status'].get('automatic_retry') is False and reused['status'].get('status_authoritative') is False
                 and 'exit.witness.json' not in remote_after['files'], 'same-key owner loss invented a confirmed outcome')
        else:
            report['release'] = channel.call('release')
            until = time.monotonic() + 30
            while True:
                terminal = controller.call('process_status', reference)
                report['calls'].append({'tool': 'process_status', 'value': terminal})
                need(terminal.get('job_id') == record['id'], 'terminal original job differs')
                if terminal.get('state') == 'succeeded':
                    break
                need(time.monotonic() < until and terminal.get('state') in ('running', 'activating', 'finalizing'), 'original remote job failed terminal publication')
                time.sleep(.2)
            final = channel.call('observe')
            exit_raw = snapshot_bytes(final, 'exit.json'); exit_value = json.loads(exit_raw)
            witness = json.loads(snapshot_bytes(final, 'exit.witness.json'))
            req = json.loads(snapshot_bytes(final, 'request.json'))
            need(terminal.get('terminal_publication_confirmed') is True and terminal.get('exit_code') == 0
                 and terminal.get('output_complete') is True and terminal.get('output_durable') is True
                 and terminal.get('automatic_retry') is False
                 and all(terminal.get(key) == value for key, value in exit_value.items()), 'native terminal differs from original remote exit')
            for value in (req, exit_value, witness):
                need(type(value.get('terminal_publication_protocol')) is int and value['terminal_publication_protocol'] == 1
                     and value.get('job_id') == record['id'] and value.get('launch_nonce') == req['launch_nonce'], 'original terminal identity differs')
            need(witness.get('exit_sha256') == base.digest(exit_raw), 'original witness does not bind original exit bytes')
            output = controller.call('process_read', {**reference, 'stdout_offset': 0, 'stderr_offset': 0, 'limit': 16384})
            expected = {'stdout': ('BEGIN\nEND ' + base.digest(base.INPUT) + '\n').encode(), 'stderr': b'RECOVERY-STDERR\n'}
            for stream, raw in expected.items():
                part = output[stream]
                need(bytes.fromhex(part['bytes_hex']) == raw == snapshot_bytes(final, stream + '.log')
                     and part['offset'] == 0 and part['next_offset'] == part['size'] == len(raw) and part['eof'] is True,
                     'native output differs from complete remote original bytes/cursors')
            need(snapshot_bytes(final, 'stdin.bin') == base.INPUT, 'original durable stdin differs')
            report.update(terminal=terminal, witness=witness, output=output, final_remote=final)
        report['shutdown'] = controller.stop()
        shutdown = report['shutdown']
        need(shutdown['shutdown'] == 'stdin_eof' and shutdown['original_wait4']['exit_code'] == 0
             and shutdown['stdout_eof'] and shutdown['cleanup_complete'] and not shutdown['cleanup_errors']
             and not shutdown['adopted_children'], 'normal original controller shutdown incomplete')
        controller = None
        report['remote_finish'] = channel.call('finish')
        finished = report['remote_finish']
        final_raw = base64.b64decode(finished['base64'], validate=True)
        need(base.digest(final_raw) == finished['receipt']['sha256'] and len(final_raw) == finished['receipt']['bytes']
             and json.loads(final_raw) == finished['report'] and finished['report']['cleanup_complete'] is True,
             'remote final original receipt or pidfd cleanup incomplete')
        report['custody_ssh_shutdown'] = channel.close()
        need(channel.cleanup_complete and channel.result['original_wait4']['exit_code'] == 0
             and not channel.result['signals'] and not channel.result['cleanup_errors']
             and channel.result['unconsumed_reply_bytes'] == 0, 'original custody SSH wait4/full-capture incomplete')
        report.update(passed=True, same_job_identity_preserved=True, business_effect_count=1)
    finally:
        if channel is not None and not channel.failed and not channel.finished and not channel.reaped:
            try:
                report['cleanup_release'] = channel.call('release')
            except BaseException as error:
                report['cleanup_release_error'] = type(error).__name__ + ': ' + str(error); report['passed'] = False
        if controller is not None:
            try:
                report['cleanup_controller'] = controller.stop()
                need(controller.cleanup_complete and not controller.result['cleanup_errors'], 'controller cleanup incomplete')
            except BaseException as error:
                report['cleanup_controller_error'] = type(error).__name__ + ': ' + str(error); report['passed'] = False
        if channel is not None:
            if not channel.failed and not channel.finished and not channel.reaped:
                try:
                    report['cleanup_remote_finish'] = channel.call('finish')
                except BaseException as error:
                    report['cleanup_remote_finish_error'] = type(error).__name__ + ': ' + str(error); report['passed'] = False
            try:
                report['final_custody_ssh_receipt'] = channel.close()
                need(channel.cleanup_complete and not channel.result['cleanup_errors'], 'custody SSH cleanup incomplete')
            except BaseException as error:
                report['cleanup_ssh_error'] = type(error).__name__ + ': ' + str(error); report['passed'] = False
        try:
            report['retained_local_files'] = [base.file_receipt(path) for path in sorted(root.rglob('*'))
                                            if path.is_file() and path.name not in ('case-report.json', 'case-report.json.pending')]
        except BaseException as error:
            report['file_receipt_error'] = type(error).__name__ + ': ' + str(error); report['passed'] = False
        base.save(root / 'case-report.json', report)


def main(args):
    require_bindings()
    base = load_base(); os.umask(0o077)
    need(args.plan.absolute() == BASE / 'tools/a54-native-owner-remote-plan-r01.json', 'only fixed local reviewed plan is admitted')
    raw = base.read(args.plan)
    need(base.digest(raw) == args.plan_sha256, 'frozen local plan differs')
    plan = json.loads(raw)
    need(plan['schema'] == 'hepta-native-remote-owner-plan/v1' and plan['ready'] is True
         and plan['remote_parent'] == str(REMOTE) and plan['local_out'] == str(OUT)
         and plan['cases'] == list(CASES) and plan['base_harness_sha256'] == BASE_SHA
         and plan['business_code'] == base.CHILD and plan['input_sha256'] == base.digest(base.INPUT)
         and re.fullmatch(r'[0-9a-f]{64}', plan['attempt_nonce']), 'explicit remote-owner plan incomplete')
    need(base.file_receipt(Path(__file__).absolute())['sha256'] == plan['harness_sha256']
         and base.file_receipt(BASE / 'tools/remote_owner_custody_a54.py')['sha256'] == plan['helper_sha256'],
         'frozen reviewed remote-mode helper/harness changed')
    need(plan['controller_identity'] == {'uid': os.geteuid(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()},
         'admitted X230 controller account/boot differs')
    admission = plan['independent_admission']
    need(admission['path'] == str(PROFILE / 'ai395-independent-identity.original.json')
         and admission['sha256'] == ADMISSION_SHA and base.file_receipt(admission['path'])['sha256'] == ADMISSION_SHA,
         'actual independent AI395 operator receipt differs')
    independent = json.loads(base.read(admission['path']))
    need(independent['schema'] == 'hepta-a52-ai395-independent-identity/v1'
         and independent['systemctl_exists'] is True and independent['user_bus']['socket'] is True
         and independent['user_bus']['uid'] == independent['uid'] == 1000, 'independent systemd/account admission incomplete')
    observed = {key: independent[key] for key in ('uid', 'home', 'hostname', 'boot_id', 'machine_id', 'machine')}
    observed.update(username='qq', python_realpath=independent['python'])
    need(plan['remote_identity'] == observed and observed['boot_id'] != plan['controller_identity']['boot_id'],
         'independent remote identity differs or is not a distinct host boot')
    need(plan['ssh_config'] == str(PROFILE / 'ssh_config') and plan['known_hosts'] == str(PROFILE / 'known_hosts')
         and plan['ssh_target'] == 'native-ai395' and plan['ssh_config_sha256'] == SSH_CONFIG_SHA
         and plan['known_hosts_sha256'] == KNOWN_HOSTS_SHA, 'fresh direct profile binding differs')
    base.validate_ssh_config(Path(plan['ssh_config']))
    need(base.file_receipt(plan['ssh_config'])['sha256'] == SSH_CONFIG_SHA
         and base.file_receipt(plan['known_hosts'])['sha256'] == KNOWN_HOSTS_SHA, 'actual fresh direct profile changed')
    qualification = plan['qualification']
    need(qualification['sha256'] == ACTUAL_QUALIFICATION_SHA256
         and qualification['release_sha256'] == ACTUAL_RELEASE_SHA256
         and qualification['source_files'] == 175
         and qualification['tested_map_compact_sha256'] == ACTUAL_TESTED_MAP_COMPACT_SHA256,
         'frozen A54 qualification/release/tested-source plan differs')
    need(qualification['path'] == str(BASE / 'qualification-a54-compact-view-r01/report.json'), 'only actual A54 qualification supported')
    q, bundle = base.qualification(Path(qualification['path']), qualification['sha256'])
    need(base.digest(json.dumps(bundle['source_map'], sort_keys=True, separators=(',', ':')).encode()) == ACTUAL_TESTED_MAP_COMPACT_SHA256,
         'actual A54 tested-source compact map differs')
    need(bundle['binary']['sha256'] == qualification['release_sha256'] and bundle['source_files'] == 175,
         'actual combined A54 ELF/source differs')
    need(not os.path.lexists(OUT) and OUT.parent == base.direct(BASE), 'new local fixture required')
    need(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, 'local subreaper unavailable')
    need(not base.own_child_pids(), 'harness already owns an unexpected child')
    OUT.mkdir(mode=0o700)
    registry = {}; all_children = exclude_custody_children(base, registry)
    report = {'schema': 'hepta-native-remote-owner-recovery/v1', 'passed': False, 'cases': [], 'errors': [],
              'mode': 'x230-controller-ai395-original-systemd-owner', 'plan_sha256': args.plan_sha256,
              'planned_cases': list(CASES), 'automatic_retries': 0, 'business_launches_planned': 3,
              'service_configuration_changes': 0, 'remote_helper_business_launches': 0,
              'not_covered': ['observation pool authentication', 'host reboot', 'power loss', 'arbitrary external-effect exactly-once'],
              'qualified_bundle': bundle, 'independent_admission': admission}
    inputs = [base.file_receipt(path) for path in (Path(__file__).absolute(), BASE_HARNESS,
              BASE / 'tools/remote_owner_custody_a54.py', args.plan,
              Path(admission['path']), Path(plan['ssh_config']), Path(plan['known_hosts']))]
    inputs.extend([bundle['qualification'], bundle['binary']])
    identity_file = Path('/home/qian/.ssh/id_ed25519_ai395_mesh')
    public = identity_file.with_suffix('.pub')
    before_private = list(base.stamp(identity_file.lstat()))
    need(stat.S_ISREG(identity_file.lstat().st_mode) and identity_file.lstat().st_uid == os.geteuid()
         and not identity_file.lstat().st_mode & 0o077, 'existing private identity metadata unsafe')
    need(plan['private_identity_metadata'] == {'path': str(identity_file), 'identity': before_private}
         and base.file_receipt(public) == plan['public_identity_receipt']
         and plan['public_identity_receipt']['sha256'] == PUBLIC_KEY_SHA, 'original admitted identity metadata/public key changed')
    inputs.append(plan['public_identity_receipt'])
    report['private_identity_metadata_only'] = {'path': str(identity_file), 'identity': before_private, 'contents_read_by_harness': False}
    report['inputs'] = inputs
    try:
        for key in list(os.environ):
            if key.startswith('SSH_') or key.startswith('HEPTA_') or key in ('PYTHONPATH', 'PYTHONHOME'):
                os.environ.pop(key, None)
        wrapper = OUT / 'bin'; wrapper.mkdir(mode=0o700)
        options = {'BatchMode': 'yes', 'ConnectTimeout': '8', 'ConnectionAttempts': '1', 'IdentityAgent': 'none',
                   'IdentitiesOnly': 'yes', 'StrictHostKeyChecking': 'yes', 'ForwardAgent': 'no', 'ForwardX11': 'no',
                   'ClearAllForwardings': 'yes', 'ControlMaster': 'no', 'ControlPath': 'none', 'ControlPersist': 'no',
                   'PasswordAuthentication': 'no', 'KbdInteractiveAuthentication': 'no', 'AddKeysToAgent': 'no',
                   'UpdateHostKeys': 'no', 'UserKnownHostsFile': plan['known_hosts'], 'GlobalKnownHostsFile': '/dev/null',
                   'KnownHostsCommand': 'none', 'LocalCommand': 'none', 'PermitLocalCommand': 'no', 'RequestTTY': 'no'}
        command = ['/usr/bin/ssh', '-F', plan['ssh_config']]
        for key, value in options.items():
            command.extend(['-o', key + '=' + value])
        base.create(wrapper / 'ssh', ('#!/bin/sh\nexec ' + shlex.join(command) + ' "$@"\n').encode(), 0o700)
        base.create(OUT / 'frozen-plan.original.json', raw)
        for name in CASES:
            row = {'name': name, 'passed': False}; report['cases'].append(row)
            base.save(OUT / 'report.json', report)
            try:
                case(base, plan, args.plan_sha256, name, Path(bundle['binary']['path']), wrapper, command, registry, row)
            except BaseException as error:
                row['error'] = type(error).__name__ + ': ' + str(error)
                raise
            need(row['passed'], 'remote owner case did not pass: ' + name)
        report['passed'] = True
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        # Failed constructors remain reachable here through their original
        # Popen registry. Reentry never renews their original cleanup deadline.
        for channel in list(registry.values()):
            try:
                result = channel.close()
                report.setdefault('remaining_custody_cleanup', []).append(result)
                need(channel.cleanup_complete, 'original custody SSH remains unresolved')
            except BaseException as error:
                report['passed'] = False
                report['errors'].append('remaining custody cleanup: ' + type(error).__name__ + ': ' + str(error))
        try:
            need(not registry and not all_children(), 'original local child ownership remains unresolved')
            for item in inputs:
                need(base.file_receipt(item['path']) == item, 'frozen input changed: ' + item['path'])
            need(list(base.stamp(identity_file.lstat())) == before_private, 'private identity metadata changed')
            source = Path(bundle['source'])
            actual = {str(path.relative_to(source)): base.file_receipt(path)['sha256']
                      for path in sorted(source.rglob('*')) if path.is_file()}
            need(actual == bundle['source_map'], 'qualified A54 source changed')
            report['frozen_inputs_unchanged'] = True
        except BaseException as error:
            report['passed'] = False; report['errors'].append('final fence: ' + type(error).__name__ + ': ' + str(error))
        report['unexecuted_cases'] = [name for name in CASES if name not in [row['name'] for row in report['cases']]]
        base.save(OUT / 'report.json', report)
        print(json.dumps({'report': str(OUT / 'report.json'), 'passed': report['passed'], 'errors': report['errors']}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    def interrupted(signum, _frame):
        raise InterruptedError('local recovery harness interrupted: ' + signal.Signals(signum).name)
    signal.signal(signal.SIGINT, interrupted); signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main(args))
