#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One fresh three-process custody slice; retain its socket, never reclaim it.

The probe driver is the pre-existing owner. Its only two children are a fixed
controller client and a fixed socket writer. Only the original controller is
sent SIGKILL. No SSH, runtime, historical root, arbitrary command, or arbitrary
path is accepted. Files ending .private.json contain original process/root
identities and must not be published without a separate privacy review.
"""

import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time


OUT = Path('/home/qian/hepta-runtime-optimization-20261023/a27-custody-owner-r01')
WAIT_SECONDS = 5
EXPECTED_CHECKS = {
    'original_writer_peer_verified', 'writer_alive_before_controller_death',
    'writer_received_no_control_channel_descriptor', 'original_controller_terminal_and_reaped',
    'control_EOF_seen_while_original_writer_alive', 'admission_frozen_on_control_EOF',
    'original_writer_terminal_and_reaped', 'same_socket_retained_after_reap',
    'root_descriptor_and_path_preserved', 'same_owner_identity_at_end',
    'SIGKILL_sent_only_to_original_controller', 'one_writer_launched',
    'source_unchanged', 'all_four_child_logs_empty'}
PARENT_GUARD = r'''
import os, signal, sys
parent = int(sys.argv[1])
if os.getppid() != parent:
    raise SystemExit(91)
'''
CONTROLLER = PARENT_GUARD + r'''
import socket
channel = socket.socket(fileno=int(sys.argv[2]))
try:
    channel.sendall(b'START\n')
    expected = b'ACCEPTED\n'
    received = b''
    while len(received) < len(expected):
        part = channel.recv(len(expected) - len(received))
        if not part:
            raise SystemExit(92)
        received += part
    if received != expected:
        raise SystemExit(93)
    channel.sendall(b'RUNNING\n')
    if channel.recv(1) != b'':
        raise SystemExit(94)
finally:
    channel.close()
'''
WRITER = PARENT_GUARD + r'''
import select, socket
root, ready, stop_gate, notice = map(int, sys.argv[2:])
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

def terminated(signum, frame):
    os.write(notice, b'T')
    raise SystemExit(0)

signal.signal(signal.SIGTERM, terminated)
try:
    listener.bind('/proc/self/fd/' + str(root) + '/writer.sock')
    os.chmod('writer.sock', 0o600, dir_fd=root, follow_symlinks=False)
    listener.listen(1)
    os.write(ready, b'R')
    os.close(ready)
    while True:
        readable, _, _ = select.select([listener, stop_gate], [], [])
        if stop_gate in readable:
            # Owner-only EOF is the failure-path stop request. It neither
            # unlinks the socket nor authorizes a different process to act.
            if os.read(stop_gate, 1) != b'':
                raise SystemExit(95)
            break
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(3)
            received = b''
            while len(received) < 4:
                part = connection.recv(4 - len(received))
                if not part:
                    raise SystemExit(96)
                received += part
            if received != b'PING':
                raise SystemExit(96)
            connection.sendall(b'PONG')
finally:
    listener.close()
    os.close(root)
    os.close(stop_gate)
    os.close(notice)
'''


class Refusal(Exception):
    """A fixed category safe to include in the public receipt."""


def need(value, category):
    if not value:
        raise Refusal(category)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def failure(error):
    row = {'type': type(error).__name__, 'errno': getattr(error, 'errno', None)}
    if isinstance(error, Refusal):
        row['category'] = str(error)
    return row


def directory_identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino,
            'uid': info.st_uid, 'mode': info.st_mode}


def file_stamp(info):
    return {**directory_identity(info), 'links': info.st_nlink, 'bytes': info.st_size,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def process_identity(pid):
    path = Path('/proc') / str(pid)

    def process_stat():
        fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
        need(fields[0] != 'Z', 'identity_already_terminal')
        return int(fields[19]), int(fields[1])

    born, parent = process_stat()
    uid = path.stat().st_uid
    exe = (path / 'exe').stat()
    args = (path / 'cmdline').read_bytes()
    need(bool(args), 'identity_argv_empty')
    need(process_stat() == (born, parent), 'identity_changed_during_read')
    return {'pid': pid, 'parent_pid': parent, 'birth_ticks': born, 'uid': uid,
            'exe_device': exe.st_dev, 'exe_inode': exe.st_ino, 'argv_sha256': sha(args)}


def ready(fd, seconds=WAIT_SECONDS):
    return bool(select.select([fd], [], [], seconds)[0])


def receive(channel, expected):
    until = time.monotonic() + WAIT_SECONDS
    result = b''
    while len(result) < len(expected):
        remaining = until - time.monotonic()
        need(remaining > 0, 'control_frame_deadline')
        channel.settimeout(remaining)
        part = channel.recv(len(expected) - len(result))
        need(bool(part), 'control_frame_ended_early')
        result += part
    need(result == expected, 'control_frame_mismatch')


class Fixture:
    def __init__(self):
        OUT.mkdir(mode=0o700)
        self.fd = os.open(OUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.identity = directory_identity(os.fstat(self.fd))
        need(self.identity == directory_identity(os.lstat(OUT)), 'fixture_root_changed')
        need(self.identity['uid'] == os.geteuid() and
             stat.S_IMODE(self.identity['mode']) == 0o700, 'fixture_root_authority_mismatch')
        self.files = []
        self.events = None
        self.sequence = 0
        self.origin = time.monotonic()

    def open_new(self, name):
        need('/' not in name and name not in ('', '.', '..'), 'invalid_artifact_name')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        self.files.append(name)
        return os.fdopen(fd, 'wb')

    def save(self, name, value):
        raw = canonical(value)
        with self.open_new(name) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.fd)
        return {'file': name, 'bytes': len(raw), 'sha256': sha(raw),
                'private_identity': name.endswith('.private.json')}

    def event(self, phase, **details):
        if self.events is None:
            self.events = self.open_new('events.jsonl')
        row = {'sequence': self.sequence, 'seconds': time.monotonic() - self.origin,
               'phase': phase, 'details': details}
        raw = canonical(row)
        self.events.write(raw)
        self.events.flush()
        os.fsync(self.events.fileno())
        self.sequence += 1

    def socket_stamp(self):
        info = os.stat('writer.sock', dir_fd=self.fd, follow_symlinks=False)
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid() and
             info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
             'fixture_socket_authority_mismatch')
        return file_stamp(info)

    def receipt(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 before.st_size <= 1024 * 1024, 'artifact_identity_or_size_mismatch')
            raw = stream.read(1024 * 1024 + 1)
            need(len(raw) == before.st_size and file_stamp(os.fstat(stream.fileno())) ==
                 file_stamp(before), 'artifact_changed_during_receipt')
        return {'file': name, 'bytes': len(raw), 'sha256': sha(raw),
                'private_identity': name.endswith('.private.json')}


class OriginalChild:
    def __init__(self, role, code, passed, owner_pid):
        self.role = role
        self.process = None
        self.start_attempted = False
        self.pidfd = None
        self.identity = None
        self.signals = []
        self.passed = tuple(passed)
        self.args = [sys.executable, '-I', '-S', '-c', code, str(owner_pid), *map(str, passed)]

    def start(self, fixture):
        # The outer owner stores this object before calling start. Even a
        # subsequent log-close or pidfd error cannot drop the original Popen.
        need(not self.start_attempted, self.role + '_start_already_attempted')
        self.start_attempted = True
        with fixture.open_new(self.role + '.stdout') as stdout, fixture.open_new(self.role + '.stderr') as stderr:
            self.process = subprocess.Popen(self.args, close_fds=True, pass_fds=self.passed,
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})

    def acquire_pidfd(self):
        # The original Popen has not been polled or reaped before this open.
        self.pidfd = os.pidfd_open(self.process.pid, 0)

    def capture(self, owner_pid, interpreter_identity):
        need(self.process.poll() is None, self.role + '_exited_before_identity')
        identity = process_identity(self.process.pid)
        expected_args = b''.join(arg.encode() + b'\0' for arg in self.args)
        need(identity['parent_pid'] == owner_pid and identity['uid'] == os.geteuid(),
             self.role + '_parent_or_uid_mismatch')
        need((identity['exe_device'], identity['exe_inode']) == interpreter_identity,
             self.role + '_executable_mismatch')
        need(identity['argv_sha256'] == sha(expected_args), self.role + '_argv_mismatch')
        self.identity = identity
        return identity

    def live(self):
        need(self.process.poll() is None and self.pidfd is not None and
             not ready(self.pidfd, 0), self.role + '_not_live')
        need(self.identity is not None and process_identity(self.process.pid) == self.identity,
             self.role + '_live_identity_changed')

    def send(self, value):
        self.live()
        need(not self.signals, self.role + '_signal_already_sent')
        signal.pidfd_send_signal(self.pidfd, value, None, 0)
        self.signals.append(value)

    def terminal(self, expected):
        value = self.process.wait(timeout=WAIT_SECONDS)
        need(value == expected, self.role + '_unexpected_exit')
        need(ready(self.pidfd, 0), self.role + '_pidfd_not_terminal')
        return value


def main():
    report = {'schema': 'hepta-x230-controller-custody-slice/v1', 'passed': False,
              'subject_processes': 3, 'owner_is_probe_driver': True,
              'owner_preexists_controller_client': True, 'runtime_modified': False,
              'SSH_invoked': False, 'historical_roots_inspected': False,
              'automatic_reclamation_implemented': False,
              'same_uid_namespace_replacement_solved': False,
              'production_controller_to_owner_launch_tested': False,
              'owner_crash_tested': False, 'single_request_state_machine_only': True,
              'competing_or_queued_admission_tested': False,
              'checks': {}, 'cleanup_errors': []}
    fixture = None
    controller = writer = None
    channel = controller_channel = None
    descriptors = set()
    phase = 'prepare'
    source = Path(__file__).read_bytes()
    report['source_sha256_before'] = sha(source)

    def own(fd):
        descriptors.add(fd)
        return fd

    def close(fd):
        if fd in descriptors:
            descriptors.remove(fd)
            os.close(fd)

    try:
        need(len(sys.argv) == 1 and sys.platform == 'linux' and os.getuid() == os.geteuid(),
             'unsupported_invocation')
        need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
             'pidfd_API_unavailable')
        fixture = Fixture()
        plan = {'schema': 'hepta-x230-controller-custody-plan/v1',
                'source_sha256': report['source_sha256_before'],
                'topology': 'pre-existing owner driver, fixed controller client, fixed socket writer',
                'controller_termination': 'one SIGKILL through its original pidfd',
                'writer_termination': 'SIGTERM through its original pidfd after control EOF',
                'failure_writer_stop': 'owner-only stop-pipe EOF; no writer SIGKILL retry',
                'parent_death_signal_configured': False,
                'socket_action': 'retain new fixture socket; no unlink or old-root scan',
                'phase_timeout_seconds': WAIT_SECONDS,
                'claims': ['original child custody', 'controller IPC EOF while writer alive',
                           'writer terminal and reaped', 'new socket retained'],
                'excluded_claims': ['production owner startup', 'same-UID replacement protection',
                                    'owner crash recovery', 'reboot', 'power loss', 'exactly-once effects']}
        report['plan'] = fixture.save('plan.json', plan)
        owner = process_identity(os.getpid())
        interpreter = (owner['exe_device'], owner['exe_inode'])
        fixture.save('owner.identity.private.json', {'process': owner, 'root': fixture.identity})
        fixture.event('owner_ready')
        phase = 'controller_start'
        channel, controller_channel = socket.socketpair()
        control_inodes = {(os.fstat(value.fileno()).st_dev, os.fstat(value.fileno()).st_ino)
                          for value in (channel, controller_channel)}
        controller = OriginalChild('controller', CONTROLLER,
                                   [controller_channel.fileno()], os.getpid())
        controller.start(fixture)
        controller.acquire_pidfd()
        fixture.save('controller.spawn.private.json',
                     {'pid': controller.process.pid, 'original_Popen_retained': True,
                      'original_pidfd_acquired': True})
        controller_channel.close()
        controller_channel = None
        receive(channel, b'START\n')
        fixture.save('controller.identity.private.json',
                     controller.capture(os.getpid(), interpreter))
        fixture.event('controller_start_request')
        phase = 'writer_start'
        ready_r, ready_w = (own(fd) for fd in os.pipe2(os.O_CLOEXEC))
        stop_r, stop_w = (own(fd) for fd in os.pipe2(os.O_CLOEXEC))
        notice_r, notice_w = (own(fd) for fd in os.pipe2(os.O_CLOEXEC))
        passed = [fixture.fd, ready_w, stop_r, notice_w]
        need(all((os.fstat(fd).st_dev, os.fstat(fd).st_ino) not in control_inodes for fd in passed),
             'control_socket_in_writer_pass_set')
        writer = OriginalChild('writer', WRITER, passed, os.getpid())
        writer.start(fixture)
        writer.acquire_pidfd()
        fixture.save('writer.spawn.private.json',
                     {'pid': writer.process.pid, 'original_Popen_retained': True,
                      'original_pidfd_acquired': True})
        for fd in (ready_w, stop_r, notice_w):
            close(fd)
        need(ready(ready_r) and os.read(ready_r, 1) == b'R', 'writer_readiness_missing')
        fixture.save('writer.identity.private.json', writer.capture(os.getpid(), interpreter))
        before = fixture.socket_stamp()
        fixture.save('socket.before.private.json', before)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(WAIT_SECONDS)
            probe.connect(str(OUT / 'writer.sock'))
            peer_pid, peer_uid, _ = struct.unpack('3i', probe.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            need(peer_pid == writer.process.pid and peer_uid == os.geteuid(), 'writer_peer_mismatch')
            probe.sendall(b'PING')
            receive(probe, b'PONG')
        need(fixture.socket_stamp() == before, 'socket_changed_during_peer_check')
        channel.sendall(b'ACCEPTED\n')
        receive(channel, b'RUNNING\n')
        controller.live()
        writer.live()
        report['checks'].update(original_writer_peer_verified=True,
                                writer_alive_before_controller_death=True,
                                writer_received_no_control_channel_descriptor=True)
        fixture.event('both_original_children_ready')
        phase = 'controller_sigkill'
        controller.send(signal.SIGKILL)
        fixture.event('controller_sigkill_sent')
        report['controller_exit_code'] = controller.terminal(-signal.SIGKILL)
        report['checks']['original_controller_terminal_and_reaped'] = True
        writer.live()
        phase = 'control_EOF'
        channel.settimeout(WAIT_SECONDS)
        need(channel.recv(1) == b'', 'control_channel_not_EOF')
        writer.live()
        admission_frozen = True
        report['checks'].update(control_EOF_seen_while_original_writer_alive=True,
                                admission_frozen_on_control_EOF=admission_frozen)
        fixture.event('control_EOF_admission_frozen', original_writer_still_live=True)
        phase = 'writer_drain'
        need(admission_frozen, 'writer_drain_before_admission_freeze')
        writer.send(signal.SIGTERM)
        need(ready(notice_r) and os.read(notice_r, 1) == b'T', 'writer_TERM_notice_missing')
        report['writer_exit_code'] = writer.terminal(0)
        report['checks']['original_writer_terminal_and_reaped'] = True
        fixture.event('original_writer_reaped')
        after = fixture.socket_stamp()
        fixture.save('socket.after.private.json', after)
        report['checks']['same_socket_retained_after_reap'] = after == before
        report['checks']['root_descriptor_and_path_preserved'] = (
            directory_identity(os.fstat(fixture.fd)) == fixture.identity ==
            directory_identity(os.lstat(OUT)))
        report['checks']['same_owner_identity_at_end'] = process_identity(os.getpid()) == owner
        report['checks']['SIGKILL_sent_only_to_original_controller'] = (
            controller.signals == [signal.SIGKILL] and writer.signals == [signal.SIGTERM])
        report['checks']['one_writer_launched'] = True
        phase = 'complete'
        fixture.event('custody_observations_complete', socket_retained=True)
    except BaseException as error:
        report['error'] = {'phase': phase, **failure(error)}
    finally:
        # Gate EOF is a graceful failure-path stop request to these fixed
        # original children. No process is rediscovered or adopted by PID.
        for value in (controller_channel, channel):
            if value is not None:
                try:
                    value.close()
                except BaseException as error:
                    report['cleanup_errors'].append({'operation': 'close_control', **failure(error)})
        for fd in tuple(descriptors):
            try:
                close(fd)
            except BaseException as error:
                report['cleanup_errors'].append({'operation': 'close_fixture_pipe', **failure(error)})
        for child in (controller, writer):
            if child is None or child.process is None:
                continue
            try:
                # Fixed controller exits on channel EOF; writer exits on its
                # separate stop-pipe EOF. Uncertain completion is preserved.
                child.process.wait(timeout=WAIT_SECONDS)
                report[child.role + '_finally_reaped'] = True
            except BaseException as error:
                report[child.role + '_finally_reaped'] = False
                report['cleanup_errors'].append({'operation': child.role + '_wait', **failure(error)})
            finally:
                if child.pidfd is not None:
                    try:
                        os.close(child.pidfd)
                    except BaseException as error:
                        report['cleanup_errors'].append({'operation': child.role + '_pidfd_close',
                                                         **failure(error)})
        try:
            report['source_sha256_after'] = sha(Path(__file__).read_bytes())
            report['checks']['source_unchanged'] = (
                report['source_sha256_after'] == report['source_sha256_before'])
        except BaseException as error:
            report['cleanup_errors'].append({'operation': 'source_receipt', **failure(error)})
        if fixture is not None:
            try:
                if fixture.events is not None:
                    fixture.events.flush()
                    os.fsync(fixture.events.fileno())
                    fixture.events.close()
                receipts = [fixture.receipt(name) for name in fixture.files]
                report['artifacts'] = receipts
                report['private_identity_files_must_not_be_published_raw'] = True
                logs = [row for row in receipts if row['file'].endswith(('.stdout', '.stderr'))]
                report['checks']['all_four_child_logs_empty'] = len(logs) == 4 and all(
                    row['bytes'] == 0 for row in logs)
                report['event_count'] = fixture.sequence
                report['passed'] = (phase == 'complete' and 'error' not in report and
                    not report['cleanup_errors'] and
                    report.get('controller_finally_reaped') is True and
                    report.get('writer_finally_reaped') is True and
                    set(report['checks']) == EXPECTED_CHECKS and all(report['checks'].values()))
                result = fixture.save('report.json', report)
                print(json.dumps({'schema': report['schema'], 'passed': report['passed'],
                                  'report': result, 'error': report.get('error')}, sort_keys=True), flush=True)
            except BaseException as error:
                report['passed'] = False
                print(json.dumps({'schema': report['schema'], 'passed': False,
                                  'report_persisted': False, 'phase': phase,
                                  'error': failure(error)}, sort_keys=True), flush=True)
            finally:
                os.close(fixture.fd)
        else:
            print(json.dumps({'schema': report['schema'], 'passed': False,
                              'report_persisted': False, 'error': report.get('error')},
                             sort_keys=True), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
