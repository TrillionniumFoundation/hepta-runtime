"""Verify the installed standalone HIA job receipt effect against the local filesystem."""
from __future__ import annotations

import errno
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


CAPACITY = 4 << 20
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


def native_entry(resources, code, prototype):
    import ctypes
    import mmap

    protect = ctypes.CDLL(None, use_errno=True).mprotect
    protect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    protect.restype = ctypes.c_int
    region = resources.enter_context(mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE))
    region.write(code)
    address = ctypes.addressof(ctypes.c_char.from_buffer(region))
    if protect(address, len(code), mmap.PROT_READ | mmap.PROT_EXEC):
        raise OSError(ctypes.get_errno(), 'test mapping could not become executable')
    return prototype(address)


@unittest.skipUnless(os.environ.get('HIA_TEST_JOB_RECEIPT_EXE'), 'requires the installed HIA receipt writer')
class JobReceiptExecutableTests(unittest.TestCase):
    def setUp(self):
        self.executable = Path(os.environ['HIA_TEST_JOB_RECEIPT_EXE']).resolve(strict=True)
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)

    def request(self, name=b'job_1.2@local', payload=b'{\n  "launch_state": "pending"\n}',
                *, parent=None, sealed=True, suffix=b'', magic=b'HIAJRQ01'):
        pid = os.getpid() if parent is None else parent
        frame = struct.pack('<8s3Q', magic, len(payload), pid, len(name)) + name + payload + suffix
        return self.invoke(frame, sealed=sealed)

    def invoke(self, frame, *, sealed=True, pass_fds=()):
        with os.fdopen(os.memfd_create('test-job-receipt', os.MFD_ALLOW_SEALING), 'wb', buffering=0) as source:
            self.assertEqual(len(frame), source.write(frame))
            if sealed:
                fcntl.fcntl(source, fcntl.F_ADD_SEALS, SEALS)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                return subprocess.run([self.executable], stdin=source, stdout=directory,
                                      stderr=subprocess.PIPE, env={'PATH': ''}, timeout=5, pass_fds=pass_fds)
            finally:
                os.close(directory)

    def check_receipt(self, result, phase, status):
        self.assertEqual(result.returncode, 0)
        self.assertEqual(struct.unpack('<8sQq', result.stderr), (b'HIAJRW01', phase, status))

    def test_owner_markers_observe_only_original_directory_entries(self):
        names = ('owner-intent.json', 'started.json', 'exit.json', 'exit.witness.json', 'exit.witness.json.tmp')
        state = self.root.stat()
        frame = struct.pack('<8s4Q', b'HIAJMK01', os.getpid(), state.st_dev, state.st_ino, 0)
        for mask in range(32):
            for index, name in enumerate(names):
                path = self.root / name
                path.unlink(missing_ok=True)
                if mask & (1 << index):
                    if index % 2:
                        path.symlink_to('missing-target')
                    else:
                        path.touch()
            self.check_receipt(self.invoke(frame), 3, mask)
        for altered in (frame[:-1], frame + b'x',
                        struct.pack('<8s4Q', b'HIAJMK01', os.getppid(), state.st_dev, state.st_ino, 0),
                        struct.pack('<8s4Q', b'HIAJMK01', os.getpid(), state.st_dev, state.st_ino + 1, 0)):
            refused = self.invoke(altered)
            self.assertEqual((refused.returncode, refused.stderr), (65, b''))
        refused = self.invoke(frame, sealed=False)
        self.assertEqual((refused.returncode, refused.stderr), (65, b''))
        self.root.chmod(0o750)
        refused = self.invoke(frame)
        self.assertEqual((refused.returncode, refused.stderr), (65, b''))

    def request_custody(self, directory, sender, *, state=None, parent=None):
        status = os.fstat(directory) if state is None else state
        caller = os.getpid() if parent is None else parent
        frame = struct.pack('<8s5Q', b'HIAJLH01', caller, status.st_dev, status.st_ino, sender.fileno(), 0)
        with os.fdopen(os.memfd_create('custody-frame', os.MFD_ALLOW_SEALING), 'wb', buffering=0) as source:
            source.write(frame)
            fcntl.fcntl(source, fcntl.F_ADD_SEALS, SEALS)
            return subprocess.run([self.executable], stdin=source, stdout=directory, stderr=subprocess.PIPE,
                                  pass_fds=(sender.fileno(),), env={'PATH': ''}, timeout=5)

    def test_native_custody_returns_one_locked_description_with_close_on_exec(self):
        from array import array
        from contextlib import ExitStack

        with ExitStack() as stack:
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, directory)
            receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            stack.enter_context(receiver)
            stack.enter_context(sender)
            self.check_receipt(self.request_custody(directory, sender), 12, 0)
            width = array('i').itemsize
            tag, ancillary, flags, _ = receiver.recvmsg(1, socket.CMSG_SPACE(width), socket.MSG_CMSG_CLOEXEC)
            self.assertEqual((tag, flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)), (b'L', 0))
            self.assertEqual(len(ancillary), 1)
            level, kind, data = ancillary[0]
            self.assertEqual((level, kind, len(data)), (socket.SOL_SOCKET, socket.SCM_RIGHTS, width))
            held = array('i')
            held.frombytes(data)
            received, = held
            with os.fdopen(received, 'r+b') as owner:
                self.assertFalse(os.get_inheritable(received))
                path = self.root / 'owner.lock'
                self.assertEqual(os.fstat(received).st_ino, path.stat().st_ino)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                with path.open('r+b') as other, self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.check_receipt(self.request_custody(directory, sender), 5, -errno.EWOULDBLOCK)
            with path.open('r+b') as successor:
                fcntl.flock(successor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(path.read_bytes(), b'')

    def test_native_custody_refuses_changed_directory_prior_names_and_unsafe_lock(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, directory)
            receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            stack.enter_context(receiver)
            stack.enter_context(sender)
            result = self.request_custody(directory, sender, parent=os.getppid())
            self.assertEqual((result.returncode, result.stderr), (65, b''))
            result = self.request_custody(directory, sender, state=self.root.parent.stat())
            self.assertEqual((result.returncode, result.stderr), (65, b''))
            lock = self.root / 'owner.lock'
            self.assertFalse(lock.exists())
            lock.touch(mode=0o640)
            lock.chmod(0o640)
            self.check_receipt(self.request_custody(directory, sender), 20, 0)
            lock.chmod(0o600)
            os.link(lock, self.root / 'second')
            self.check_receipt(self.request_custody(directory, sender), 20, 0)
            (self.root / 'second').unlink()
            names = ('owner-intent.json', 'started.json', 'exit.json', 'exit.witness.json', 'exit.witness.json.tmp')
            for index, name in enumerate(names):
                (self.root / name).symlink_to('missing')
                self.check_receipt(self.request_custody(directory, sender), 21, 1 << index)
                (self.root / name).unlink()
            receiver.setblocking(False)
            with self.assertRaises(BlockingIOError):
                receiver.recv(1)
            with lock.open('r+b') as independent:
                fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_native_custody_checks_socket_creator_before_opening(self):
        from array import array

        transfer, child_transfer = socket.socketpair()
        with transfer, child_transfer:
            child = os.fork()
            if child == 0:
                try:
                    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                    with left, right:
                        child_transfer.sendmsg([b'P'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array('i', [right.fileno()]))])
                finally:
                    os._exit(0)
            try:
                width = array('i').itemsize
                _, control, _, _ = transfer.recvmsg(1, socket.CMSG_SPACE(width), socket.MSG_CMSG_CLOEXEC)
                descriptors = array('i')
                descriptors.frombytes(control[0][2])
                with socket.socket(fileno=descriptors[0]) as foreign:
                    directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        result = self.request_custody(directory, foreign)
                    finally:
                        os.close(directory)
                    self.assertEqual((result.returncode, result.stderr), (65, b''))
                    self.assertFalse((self.root / 'owner.lock').exists())
            finally:
                os.waitpid(child, 0)

    def acquire_owner_lock(self, descriptor, *, parent=None, device=None, inode=None, sealed=True):
        state = os.fstat(descriptor)
        caller = os.getpid() if parent is None else parent
        frame = struct.pack('<8s4Q', b'HIAJLF01', caller, state.st_dev if device is None else device,
                            state.st_ino if inode is None else inode, 0)
        with os.fdopen(os.memfd_create('owner-fd-frame', os.MFD_ALLOW_SEALING), 'wb', buffering=0) as source:
            source.write(frame)
            if sealed:
                fcntl.fcntl(source, fcntl.F_ADD_SEALS, SEALS)
            return subprocess.run([self.executable], stdin=source, stdout=descriptor, stderr=subprocess.PIPE,
                                  env={'PATH': ''}, timeout=5)

    def test_owner_lock_stays_with_original_open_description(self):
        path = self.root / 'owner.lock'
        with path.open('x+b') as owner, path.open('r+b') as competing:
            path.chmod(0o600)
            self.check_receipt(self.acquire_owner_lock(owner.fileno()), 2, 0)
            self.check_receipt(self.acquire_owner_lock(competing.fileno()), 2, -errno.EWOULDBLOCK)
            with os.fdopen(os.dup(owner.fileno()), 'r+b') as duplicate:
                owner.close()
                self.check_receipt(self.acquire_owner_lock(duplicate.fileno()), 2, 0)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.check_receipt(self.acquire_owner_lock(competing.fileno()), 2, 0)
            self.assertEqual(path.read_bytes(), b'')

    def test_owner_lock_requires_sealed_parent_and_exact_private_inode(self):
        path = self.root / 'owner.lock'
        with path.open('x+b') as owner, path.open('r+b') as independent:
            path.chmod(0o600)
            fd = owner.fileno()
            for change in ({'parent': os.getppid()}, {'inode': os.fstat(fd).st_ino + 1},
                           {'device': os.fstat(fd).st_dev + 1}, {'sealed': False}):
                result = self.acquire_owner_lock(fd, **change)
                self.assertEqual((result.returncode, result.stderr), (65, b''))
            path.chmod(0o640)
            result = self.acquire_owner_lock(fd)
            self.assertEqual((result.returncode, result.stderr), (65, b''))
            path.chmod(0o600)
            os.link(path, self.root / 'second')
            result = self.acquire_owner_lock(fd)
            self.assertEqual((result.returncode, result.stderr), (65, b''))
            fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def group_signal(self, leader, action, *, parent=None):
        caller = os.getpid() if parent is None else parent
        return self.invoke(struct.pack('<8s4Q', b'HIASGQ01', caller, leader, action, 0))

    def test_signal_is_issued_only_to_an_original_child_in_its_own_group(self):
        marker = ("import ctypes, time; "
                  "assert ctypes.CDLL(None).prctl(15, b'odd) name\\n)', 0, 0, 0) == 0; "
                  "print('ready', flush=True); time.sleep(20)")
        self.check_receipt(self.group_signal(0, 0), 0, 0)
        for operation, number in ((1, signal.SIGTERM), (2, signal.SIGKILL)):
            with self.subTest(number=number), subprocess.Popen(
                    [sys.executable, '-c', marker], start_new_session=True,
                    stdout=subprocess.PIPE, text=True) as child:
                try:
                    self.assertEqual(child.stdout.readline(), 'ready\n')
                    invalid = self.group_signal(child.pid, operation, parent=os.getppid())
                    self.assertEqual((invalid.returncode, invalid.stderr), (65, b''))
                    arbitrary = self.group_signal(child.pid, 15)
                    self.assertEqual((arbitrary.returncode, arbitrary.stderr), (65, b''))
                    self.assertIsNone(child.poll())
                    self.check_receipt(self.group_signal(child.pid, operation), 3, 0)
                    self.assertEqual(child.wait(timeout=5), -number)
                finally:
                    if child.poll() is None:
                        child.kill()

        with subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']) as child:
            try:
                self.assertNotEqual(os.getpgid(child.pid), child.pid)
                self.check_receipt(self.group_signal(child.pid, 1), 2, -errno.EBADMSG)
                self.assertIsNone(child.poll())
            finally:
                child.terminate()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_both_durable_publications_preserve_bytes_and_mode(self):
        destination = self.root / 'job_1.2@local.json'
        self.check_receipt(self.request(), 6, 0)
        self.assertEqual(destination.read_bytes(), b'{\n  "launch_state": "pending"\n}')
        old = destination.stat().st_ino
        result = b'{\n  "launch_state": "started"\n}'
        self.check_receipt(self.request(payload=result), 6, 0)
        self.assertEqual(destination.read_bytes(), result)
        self.assertNotEqual(old, destination.stat().st_ino)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(list(self.root.iterdir()), [destination])

    def test_existing_temporary_is_not_overwritten_or_promoted(self):
        pending = self.root / f'job_1.2@local.json.tmp.{os.getpid()}'
        pending.write_bytes(b'frozen prior attempt')
        self.check_receipt(self.request(), 1, -errno.EEXIST)
        self.assertEqual(pending.read_bytes(), b'frozen prior attempt')
        self.assertEqual(list(self.root.iterdir()), [pending])

    def test_rename_failure_is_not_success_or_replayed(self):
        destination = self.root / 'job_1.2@local.json'
        destination.mkdir()
        self.check_receipt(self.request(payload=b'{}'), 5, -errno.EISDIR)
        pending = self.root / f'job_1.2@local.json.tmp.{os.getpid()}'
        self.assertEqual(pending.read_bytes(), b'{}')
        self.assertTrue(destination.is_dir())
        self.check_receipt(self.request(), 1, -errno.EEXIST)

    def test_bad_descriptor_and_frame_refuse_before_owning_a_name(self):
        for kwargs in ({'parent': os.getpid() + 1}, {'sealed': False}, {'suffix': b'x'},
                       {'name': b'../outside'}, {'name': b'x\0y'}, {'name': b'x' * 129},
                       {'payload': b'[]'}, {'payload': b'{}' * (CAPACITY // 2 + 1)}):
            with self.subTest(fields=tuple(kwargs)):
                refused = self.request(**kwargs)
                self.assertEqual((refused.returncode, refused.stderr), (65, b''))
                self.assertEqual(list(self.root.iterdir()), [])

    def test_original_registry_size_boundary(self):
        payload = b'{"value":"' + b'x' * (CAPACITY - 12) + b'"}'
        self.assertEqual(len(payload), CAPACITY)
        self.check_receipt(self.request(name=b'id', payload=payload), 6, 0)
        self.assertEqual((self.root / 'id.json').read_bytes(), payload)

    def test_terminal_wire_publishes_the_existing_newline_terminated_files(self):
        payload = b'{"terminal_publication_protocol": 1}\n'
        for name, raw, magic in ((b'exit', b'{}', b'HIAJRQ02'),
                                 (b'exit', b'{}\n\n', b'HIAJRQ02'),
                                 (b'exit.witnezz', payload, b'HIAJRQ02'),
                                 (b'job', payload, b'HIAJRQ02'),
                                 (b'exit', payload, b'HIAJRQ01')):
            refused = self.request(name=name, payload=raw, magic=magic)
            self.assertEqual((refused.returncode, refused.stderr), (65, b''))
            self.assertEqual(list(self.root.iterdir()), [])
        for name in (b'exit', b'exit.witness'):
            self.check_receipt(self.request(name=name, payload=payload, magic=b'HIAJRQ02'), 6, 0)
            destination = self.root / (name.decode('ascii') + '.json')
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_owner_wire_creates_both_exact_records_and_never_replaces_previous_intent(self):
        def owner(**kwargs):
            return self.request(name=b'', payload=b'{"supervisor_pid": 13}', magic=b'HIAJRO01', **kwargs)
        self.check_receipt(owner(), 6, 0)
        names = ('owner-intent.json', 'started.json')
        records = {name: (self.root / name).stat().st_ino for name in names}
        self.assertEqual(set(path.name for path in self.root.iterdir()), set(names))
        for name in names:
            record = self.root / name
            self.assertEqual(record.read_bytes(), b'{"supervisor_pid": 13}')
            self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.check_receipt(owner(), 1, -errno.EEXIST)
        self.assertEqual({name: (self.root / name).stat().st_ino for name in names}, records)

    def test_child_receipt_probe_and_exact_publication_are_distinct(self):
        magic = b'HIAJCH01'
        payload = b'{"identity": null, "pid": 13}\n'
        self.check_receipt(self.request(name=b'', payload=b'{}\n', magic=magic), 0, 0)
        for fields in ({'name': b''}, {'name': b'exit'}, {'payload': payload[:-1]},
                       {'parent': os.getppid()}, {'sealed': False}, {'suffix': b'x'},
                       {'payload': b'{' + b'x' * 65535 + b'}\n'}):
            result = self.request(**({'name': b'child', 'payload': payload, 'magic': magic} | fields))
            self.assertEqual((result.returncode, result.stderr), (65, b''))
            self.assertEqual(list(self.root.iterdir()), [])
        child = self.root / 'child.json'
        staging = self.root / f'child.json.tmp.{os.getpid()}'
        staging.write_bytes(b'unchanged')
        self.check_receipt(self.request(name=b'child', payload=payload, magic=magic), 1, -errno.EEXIST)
        self.assertFalse(child.exists())
        self.assertEqual(staging.read_bytes(), b'unchanged')
        staging.unlink()
        self.check_receipt(self.request(name=b'child', payload=payload, magic=magic), 6, 0)
        self.assertEqual(list(self.root.iterdir()), [child])
        self.assertEqual(child.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o600)

    def test_owner_wire_stops_at_partial_publication_without_retry(self):
        started = self.root / 'started.json'
        started.write_bytes(b'prior receipt')
        kwargs = {'name':b'', 'payload':b'{"supervisor_pid": 13}', 'magic':b'HIAJRO01'}
        self.check_receipt(self.request(**kwargs), 5, -errno.EEXIST)
        self.assertEqual(started.read_bytes(), b'prior receipt')
        intent = self.root / 'owner-intent.json'
        self.assertEqual(intent.read_bytes(), kwargs['payload'])
        previous = intent.stat().st_ino
        self.check_receipt(self.request(**kwargs), 1, -errno.EEXIST)
        self.assertEqual(intent.stat().st_ino, previous)

    def test_original_wait_holds_custody_and_returns_real_wait_status(self):
        import ctypes
        import mmap
        import time

        _, marker, remainder = self.executable.read_bytes().partition(b'HIAWABI1')
        code, end, _ = remainder.partition(b'HIAWEND1')
        self.assertTrue(marker and end and 32 <= len(code) <= 256)
        with mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE) as mapping:
            mapping.write(code)
            address = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
            protect = ctypes.CDLL(None, use_errno=True).mprotect
            protect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            protect.restype = ctypes.c_int
            self.assertEqual(protect(address, len(code), mmap.PROT_READ | mmap.PROT_EXEC), 0)
            wait = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_uint64, ctypes.c_uint64)(address)
            for pid, mode in ((0, 0), (0, 1), (2**31, 0), (os.getpid(), 2)):
                self.assertEqual(wait(pid, mode), -errno.EINVAL)
            self.assertEqual(wait(os.getpid(), 0), -errno.ECHILD)
            for exit_code in (0, 37):
                with self.subTest(exit_code=exit_code), subprocess.Popen(
                        [sys.executable, '-c', f'import sys; sys.stdin.buffer.read(); sys.exit({exit_code})'],
                        stdin=subprocess.PIPE) as child:
                    self.assertEqual(wait(child.pid, 0), 0)
                    self.assertEqual(wait(child.pid, 1), 0)
                    child.stdin.close()
                    deadline = time.monotonic() + 4
                    while wait(child.pid, 0) == 0 and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertEqual(wait(child.pid, 0), 1)
                    self.assertEqual(wait(child.pid, 0), 1)
                    status = wait(child.pid, 1)
                    self.assertEqual(status >> 32, 1)
                    child.returncode = os.waitstatus_to_exitcode(status & 0xffffffff)
                    self.assertEqual(child.returncode, exit_code)
                    self.assertEqual(wait(child.pid, 0), -errno.ECHILD)
                    self.assertEqual(wait(child.pid, 1), -errno.ECHILD)

    def test_owner_wire_requires_seals_exact_parent_and_no_caller_names(self):
        request = {'name':b'', 'payload':b'{"supervisor_pid": 13}', 'magic':b'HIAJRO01'}
        for patch in ({'name':b'started'}, {'sealed':False}, {'parent':os.getpid()+1},
                      {'payload':b'{"supervisor_pid": 13}\n'}, {'suffix':b'x'},
                      {'payload':b'{'+b'x'*65535+b'}'}):
            refused = self.request(**(request | patch))
            self.assertEqual((refused.returncode, refused.stderr), (65, b''))
            self.assertEqual(list(self.root.iterdir()), [])

    def test_native_owner_identity_uses_the_original_pid_boot_and_start_ticks(self):
        from contextlib import ExitStack
        import ctypes

        raw = self.executable.read_bytes()
        self.assertIn(b'HIAOWNIDHIAWABI1', raw)
        policy = raw.split(b'HIAJPOL1', 1)[1]
        pid = os.getpid()
        boot = Path('/proc/sys/kernel/random/boot_id').read_bytes()
        record = Path('/proc/self/stat').read_bytes()
        fields = record.rsplit(b') ', 1)[1].split()
        expected = boot.strip() + b':' + fields[19]
        unusual = str(pid).encode() + b' (own) name\n)) ' + b' '.join(fields) + b'\n'
        with ExitStack() as stack:
            call = native_entry(stack, policy, ctypes.CFUNCTYPE(ctypes.c_uint64, *([ctypes.c_void_p, ctypes.c_uint64] * 3)))

            def observe(snapshot=record, boot_id=boot, owner=pid):
                request = struct.pack('<8s2Q', b'HIAJPI01', owner, len(snapshot)) + boot_id + snapshot
                output = ctypes.create_string_buffer(57)
                used = call(request, len(request), output, len(output), None, 0)
                self.assertLessEqual(used, len(output))
                return output.raw[:used]

            self.assertEqual(observe(), expected)
            self.assertEqual(observe(unusual), expected)
            self.assertEqual(observe(owner=pid + 1), b'')
            self.assertEqual(observe(boot_id=b'x' + boot[1:]), b'')
            self.assertEqual(observe(record[:record.rfind(b') ')]), b'')
            for value in (b'18446744073709551616', b'0001', b'-1'):
                changed = fields[:19] + [value] + fields[20:]
                invalid = str(pid).encode() + b' (own) ' + b' '.join(changed) + b'\n'
                self.assertEqual(observe(invalid), b'')

    def test_native_capture_preserves_isolated_extent_and_actual_io(self):
        from contextlib import ExitStack
        import ctypes

        raw = self.executable.read_bytes()
        capture = raw.split(b'HIAKABI1', 1)[1].split(b'HIAKEND1', 1)[0]
        policy = raw.split(b'HIAJPOL1', 1)[1]
        limit = 16 << 20
        with ExitStack() as stack:
            plan = native_entry(stack, policy, ctypes.CFUNCTYPE(ctypes.c_uint64, *([ctypes.c_void_p, ctypes.c_uint64] * 3)))
            perform = native_entry(stack, capture, ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_int64,
                                                                 ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64))
            cases = ((0, limit, 65536, 0, (65536, 0)),
                     (1, limit - 3, 65536, 0, (3, 1)),
                     (1, limit - 3, 65536, 1, (0, 1)),
                     (1, limit, 0, 0, (0, 0)),
                     (1, limit, 1, 0, (0, 1)),
                     (1, limit + 1, 1, 0, None),
                     (0, 0, 65537, 0, None),
                     (0, 0, 1, 2, None))
            for mode, stored, size, failed, expected in cases:
                with self.subTest(mode=mode, stored=stored, size=size, failed=failed):
                    request = struct.pack('<8s5Q', b'HIAJLG01', mode, stored, size, failed, 0)
                    reply = ctypes.create_string_buffer(16)
                    result = plan(request, len(request), reply, 16, None, 0)
                    if expected is None:
                        self.assertEqual(result, 0)
                        self.assertEqual(reply.raw, bytes(16))
                    else:
                        self.assertEqual(result, 16)
                        self.assertEqual(struct.unpack('<2Q', reply.raw), expected)

            for descriptor_tuple, expected in (
                    ((9, 3, 11, 7, 0), (3, 0, 11, 1, 7, 2, 3, 7)),
                    ((3, 4, 5, 3, 0), None),
                    ((3, 4, 1, 5, 0), None),
                    ((3, 4, 2**31, 5, 0), None),
                    ((3, 4, 5, 6, 1), None)):
                request = struct.pack('<8s5Q', b'HIAJSP01', *descriptor_tuple)
                reply = ctypes.create_string_buffer(64)
                result = plan(request, len(request), reply, len(reply), None, 0)
                if expected is None:
                    self.assertEqual((result, reply.raw), (0, bytes(64)), descriptor_tuple)
                else:
                    self.assertEqual((result, struct.unpack('<8Q', reply.raw)), (64, expected))

            reader, writer = os.pipe()
            stack.callback(os.close, reader)
            with os.fdopen(writer, 'wb', buffering=0) as pipe:
                pipe.write(b'native-log')
            buffer = ctypes.create_string_buffer(65536)
            self.assertEqual(perform(reader, buffer, len(buffer), 2), 10)
            log = self.root / 'captured'
            with log.open('xb', buffering=0) as sink:
                self.assertEqual(perform(sink.fileno(), buffer, 6, 0), 6)
                self.assertEqual(perform(sink.fileno(), None, 0, 1), 0)
            self.assertEqual(log.read_bytes(), b'native')
            self.assertEqual(perform(reader, buffer, len(buffer), 2), 0)
            with open('/dev/full', 'wb', buffering=0) as sink:
                self.assertEqual(perform(sink.fileno(), buffer, 6, 0), errno.ENOSPC << 32)
            self.assertEqual(perform(-1, None, 0, 1), errno.EINVAL << 32)

    def test_cancellation_publishes_before_signalling_only_the_original_pidfd(self):
        nonce = b'0123456789abcdef' * 2
        job = b'original-cancel'
        timestamp = 18446744073709551615
        record = self.root / 'cancel-request.json'
        staged = self.root / 'cancel-request.json.tmp'
        child = subprocess.Popen([sys.executable, '-I', '-S', '-c', 'import time; time.sleep(10)'])
        try:
            owner = os.pidfd_open(child.pid)
            try:
                def request(target=owner, name=job, token=nonce):
                    return struct.pack('<8s5Q32s', b'HIAJRC01', os.getpid(), target,
                                       timestamp, len(name), 0, token) + name

                for wrong in (request(target=1), request(name=b'not/a/name'), request(token=b'z' * 32)):
                    refused = self.invoke(wrong, pass_fds=(owner,))
                    self.assertEqual((refused.returncode, refused.stderr), (65, b''))
                    self.assertIsNone(child.poll())
                    self.assertEqual(list(self.root.iterdir()), [])
                staged.write_bytes(b'original incomplete cancellation')
                staged_inode = staged.stat().st_ino
                self.check_receipt(self.invoke(request(), pass_fds=(owner,)), 1, -errno.EEXIST)
                self.assertEqual(staged.stat().st_ino, staged_inode)
                self.assertFalse(record.exists())
                self.assertIsNone(child.poll())
                staged.unlink()
                self.check_receipt(self.invoke(request(), pass_fds=(owner,)), 7, 0)
                self.assertEqual(child.wait(timeout=4), -15)
                expected = {'at_unix_ms': timestamp, 'job_id': job.decode(), 'launch_nonce': nonce.decode()}
                self.assertEqual(record.read_bytes(), (json.dumps(expected, sort_keys=True) + '\n').encode())
                self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
                self.assertFalse(staged.exists())
            finally:
                os.close(owner)
        finally:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=4)
