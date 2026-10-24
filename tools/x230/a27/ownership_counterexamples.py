#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reproduce unsafe cleanup inferences only inside fresh, owned Linux fixtures.

An exit of zero means the counterexamples were observed, not that runtime
recovery is implemented or safe. No SSH, controller, old socket, profile,
runtime state, or user-supplied path is opened. The only child is this Python
interpreter running the fixed helper below. Run without arguments and capture
stdout as the receipt. Failed/uncertain fixture cleanup leaves its new files.
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import sys
import tempfile


WAIT_SECONDS = 5
CHILD = r"""
import os
import sys
lease, root, ready, release, done = map(int, sys.argv[1:])
# Model an executable that closes an inherited lease descriptor but can still
# mutate its namespace. This is not a claim about the installed SSH binary.
os.close(lease)
os.write(ready, b'L')
if os.read(release, 1) != b'W':
    raise SystemExit(21)
written = os.open('written-after-lease', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                  os.O_NOFOLLOW, 0o600, dir_fd=root)
try:
    os.write(written, b'OWNED-FIXTURE\n')
finally:
    os.close(written)
os.write(done, b'W')
if os.read(release, 1) != b'X':
    raise SystemExit(22)
"""


class Refusal(Exception):
    """A fixed, non-sensitive failure category."""


def need(value, category):
    if not value:
        raise Refusal(category)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_mode)


def stamp(value):
    return identity(value) + (value.st_nlink, value.st_size,
                              value.st_mtime_ns, value.st_ctime_ns)


class Fixture:
    """Track only objects deliberately created by this one fixture.

    Cleanup is a test-harness convenience, not a production recovery primitive.
    No recursive removal or directory scanning outside this fresh root occurs.
    """

    def __init__(self):
        self.path = Path(tempfile.mkdtemp(prefix="hepta-a27-custody-", dir="/tmp"))
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC)
        self.root_identity = identity(os.fstat(self.fd))
        need(self.root_identity == identity(os.lstat(self.path)), "fixture_root_changed")
        need(os.fstat(self.fd).st_uid == os.geteuid(), "fixture_owner_mismatch")
        need(stat.S_IMODE(os.fstat(self.fd).st_mode) == 0o700, "fixture_mode_mismatch")
        self.expected = {}
        self.listeners = []
        self.uncertain_writer = False

    def remember(self, name):
        need(name and "/" not in name and name not in (".", ".."), "invalid_fixture_name")
        self.expected[name] = stamp(os.stat(name, dir_fd=self.fd, follow_symlinks=False))

    def forget_removed(self, name):
        try:
            os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            self.expected.pop(name)
            return
        raise Refusal("fixture_name_still_present")

    def listener(self, name):
        result = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listeners.append(result)
        result.bind(str(self.path / name))
        result.listen(1)
        os.chmod(name, 0o600, dir_fd=self.fd, follow_symlinks=False)
        self.remember(name)
        return result

    def rename(self, old, new):
        os.rename(old, new, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        self.expected.pop(old)
        self.remember(new)

    def cleanup(self):
        for listener in self.listeners:
            listener.close()
        try:
            if self.uncertain_writer:
                return False
            if identity(os.fstat(self.fd)) != self.root_identity:
                return False
            if identity(os.lstat(self.path)) != self.root_identity:
                return False
            if set(os.listdir(self.fd)) != set(self.expected):
                return False
            for name, expected in self.expected.items():
                current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if stamp(current) != expected:
                    return False
                if stat.S_ISDIR(current.st_mode):
                    os.rmdir(name, dir_fd=self.fd)
                else:
                    os.unlink(name, dir_fd=self.fd)
            if os.listdir(self.fd):
                return False
            if identity(os.lstat(self.path)) != self.root_identity:
                return False
            os.rmdir(self.path)
            return True
        except OSError:
            return False
        finally:
            os.close(self.fd)


def byte_with_deadline(fd, wanted):
    readable, _, _ = select.select([fd], [], [], WAIT_SECONDS)
    need(bool(readable), "fixture_handshake_timeout")
    need(os.read(fd, 1) == wanted, "fixture_handshake_mismatch")


def inherited_lease_release_does_not_end_writer(fixture):
    descriptors = set()
    child = None

    def own(fd):
        descriptors.add(fd)
        return fd

    def close(fd):
        if fd in descriptors:
            descriptors.remove(fd)
            os.close(fd)

    try:
        lease = own(os.open("lease", os.O_RDWR | os.O_CREAT | os.O_EXCL |
                            os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fixture.fd))
        fixture.remember("lease")
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ready_r, ready_w = (own(fd) for fd in os.pipe2(os.O_CLOEXEC))
        release_r, release_w = (own(fd) for fd in os.pipe2(os.O_CLOEXEC))
        done_r, done_w = (own(fd) for fd in os.pipe2(os.O_CLOEXEC))
        inherited = (lease, fixture.fd, ready_w, release_r, done_w)
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", CHILD, *map(str, inherited)],
            pass_fds=inherited, close_fds=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        fixture.uncertain_writer = True
        for fd in (ready_w, release_r, done_w):
            close(fd)
        byte_with_deadline(ready_r, b"L")
        close(lease)
        recovering = own(os.open("lease", os.O_RDWR | os.O_NOFOLLOW |
                                 os.O_CLOEXEC, dir_fd=fixture.fd))
        fcntl.flock(recovering, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(child.poll() is None, "writer_exited_before_reacquisition")
        os.write(release_w, b"W")
        byte_with_deadline(done_r, b"W")
        fixture.remember("written-after-lease")
        reader = own(os.open("written-after-lease", os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_CLOEXEC, dir_fd=fixture.fd))
        need(os.read(reader, 64) == b"OWNED-FIXTURE\n", "writer_marker_mismatch")
        need(child.poll() is None, "writer_exited_before_final_gate")
        os.write(release_w, b"X")
        need(child.wait(timeout=WAIT_SECONDS) == 0, "writer_nonzero_exit")
        fixture.uncertain_writer = False
        need(child.stderr.read(4097) == b"", "writer_stderr_present")
        return {"lease_reacquired_while_original_child_alive": True,
                "writer_created_file_while_recovery_lock_held": True,
                "owned_child_reaped": True,
                "models_PDEATHSIG_timing": False,
                "claims_installed_SSH_fd_behavior": False}
    finally:
        # Only this original Popen child may be signalled on a failed fixture.
        # Closing the parent-only gate writer normally makes the helper exit.
        for fd in tuple(descriptors):
            close(fd)
        if child is not None:
            try:
                if child.poll() is None:
                    try:
                        child.wait(timeout=WAIT_SECONDS)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=WAIT_SECONDS)
                fixture.uncertain_writer = False
            finally:
                if child.stderr is not None:
                    child.stderr.close()


def checked_socket_name_can_be_replaced(fixture):
    fixture.listener("control")
    checked = fixture.expected["control"]
    fixture.rename("control", "original-control")
    fixture.listener("control")
    replacement = fixture.expected["control"]
    need(checked[:2] != replacement[:2], "replacement_inode_not_distinct")
    # The naive recovery action has a pinned parent but no inode predicate.
    os.unlink("control", dir_fd=fixture.fd)
    fixture.forget_removed("control")
    need("original-control" in os.listdir(fixture.fd), "original_socket_missing")
    return {"pinned_parent_unchanged": True,
            "replacement_socket_removed_by_name_unlink": True,
            "original_socket_preserved_under_its_fixture_name": True}


def checked_socket_name_can_become_symlink(fixture):
    fixture.listener("control")
    fixture.rename("control", "original-control")
    target = os.open("target", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fixture.fd)
    os.close(target)
    fixture.remember("target")
    target_before = fixture.expected["target"]
    os.symlink("target", "control", dir_fd=fixture.fd)
    fixture.remember("control")
    os.unlink("control", dir_fd=fixture.fd)
    fixture.forget_removed("control")
    need(stamp(os.stat("target", dir_fd=fixture.fd, follow_symlinks=False)) ==
         target_before, "fixture_symlink_target_changed")
    return {"replacement_symlink_removed_by_name_unlink": True,
            "symlink_target_was_not_followed_or_removed": True}


def checked_empty_root_name_can_be_replaced(fixture):
    os.mkdir("root", 0o700, dir_fd=fixture.fd)
    fixture.remember("root")
    original = os.open("root", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                       os.O_CLOEXEC, dir_fd=fixture.fd)
    try:
        checked = identity(os.fstat(original))
        fixture.rename("root", "original-root")
        os.mkdir("root", 0o700, dir_fd=fixture.fd)
        fixture.remember("root")
        need(identity(os.stat("root", dir_fd=fixture.fd, follow_symlinks=False)) !=
             checked, "replacement_root_not_distinct")
        os.rmdir("root", dir_fd=fixture.fd)
        fixture.forget_removed("root")
        need(identity(os.fstat(original)) == checked, "pinned_root_changed")
        return {"pinned_original_directory_still_exists": True,
                "replacement_empty_directory_removed_by_name": True}
    finally:
        os.close(original)


def main():
    report = {"schema": "hepta-x230-socket-custody-counterexamples/v1",
              "meaning": "Success means unsafe cleanup inferences reproduced in owned fixtures.",
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "automatic_recovery_implemented": False, "runtime_changed": False,
              "preexisting_socket_paths_inspected": False, "ssh_invoked": False,
              "controller_SIGKILL_exercised": False, "tests": []}
    if len(sys.argv) != 1 or sys.platform != "linux" or os.getuid() != os.geteuid():
        report.update(all_counterexamples_observed=False, refusal="unsupported_invocation")
        print(json.dumps(report, sort_keys=True, indent=2))
        return 2
    for run in (inherited_lease_release_does_not_end_writer,
                checked_socket_name_can_be_replaced,
                checked_socket_name_can_become_symlink,
                checked_empty_root_name_can_be_replaced):
        fixture = None
        row = {"name": run.__name__, "counterexample_observed": False,
               "owned_fixture_cleanup_complete": False}
        try:
            fixture = Fixture()
            row["observations"] = run(fixture)
            row["counterexample_observed"] = True
        except Exception as error:
            row["error_type"] = type(error).__name__
            if isinstance(error, Refusal):
                row["refusal"] = str(error)
        finally:
            if fixture is not None:
                row["owned_fixture_cleanup_complete"] = fixture.cleanup()
        report["tests"].append(row)
        if not row["counterexample_observed"] or not row["owned_fixture_cleanup_complete"]:
            break
    report["all_counterexamples_observed"] = len(report["tests"]) == 4 and all(
        row["counterexample_observed"] and row["owned_fixture_cleanup_complete"]
        for row in report["tests"])
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["all_counterexamples_observed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
