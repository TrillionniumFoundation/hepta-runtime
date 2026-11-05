#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Run the complete, serial REA qualification gates and retain their evidence.

Preparation does not run this script. An operator starts it only after source
freeze, with explicit absolute paths and an otherwise idle task-owned target:

    python3 scripts/rea_full_qualification.py \
        --repo /absolute/hepta-runtime-checkout \
        --cargo-home /absolute/available-offline-cargo-cache \
        --target-dir /absolute/task-exclusive-target \
        --jobs 4 --output-dir /absolute/new-qualification-results

An existing dedicated target is allowed and preserved. The repository's default
target is rejected. A nonblocking flock and a repository ownership marker guard
against reuse by another instance of this runner; the operator must still ensure
that unrelated cargo processes do not use this target. HOME is never changed.

The five gates run exactly once, in order: formatting, all-feature Clippy,
no-default-feature Clippy, all-feature nextest, no-default-feature nextest.
A failing gate does not suppress later gates. Test retries are zero. Nextest's
--build-jobs controls compilation; its --jobs alias controls test concurrency
and must not be confused with Cargo's --jobs.

Source/fixture/config/script SHA-256 inventories bracket the gates. Linux
inotify also records local writes, replacements and metadata changes during the
interval, including a change subsequently restored to the original bytes.
Observed changes or loss of monitoring invalidate the run. This requires Linux
and a filesystem delivering local inotify events; it is not a malicious same-UID
or remote-filesystem mutation proof. Docs, results, build/cache directories and
explicit test temporary directories are excluded. Toolchain, system libraries
and the offline dependency cache remain trusted external inputs.

Every stage retains exact argv, timing, exit code, stdout/stderr and their
SHA-256 values. nextest summaries remain verbatim log excerpts rather than
invented structured test counts. Ignored tests follow nextest's normal policy;
doctests are not part of nextest --all-targets. Feature-specific and final
binary digests identify observed bytes; this script does not publish a binary.

References:
https://nexte.st/docs/running/
https://nexte.st/docs/features/retries/
https://doc.rust-lang.org/clippy/usage.html
https://man7.org/linux/man-pages/man7/inotify.7.html
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
import traceback

SCHEMA = "hepta.rea.full-qualification.v1"
TOOLCHAIN = "1.95.0"
# Match CI without changing the runner process or its private evidence permissions.
CHILD_LAUNCH_UMASK = 0o022
SOURCE_ROOTS = {"src", "tests", "test", "benches", "examples", "scripts", "crates"}
ROOT_FILES = {
    "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain",
    "rust-toolchain.toml", "rustfmt.toml", ".rustfmt.toml",
    "clippy.toml", ".clippy.toml",
}
CONFIG_FILES = {".cargo/config", ".cargo/config.toml", ".config/nextest.toml"}
CACHE_DIRS = {
    ".git", "target", "node_modules", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".nextest", ".cache", ".tox", ".nox", ".venv",
}
TEST_TEMP_DIRS = {"tmp", ".tmp", "temp", "test-output", "test-results"}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def inside(path, parent):
    return path == parent or parent in path.parents


def hash_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def save_json(path, value):
    encoded = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    temporary = path.with_name(path.name + ".writing")
    with open(temporary, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return {"path": str(path), "sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}


def file_identity(metadata):
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_size,
        metadata.st_mode, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def source_file(path, relative):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("non-regular source input: " + relative)
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(stream.fileno())
    if file_identity(before) != file_identity(after) or file_identity(after) != file_identity(path.lstat()):
        raise RuntimeError("source changed while hashing: " + relative)
    return {
        "path": relative, "bytes": before.st_size,
        "mode": oct(stat.S_IMODE(before.st_mode)), "sha256": digest.hexdigest(),
    }


class Selection:
    def __init__(self, repo, target, output):
        self.repo, self.target, self.output = repo, target, output

    def ignored(self, path):
        if inside(path, self.target) or inside(path, self.output):
            return True
        relative = path.relative_to(self.repo)
        parts = relative.parts
        if not parts:
            return False
        if parts[0] == "docs" or any(part in CACHE_DIRS for part in parts):
            return True
        # Exact temporary roots only; fixtures below tests/fixtures stay bound.
        if len(parts) >= 2 and parts[0] in {"test", "tests"} and parts[1] in TEST_TEMP_DIRS:
            return True
        return path.suffix in {".pyc", ".pyo"}

    def source(self, path):
        if self.ignored(path):
            return False
        relative = path.relative_to(self.repo)
        parts = relative.parts
        return bool(parts) and (
            parts[0] in SOURCE_ROOTS or relative.as_posix() in CONFIG_FILES
            or (len(parts) == 1 and path.name in ROOT_FILES)
            or path.suffix == ".rs" or path.name in {"Cargo.toml", "Cargo.lock", "build.rs"}
        )

    def walk(self):
        def failed(error):
            raise error
        for raw, directories, filenames in os.walk(self.repo, followlinks=False, onerror=failed):
            directory = Path(raw)
            keep = []
            for name in sorted(directories):
                child = directory / name
                if self.ignored(child):
                    continue
                if child.is_symlink():
                    raise RuntimeError("source monitoring cannot traverse directory symlink: " + str(child))
                keep.append(name)
            directories[:] = keep
            yield directory, sorted(filenames)

    def snapshot(self):
        files = []
        for directory, names in self.walk():
            for name in names:
                path = directory / name
                if self.source(path):
                    files.append(source_file(path, path.relative_to(self.repo).as_posix()))
        files.sort(key=lambda item: item["path"])
        canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        return {
            "schema": "hepta.rea.source-snapshot.v1",
            "selection": {
                "source_roots": sorted(SOURCE_ROOTS), "root_files": sorted(ROOT_FILES),
                "configuration_files": sorted(CONFIG_FILES),
                "additional": "all .rs and Cargo.toml/Cargo.lock/build.rs outside exclusions",
                "excluded": ["docs/**", "explicit target_dir/**", "explicit output_dir/**"]
                + sorted(CACHE_DIRS)
                + ["tests/" + name + "/**" for name in sorted(TEST_TEMP_DIRS)]
                + ["test/" + name + "/**" for name in sorted(TEST_TEMP_DIRS)]
                + ["*.pyc", "*.pyo"],
            },
            "file_count": len(files), "total_bytes": sum(item["bytes"] for item in files),
            "tree_sha256": hashlib.sha256(canonical).hexdigest(), "files": files,
        }


class SourceMonitor:
    # Linux inotify ABI. Overflow/unmount/ignored events are delivered automatically.
    MASK = 0x00000FC6
    LOST = 0x00002000 | 0x00004000 | 0x00008000
    SELF = 0x00000400 | 0x00000800
    ISDIR = 0x40000000
    EVENT = struct.Struct("=iIII")

    def __init__(self, selection):
        if not sys.platform.startswith("linux"):
            raise RuntimeError("source-change qualification requires Linux inotify")
        self.selection = selection
        self.events, self.errors = [], []
        self.event_count = 0
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.thread = None
        self.watches = {}
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        try:
            for directory, _ in selection.walk():
                wd = libc.inotify_add_watch(
                    self.fd, os.fsencode(directory), self.MASK | 0x01000000 | 0x02000000
                )
                if wd < 0:
                    raise OSError(ctypes.get_errno(), "inotify_add_watch failed: " + str(directory))
                self.watches[wd] = directory
        except BaseException:
            os.close(self.fd)
            raise

    def start(self):
        self.thread = threading.Thread(target=self._run, name="source-monitor", daemon=True)
        self.thread.start()

    def _record(self, path, mask, cookie):
        with self.lock:
            self.event_count += 1
            if len(self.events) < 2048:
                self.events.append({
                    "at": utc_now(), "path": str(path.relative_to(self.selection.repo)),
                    "mask_hex": hex(mask), "rename_cookie": cookie,
                })

    def _drain(self):
        while True:
            try:
                data = os.read(self.fd, 64 * 1024)
            except BlockingIOError:
                return
            if not data:
                raise RuntimeError("inotify unexpectedly ended")
            position = 0
            while position < len(data):
                if len(data) - position < self.EVENT.size:
                    raise RuntimeError("truncated inotify event")
                wd, mask, cookie, length = self.EVENT.unpack_from(data, position)
                position += self.EVENT.size
                if position + length > len(data):
                    raise RuntimeError("truncated inotify name")
                name = os.fsdecode(data[position:position + length].split(b"\0", 1)[0])
                position += length
                if mask & self.LOST:
                    with self.lock:
                        self.errors.append("inotify coverage lost: mask=" + hex(mask))
                    continue
                parent = self.watches.get(wd)
                if parent is None:
                    raise RuntimeError("inotify returned an unknown watch")
                path = parent / name if name else parent
                if self.selection.ignored(path):
                    continue
                if mask & (self.ISDIR | self.SELF) or self.selection.source(path):
                    # Any nonexcluded directory mutation can add/remove source.
                    # No need to add watches after that: the run is already invalid.
                    self._record(path, mask, cookie)

    def _run(self):
        try:
            while not self.stopping.is_set():
                ready, _, _ = select.select([self.fd], [], [], 0.2)
                if ready:
                    self._drain()
            self._drain()
        except BaseException as error:
            with self.lock:
                self.errors.append(type(error).__name__ + ": " + str(error))

    def stop(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                with self.lock:
                    self.errors.append("source monitor did not stop")
        os.close(self.fd)
        with self.lock:
            return {
                "event_count": self.event_count, "retained_events": self.events,
                "events_truncated": self.event_count > len(self.events), "errors": self.errors,
            }


class Cancellation:
    def __init__(self):
        self.signal = None

    def receive(self, signum, _frame):
        self.signal = signum


def log_summary(paths):
    tail = collections.deque(maxlen=24)
    summaries = []
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                cleaned = ANSI.sub("", line.rstrip("\r\n"))
                if "Summary [" in cleaned or cleaned.lstrip().startswith("Summary "):
                    summaries.append(cleaned[:4096])
                tail.append(cleaned[:4096])
    return {"nextest_summary_lines": summaries[-8:], "tail": list(tail)}


def run_stage(index, name, command, repo, output, env, cancellation, kind):
    stdout_path = output / (f"{index:02d}-{name}.stdout.log")
    stderr_path = output / (f"{index:02d}-{name}.stderr.log")
    started, clock = utc_now(), time.monotonic()
    print(json.dumps({"event": "stage_started", "name": name, "command": command}), flush=True)
    interrupted = False
    with open(stdout_path, "xb") as stdout, open(stderr_path, "xb") as stderr:
        try:
            process = subprocess.Popen(
                command, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True,
                umask=CHILD_LAUNCH_UMASK,
            )
            stop_at = None
            while True:
                try:
                    exit_code = process.wait(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    if cancellation.signal is not None and stop_at is None:
                        interrupted = True
                        stop_at = time.monotonic()
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    elif stop_at is not None and time.monotonic() - stop_at > 10:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
        except OSError as error:
            stderr.write((type(error).__name__ + ": " + str(error) + "\n").encode())
            exit_code = 127
        stdout.flush()
        stderr.flush()
        os.fsync(stdout.fileno())
        os.fsync(stderr.fileno())
    logs = {}
    for label, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        logs[label] = {
            "path": str(path), "bytes": path.stat().st_size,
            "sha256_at_stage_exit": hash_file(path),
        }
    result = {
        "name": name, "kind": kind, "command": command, "cwd": str(repo),
        "child_launch_umask": f"{CHILD_LAUNCH_UMASK:04o}",
        "started_at": started, "finished_at": utc_now(),
        "duration_seconds": round(time.monotonic() - clock, 6),
        "exit_code": exit_code, "interrupted": interrupted,
        "status": "passed" if exit_code == 0 else "failed",
        "logs": logs, "summary": log_summary([stdout_path, stderr_path]),
    }
    print(json.dumps({"event": "stage_finished", "name": name, "exit_code": exit_code,
                      "duration_seconds": result["duration_seconds"]}), flush=True)
    return result


def absolute_path(value):
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("must be an explicit absolute path")
    return path.resolve()


def executable(value):
    chosen = shutil.which(value)
    if chosen is None:
        raise RuntimeError("executable not found: " + value)
    # Keep the invocation name: resolving a rustup symlink to 'rustup' would
    # change shim dispatch. The resolved path is recorded separately.
    return os.path.abspath(chosen)


def observe_binary(target, relative):
    path = target / relative
    if not path.exists():
        return {"path": str(path), "exists": False}
    facts = source_file(path, relative.as_posix())
    return {"path": str(path), "exists": True, **{key: value for key, value in facts.items() if key != "path"}}


def pin_target(target, repo):
    target.mkdir(parents=True, exist_ok=True)
    fd = os.open(target / ".rea-qualification.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    lock = os.fdopen(fd, "r+b")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = target / ".rea-qualification-owner.json"
        expected = {"schema": "hepta.rea.target-owner.v1", "repo": str(repo)}
        if marker.exists():
            if json.loads(marker.read_text()) != expected:
                raise RuntimeError("target ownership marker belongs to another repository")
        else:
            with open(marker, "x", encoding="utf-8") as stream:
                json.dump(expected, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        return lock
    except BaseException:
        lock.close()
        raise


def arguments():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, type=absolute_path)
    parser.add_argument("--cargo-home", required=True, type=absolute_path)
    parser.add_argument("--target-dir", required=True, type=absolute_path)
    parser.add_argument("--output-dir", required=True, type=absolute_path)
    parser.add_argument("--jobs", required=True, type=int)
    parser.add_argument("--cargo", default="cargo", help="Cargo executable or shim; default PATH cargo")
    parser.add_argument("--rustc", default="rustc", help="rustc executable or shim; default PATH rustc")
    parser.add_argument("--binary-relative-path", default="debug/hepta-runtime",
                        help="native binary path relative to the explicit target directory")
    result = parser.parse_args()
    if not 1 <= result.jobs <= 256:
        parser.error("--jobs must be between 1 and 256")
    binary = Path(result.binary_relative_path)
    if binary.is_absolute() or ".." in binary.parts or not binary.parts:
        parser.error("--binary-relative-path must stay inside target_dir")
    result.binary_relative_path = binary
    return result


def main():
    args = arguments()
    # Never truncate/reuse an earlier qualification's evidence.
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    report_path = args.output_dir / "summary.json"
    report = {
        "schema": SCHEMA, "status": "running", "qualified": False, "started_at": utc_now(),
        "inputs": {
            "repo": str(args.repo), "cargo_home": str(args.cargo_home),
            "target_dir": str(args.target_dir), "target_preexisting": args.target_dir.exists(),
            "output_dir": str(args.output_dir), "jobs": args.jobs,
            "binary_relative_path": str(args.binary_relative_path), "toolchain": TOOLCHAIN,
            "child_launch_umask": f"{CHILD_LAUNCH_UMASK:04o}",
        },
        "platform": platform.platform(), "python": sys.version,
        "stages": [], "binaries_after_nextest": [], "invalid_reasons": [],
        "scope": {
            "tests": "all targets, both requested feature sets, one thread, zero retries, no fail fast",
            "default_filter": "explicitly ignored", "ignored_tests": "nextest default policy",
            "doctests": False, "home_modified": False, "cargo_cache": "trusted external input",
            "target": "operator-asserted task-exclusive existing cache, additionally runner-flocked",
            "source_monitor": "local Linux inotify plus content inventories; not remote/same-UID adversarial proof",
        },
    }
    save_json(report_path, report)
    selection = Selection(args.repo, args.target_dir, args.output_dir)
    monitor, target_lock, before, after = None, None, None, None
    cancellation = Cancellation()
    old_handlers = {sig: signal.signal(sig, cancellation.receive) for sig in (signal.SIGINT, signal.SIGTERM)}
    fatal = None
    try:
        if not args.repo.is_dir() or not (args.repo / "Cargo.toml").is_file() or not (args.repo / "Cargo.lock").is_file():
            raise RuntimeError("repo must contain Cargo.toml and Cargo.lock")
        if not args.cargo_home.is_dir():
            raise RuntimeError("explicit offline cargo_home is not an existing directory")
        if args.target_dir == (args.repo / "target").resolve() or args.target_dir == args.repo:
            raise RuntimeError("use a task-exclusive target, not the repository default target")
        for left, right in ((args.target_dir, args.output_dir), (args.target_dir, args.cargo_home),
                            (args.output_dir, args.cargo_home)):
            if inside(left, right) or inside(right, left):
                raise RuntimeError("cargo_home, target_dir and output_dir must not overlap")
        if inside(args.target_dir, args.repo):
            relative_target = args.target_dir.relative_to(args.repo)
            if relative_target.parts and relative_target.parts[0] in SOURCE_ROOTS:
                raise RuntimeError("target_dir cannot occupy source inputs")
        if inside(args.output_dir, args.repo):
            relative = args.output_dir.relative_to(args.repo)
            if relative.parts and relative.parts[0] in SOURCE_ROOTS:
                raise RuntimeError("output_dir cannot occupy source, fixture or script inputs")
        target_lock = pin_target(args.target_dir, args.repo)
        cargo, rustc = executable(args.cargo), executable(args.rustc)
        env = os.environ.copy()
        env.update({
            "CARGO_HOME": str(args.cargo_home), "CARGO_TARGET_DIR": str(args.target_dir),
            "CARGO_BUILD_JOBS": str(args.jobs), "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never", "RUSTUP_TOOLCHAIN": TOOLCHAIN, "RUSTC": rustc,
            "NEXTEST_TEST_THREADS": "1", "NEXTEST_RETRIES": "0",
        })
        report["environment_overrides"] = {key: env[key] for key in (
            "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE",
            "CARGO_TERM_COLOR", "RUSTUP_TOOLCHAIN", "RUSTC", "NEXTEST_TEST_THREADS", "NEXTEST_RETRIES",
        )}
        report["executables"] = {
            "cargo": {"invoked": cargo, "resolved": os.path.realpath(cargo)},
            "rustc": {"invoked": rustc, "resolved": os.path.realpath(rustc)},
        }
        # Bind relevant inherited build overrides without recording secret values.
        report["ambient_build_override_sha256"] = {
            name: hashlib.sha256(os.environ[name].encode()).hexdigest()
            for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                         "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET")
            if name in os.environ
        }
        report["binary_before_gates"] = observe_binary(args.target_dir, args.binary_relative_path)
        monitor = SourceMonitor(selection)
        monitor.start()
        before = selection.snapshot()
        report["source_before"] = save_json(args.output_dir / "source-before.json", before)
        report["source_before"]["tree_sha256"] = before["tree_sha256"]
        save_json(report_path, report)

        versions = [
            ("cargo-version", [cargo, "--version", "--verbose"]),
            ("rustc-version", [rustc, "--version", "--verbose"]),
            ("nextest-version", [cargo, "nextest", "--version"]),
        ]
        for name, command in versions:
            if cancellation.signal is not None:
                break
            stage = run_stage(len(report["stages"]) + 1, name, command, args.repo,
                              args.output_dir, env, cancellation, "version")
            report["stages"].append(stage)
            save_json(report_path, report)
        if len(report["stages"]) != len(versions) or any(stage["exit_code"] != 0 for stage in report["stages"]):
            raise RuntimeError("tool version preflight failed or was interrupted; gates were not started")
        for stage in report["stages"][:2]:
            text = Path(stage["logs"]["stdout"]["path"]).read_text(errors="replace")
            release = next((line.split(":", 1)[1].strip() for line in text.splitlines()
                            if line.startswith("release:")), None)
            if release != TOOLCHAIN:
                raise RuntimeError(stage["name"] + " does not report required release " + TOOLCHAIN)

        common = ["--locked", "--offline", "--all-targets"]
        cargo_build = ["--jobs", str(args.jobs), "--target-dir", str(args.target_dir)]
        nextest_build = ["--build-jobs", str(args.jobs), "--target-dir", str(args.target_dir)]
        test_control = [
            "--test-threads", "1", "--retries", "0", "--no-fail-fast",
            "--profile", "default", "--ignore-default-filter", "--no-tests", "fail",
        ]
        gates = [
            ("fmt-check", [cargo, "fmt", "--all", "--", "--check"], None),
            ("clippy-all-features", [cargo, "clippy"] + common + ["--all-features"] + cargo_build + ["--", "-D", "warnings"], None),
            ("clippy-no-default-features", [cargo, "clippy"] + common + ["--no-default-features"] + cargo_build + ["--", "-D", "warnings"], None),
            ("nextest-all-features", [cargo, "nextest", "run"] + common + ["--all-features"] + nextest_build + test_control, "all-features"),
            ("nextest-no-default-features", [cargo, "nextest", "run"] + common + ["--no-default-features"] + nextest_build + test_control, "no-default-features"),
        ]
        report["planned_gates"] = [
            {"name": name, "command": command, "child_launch_umask": f"{CHILD_LAUNCH_UMASK:04o}"}
            for name, command, _ in gates
        ]
        save_json(report_path, report)
        for name, command, feature_set in gates:
            if cancellation.signal is not None:
                report["stages"].append({
                    "name": name, "kind": "gate", "command": command,
                    "child_launch_umask": f"{CHILD_LAUNCH_UMASK:04o}",
                    "status": "not_run_after_interrupt", "exit_code": None,
                })
                continue
            stage = run_stage(len(report["stages"]) + 1, name, command, args.repo,
                              args.output_dir, env, cancellation, "gate")
            report["stages"].append(stage)
            if feature_set is not None:
                binary = observe_binary(args.target_dir, args.binary_relative_path)
                binary.update({"feature_set": feature_set, "stage": name, "stage_exit_code": stage["exit_code"]})
                report["binaries_after_nextest"].append(binary)
                if stage["exit_code"] == 0 and not binary["exists"]:
                    report["invalid_reasons"].append("successful nextest stage has no expected native binary: " + name)
            save_json(report_path, report)
    except BaseException as error:
        fatal = type(error).__name__ + ": " + str(error)
        report["invalid_reasons"].append(fatal)
        (args.output_dir / "runner-error.log").write_text(traceback.format_exc(), encoding="utf-8")
    finally:
        try:
            after = selection.snapshot()
            report["source_after"] = save_json(args.output_dir / "source-after.json", after)
            report["source_after"]["tree_sha256"] = after["tree_sha256"]
        except BaseException as error:
            report["invalid_reasons"].append("source-after unavailable: " + str(error))
            report["source_after"] = save_json(args.output_dir / "source-after.json", {"error": str(error)})
        if before is None:
            report["source_before"] = save_json(args.output_dir / "source-before.json", {"error": "no complete source-before snapshot"})
        observation = {"event_count": 0, "retained_events": [], "errors": ["monitor not established"]}
        if monitor is not None:
            try:
                observation = monitor.stop()
            except BaseException as error:
                observation["errors"] = ["monitor shutdown failed: " + str(error)]
        report["source_events"] = save_json(args.output_dir / "source-events.json", observation)
        report["source_monitor_complete"] = not observation["errors"]
        if observation["event_count"] or observation["errors"]:
            report["invalid_reasons"].append("source writes/metadata changes or monitor coverage loss occurred during qualification")
        report["source_inventory_changed"] = (
            before is None or after is None or before["tree_sha256"] != after["tree_sha256"]
        )
        report["source_changed"] = report["source_inventory_changed"] or observation["event_count"] > 0
        if report["source_inventory_changed"]:
            report["invalid_reasons"].append("source inventories differ or are incomplete")
        try:
            report["final_binary"] = observe_binary(args.target_dir, args.binary_relative_path)
        except BaseException as error:
            report["final_binary"] = {"error": str(error)}
            report["invalid_reasons"].append("final binary could not be hashed consistently")
        for stage in report["stages"]:
            for log in stage.get("logs", {}).values():
                try:
                    current = hash_file(Path(log["path"]))
                    log["sha256"] = current
                    log["final_bytes"] = Path(log["path"]).stat().st_size
                    if current != log["sha256_at_stage_exit"]:
                        report["invalid_reasons"].append("stage log changed after exit: " + log["path"])
                except OSError as error:
                    report["invalid_reasons"].append("stage log unavailable: " + str(error))
        gates = [stage for stage in report["stages"] if stage["kind"] == "gate"]
        passed = len(gates) == 5 and all(stage["exit_code"] == 0 for stage in gates)
        report["interrupted_by_signal"] = cancellation.signal
        report["status"] = "invalid" if report["invalid_reasons"] else ("passed" if passed else "failed")
        report["qualified"] = report["status"] == "passed"
        report["finished_at"] = utc_now()
        save_json(report_path, report)
        if target_lock is not None:
            target_lock.close()
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    print(json.dumps({
        "event": "qualification_finished", "status": report["status"],
        "summary": str(report_path), "source_before": report.get("source_before"),
        "source_after": report.get("source_after"), "final_binary": report.get("final_binary"),
    }, sort_keys=True), flush=True)
    if cancellation.signal is not None:
        return 128 + cancellation.signal
    return 0 if report["qualified"] else (2 if report["status"] == "invalid" else 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "operations":
        from rea_operation_qualification import main as operations_main
        sys.exit(operations_main(sys.argv[2:]))
    sys.exit(main())
