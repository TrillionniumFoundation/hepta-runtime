#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fixed ext4 audit qualification: ABBA BAAB, pinned test libraries, zero retries.

No Cargo invocation. The outer 120-second fixture limit never replaces the
compiled 3-second query budget. Timeout cleanup waits for actual owned-process
exit; kernel-uninterruptible cleanup is reported and may exceed the scheduling
budget. See README.md for inputs, source linkage and trace interpretation.
"""
from __future__ import annotations
import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

BASE_COMMIT = "23246a5313957e9e97e324303bc47a91808f1ea8"
BASE_SHA = "7ec5383c2f5f56006564fb2eb3f8f7c72027c73f94f7c5e524cf7567ab8f90ed"
DIAGNOSTIC = "docs/qualification/rea-audit-budget-diagnostic-20261103-r1"
INDEX = "mcp::runtime::request_audit::index::tests::"
QUERY = "mcp::runtime::request_audit::query_tests::"
PUBLICATION = INDEX + "large_pending_view_remains_exact_while_continuous_publications_progress"
REGRESSIONS = [
    INDEX + "warm_usage_keeps_its_admitted_store_turn",
    INDEX + "large_cache_preparing_reply_does_not_wait_for_the_query_budget",
    INDEX + "bounded_index_capacity_waits_without_retiring_live_callers_or_blocking_writers",
    INDEX + "large_pending_view_cannot_publish_while_a_taken_worker_cohort_is_in_flight",
    INDEX + "metadata_deadline_does_not_leave_a_blocking_query_behind_the_store_lock",
    INDEX + "audit_store_timed_cancellation_removes_head_and_middle_waiters",
    INDEX + "large_pending_view_preserves_exact_states_tools_owners_and_cursor_pages_without_writes",
    INDEX + "large_pending_view_rechecks_the_final_watch_and_each_returned_original_stamp",
    QUERY + "metadata_query_cancelled_while_waiting_never_spawns",
    QUERY + "metadata_query_cancelled_worker_retains_capacity_until_exit",
    QUERY + "metadata_query_timed_out_worker_retains_capacity_until_exit",
    QUERY + "metadata_query_expired_in_blocking_queue_never_runs",
    QUERY + "metadata_query_preserves_result_and_original_deadline",
    QUERY + "metadata_query_ready_success_consumed_after_deadline_is_refused",
    QUERY + "archive_query_expired_deadline_does_not_open_missing_store",
]
ORDER = "ABBABAAB"
CASE_SECONDS, SUITE_SECONDS, TERM_GRACE_SECONDS = 120, 1800, 2
RUN_LOG_LIMIT, TOTAL_LOG_LIMIT = 8 * 1024**2, 128 * 1024**2
BINARY_LIMIT, FILE_LIMIT = 2 * 1024**3, 16 * 1024**2
INTERRUPTED = None
RELATED = re.compile(r"src/mcp/runtime/request_(?:audit|archive|usage|metadata).*\.rs$")
TRACE_NOTE = (
    "Baseline metadata_drain begins after ready and covers the final acquisition/read. "
    "Candidate metadata_snapshot begins with initial admission and also includes hot/ready "
    "work and all actual reacquisitions. Their fields have different scopes; this driver "
    "does not compute a cross-variant phase ratio, subtraction or causal performance claim."
)

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def absolute(value):
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts, "absolute normalized paths required")
    return path

def identity(value):
    return dict(device=value.st_dev, inode=value.st_ino, size=value.st_size,
                mode=oct(stat.S_IMODE(value.st_mode)), uid=value.st_uid, nlink=value.st_nlink,
                mtime_ns=value.st_mtime_ns, ctime_ns=value.st_ctime_ns)

def read_regular(path, limit=FILE_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                "expected bounded regular file: " + str(path))
        chunks, count = [], 0
        while True:
            block = os.read(fd, min(1024**2, limit + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
            require(count <= limit, "file exceeded bound: " + str(path))
        require(identity(before) == identity(os.fstat(fd)) ==
                identity(os.stat(path, follow_symlinks=False)), "file changed: " + str(path))
        return b"".join(chunks)
    finally:
        os.close(fd)

def put(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

def save(path, value):
    put(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())

def fd_digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    hashed = hashlib.sha256()
    while True:
        block = os.read(fd, 1024**2)
        if not block:
            return hashed.hexdigest()
        hashed.update(block)

def pin(source, destination, expected):
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "invalid expected SHA256")
    src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    dst = None
    try:
        before = os.fstat(src)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= BINARY_LIMIT,
                "binary must be a bounded regular inode")
        dst = os.open(destination, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                      os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        hashed, count = hashlib.sha256(), 0
        while True:
            block = os.read(src, 1024**2)
            if not block:
                break
            hashed.update(block)
            count += len(block)
            require(count <= BINARY_LIMIT, "binary grew beyond bound")
            view = memoryview(block)
            while view:
                written = os.write(dst, view)
                require(written > 0, "short binary write")
                view = view[written:]
        after = os.fstat(src)
        require(identity(before) == identity(after) ==
                identity(os.stat(source, follow_symlinks=False)), "source inode changed during copy")
        require(count == before.st_size and hashed.hexdigest() == expected,
                "source binary SHA256/length mismatch")
        os.fsync(dst)
        require(fd_digest(dst) == expected, "destination FD rehash mismatch")
        os.fchmod(dst, 0o500)
        os.fsync(dst)
        fixed = identity(os.fstat(dst))
    finally:
        os.close(src)
        if dst is not None:
            os.close(dst)
    # A writable FD cannot remain open when fexecve starts.
    fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    require(identity(os.fstat(fd)) == fixed and fixed["mode"] == "0o500" and
            fixed["nlink"] == 1 and fixed["uid"] == os.geteuid(), "fixed binary changed")
    return dict(fd=fd, path=str(destination), sha256=expected, fixed=fixed,
                source=str(source), source_before=identity(before), source_after=identity(after))

def public_pin(pinned):
    return {key: value for key, value in pinned.items() if key != "fd"}

def check_pin(pinned, rehash=False):
    require(identity(os.fstat(pinned["fd"])) == pinned["fixed"] ==
            identity(os.stat(pinned["path"], follow_symlinks=False)), "fixed binary identity changed")
    if rehash:
        require(fd_digest(pinned["fd"]) == pinned["sha256"], "fixed binary bytes changed")

def proc_read(path, limit=32768):
    try:
        with open(path, "rb", buffering=0) as stream:
            raw = stream.read(limit + 1)
        return dict(text=raw[:limit].decode(errors="replace"), truncated=len(raw) > limit)
    except OSError as error:
        return dict(error=type(error).__name__, errno=error.errno)

def process_info(pid):
    raw = proc_read(f"/proc/{pid}/status")
    keys = {"Name", "State", "Umask", "Uid", "Gid", "Threads", "VmRSS", "VmHWM",
            "Cpus_allowed_list", "Mems_allowed_list"}
    fields = {key: value.strip() for line in raw.get("text", "").splitlines()
              for key, sep, value in [line.partition(":")] if sep and key in keys}
    result = dict(pid=pid, status=fields, status_error=raw.get("error"),
                  cgroup=proc_read(f"/proc/{pid}/cgroup"), io=proc_read(f"/proc/{pid}/io"))
    try:
        result["exe"] = os.readlink(f"/proc/{pid}/exe")
        result["mount_namespace"] = os.readlink(f"/proc/{pid}/ns/mnt")
    except OSError as error:
        result["identity_error"] = type(error).__name__
    return result

def cgroup_observation(pid):
    raw = proc_read(f"/proc/{pid}/cgroup")
    unified = next((line[3:] for line in raw.get("text", "").splitlines()
                    if line.startswith("0::")), None)
    result = dict(membership=raw, hierarchy=[])
    if unified is None or ".." in Path(unified).parts:
        result["unavailable"] = "No readable cgroup-v2 membership."
        return result
    base = Path("/sys/fs/cgroup")
    current = base / unified.lstrip("/")
    names = ("cpu.max", "cpu.stat", "cpu.pressure", "io.max", "io.stat", "io.pressure",
             "memory.max", "memory.current", "memory.peak", "memory.events", "memory.pressure",
             "pids.max", "pids.current", "cpuset.cpus.effective")
    for _ in range(32):
        result["hierarchy"].append(dict(path=str(current),
                                      files={name: proc_read(current / name) for name in names}))
        if current == base:
            break
        current = current.parent
        names = ("cpu.max", "memory.max", "pids.max", "cpuset.cpus.effective")
    return result

def observation(pid=None):
    return dict(at=utc(), monotonic_ns=time.monotonic_ns(), loadavg=os.getloadavg(),
                pressure={name: proc_read("/proc/pressure/" + name)
                          for name in ("cpu", "io", "memory")},
                parent_cgroup=cgroup_observation(os.getpid()),
                child=None if pid is None else process_info(pid),
                child_cgroup=None if pid is None else cgroup_observation(pid))

def filesystem(path):
    response = subprocess.run(
        ["findmnt", "-T", str(path), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "-J"],
        capture_output=True, text=True, timeout=10, check=False,
        env=dict(PATH="/usr/bin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8"))
    require(response.returncode == 0, "findmnt could not identify filesystem")
    mounts = json.loads(response.stdout)["filesystems"]
    require(len(mounts) == 1 and mounts[0]["fstype"] == "ext4", "fixture filesystem is not ext4")
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
            info.st_uid == os.geteuid(), "fixture directory is not private")
    free = os.statvfs(path)
    return dict(mount=mounts[0], directory=identity(info),
                namespace=os.readlink("/proc/self/ns/mnt"),
                free_bytes=free.f_bavail * free.f_frsize)

def git_bytes(root, *arguments):
    env = dict(PATH="/usr/bin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_OPTIONAL_LOCKS="0")
    response = subprocess.run(["git", "-c", "core.fsmonitor=false", *arguments], cwd=root,
                              env=env, capture_output=True, timeout=20, check=False)
    require(response.returncode == 0, "read-only git command failed: " + repr(arguments))
    require(len(response.stdout) <= FILE_LIMIT, "git output exceeded bound")
    return response.stdout

def related_sources(root):
    paths = sorted(path.relative_to(root).as_posix()
                   for path in (root / "src/mcp/runtime").glob("request_*.rs")
                   if RELATED.fullmatch(path.relative_to(root).as_posix()))
    require(0 < len(paths) < 256, "unexpected related source set")
    return [dict(path=path, size=len(raw), sha256=digest(raw))
            for path in ["Cargo.toml", "Cargo.lock", *paths]
            for raw in [read_regular(root / path)]]

def baseline_linkage(root, evidence):
    names = ["README.md", "binary-provenance.json", "selected-test-lib-fingerprint.json",
             "prior-source-before.json", "prior-source-after.json",
             "prior-source-events.json", "prior-summary.json", "result.json", "environment.json"]
    raw, records = {}, {}
    for name in names:
        raw[name] = read_regular(root / DIAGNOSTIC / name)
        require(raw[name] == git_bytes(root, "show", BASE_COMMIT + ":" + DIAGNOSTIC + "/" + name),
                "baseline evidence changed from its recorded commit: " + name)
        put(evidence / ("baseline-" + name), raw[name])
        if name.endswith(".json"):
            records[name] = json.loads(raw[name])
    old, fp = records["binary-provenance.json"], records["selected-test-lib-fingerprint.json"]
    before, summary = records["prior-source-before.json"], records["prior-summary.json"]
    events = records["prior-source-events.json"]
    require(old["sha256"] == BASE_SHA, "diagnostic baseline identity mismatch")
    require(digest(raw["selected-test-lib-fingerprint.json"]) == old["fingerprint_sha256"],
            "baseline feature fingerprint hash mismatch")
    require(json.loads(fp["features"]) == ["default", "remote-fs"] and fp["rustflags"] == [],
            "baseline feature configuration mismatch")
    require(raw["prior-source-before.json"] == raw["prior-source-after.json"] and
            summary["source_monitor_complete"] and not summary["source_changed"] and
            events["event_count"] == 0 and not events["errors"],
            "baseline build source-monitor linkage is incomplete")
    require(records["result.json"]["binary_sha256"] == BASE_SHA and
            records["result.json"]["test_status"] == "failed",
            "the retained result is not the original failed diagnostic")
    require(old["fixed_binary"] in raw["README.md"].decode(),
            "documented original fixed baseline path is inconsistent")
    tracked = git_bytes(root, "ls-tree", "-r", "--name-only", BASE_COMMIT,
                        "--", "src/mcp/runtime").decode().splitlines()
    paths = ["Cargo.toml", "Cargo.lock"] + sorted(p for p in tracked if RELATED.fullmatch(p))
    previous = {row["path"]: row for row in before["files"]}
    checked = []
    for path in paths:
        content = git_bytes(root, "show", BASE_COMMIT + ":" + path)
        row = dict(path=path, size=len(content), sha256=digest(content))
        require(path in previous and previous[path]["bytes"] == row["size"] and
                previous[path]["sha256"] == row["sha256"],
                "baseline related source is not byte-identical to 23246: " + path)
        checked.append(row)
    result = dict(binary_sha256=BASE_SHA, relevant_commit=BASE_COMMIT, sources=checked,
                  historical_source_tree_sha256=before["tree_sha256"],
                  documented_fixed_binary=old["fixed_binary"],
                  features=json.loads(fp["features"]), rustflags=fp["rustflags"],
                  fingerprint={k: fp[k] for k in ("rustc", "profile", "target", "compile_kind")},
                  expected_filesystem=records["environment.json"]["filesystem"],
                  expected_fixture_device=records["environment.json"]["fixture_root_stat"]["device"],
                  expected_uid=records["environment.json"]["fixture_root_stat"]["uid"],
                  whole_old_binary_claimed_as_commit_build=False,
                  limitation="Only the enumerated source bytes and recorded feature/build "
                  "linkage match the relevant commit. The entire old executable is not "
                  "claimed to be a 23246 build. Cargo metadata is not a source attestation.")
    save(evidence / "baseline-linkage.json", result)
    return result

def provenance_paths(value):
    defaults = dict(launch="launch.json", source_before="source-before.json",
                    source_after="source-after.json", artifact="all-test-build-artifact.json",
                    build_result="result.json")
    if value.is_dir() and (value / "provenance.json").is_file():
        value = value / "provenance.json"
    if value.is_dir():
        return {key: value / name for key, name in defaults.items()}
    mapping = json.loads(read_regular(value))
    require(all(key in mapping for key in defaults), "provenance manifest lacks required refs")
    return {key: absolute(path) for key, path in mapping.items()
            if key in {*defaults, "continuation_result"}}

def candidate_linkage(args, evidence, current_sources):
    paths = provenance_paths(args.candidate_provenance)
    data = {}
    references = {}
    for key, path in paths.items():
        raw = read_regular(path)
        data[key] = json.loads(raw)
        references[key] = dict(path=str(path), sha256=digest(raw), bytes=len(raw))
        put(evidence / ("candidate-" + key + ".json"), raw)
    launch, artifact, result = data["launch"], data["artifact"], data["build_result"]
    before, after = data["source_before"], data["source_after"]
    require(artifact["sha256"] == args.candidate_sha256 and artifact["single_source_fd"] is True
            and int(artifact["mode"], 8) == 0o500, "candidate artifact pin receipt mismatch")
    message = artifact["compiler_artifact"]
    require(artifact["features"] == message["features"] == ["default", "remote-fs"] and
            message["reason"] == "compiler-artifact" and message["profile"]["test"] is True and
            message["target"]["kind"] == ["lib"] and message["target"]["name"] == "hepta_runtime",
            "candidate is not the all-features Cargo test-library artifact")
    require(message["manifest_path"] == str(args.source_root / "Cargo.toml") and
            message["target"]["src_path"] == str(args.source_root / "src/lib.rs"),
            "Cargo compiler artifact source root differs")
    require(launch["head"] == result["head"] == BASE_COMMIT and result["git_head_unchanged"],
            "candidate build base changed")
    require(launch["status"] and launch["diff_sha256"] == result["diff_before"] ==
            result["diff_after"], "candidate dirty-tree diff linkage changed")
    require(before["sha256"] == after["sha256"] == result["source_before"] ==
            result["source_after"] and before["files"] == after["files"] and
            result["source_unchanged"], "candidate build source manifests differ")
    monitor = result["monitor"]
    require(monitor["completed"] and not monitor["events"] and not monitor["errors"],
            "candidate build source monitor is incomplete or changed")
    stages = [s for s in result["stages"] if s["name"] == "all-test-build"]
    require(len(stages) == 1 and stages[0]["exit_code"] == 0 and
            "--all-features" in stages[0]["argv"] and "--no-run" in stages[0]["argv"],
            "candidate compilation did not succeed")
    require(launch["env"].get("RUSTFLAGS") in (None, "") and
            launch["env"].get("CARGO_ENCODED_RUSTFLAGS") in (None, ""),
            "candidate rustflags differ from baseline")
    require(Path(launch["cwd"]) == args.source_root and
            git_bytes(args.source_root, "rev-parse", "HEAD").decode().strip() == BASE_COMMIT and
            digest(git_bytes(args.source_root, "diff", "--binary", "HEAD")) ==
            launch["diff_sha256"], "current candidate source/diff is not the build input")
    indexed = {row["path"]: row for row in before["files"]}
    for row in current_sources:
        require(row["path"] in indexed and
                indexed[row["path"]]["sha256"] == row["sha256"] and
                indexed[row["path"]]["size"] == row["size"],
                "current related source differs from candidate build: " + row["path"])
    changed = []
    for line in launch["status"].splitlines():
        path = line[3:]
        require(line[:2] == " M" and ".." not in Path(path).parts and
                not Path(path).is_absolute(), "unexpected candidate dirty-tree status")
        content = read_regular(args.source_root / path)
        require(path in indexed and digest(content) == indexed[path]["sha256"] and
                len(content) == indexed[path]["size"], "changed build input no longer matches")
        changed.append(dict(path=path, sha256=digest(content), size=len(content)))
    require(len(changed) == 6, "candidate does not have the reviewed six modified source files")
    # A driver-summary regex failure does not undo a successful compilation.
    # Preserve the failed enclosing result and independently verify its build stage.
    record = dict(binary_sha256=args.candidate_sha256, artifact_path=artifact["path"],
                  base_commit=BASE_COMMIT, source_state="dirty tree with reviewed manifest",
                  clean_commit_build=False, source_manifest_sha256=before["sha256"],
                  diff_sha256=launch["diff_sha256"], modified_sources=changed,
                  features=message["features"], profile=message["profile"],
                  rustup_toolchain=launch["env"].get("RUSTUP_TOOLCHAIN"),
                  compiler_artifact=message, compilation_stage=stages[0],
                  original_build_overall_qualified=result.get("qualified"),
                  original_build_failure=result.get("failure"), references=references,
                  source_linkage_limit="Artifact SHA, Cargo compiler message, successful "
                  "compile stage and stable monitored dirty source inputs establish build "
                  "linkage; they are not a cryptographic compiler attestation.")
    save(evidence / "candidate-linkage.json", record)
    return record

def proc_stat(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        fields = raw[raw.rfind(")") + 2:].split()
        return dict(pid=pid, state=fields[0], parent=int(fields[1]), pgroup=int(fields[2]),
                    session=int(fields[3]), start_ticks=int(fields[19]))
    except (OSError, ValueError, IndexError):
        return None

def descendant_ids(parent):
    children = set()
    try:
        tasks = list(Path(f"/proc/{parent}/task").iterdir())
    except OSError:
        return children
    for task in tasks:
        try:
            children.update(int(value) for value in (task / "children").read_text().split())
        except (OSError, ValueError):
            continue
    return children

def pidfd_exited(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    return bool(poll.poll(0))

def usage_record(value):
    return dict(user_seconds=value.ru_utime, system_seconds=value.ru_stime,
                max_rss_kib=value.ru_maxrss, block_inputs=value.ru_inblock,
                block_outputs=value.ru_oublock, voluntary_context_switches=value.ru_nvcsw,
                involuntary_context_switches=value.ru_nivcsw)

def exec_child():
    binary_fd, ready_fd, go_fd = map(int, sys.argv[2:5])
    argv = sys.argv[5:]
    old = os.umask(0o022)
    require(old == 0o022, "child launch did not establish umask 0022")
    os.write(ready_fd, json.dumps(dict(pid=os.getpid(), umask="0022", argv=argv)).encode() + b"\n")
    os.close(ready_fd)
    require(os.read(go_fd, 1) == b"G", "parent did not release execution")
    os.close(go_fd)
    os.set_inheritable(binary_fd, False)
    os.execve(binary_fd, argv, dict(os.environ))

def signal_handler(number, _frame):
    global INTERRUPTED
    INTERRUPTED = number

def run_one(args, out, tmp_root, driver, pinned, name, test, listing, budget):
    run = out / "runs" / name
    run.mkdir(mode=0o700)
    tmp = tmp_root / name.split("-")[0]
    tmp.mkdir(mode=0o700)
    require(len(os.fsencode(tmp)) <= 48, "TMPDIR is not short enough")
    mount = filesystem(tmp)
    require(mount["free_bytes"] >= 256 * 1024**2, "less than 256 MiB fixture space remains")
    check_pin(pinned)
    require(not descendant_ids(os.getpid()), "unexpected existing child before invocation")
    argv = [pinned["path"], "--list"] if listing else [
        pinned["path"], "--exact", test, "--nocapture", "--test-threads=1"]
    env = dict(PATH="/usr/bin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC",
               TMPDIR=str(tmp), RUST_LIB_BACKTRACE="1", HEPTA_ARCHIVE_INDEX_TRACE="1",
               RUST_TEST_THREADS="1")
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    go_r, go_w = os.pipe2(os.O_CLOEXEC)
    launcher = [sys.executable, "-I", "-S", str(driver), "--exec-child",
                str(pinned["fd"]), str(ready_w), str(go_r), *argv]
    started, clock = utc(), time.monotonic()
    save(run / "started.json", dict(started_at=started, scheduled_name=name,
        kind="listing" if listing else "test", test=test, argv=argv, launcher_argv=launcher,
        cwd=str(args.source_root), environment=env, configured_child_umask="0022",
        filesystem=mount, binary=public_pin(pinned), timeout_seconds=CASE_SECONDS,
        retry_number=0, host_before=observation()))
    logs = {key: open(run / (key + ".log"), "xb", buffering=0) for key in ("stdout", "stderr")}
    metrics = open(run / "observations.jsonl", "xb", buffering=0)
    hashes = {key: hashlib.sha256() for key in logs}
    sizes = {key: 0 for key in logs}
    child, selector, owned, reaped = None, selectors.DefaultSelector(), {}, []
    leader_rc, leader_usage, leader_at, terminal_at = None, None, None, None
    reason, sent_at, observed, released_at, setup_error = None, None, None, None, None
    killed, pending_notice, leader_wait_lost = False, False, False
    count, metric_bytes, next_sample, drained_since = 0, 0, clock, None

    def discover():
        pending, visited = [os.getpid()], set()
        while pending:
            parent = pending.pop()
            if parent in visited:
                continue
            visited.add(parent)
            parent_member = None
            if parent != os.getpid():
                parent_member = next((m for m in owned.values()
                    if m["identity"]["pid"] == parent and not pidfd_exited(m["fd"])), None)
                if parent_member is None:
                    continue
                current = proc_stat(parent)
                if current is None or current["start_ticks"] != parent_member["identity"]["start_ticks"]:
                    continue
            for pid in descendant_ids(parent):
                info = proc_stat(pid)
                if info is None or info["parent"] != parent:
                    continue
                existing = next((m for m in owned.values()
                    if m["identity"]["pid"] == pid and
                       m["identity"]["start_ticks"] == info["start_ticks"] and not m["reaped"] and
                       (not pidfd_exited(m["fd"]) or info["state"] == "Z")), None)
                if existing is None:
                    try:
                        fd = os.pidfd_open(pid, 0)
                    except ProcessLookupError:
                        continue
                    after = proc_stat(pid)
                    if (after is None or after["start_ticks"] != info["start_ticks"] or
                            after["parent"] != parent or
                            (parent_member is not None and pidfd_exited(parent_member["fd"]))):
                        os.close(fd)
                        continue
                    owned[fd] = dict(fd=fd, identity=after, leader=False, reaped=False, kill_sent=False)
                pending.append(pid)

    def send_owned(number):
        # Before our sole wait4 owner reaps the leader, its PID/PGID cannot be
        # recycled. Afterwards only identity-bound descendant pidfds are signalled.
        if child is not None and leader_rc is None and not leader_wait_lost:
            try:
                os.killpg(child.pid, number)
            except ProcessLookupError:
                pass
        discover()
        for member in owned.values():
            if not pidfd_exited(member["fd"]):
                try:
                    signal.pidfd_send_signal(member["fd"], number)
                except ProcessLookupError:
                    pass
                if number == signal.SIGKILL:
                    member["kill_sent"] = True

    def kill_new_owned():
        discover()
        for member in owned.values():
            if not member["kill_sent"] and not pidfd_exited(member["fd"]):
                try:
                    signal.pidfd_send_signal(member["fd"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
                member["kill_sent"] = True

    def reap():
        nonlocal leader_rc, leader_usage, leader_at, leader_wait_lost
        if child is not None and leader_rc is None and not leader_wait_lost:
            try:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
            except ChildProcessError:
                leader_wait_lost = True
                # Suppress Popen's future implicit poll of a lost numeric PID.
                # The published actual status remains None.
                child.returncode = -255
                raise
            if pid:
                leader_rc = os.waitstatus_to_exitcode(status)
                child.returncode = leader_rc
                leader_usage, leader_at = usage_record(usage), time.monotonic()
                for member in owned.values():
                    if member["leader"]:
                        member["reaped"] = True
        # A live leader does not prevent an earlier orphan from being adopted
        # by this supervisor. Reap those children promptly, including zombies.
        for member in list(owned.values()):
            if member["leader"] or member["reaped"]:
                continue
            pid, ticks = member["identity"]["pid"], member["identity"]["start_ticks"]
            current = proc_stat(pid)
            if current is None or current["start_ticks"] != ticks or current["parent"] != os.getpid():
                continue
            try:
                got, status, usage = os.wait4(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            if got:
                member["reaped"] = True
                reaped.append(dict(pid=got, start_ticks=ticks, reaped_at=utc(),
                    returncode=os.waitstatus_to_exitcode(status), usage=usage_record(usage)))

    def settled():
        reap()
        discover()
        if leader_rc is None and not leader_wait_lost:
            return False
        if any(not pidfd_exited(member["fd"]) for member in owned.values()):
            return False
        # With every known parent exited, any formerly unknown descendants
        # must be visible to our subreaper. Re-scan after that exit boundary.
        discover()
        reap()
        return (not any(not pidfd_exited(member["fd"]) for member in owned.values()) and
                not descendant_ids(os.getpid()))

    try:
        child = subprocess.Popen(launcher, cwd=args.source_root, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, umask=0o022, pass_fds=(pinned["fd"], ready_w, go_r))
        leader_fd = os.pidfd_open(child.pid, 0)
        leader_info = proc_stat(child.pid)
        require(leader_info is not None, "leader identity unavailable before handshake")
        owned[leader_fd] = dict(fd=leader_fd, identity=leader_info, leader=True, reaped=False, kill_sent=False)
        os.close(ready_w)
        ready_w = None
        os.close(go_r)
        go_r = None
        discover()
        for label in logs:
            pipe = getattr(child, label)
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, label)
        os.set_blocking(ready_r, False)
        selector.register(ready_r, selectors.EVENT_READ, "ready")
        ready = bytearray()
        while True:
            now = time.monotonic()
            reap()
            discover()
            if (now >= next_sample and count < RUN_LOG_LIMIT and
                    budget["log_bytes"] < TOTAL_LOG_LIMIT):
                sample = observation(child.pid)
                sample["owned_processes"] = [member["identity"] for member in owned.values()]
                raw = (json.dumps(sample, sort_keys=True) + "\n").encode()
                metrics.write(raw)
                count += len(raw)
                metric_bytes += len(raw)
                budget["log_bytes"] += len(raw)
                next_sample = now + 1
            if count > RUN_LOG_LIMIT or budget["log_bytes"] > TOTAL_LOG_LIMIT:
                reason = "log_limit"
            if INTERRUPTED is not None and reason is None:
                reason = "interrupted"
            if now >= budget["deadline"] and reason is None:
                reason = "suite_deadline"
            if now - clock >= CASE_SECONDS and reason is None:
                reason = "case_timeout"
            if released_at is None and now - clock >= 10 and reason is None:
                reason = "child_handshake_timeout"
            alive = [m for m in owned.values() if not pidfd_exited(m["fd"])]
            if leader_rc is not None and alive and reason is None:
                reason = "descendant_outlived_leader"
            if reason is not None and sent_at is None:
                sent_at = now
                send_owned(signal.SIGTERM)
            if sent_at is not None and not killed and (
                    now - sent_at >= TERM_GRACE_SECONDS or reason == "log_limit"):
                send_owned(signal.SIGKILL)
                killed = True
            if killed:
                kill_new_owned()
                alive = [m for m in owned.values() if not pidfd_exited(m["fd"])]
            if killed and alive and now - sent_at >= 15 and not pending_notice:
                save(run / "terminal-pending.json", dict(at=utc(), reason=reason,
                    qualified=False, message="SIGKILL requested; kernel exit remains pending. "
                    "No later case will run until all owned processes are terminal."))
                pending_notice = True
            for key, _ in selector.select(0.1):
                block = os.read(key.fd, 65536)
                label = key.data
                if not block:
                    selector.unregister(key.fileobj)
                    if label == "ready":
                        os.close(ready_r)
                        ready_r = None
                    else:
                        key.fileobj.close()
                    continue
                if label == "ready":
                    ready.extend(block)
                    require(len(ready) <= 8192, "child handshake exceeded bound")
                    if b"\n" in ready and go_w is not None:
                        hello = json.loads(ready)
                        observed = process_info(child.pid)
                        require(hello["pid"] == child.pid and hello["argv"] == argv and
                                observed.get("status", {}).get("Umask") == "0022" and
                                observed.get("mount_namespace") == mount["namespace"],
                                "actual child umask/argv handshake failed")
                        save(run / "child-observed.json", observed)
                        released_at = time.monotonic()
                        os.write(go_w, b"G")
                        os.close(go_w)
                        go_w = None
                else:
                    logs[label].write(block)
                    hashes[label].update(block)
                    sizes[label] += len(block)
                    count += len(block)
                    budget["log_bytes"] += len(block)
                    if count > RUN_LOG_LIMIT or budget["log_bytes"] > TOTAL_LOG_LIMIT:
                        reason = "log_limit"
                        sent_at = sent_at or time.monotonic()
                        send_owned(signal.SIGKILL)
                        killed = True
            reap()
            discover()
            if settled():
                drained_since = drained_since or time.monotonic()
                if not selector.get_map():
                    terminal_at = time.monotonic()
                    break
                require(time.monotonic() - drained_since < 5,
                        "owned processes exited but an inherited output descriptor remains open")
            else:
                drained_since = None
    except BaseException as error:
        setup_error = dict(type=type(error).__name__, message=str(error))
        reason = reason or "driver_error"
    finally:
        for fd in (ready_w, go_r, go_w):
            if fd is not None:
                os.close(fd)
        if child is not None and terminal_at is None:
            send_owned(signal.SIGKILL)
            cleanup_started = time.monotonic()
            while True:
                try:
                    complete = settled()
                except ChildProcessError as error:
                    setup_error = setup_error or dict(type=type(error).__name__, message=str(error))
                    complete = False
                if complete:
                    terminal_at = time.monotonic()
                    break
                if time.monotonic() - cleanup_started >= 15 and not pending_notice:
                    save(run / "terminal-pending.json", dict(at=utc(), reason=reason,
                        qualified=False, message="Exceptional cleanup is awaiting actual "
                        "kernel termination; no later case can start."))
                    pending_notice = True
                kill_new_owned()
                time.sleep(0.1)
        terminal_members = [dict(identity=member["identity"],
            pidfd_exit_confirmed=pidfd_exited(member["fd"]), reaped_by_driver=member["reaped"],
            sigkill_sent=member["kill_sent"]) for member in owned.values()]
        for member in owned.values():
            os.close(member["fd"])
        selector.close()
        if ready_r is not None:
            os.close(ready_r)
        if child is not None:
            for label in logs:
                pipe = getattr(child, label)
                if pipe is not None and not pipe.closed:
                    while True:
                        try:
                            block = os.read(pipe.fileno(), 65536)
                        except BlockingIOError:
                            setup_error = setup_error or dict(type="OutputStillOpen",
                                message="Owned processes exited; buffered logs lack a final EOF.")
                            reason = reason or "driver_error"
                            break
                        if not block:
                            break
                        logs[label].write(block)
                        hashes[label].update(block)
                        sizes[label] += len(block)
                        budget["log_bytes"] += len(block)
                    pipe.close()
        for stream in [*logs.values(), metrics]:
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
    intact, identity_error = True, None
    try:
        check_pin(pinned)
    except RuntimeError as error:
        intact, identity_error = False, str(error)
    filesystem_after, filesystem_valid = None, False
    try:
        filesystem_after = filesystem(tmp)
        filesystem_valid = (filesystem_after["mount"] == mount["mount"] and
            all(filesystem_after["directory"][key] == mount["directory"][key]
                for key in ("device", "inode", "mode", "uid")))
    except BaseException as error:
        filesystem_after = dict(error=type(error).__name__, message=str(error))
    harness_pass = False
    if reason is None and setup_error is None:
        stdout = read_regular(run / "stdout.log").decode(errors="replace")
        harness_pass = listing or bool(re.search(
            r"test result: ok\. 1 passed; 0 failed; 0 ignored;", stdout))
    passed = (terminal_at is not None and leader_rc == 0 and reason is None and
              setup_error is None and intact and filesystem_valid and observed is not None and harness_pass)
    result = dict(variant="A" if pinned["sha256"] == BASE_SHA else "B",
        scheduled_name=name, kind="listing" if listing else "test", test=test,
        argv=argv, launcher_argv=launcher, binary_sha256=pinned["sha256"],
        started_at=started, finished_at=utc(), returncode=leader_rc,
        termination_reason=reason, timeout=reason in ("case_timeout", "suite_deadline"),
        terminal_confirmed=terminal_at is not None, wait_ownership_lost=leader_wait_lost,
        launch_wall_seconds=None if leader_at is None else leader_at - clock,
        execution_wall_seconds=None if leader_at is None or released_at is None
            else leader_at - released_at,
        custody_wall_seconds=None if terminal_at is None else terminal_at - clock,
        record_completion_seconds=time.monotonic() - clock,
        leader_usage=leader_usage, adopted_descendants_reaped=reaped,
        owned_processes_terminal=terminal_members,
        setup_error=setup_error, fixed_identity_unchanged=intact, identity_error=identity_error,
        actual_child_umask=None if observed is None else observed.get("status", {}).get("Umask"),
        passed=passed, retry_number=0, expected_test_count=None if listing else 1,
        logs={key: dict(bytes=sizes[key], sha256=hashes[key].hexdigest()) for key in logs},
        observation_bytes=metric_bytes, logs_complete=terminal_at is not None and setup_error is None,
        host_after=observation(), tmpdir=str(tmp), filesystem=mount,
        filesystem_after=filesystem_after, filesystem_valid=filesystem_valid,
        fixture_entries_after=sorted(path.name for path in tmp.iterdir()))
    save(run / "result.json", result)
    print(json.dumps(dict(run=name, passed=passed, returncode=leader_rc,
                          seconds=result["execution_wall_seconds"], reason=reason)), flush=True)
    return result

def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "candidate", "source-root", "output", "tmp-parent",
                 "candidate-provenance"):
        parser.add_argument("--" + name, required=True, type=absolute)
    parser.add_argument("--baseline-sha256", required=True)
    parser.add_argument("--candidate-sha256", required=True)
    return parser.parse_args()

def main():
    args = arguments()
    require(sys.platform == "linux" and hasattr(os, "pidfd_open") and
            hasattr(signal, "pidfd_send_signal") and os.execve in os.supports_fd,
            "Linux pidfds and FD exec support are required")
    require(args.baseline_sha256 == BASE_SHA, "baseline must be the retained failed 7ec test-lib")
    require(args.candidate_sha256 != BASE_SHA, "candidate must identify the changed executable")
    require(args.source_root.is_dir(), "source root is missing")
    require(not args.output.exists() and not args.output.is_symlink(), "output must be new")
    require(args.output.parent.is_dir() and args.tmp_parent.is_dir(), "parents must exist")
    require(not (args.output.parent.resolve() / args.output.name).is_relative_to(
            args.source_root.resolve()), "output must be outside source checkout")
    # This standalone single-threaded supervisor is the only child reaper.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    # Subreaper ownership lets us account for a fixture's orphaned descendants.
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0,
            "cannot establish child-subreaper ownership")
    os.umask(0o077)
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, signal_handler)
    args.output.mkdir(mode=0o700)
    out = args.output
    for directory in ("pins", "provenance", "runs"):
        (out / directory).mkdir(mode=0o700)
    plan = [dict(name=f"{number:02d}-{variant}-publication", variant=variant,
                 test=PUBLICATION, repetition=ORDER[:number].count(variant))
            for number, variant in enumerate(ORDER, 1)]
    plan += [dict(name=f"{number:02d}-B-regression", variant="B", test=test, repetition=1)
             for number, test in enumerate(REGRESSIONS, len(ORDER) + 1)]
    save(out / "plan.json", dict(schema="hepta.rea.audit-ext4-plan.v1", created_at=utc(),
        order="A B B A B A A B", runs=plan, retries=0, cargo_invocations=0,
        baseline_rule="Run every scheduled baseline, preserving every success and failure; "
        "baseline failure is not required and never selects or filters the candidate.",
        candidate_success_rule="All four candidate publication runs and every listed regression pass.",
        case_timeout_seconds=CASE_SECONDS, suite_schedule_budget_seconds=SUITE_SECONDS,
        process_cleanup="wait4 and pidfds must prove all owned processes terminal. Kernel "
        "uninterruptible cleanup can exceed the scheduling budget; later cases remain stopped.",
        run_log_limit_bytes=RUN_LOG_LIMIT, total_log_limit_bytes=TOTAL_LOG_LIMIT,
        log_limit_policy="Thresholds include stdout/stderr and observation samples. Terminate "
        "only owned processes and retain all buffered bytes; no silent log truncation.",
        trace_scope_note=TRACE_NOTE, source_root=str(args.source_root),
        baseline_input=str(args.baseline), baseline_expected_sha256=args.baseline_sha256,
        candidate_input=str(args.candidate), candidate_expected_sha256=args.candidate_sha256,
        candidate_provenance=str(args.candidate_provenance), child_umask="0022",
        parent_umask="0077", python=sys.version, kernel=list(os.uname()),
        driver_sha256=digest(read_regular(Path(__file__)))))
    pins, results = {}, []
    error, linkage, tmp_root, before, after_state = None, None, None, None, None
    budget = dict(deadline=time.monotonic() + SUITE_SECONDS, log_bytes=0)
    try:
        fixed_driver = out / "qualification-driver.py"
        put(fixed_driver, read_regular(Path(__file__)), 0o500)
        tmp_root = Path(tempfile.mkdtemp(prefix="ha-", dir=args.tmp_parent))
        filesystem(tmp_root)
        require(len(os.fsencode(tmp_root)) + 4 <= 48, "fixture root path is too long")
        binary_sizes = sum(os.stat(path, follow_symlinks=False).st_size
                           for path in (args.baseline, args.candidate))
        free = os.statvfs(out)
        require(free.f_bavail * free.f_frsize > binary_sizes + 1024**3,
                "less than binary-copy sizes plus 1 GiB free space")
        baseline = baseline_linkage(args.source_root, out / "provenance")
        actual_fs = filesystem(tmp_root)
        require(actual_fs["directory"]["device"] == baseline["expected_fixture_device"] and
                all(actual_fs["mount"][key] == baseline["expected_filesystem"][key]
                    for key in ("source", "target", "fstype")) and
                os.geteuid() == baseline["expected_uid"],
                "fixture device/mount/account differs from the original main ext4 diagnostic")
        before = related_sources(args.source_root)
        candidate = candidate_linkage(args, out / "provenance", before)
        require(candidate["features"] == baseline["features"], "feature sets differ")
        linkage = dict(baseline=baseline, candidate=candidate)
        save(out / "sources-before.json", before)
        pins["A"] = pin(args.baseline, out / "pins/baseline-test-lib", args.baseline_sha256)
        pins["B"] = pin(args.candidate, out / "pins/candidate-test-lib", args.candidate_sha256)
        save(out / "binary-pins.json", {key: public_pin(value) for key, value in pins.items()})
        for variant in "AB":
            listed = run_one(args, out, tmp_root, fixed_driver, pins[variant],
                             "L" + variant + "-listing", None, True, budget)
            results.append(listed)
            require(listed["passed"], "test listing failed: " + variant)
            text = read_regular(out / "runs" / listed["scheduled_name"] / "stdout.log").decode()
            names = {line[:-6] for line in text.splitlines() if line.endswith(": test")}
            needed = {PUBLICATION} if variant == "A" else {PUBLICATION, *REGRESSIONS}
            require(needed <= names, "required exact tests missing: " + repr(sorted(needed - names)))
        for item in plan:
            if INTERRUPTED is not None or time.monotonic() >= budget["deadline"] or \
                    budget["log_bytes"] > TOTAL_LOG_LIMIT:
                break
            result = run_one(args, out, tmp_root, fixed_driver, pins[item["variant"]],
                             item["name"], item["test"], False, budget)
            results.append(result)
            if not result["terminal_confirmed"] or not result["fixed_identity_unchanged"] or \
                    result["setup_error"] is not None:
                break
    except BaseException as caught:
        error = dict(type=type(caught).__name__, message=str(caught), at=utc())
        save(out / "driver-failure.json", error)
    finally:
        after = None
        if before is not None:
            try:
                after = related_sources(args.source_root)
                save(out / "sources-after.json", after)
                after_state = dict(head=git_bytes(args.source_root, "rev-parse", "HEAD").decode().strip(),
                                   diff_sha256=digest(git_bytes(args.source_root,
                                                               "diff", "--binary", "HEAD")))
                save(out / "source-state-after.json", after_state)
            except BaseException as caught:
                error = error or dict(type=type(caught).__name__, message=str(caught))
        fixed = {}
        for key, value in pins.items():
            try:
                check_pin(value, rehash=True)
                fixed[key] = True
            except BaseException as caught:
                fixed[key] = False
                error = error or dict(type=type(caught).__name__, message=str(caught))
            finally:
                os.close(value["fd"])
        scheduled = [row for row in results if row["kind"] == "test"]
        candidates = [row for row in scheduled if row["variant"] == "B"]
        baselines = [row for row in scheduled if row["variant"] == "A"]
        complete = len(scheduled) == len(plan)
        source_state_matches = (linkage is not None and after_state is not None and
            after_state["head"] == BASE_COMMIT and
            after_state["diff_sha256"] == linkage["candidate"]["diff_sha256"])
        integrity = (error is None and INTERRUPTED is None and before is not None and
            before == after and source_state_matches and fixed == {"A": True, "B": True} and
            complete and all(row["terminal_confirmed"] and row["actual_child_umask"] == "0022"
                             and row["logs_complete"] and row["filesystem_valid"] and
                             row["termination_reason"] != "log_limit" for row in results))
        qualified = integrity and len(candidates) == 4 + len(REGRESSIONS) and all(
            row["passed"] for row in candidates)
        attempted = []
        for path in sorted((out / "runs").glob("*/started.json")):
            record = json.loads(read_regular(path))
            if record["kind"] == "test":
                attempted.append(record["scheduled_name"])
        report = dict(schema="hepta.rea.audit-ext4-result.v1", finished_at=utc(),
            qualified=qualified, schedule_complete=complete, integrity_valid=integrity,
            error=error, interrupted_by_signal=INTERRUPTED, retries=0, cargo_invocations=0,
            baseline_counts=dict(total=len(baselines), passed=sum(r["passed"] for r in baselines),
                                 failed=sum(not r["passed"] for r in baselines)),
            candidate_counts=dict(total=len(candidates), passed=sum(r["passed"] for r in candidates),
                                  failed=sum(not r["passed"] for r in candidates)),
            planned_tests=len(plan), test_launch_attempts=attempted,
            test_results_saved=len(scheduled), not_run=[item for item in plan
                if item["name"] not in attempted],
            sources_unchanged=before is not None and before == after,
            dirty_tree_state_unchanged=source_state_matches, fixed_binaries_rehashed=fixed,
            linkage_checked=linkage is not None, total_log_bytes_observed=budget["log_bytes"],
            results=results, fixture_root=None if tmp_root is None else str(tmp_root),
            trace_scope_note=TRACE_NOTE, scope="These pinned executables, the fixed 64-publication "
            "case and named regressions in this observed ext4 resource window. No whole-commit "
            "baseline claim, production-capacity claim, physical power-loss claim or "
            "cross-scope phase comparison.")
        save(out / "summary.json", report)
        sums = []
        for path in sorted(out.rglob("*")):
            if path.is_file() and "pins" not in path.relative_to(out).parts:
                sums.append(digest(read_regular(path, TOTAL_LOG_LIMIT + FILE_LIMIT)) +
                            "  " + path.relative_to(out).as_posix())
        put(out / "SHA256SUMS", ("\n".join(sums) + "\n").encode())
        print(json.dumps(dict(output=str(out), qualified=qualified, complete=complete,
                              test_results_saved=len(scheduled))), flush=True)
    return 0 if qualified else 1

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--exec-child":
        exec_child()
    else:
        raise SystemExit(main())
