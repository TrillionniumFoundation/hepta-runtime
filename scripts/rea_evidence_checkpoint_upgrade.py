#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Finite Linux/private-HTTP checkpoint-v1 upgrade and rollback observation.

Run only after both binary/build bindings exist. This starts exactly four actual
servers A(c25) -> B -> A -> B and never retries a failed phase. The imported
fixture comes from the pinned original REA constructors; its fixed public Unknown
order is independently observed in the original 118-case MCP qualification.
Historical A source is checked against immutable Git blobs and its original
matrix, not against whatever now occupies its old worktree path. Current B must
be clean, match its build selection, and remain under the existing source monitor.

The HTTP helper supplies actual SIGKILL + wait. This runner adds raw HTTP body
capture, private generated credentials, process identities and close receipts.
It never qualifies general deployment, migration, rollback, production or cost.
"""
from __future__ import annotations

import argparse
import gzip
import io
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import select
import secrets
import signal
import stat
import subprocess
import sys
import time
import traceback
import types
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
SCHEMA = "hepta.rea.checkpoint-upgrade-observation.v1"
PROFILE = "Linux/private-authenticated-HTTP/checkpoint-v1/c25-B-c25-B"
OLD_COMMIT = "c25e4cef0610816bfd1263b69d3dd63e4114aa49"
OLD_TREE = "c6db025f5902570bd63520751cf84c57505eb6f4"
OLD_BINARY_SHA = "9cde66234030515651177e3d8ab113b2b6f674ee76196283c71874348a0b6c90"
HTTP_HELPER_SHA = "b6fb30835c26739b0982acd607763242d1db407d91083d53162dca0f1aee3818"
FIXTURE_SHA = "97e4e75d4e56c9c7eca22c91a0b0309be475141d22724027e96b3f1049c96215"
FIXTURE_PROVENANCE_SHA = "014f9a45c6108cdfe72487c56fee93cec411f6bb19cbdd585ffe6f71e93e0e1d"
ORIGINAL_PUBLIC_ORDER = {
    "observation": "evidence-import-r1/reference-cold/call-003-cold-complete.json",
    "sha256": "2731674c30c89cc91124430db061599626410a23562faa0820ba36694a89fc71",
    "scope": "Original REA 6.8.0 complete public Unknown key sequence; not a checkpoint receipt",
}

ORIGINAL_PUBLIC_RECORD_ORDER = {
    "observation": "evidence-import-r1/reference-main/call-026-unknown-verified-complete.json",
    "sha256": "e6420a795dd15d1a44437dd4d540b008195bd603089839f779ecf100d011ca18",
    "manifest_sha256": "dc95e62a9008731bae830389ef0470e95edfbffbe10ff973c0efc76af8b4657d",
    "scope": "Observed 16-key Evidence envelopes and this fixture's optional caller_input_path 17-key envelope only",
    "frames": {
        "sent": {"path": "wire-0055-sent.json.gz", "gzip_bytes": 110,
                 "gzip_sha256": "cd4c4c5eb273be358d625bcc3d8a4a867aff46816d0c2764e024c88305e30f84",
                 "raw_bytes": 103, "raw_sha256": "5113cc06f61d377e08b83d6c9cbd00ca7a8e253adb04babf23f901c8296e0d5c"},
        "received": {"path": "wire-0056-received.json.gz", "gzip_bytes": 1915,
                     "gzip_sha256": "63a215e60664c2f818fcba90d72ee9a8e49b19e36c561076cc1e83de71cb1570",
                     "raw_bytes": 12469, "raw_sha256": "947187395b9f8a88ec3d16d9f05a5be63ace356d9af8262d1a8cf2c69ae3268a"},
    },
}

UNKNOWN_KEYS = [
    "unknown_id", "revision", "previous_revision_digest", "revision_digest",
    "scope_digest", "question", "status", "severity", "domain",
    "supporting_evidence_ids", "contradicting_evidence_ids", "required_authority",
    "required_confidence", "required_environment", "recommended_probes",
    "relationships", "resolution", "mutation_evidence_ids",
]
BUNDLE_KEYS = ["artifacts", "providers", "environments", "scenarios", "captures", "unknowns", "records"]
EVIDENCE_KEYS = [
    "evidence_id", "subject", "provider", "analysis_profile", "predicate_type",
    "operation", "parameters", "raw_result", "normalized_result", "confidence",
    "authority", "environment", "limitations", "relationship_coverage",
    "locations", "evidence_links",
]
CHECKPOINT_TOOLS = {
    "rea_evidence_session_checkpoint", "rea_evidence_session_resume", "rea_evidence_session_list",
}
BASIC_TOOLS = {"rea_import_evidence_bundle", "rea_get_evidence_bundle"}
STORE_NAME = "rea-evidence-checkpoints-v1"
MAX_BODY = 16 * 1024 * 1024
TOKEN = None
PHASE = None


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode()


def parse(raw):
    def members(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON member in retained observation")
            result[key] = value
        return result
    def finite(value):
        result = float(value)
        require(math.isfinite(result), "nonfinite JSON number")
        return result
    return json.loads(raw, object_pairs_hook=members, parse_float=finite,
                      parse_constant=lambda _: require(False, "nonfinite JSON literal"))


def metadata(value):
    return {name[3:]: getattr(value, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns")}


def read(path, cap=256 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                "input must be a single-link regular file: " + str(path))
        require(before.st_size <= cap, "input byte allowance exceeded: " + str(path))
        raw = source.read(cap + 1)
        after = os.fstat(source.fileno())
    require(len(raw) == before.st_size and metadata(before) == metadata(after)
            == metadata(path.lstat()), "input identity changed during read: " + str(path))
    return raw


def identity(path, raw=None):
    raw = read(path) if raw is None else raw
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def pinned(path, digest):
    raw = read(path)
    require(sha(raw) == digest, "pinned SHA256 mismatch: " + str(path))
    return raw


def clean_message(error):
    value = str(error)
    return value.replace(TOKEN, "<generated-credential>") if TOKEN else value


def write(path, raw):
    require(not TOKEN or TOKEN.encode() not in raw, "generated credential detected in publishable bytes")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return identity(path, raw)


def save(path, value):
    return write(path, encoded(value))


def git(repo, *args):
    run = subprocess.run(["git", "-C", str(repo), *args], stdin=subprocess.DEVNULL,
                         capture_output=True, timeout=60)
    require(run.returncode == 0, "read-only Git command failed: " + clean_message(run.stderr.decode(errors="replace")))
    return run.stdout


def git_identity(repo):
    return {
        "commit": git(repo, "rev-parse", "HEAD").decode().strip(),
        "tree": git(repo, "rev-parse", "HEAD^{tree}").decode().strip(),
        "status": git(repo, "status", "--porcelain=v1", "--untracked-files=all").decode(),
    }


def module_from_bytes(name, path, raw):
    write(path, raw)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def original_tree(repo, binding, snapshot, producer, build_inputs):
    commit, tree = binding["source_commit"], binding["source_git_tree"]
    require(git(repo, "rev-parse", commit + "^{tree}").decode().strip() == tree,
            "historical Git tree differs from old binding")
    selected = producer.Selection(Path(build_inputs["repo"]), Path(build_inputs["target_dir"]), None)
    entries = {}
    for entry in git(repo, "ls-tree", "-r", "-z", commit).split(b"\0"):
        if not entry:
            continue
        head, name = entry.split(b"\t", 1)
        mode, kind, oid = head.decode().split()
        name = name.decode()
        if selected.source(selected.repo / name):
            require(kind == "blob" and mode in ("100644", "100755"),
                    "historical selected path is not a regular Git blob")
            entries[name] = oid
    require(set(entries) == {row["path"] for row in snapshot["files"]},
            "historical selected Git path set differs from recorded matrix selection")
    process = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    verified, cache = [], {}
    try:
        for row in snapshot["files"]:
            oid = entries[row["path"]]
            if oid not in cache:
                process.stdin.write((oid + "\n").encode())
                process.stdin.flush()
                header = process.stdout.readline().decode().split()
                require(len(header) == 3 and header[:2] == [oid, "blob"], "Git blob response differs")
                remaining, digest = int(header[2]), hashlib.sha256()
                length = remaining
                while remaining:
                    block = process.stdout.read(min(remaining, 1024 * 1024))
                    require(block, "Git blob response ended early")
                    digest.update(block)
                    remaining -= len(block)
                require(process.stdout.read(1) == b"\n", "Git blob boundary differs")
                cache[oid] = (length, digest.hexdigest())
            require(cache[oid] == (row["bytes"], row["sha256"]),
                    "historical Git blob differs from compiled input: " + row["path"])
            verified.append({"path": row["path"], "git_blob": oid, "bytes": row["bytes"], "sha256": row["sha256"]})
        process.stdin.close()
        stderr = process.stderr.read()
        require(process.wait(timeout=15) == 0 and not stderr, "historical Git consumer did not close cleanly")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        process.stdout.close()
        process.stderr.close()
    return {"source_kind": "historical immutable Git objects and original matrix",
            "commit": commit, "tree": tree, "files": verified,
            "old_worktree_current_content_used": False, "git_exit_code": process.returncode}


def bind(label, args, repo, output, report, state):
    binary = getattr(args, label + "_runtime")
    digest = getattr(args, label + "_sha256")
    binding_path = getattr(args, label + "_binding")
    binding_raw = pinned(binding_path, getattr(args, label + "_binding_sha256"))
    binding = parse(binding_raw)
    require(binding["schema"] == "hepta.rea.p0p5.build-binding.v1", "unsupported build binding")
    runtime = identity(binary, pinned(binary, digest))
    require(runtime == binding["runtime"], "runtime path/bytes/SHA differ from build binding")
    require(os.access(binary, os.X_OK), "runtime is not executable")
    folder = output / "inputs" / (label + "-build")
    folder.mkdir(mode=0o700)
    write(folder / "binding.original.json", binding_raw)
    summary_path = Path(binding["build_summary"]["path"])
    summary_raw = pinned(summary_path, binding["build_summary"]["sha256"])
    require(identity(summary_path, summary_raw) == binding["build_summary"], "build-summary byte binding differs")
    write(folder / "summary.original.json", summary_raw)
    summary = parse(summary_raw)
    old_source_raw = read(summary_path.parent / "source-before.json")
    original_source = parse(old_source_raw)
    files = {item["path"]: item for item in original_source["files"]}
    code = {}
    for key, relative in (("producer", "scripts/rea_full_qualification.py"),
                          ("consumer", "scripts/rea_build_evidence.py")):
        if label == "old":
            raw = git(repo, "show", binding["source_commit"] + ":" + relative)
        else:
            raw = read(repo / relative)
        require(sha(raw) == files[relative]["sha256"] and len(raw) == files[relative]["bytes"],
                label + " build helper differs from selected source")
        code[key] = module_from_bytes("checkpoint_upgrade_" + label + "_" + key,
                                     folder / (key + ".py"), raw)
    producer, consumer = code["producer"], code["consumer"]
    source = original_source
    if label == "old":
        require(binding["source_commit"] == OLD_COMMIT and binding["source_git_tree"] == OLD_TREE
                and digest == OLD_BINARY_SHA, "old endpoint is outside the fixed c25 profile")
        proof = original_tree(repo, binding, original_source, producer, summary["inputs"])
        save(folder / "historical-git-content.json", proof)
    else:
        current = git_identity(repo)
        require(current == {"commit": binding["source_commit"], "tree": binding["source_git_tree"], "status": ""},
                "new candidate is not the bound clean commit/tree")
        require(Path(summary["inputs"]["repo"]) == repo, "new build used a different active source directory")
        selection = producer.Selection(repo, Path(summary["inputs"]["target_dir"]), summary_path.parent)
        monitor = producer.SourceMonitor(selection)
        monitor.start()
        state.update(monitor=monitor, selection=selection, git_before=current)
        source = selection.snapshot()
        state["source_before"] = source
        save(folder / "current-source-before.json", source)
        require(read(Path(__file__).resolve()) == state["runner_raw"], "runner changed before source monitoring")
        runner_source = state["runner_source"]
        if runner_source["repository_raw"] is not None:
            relative = runner_source["binding"]["repository_source_relative_path"]
            rows = [row for row in source["files"] if row["path"] == relative]
            pinned_repository = runner_source["binding"]["replaced_repository_runner"]
            require(len(rows) == 1 and rows[0]["bytes"] == pinned_repository["bytes"]
                    and rows[0]["sha256"] == pinned_repository["sha256"],
                    "replaced repository runner differs from current selected build source")
            require(read(repo / relative) == runner_source["repository_raw"],
                    "replaced repository runner changed before source monitoring")
    captured = {}
    def artifact(name):
        raw = consumer.read_regular(summary_path.parent, name)
        if name in captured:
            require(captured[name]["sha256"] == sha(raw), "build artifact changed during consumption")
        else:
            captured[name] = write(folder / name, raw)
        return raw
    validation = consumer.validate_matrix(summary_raw, artifact, source, runtime)
    require(validation == binding["independent_consumer"], label + " independent consumer result differs")
    save(folder / "independent-validation.json", validation)
    report["bindings"][label] = {
        "binding": identity(binding_path, binding_raw), "runtime": runtime,
        "source_commit": binding["source_commit"], "source_git_tree": binding["source_git_tree"],
        "selected_source_sha256": source["tree_sha256"],
        "source_kind": "historical Git blobs" if label == "old" else "current clean source with inotify",
        "build_consumer_sha256": files["scripts/rea_build_evidence.py"]["sha256"],
        "matrix_artifacts": captured, "validated": True,
    }
    state[label + "_binding"] = binding
    state[label + "_binding_raw"] = binding_raw
    state[label + "_binary_before"] = metadata(binary.lstat())
    return runtime


def process_identity(process):
    raw = Path("/proc") / str(process.pid) / "stat"
    fields = raw.read_text().rsplit(")", 1)[1].split()
    return {"pid": process.pid, "start_ticks": int(fields[19]),
            "process_group": os.getpgid(process.pid), "session_id": os.getsid(process.pid),
            "executable": os.readlink(Path("/proc") / str(process.pid) / "exe")}


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def load_http_helper(tests, output):
    raw = pinned(tests / "rea_model_session_http.py", HTTP_HELPER_SHA)
    helper = module_from_bytes("checkpoint_upgrade_http_helper", output / "inputs" / "http_helper.py", raw)
    original_client = helper.Client

    class RecordedClient(original_client):
        def rpc(self, method, params, notify=False):
            phase = PHASE
            require(phase is not None, "HTTP call escaped its owned phase")
            self.i += 1
            body = {"jsonrpc": "2.0", "method": method, "params": params}
            if not notify:
                body["id"] = self.i
            raw_request = json.dumps(body, allow_nan=False).encode()
            headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                       "X-Hepta-Runtime-Token": self.token, "MCP-Protocol-Version": self.protocol,
                       "Mcp-Method": method}
            if method == "tools/call":
                headers["Mcp-Name"] = params["name"]
            if self.session:
                headers["Mcp-Session-Id"] = self.session
            number = len(phase.wire) + 1
            event = {"sequence": number, "method": method, "notify": notify,
                     "request": write(phase.path / f"http-{number:03d}.request.body", raw_request),
                     "safe_request_headers": {key: value for key, value in headers.items()
                                              if key != "X-Hepta-Runtime-Token"},
                     "authorization_header_retained": False, "started_ns": time.monotonic_ns()}
            phase.wire.append(event)
            request = urllib.request.Request(self.url, data=raw_request, headers=headers)
            try:
                try:
                    response = urllib.request.urlopen(request, timeout=30)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    self.session = response.headers.get("Mcp-Session-Id", self.session)
                    event["http_status"] = response.status
                    event["safe_response_headers"] = {
                        key: response.headers[key] for key in ("Content-Type", "Mcp-Session-Id")
                        if key in response.headers}
                    raw = response.read(MAX_BODY + 1)
                    event["response"] = write(phase.path / f"http-{number:03d}.response.body", raw)
                    require(len(raw) <= MAX_BODY, "HTTP response exceeded capture allowance")
                    event["capture_complete"] = True
                    require(200 <= response.status < 300, "HTTP request was refused; inspect retained body")
                if notify:
                    return None
                text = raw.decode("utf-8")
                records = [parse(line[5:].strip()) for line in text.splitlines()
                           if line.startswith("data:") and line[5:].strip()]
                frame = records[-1] if records else parse(raw)
                require(frame.get("jsonrpc") == "2.0" and frame.get("id") == self.i,
                        "HTTP JSONRPC response identity differs")
                require("error" not in frame and "result" in frame, "JSONRPC error; inspect retained body")
                return frame["result"]
            except BaseException as error:
                event["failure"] = {"type": type(error).__name__, "message": clean_message(error)}
                raise
            finally:
                event["ended_ns"] = time.monotonic_ns()

    helper.Client = RecordedClient
    def launch(*values, **kwargs):
        require(PHASE is not None and PHASE.process is None, "a phase attempted another server launch")
        kwargs["start_new_session"] = True
        phase = PHASE
        # The child is spawned with the caller mask; only handler changes are masked.
        with deferred_soft_signals(phase.path, 1, receipt_prefix="launch"):
            process = subprocess.Popen(*values, **kwargs)
            phase.process = process
            phase.server.process = process
            phase.pidfd = os.pidfd_open(process.pid)
            observed = process_identity(process)
            expected = phase.binary.lstat()
            actual = (Path("/proc") / str(process.pid) / "exe").stat()
            require((expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino),
                    "executed image inode differs from pinned runtime")
            phase.row["launch"] = {"argv": [str(value) for value in values[0]],
                                   "cwd": str(kwargs["cwd"]), "environment": kwargs["env"],
                                   "process": observed, "executable_sha256": phase.runtime["sha256"],
                                   "separate_owned_process_group": True, "pidfd_opened": True}
            save(phase.path / "launch.json", phase.row["launch"])
            return process
    helper.subprocess = types.SimpleNamespace(Popen=launch, DEVNULL=subprocess.DEVNULL)
    return helper



@contextmanager
def deferred_soft_signals(path, attempt, receipt_prefix="close"):
    """Finish owned registration/termination before propagating soft cancellation."""
    numbers = {signal.SIGINT, signal.SIGTERM}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, numbers)
    previous_handlers = {number: signal.getsignal(number) for number in numbers}
    received = []

    def remember(number, _frame):
        received.append({"signal": number, "monotonic_ns": time.monotonic_ns()})

    try:
        for number in numbers:
            signal.signal(number, remember)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        try:
            yield received
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK, numbers)
            # Capture signals queued in this thread while closing the guard.
            for _ in range(16):
                pending = signal.sigtimedwait(numbers, 0)
                if pending is None:
                    break
                remember(pending.si_signo, None)
            save(path / (receipt_prefix + "-signals-" + str(attempt) + ".json"),
                 {"attempt": attempt, "deferred_soft_signals": received,
                  "restoration_follows_owned_boundary": receipt_prefix})
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    if received:
        raise InterruptedError("qualification soft cancellation deferred until owned " + receipt_prefix + ": "
                               + ",".join(str(item["signal"]) for item in received))


class Phase:
    def __init__(self, label, binary, runtime, helper, config, output, report):
        self.label, self.binary, self.runtime = label, binary, runtime
        self.helper, self.config, self.output = helper, config, output
        self.path = output / label
        self.path.mkdir(mode=0o700)
        self.process, self.server, self.pidfd = None, None, None
        self.wire = []
        self.close_attempt = 0
        self.row = {"phase": label, "runtime": runtime, "status": "RUNNING", "calls": []}
        report["phases"].append(self.row)

    def start(self):
        global PHASE
        PHASE = self
        require(identity(self.binary, pinned(self.binary, self.runtime["sha256"])) == self.runtime,
                "binary changed before server launch")
        self.server = self.helper.Server.__new__(self.helper.Server)
        self.helper.Server.__init__(self.server, str(self.binary), self.path, self.config, TOKEN)
        self.row["ready"] = True

    def call(self, label, name, arguments):
        result = self.server.client.rpc("tools/call", {"name": name, "arguments": arguments})
        self.row["calls"].append({"id": label, "tool": name,
                                 "result": save(self.path / (label + ".result.json"), result),
                                 "wire_sequence": self.wire[-1]["sequence"]})
        return result

    def catalog(self, new):
        reply = self.server.client.rpc("tools/list", {})
        require(not reply.get("nextCursor"), "catalog requires unimplemented continuation")
        names = {item["name"] for item in reply["tools"]}
        require(BASIC_TOOLS <= names, "basic Evidence routes are missing")
        require(CHECKPOINT_TOOLS <= names if new else not (CHECKPOINT_TOOLS & names),
                "catalog checkpoint routes differ from the selected generation")
        if new:
            require("rea_inspect_apk_signature_evidence" in names, "native APK Evidence route is missing")
        self.row["catalog"] = save(self.path / "catalog.json", reply)
        return reply

    def close(self):
        self.close_attempt += 1
        with deferred_soft_signals(self.path, self.close_attempt) as received:
            self._close_owned(self.close_attempt, received)

    def _close_owned(self, attempt, received):
        global PHASE
        closed = {"helper_stop": "Server.stop: actual SIGKILL + wait(timeout=15)",
                  "attempt": attempt, "deferred_soft_signals": received,
                  "server_started": self.process is not None, "errors": [], "forced_group_cleanup": False}
        try:
            if self.process is not None:
                closed["before_stop_returncode"] = self.process.poll()
                if closed["before_stop_returncode"] is None:
                    try:
                        closed["before_stop_process"] = process_identity(self.process)
                    except BaseException as error:
                        closed["errors"].append({"step": "before-stop-identity", "message": clean_message(error)})
                try:
                    self.helper.Server.stop(self.server)
                except BaseException as error:
                    closed["errors"].append({"step": "helper-stop", "message": clean_message(error)})
                    if self.process.poll() is None:
                        self.process.kill()
                        self.process.wait(timeout=15)
                    if hasattr(self.server, "log") and not self.server.log.closed:
                        self.server.log.close()
                closed["returncode"] = self.process.returncode
                closed["wait_completed"] = self.process.returncode is not None
                closed["pidfd_exited"] = bool(select.select([self.pidfd], [], [], 5)[0]) if self.pidfd is not None else False
                pgid = self.process.pid
                drain_deadline = time.monotonic() + 2
                while group_exists(pgid) and time.monotonic() < drain_deadline:
                    time.sleep(0.02)
                if group_exists(pgid):
                    closed["forced_group_cleanup"] = True
                    os.killpg(pgid, signal.SIGKILL)
                    deadline = time.monotonic() + 5
                    while group_exists(pgid) and time.monotonic() < deadline:
                        time.sleep(0.02)
                closed["process_group_gone"] = not group_exists(pgid)
                closed["confirmed_terminal"] = (closed["wait_completed"] and closed["pidfd_exited"]
                                                and closed["process_group_gone"])
                if hasattr(self.server, "log"):
                    log_path = Path(self.server.log.name)
                    log_fd = os.open(log_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        os.fsync(log_fd)
                    finally:
                        os.close(log_fd)
                    closed["raw_log_sync_confirmed"] = True
                    raw = read(log_path, 64 * 1024 * 1024)
                    if TOKEN.encode() in raw:
                        quarantine = self.output / (".credential-quarantine-" + self.label)
                        log_path.rename(quarantine)
                        closed["errors"].append({"step": "log-secret-check", "message": "private capture quarantined; not publishable"})
                        closed["raw_log_publishable"] = False
                    else:
                        closed["raw_log"] = identity(log_path, raw)
                        closed["raw_log_publishable"] = True
                token_path = self.path / "http-token"
                if closed["confirmed_terminal"] and token_path.exists():
                    require(stat.S_IMODE(token_path.lstat().st_mode) == 0o600, "credential file mode changed")
                    token_path.unlink()
                closed["credential_deleted_after_terminal"] = closed["confirmed_terminal"] and not token_path.exists()
            else:
                if self.server is not None and hasattr(self.server, "log") and not self.server.log.closed:
                    self.server.log.close()
                closed["confirmed_terminal"] = True
                closed["launch_failed_before_child"] = True
                token_path = self.path / "http-token"
                if token_path.exists():
                    token_path.unlink()
                closed["credential_deleted_after_terminal"] = not token_path.exists()
        except BaseException as error:
            closed["errors"].append({"step": "close", "type": type(error).__name__, "message": clean_message(error)})
        finally:
            # Metadata/log failures must not discard the live process handle.
            # This is owned cleanup only; it never starts or repeats a phase.
            if self.process is not None and not closed.get("confirmed_terminal"):
                try:
                    closed["fallback_owned_cleanup"] = True
                    if self.process.poll() is None:
                        self.process.kill()
                    self.process.wait(timeout=15)
                    if self.server is not None and hasattr(self.server, "log") and not self.server.log.closed:
                        self.server.log.close()
                    closed["returncode"] = self.process.returncode
                    closed["wait_completed"] = self.process.returncode is not None
                    closed["pidfd_exited"] = (bool(select.select([self.pidfd], [], [], 5)[0])
                                             if self.pidfd is not None else False)
                    if group_exists(self.process.pid):
                        closed["forced_group_cleanup"] = True
                        os.killpg(self.process.pid, signal.SIGKILL)
                        deadline = time.monotonic() + 5
                        while group_exists(self.process.pid) and time.monotonic() < deadline:
                            time.sleep(0.02)
                    closed["process_group_gone"] = not group_exists(self.process.pid)
                    closed["confirmed_terminal"] = (closed["wait_completed"] and closed["pidfd_exited"]
                                                    and closed["process_group_gone"])
                except BaseException as error:
                    closed["errors"].append({"step": "fallback-owned-cleanup", "message": clean_message(error)})
            if closed.get("confirmed_terminal") and not closed.get("credential_deleted_after_terminal"):
                try:
                    token_path = self.path / "http-token"
                    if token_path.exists():
                        require(stat.S_IMODE(token_path.lstat().st_mode) == 0o600, "credential file mode changed")
                        token_path.unlink()
                    closed["credential_deleted_after_terminal"] = not token_path.exists()
                except BaseException as error:
                    closed["errors"].append({"step": "final-credential-cleanup", "message": clean_message(error)})
            terminal_cleanup = (closed.get("confirmed_terminal")
                                and closed.get("credential_deleted_after_terminal"))
            if terminal_cleanup:
                if self.pidfd is not None:
                    os.close(self.pidfd)
                    self.pidfd = None
                PHASE = None
            else:
                PHASE = self
                closed["owner_handle_retained_for_final_cleanup"] = True
            suffix = "" if attempt == 1 else "-cleanup-" + str(attempt)
            save(self.path / ("wire" + suffix + ".json"), self.wire)
            self.row["close"] = closed
            receipt = save(self.path / ("close" + suffix + ".json"), closed)
            self.row.setdefault("close_attempts", []).append({"attempt": attempt, "receipt": receipt})
        ok = (closed.get("returncode") == -signal.SIGKILL
              and closed.get("before_stop_returncode") is None
              and closed.get("confirmed_terminal") is True
              and closed.get("process_group_gone") is True
              and closed.get("credential_deleted_after_terminal") is True
              and closed.get("raw_log_publishable") is True
              and closed.get("raw_log_sync_confirmed") is True
              and not closed["forced_group_cleanup"] and not closed["errors"])
        require(ok, "server did not finish with a complete owned SIGKILL/wait/credential-cleanup receipt")

    def run(self, action):
        try:
            self.start()
            result = action(self)
            self.row["status"] = "ACTIONS_PASSED"
            return result
        except BaseException as error:
            self.row["status"] = "FAIL"
            self.row["error"] = {"type": type(error).__name__, "message": clean_message(error)}
            raise
        finally:
            try:
                self.close()
            except BaseException:
                self.row["status"] = "FAIL"
                raise
            if self.row["status"] == "ACTIONS_PASSED":
                self.row["status"] = "PASS"


def orders(value, path=()):
    result = []
    if isinstance(value, dict):
        result.append({"path": list(path), "keys": list(value)})
        for key, child in value.items():
            result.extend(orders(child, path + (key,)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.extend(orders(child, path + (index,)))
    return result


def expected_http_structured(body):
    """Expected native HTTP structured channel for the pinned serde_json Value build.

    The actual c25 HTTP frame and both bound build artifact streams establish
    BTreeMap member order without preserve_order. Text keeps its own REA order.
    Only the expected representation is built here; observed replies are never
    reordered, normalized, or accepted under a second ordering profile.
    """
    if isinstance(body, dict):
        return {key: expected_http_structured(body[key]) for key in sorted(body)}
    if isinstance(body, list):
        return [expected_http_structured(item) for item in body]
    return body


def tool_json(reply, compatibility=False):
    require(not reply.get("isError"), "public tool returned an error; inspect raw HTTP response")
    content = reply.get("content")
    require(isinstance(content, list) and len(content) == 1 and content[0].get("type") == "text"
            and isinstance(content[0].get("text"), str), "tool did not return one complete text body")
    body = parse(content[0]["text"])
    require(isinstance(body, dict), "tool body is not an object")
    if compatibility:
        require(list(body) == ["result"], "compatibility result wrapper differs")
        require(reply.get("structuredContent") == body, "text and structured values differ")
        require(orders(reply["structuredContent"]) == orders(expected_http_structured(body)),
                "native HTTP structured object order differs")
        require(reply.get("_meta") == {"provenance": {"untrusted_content": True, "source": "analysis_target"}},
                "original target-content provenance differs")
        return body["result"]
    return body



def evidence_json(reply, operation):
    """Decode the original direct Evidence body, never a {result} receipt."""
    body = tool_json(reply)
    require(list(body) == EVIDENCE_KEYS, "direct Evidence member set/order differs")
    require(body["operation"] == operation, "direct Evidence operation differs")
    require(isinstance(body["evidence_id"], str)
            and re.fullmatch(r"ev_[0-9a-f]{64}", body["evidence_id"]),
            "direct Evidence identity differs")
    require(reply.get("structuredContent") == body, "Evidence text and structured values differ")
    require(orders(reply["structuredContent"]) == orders(expected_http_structured(body)),
            "native HTTP Evidence structured object order differs")
    require(reply.get("_meta") == {"provenance": {"untrusted_content": True, "source": "analysis_target"}},
            "Evidence target-content provenance differs")
    return body


def consume_original_public_order(path, output):
    """Derive the public Unknown order from a pinned original MCP text body."""
    raw = pinned(path, ORIGINAL_PUBLIC_ORDER["sha256"])
    observation = parse(raw)
    frame = observation["response"]
    require(frame.get("jsonrpc") == "2.0" and "error" not in frame,
            "original public observation is not a successful JSONRPC response")
    result = frame["result"]
    require(not result.get("isError") and isinstance(result.get("content"), list)
            and len(result["content"]) == 1 and result["content"][0].get("type") == "text",
            "original public observation is not a single successful text result")
    text = result["content"][0]["text"]
    require(isinstance(text, str), "original public text is not a string")
    text_raw = text.encode("utf-8")
    body = parse(text_raw)
    require(list(body) == ["result"] and list(body["result"]) == BUNDLE_KEYS,
            "original public bundle order differs")
    bundle = body["result"]
    require(len(bundle["records"]) == 3 and len(bundle["unknowns"]) == 3,
            "original public observation lost complete records/history")
    observed_keys = list(bundle["unknowns"][0])
    require(observed_keys == UNKNOWN_KEYS
            and all(list(revision) == observed_keys for revision in bundle["unknowns"]),
            "original public Unknown key sequence differs")
    require(result["structuredContent"] == body,
            "original public structured value differs from its text body")
    reference = identity(path, raw)
    write(output / "inputs" / "public-order.original-call.json", raw)
    write(output / "inputs" / "public-order.original-text.json", text_raw)
    return observed_keys, {
        "source": ORIGINAL_PUBLIC_ORDER, "consumed_in_this_run": True,
        "observation": reference, "text_bytes": len(text_raw), "text_sha256": sha(text_raw),
        "derived_bundle_keys": list(bundle), "derived_unknown_keys": observed_keys,
        "unknown_revisions": [item["revision"] for item in bundle["unknowns"]],
    }



def consume_original_public_record_order(path, fixture, output):
    """Consume the actual original MCP frame; never infer public order from a fixture."""
    raw = pinned(path, ORIGINAL_PUBLIC_RECORD_ORDER["sha256"])
    observation = parse(raw)
    require(observation["id"] == "unknown-verified-complete"
            and observation["operation"] == "get_evidence_bundle" and observation["arguments"] == {},
            "original public record observation is not the fixed complete bundle call")
    manifest_path = path.parent / "wire.jsonl"
    manifest_raw = pinned(manifest_path, ORIGINAL_PUBLIC_RECORD_ORDER["manifest_sha256"])
    entries = [parse(line) for line in manifest_raw.splitlines()]
    require(0 < len(entries) < 10000, "original raw-frame manifest is empty or excessive")
    inputs = [identity(path, raw), identity(manifest_path, manifest_raw)]
    frames = {}
    write(output / "inputs" / "public-record-order.original-call.json", raw)
    write(output / "inputs" / "public-record-order.original-manifest.jsonl", manifest_raw)
    for direction, expected in ORIGINAL_PUBLIC_RECORD_ORDER["frames"].items():
        selected = [entry for entry in entries if entry.get("path") == expected["path"]]
        require(len(selected) == 1 and selected[0]["direction"] == direction
                and selected[0]["encoding"] == "gzip-original-jsonrpc-line"
                and all(selected[0][key] == value for key, value in expected.items()),
                "original public record raw-frame manifest entry differs")
        member = path.parent / expected["path"]
        compressed = pinned(member, expected["gzip_sha256"])
        require(len(compressed) == expected["gzip_bytes"], "original frame gzip length differs")
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
            frame_raw = stream.read(expected["raw_bytes"] + 1)
        require(len(frame_raw) == expected["raw_bytes"] and sha(frame_raw) == expected["raw_sha256"]
                and frame_raw.endswith(b"\n") and frame_raw.count(b"\n") == 1,
                "original public record frame is not losslessly recovered")
        frames[direction] = parse(frame_raw)
        inputs.append(identity(member, compressed))
        write(output / "inputs" / ("public-record-order.original-" + direction + ".jsonrpc"), frame_raw)
    frame = frames["received"]
    require(frame == observation["response"] and frame.get("jsonrpc") == "2.0" and "error" not in frame,
            "retained original record observation differs from its actual raw frame")
    require(frames["sent"] == {"jsonrpc": "2.0", "id": frame["id"], "method": "tools/call",
                               "params": {"name": "get_evidence_bundle", "arguments": {}}},
            "original record frame lacks the exact complete-bundle request")
    result = frame["result"]
    require(not result.get("isError") and len(result.get("content", [])) == 1
            and result["content"][0].get("type") == "text"
            and isinstance(result["content"][0].get("text"), str),
            "original public record frame is not a successful single text result")
    text_raw = result["content"][0]["text"].encode("utf-8")
    body = parse(text_raw)
    require(list(body) == ["result"] and list(body["result"]) == BUNDLE_KEYS
            and result["structuredContent"] == body, "original public bundle shape/value differs")
    bundle = body["result"]
    require(len(bundle["records"]) == len(bundle["unknowns"]) == 3
            and [(record["evidence_id"], record["operation"]) for record in bundle["records"]]
            == [(record["evidence_id"], record["operation"]) for record in fixture["records"]]
            and bundle["unknowns"] == fixture["unknowns"],
            "original record identity/operation or complete Unknown history differs")
    optional_keys = EVIDENCE_KEYS[:7] + ["caller_input_path"] + EVIDENCE_KEYS[7:]
    record_orders = []
    for index, (record, authored) in enumerate(zip(bundle["records"], fixture["records"], strict=True)):
        keys = list(record)
        expected_keys = optional_keys if index == 1 else EVIDENCE_KEYS
        require(keys == expected_keys and set(authored) == set(keys),
                "record is outside the observed 16-key/optional 17-key envelope")
        require(index != 1 or record["operation"] == "import_fixture_observation",
                "optional caller_input_path order is outside its observed fixture operation")
        record_orders.append({"evidence_id": record["evidence_id"], "operation": record["operation"], "keys": keys})
    write(output / "inputs" / "public-record-order.original-text.json", text_raw)
    return record_orders, {
        "source": ORIGINAL_PUBLIC_RECORD_ORDER, "consumed_in_this_run": True,
        "inputs": inputs, "original_jsonrpc_id": frame["id"],
        "text_bytes": len(text_raw), "text_sha256": sha(text_raw),
        "derived_record_envelope_orders": record_orders,
        "fixture_values_replaced_with_historical_paths": False,
        "actual_response_reordered": False,
        "scope": "Only expected imported Evidence root envelopes use observed public order; generic JSON child order remains the authored fixture's",
    }


def expected_bundle(fixture, unknown_keys=None, record_orders=None):
    require(list(fixture) == BUNDLE_KEYS and len(fixture["records"]) == 3
            and len(fixture["unknowns"]) == 3, "original fixture shape/counts changed")
    unknown_keys = UNKNOWN_KEYS if unknown_keys is None else unknown_keys
    require(unknown_keys == UNKNOWN_KEYS, "observed Unknown order differs from the supported public schema")
    require(isinstance(record_orders, list) and len(record_orders) == 3,
            "expected imported record order requires the consumed original public frames")
    result = dict(fixture)
    result["records"] = []
    for record, observed in zip(fixture["records"], record_orders, strict=True):
        require((record["evidence_id"], record["operation"]) == (observed["evidence_id"], observed["operation"])
                and set(record) == set(observed["keys"]),
                "expected record identity/operation/key set differs from its original public envelope")
        result["records"].append({key: record[key] for key in observed["keys"]})
    history = []
    for revision in fixture["unknowns"]:
        require(set(revision) == set(UNKNOWN_KEYS), "fixture Unknown fields differ from observed public schema")
        history.append({key: revision[key] for key in unknown_keys})
    result["unknowns"] = history
    require([entry["revision"] for entry in history] == [1, 2, 3]
            and history[-1]["status"] == "resolved"
            and history[-1]["resolution"]["disposition"] == "verified", "complete original Unknown history is missing")
    return result


def expected_delivery(reply, expected, name):
    value = tool_json(reply, True)
    require(value == expected, name + ": complete original value differs")
    body = {"result": expected}
    raw_expected = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    require(reply["content"][0]["text"] == raw_expected, name + ": exact public text differs")
    require(orders(reply["structuredContent"]) == orders(expected_http_structured(body)),
            name + ": complete native HTTP structured key order differs")
    return value


def get_bundle(phase, label):
    result = phase.call(label, "rea_get_evidence_bundle", {})
    tool_json(result, True)
    return result


def require_empty(phase, label):
    reply = get_bundle(phase, label)
    expected_delivery(reply, {key: [] for key in BUNDLE_KEYS}, label)
    return reply


def import_and_compare(phase, path, expected, label):
    imported = phase.call(label + "-import", "rea_import_evidence_bundle", {"path": str(path)})
    expected_delivery(imported, {"imported": 3, "unknowns_added": 3, "total": 3}, label + " import")
    bundle = get_bundle(phase, label + "-bundle")
    expected_delivery(bundle, expected, label + " bundle")
    return imported, bundle


def same_delivery(left, right, name):
    require(left == right, name + ": complete CallToolResult differs")
    require(left["content"][0]["text"] == right["content"][0]["text"], name + ": exact text bytes differ")
    require(orders(left["structuredContent"]) == orders(right["structuredContent"]),
            name + ": structured object order differs")
    require(orders(parse(left["content"][0]["text"])) == orders(parse(right["content"][0]["text"])),
            name + ": text object order differs")


def directory_identity(path):
    before = path.lstat()
    require(stat.S_ISDIR(before.st_mode) and before.st_uid == os.geteuid()
            and stat.S_IMODE(before.st_mode) == 0o700, "checkpoint directory must remain private/owned")
    return metadata(before)


def checkpoint_inventory(state_dir, checkpoint_id, expected, expected_origins, copy_to=None):
    require(re.fullmatch(r"ecp1_[0-9a-f]{64}", checkpoint_id), "unexpected checkpoint identity format")
    root, directory = state_dir / STORE_NAME, state_dir / STORE_NAME / checkpoint_id
    root_before, dir_before = directory_identity(root), directory_identity(directory)
    require(sorted(entry.name for entry in root.iterdir()) == [checkpoint_id], "checkpoint store gained unexpected entries")
    require(sorted(entry.name for entry in directory.iterdir()) == ["bundle.json", "manifest.json", "retention.json"],
            "checkpoint member set differs")
    files, payloads = {}, {}
    for member in ("bundle.json", "manifest.json", "retention.json"):
        path = directory / member
        before = path.lstat()
        require(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
                "checkpoint file owner/mode/link count differs")
        raw = read(path)
        require(metadata(path.lstat()) == metadata(before), "checkpoint member identity changed around hashing")
        files[member] = {"bytes": len(raw), "sha256": sha(raw), **metadata(before)}
        payloads[member] = parse(raw)
        if copy_to:
            write(copy_to / member, raw)
    manifest = payloads["manifest.json"]
    require(checkpoint_id == "ecp1_" + files["manifest.json"]["sha256"], "manifest bytes do not bind checkpoint ID")
    require(manifest["schema"] == "hepta.rea.evidence-checkpoint.v1"
            and manifest["retention_schema"] == "hepta.rea.evidence-retention.v1"
            and manifest["json_profile"] == "hepta.rea.native-json-128m-16m-depth120.v1",
            "checkpoint schema/profile differs")
    for prefix, member in (("bundle", "bundle.json"), ("retention", "retention.json")):
        require(manifest[prefix + "_bytes"] == files[member]["bytes"]
                and manifest[prefix + "_sha256"] == files[member]["sha256"], "manifest payload binding differs")
    require(manifest["records"] == 5 and manifest["unknown_revisions"] == 3
            and payloads["bundle.json"] == expected, "checkpoint lost complete mixed Evidence/history")
    sidecar = payloads["retention.json"]
    require(sidecar["schema"] == "hepta.rea.evidence-retention.v1"
            and sidecar["order_profile"] == "hepta.rea.response-order.v1", "retention schema/profile differs")
    rows = sidecar["records"]
    require(len(rows) == len(expected_origins) and len({row["evidence_id"] for row in rows}) == len(rows),
            "retention does not cover every record exactly once")
    for row in rows:
        require(row["origin"] == expected_origins[row["evidence_id"]], "retained producer origin differs")
        imported = row["origin"] == "unknown"
        require(row["has_imported_order"] is imported
                and (bool(row["imported_order"]) if imported else row["imported_order"] == []),
                "retention lost imported order or claimed native import authority")
    require(directory_identity(root) == root_before and directory_identity(directory) == dir_before,
            "checkpoint namespace changed during complete inventory")
    return {"root": root_before, "directory": dir_before, "files": files,
            "checkpoint_id": checkpoint_id, "manifest": manifest,
            "origins": dict(sorted(expected_origins.items()))}


def policy(state_dir, workspace, root):
    return {
        "state_dir": str(state_dir), "controller_workspace_roots": [str(workspace)],
        "hosts": {"denied": {
            "checkpoint_binary": None, "checkpoint_binary_sha256": None,
            "execution_mode": "isolated", "ssh_target": "never-connect-checkpoint-upgrade-test",
            "platform": "linux", "remote_state_dir": str(root / "no-remote"),
            "allow_execute": False, "allow_pty": False, "allow_write": False,
            "allow_job_network": False, "allow_detached_fallback": False,
            "allowed_cwd_prefixes": [], "allowed_read_path_prefixes": [], "allowed_write_path_prefixes": [],
            "protected_path_prefixes": [], "protected_argument_substrings": [],
            "denied_executables": [], "allowed_dangerous_executables": [], "privileged_actions": {},
        }},
        "weight_workers": {}, "rea_static_profiles": {},
    }


def safe_inventory(root):
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if path.name == "http-token" or path.name.startswith(".credential-quarantine-"):
            continue
        raw = read(path)
        require(not TOKEN or TOKEN.encode() not in raw, "credential bytes appeared in publishable inventory")
        rows.append({"path": str(path.relative_to(root)), "bytes": len(raw), "sha256": sha(raw),
                     "mode": oct(stat.S_IMODE(path.lstat().st_mode))})
    return rows



def cleanup_signal_handler(report):
    def record(number, _frame):
        report["cleanup_signal"] = number
        report.setdefault("cleanup_signals", []).append(number)
    return record


def qualification_passed(report, actions_passed):
    return (bool(actions_passed) and not report["errors"] and not report.get("cleanup_signal")
            and not report.get("interrupted_by_signal") and len(report["phases"]) == 4
            and all(item["status"] == "PASS" for item in report["phases"]))



def select_runner_source(args, repo, executing_file, invoked_file):
    """Bind an actual entrypoint; external review never changes __file__."""
    repository_path = repo / "scripts" / "rea_evidence_checkpoint_upgrade.py"
    extra = (args.external_reviewed_runner_sha256, args.external_reviewed_runner_bytes,
             args.replaced_repo_runner_sha256, args.replaced_repo_runner_bytes)
    if args.external_reviewed_runner is None:
        require(all(value is None for value in extra),
                "external runner pins require the explicit external-reviewed-runner mode")
        require(args.tests_dir.name == "tests" and Path(executing_file).resolve() == repository_path,
                "tests and runner must belong to the selected current source checkout")
        actual = Path(executing_file).resolve()
        raw = read(actual)
        return {"raw": raw, "path": actual, "repository_raw": None,
                "binding": {"mode": "repository", "runner": identity(actual, raw)}}

    require(all(value is not None for value in extra), "external mode requires both SHA256 and byte-count pins")
    for digest in (args.external_reviewed_runner_sha256, args.replaced_repo_runner_sha256):
        require(re.fullmatch(r"[0-9a-f]{64}", digest), "external runner SHA256 must be explicit lowercase hex")
    require(args.external_reviewed_runner_bytes > 0 and args.replaced_repo_runner_bytes > 0,
            "external runner byte-count pins must be positive")
    declared = Path(args.external_reviewed_runner)
    require(str(declared) == args.external_reviewed_runner,
            "external runner path must use its exact canonical spelling")
    actual = Path(executing_file)
    invoked = Path(invoked_file)
    require(str(actual) == executing_file and str(invoked) == invoked_file,
            "actual entrypoint path contains a lexical alias")
    for path in (repo, args.tests_dir, repository_path, declared, actual, invoked):
        require(path.is_absolute() and ".." not in path.parts and path.resolve(strict=True) == path,
                "external mode requires existing canonical paths without aliases: " + str(path))
    require(args.tests_dir.name == "tests" and args.tests_dir.is_dir() and repo.is_dir(),
            "external runner requires the selected current tests directory")
    require(actual == invoked == declared, "actual __file__/argv entrypoint differs from explicitly reviewed path")
    require(actual != repo and repo not in actual.parents,
            "external-reviewed runner must be outside the selected repository")
    raw = pinned(actual, args.external_reviewed_runner_sha256)
    repository_raw = pinned(repository_path, args.replaced_repo_runner_sha256)
    require(len(raw) == args.external_reviewed_runner_bytes
            and len(repository_raw) == args.replaced_repo_runner_bytes,
            "external or replaced repository runner byte-count pin differs")
    current_binding_raw = pinned(args.new_binding, args.new_binding_sha256)
    current_binding = parse(current_binding_raw)
    require(current_binding["schema"] == "hepta.rea.p0p5.build-binding.v1",
            "external runner requires the original current build-binding schema")
    build_summary_pin = current_binding["build_summary"]
    build_summary_path = Path(build_summary_pin["path"])
    build_summary_raw = pinned(build_summary_path, build_summary_pin["sha256"])
    require(identity(build_summary_path, build_summary_raw) == build_summary_pin,
            "external runner current build-summary byte binding differs")
    require(Path(parse(build_summary_raw)["inputs"]["repo"]) == repo,
            "external runner selected repository differs from the actual bound build directory")
    return {
        "raw": raw, "path": actual, "repository_raw": repository_raw,
        "binding": {
            "mode": "external-reviewed-runner", "actual___file__": executing_file,
            "actual_argv_entrypoint": invoked_file, "runner": identity(actual, raw),
            "replaced_repository_runner": identity(repository_path, repository_raw),
            "runner_metadata": metadata(actual.lstat()),
            "replaced_repository_runner_metadata": metadata(repository_path.lstat()),
            "repository_source_relative_path": "scripts/rea_evidence_checkpoint_upgrade.py",
            "external_runner_is_compiled_source": False,
            "repository_build_binding": identity(args.new_binding, current_binding_raw),
            "repository_build_summary": build_summary_pin,
        },
    }


def main():
    global TOKEN
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("old", "new"):
        parser.add_argument("--" + label + "-runtime", type=Path, required=True)
        parser.add_argument("--" + label + "-sha256", required=True)
        parser.add_argument("--" + label + "-binding", type=Path, required=True)
        parser.add_argument("--" + label + "-binding-sha256", required=True)
    parser.add_argument("--original-public-observation", type=Path, required=True,
                        help="Pinned original REA 118-case cold-complete CallToolResult observation")
    parser.add_argument("--original-public-record-observation", type=Path, required=True,
                        help="Pinned original 17-field record observation and its sibling compressed raw frames")
    parser.add_argument("--tests-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--external-reviewed-runner", help="Exact canonical path of a separately reviewed external entrypoint")
    parser.add_argument("--external-reviewed-runner-sha256")
    parser.add_argument("--external-reviewed-runner-bytes", type=int)
    parser.add_argument("--replaced-repo-runner-sha256")
    parser.add_argument("--replaced-repo-runner-bytes", type=int)
    args = parser.parse_args()
    for label in ("old", "new"):
        for name in (label + "_sha256", label + "_binding_sha256"):
            require(re.fullmatch(r"[0-9a-f]{64}", getattr(args, name)), "explicit lowercase SHA256 required")
    for name in ("old_runtime", "new_runtime", "old_binding", "new_binding", "original_public_observation", "original_public_record_observation", "tests_dir", "output_dir"):
        path = getattr(args, name)
        require(path.is_absolute() and ".." not in path.parts, "explicit normal absolute paths required")
    require(sys.platform.startswith("linux") and hasattr(os, "pidfd_open")
            and hasattr(signal, "pthread_sigmask") and hasattr(signal, "sigtimedwait"),
            "this profile requires Linux pidfds and POSIX signal deferral")
    output, repo = args.output_dir, args.tests_dir.parent
    runner_source = select_runner_source(args, repo, __file__, sys.argv[0])
    require(output != repo and repo not in output.parents and output not in repo.parents,
            "output must be a new path outside the current repository")
    require(not output.exists() and not output.is_symlink(), "output must not already exist")
    previous_umask = os.umask(0o077)
    output.mkdir(mode=0o700)
    (output / "inputs").mkdir(mode=0o700)
    report = {
        "schema": SCHEMA, "profile": PROFILE, "status": "FAIL", "passed": False,
        "started_unix_ns": time.time_ns(), "phases": [], "bindings": {}, "errors": [],
        "automatic_retry": False, "logical_phase_retries": 0,
        "initialization_readiness_polling": "helper-only connection readiness; each attempt retained, no phase restart",
        "full_upgrade_qualified": False, "full_rollback_qualified": False, "deployment_qualified": False,
        "production_qualified": False, "cost_qualified": False, "complete_rea_parity": False,
        "automatic_evidence_recovery": False, "authenticated_chatgpt_user_isolation": False,
        "raw_outer_jsonrpc_equality_qualified": False, "remote_host_contacted": False,
        "generated_private_operator_credential": True, "production_credentials_used": False,
        "original_unknown_public_order": {"source": ORIGINAL_PUBLIC_ORDER, "consumed_in_this_run": False},
    }
    state = {"runner_raw": runner_source["raw"], "runner_source": runner_source}
    old_handlers = {}
    def interrupted(signum, _frame):
        report["interrupted_by_signal"] = signum
        raise InterruptedError("qualification interrupted by signal " + str(signum))
    for number in (signal.SIGINT, signal.SIGTERM):
        old_handlers[number] = signal.signal(number, interrupted)
    try:
        write(output / "inputs" / "runner.original.py", state["runner_raw"])
        if runner_source["repository_raw"] is not None:
            write(output / "inputs" / "replaced-repository-runner.original.py", runner_source["repository_raw"])
        report["invocation"] = {"argv": sys.argv, "python": sys.executable, "actual___file__": __file__,
                                "runner": identity(runner_source["path"], state["runner_raw"]),
                                "runner_source_binding": runner_source["binding"]}
        old_runtime = bind("old", args, repo, output, report, state)
        new_runtime = bind("new", args, repo, output, report, state)
        helper = load_http_helper(args.tests_dir, output)
        fixture_root = args.tests_dir / "fixtures" / "rea_evidence_checkpoint"
        fixture_raw = pinned(fixture_root / "unknown-verified.json", FIXTURE_SHA)
        provenance_raw = pinned(fixture_root / "provenance.json", FIXTURE_PROVENANCE_SHA)
        provenance = parse(provenance_raw)
        producer_raw = read(fixture_root / "producer-run.stdout")
        require(parse(producer_raw) == provenance["original_producer"], "original producer stdout differs from provenance")
        terminal = provenance["controller_terminal"]
        require(terminal["exit_code"] == 0 and terminal["state"] == "succeeded"
                and terminal["output_complete"] is True and terminal["output_durable"] is True
                and terminal["terminal_publication_confirmed"] is True and terminal["automatic_retry"] is False,
                "original fixture producer did not reach the retained terminal")
        require(provenance["fixture_sha256"] == sha(fixture_raw)
                and provenance["fixture_bytes"] == len(fixture_raw), "original fixture identity differs")
        write(output / "inputs" / "unknown-verified.original.json", fixture_raw)
        write(output / "inputs" / "fixture-provenance.original.json", provenance_raw)
        write(output / "inputs" / "fixture-producer.original.stdout", producer_raw)
        observed_unknown_keys, public_order = consume_original_public_order(args.original_public_observation, output)
        report["original_unknown_public_order"] = public_order
        state["original_public_order_identity"] = public_order["observation"]
        authored_fixture = parse(fixture_raw)
        record_orders, public_records = consume_original_public_record_order(
            args.original_public_record_observation, authored_fixture, output)
        report["original_record_public_order"] = public_records
        state["original_public_record_inputs"] = public_records["inputs"]
        expected = expected_bundle(authored_fixture, observed_unknown_keys, record_orders)
        save(output / "inputs" / "expected-public-bundle.json", expected)
        apk_original = args.tests_dir / "fixtures" / "rea_apk_signature" / "rotation-v31.apk"
        apk_raw = read(apk_original)
        report["fixture_inputs"] = {"original_bundle": identity(fixture_root / "unknown-verified.json", fixture_raw),
                                    "original_provenance": identity(fixture_root / "provenance.json", provenance_raw),
                                    "apk": identity(apk_original, apk_raw)}
        workspace, state_dir = output / "workspace", output / "state"
        workspace.mkdir(mode=0o700)
        state_dir.mkdir(mode=0o700)
        initial_state = {key: directory_identity(state_dir)[key] for key in ("dev", "ino", "mode", "uid", "gid")}
        source, apk = workspace / "import-source.json", workspace / "analysis-source.apk"
        write(source, fixture_raw)
        write(apk, apk_raw)
        config = output / "policy.json"
        policy_ref = save(config, policy(state_dir, workspace, output))
        report["policy"] = policy_ref
        TOKEN = secrets.token_hex(32)

        def phase(label, binary, runtime, action):
            require(identity(config) == policy_ref, "complete policy changed before phase")
            require({key: directory_identity(state_dir)[key] for key in initial_state} == initial_state,
                    "private state named directory changed between phases")
            selected = Phase(label, binary, runtime, helper, config, output, report)
            result = selected.run(action)
            require(identity(config) == policy_ref, "complete policy changed during phase")
            require(identity(binary, pinned(binary, runtime["sha256"])) == runtime, "runtime changed during phase")
            return result

        def a_first(p):
            catalog = p.catalog(False)
            empty = require_empty(p, "cold-empty")
            imported, bundle = import_and_compare(p, source, expected, "original")
            require(not (state_dir / STORE_NAME).exists(), "old runtime unexpectedly created the new store")
            return {"catalog": catalog, "empty": empty, "imported": imported, "bundle": bundle}
        a1 = phase("01-old-initial", args.old_runtime, old_runtime, a_first)

        def b_create(p):
            catalog = p.catalog(True)
            require_empty(p, "cold-empty")
            imported, original = import_and_compare(p, source, expected, "original")
            same_delivery(a1["imported"], imported, "old/new original import")
            same_delivery(a1["bundle"], original, "old/new original complete bundle")
            derived_reply = p.call("native-apk-view", "rea_inspect_apk_signature_evidence", {"path": str(apk)})
            derived = evidence_json(derived_reply, "inspect_analysis_view")
            require(derived["operation"] == "inspect_analysis_view", "native APK summary did not produce analysis-view Evidence")
            mixed_reply = get_bundle(p, "mixed-bundle")
            mixed = tool_json(mixed_reply, True)
            require(len(mixed["records"]) == 5 and mixed["unknowns"] == expected["unknowns"],
                    "mixed registry lost records or complete Unknown history")
            records = {record["evidence_id"]: record for record in mixed["records"]}
            originals = {record["evidence_id"]: record for record in expected["records"]}
            require(len(records) == 5 and all(records[key] == value for key, value in originals.items()),
                    "native observation altered original imported records")
            native = {key: value for key, value in records.items() if key not in originals}
            require({value["operation"] for value in native.values()} == {"inspect_apk_signature", "inspect_analysis_view"}
                    and derived["evidence_id"] in native and native[derived["evidence_id"]] == derived,
                    "native parent/derived records were not retained in full")
            require(derived["parameters"]["parent_evidence_id"] in native
                    and native[derived["parameters"]["parent_evidence_id"]]["operation"] == "inspect_apk_signature",
                    "native view lost its retained parent")
            require(all(value["subject"]["digest"]["sha256"] == sha(apk_raw) for value in native.values()),
                    "native records do not bind the actual authored APK")
            origins = {key: "unknown" for key in originals}
            origins.update({key: "apk-tool-derived" if value["operation"] == "inspect_analysis_view"
                            else "native-tool" for key, value in native.items()})
            checkpoint = tool_json(p.call("checkpoint", "rea_evidence_session_checkpoint", {}))
            require(checkpoint["records"] == 5 and checkpoint["unknown_revisions"] == 3
                    and checkpoint["reused"] is False
                    and checkpoint["durability"] == "file_and_directory_sync_confirmed",
                    "first native checkpoint did not confirm complete durable state")
            target = output / "checkpoint-before"
            target.mkdir(mode=0o700)
            inventory = checkpoint_inventory(state_dir, checkpoint["checkpoint_id"], mixed, origins, target)
            save(output / "checkpoint-before.inventory.json", inventory)
            return {"catalog": catalog, "reply": mixed_reply, "bundle": mixed,
                    "origins": origins, "checkpoint": checkpoint, "inventory": inventory}
        b2 = phase("02-new-checkpoint", args.new_runtime, new_runtime, b_create)
        checkpoint_id = b2["checkpoint"]["checkpoint_id"]
        require(checkpoint_inventory(state_dir, checkpoint_id, b2["bundle"], b2["origins"]) == b2["inventory"],
                "checkpoint changed during actual B termination")
        deletion = {"after_phase": "02-new-checkpoint", "server_terminal_confirmed": True,
                    "source": identity(source), "apk": identity(apk)}
        source.unlink()
        apk.unlink()
        deletion.update(source_absent=not source.exists(), apk_absent=not apk.exists())
        save(output / "source-deletion.json", deletion)

        # A rollback gets a different control import. The actual B source/APK
        # paths remain absent, and this control is also removed before B resume.
        rollback_source = workspace / "rollback-control.json"
        write(rollback_source, fixture_raw)
        def a_rollback(p):
            require(not source.exists() and not apk.exists(), "deleted B sources reappeared")
            require(p.catalog(False) == a1["catalog"], "old catalog changed on rollback")
            same_delivery(require_empty(p, "cold-empty"), a1["empty"], "old rollback cold-empty")
            imported, bundle = import_and_compare(p, rollback_source, expected, "rollback-original")
            same_delivery(imported, a1["imported"], "old rollback basic import")
            same_delivery(bundle, a1["bundle"], "old rollback complete Evidence")
            require(checkpoint_inventory(state_dir, checkpoint_id, b2["bundle"], b2["origins"]) == b2["inventory"],
                    "old runtime changed the checkpoint while running")
        phase("03-old-rollback", args.old_runtime, old_runtime, a_rollback)
        rollback_source.unlink()
        rollback_inventory = checkpoint_inventory(state_dir, checkpoint_id, b2["bundle"], b2["origins"])
        require(rollback_inventory == b2["inventory"], "old rollback modified checkpoint bytes/inodes/permissions")
        save(output / "checkpoint-after-rollback.inventory.json", rollback_inventory)

        def b_resume(p):
            require(not source.exists() and not apk.exists() and not rollback_source.exists(),
                    "an admitted source input exists at recovery")
            require(p.catalog(True) == b2["catalog"], "new catalog changed on re-upgrade")
            require_empty(p, "cold-empty-before-explicit-resume")
            catalog = tool_json(p.call("checkpoint-list", "rea_evidence_session_list", {"offset": 0, "limit": 16}))
            require(catalog["total"] == 1 and catalog["returned"] == 1
                    and catalog["checkpoints"][0]["checkpoint_id"] == checkpoint_id,
                    "same credential/policy did not discover the retained checkpoint")
            resumed = tool_json(p.call("explicit-resume", "rea_evidence_session_resume", {"checkpoint_id": checkpoint_id}))
            require(resumed["restored"] is True and resumed["records"] == 5 and resumed["unknown_revisions"] == 3,
                    "explicit empty-session restore lost records or revisions")
            recovered = get_bundle(p, "recovered-bundle")
            same_delivery(recovered, b2["reply"], "complete mixed Evidence after upgrade/rollback/re-upgrade")
            repeated = tool_json(p.call("idempotent-checkpoint", "rea_evidence_session_checkpoint", {}))
            require(repeated["checkpoint_id"] == checkpoint_id and repeated["reused"] is True
                    and repeated["durability"] == "file_and_directory_sync_confirmed",
                    "identical restored state did not reconcile the same durable checkpoint ID")
            require(checkpoint_inventory(state_dir, checkpoint_id, b2["bundle"], b2["origins"]) == b2["inventory"],
                    "resume/reconciliation modified immutable checkpoint bytes or identities")
        phase("04-new-explicit-resume", args.new_runtime, new_runtime, b_resume)
        final_inventory = checkpoint_inventory(state_dir, checkpoint_id, b2["bundle"], b2["origins"])
        require(final_inventory == b2["inventory"], "checkpoint changed after final B termination")
        save(output / "checkpoint-final.inventory.json", final_inventory)
        require(not source.exists() and not apk.exists() and not rollback_source.exists(), "source absence was not preserved")
        report["finite_checks"] = {
            "four_actual_servers_A_B_A_B": True, "same_generated_credential_and_complete_policy": True,
            "old_catalog_has_no_checkpoint_routes": True, "all_four_sessions_initially_empty": True,
            "original_import_values_text_and_structured_order_equal": True,
            "native_apk_parent_and_derived_retained_with_imported_origins": True,
            "checkpoint_member_hashes_modes_and_inodes_bound": True,
            "actual_B_SIGKILL_wait_precedes_source_deletion": True,
            "old_basic_evidence_operations_survive_rollback": True,
            "old_runtime_does_not_modify_new_checkpoint": True,
            "explicit_resume_after_reupgrade_preserves_complete_history_and_delivery_order": True,
            "same_content_reconciles_same_checkpoint_id": True,
            "all_admitted_inputs_absent_at_final_resume": True,
        }
        report["checkpoint_id"] = checkpoint_id
        state["actions_passed"] = True
    except BaseException as error:
        report["errors"].append({"phase": "run", "type": type(error).__name__,
                                 "message": clean_message(error),
                                 "traceback": clean_message(traceback.format_exc())})
    finally:
        # A second soft interruption must not bypass owned process/secret cleanup.
        cleanup_handler = cleanup_signal_handler(report)
        for number in old_handlers:
            signal.signal(number, cleanup_handler)
        # Also cover a cancellation during close-guard setup or a failed cleanup
        # syscall: retain the actual owner/pidfd until termination is confirmed.
        pending_phase = PHASE
        if pending_phase is not None:
            try:
                pending_phase.close()
            except BaseException as error:
                report["errors"].append({"phase": "final-owned-cleanup",
                                         "type": type(error).__name__, "message": clean_message(error)})
        try:
            if "selection" in state:
                after = state["selection"].snapshot()
                save(output / "inputs" / "new-build" / "current-source-after.json", after)
                require(after == state["source_before"], "current source selection changed")
                require(git_identity(repo) == state["git_before"], "current source commit/tree/clean changed")
            for label in ("old", "new"):
                if label + "_binding" not in state:
                    continue
                path = getattr(args, label + "_runtime")
                require(identity(path, pinned(path, getattr(args, label + "_sha256"))) == state[label + "_binding"]["runtime"],
                        label + " runtime changed after phases")
                require(metadata(path.lstat()) == state[label + "_binary_before"],
                        label + " binary inode/metadata changed during execution")
                require(read(getattr(args, label + "_binding")) == state[label + "_binding_raw"],
                        label + " build binding changed")
            if "original_public_order_identity" in state:
                require(identity(args.original_public_observation,
                                 pinned(args.original_public_observation, ORIGINAL_PUBLIC_ORDER["sha256"]))
                        == state["original_public_order_identity"],
                        "consumed original public observation changed during execution")
            for item in state.get("original_public_record_inputs", []):
                require(identity(Path(item["path"]), pinned(Path(item["path"]), item["sha256"])) == item,
                        "consumed original public record input changed during execution")
            if runner_source["repository_raw"] is not None:
                selected = runner_source["binding"]
                for path, original_raw, expected_metadata in (
                        (runner_source["path"], runner_source["raw"], selected["runner_metadata"]),
                        (repo / selected["repository_source_relative_path"], runner_source["repository_raw"],
                         selected["replaced_repository_runner_metadata"])):
                    require(read(path) == original_raw and metadata(path.lstat()) == expected_metadata,
                            "reviewed runner path/bytes/identity changed during execution: " + str(path))
            if "policy" in report:
                require(identity(output / "policy.json") == report["policy"], "complete policy changed")
        except BaseException as error:
            report["errors"].append({"phase": "final-binding", "type": type(error).__name__, "message": clean_message(error)})
        if "monitor" in state:
            try:
                events = state["monitor"].stop()
                save(output / "inputs" / "new-build" / "current-source-events.json", events)
                require(events == {"event_count": 0, "retained_events": [], "events_truncated": False, "errors": []},
                        "current source changed or monitoring coverage was lost")
            except BaseException as error:
                report["errors"].append({"phase": "source-monitor", "type": type(error).__name__, "message": clean_message(error)})
        remaining = [str(path.relative_to(output)) for path in output.rglob("http-token")]
        report["credential_cleanup"] = {"remaining_files": remaining, "actual_token_published": False,
                                        "deletion_requires_actual_owned_server_terminal": True}
        if remaining:
            report["errors"].append({"phase": "credential-cleanup", "message": "private credential remains after incomplete owner termination"})
        try:
            inventory = safe_inventory(output)
            save(output / "inventory.json", inventory)
        except BaseException as error:
            report["errors"].append({"phase": "inventory", "type": type(error).__name__, "message": clean_message(error)})
        # Owners, credentials and monitor are now closed. A new cancellation
        # during terminal publication must raise, never preserve an exit-0 PASS.
        for number in old_handlers:
            signal.signal(number, interrupted)
        report["ended_unix_ns"] = time.time_ns()
        report["passed"] = qualification_passed(report, state.get("actions_passed"))
        report["status"] = "PASS" if report["passed"] else "FAIL"
        report["qualified_profile"] = PROFILE if report["passed"] else None
        report["global_status"] = "HOLD/NO_GO"
        save(output / "qualification.json", report)
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
        TOKEN = None
        os.umask(previous_umask)
    print(json.dumps({"schema": SCHEMA, "status": report["status"], "passed": report["passed"],
                      "qualified_profile": report["qualified_profile"], "qualification": str(output / "qualification.json"),
                      "phases": [{"phase": row["phase"], "status": row["status"]} for row in report["phases"]],
                      "errors": len(report["errors"]), "production_qualified": False, "cost_qualified": False},
                     sort_keys=True), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
