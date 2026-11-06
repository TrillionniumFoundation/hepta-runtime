#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Observe owned ELF MCP cancellation, capacity, deadline and EOF lifecycles.

Only newly launched clients and their identity-checked children are controlled.
An unobserved active phase is OPEN, never a successful cancellation. The frozen
Node provider has no separately controllable parser process, so native stopped
worker/deadline observations do not claim an equivalent original deadline.
The independent consumer replays wires and proc observations; summary status
fields and successful cleanup performed by this harness are not authorities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time

import rea_operation_qualification as q


SCHEMA = "hepta.rea.lifecycle-qualification.v1"
PROFILE = "rea-agents-6.8.0/inspect_elf_notes/linux-owned-lifecycle/v1"
ACTIVE_BYTES = 536870912
WORKER_BYTES = 33554432
ACTIVE_SECONDS = 15.0
DRAIN_SECONDS = 5.0
STEADY_SECONDS = 5.0
DEADLINE_SECONDS = 30.0
POLL_SECONDS = 0.005
UNKNOWN_REQUEST_ID = 1000000
PRODUCER_FILES = (
    "scripts/rea_lifecycle_qualification.py", "scripts/rea_lifecycle_evidence.py",
    "tests/rea_lifecycle_qualification_tests.py", "scripts/rea_operation_qualification.py",
    "scripts/rea_operation_evidence.py", "scripts/rea_full_qualification.py",
)
REFERENCE_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
    "REA_MCP_INPUT_SCHEMA_PROFILE": "full", "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full",
}


class Unobserved(q.QualificationError):
    """The requested phase was not observed, so the trace remains OPEN."""


def proc_identity(raw):
    """Parse Linux stat without assuming that the parenthesized comm has no spaces."""
    tail = raw[raw.rfind(")") + 2:].split()
    q.require(len(tail) >= 20, "incomplete process stat")
    return {"pid": int(raw.split(" ", 1)[0]), "parent_pid": int(tail[1]),
            "process_group": int(tail[2]), "start_time_ticks": int(tail[19])}


def proc_stat(pid):
    return (Path("/proc") / str(pid) / "stat").read_text()


class ProcessProbe:
    """Bounded observations of this client's process tree, with explicit unknowns.

    Missing descriptors during a scan and unreadable children are recorded as
    unknown. They cannot establish a negative (drained) observation. Signals use
    pidfds after a repeated identity check, never a PID guessed from a pathname.
    """

    def __init__(self, client, targets):
        self.client, self.targets = client, targets
        self.tracked = {}

    def snapshot(self):
        observed = {"schema": "hepta.rea.proc-observation.v1",
                    "start_ns": time.monotonic_ns(), "processes": [], "errors": [],
                    "tracked": []}
        todo, seen = [self.client.owner["pid"]], set()
        while todo:
            pid = todo.pop(0)
            if pid in seen:
                continue
            seen.add(pid)
            if len(seen) > 128:
                observed["errors"].append("owned process inventory exceeded 128")
                break
            base = Path("/proc") / str(pid)
            item = {"pid": pid, "fds": [], "listed_fds": [], "thread_children": {}}
            try:
                item["stat"] = proc_stat(pid)
                item["cmdline_hex"] = (base / "cmdline").read_bytes().hex()
                q.require(len(item["cmdline_hex"]) <= 131072, "owned argv exceeded 64 KiB")
                item["exe"] = os.readlink(base / "exe")
                threads = sorted((base / "task").iterdir(), key=lambda p: int(p.name))
                q.require(len(threads) <= 4096, "owned thread inventory exceeded 4096")
                item["listed_threads"] = [int(p.name) for p in threads]
                for thread in threads:
                    try:
                        raw = (thread / "children").read_text()
                        q.require(len(raw) <= 65536, "owned children list exceeded 64 KiB")
                        item["thread_children"][thread.name] = raw
                        todo.extend(int(value) for value in raw.split())
                    except (OSError, ValueError) as error:
                        observed["errors"].append(f"children {pid}/{thread.name}: {error}")
                descriptors = sorted((base / "fd").iterdir(), key=lambda p: int(p.name))
                q.require(len(descriptors) <= 4096, "owned descriptor inventory exceeded 4096")
                item["listed_fds"] = [int(p.name) for p in descriptors]
                for descriptor in descriptors:
                    try:
                        value = descriptor.stat()
                        record = {"fd": int(descriptor.name), "dev": value.st_dev,
                                  "ino": value.st_ino, "mode": value.st_mode}
                        if any((value.st_dev, value.st_ino) == (target["dev"], target["ino"])
                               for target in self.targets.values()):
                            record["link"] = os.readlink(descriptor)
                            record["fdinfo"] = (base / "fdinfo" / descriptor.name).read_text()
                        item["fds"].append(record)
                    except OSError as error:
                        observed["errors"].append(f"descriptor {pid}/{descriptor.name}: {error}")
                item["stat_after"] = proc_stat(pid)
                if proc_identity(item["stat"]) != proc_identity(item["stat_after"]):
                    observed["errors"].append(f"process {pid} changed identity during observation")
            except (OSError, ValueError) as error:
                observed["errors"].append(f"process {pid}: {error}")
            observed["processes"].append(item)
        for pid, (identity, pidfd) in sorted(self.tracked.items()):
            row = {"identity": identity, "pidfd_exited": bool(select.select([pidfd], [], [], 0)[0])}
            try:
                row["stat"] = proc_stat(pid)
            except FileNotFoundError:
                row["stat"] = None
            except OSError as error:
                row["stat"] = None
                row["error"] = str(error)
            observed["tracked"].append(row)
        observed["end_ns"] = time.monotonic_ns()
        return observed

    def stop_worker(self, identity):
        q.require(identity["parent_pid"] == self.client.owner["pid"]
                  and identity["process_group"] == self.client.owner["process_group"],
                  "worker is not a direct child in this runner's owned session")
        pid = identity["pid"]
        try:
            pidfd = os.pidfd_open(pid)
            if proc_identity(proc_stat(pid)) != identity:
                os.close(pidfd)
                raise Unobserved("worker identity changed before pidfd admission")
        except ProcessLookupError as error:
            raise Unobserved("worker exited before pidfd admission") from error
        q.require(pid not in self.tracked, "refusing to replace an existing tracked pidfd")
        self.tracked[pid] = (identity, pidfd)
        when = time.monotonic_ns()
        signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
        return {"event": "signal", "when_ns": when, "signal": "SIGSTOP", "identity": identity,
                "delivery": "pidfd", "purpose": "hold an observed owned parser before lifecycle trigger"}

    def close(self):
        for _, pidfd in self.tracked.values():
            os.close(pidfd)
        self.tracked.clear()


def matches_target(observation, target):
    return any((fd.get("dev"), fd.get("ino")) == (target["dev"], target["ino"])
               for process in observation["processes"] for fd in process.get("fds", []))


def worker_identities(observation, binary):
    workers = []
    for process in observation["processes"]:
        raw = process.get("stat")
        if not raw:
            continue
        argv = bytes.fromhex(process.get("cmdline_hex", "")).rstrip(b"\0").split(b"\0")
        if argv == [os.fsencode(binary), b"rea-elf-notes-worker"] and process.get("exe") == str(binary):
            workers.append(proc_identity(raw))
    return workers


def drained(observation, owner, targets):
    """Producer convenience only. The consumer independently checks every fact."""
    if observation["errors"] or len(observation["processes"]) != 1:
        return False
    try:
        if proc_identity(observation["processes"][0]["stat"]) != owner:
            return False
    except (KeyError, ValueError):
        return False
    if any(matches_target(observation, target) for target in targets):
        return False
    return all(row.get("pidfd_exited") is True and row.get("stat") is None and "error" not in row
               for row in observation["tracked"])


def wait_observation(probe, predicate, seconds):
    deadline = time.monotonic() + seconds
    count, last = 0, None
    while time.monotonic() < deadline:
        last = probe.snapshot()
        count += 1
        if predicate(last):
            return last, count
        if probe.client.process.poll() is not None:
            break
        time.sleep(POLL_SECONDS)
    raise Unobserved(json.dumps({"reason": "required process phase was not observed",
                                "polls": count, "last": last}, sort_keys=True))


def fixture_files(workspace):
    prefix = q.elf(q.note())
    files = {}
    for name, size in (("prime", len(prefix)), ("active", ACTIVE_BYTES), ("worker", WORKER_BYTES)):
        path = workspace / (name + ".elf")
        with path.open("xb") as handle:
            handle.write(prefix)
            handle.truncate(size)
            handle.flush()
            os.fsync(handle.fileno())
        identity = q.identity(path)
        value = path.stat()
        files[name] = {**identity, "dev": value.st_dev, "ino": value.st_ino, "mode": value.st_mode}
    return files


def prime_case(fixtures):
    value = fixtures["prime"]
    return {"arguments": {"path": value["path"]}, "facts": {
        "path": value["path"], "sha256": value["sha256"], "bytes": value["bytes"],
        "entries": 1, "tables": 1, "format": "elf64", "byte_order": "little",
        "owner": "GNU", "descriptor_hex": bytes(range(20)).hex(),
    }}


class Session:
    def __init__(self, label, scenario, args, output, fixtures, config):
        self.label, self.scenario, self.output = label, scenario, output
        self.fixtures, self.events, self.request_ids = fixtures, [], []
        self.tool = "inspect_elf_notes" if label == "reference" else "rea_inspect_elf_notes"
        self.bundle_tool = "get_evidence_bundle" if label == "reference" else "rea_get_evidence_bundle"
        argv = ([str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"]
                if label == "reference" else [str(args.binary), "mcp", "--runtime-config", str(config)])
        self.client = q.Mcp(argv, output / "workspace",
                            REFERENCE_ENVIRONMENT if label == "reference" else {},
                            output / (label + "-" + scenario))
        self.probe = ProcessProbe(self.client, fixtures)

    def initialize(self):
        self.client.initialize()
        self.call("prime", self.tool, {"path": self.fixtures["prime"]["path"]})
        self.call("baseline", self.bundle_tool, {})

    def append(self, event, **values):
        row = {"event": event, "when_ns": time.monotonic_ns(), **values}
        self.events.append(row)
        return row

    def call(self, role, tool, arguments, seconds=q.REQUEST_SECONDS):
        identifier = self.client.begin("tools/call", {"name": tool, "arguments": arguments})
        self.append("request", role=role, request_id=identifier, tool=tool, arguments=arguments)
        response = self.client.receive(identifier, seconds=seconds)
        self.append("response", role=role, request_id=identifier, response=response)
        if role in {"prime", "followup", "unknown-followup"}:
            q.check_independent_facts(q.evidence_value(response), prime_case(self.fixtures))
        return response

    def begin(self, role, fixture):
        arguments = {"path": self.fixtures[fixture]["path"], "max_file_bytes": ACTIVE_BYTES}
        identifier = self.client.begin("tools/call", {"name": self.tool, "arguments": arguments})
        self.append("request", role=role, request_id=identifier, tool=self.tool, arguments=arguments)
        self.request_ids.append(identifier)
        return identifier

    def cancel(self, identifier, role="cancel"):
        params = {"requestId": identifier, "reason": "Qualification cancellation of observed owned work"}
        self.client.send("notifications/cancelled", params)
        self.append("notification", role=role, method="notifications/cancelled", params=params)

    def observe(self, role, predicate, seconds=ACTIVE_SECONDS):
        snapshot, polls = wait_observation(self.probe, predicate, seconds)
        self.append("observation", role=role, polls=polls, snapshot=snapshot)
        return snapshot

    def clear(self, role):
        return self.observe(role, lambda s: drained(s, self.client.owner,
                            [self.fixtures["active"], self.fixtures["worker"]]), DRAIN_SECONDS)

    def steady(self):
        start = time.monotonic()
        for index in range(6):
            remaining = start + index - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            self.clear("steady-" + str(index))
            self.call("retention-" + str(index), self.bundle_tool, {})
        self.call("followup", self.tool, {"path": self.fixtures["prime"]["path"]})
        self.call("final-retention", self.bundle_tool, {})

    def unknown(self):
        self.cancel(UNKNOWN_REQUEST_ID, "unknown-cancel")
        completed = next(row["request_id"] for row in self.events
                         if row["event"] == "response" and row["role"] == "prime")
        self.cancel(completed, "completed-cancel")
        self.call("unknown-followup", self.tool, {"path": self.fixtures["prime"]["path"]})
        self.call("unknown-retention", self.bundle_tool, {})
        self.clear("unknown-drained")

    def stopped_worker(self, role, binary):
        prior = set(self.probe.tracked)
        active = self.observe(role + "-active", lambda s: any(
            item["pid"] not in prior for item in worker_identities(s, binary)))
        identity = next(item for item in worker_identities(active, binary) if item["pid"] not in prior)
        self.events.append(self.probe.stop_worker(identity))
        def stopped(observation):
            return any(item.get("stat") and proc_identity(item["stat"]) == identity
                       and item["stat"][item["stat"].rfind(")") + 2:].split()[0] in {"T", "t"}
                       for item in observation["processes"])
        self.observe(role + "-stopped", stopped, DRAIN_SECONDS)
        return identity

    def finish(self):
        try:
            self.append("eof", owner=self.client.owner)
            close = self.client.close()
            self.append("closed", observation=close)
            for item in self.probe.snapshot()["tracked"]:
                self.append("post-close-worker", observation=item)
        finally:
            self.probe.close()
        stem = self.label + "-" + self.scenario
        trace = q.artifact_json(self.output, stem + ".trace.json", {
            "schema": "hepta.rea.lifecycle-trace.v1", "producer": self.label,
            "scenario": self.scenario, "events": self.events,
        })
        return {"producer": self.label, "scenario": self.scenario, "trace": trace,
                **{key: q.artifact_reference(self.client.output / name, self.output)
                   for key, name in (("wire", "wire.jsonl"), ("launch", "launch.json"),
                                     ("close", "close.json"), ("stderr", "stderr.log"))}}


def run_capture(session, _args):
    identifier = session.begin("active", "active")
    session.observe("active", lambda s: matches_target(s, session.fixtures["active"]))
    session.cancel(identifier)
    session.clear("drained")
    session.steady()
    session.unknown()


def run_worker_capacity(session, args):
    for round_index in range(2):
        identifiers = []
        for slot in range(2):
            role = f"round-{round_index}-slot-{slot}"
            identifiers.append(session.begin(role, "worker"))
            session.stopped_worker(role, args.binary)
        session.call(f"round-{round_index}-capacity", session.tool,
                     {"path": session.fixtures["prime"]["path"]})
        for identifier in identifiers:
            session.cancel(identifier)
        session.clear(f"round-{round_index}-drained")
    session.steady()


def run_deadline(session, args):
    identifier = session.begin("deadline", "worker")
    session.stopped_worker("deadline", args.binary)
    response = session.client.receive(identifier, seconds=DEADLINE_SECONDS + 10)
    session.append("response", role="deadline", request_id=identifier, response=response)
    session.clear("deadline-drained")
    session.steady()


def run_active_eof(session, args):
    session.begin("active-eof", "active" if session.label == "reference" else "worker")
    if session.label == "reference":
        session.observe("active-eof", lambda s: matches_target(s, session.fixtures["active"]))
    else:
        session.stopped_worker("active-eof", args.binary)


def execute_session(label, scenario, action, args, output, fixtures, config):
    session = None
    try:
        session = Session(label, scenario, args, output, fixtures, config)
        session.initialize()
        action(session, args)
    except Unobserved as error:
        if session is None:
            raise
        session.append("unobserved", reason=str(error))
        # An unobserved phase cannot be qualified. Cancellation only bounds this
        # runner's unfinished work; it is explicitly cleanup, not test evidence.
        for identifier in session.request_ids:
            session.cancel(identifier, "cleanup-cancel")
    except Exception as error:
        if session is None:
            raise
        session.append("error", error_type=type(error).__name__, reason=str(error))
        for identifier in session.request_ids:
            session.cancel(identifier, "cleanup-cancel")
    finally:
        if session is not None:
            result = session.finish()
    return result


def producer_sources(repo):
    return [{**q.identity(repo / name), "path": name} for name in PRODUCER_FILES]


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "binary", "reference-package", "reference-tarball", "node", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--binary-source-commit", help="Declared build revision; not a substitute for build attestation")
    parser.add_argument("--binary-source-receipt", type=Path, required=True,
                        help="Original build/source receipt retained verbatim; verified by the separate build consumer")
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    q.require(sys.platform.startswith("linux") and hasattr(os, "pidfd_open")
              and hasattr(signal, "pidfd_send_signal"), "this profile requires Linux procfs and pidfds")
    for name in ("repo", "binary", "reference_package", "reference_tarball", "node", "output_dir", "binary_source_receipt"):
        q.require(getattr(args, name).is_absolute(), "all profile paths must be absolute")
    q.require(args.repo.resolve() == Path(__file__).resolve().parents[1], "producer must execute from its selected repo")
    q.require(re.fullmatch("[0-9a-f]{64}", args.binary_sha256), "invalid binary digest")
    q.require(args.binary_source_commit is None or re.fullmatch("[0-9a-f]{40}", args.binary_source_commit),
              "invalid declared binary source commit")
    q.require(not args.output_dir.exists(), "refusing to reuse an evidence directory")
    args.output_dir.mkdir(parents=True, mode=0o700)
    output = args.output_dir
    report = {"schema": SCHEMA, "profile": PROFILE, "operation": "inspect_elf_notes",
              "qualified": False, "status": "OPEN", "sessions": [], "errors": [],
              "scope": "Linux owned-process observations; not whole-operation or cross-platform qualification",
              "producer_repo": str(args.repo), "binary_source_commit_declared": args.binary_source_commit,
              "unsupported": [{"producer": "reference", "scenario": "worker-deadline",
                  "reason": "frozen ElfNotesProvider parses in process; no independent parser pidfd deadline injection boundary"}]}
    monitor = None
    try:
        report["reference_before"] = q.reference_package(args.reference_package, args.reference_tarball)
        q.require(report["reference_before"]["files_sha256"] == q.PACKAGE_FILES_SHA256, "unfrozen package inventory")
        report["native_before"] = q.identity(args.binary)
        q.require(report["native_before"]["sha256"] == args.binary_sha256, "native digest mismatch")
        report["node_before"] = q.identity(args.node.resolve())
        version = subprocess.run([str(args.node), "--version"], capture_output=True, check=True,
                                 timeout=10, env={}).stdout.decode().strip()
        q.require(version == "v22.23.4", "this profile requires Node v22.23.4")
        report["node_version"] = version
        receipt = args.binary_source_receipt.read_bytes()
        q.require(len(receipt) <= 16 * 1024 * 1024, "build/source receipt exceeds allowance")
        with (output / "binary-source-receipt.json").open("xb") as handle:
            handle.write(receipt)
        q.parse_json(receipt)
        report["binary_source_receipt"] = q.artifact_reference(output / "binary-source-receipt.json", output)
        report["producer_before"] = producer_sources(args.repo)
        from rea_full_qualification import Selection, SourceMonitor
        selection = Selection(args.repo, output / "unused-target", output)
        monitor = SourceMonitor(selection)
        monitor.start()
        report["source_before"] = q.artifact_json(output, "source-before.json", selection.snapshot())
        (output / "workspace").mkdir(mode=0o700)
        fixtures = fixture_files(output / "workspace")
        report["fixtures"] = q.artifact_json(output, "fixtures.json", fixtures)
        config = output / "runtime.json"
        q.write_json(config, {"controller_workspace_roots": [str(output / "workspace")],
            "state_dir": str(output / "state"), "hosts": {"never-connect": {
                "ssh_target": "never-connect-invalid", "remote_state_dir": str(output / "unused-remote"),
                "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}})
        report["config"] = q.artifact_reference(config, output)
        for label in ("reference", "native"):
            report["sessions"].append(execute_session(label, "capture-cancel", run_capture,
                                                     args, output, fixtures, config))
        report["sessions"].append(execute_session("native", "worker-capacity-cancel", run_worker_capacity,
                                                 args, output, fixtures, config))
        report["sessions"].append(execute_session("native", "worker-deadline", run_deadline,
                                                 args, output, fixtures, config))
        for label in ("reference", "native"):
            report["sessions"].append(execute_session(label, "active-eof", run_active_eof,
                                                     args, output, fixtures, config))
        report["fixtures_after"] = q.artifact_json(output, "fixtures-after.json", {
            name: {**q.identity(Path(item["path"])), "dev": Path(item["path"]).stat().st_dev,
                   "ino": Path(item["path"]).stat().st_ino, "mode": Path(item["path"]).stat().st_mode}
            for name, item in fixtures.items()})
        report["reference_after"] = q.reference_package(args.reference_package, args.reference_tarball)
        report["native_after"] = q.identity(args.binary)
        report["node_after"] = q.identity(args.node.resolve())
        report["producer_after"] = producer_sources(args.repo)
        report["source_after"] = q.artifact_json(output, "source-after.json", selection.snapshot())
    except Exception as error:
        report["errors"].append({"error_type": type(error).__name__, "reason": str(error)})
    finally:
        if monitor is not None:
            report["source_monitor"] = q.artifact_json(output, "source-monitor.json", monitor.stop())
    original = q.write_json(output / "qualification.json", report)
    try:
        from rea_lifecycle_evidence import validate_lifecycle_receipt
        assessment = validate_lifecycle_receipt(args.repo, output / "qualification.json", original["sha256"])
    except (OSError, ValueError, KeyError, TypeError) as error:
        assessment = {"schema": "hepta.rea.lifecycle-assessment.v1", "qualified": False,
                      "status": "INVALID", "error": str(error)}
    q.write_json(output / "assessment.json", assessment)
    print(json.dumps({"qualified": False, "status": assessment["status"], "receipt": original,
                      "gates": assessment.get("gates"), "error": assessment.get("error")}, sort_keys=True))
    return 1 if assessment["status"] in {"FAILED", "INVALID"} else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"qualified": False, "status": "INVALID", "error": str(error)}), file=sys.stderr)
        raise SystemExit(2)
