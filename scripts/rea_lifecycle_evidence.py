#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Independently replay the finite Linux ELF lifecycle profile.

No status/qualified/passed flag from a producer closes a gate. Artifacts are
digest bound, requests and notifications come from original MCP wire, active
phases come from process/descriptor identities, and negative observations must
have complete inventories. A missing observation is OPEN; a known leak, forced
cleanup or unexpected public result is FAILED. Whole-operation qualification
and original build-source attestation remain the enclosing consumer's work.
"""

from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import rea_operation_evidence as e
import rea_operation_qualification as q


SCHEMA = "hepta.rea.lifecycle-qualification.v1"
PROFILE = "rea-agents-6.8.0/inspect_elf_notes/linux-owned-lifecycle/v1"
SESSION_ORDER = (("reference", "capture-cancel"), ("native", "capture-cancel"),
                 ("native", "worker-capacity-cancel"), ("native", "worker-deadline"),
                 ("reference", "active-eof"), ("native", "active-eof"))
PRODUCER_FILES = (
    "scripts/rea_lifecycle_qualification.py", "scripts/rea_lifecycle_evidence.py",
    "tests/rea_lifecycle_qualification_tests.py", "scripts/rea_operation_qualification.py",
    "scripts/rea_operation_evidence.py", "scripts/rea_full_qualification.py",
)
ACTIVE_BYTES = 536870912
WORKER_BYTES = 33554432


class OpenObservation(ValueError):
    """Required knowledge is absent; no affirmative gate is derivable."""


class FailedObservation(ValueError):
    """An observed public result or lifecycle violates the reviewed condition."""


def need(value, message):
    if not value:
        raise FailedObservation(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def parse_stat(raw):
    q.require(isinstance(raw, str) and len(raw) <= 65536 and ") " in raw, "invalid process stat")
    head, tail = raw[:raw.rfind(")") + 1], raw[raw.rfind(")") + 2:].split()
    q.require(re.match(r"^[0-9]+ \(", head) is not None and len(tail) >= 20, "incomplete process stat")
    identity = {"pid": int(head.split(" ", 1)[0]), "parent_pid": int(tail[1]),
                "process_group": int(tail[2]), "start_time_ticks": int(tail[19])}
    q.require(all(integer(value, 1) for value in identity.values()), "invalid process identity")
    q.require(tail[0] in set("RSDZTWtXxKWPIN"), "unknown Linux task state")
    return identity, tail[0]


def validate_observation(observation, owner, fixtures, binary):
    q.require(isinstance(observation, dict) and observation.get("schema") == "hepta.rea.proc-observation.v1",
              "unknown process observation schema")
    q.require(integer(observation.get("start_ns")) and integer(observation.get("end_ns"))
              and observation["start_ns"] <= observation["end_ns"], "invalid process observation interval")
    errors, processes, tracked = (observation.get(key) for key in ("errors", "processes", "tracked"))
    q.require(isinstance(errors, list) and all(isinstance(value, str) for value in errors), "invalid observation errors")
    q.require(isinstance(processes, list) and len(processes) <= 128 and isinstance(tracked, list),
              "invalid process inventory")
    complete, identities, children, matches, workers, states = not errors, {}, set(), set(), [], {}
    for process in processes:
        pid = process.get("pid")
        q.require(integer(pid, 1) and pid not in identities, "duplicate/invalid process inventory pid")
        if "stat" not in process or "stat_after" not in process:
            q.require(bool(errors), "partial process observation hid its error")
            complete = False
            continue
        identity, state = parse_stat(process["stat"])
        after, _ = parse_stat(process["stat_after"])
        q.require(identity["pid"] == pid, "stat pid does not match inventory pid")
        q.require(identity == after, "process identity changed during observation")
        identities[pid], states[pid] = identity, state
        q.require(identity["process_group"] == owner["process_group"], "observation escaped owned process group")
        threads, by_thread = process.get("listed_threads"), process.get("thread_children")
        q.require(isinstance(threads, list) and len(threads) <= 4096 and all(integer(tid, 1) for tid in threads)
                  and len(threads) == len(set(threads)) and isinstance(by_thread, dict), "invalid thread inventory")
        if set(by_thread) != {str(tid) for tid in threads}:
            q.require(bool(errors), "missing children list was treated as empty")
            complete = False
        for tid, raw in by_thread.items():
            q.require(tid.isdecimal() and isinstance(raw, str) and len(raw) <= 65536,
                      "invalid original children list")
            q.require(all(token.isdecimal() and int(token) > 0 for token in raw.split()), "invalid child pid")
            children.update(int(token) for token in raw.split())
        listed, fds = process.get("listed_fds"), process.get("fds")
        q.require(isinstance(listed, list) and len(listed) <= 4096 and all(integer(fd) for fd in listed)
                  and len(listed) == len(set(listed)) and isinstance(fds, list), "invalid descriptor inventory")
        q.require(all(isinstance(fd, dict) and integer(fd.get("fd")) for fd in fds), "invalid descriptor record")
        q.require(len({fd["fd"] for fd in fds}) == len(fds), "duplicate descriptor observation")
        if {fd["fd"] for fd in fds} != set(listed):
            q.require(bool(errors), "unreadable descriptor was treated as absent")
            complete = False
        for fd in fds:
            q.require(all(integer(fd.get(key)) for key in ("dev", "ino", "mode")), "invalid descriptor identity")
            for name, fixture in fixtures.items():
                if (fd["dev"], fd["ino"]) == (fixture["dev"], fixture["ino"]):
                    q.require(stat.S_ISREG(fd["mode"]) and isinstance(fd.get("fdinfo"), str)
                              and re.search(r"(?m)^pos:\s*[0-9]+$", fd["fdinfo"]),
                              "active target descriptor has no regular-file position observation")
                    q.require(fd.get("link") == fixture["path"], "active descriptor refers to a different name")
                    matches.add(name)
        raw_argv = process.get("cmdline_hex")
        q.require(isinstance(raw_argv, str) and len(raw_argv) <= 131072
                  and re.fullmatch(r"(?:[0-9a-f]{2})*", raw_argv), "invalid original argv bytes")
        argv = bytes.fromhex(raw_argv).rstrip(b"\0").split(b"\0")
        if argv == [os.fsencode(binary), b"rea-elf-notes-worker"]:
            q.require(process.get("exe") == str(binary) and identity["parent_pid"] == owner["pid"],
                      "native parser is not the selected binary's owned child")
            workers.append(identity)
    if identities.get(owner["pid"]) != owner:
        raise OpenObservation("the original live MCP owner was not positively observed")
    if states[owner["pid"]] in {"Z", "X", "x"}:
        raise FailedObservation("the MCP owner exited during the requested live-session observation")
    if set(identities) != children | {owner["pid"]}:
        q.require(bool(errors), "children inventory is incomplete without an unknown observation")
        complete = False
    for pid, identity in identities.items():
        if pid != owner["pid"]:
            q.require(identity["parent_pid"] in identities, "unowned/reparented process appeared in observed tree")
    tracked_ids, tracked_clear = set(), True
    for item in tracked:
        identity = item.get("identity")
        q.require(isinstance(identity, dict) and set(identity) == set(owner)
                  and all(integer(value, 1) for value in identity.values()), "invalid tracked pidfd identity")
        q.require(identity["parent_pid"] == owner["pid"] and identity["process_group"] == owner["process_group"],
                  "tracked pidfd belongs to a different owner")
        key = (identity["pid"], identity["start_time_ticks"])
        q.require(key not in tracked_ids and type(item.get("pidfd_exited")) is bool, "duplicate/invalid pidfd observation")
        tracked_ids.add(key)
        if item.get("stat") is not None:
            current, _ = parse_stat(item["stat"])
            q.require(current == identity, "tracked PID was reused; absence is unknown")
        if item.get("error") is not None:
            complete = False
        tracked_clear &= item.get("pidfd_exited") is True and item.get("stat") is None and "error" not in item
    return {"complete": complete, "matches": matches, "workers": workers, "identities": identities,
            "states": states, "tracked_clear": tracked_clear, "tracked_ids": tracked_ids,
            "clear": complete and len(identities) == 1 and not (matches & {"active", "worker"}) and tracked_clear}


def typed_failure(response):
    result = q.tool_value(response)
    q.require("rpc_error" not in result and result.get("isError") is True, "expected a typed tool failure")
    value = result["content"][0]["text"]
    q.require(isinstance(value, dict) and isinstance(value.get("error"), dict), "missing typed error object")
    q.require(result.get("_meta") == q.TARGET_META, "failure omitted analysis-target provenance")
    return value["error"]


@lru_cache(maxsize=3)
def expected_fixture(size):
    prefix = q.elf(q.note())
    q.require(size >= len(prefix), "fixture is shorter than the reviewed ELF")
    hasher = hashlib.sha256(prefix)
    remaining, zeros = size - len(prefix), bytes(1024 * 1024)
    while remaining:
        length = min(remaining, len(zeros))
        hasher.update(zeros[:length])
        remaining -= length
    return hasher.hexdigest()


def original_wire(raw):
    indexed = e.wire_index(raw)
    times, notifications = {"sent": {}, "received": {}}, []
    for line in raw.splitlines():
        record = q.parse_json(line)
        value = q.parse_json(record["wire_utf8"].encode())
        if "id" in value:
            times[record["direction"]][value["id"]] = record["monotonic_ns"]
        elif record["direction"] == "sent" and value["method"] == "notifications/cancelled":
            notifications.append({"value": value, "when_ns": record["monotonic_ns"]})
    for identifier in times["received"]:
        q.require(times["sent"][identifier] <= times["received"][identifier], "response preceded its original request")
    return {**indexed, "times": times, "notifications": notifications}


def cancellation_outcome(wire, identifier, notification_ns):
    """A cancellation notification needs no acknowledgement or terminal response."""
    response = wire["received"].get(identifier)
    if response is None:
        return "no-terminal-response"
    if wire["times"]["received"][identifier] < notification_ns:
        raise OpenObservation("operation completed before cancellation; active cancellation was not established")
    value = q.tool_value(response)
    if "rpc_error" in value:
        need(value["rpc_error"].get("code") == -32800, "unexpected JSON-RPC error after cancellation")
        return "json-rpc-cancelled"
    error = typed_failure(response)
    need(error.get("code") == "cancelled" and error.get("category") == "cancelled"
         and error.get("details", {}).get("operation") == "inspect_elf_notes", "cancelled work returned an unexpected result")
    return "typed-cancelled"


class Replay:
    def __init__(self, root, row, report, fixtures):
        self.label, self.scenario = row["producer"], row["scenario"]
        self.report, self.fixtures = report, fixtures
        self.binary = report["native_before"]["path"]
        self.trace = e.artifact_json(root, row["trace"])
        q.require(self.trace.get("schema") == "hepta.rea.lifecycle-trace.v1"
                  and self.trace.get("producer") == self.label and self.trace.get("scenario") == self.scenario,
                  "lifecycle trace identity mismatch")
        self.events = self.trace.get("events")
        q.require(isinstance(self.events, list) and self.events, "empty lifecycle trace")
        q.require(all(isinstance(event, dict) and integer(event.get("when_ns")) for event in self.events),
                  "invalid lifecycle event")
        q.require(all(a["when_ns"] <= b["when_ns"] for a, b in zip(self.events, self.events[1:])),
                  "lifecycle events are out of order")
        allowed = {"request", "response", "notification", "observation", "signal", "eof", "closed",
                   "post-close-worker", "unobserved", "error"}
        q.require(all(event.get("event") in allowed for event in self.events), "unknown lifecycle event type")
        self.wire = original_wire(e.read_artifact(root, row["wire"]))
        self.launch = e.artifact_json(root, row["launch"])
        self.close = e.artifact_json(root, row["close"])
        e.read_artifact(root, row["stderr"], 16 * 1024 * 1024)
        self.owner = self.launch["owner"]
        q.require(self.owner["pid"] == self.launch["pid"] == self.owner["process_group"], "owner is not a fresh session")
        package = report["reference_before"]["package_root"]
        expected = ([report["node_before"]["path"], str(Path(package) / "scripts/rea.mjs"), "mcp"]
                    if self.label == "reference" else [self.binary, "mcp", "--runtime-config", str(root / "runtime.json")])
        q.require(self.launch["argv"] == expected and self.launch["cwd"] == str(root / "workspace"),
                  "trace did not launch the selected public MCP entry point")
        if self.label == "reference":
            q.require(self.launch["environment"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                      "REA_MCP_INPUT_SCHEMA_PROFILE": "full", "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"},
                      "unreviewed reference environment")
        else:
            q.require(self.launch["environment"] == {}, "unreviewed native environment")
        self.tool = "inspect_elf_notes" if self.label == "reference" else "rea_inspect_elf_notes"
        self.bundle = "get_evidence_bundle" if self.label == "reference" else "rea_get_evidence_bundle"
        self.bind_events()

    def one(self, event_type, role=None):
        values = [event for event in self.events if event["event"] == event_type
                  and (role is None or event.get("role") == role)]
        q.require(len(values) == 1, f"missing/duplicate {event_type} {role}")
        return values[0]

    def bind_events(self):
        recorded_notifications = []
        sent_ids, received_ids = set(), set()
        for event in self.events:
            if event["event"] == "request":
                identifier = event.get("request_id")
                q.require(integer(identifier, 1) and identifier not in sent_ids, "duplicate recorded request")
                sent_ids.add(identifier)
                q.require(self.wire["sent"].get(identifier) == {"jsonrpc": "2.0", "id": identifier,
                    "method": "tools/call", "params": {"name": event["tool"], "arguments": event["arguments"]}},
                    "trace request was not sent on the original wire")
                q.require(self.wire["times"]["sent"][identifier] <= event["when_ns"], "request trace preceded original send")
            elif event["event"] == "response":
                identifier = event.get("request_id")
                q.require(identifier not in received_ids and event.get("response") == self.wire["received"].get(identifier),
                          "response summary differs from original wire")
                q.require(self.wire["times"]["received"][identifier] <= event["when_ns"], "response trace preceded original receive")
                received_ids.add(identifier)
            elif event["event"] == "notification":
                recorded_notifications.append(event)
        public_ids = {identifier for identifier, value in self.wire["sent"].items() if value.get("method") == "tools/call"}
        q.require(sent_ids == public_ids, "trace omitted or invented a public operation request")
        q.require(len(recorded_notifications) == len(self.wire["notifications"]), "cancellation notifications omitted or invented")
        for event, original in zip(recorded_notifications, self.wire["notifications"], strict=True):
            q.require(original["value"] == {"jsonrpc": "2.0", "method": event["method"], "params": event["params"]}
                      and original["when_ns"] <= event["when_ns"], "notification differs from original wire")
            event["original_ns"] = original["when_ns"]

    def observation(self, role, clear=False):
        event = self.one("observation", role)
        value = event["snapshot"]
        q.require(value["end_ns"] <= event["when_ns"], "process observation ended after its trace event")
        result = validate_observation(value, self.owner, self.fixtures, self.binary)
        if clear and not result["complete"]:
            raise OpenObservation("incomplete process/descriptor observation cannot prove owner drain")
        if clear:
            need(result["clear"], "owned process, target descriptor or unreaped pidfd remained after drain")
        return event, result

    def result(self, role):
        request, response = self.one("request", role), self.one("response", role)
        q.require(request["request_id"] == response["request_id"], "trace role paired different requests")
        return response["response"]

    def baseline(self):
        prime = self.result("prime")
        request = self.one("request", "prime")
        q.require(request["tool"] == self.tool and request["arguments"] == {"path": self.fixtures["prime"]["path"]},
                  "prime was not the reviewed ELF fixture")
        fixture = self.fixtures["prime"]
        record = q.evidence_value(prime)
        q.check_independent_facts(record, {"arguments": request["arguments"], "facts": {
            "path": fixture["path"], "sha256": fixture["sha256"], "bytes": fixture["bytes"],
            "entries": 1, "tables": 1, "format": "elf64", "byte_order": "little",
            "owner": "GNU", "descriptor_hex": bytes(range(20)).hex()}})
        baseline = self.result("baseline")
        self.bundle_result("baseline", record)
        return prime, record, baseline

    def bundle_result(self, role, record):
        request = self.one("request", role)
        q.require(request["tool"] == self.bundle and request["arguments"] == {}, "unexpected retention query")
        q.check_retention_response({"id": "complete", "arguments": {}}, self.result(role), [record])

    def closed(self):
        q.require(self.close["owner"] == self.owner and self.one("closed")["observation"] == self.close,
                  "close observation changed owner or original receipt")
        q.require(self.one("eof")["owner"] == self.owner, "EOF addressed a different process")
        need(e.owner_closed(self.close), "owned MCP needed forced cleanup or did not reap/read EOF cleanly")
        for event in self.events:
            if event["event"] == "post-close-worker":
                item = event["observation"]
                need(item.get("pidfd_exited") is True and item.get("stat") is None and "error" not in item,
                     "owned parser survived MCP EOF or remained unreaped")

    def active_request(self, role, fixture):
        request = self.one("request", role)
        q.require(request["tool"] == self.tool and request["arguments"] == {
            "path": self.fixtures[fixture]["path"], "max_file_bytes": ACTIVE_BYTES}, "unreviewed active fixture/request")
        return request["request_id"], self.wire["times"]["sent"][request["request_id"]]

    def cancelled(self, identifier, active):
        notifications = [event for event in self.events if event["event"] == "notification"
                         and event.get("role") == "cancel" and event["params"].get("requestId") == identifier]
        q.require(len(notifications) == 1, "missing/duplicate tested cancellation")
        when = notifications[0]["original_ns"]
        q.require(active["snapshot"]["end_ns"] <= when, "cancellation raced before the observed active phase")
        outcome = cancellation_outcome(self.wire, identifier, when)
        return when, outcome

    def steady(self, prime, record):
        snapshots = []
        for index in range(6):
            event, _ = self.observation("steady-" + str(index), clear=True)
            snapshots.append(event["snapshot"])
            self.bundle_result("retention-" + str(index), record)
        need(snapshots[-1]["end_ns"] - snapshots[0]["start_ns"] >= 5_000_000_000,
             "post-cancellation retention/drain observation window was shortened")
        request = self.one("request", "followup")
        q.require(request["tool"] == self.tool and request["arguments"] == {"path": self.fixtures["prime"]["path"]},
                  "follow-up did not use the same public operation")
        need(q.tool_value(self.result("followup")) == q.tool_value(prime), "same-session follow-up failed or changed evidence")
        self.bundle_result("final-retention", record)

    def stopped(self, role):
        active, parsed = self.observation(role + "-active")
        stopped, after = self.observation(role + "-stopped")
        signals = [event for event in self.events if event["event"] == "signal"
                   and active["when_ns"] <= event["when_ns"] <= stopped["snapshot"]["start_ns"]]
        q.require(len(signals) == 1, "missing/duplicate owned worker stop")
        control = signals[0]
        q.require(control.get("signal") == "SIGSTOP" and control.get("delivery") == "pidfd"
                  and control.get("identity") in parsed["workers"], "worker control was not bound to an observed parser")
        identity = control["identity"]
        q.require(after["identities"].get(identity["pid"]) == identity
                  and after["states"].get(identity["pid"]) in {"T", "t"}, "parser stop was not observed")
        q.require((identity["pid"], identity["start_time_ticks"]) in after["tracked_ids"], "stopped worker lacks a retained pidfd")
        return stopped, identity

    def replay(self):
        self.closed()
        if any(event["event"] == "error" for event in self.events):
            raise FailedObservation("runner recorded a failed execution: " + next(
                event["reason"] for event in self.events if event["event"] == "error"))
        if any(event["event"] == "unobserved" for event in self.events):
            raise OpenObservation("active phase was not observed; cleanup is not qualification")
        prime, record, _ = self.baseline()
        details = {}
        if self.scenario == "capture-cancel":
            identifier, sent = self.active_request("active", "active")
            active, observed = self.observation("active")
            q.require(sent <= active["snapshot"]["start_ns"] and "active" in observed["matches"],
                      "cancellation lacked a positive descriptor observation after its request")
            when, details["terminal"] = self.cancelled(identifier, active)
            drain, _ = self.observation("drained", clear=True)
            need(0 <= drain["snapshot"]["start_ns"] - when <= 5_000_000_000, "cancellation drain missed its bound")
            self.steady(prime, record)
            unknown, completed = self.one("notification", "unknown-cancel"), self.one("notification", "completed-cancel")
            q.require(unknown["params"]["requestId"] == 1000000 and 1000000 not in self.wire["sent"],
                      "unknown cancellation addressed a real request")
            prime_id = self.one("request", "prime")["request_id"]
            q.require(completed["params"]["requestId"] == prime_id
                      and self.wire["times"]["received"][prime_id] < completed["original_ns"],
                      "completed cancellation was not actually late")
            need(q.tool_value(self.result("unknown-followup")) == q.tool_value(prime), "unknown cancellation damaged the session")
            self.bundle_result("unknown-retention", record)
            self.observation("unknown-drained", clear=True)
        elif self.scenario == "worker-capacity-cancel":
            workers = set()
            for round_index in range(2):
                selected = []
                for slot in range(2):
                    role = f"round-{round_index}-slot-{slot}"
                    identifier, sent = self.active_request(role, "worker")
                    stopped, identity = self.stopped(role)
                    q.require(sent <= stopped["snapshot"]["start_ns"], "worker preceded its admitted request")
                    key = (identity["pid"], identity["start_time_ticks"])
                    q.require(key not in workers, "capacity recovery reused an earlier worker observation")
                    workers.add(key)
                    selected.append((identifier, stopped, identity))
                last = validate_observation(selected[-1][1]["snapshot"], self.owner, self.fixtures, self.binary)
                q.require(all(last["identities"].get(identity["pid"]) == identity
                              and last["states"][identity["pid"]] in {"T", "t"}
                              for _, _, identity in selected), "two worker slots were not occupied together")
                capacity_role = f"round-{round_index}-capacity"
                error = typed_failure(self.result(capacity_role))
                need(error.get("code") == "resource_constraint" and error.get("details", {}).get("resource") == "capacity"
                     and error["details"].get("reported_limits") == {"max_concurrent_elf_workers": 2},
                     "third request did not encounter the native two-slot capacity boundary")
                for identifier, active, _ in selected:
                    self.cancelled(identifier, active)
                self.observation(f"round-{round_index}-drained", clear=True)
            self.steady(prime, record)
            details["distinct_reaped_workers"] = len(workers)
        elif self.scenario == "worker-deadline":
            identifier, sent = self.active_request("deadline", "worker")
            stopped, _ = self.stopped("deadline")
            q.require(not self.wire["notifications"], "deadline observation contained a cancellation trigger")
            error = typed_failure(self.result("deadline"))
            need(error.get("code") == "provider_timeout" and error.get("category") == "timeout"
                 and error.get("details", {}).get("operation") == "inspect_elf_notes"
                 and error["details"].get("timeout_ms") == 30000, "native worker did not report its fixed provider deadline")
            completed = self.wire["times"]["received"][identifier]
            need(29_000_000_000 <= completed - sent <= 45_000_000_000
                 and completed > stopped["snapshot"]["end_ns"], "deadline result timing was not the fixed native budget")
            self.observation("deadline-drained", clear=True)
            self.steady(prime, record)
        elif self.scenario == "active-eof":
            _, sent = self.active_request("active-eof", "active" if self.label == "reference" else "worker")
            if self.label == "reference":
                active, observed = self.observation("active-eof")
                q.require("active" in observed["matches"], "EOF was not sent during observed target capture")
            else:
                active, _ = self.stopped("active-eof")
            q.require(sent <= active["snapshot"]["start_ns"] <= active["snapshot"]["end_ns"]
                      <= self.one("eof")["when_ns"], "EOF preceded active ownership")
            q.require(not self.wire["notifications"], "active EOF was replaced by a prior cancellation")
        return {"status": "PASS", "details": details}


def validate_lifecycle_receipt(repo, receipt_path, expected_sha256):
    """Exported read-only validator. The caller supplies a pinned original receipt."""
    repo, receipt_path = Path(repo), Path(receipt_path)
    q.require(repo.is_absolute() and receipt_path.is_absolute() and not receipt_path.is_symlink(),
              "validator requires explicit absolute repository and receipt paths")
    q.require(re.fullmatch("[0-9a-f]{64}", expected_sha256) and q.file_hash(receipt_path) == expected_sha256,
              "lifecycle receipt digest mismatch")
    raw = receipt_path.read_bytes()
    q.require(len(raw) <= q.MAX_WIRE_BYTES, "lifecycle receipt exceeds allowance")
    report, root = q.parse_json(raw), receipt_path.parent
    q.require(report.get("schema") == SCHEMA and report.get("profile") == PROFILE
              and report.get("operation") == "inspect_elf_notes", "unknown lifecycle qualification profile")
    q.require(report.get("errors") == [], "lifecycle execution did not produce a complete receipt")
    bindings = report.get("producer_before")
    q.require(isinstance(bindings, list) and [item["path"] for item in bindings] == list(PRODUCER_FILES)
              and report.get("producer_after") == bindings, "lifecycle producer changed or omitted source files")
    for item in bindings:
        e.read_artifact(repo, item)
    before, after = e.artifact_json(root, report["source_before"]), e.artifact_json(root, report["source_after"])
    q.require(before == after and before["tree_sha256"] == q.digest(before["files"]), "producer source inventory changed")
    from rea_full_qualification import Selection
    q.require(Selection(repo, root / "unused-target", root).snapshot() == before, "stale lifecycle producer source inventory")
    monitor = e.artifact_json(root, report["source_monitor"])
    q.require(monitor["event_count"] == 0 and monitor["errors"] == [] and monitor["retained_events"] == []
              and monitor["events_truncated"] is False, "source changed or inotify coverage was lost")
    reference = report["reference_before"]
    q.require(reference == report["reference_after"], "original package changed during lifecycle run")
    for key, value in {"name": "rea-agents", "version": "6.8.0", "file_count": 2398,
                       "tarball_sha256": q.PACKAGE_SHA256, "files_sha256": q.PACKAGE_FILES_SHA256,
                       "catalog_sha256": q.CATALOG_SHA256, "git_source_commit": q.REFERENCE_COMMIT}.items():
        q.require(reference.get(key) == value, "unfrozen original package identity: " + key)
    q.require(report["native_before"] == report["native_after"] and report["node_before"] == report["node_after"]
              and report["node_version"] == "v22.23.4", "selected executable changed during run")
    for key in ("native_before", "node_before"):
        item = report[key]
        q.require(set(item) == {"path", "bytes", "sha256"} and Path(item["path"]).is_absolute()
                  and integer(item["bytes"], 1) and re.fullmatch("[0-9a-f]{64}", item["sha256"]), "invalid executable identity")
    source_receipt = e.artifact_json(root, report["binary_source_receipt"])
    declared = report.get("binary_source_commit_declared")
    q.require(declared is None or re.fullmatch("[0-9a-f]{40}", declared), "invalid declared binary revision")
    if isinstance(source_receipt, dict) and isinstance(source_receipt.get("binary"), dict):
        q.require(source_receipt["binary"] == report["native_before"], "original source receipt names a different binary")
        if source_receipt.get("commit") is not None:
            q.require(source_receipt["commit"] == declared, "declared binary revision differs from original receipt")
    config = e.artifact_json(root, report["config"])
    q.require(config == {"controller_workspace_roots": [str(root / "workspace")], "state_dir": str(root / "state"),
        "hosts": {"never-connect": {"ssh_target": "never-connect-invalid", "remote_state_dir": str(root / "unused-remote"),
            "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}},
        "unreviewed runtime configuration")
    fixtures = e.artifact_json(root, report["fixtures"])
    q.require(fixtures == e.artifact_json(root, report["fixtures_after"]) and set(fixtures) == {"prime", "active", "worker"},
              "fixture identity changed or reviewed files are missing")
    for name, size in (("prime", len(q.elf(q.note()))), ("active", ACTIVE_BYTES), ("worker", WORKER_BYTES)):
        value = fixtures[name]
        q.require(set(value) == {"path", "sha256", "bytes", "dev", "ino", "mode"}
                  and value["path"] == str(root / "workspace" / (name + ".elf")) and value["bytes"] == size
                  and value["sha256"] == expected_fixture(size) and stat.S_ISREG(value["mode"])
                  and integer(value["dev"]) and integer(value["ino"], 1), "fixture differs from independent ELF encoding")
    rows = report.get("sessions")
    q.require(isinstance(rows, list) and [(row.get("producer"), row.get("scenario")) for row in rows] == list(SESSION_ORDER),
              "lifecycle session set/order is incomplete or invented")
    results = {}
    for row in rows:
        key = row["producer"] + "/" + row["scenario"]
        replay = Replay(root, row, report, fixtures)
        try:
            results[key] = replay.replay()
        except OpenObservation as error:
            results[key] = {"status": "OPEN", "reason": str(error)}
        except (FailedObservation, q.QualificationError) as error:
            results[key] = {"status": "FAILED", "reason": str(error)}
    def combined(names):
        values = [results[name]["status"] for name in names]
        return "FAILED" if "FAILED" in values else "OPEN" if "OPEN" in values else "PASS"
    gates = {
        "active-cancellation-owner-drain": combined(["reference/capture-cancel", "native/capture-cancel", "native/worker-capacity-cancel"]),
        "unknown-cancellation-boundary": combined(["reference/capture-cancel", "native/capture-cancel"]),
        "active-eof-owner-drain": combined(["reference/active-eof", "native/active-eof"]),
        "native-worker-deadline-owner-drain": results["native/worker-deadline"]["status"],
        "deadline-owner-drain": "OPEN",
    }
    q.require(report.get("unsupported") == [{"producer": "reference", "scenario": "worker-deadline",
        "reason": "frozen ElfNotesProvider parses in process; no independent parser pidfd deadline injection boundary"}],
        "unsupported reference deadline scope was omitted or replaced")
    return {"schema": "hepta.rea.lifecycle-assessment.v1", "profile": PROFILE,
            "qualified": False, "status": "FAILED" if "FAILED" in gates.values() else "OPEN",
            "gates": gates, "sessions": results,
            "binary": report["native_before"], "binary_source_commit_declared": declared,
            "source_attestation": "OPEN: original receipt retained; enclosing build consumer must validate compilation provenance",
            "open_requirements": ["reference-deadline-injection-not-established", "whole-operation-format-and-retention-coverage",
                                  "complete-build-source-attestation", "nonlocal-and-cross-platform-contracts"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    result = validate_lifecycle_receipt(args.repo, args.receipt, args.sha256)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "FAILED" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"qualified": False, "status": "INVALID", "error": str(error)}), file=sys.stderr)
        raise SystemExit(2)
