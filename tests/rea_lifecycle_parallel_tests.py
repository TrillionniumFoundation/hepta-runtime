#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Versioned lifecycle consumer/producer regressions; synthetic data is not qualification."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_lifecycle_evidence as evidence
import rea_lifecycle_qualification as lifecycle
import rea_operation_qualification as q
from rea_lifecycle_qualification_tests import OWNER, BINARY, process, raw_stat, wire, cancelled_response


def success(identifier):
    value = {"fixture": "synthetic baseline consumer input"}
    return {"jsonrpc": "2.0", "id": identifier, "result": {
        "_meta": q.TARGET_META, "structuredContent": value,
        "content": [{"type": "text", "text": json.dumps(value)}],
    }}


def capacity(identifier):
    value = {"error": {"code": "resource_constraint", "category": "resource",
                      "details": {"resource": "capacity", "reported_limits": {"max_concurrent_elf_workers": 2}}}}
    return {"jsonrpc": "2.0", "id": identifier, "result": {"isError": True, "_meta": q.TARGET_META,
        "content": [{"type": "text", "text": json.dumps(value)}],
    }}


def held_snapshot(identities, retired=()):
    owner = process()
    owner["thread_children"][str(OWNER["pid"])] = " ".join(str(item["pid"]) for item in identities)
    return {"schema": "hepta.rea.proc-observation.v1", "start_ns": 0, "end_ns": 0, "errors": [],
            "processes": [owner] + [process(item, "T", worker=True) for item in identities],
            "tracked": ([{"identity": item, "pidfd_exited": True, "stat": None} for item in retired]
                        + [{"identity": item, "pidfd_exited": False, "stat": raw_stat(item, "T")}
                           for item in identities])}


class ParallelTrace:
    """Construct internally bound wire/proc rows for exercising consumer refusals."""
    def __init__(self, legacy=False):
        self.clock, self.next_id, self.records, self.events = 0, 0, [], []
        self.replay = evidence.Replay.__new__(evidence.Replay)
        replay = self.replay
        replay.owner, replay.binary, replay.tool = OWNER, BINARY, "rea_inspect_elf_notes"
        replay.label = "native"
        replay.scenario = "worker-capacity-cancel" if legacy else "worker-parallel-cancel"
        replay.fixtures = {"prime": {"path": "/owned/prime.elf", "dev": 8, "ino": 42},
                           "worker": {"path": "/owned/worker.elf", "dev": 8, "ino": 43}}
        replay.closed = lambda: None
        replay.baseline = lambda: (success(0), {"synthetic": True}, {})
        replay.steady = lambda prime, record: None
        retired = []
        for round_index in range(2):
            held, identifiers = [], []
            for index in range(2):
                role = f"round-{round_index}-{'slot' if legacy else 'held'}-{index}"
                identifier = self.send(role, {"path": replay.fixtures["worker"]["path"],
                                              "max_file_bytes": evidence.ACTIVE_BYTES})
                identity = {"pid": 1400 + round_index * 2 + index, "parent_pid": OWNER["pid"],
                            "process_group": OWNER["process_group"], "start_time_ticks": 100 + round_index * 2 + index}
                snapshot = held_snapshot(held + [identity], retired)
                snapshot["processes"][-1] = process(identity, "R", worker=True)
                snapshot["tracked"] = snapshot["tracked"][:-1]
                self.observe(role + "-active", snapshot)
                self.event("signal", signal="SIGSTOP", identity=identity, delivery="pidfd")
                held.append(identity)
                self.observe(role + "-stopped", held_snapshot(held, retired))
                identifiers.append((role, identifier))
            if legacy:
                role = f"round-{round_index}-capacity"
                identifier = self.send(role, {"path": replay.fixtures["prime"]["path"]})
                self.respond(role, capacity(identifier))
            else:
                self.observe(f"round-{round_index}-held-before", held_snapshot(held, retired))
                pending = [(f"round-{round_index}-parallel-{index}",
                            self.send(f"round-{round_index}-parallel-{index}",
                                      {"path": replay.fixtures["prime"]["path"]}))
                           for index in range(evidence.PARALLEL_REQUESTS)]
                for role, identifier in pending:
                    self.respond(role, success(identifier))
                self.observe(f"round-{round_index}-held-after", held_snapshot(held, retired))
            for role, identifier in identifiers:
                params = {"requestId": identifier, "reason": "synthetic consumer cancellation"}
                self.records.append(("sent", self.tick(), {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": params}))
                self.event("notification", role="cancel", method="notifications/cancelled", params=params)
                self.respond(role, cancelled_response(identifier))
            retired.extend(held)
            self.observe(f"round-{round_index}-drained", held_snapshot([], retired))
        self.bind()

    def tick(self):
        self.clock += 100
        return self.clock

    def event(self, event, **values):
        row = {"event": event, "when_ns": self.tick(), **values}
        self.events.append(row)
        return row

    def send(self, role, arguments):
        self.next_id += 1
        identifier = self.next_id
        request = {"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                   "params": {"name": self.replay.tool, "arguments": arguments}}
        self.records.append(("sent", self.tick(), request))
        self.event("request", role=role, request_id=identifier, tool=self.replay.tool, arguments=arguments)
        return identifier

    def respond(self, role, response):
        self.records.append(("received", self.tick(), response))
        self.event("response", role=role, request_id=response["id"], response=response)

    def observe(self, role, snapshot):
        snapshot["start_ns"], snapshot["end_ns"] = self.tick(), self.tick()
        self.event("observation", role=role, snapshot=snapshot)

    def one(self, kind, role):
        return next(item for item in self.events if item["event"] == kind and item.get("role") == role)

    def replace_response(self, role, replacement):
        event = self.one("response", role)
        replacement["id"] = event["request_id"]
        event["response"] = replacement
        self.records = [(direction, when, replacement if direction == "received" and item.get("id") == event["request_id"] else item)
                        for direction, when, item in self.records]
        self.bind()

    def bind(self):
        self.events.sort(key=lambda item: item["when_ns"])
        self.records.sort(key=lambda item: item[1])
        self.replay.events = self.events
        self.replay.wire = evidence.original_wire(wire(self.records))
        self.replay.bind_events()


class ParallelConsumerTests(unittest.TestCase):
    def test_sixteen_independent_successes_and_four_original_reaps_are_required(self):
        result = ParallelTrace().replay.replay()
        self.assertEqual(result, {"status": "PASS", "details": {
            "distinct_reaped_workers": 4, "successful_requests_while_workers_stopped": 16,
            "held_workers_per_round": 2, "additional_requests_per_round": 8}})

    def test_former_capacity_refusal_is_a_failure_in_parallel_profile(self):
        trace = ParallelTrace()
        trace.replace_response("round-0-parallel-0", capacity(0))
        with self.assertRaisesRegex(evidence.FailedObservation, "independent request failed"):
            trace.replay.replay()

    def test_legacy_capacity_profile_still_requires_its_original_refusal(self):
        trace = ParallelTrace(legacy=True)
        self.assertEqual(trace.replay.replay(), {"status": "PASS", "details": {"distinct_reaped_workers": 4}})
        trace.replace_response("round-0-capacity", success(0))
        with self.assertRaisesRegex(ValueError, "typed tool failure"):
            trace.replay.replay()

    def test_missing_eighth_request_cannot_be_reported_as_full_sample(self):
        trace = ParallelTrace()
        role = "round-0-parallel-7"
        identifier = trace.one("request", role)["request_id"]
        trace.events = [item for item in trace.events if item.get("role") != role]
        trace.records = [row for row in trace.records if row[2].get("id") != identifier]
        trace.bind()
        with self.assertRaisesRegex(ValueError, "missing/duplicate request"):
            trace.replay.replay()

    def test_response_after_workers_were_cancelled_cannot_prove_parallel_completion(self):
        trace = ParallelTrace()
        response = trace.one("response", "round-0-parallel-0")
        when = trace.one("observation", "round-0-drained")["snapshot"]["start_ns"]
        response["when_ns"] = when + 2
        trace.records = [(direction, when + 1 if direction == "received" and item.get("id") == response["request_id"] else time, item)
                         for direction, time, item in trace.records]
        trace.bind()
        with self.assertRaisesRegex(ValueError, "between original held-worker observations"):
            trace.replay.replay()

    def test_original_workers_must_still_be_stopped_with_live_pidfds(self):
        for mutation in ("running", "exited", "different_identity"):
            trace = ParallelTrace()
            snapshot = trace.one("observation", "round-0-held-after")["snapshot"]
            identity = snapshot["tracked"][0]["identity"]
            if mutation == "running":
                snapshot["processes"][1] = process(identity, "R", worker=True)
            elif mutation == "exited":
                snapshot["tracked"][0]["pidfd_exited"] = True
            else:
                snapshot["processes"][1] = process({**identity, "start_time_ticks": 999}, "T", worker=True)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(evidence.FailedObservation, "original held workers"):
                trace.replay.replay()

    def test_incomplete_observation_remains_open(self):
        trace = ParallelTrace()
        trace.one("observation", "round-0-held-after")["snapshot"]["errors"] = ["missing thread children"]
        with self.assertRaisesRegex(evidence.OpenObservation, "incomplete inventory"):
            trace.replay.replay()

    def test_zombie_is_not_reap_completion(self):
        trace = ParallelTrace()
        snapshot = trace.one("observation", "round-0-drained")["snapshot"]
        snapshot["tracked"][0]["stat"] = raw_stat(snapshot["tracked"][0]["identity"], "Z")
        with self.assertRaisesRegex(evidence.FailedObservation, "unreaped pidfd"):
            trace.replay.replay()

    def test_missing_original_pidfd_cannot_be_reported_as_reap_completion(self):
        trace = ParallelTrace()
        trace.one("observation", "round-0-drained")["snapshot"]["tracked"] = []
        with self.assertRaisesRegex(ValueError, "omitted an original worker pidfd"):
            trace.replay.replay()

    def test_drain_after_five_seconds_fails(self):
        trace = ParallelTrace()
        event = trace.one("observation", "round-0-drained")
        event["snapshot"]["end_ns"] += 6_000_000_000
        event["when_ns"] = event["snapshot"]["end_ns"] + 1
        with self.assertRaisesRegex(evidence.FailedObservation, "within five seconds"):
            trace.replay.replay()

    def test_harness_resume_cannot_substitute_for_cancel_of_stopped_work(self):
        trace = ParallelTrace()
        held = trace.one("observation", "round-0-held-after")
        trace.events.append({"event": "signal", "when_ns": held["when_ns"] + 1,
                             "signal": "SIGCONT", "delivery": "pidfd",
                             "identity": held["snapshot"]["tracked"][0]["identity"]})
        with self.assertRaisesRegex(ValueError, "unreviewed process control"):
            trace.replay.replay()

    def test_cancelled_terminal_must_belong_to_original_cancel(self):
        trace = ParallelTrace()
        trace.replace_response("round-0-held-0", success(0))
        with self.assertRaisesRegex(ValueError, "typed tool failure"):
            trace.replay.replay()


class ProducerSession:
    """Synthetic transport records ordering without launching a provider."""
    def __init__(self, fail=False):
        self.tool = "rea_inspect_elf_notes"
        self.fixtures = {"prime": {"path": "/owned/prime.elf", "sha256": "1" * 64, "bytes": 156}}
        self.request_ids, self.actions, self.held, self.pending = [], [], [], []
        self.counter, self.fail = 0, fail
        self.client = SimpleNamespace(begin=self.submit, receive=self.receive)

    def submit(self, method, params):
        self.counter += 1
        self.actions.append(("submit", self.counter))
        self.pending.append(self.counter)
        return self.counter

    def receive(self, identifier, seconds):
        self.actions.append(("receive", identifier))
        if len(self.pending) != lifecycle.PARALLEL_REQUESTS:
            raise AssertionError("producer collected before submitting the full parallel sample")
        if len(self.held) != 2:
            raise AssertionError("producer did not preserve the original held workers")
        return capacity(identifier) if self.fail else success(identifier)

    def append(self, event, **values):
        self.actions.append((event, values.get("role")))

    def begin(self, role, fixture):
        self.counter += 1
        self.actions.append(("held", self.counter))
        return self.counter

    def stopped_worker(self, role, binary):
        identity = {"pid": 1400 + self.counter, "parent_pid": OWNER["pid"],
                    "process_group": OWNER["process_group"], "start_time_ticks": 100 + self.counter}
        self.held.append(identity)
        self.actions.append(("stop", identity["pid"]))
        return identity

    def observe(self, role, predicate, seconds):
        if not predicate(held_snapshot(self.held)):
            raise AssertionError("producer did not positively observe its held worker identities")
        self.actions.append(("observe", role))

    def cancel(self, identifier):
        self.actions.append(("cancel", identifier))

    def clear(self, role):
        self.actions.append(("drain", role))
        self.held, self.pending = [], []

    def steady(self):
        self.actions.append(("steady", None))


class ParallelProducerTests(unittest.TestCase):
    def test_producer_submits_eight_before_collection_and_checks_both_held_phases(self):
        session = ProducerSession()
        with mock.patch.object(q, "check_independent_facts") as facts:
            lifecycle.run_worker_parallel(session, SimpleNamespace(binary=Path(BINARY)))
        self.assertEqual(facts.call_count, 16)
        self.assertEqual(sum(kind == "receive" for kind, _ in session.actions), 16)
        self.assertEqual(sum(kind == "cancel" for kind, _ in session.actions), 4)
        for round_index in range(2):
            after = session.actions.index(("observe", f"round-{round_index}-held-after"))
            drain = session.actions.index(("drain", f"round-{round_index}-drained"))
            self.assertEqual(sum(kind == "cancel" for kind, _ in session.actions[after:drain]), 2)
        self.assertEqual(session.actions[-1], ("steady", None))
        self.assertEqual(lifecycle.PROFILE, evidence.PROFILE)
        self.assertNotEqual(lifecycle.PROFILE, evidence.LEGACY_PROFILE)

    def test_producer_does_not_turn_capacity_failure_into_a_parallel_success(self):
        session = ProducerSession(fail=True)
        with self.assertRaisesRegex(ValueError, "successful Evidence"):
            lifecycle.run_worker_parallel(session, SimpleNamespace(binary=Path(BINARY)))
        self.assertFalse(any(kind in {"cancel", "drain", "steady"} for kind, _ in session.actions))

    def test_producer_requires_live_stopped_identities_and_complete_observation(self):
        identity = {"pid": 1400, "parent_pid": OWNER["pid"], "process_group": OWNER["process_group"], "start_time_ticks": 100}
        good = held_snapshot([identity])
        self.assertTrue(lifecycle.workers_still_stopped(good, [identity]))
        for mutation in ("unknown", "exited", "running", "missing"):
            row = copy.deepcopy(good)
            if mutation == "unknown":
                row["errors"] = ["children unavailable"]
            elif mutation == "exited":
                row["tracked"][0]["pidfd_exited"] = True
            elif mutation == "running":
                row["processes"][1] = process(identity, "R", worker=True)
            else:
                row["tracked"] = []
            with self.subTest(mutation=mutation):
                self.assertFalse(lifecycle.workers_still_stopped(row, [identity]))


if __name__ == "__main__":
    unittest.main()
