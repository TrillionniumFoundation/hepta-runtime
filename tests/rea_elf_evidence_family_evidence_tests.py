#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Adversarial receipt-reader controls; these are not provider execution receipts."""

import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import rea_elf_evidence_family_evidence as evidence


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def json_line(value):
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()


class ArtifactFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rea-family-evidence-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def plain(self, raw, name="artifact.json"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return {"path": name, "bytes": len(raw), "sha256": digest(raw)}

    def zipped(self, raw, name="artifact.json.gz", encoding="gzip-original-bytes", stored=None):
        compressed = gzip.compress(raw, mtime=0) if stored is None else stored
        self.plain(compressed, name)
        return {"path": name, "encoding": encoding, "raw_bytes": len(raw), "raw_sha256": digest(raw),
                "gzip_bytes": len(compressed), "gzip_sha256": digest(compressed)}


class ArtifactReaderTests(ArtifactFixture, unittest.TestCase):
    def test_pinned_reader_requires_actual_bytes_length_and_digest(self):
        reference = self.plain(b"original")
        self.assertEqual(evidence.read_pinned(self.root, reference, maximum=8), b"original")
        with self.assertRaises((ValueError, OSError)):
            evidence.read_pinned(self.root, reference, maximum=7)
        (self.root / reference["path"]).write_bytes(b"modified")
        with self.assertRaises((ValueError, OSError)):
            evidence.read_pinned(self.root, reference)

    def test_pinned_reference_types_and_digest_are_not_coerced(self):
        reference = self.plain(b"x")
        for field, value in (("bytes", True), ("bytes", "1"), ("bytes", -1),
                             ("sha256", "0" * 64), ("sha256", "A" * 64), ("sha256", None)):
            changed = {**reference, field: value}
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, OSError)):
                evidence.read_pinned(self.root, changed)

    def test_artifact_paths_cannot_escape_or_normalize_away_segments(self):
        reference = self.plain(b"pinned")
        names = ("../artifact.json", str(self.root / "artifact.json"), "dir/../artifact.json",
                 "./artifact.json", "dir//artifact.json", "dir\\artifact.json", "a:b", "nul\0file")
        for name in names:
            with self.subTest(path=repr(name)), self.assertRaises((ValueError, OSError)):
                evidence.read_pinned(self.root, {**reference, "path": name})

    def test_symlink_file_ancestor_and_root_are_refused(self):
        reference = self.plain(b"pinned", "actual/value")
        (self.root / "file-link").symlink_to(self.root / "actual/value")
        (self.root / "ancestor-link").symlink_to(self.root / "actual", target_is_directory=True)
        (self.root / "root-link").symlink_to(self.root, target_is_directory=True)
        for name in ("file-link", "ancestor-link/value"):
            with self.subTest(path=name), self.assertRaises((ValueError, OSError)):
                evidence.read_pinned(self.root, {**reference, "path": name})
        with self.assertRaises((ValueError, OSError)):
            evidence.read_pinned(self.root / "root-link", reference)

    def test_hardlinks_and_fifo_are_not_regular_owned_artifacts(self):
        reference = self.plain(b"pinned")
        os.link(self.root / reference["path"], self.root / "second-link")
        with self.assertRaises((ValueError, OSError)):
            evidence.read_pinned(self.root, reference)
        os.mkfifo(self.root / "fifo")
        with self.assertRaises((ValueError, OSError)):
            evidence.read_pinned(self.root, {"path": "fifo", "bytes": 0, "sha256": digest(b"")})

    def test_gzip_reader_preserves_every_original_byte(self):
        raw = b' {"path":"' + "中文🙂".encode() + b'","bytes":"\\u0000"}\n\x00\xff'
        reference = self.zipped(raw)
        self.assertEqual(evidence.read_gzip(self.root, reference, maximum=len(raw)), raw)
        with self.assertRaises((ValueError, OSError)):
            evidence.read_gzip(self.root, reference, maximum=len(raw) - 1)

    def test_gzip_reference_does_not_trust_claimed_lengths_or_hashes(self):
        reference = self.zipped(b"x")
        for field, value in (("raw_bytes", True), ("gzip_bytes", True), ("raw_bytes", 0),
                             ("raw_sha256", "0" * 64), ("gzip_sha256", "0" * 64),
                             ("encoding", "identity")):
            with self.subTest(field=field), self.assertRaises((ValueError, OSError)):
                evidence.read_gzip(self.root, {**reference, field: value})

    def test_gzip_crc_truncation_and_non_gzip_bytes_are_refused(self):
        raw = b"one original frame\n"
        good = gzip.compress(raw, mtime=0)
        crc = bytearray(good)
        crc[-8] ^= 1
        for index, stored in enumerate((good[:-1], bytes(crc), b"not gzip")):
            reference = self.zipped(raw, name=f"broken-{index}.gz", stored=stored)
            with self.subTest(index=index), self.assertRaises((ValueError, OSError)):
                evidence.read_gzip(self.root, reference)

    def test_gzip_extra_members_and_trailing_data_are_refused(self):
        raw = b"original"
        compressed = gzip.compress(raw, mtime=0)
        for index, (claimed, stored) in enumerate((
                (raw + b"second", compressed + gzip.compress(b"second", mtime=0)),
                (raw, compressed + b"trailing"), (raw, compressed + b"\0"))):
            reference = self.zipped(claimed, name=f"extra-{index}.gz", stored=stored)
            with self.subTest(index=index), self.assertRaises((ValueError, OSError)):
                evidence.read_gzip(self.root, reference)

    def test_gzip_expansion_cannot_hide_behind_a_small_declared_size(self):
        reference = self.zipped(bytes(2 * 1024 * 1024))
        reference["raw_bytes"], reference["raw_sha256"] = 32, digest(bytes(32))
        with self.assertRaises((ValueError, OSError)):
            evidence.read_gzip(self.root, reference, maximum=64)


class WireIndexTests(ArtifactFixture, unittest.TestCase):
    def conversation(self):
        return [
            ("sent", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2026-07-28", "capabilities": {},
                "clientInfo": {"name": "hepta-rea-operation-qualification", "version": "1"}}}),
            ("received", {"jsonrpc": "2.0", "id": 1, "result": {
                "protocolVersion": "2026-07-28", "capabilities": {},
                "serverInfo": {"name": "original", "version": "1"}}}),
            ("sent", {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
            ("sent", {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_evidence_bundle", "arguments": {"detail": "summary"}}}),
            ("received", {"jsonrpc": "2.0", "id": 2, "result": {
                "content": [{"type": "text", "text": '{ "second": 2, "first": 1 }'}],
                "structuredContent": {"second": 2, "first": 1}}}),
        ]

    def index(self, conversation, mutate_entry=None):
        entries = []
        for number, (direction, value) in enumerate(conversation):
            raw = value if isinstance(value, bytes) else json_line(value)
            reference = self.zipped(raw, name=f"owner/wire-{number:04d}-{direction}.json.gz",
                                    encoding="gzip-original-jsonrpc-line")
            reference["path"] = Path(reference["path"]).name
            entry = {"direction": direction, "monotonic_ns": 1000 + number, **reference}
            if mutate_entry:
                mutate_entry(number, entry)
            entries.append(entry)
        raw = b"".join(json_line(entry) for entry in entries)
        return self.plain(raw, "owner/wire.jsonl")

    def test_complete_original_index_is_replayed_and_opaque_text_is_preserved(self):
        result = evidence.wire_index(self.root, self.index(self.conversation()))
        self.assertEqual(result["sent"][2]["params"]["arguments"], {"detail": "summary"})
        self.assertEqual(result["received"][2]["result"]["content"][0]["text"],
                         '{ "second": 2, "first": 1 }')

    def test_duplicate_response_or_request_in_full_index_is_refused(self):
        for direction in ("sent", "received"):
            rows = self.conversation()
            duplicate = next(row for row in reversed(rows) if row[0] == direction)
            rows.append(copy.deepcopy(duplicate))
            with self.subTest(direction=direction), self.assertRaises((ValueError, OSError)):
                evidence.wire_index(self.root, self.index(rows))

    def test_unmatched_response_and_missing_response_are_refused(self):
        for changed in (self.conversation()[:-1], self.conversation()[:3] + self.conversation()[4:]):
            with self.subTest(rows=len(changed)), self.assertRaises((ValueError, OSError)):
                evidence.wire_index(self.root, self.index(changed))

    def test_response_must_follow_its_actual_request(self):
        rows = self.conversation()
        rows[3], rows[4] = rows[4], rows[3]
        with self.assertRaises((ValueError, OSError)):
            evidence.wire_index(self.root, self.index(rows))

    def test_one_outstanding_request_preserves_the_recorded_causal_order(self):
        rows = self.conversation()
        request, response = copy.deepcopy(rows[-2:])
        request[1]["id"] = response[1]["id"] = 3
        concurrent = rows[:-1] + [request, rows[-1], response]
        with self.assertRaises((ValueError, OSError)):
            evidence.wire_index(self.root, self.index(concurrent))
        sequential = evidence.wire_index(self.root, self.index(rows + [request, response]))
        self.assertEqual(list(sequential["sent"]), [1, 2, 3])

    def test_requests_cannot_precede_or_repeat_the_handshake(self):
        rows = self.conversation()
        cases = [rows[:2] + rows[3:] + rows[2:3], rows + [
            ("sent", {**rows[0][1], "id": 3}), ("received", {**rows[1][1], "id": 3})]]
        for changed in cases:
            with self.subTest(frame_count=len(changed)), self.assertRaises((ValueError, OSError)):
                evidence.wire_index(self.root, self.index(changed))

    def test_boolean_and_string_request_ids_are_not_integer_identities(self):
        for identifier in (True, "2", None):
            rows = self.conversation()
            rows[3][1]["id"] = rows[4][1]["id"] = identifier
            with self.subTest(identifier=identifier), self.assertRaises((ValueError, OSError)):
                evidence.wire_index(self.root, self.index(rows))

    def test_wire_direction_and_timestamp_are_not_handwritten_pass_flags(self):
        def mutation(field, value):
            return lambda number, entry: entry.update({field: value}) if number == 4 else None
        for field, value in (("direction", "ignored"), ("monotonic_ns", True),
                             ("monotonic_ns", 999), ("encoding", "gzip-original-bytes")):
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, OSError)):
                evidence.wire_index(self.root, self.index(self.conversation(), mutation(field, value)))

    def test_first_monotonic_time_cannot_be_negative(self):
        def change_first(number, entry):
            if number == 0:
                entry["monotonic_ns"] = -1
        with self.assertRaises((ValueError, OSError)):
            evidence.wire_index(self.root, self.index(self.conversation(), change_first))

    def test_full_index_cannot_silently_drop_unreviewed_notifications(self):
        additions = (
            ("sent", {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}}),
            ("received", {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}),
            ("received", {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        )
        for direction, notification in additions:
            rows = self.conversation() + [(direction, notification)]
            with self.subTest(method=notification["method"], direction=direction), self.assertRaises((ValueError, OSError)):
                evidence.wire_index(self.root, self.index(rows))

    def test_original_jsonrpc_line_requires_one_utf8_object_and_lf(self):
        base = json_line(self.conversation()[-1][1])
        invalid = (base[:-1], base + base, b'{"jsonrpc":"2.0","id":2,"id":2,"result":{}}\n',
                   b'{"jsonrpc":"2.0","id":2,"result":{"number":NaN}}\n',
                   b'{"jsonrpc":"2.0","id":2,"result":"\xff"}\n')
        for index, raw in enumerate(invalid):
            rows = self.conversation()
            rows[-1] = ("received", raw)
            with self.subTest(index=index), self.assertRaises((ValueError, OSError)):
                evidence.wire_index(self.root, self.index(rows))

    def test_rpc_result_and_error_cannot_both_claim_one_response(self):
        rows = self.conversation()
        rows[-1][1]["error"] = {"code": -32603, "message": "hidden failure"}
        with self.assertRaises((ValueError, OSError)):
            evidence.wire_index(self.root, self.index(rows))

    def test_wire_frame_path_is_relative_to_its_index_owner(self):
        reference = self.index(self.conversation())
        raw = (self.root / reference["path"]).read_bytes()
        entries = [json.loads(line) for line in raw.splitlines()]
        entries[-1]["path"] = "../" + entries[-1]["path"]
        # The index itself is correctly re-pinned; the invalid inner frame path
        # must still be rejected instead of being resolved outside its owner.
        changed = self.plain(b"".join(json_line(entry) for entry in entries), "owner/wire.jsonl")
        with self.assertRaises((ValueError, OSError)):
            evidence.wire_index(self.root, changed)


class SessionBindingTests(ArtifactFixture, unittest.TestCase):
    def session_fixture(self, *, calls=1, protocol="2026-07-28"):
        prefix = "native-producer"
        tools = [{"name": alias, "inputSchema": {"type": "object"}, "outputSchema": {"type": "object"},
                  "annotations": {"readOnlyHint": True}} for alias in evidence.profile.ALIASES.values()]
        initialize = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2026-07-28"}}
        frames = [("sent", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": protocol, "capabilities": {}, "clientInfo": {"name": "hepta-rea-operation-qualification", "version": "1"}}}),
            ("received", initialize),
            ("sent", {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
            ("sent", {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            ("received", {"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}})]
        bodies = []
        for index in range(calls):
            identifier = index + 3
            arguments = {"limit": 1}
            response = {"jsonrpc": "2.0", "id": identifier, "result": {
                "content": [{"type": "text", "text": '{"error":{"code":"invalid_request"}}'}], "isError": True}}
            frames.extend([("sent", {"jsonrpc": "2.0", "id": identifier, "method": "tools/call", "params": {
                "name": "rea_get_evidence_bundle", "arguments": arguments}}), ("received", response)])
            bodies.append({"id": "case-" + str(index), "operation": "get_evidence_bundle", "arguments": arguments,
                           "response": response, "response_bytes": len(json_line(response)),
                           "response_sha256": digest(json_line(response)), "seconds": 0.01})
        entries, references = [], {}
        for index, (direction, value) in enumerate(frames):
            name = f"wire-{index:03d}.json.gz"
            reference = self.zipped(json_line(value), prefix + "/" + name, "gzip-original-jsonrpc-line")
            complete = {**reference, "direction": direction, "monotonic_ns": index + 1}
            entries.append({**complete, "path": name})
            if "id" in value:
                references[(direction, value["id"])] = complete
        owner = {"pid": 41, "parent_pid": 40, "process_group": 41, "start_time_ticks": 100}
        close = {"owner": owner, "returncode": 0, "forced_cleanup": [], "reader_stopped": True,
                 "owner_pidfd_exited": True, "process_group_gone": True, "elapsed_seconds": 0.1}
        launch = {"argv": ["/native", "mcp", "--runtime-config", "/recorded/runtime.json"],
                  "cwd": "/recorded/workspace", "environment": {}, "pid": 41, "owner": owner}
        state = {"rows": [], "exports": {}, "close": close, "status": "PASS",
                 "contracts": {name: {field: tools[index][field] for field in ("inputSchema", "outputSchema", "annotations")}
                               for index, name in enumerate(evidence.profile.ALIASES)}}
        for field, filename, value in (("initialize", "initialize.json", initialize), ("tools", "tools.json", tools),
                                        ("launch", "launch.json", launch), ("close_artifact", "close.json", close)):
            state[field] = self.plain(json_line(value), prefix + "/" + filename)
        state["stderr"] = self.plain(b"", prefix + "/stderr.log")
        state["wire_index"] = self.plain(b"".join(json_line(entry) for entry in entries), prefix + "/wire.jsonl")
        for index, row in enumerate(bodies):
            state["rows"].append({"id": row["id"], "operation": row["operation"],
                "artifact": self.zipped(json_line(row), prefix + f"/case-{index}.json.gz"),
                "request_wire": references[("sent", row["response"]["id"])],
                "response_wire": references[("received", row["response"]["id"])]})
        return state, bodies

    def replay(self, state):
        return evidence.ReplaySession(self.root, "native", "producer", state,
                                      {"binary_before": {"path": "/native"}}, Path("/recorded/workspace"))

    def test_rows_are_read_from_the_complete_bound_wire(self):
        state, _ = self.session_fixture()
        replay = self.replay(state)
        response = replay.call("case-0", "get_evidence_bundle", {"limit": 1})
        self.assertIs(response, replay.wire["received"][3])
        replay.finish()

    def test_rehashing_row_text_or_arguments_does_not_override_original_wire(self):
        state, rows = self.session_fixture()
        original = copy.deepcopy(state)
        for kind in ("text", "boolean"):
            changed = copy.deepcopy(rows[0])
            if kind == "text":
                changed["response"]["result"]["content"][0]["text"] = '{ "error": { "code": "invalid_request" } }'
            else:
                changed["arguments"]["limit"] = True
            state = copy.deepcopy(original)
            state["rows"][0]["artifact"] = self.zipped(json_line(changed), "native-producer/changed.json.gz")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.replay(state)

    def test_missing_duplicate_or_reordered_rows_cannot_hide_index_calls(self):
        state, _ = self.session_fixture(calls=2)
        for rows in (state["rows"][:1], [state["rows"][0], state["rows"][0]], list(reversed(state["rows"]))):
            changed = {**state, "rows": rows}
            with self.subTest(rows=[row["id"] for row in rows]), self.assertRaises(ValueError):
                self.replay(changed)

    def test_expected_sequence_and_argument_kinds_are_checked_again(self):
        state, _ = self.session_fixture()
        for name, args in (("invented", {"limit": 1}), ("case-0", {"limit": True})):
            with self.subTest(name=name, arguments=args), self.assertRaises(ValueError):
                self.replay(state).call(name, "get_evidence_bundle", args)
        with self.assertRaises(ValueError):
            self.replay(state).finish()

    def test_initialize_input_is_the_reviewed_protocol_not_only_a_bound_response(self):
        state, _ = self.session_fixture(protocol="invented-protocol")
        with self.assertRaises(ValueError):
            self.replay(state)

    def test_close_summary_and_original_close_are_both_required(self):
        state, _ = self.session_fixture()
        summary_only = copy.deepcopy(state)
        summary_only["close"]["forced_cleanup"] = ["SIGTERM"]
        with self.assertRaises(ValueError):
            self.replay(summary_only)
        for field, value in (("returncode", False), ("forced_cleanup", ["SIGKILL"]),
                             ("reader_stopped", 1), ("owner_pidfd_exited", False), ("process_group_gone", False)):
            changed = copy.deepcopy(state)
            changed["close"][field] = value
            changed["close_artifact"] = self.plain(json_line(changed["close"]), "native-producer/close.json")
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.replay(changed)


class CanonicalExportTests(ArtifactFixture, unittest.TestCase):
    def export_fixture(self, raw=None, mutate_receipt=None):
        bundle = {key: [] for key in evidence.profile.BUNDLE_KEYS}
        if raw is None:
            raw = evidence.profile.canonical_json(bundle)
        entry = {"file": {"path": "/recorded/export.json", "bytes": len(raw), "sha256": digest(raw)},
                 "artifact": self.zipped(raw, "owner/export.json.gz")}
        result = {"path": "/recorded/export.json", "bytes": len(raw), "records": 0, "unknowns": 0}
        if mutate_receipt:
            mutate_receipt(result)
        body = {"result": result}
        response = {"jsonrpc": "2.0", "id": 3, "result": {
            "content": [{"type": "text", "text": json.dumps(body)}], "structuredContent": body}}
        replay = evidence.ReplaySession.__new__(evidence.ReplaySession)
        replay.root, replay.exports, replay.state = self.root, {}, {"exports": {"export": entry}}
        replay.call = mock.Mock(return_value=response)
        return replay, bundle, raw

    def test_full_export_is_compared_as_canonical_bytes(self):
        replay, bundle, raw = self.export_fixture()
        result = replay.export("export", Path("/recorded/export.json"), [], raw)
        self.assertEqual(result, (raw, bundle))
        replay.call.assert_called_once_with("export", "export_evidence_bundle", {
            "path": "/recorded/export.json", "overwrite": True})

    def test_rehashed_json_whitespace_cannot_become_an_exact_export_match(self):
        _, bundle, raw = self.export_fixture()
        for changed in (raw + b"\n", json.dumps(bundle, indent=2).encode()):
            replay, _, _ = self.export_fixture(changed)
            with self.subTest(bytes=len(changed)), self.assertRaises(ValueError):
                replay.export("export", Path("/recorded/export.json"), [])

    def test_export_wire_count_and_byte_types_are_exact(self):
        for field, value in (("bytes", 1), ("records", False), ("unknowns", False),
                             ("path", "/recorded/other.json")):
            replay, _, _ = self.export_fixture(mutate_receipt=lambda result: result.update({field: value}))
            with self.subTest(field=field), self.assertRaises(ValueError):
                replay.export("export", Path("/recorded/export.json"), [])

    def test_export_must_equal_the_selected_original_bytes_and_full_manifests(self):
        replay, bundle, raw = self.export_fixture()
        with self.assertRaises(ValueError):
            replay.export("export", Path("/recorded/export.json"), [], raw + b"\n")
        changed = copy.deepcopy(bundle)
        del changed["providers"]
        replay, _, _ = self.export_fixture(evidence.profile.canonical_json(changed))
        with self.assertRaises(ValueError):
            replay.export("export", Path("/recorded/export.json"), [])


class OwnerAndSourceTests(ArtifactFixture, unittest.TestCase):
    def test_eight_fresh_owners_and_ordered_wire_intervals_are_required(self):
        sessions = {key: SimpleNamespace(close={"owner": {"pid": index + 100, "start_time_ticks": index + 200}},
                    wire={"first_ns": index * 10, "last_ns": index * 10 + 9})
                    for index, key in enumerate(evidence.SESSION_ORDER)}
        self.assertEqual(evidence.verify_owner_set(sessions), 8)
        last = evidence.SESSION_ORDER[-1]
        changed = copy.deepcopy(sessions)
        changed[last].close = changed[evidence.SESSION_ORDER[0]].close
        with self.assertRaises(ValueError):
            evidence.verify_owner_set(changed)
        changed = copy.deepcopy(sessions)
        changed[last].wire["first_ns"] = changed[evidence.SESSION_ORDER[-2]].wire["last_ns"]
        with self.assertRaises(ValueError):
            evidence.verify_owner_set(changed)

    def source_fixture(self):
        source = {"files": [], "tree_sha256": evidence.q.digest([])}
        report = {"node_version": "v22.23.4", "build_binding": {"qualified": True}}
        for name in ("binary", "node", "real_input"):
            identity = {"path": "/" + name, "bytes": 100, "sha256": evidence.profile.NODE_SHA256 if name == "node" else "1" * 64}
            report[name + "_before"] = identity
            report[name + "_after"] = copy.deepcopy(identity)
        report["reference_before"] = {"name": "rea-agents", "version": "6.8.0", "file_count": 2398,
            "tarball_sha256": evidence.q.PACKAGE_SHA256, "files_sha256": evidence.q.PACKAGE_FILES_SHA256,
            "catalog_sha256": evidence.q.CATALOG_SHA256, "git_source_commit": evidence.q.REFERENCE_COMMIT,
            "package_root": "/frozen/package"}
        report["reference_after"] = copy.deepcopy(report["reference_before"])
        for name in ("source_before", "source_after"):
            report[name] = self.plain(json_line(source), name + ".json")
        events = {"event_count": 0, "retained_events": [], "events_truncated": False, "errors": []}
        report["source_events"] = self.plain(json_line(events), "events.json")
        return source, report, events

    def test_handwritten_build_binding_is_not_original_build_evidence(self):
        source, report, _ = self.source_fixture()
        with mock.patch.object(evidence.Selection, "snapshot", return_value=source):
            observed, binding = evidence.verify_identity_and_source(self.root, self.root, report)
        self.assertEqual(observed, source)
        self.assertIsNone(binding)
        report["build_evidence"] = {"status": "PASS", "qualified": True}
        with mock.patch.object(evidence.Selection, "snapshot", return_value=source), self.assertRaises(ValueError):
            evidence.verify_identity_and_source(self.root, self.root, report)

    def test_source_mutation_monitor_loss_and_runtime_type_changes_are_refused(self):
        source, report, events = self.source_fixture()
        for field, value in (("event_count", False), ("event_count", 1), ("events_truncated", True), ("errors", ["lost"])):
            changed = copy.deepcopy(report)
            changed["source_events"] = self.plain(json_line({**events, field: value}), "events.json")
            with self.subTest(field=field), mock.patch.object(evidence.Selection, "snapshot", return_value=source), self.assertRaises(ValueError):
                evidence.verify_identity_and_source(self.root, self.root, changed)
        report["source_events"] = self.plain(json_line(events), "events.json")
        with mock.patch.object(evidence.Selection, "snapshot", return_value={"different": True}), self.assertRaises(ValueError):
            evidence.verify_identity_and_source(self.root, self.root, report)
        report["node_after"]["bytes"] = True
        with mock.patch.object(evidence.Selection, "snapshot", return_value=source), self.assertRaises(ValueError):
            evidence.verify_identity_and_source(self.root, self.root, report)


if __name__ == "__main__":
    unittest.main()
