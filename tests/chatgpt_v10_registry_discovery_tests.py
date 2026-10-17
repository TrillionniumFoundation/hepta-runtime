#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bounded dual-registry discovery; private fixtures and mocked read RPCs only."""
import copy
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import chatgpt_v10_dual_read as D
from mcp_tool_contract import ToolContract


class RegistryDiscovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-dual-registry-")
        self.addCleanup(self.temp.cleanup)
        base = pathlib.Path(self.temp.name)
        self.roots = {"legacy": base / "v4", "native": base / "v10"}
        for root in self.roots.values():
            root.mkdir(mode=0o700)
            for kind in ("jobs", "terminals"):
                (root / kind).mkdir(mode=0o700)
        c4 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json",
            "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1")
        c10 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v10.json",
            "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553")
        self.proxy = D.DualReadNativeProxy("http://127.0.0.1:8791/mcp", "fake", c10,
            "http://127.0.0.1:8790/mcp", "fake", c4,
            self.roots["legacy"], self.roots["native"], route_original_effects=True)
        self.proxy.legacy_ready = True
        self.rows = {backend: {name: [] for name in D.REGISTRY_LIST_NAMES}
                     for backend in self.roots}
        self.calls = []
        self.alter = {}
        self.proxy._original = lambda request, context, era, *, mutating: self.reply(
            "legacy", request, mutating)
        test = self
        patcher = mock.patch.object(D.NativeProxy, "_dispatch",
            lambda proxy, request, context=None: test.reply("native", request, False))
        patcher.start()
        self.addCleanup(patcher.stop)

    def add(self, backend, name, number, host="main", **extra):
        key = "id" if name == "process_list" else "session_id"
        identity = f"{number:x}-b2f-{number:x}" if key == "id" else f"dpty-{number:08x}"
        row = {key: identity, "host": host, **extra}
        self.rows[backend][name].append(row)
        record = self.roots[backend] / ("jobs" if key == "id" else "terminals") / (identity + ".json")
        record.write_text(json.dumps({key: identity, "host": host}))
        record.chmod(0o600)
        return row

    @staticmethod
    def request(name="process_list", arguments=None, modern=False):
        value = {"jsonrpc": "2.0", "id": "inventory", "method": "tools/call",
                 "params": {"name": name, "arguments": arguments or {}}}
        if modern:
            value["params"]["_meta"] = {
                "io.modelcontextprotocol/protocolVersion": D.MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}}
        return value

    def reply(self, backend, request, mutating):
        self.assertFalse(mutating, "discovery may never create a backend effect")
        name = request["params"]["name"]
        arguments = request["params"].get("arguments", {})
        self.calls.append((backend, name, copy.deepcopy(arguments)))
        rows = copy.deepcopy(self.rows[backend][name])
        if arguments.get("host") is not None:
            rows = [row for row in rows if row["host"] == arguments["host"]]
        if name == "process_list":
            payload = {"jobs": rows, "total": len(rows), "inventory_complete": True,
                       "status_authoritative": False, "native_extension": {"backend": backend}}
        else:
            rows.sort(key=lambda row: row["session_id"])
            after = arguments.get("after_session_id")
            rows = [row for row in rows if after is None or row["session_id"] > after]
            limit = arguments.get("limit", 128)
            page, more = rows[:limit], len(rows) > limit
            payload = {"sessions": page, "has_more": more,
                       "next_after_session_id": page[-1]["session_id"] if more else None,
                       "native_extension": {"backend": backend}}
        if (backend, name) in self.alter:
            replacement = self.alter[backend, name](payload, arguments)
            if replacement is not None:
                return replacement
        return {"jsonrpc": "2.0", "id": request["id"], "result": {
            "content": [{"type": "text", "text": json.dumps(payload), "annotations": {"priority": 0.5}}],
            "isError": False, "_meta": {"native_backend": backend}}}

    def payload(self, response):
        self.assertNotIn("error", response)
        return json.loads(response["result"]["content"][0]["text"])

    def unavailable(self, name="process_list", arguments=None):
        response = self.proxy._dispatch(self.request(name, arguments))
        self.assertEqual(response["error"]["data"]["outcome"], "unavailable")
        self.assertFalse(response["error"]["data"]["partial_inventory_returned"])
        self.assertFalse(response["error"]["data"]["automatic_retry"])
        self.assertNotIn("result", response)

    def test_original_and_candidate_jobs_are_both_discoverable_without_row_projection(self):
        old = self.add("legacy", "process_list", 3, executable="/original", args=["private value"],
                       launch_state="launched", future_field={"nested": [1, 2]})
        new = self.add("native", "process_list", 1, execution_mode="operator", created_unix_ms=123)
        payload = self.payload(self.proxy._dispatch(self.request()))
        self.assertEqual(payload["jobs"], [new, old])
        self.assertEqual(payload["total"], 2)
        self.assertTrue(payload["inventory_complete"])
        self.assertFalse(payload["status_authoritative"])
        provenance = payload["dual_controller_inventory"]
        self.assertFalse(provenance["effect_owner_changed"])
        self.assertIn("not_global_freeze", provenance["semantics"])
        for backend, field in (("legacy", "original_v4"), ("native", "native_v10")):
            self.assertEqual(provenance[field][0]["payload"]["native_extension"], {"backend": backend})
            self.assertEqual(provenance[field][0]["result"]["_meta"], {"native_backend": backend})
            self.assertEqual(provenance[field][0]["content"]["annotations"], {"priority": 0.5})

    def test_unfiltered_jobs_use_each_fixed_host_instead_of_oversize_all_host_rpc(self):
        self.payload(self.proxy._dispatch(self.request()))
        self.assertEqual(len(self.calls), 12)
        for backend in self.roots:
            hosts = [args["host"] for owner, _, args in self.calls if owner == backend]
            self.assertEqual(hosts, sorted(D.HOSTS))

    def test_host_filter_is_preserved_for_both_sources(self):
        visible = self.add("legacy", "process_list", 1, host="rog")
        self.add("native", "process_list", 2, host="main")
        payload = self.payload(self.proxy._dispatch(self.request(arguments={"host": "rog"})))
        self.assertEqual(payload["jobs"], [visible])
        self.assertEqual(self.calls, [(b, "process_list", {"host": "rog"}) for b in self.roots])

    def test_pty_full_backend_pagination_and_independent_union_cursor(self):
        for number in range(1, 131):
            self.add("legacy", "pty_list", number, status={"state": "inspect_with_pty_read"})
        new = self.add("native", "pty_list", 131, pid=42, extra_native_field="retained")
        request = self.request("pty_list", {"after_session_id": "dpty-00000080", "limit": 2})
        payload = self.payload(self.proxy._dispatch(request))
        self.assertEqual([r["session_id"] for r in payload["sessions"]], ["dpty-00000081", "dpty-00000082"])
        self.assertTrue(payload["has_more"])
        self.assertEqual(payload["next_after_session_id"], "dpty-00000082")
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.calls[0][2], {"limit": 128})
        self.assertEqual(self.calls[1][2], {"limit": 128, "after_session_id": "dpty-00000080"})
        payload = self.payload(self.proxy._dispatch(self.request("pty_list", {
            "after_session_id": payload["next_after_session_id"], "limit": 2})))
        self.assertEqual(payload["sessions"], [new])
        self.assertFalse(payload["has_more"])
        self.assertIsNone(payload["next_after_session_id"])

    def test_modern_result_retains_transport_metadata(self):
        result = self.proxy._dispatch(self.request(modern=True))
        self.payload(result)
        self.assertEqual(result["result"]["resultType"], "complete")
        self.assertIn("io.modelcontextprotocol/serverInfo", result["result"]["_meta"])

    def test_missing_lazy_candidate_terminals_keeps_original_discovery(self):
        row = self.add("legacy", "pty_list", 1)
        (self.roots["native"] / "terminals").rmdir()
        payload = self.payload(self.proxy._dispatch(self.request("pty_list")))
        self.assertEqual(payload["sessions"], [row])

    def test_missing_lazy_original_terminals_keeps_candidate_discovery(self):
        row = self.add("native", "pty_list", 1)
        (self.roots["legacy"] / "terminals").rmdir()
        payload = self.payload(self.proxy._dispatch(self.request("pty_list")))
        self.assertEqual(payload["sessions"], [row])

    def test_lazy_terminal_directory_appearing_during_collection_refuses(self):
        directory = self.roots["native"] / "terminals"
        directory.rmdir()
        def appeared(payload, arguments):
            directory.mkdir(mode=0o700)
        self.alter["native", "pty_list"] = appeared
        self.unavailable("pty_list")

    def test_missing_jobs_directory_is_not_silently_empty(self):
        (self.roots["native"] / "jobs").rmdir()
        self.unavailable()

    def test_legacy_must_initialize_before_any_list_rpc(self):
        self.proxy.legacy_ready = False
        result = self.proxy._dispatch(self.request())
        self.assertEqual(result["error"]["code"], -32071)
        self.assertFalse(self.calls)

    def test_default_route_is_unchanged(self):
        self.proxy.route_original_effects = False
        native = self.add("native", "process_list", 1)
        self.add("legacy", "process_list", 2)
        payload = self.payload(self.proxy._dispatch(self.request()))
        self.assertEqual(payload["jobs"], [native])
        self.assertEqual(self.calls, [("native", "process_list", {})])

    def test_duplicate_identity_between_backends_refuses_even_if_rows_match(self):
        for backend in self.roots:
            self.add(backend, "process_list", 1)
        self.unavailable()

    def test_duplicate_within_one_backend_refuses(self):
        row = self.add("legacy", "process_list", 1)
        self.rows["legacy"]["process_list"].append(copy.deepcopy(row))
        self.unavailable()

    def test_missing_native_owner_record_cannot_be_fabricated_by_list(self):
        row = self.add("native", "process_list", 1)
        (self.roots["native"] / "jobs" / (row["id"] + ".json")).unlink()
        self.unavailable()

    def test_legal_large_launch_record_does_not_block_an_unrelated_host_filter(self):
        large = self.add("legacy", "process_list", 1, host="main")
        record = self.roots["legacy"] / "jobs" / (large["id"] + ".json")
        record.write_text(json.dumps({**large, "args": ["x" * (70 * 1024)]}))
        visible = self.add("native", "process_list", 2, host="rog")
        payload = self.payload(self.proxy._dispatch(self.request(arguments={"host": "rog"})))
        self.assertEqual(payload["jobs"], [visible])

    def test_legal_large_launch_record_remains_discoverable_and_directly_routable(self):
        for backend in self.roots:
            row = self.add(backend, "process_list", 1 if backend == "legacy" else 2)
            record = self.roots[backend] / "jobs" / (row["id"] + ".json")
            record.write_text(json.dumps({**row, "args": ["x" * (70 * 1024)]}))
            self.assertGreater(record.stat().st_size, 65536)
            self.assertEqual(self.proxy.provenance.route("process_status", {
                "host": "main", "job_id": row["id"]}), backend)
        payload = self.payload(self.proxy._dispatch(self.request(arguments={"host": "main"})))
        self.assertEqual(len(payload["jobs"]), 2)

    def test_direct_lookup_above_native_request_and_wrapper_bound_still_refuses(self):
        row = self.add("legacy", "process_list", 1)
        path = self.roots["legacy"] / "jobs" / (row["id"] + ".json")
        path.write_bytes(b"x" * (D.MAX_METADATA + 1))
        with self.assertRaisesRegex(D.UnsafeProvenance, "owner_record_shape"):
            self.proxy.provenance.route("process_status", {"host": "main", "job_id": row["id"]})
        self.unavailable(arguments={"host": "rog"})

    def test_changed_owner_or_host_refuses(self):
        row = self.add("legacy", "process_list", 1)
        path = self.roots["legacy"] / "jobs" / (row["id"] + ".json")
        path.write_text(json.dumps({"id": row["id"], "host": "rog"}))
        self.unavailable()

    def test_partial_flags_and_incorrect_total_refuse_whole_inventory(self):
        for field, value in (("inventory_complete", False), ("partial", True),
                             ("truncated", True), ("has_more", True), ("total", 1)):
            with self.subTest(field=field):
                self.alter["legacy", "process_list"] = lambda p, a, f=field, v=value: p.update({f: v})
                self.unavailable()

    def test_v4_legacy_complete_shape_without_new_flags_is_supported(self):
        def original_shape(payload, arguments):
            payload.pop("inventory_complete")
            payload.pop("status_authoritative")
            payload.pop("total")
        self.alter["legacy", "process_list"] = original_shape
        self.payload(self.proxy._dispatch(self.request()))

    def test_missing_row_even_without_native_total_is_detected_independently(self):
        self.add("legacy", "process_list", 1)
        def incomplete(payload, arguments):
            payload.pop("total")
            payload["jobs"] = []
        self.alter["legacy", "process_list"] = incomplete
        self.unavailable()

    def test_membership_change_during_native_collection_refuses(self):
        added = []
        def changed(payload, arguments):
            if not added:
                added.append(self.add("native", "process_list", 1))
        self.alter["native", "process_list"] = changed
        self.unavailable()

    def test_uncommitted_writer_temporary_is_retained_and_not_opened_as_job(self):
        temporary = self.roots["legacy"] / "jobs" / "owned.json.tmp.123"
        temporary.write_text("not a committed job")
        self.payload(self.proxy._dispatch(self.request()))
        self.assertEqual(temporary.read_text(), "not a committed job")

    def test_backend_failure_never_returns_other_backend_rows(self):
        self.add("legacy", "process_list", 1)
        self.alter["native", "process_list"] = lambda p, a: {
            "jsonrpc": "2.0", "id": "inventory", "error": {"code": -32603, "message": "private detail"}}
        self.unavailable()

    def test_tool_error_and_nontext_result_are_not_silently_ignored(self):
        for result in ({"content": [{"type": "text", "text": "private detail"}], "isError": True},
                       {"content": [{"type": "image", "data": "private bytes"}]}):
            self.alter["legacy", "process_list"] = lambda p, a, r=result: {
                "jsonrpc": "2.0", "id": "inventory", "result": r}
            self.unavailable()

    def test_pty_out_of_order_and_nonadvancing_cursor_refuse(self):
        self.add("legacy", "pty_list", 1)
        self.add("legacy", "pty_list", 2)
        def reverse(payload, arguments):
            payload["sessions"].reverse()
        self.alter["legacy", "pty_list"] = reverse
        self.unavailable("pty_list")
        self.alter["legacy", "pty_list"] = lambda p, a: p.update({
            "has_more": True, "next_after_session_id": "dpty-00000000"})
        self.unavailable("pty_list")

    def test_pty_empty_nonterminal_page_and_invalid_terminal_cursor_refuse(self):
        for more, cursor in ((True, "dpty-00000001"), (False, "dpty-00000001")):
            self.alter["legacy", "pty_list"] = lambda p, a, m=more, c=cursor: p.update({
                "has_more": m, "next_after_session_id": c})
            self.unavailable("pty_list")

    def test_pty_page_and_union_row_bounds_never_truncate(self):
        for number in range(1, 130):
            self.add("legacy", "pty_list", number)
        with mock.patch.object(D, "MAX_DISCOVERY_PAGES", 1):
            self.unavailable("pty_list")
        with mock.patch.object(D, "MAX_DISCOVERY_ROWS", 128):
            self.unavailable("pty_list")

    def test_wire_bound_is_an_explicit_failure(self):
        self.add("legacy", "process_list", 1, large_extra="x" * 1000)
        with mock.patch.object(D, "MAX_RESPONSE", 512):
            self.unavailable()

    def test_final_union_wire_bound_is_also_explicit_without_partial_rows(self):
        self.add("legacy", "process_list", 1, host="rog", extra="x" * 2000)
        self.add("native", "process_list", 2, host="rog", extra="y" * 2000)
        with mock.patch.object(D, "MAX_RESPONSE", 4000):
            self.unavailable(arguments={"host": "rog"})

    def test_wrong_host_from_backend_and_malformed_rows_refuse(self):
        for row in ({"id": "1-b2f-1", "host": "rog"},
                    {"id": "../bad", "host": "main"}, {"id": "1-b2f-1", "host": []}):
            self.alter["legacy", "process_list"] = lambda p, a, r=row: p.update({"jobs": [r], "total": 1})
            self.unavailable(arguments={"host": "main"})

    def test_invalid_arguments_do_not_dispatch_or_silently_drop_unknown_keys(self):
        for name, arguments in (("process_list", {"host": []}),
                                ("process_list", {"unexpected": True}),
                                ("pty_list", {"limit": True}),
                                ("pty_list", {"limit": -1}),
                                ("pty_list", {"after_session_id": 1})):
            result = self.proxy._dispatch(self.request(name, arguments))
            self.assertEqual(result["error"]["data"]["outcome"], "not_submitted")
        self.assertFalse(self.calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
