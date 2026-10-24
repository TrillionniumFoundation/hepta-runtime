#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Explicit typed-read workflow opt-in; offline fixtures, never production effects."""
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
from mcp_tool_contract import ToolContract, make_contract

ID = "a" * 64
OLD_JOB = "1a13acafe00-b2f-134a"
NEW_JOB = "1a13acafe00-b2f-134b"


class ReadWorkflowRouting(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-read-workflows-")
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.old, self.new = self.base / "v4", self.base / "v10"
        for root in (self.old, self.new):
            root.mkdir(mode=0o700)
            (root / "jobs").mkdir(mode=0o700)
            (root / "terminals").mkdir(mode=0o700)
        self.c4 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json",
                                   "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1")
        self.c10 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v10.json",
                                    "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553")
        self.native, self.original = [], []
        self.native_response = None
        self.actual_native_dispatch = D.NativeProxy._dispatch
        patcher = mock.patch.object(D.NativeProxy, "_dispatch", self.native_dispatch)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.proxy = self.adapter()
        self.record(self.old, OLD_JOB)
        self.record(self.new, NEW_JOB)

    def adapter(self, *, original=True, workflows=True, contract=None):
        proxy = D.DualReadNativeProxy("http://127.0.0.1:8791/mcp", "fake-new-private-token", contract or self.c10,
                                      "http://127.0.0.1:8790/mcp", "fake-original-private-token", self.c4,
                                      self.old, self.new, route_original_effects=original,
                                      route_v10_read_workflows=workflows)
        proxy.legacy_ready = True
        def original_dispatch(request, context, era, *, mutating):
            self.original.append((copy.deepcopy(request), mutating))
            return {"jsonrpc": "2.0", "id": request["id"], "result": {"owner": "original-v4"}}
        proxy._original = original_dispatch
        return proxy

    def native_dispatch(self, request, context=None):
        self.native.append(copy.deepcopy(request))
        if self.native_response is not None:
            return copy.deepcopy(self.native_response)
        return {"jsonrpc": "2.0", "id": request["id"], "result": {"owner": "native-v10"}}

    @staticmethod
    def record(root, identity, host="main"):
        path = root / "jobs" / (identity + ".json")
        path.write_text(json.dumps({"id": identity, "host": host}))
        path.chmod(0o600)
        return path

    @staticmethod
    def request(name, arguments, modern=False):
        request = {"jsonrpc": "2.0", "id": "offline-" + name, "method": "tools/call",
                   "params": {"name": name, "arguments": arguments}}
        if modern:
            request["params"]["_meta"] = {"io.modelcontextprotocol/protocolVersion": D.MODERN_VERSION,
                                            "io.modelcontextprotocol/clientCapabilities": {}}
        return request

    @staticmethod
    def start(tool="file_info", arguments=None, *, key="same-private-key"):
        return {"operation": {"tool": tool, "arguments": arguments if arguments is not None else
                               {"host": "main", "path": "/private-fixture"}}, "idempotency_key": key}

    def examples(self):
        return {"operation_start": self.start(), "operation_cancel": {"operation_id": ID},
                "request_start": self.start("host_list", {}), "request_cancel": {"request_id": ID},
                "search_start": {"host": "main", "root": "/private-fixture", "query": "needle", "kind": "files"},
                "search_stop": {"search_id": ID}}

    def refused(self, name, arguments, *, reason=None):
        before_native, before_original = len(self.native), len(self.original)
        result = self.proxy._dispatch(self.request(name, arguments))
        self.assertIn("error", result)
        details = result["error"]["data"]
        self.assertEqual(details["outcome"], "not_submitted")
        self.assertFalse(details["automatic_retry"])
        self.assertFalse(details["original_request_replayed"])
        if reason is not None:
            self.assertEqual(details["reason"], reason)
        self.assertEqual(len(self.native), before_native)
        self.assertEqual(len(self.original), before_original)

    def test_default_workflow_flag_is_off_and_existing_effect_optin_does_not_enable_it(self):
        self.proxy = self.adapter(workflows=False)
        for name, arguments in self.examples().items():
            self.refused(name, arguments)
        self.assertEqual(len(self.c10.tools), 66)
        self.assertEqual(len(self.c4.tools), 50)

    def test_workflow_optin_requires_one_original_system_effect_owner(self):
        with self.assertRaisesRegex(D.UnsafeProvenance, "require_original_v4_effect_owner"):
            self.adapter(original=False)
        self.proxy.route_original_effects = False
        self.refused("operation_start", self.start())

    def test_cli_rejects_workflow_flag_without_original_effect_flag_before_loading_credentials(self):
        argv = ["adapter", "--stdio", "--upstream", "http://127.0.0.1:8791/mcp", "--token-file", "unused",
                "--contract", "unused", "--contract-sha256", "unused", "--legacy-upstream", "http://127.0.0.1:8790/mcp",
                "--legacy-token-file", "unused", "--legacy-contract", "unused", "--legacy-contract-sha256", "unused",
                "--legacy-state", str(self.old), "--new-state", str(self.new), "--acknowledge-full-operator",
                "--route-v10-read-workflows"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(D.ToolContract, "load") as load:
            with mock.patch.object(sys, "stderr"), self.assertRaises(SystemExit) as exited:
                D.main()
            self.assertEqual(exited.exception.code, 2)
            load.assert_not_called()

    def test_exact_six_names_forward_unchanged_to_original_native_handler(self):
        self.assertEqual(set(self.examples()), D.V10_READ_WORKFLOWS)
        for modern in (False, True):
            for name, arguments in self.examples().items():
                request = self.request(name, arguments, modern)
                result = self.proxy._dispatch(request)
                self.assertEqual(result["result"]["owner"], "native-v10")
                self.assertEqual(self.native[-1], request)
        self.assertEqual(len(self.native), 12)
        self.assertFalse(self.original)

    def test_native_request_and_operation_typed_read_arms_keep_their_exact_arguments(self):
        operations = {"read_multiple_files": {"host": "main", "paths": ["/fixture"]},
                      "file_info": {"host": "main", "path": "/fixture"},
                      "binary_read": {"host": "main", "path": "/fixture", "offset": 0, "limit": 8},
                      "process_status": {"host": "main", "job_id": NEW_JOB},
                      "process_read": {"host": "main", "job_id": NEW_JOB, "stdout_offset": 2, "stderr_offset": 3},
                      "process_wait": {"host": "main", "job_id": NEW_JOB, "timeout_seconds": 1},
                      "hardware_snapshot": {"host": "main"},
                      "service_status": {"host": "main", "services": ["fixture.service"]},
                      "network_inspect": {"host": "main"}}
        for tool, arguments in operations.items():
            request = self.request("operation_start", self.start(tool, arguments))
            self.assertEqual(self.proxy._dispatch(request)["result"]["owner"], "native-v10")
            self.assertEqual(self.native[-1], request)
        for tool, arguments in {"host_list": {}, "host_health": {"host": "main"}, "effective_config": {}}.items():
            self.proxy._dispatch(self.request("request_start", self.start(tool, arguments)))
            self.assertEqual(self.native[-1]["params"]["arguments"], self.start(tool, arguments))

    def test_all_original_31_effectful_names_stay_only_in_v4(self):
        self.proxy.provenance.route = lambda *_: "legacy"
        names = [tool["name"] for tool in self.c4.tools if not tool["annotations"]["readOnlyHint"]]
        self.assertEqual(len(names), 31)
        for name in names:
            result = self.proxy._dispatch(self.request(name, {"host": "main"}))
            self.assertEqual(result["result"]["owner"], "original-v4", name)
        self.assertEqual(len(self.original), 31)
        self.assertTrue(all(mutating for _, mutating in self.original))
        self.assertFalse(self.native)

    def test_new_future_effect_does_not_inherit_the_six_name_optin(self):
        tools = copy.deepcopy(self.c10.tools)
        extra = copy.deepcopy(self.c10.by_name["operation_start"])
        extra["name"] = "future_effect"
        self.proxy = self.adapter(contract=ToolContract(make_contract(tools + [extra])))
        self.refused("future_effect", {})

    def test_legacy_job_reads_refuse_before_workflow_admission(self):
        for name in ("process_status", "process_read", "process_wait"):
            self.refused("operation_start", self.start(name, {"host": "main", "job_id": OLD_JOB}),
                         reason="nested_job_not_owned_by_native_v10")

    def test_unknown_colliding_and_wrong_host_job_reads_refuse_before_admission(self):
        self.refused("operation_start", self.start("process_read", {"host": "main", "job_id": "1-2-3"}))
        self.record(self.old, NEW_JOB)
        self.refused("operation_start", self.start("process_status", {"host": "main", "job_id": NEW_JOB}))
        (self.old / "jobs" / (NEW_JOB + ".json")).unlink()
        self.refused("operation_start", self.start("process_wait", {"host": "rog", "job_id": NEW_JOB}))

    def test_direct_legacy_job_reads_still_use_original_v4(self):
        for name in ("process_status", "process_read", "process_wait"):
            result = self.proxy._dispatch(self.request(name, {"host": "main", "job_id": OLD_JOB}))
            self.assertEqual(result["result"]["owner"], "original-v4")
        self.assertEqual(len(self.original), 3)
        self.assertTrue(all(not mutating for _, mutating in self.original))
        self.assertFalse(self.native)

    def test_nested_process_list_always_refuses_even_if_old_registry_is_empty(self):
        (self.old / "jobs" / (OLD_JOB + ".json")).unlink()
        for arguments in ({}, {"host": "main"}, {"host": "rog"}, {"host": None}):
            self.refused("operation_start", self.start("process_list", arguments),
                         reason="nested_process_list_requires_shared_registry")

    def test_commands_writes_recursive_async_and_wrong_request_arms_are_not_dispatchable(self):
        for tool in ("process_start", "host_shell", "pty_write", "text_editor", "binary_upload", "operation_start",
                     "request_start", "search_start", "effective_config", "../../process_start", "PROCESS_STATUS", ""):
            self.refused("operation_start", self.start(tool, {}))
        for tool in ("process_status", "file_info", "request_start", "host_shell"):
            self.refused("request_start", self.start(tool, {}))

    def test_wrong_alias_wrapper_fields_unknown_top_level_and_inner_arguments_refuse(self):
        examples = [
            {"operation": {"name": "file_info", "params": {"host": "main", "path": "/fixture"}}, "idempotency_key": "k"},
            {"operation": {"tool": "file_info", "arguments": {}, "extra": True}, "idempotency_key": "k"},
            {**self.start(), "owner": ID}, {**self.start(), "command": "arbitrary"},
            self.start("file_info", {"host": "main", "path": "/fixture", "command": "arbitrary"}),
            self.start("file_info", {"host": "main"}),
        ]
        for arguments in examples:
            self.refused("operation_start", arguments)

    def test_malformed_scalar_container_and_array_arguments_refuse(self):
        for arguments in (self.start("file_info", []), self.start("file_info", {"host": [], "path": "/fixture"}),
                          self.start("file_info", {"host": "main", "path": {"exec": "arbitrary"}}),
                          self.start("read_multiple_files", {"host": "main", "paths": ["/fixture", 1]}),
                          self.start("process_wait", {"host": "main", "job_id": NEW_JOB, "timeout_seconds": True}),
                          {"operation": [], "idempotency_key": "key"}):
            self.refused("operation_start", arguments)

    def test_hosts_paths_and_job_identity_injection_do_not_choose_a_backend(self):
        for host in ("user@raw-target", "127.0.0.1", "../../main", "unconfigured"):
            self.refused("operation_start", self.start("file_info", {"host": host, "path": "/fixture"}))
        for identity in ("../../etc/passwd", "a" * 129, 42, "", "dpty-abc"):
            self.refused("operation_start", self.start("process_status", {"host": "main", "job_id": identity}))

    def test_private_key_utf8_byte_bound_and_control_characters_refuse(self):
        for key in ("", "a" * 129, "中" * 43, "key\n", "key\x00", "key\x85", None, 42):
            self.refused("request_start", self.start("host_list", {}, key=key))
        self.proxy._dispatch(self.request("request_start", self.start("host_list", {}, key="中" * 42)))
        self.assertEqual(len(self.native), 1)

    def test_oversized_request_refuses_without_forwarding_or_truncation(self):
        arguments = self.start("file_info", {"host": "main", "path": "/" + "x" * D.MAX_REQUEST})
        self.refused("operation_start", arguments, reason="read_workflow_request_bound")

    def test_job_symlink_hardlink_bad_mode_and_duplicate_json_refuse(self):
        path = self.new / "jobs" / (NEW_JOB + ".json")
        raw = path.read_bytes()
        target = self.base / "target-record.json"
        for shape in ("symlink", "hardlink", "group-readable", "duplicate-json"):
            with self.subTest(shape=shape):
                path.unlink()
                target.write_bytes(raw)
                target.chmod(0o600)
                if shape == "symlink":
                    path.symlink_to(target)
                elif shape == "hardlink":
                    path.hardlink_to(target)
                else:
                    path.write_bytes(raw)
                    path.chmod(0o640 if shape == "group-readable" else 0o600)
                    if shape == "duplicate-json":
                        path.write_text('{"id":"' + NEW_JOB + '","host":"main","host":"rog"}')
                self.refused("operation_start", self.start("process_read", {"host": "main", "job_id": NEW_JOB}))
                path.unlink()
                target.unlink()
                path.write_bytes(raw)
                path.chmod(0o600)

    def test_native_valid_large_job_record_is_admissible_but_bound_overflow_refuses(self):
        path = self.record(self.new, NEW_JOB)
        path.write_text(json.dumps({"id": NEW_JOB, "host": "main", "args": ["x" * 70000]}))
        self.proxy._dispatch(self.request("operation_start", self.start("process_read", {"host": "main", "job_id": NEW_JOB})))
        self.assertEqual(len(self.native), 1)
        path.write_bytes(b"x" * (D.MAX_METADATA + 1))
        self.refused("operation_start", self.start("process_read", {"host": "main", "job_id": NEW_JOB}))

    def test_cancel_and_stop_only_accept_native_opaque_id_shape_and_exact_fields(self):
        for name, field in (("operation_cancel", "operation_id"), ("request_cancel", "request_id"), ("search_stop", "search_id")):
            for value in (OLD_JOB, "../" + ID, "A" * 64, 42, "", "b" * 65):
                self.refused(name, {field: value})
            self.refused(name, {field: ID, "host": "main"})
            self.refused(name, {field: ID, "owner": ID})
            self.refused(name, {field: ID, "pid": 123})

    def test_search_has_no_command_or_regex_dispatch_surface(self):
        good = self.examples()["search_start"]
        for change in ({"command": "arbitrary"}, {"regex": ".*"}, {"owner": ID}, {"pid": 123},
                       {"host": "raw-ssh-target"}, {"kind": "regex"}, {"kind": {"command": "arbitrary"}},
                       {"max_results": True}, {"root": ["/fixture"]}):
            self.refused("search_start", {**good, **change})

    def test_native_tool_error_and_unknown_admission_ack_are_returned_without_fallback(self):
        for response in ({"jsonrpc": "2.0", "id": "offline-operation_start", "error": {
                            "code": -32603, "message": "Native result unavailable", "data": {
                                "outcome": "unknown", "automatic_retry": False}}},
                         {"jsonrpc": "2.0", "id": "offline-operation_start", "result": {
                            "content": [{"type": "text", "text": "native validation refused"}], "isError": True}}):
            self.native_response = response
            before = len(self.native)
            result = self.proxy._dispatch(self.request("operation_start", self.start()))
            self.assertEqual(result, response)
            self.assertEqual(len(self.native), before + 1)
            self.assertFalse(self.original)

    def test_actual_native_transport_failure_does_not_retry_or_dispatch_in_v4(self):
        self.proxy.initialized = True
        self.proxy.session, self.proxy.protocol = "fixed-private-session", "2025-11-25"
        self.proxy._verify_catalog = mock.Mock()
        self.proxy.exchange = mock.Mock(side_effect=OSError("lost acknowledgement"))
        with mock.patch.object(D.NativeProxy, "_dispatch", self.actual_native_dispatch):
            result = self.proxy._dispatch(self.request("operation_start", self.start()))
        self.assertEqual(result["error"]["data"]["outcome"], "unknown")
        self.assertFalse(result["error"]["data"]["automatic_retry"])
        self.proxy.exchange.assert_called_once()
        self.assertFalse(self.original)

    def test_native_catalog_attestation_failure_prevents_submission_without_v4_fallback(self):
        self.proxy.initialized = True
        self.proxy._verify_catalog = mock.Mock(side_effect=ValueError("contract drift"))
        self.proxy.exchange = mock.Mock()
        with mock.patch.object(D.NativeProxy, "_dispatch", self.actual_native_dispatch):
            result = self.proxy._dispatch(self.request("search_stop", {"search_id": ID}))
        self.assertIn("error", result)
        self.proxy.exchange.assert_not_called()
        self.assertFalse(self.original)

    def test_legacy_initialize_remains_required(self):
        self.proxy.legacy_ready = False
        result = self.proxy._dispatch(self.request("request_start", self.start("host_list", {})))
        self.assertEqual(result["error"]["code"], -32071)
        self.assertFalse(self.native)
        self.assertFalse(self.original)

    def test_catalog_annotations_and_original_definitions_remain_unchanged(self):
        original = copy.deepcopy(self.c10.tools)
        for name, arguments in self.examples().items():
            self.proxy._dispatch(self.request(name, arguments))
            self.assertFalse(self.c10.by_name[name]["annotations"]["readOnlyHint"])
        self.assertEqual(self.c10.tools, original)
        self.c10.verify_integrity()
        self.c4.verify_integrity()
        self.assertTrue(all(self.c10.by_name[name] == definition for name, definition in self.c4.by_name.items()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
