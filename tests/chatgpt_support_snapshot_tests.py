#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline redaction, counter and interpretation tests for support diagnostics."""
import importlib.util
import json
import pathlib
import unittest

PATH=pathlib.Path(__file__).resolve().parents[1]/"deploy/chatgpt_support_snapshot.py"
SPEC=importlib.util.spec_from_file_location("hepta_support_diag", PATH)
D=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)

class SupportSnapshot(unittest.TestCase):
    def test_health_never_copies_new_sensitive_component_fields(self):
        value = {
            "ready": True,
            "components": {
                "control-plane": {
                    "status": "ok", "state": "polling",
                    "api_key": "TOPSECRET",
                    "details": {
                        "last_success": "2026-10-12T09:55:55Z",
                        "consecutive_failures": 0, "bearer": "TOPSECRET",
                        "completed": {"token": "TOPSECRET"}
                    }
                },
                "mcp": {
                    "status": "unknown", "state": "not_observed",
                    "details": {
                        "initialize_epoch": 0, "tokens": ["TOPSECRET"],
                        "tools_list": {"tool_names": ["TOPSECRET"]}
                    }
                }
            }
        }
        result = D.health_projection(value)
        self.assertTrue(result["ready"])
        self.assertEqual(result["control_plane"]["counters"]["consecutive_failures"], 0)
        self.assertNotIn("TOPSECRET", json.dumps(result))
        self.assertNotIn("tools_list", json.dumps(result))

    def test_health_unapproved_status_and_time_strings_are_redacted(self):
        value = {"components": {"control-plane": {
            "status": "TOPSECRET", "state": "TOPSECRET",
            "details": {"last_success": "TOPSECRET", "failures": 4}
        }}}
        result = D.health_projection(value)
        self.assertNotIn("TOPSECRET", json.dumps(result))
        self.assertEqual(result["control_plane"]["status"], "other")
        self.assertEqual(result["control_plane"]["counters"]["failures"], 4)

    def test_journal_ignores_payload_secrets_tool_args_and_request_ids(self):
        line1 = json.dumps({
            "event": "hepta_mcp_protocol", "method": "tools/list",
            "era": "modern", "status": "ok", "error_code": None,
            "arguments": "TOPSECRET", "request_id": "TOPSECRET",
            "tool_name": "secret_name"
        })
        line2 = json.dumps({
            "msg": "dispatcher forwarded command to MCP server",
            "command": "TOPSECRET", "request_id": "TOPSECRET"
        })
        line3 = json.dumps({
            "event": "hepta_mcp_protocol", "method": "tools/call",
            "era": "modern", "status": "error", "error_code": -32603,
            "tool_arguments": {"content": "TOPSECRET"}
        })
        raw = D.journal_projection("\n".join([line1, line2, line3, "not json"]))
        self.assertEqual(raw["observed_dispatch_log_events"], 1)
        self.assertEqual(sum(e["count"] for e in raw["protocol_events"]), 2)
        self.assertNotIn("TOPSECRET", json.dumps(raw))
        self.assertNotIn("secret_name", json.dumps(raw))

    def test_no_unapproved_method_or_status_ever_echoes_into_report(self):
        raw = D.journal_projection(json.dumps({
            "event": "hepta_mcp_protocol",
            "method": "TOPSECRET", "status": "TOPSECRET",
            "era": "TOPSECRET"
        }))
        self.assertEqual(raw["protocol_events"], [])

    def test_counter_deltas_have_no_policy_inference(self):
        before = {
            "schema": "hepta-mcp-support-snapshot-v1",
            "collected_utc": "2026-10-12T08:00:00+00:00",
            "tunnel": {
                "dispatcher": {"counters": {"completed": 20, "failures": 0}},
                "response_delivery": {"counters": {
                    "accepted": 20, "terminal_failures": 0
                }}
            }
        }
        after = json.loads(json.dumps(before))
        after["collected_utc"] = "2026-10-12T08:01:00+00:00"
        after["tunnel"]["dispatcher"]["counters"]["completed"] = 21
        after["tunnel"]["response_delivery"]["counters"]["accepted"] = 21
        result = D.compare(before, after)
        self.assertEqual(result["counter_deltas"]["dispatcher.completed"], 1)
        self.assertEqual(result["counter_deltas"]["response_delivery.accepted"], 1)
        self.assertIn("cannot identify", result["interpretation"])
        self.assertIsNone(D.compare({}, after)["counter_deltas"]["dispatcher.completed"])

    def test_service_fields_explicitly_only_active_loaded(self):
        value = D.unit_projection(
            "MainPID=2927\nToken=TOPSECRET\nActiveState=active\n"
            "LoadState=loaded\n"
        )
        self.assertEqual(value, {"active": True, "loaded": True})
        self.assertNotIn("TOPSECRET", json.dumps(value))

if __name__ == "__main__":
    unittest.main(verbosity=2)
