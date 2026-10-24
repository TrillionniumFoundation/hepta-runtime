#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("chatgpt_bridge",ROOT/"deploy/chatgpt_mcp_bridge.py")
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)

class ChatGPTBridge(unittest.TestCase):
    def test_allowlist_is_exact_and_read_only(self):
        self.assertEqual(B.ALLOWED_TOOLS,{
            "host_list","process_status","file_info",
            "stream_handoff_list","stream_handoff_status","stream_handoff_read","document_read",
        })
        for name in B.ALLOWED_TOOLS:
            self.assertIsNone(B.inspect_request({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":{}}}))

    def test_mutating_and_unknown_tools_are_denied(self):
        for name in ("shell_start","host_signal","sudo_start","process_start","pty_write","binary_write","document_write","not_a_tool"):
            error=B.inspect_request({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":{}}})
            self.assertEqual(error["error"]["code"],-32601)

    def test_unknown_methods_are_denied(self):
        error=B.inspect_request({"jsonrpc":"2.0","id":9,"method":"resources/read","params":{}})
        self.assertEqual(error["id"],9);self.assertEqual(error["error"]["code"],-32601)

    def test_discovery_filter_removes_write_tools_and_sets_annotations(self):
        request={"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
        response={"jsonrpc":"2.0","id":2,"result":{"tools":[
            {"name":"host_list","inputSchema":{"type":"object"}},
            {"name":"shell_start","inputSchema":{"type":"object"}},
        ]}}
        filtered=B.filter_response(request,response)
        self.assertEqual([t["name"] for t in filtered["result"]["tools"]],["host_list"])
        ann=filtered["result"]["tools"][0]["annotations"]
        self.assertEqual(ann,{"readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":False})

    def test_initialize_rebrands_only_server_name(self):
        req={"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
        response={"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"private","version":"9"}}}
        out=B.filter_response(req,response)
        self.assertEqual(out["result"]["serverInfo"]["name"],"hepta-chatgpt-readonly")
        self.assertEqual(out["result"]["serverInfo"]["version"],"9")
        self.assertEqual(out["result"]["protocolVersion"],"2025-06-18")

    def test_private_token_file_policy(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/"token";p.write_bytes(b"secret")
            os.chmod(p,0o600)
            self.assertEqual(B.private_file(p),b"secret")
            os.chmod(p,0o644)
            with self.assertRaises(PermissionError):B.private_file(p)

    def test_batch_filter_maps_by_jsonrpc_id(self):
        req=[
            {"jsonrpc":"2.0","id":"a","method":"initialize","params":{}},
            {"jsonrpc":"2.0","id":"b","method":"tools/list","params":{}},
        ]
        resp=[
            {"jsonrpc":"2.0","id":"b","result":{"tools":[{"name":"host_list"},{"name":"process_start"}]}},
            {"jsonrpc":"2.0","id":"a","result":{"serverInfo":{"name":"old"}}},
        ]
        out=B.filter_response(req,resp)
        by={v["id"]:v for v in out}
        self.assertEqual([t["name"] for t in by["b"]["result"]["tools"]],["host_list"])
        self.assertEqual(by["a"]["result"]["serverInfo"]["name"],"hepta-chatgpt-readonly")

if __name__=="__main__":unittest.main(verbosity=2)
