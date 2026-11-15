#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Opt-in V4 single-owner effect dispatch; no production hosts are contacted."""
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import chatgpt_v10_dual_read as D
from mcp_tool_contract import ToolContract

HASH4 = "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1"
HASH10 = "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553"


class OriginalSingleOwner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-v4-effect-owner-")
        self.root = pathlib.Path(self.temp.name)
        self.original = self.root / "old"
        self.current = self.root / "new"
        for base in (self.original, self.current):
            base.mkdir(mode=0o700)
            (base / "jobs").mkdir(mode=0o700)
            (base / "terminals").mkdir(mode=0o700)
        self.c4 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json", HASH4)
        self.c10 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v10.json", HASH10)
        self.assertEqual(len(self.c4.tools), 50)
        self.assertEqual(len(self.c10.tools), 66)

    def tearDown(self):
        self.temp.cleanup()

    def adapter(self, enabled=True):
        proxy=D.DualReadNativeProxy(
            "http://127.0.0.1:8791/mcp", "fake-private-token", self.c10,
            "http://127.0.0.1:8790/mcp", "fake-other-private-token", self.c4,
            str(self.original), str(self.current),
            route_original_effects=enabled)
        proxy.legacy_ready=True
        calls=[]
        def original(request,context,era,*,mutating):
            calls.append({"name":request["params"]["name"],"mutating":mutating,
                          "backend":"original-v4","era":era})
            return {"jsonrpc":"2.0","id":request["id"],"result":{"routed_to":"original-v4"}}
        proxy._original=original
        return proxy,calls

    @staticmethod
    def req(name,arguments=None):
        return {"jsonrpc":"2.0","id":"test-effect-"+name,
                "method":"tools/call","params":{"name":name,"arguments":arguments or {}}}

    def create_identity(self, kind, identity, *, original=True, host="main"):
        root=(self.original if original else self.current)/kind
        rec={"id" if kind=="jobs" else "session_id":identity,"host":host}
        file=root/(identity+".json")
        file.write_text(json.dumps(rec));file.chmod(0o600)

    def test_opt_in_is_necessary(self):
        proxy,calls=self.adapter(enabled=False)
        r=proxy._dispatch(self.req("process_start",{"host":"main"}))
        self.assertEqual(r["error"]["data"]["outcome"],"not_submitted")
        self.assertFalse(calls)

    def test_every_exact_legacy_effect_has_only_one_v4_backend(self):
        proxy,calls=self.adapter()
        proxy.provenance.route=lambda name,args:"legacy"
        names=[t["name"] for t in self.c4.tools if not t["annotations"]["readOnlyHint"]]
        self.assertEqual(len(names),31)
        for name in names:
            result=proxy._dispatch(self.req(name,{"host":"main"}))
            self.assertEqual(result["result"]["routed_to"],"original-v4",name)
        self.assertEqual(len(calls),31)
        self.assertTrue(all(z["backend"]=="original-v4" and z["mutating"] for z in calls))

    def test_all_v10_only_effectful_names_stay_blocked(self):
        proxy,calls=self.adapter()
        native={t["name"] for t in self.c4.tools}
        additional=[t["name"] for t in self.c10.tools
                    if t["name"] not in native and not t["annotations"]["readOnlyHint"]]
        self.assertGreaterEqual(len(additional),6)
        for name in additional:
            r=proxy._dispatch(self.req(name))
            self.assertEqual(r["error"]["data"]["outcome"],"not_submitted",name)
            self.assertFalse(r["error"]["data"]["automatic_retry"],name)
        self.assertEqual(calls,[])

    def test_legacy_process_cancel_requires_original_job_identity(self):
        proxy,calls=self.adapter()
        old="1a13acafe00-b2f-134a"
        newer="1a13acafe00-b2f-134b"
        self.create_identity("jobs",old)
        self.create_identity("jobs",newer,original=False)
        original=proxy._dispatch(self.req("process_cancel",{"host":"main","job_id":old}))
        self.assertEqual(original["result"]["routed_to"],"original-v4")
        refused=proxy._dispatch(self.req("process_cancel",{"host":"main","job_id":newer}))
        self.assertEqual(refused["error"]["data"]["outcome"],"not_submitted")
        self.assertEqual(len(calls),1)

    def test_terminal_input_and_close_need_original_session(self):
        proxy,calls=self.adapter()
        old="dpty-abcdef9876"
        new="dpty-abcdef9877"
        self.create_identity("terminals",old)
        self.create_identity("terminals",new,original=False)
        for name in ("pty_write","pty_close"):
            a={"host":"main","session_id":old}
            if name=="pty_write":a.update({"data":"PING\n","request_id":"unique-test"})
            yes=proxy._dispatch(self.req(name,a))
            self.assertEqual(yes["result"]["routed_to"],"original-v4")
            no={**a,"session_id":new}
            denied=proxy._dispatch(self.req(name,no))
            self.assertEqual(denied["error"]["data"]["outcome"],"not_submitted")
        self.assertEqual(len(calls),2)

    def test_collision_in_old_and_new_refuses_job_cancel(self):
        proxy,calls=self.adapter()
        shared="1a13acafe00-b2f-134a"
        self.create_identity("jobs",shared)
        self.create_identity("jobs",shared,original=False)
        outcome=proxy._dispatch(self.req("process_cancel",{"host":"main","job_id":shared}))
        self.assertEqual(outcome["error"]["data"]["outcome"],"not_submitted")
        self.assertEqual(calls,[])

    def test_legacy_calls_require_initialize_even_for_effect(self):
        proxy,calls=self.adapter()
        proxy.legacy_ready=False
        r=proxy._dispatch(self.req("process_start"))
        self.assertEqual(r["error"]["code"],-32071)
        self.assertFalse(r["error"]["data"]["original_request_replayed"])
        self.assertEqual(calls,[])

    def test_original_read_ownership_is_unchanged_by_opt_in(self):
        proxy,calls=self.adapter()
        original="1a13acafe00-b2f-134a"
        self.create_identity("jobs",original)
        r=proxy._dispatch(self.req("process_status",{"host":"main","job_id":original}))
        self.assertEqual(r["result"]["routed_to"],"original-v4")
        self.assertEqual(calls,[{"name":"process_status","mutating":False,"backend":"original-v4","era":"legacy"}])


if __name__=="__main__":
    unittest.main(verbosity=2)
