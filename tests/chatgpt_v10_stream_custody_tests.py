#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Offline original cooperative stream custody and mutation-owner tests."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
import chatgpt_v10_dual_read as D
from mcp_tool_contract import ToolContract


class StreamCustody(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="hepta-original-stream-")
        self.root=Path(self.temp.name)
        self.old=self.root/"old"
        self.new=self.root/"new"
        self.old.mkdir(mode=0o700)
        self.new.mkdir(mode=0o700)
        self.owner=D.OriginalOwner(self.old,self.new)
        self.sid="stream-"+"a"*64
        self.sid2="stream-"+"b"*64

    def tearDown(self):
        self.temp.cleanup()

    def add(self,root,sid=None):
        sid=sid or self.sid
        base=root/"stream_handoffs"
        if not base.exists():base.mkdir(mode=0o700)
        d=base/sid
        d.mkdir(mode=0o700)
        path=d/"request.json"
        path.write_text(json.dumps({"schema":"test","session_id":sid,"application_identities":[]}))
        path.chmod(0o600)
        return path

    def test_original_stream_list_status_and_byte_read(self):
        self.add(self.old)
        self.add(self.old,self.sid2)
        self.assertEqual(self.owner.route("stream_handoff_list",{}),"legacy")
        self.assertEqual(self.owner.route("stream_handoff_status",{"session_id":self.sid}),"legacy")
        self.assertEqual(self.owner.route("stream_handoff_read",{"session_id":self.sid,"stream":"stderr","offset":19}),"legacy")
        self.assertEqual(D.owned_stream_names(self.old),[self.sid,self.sid2])

    def test_missing_new_registry_is_legitimately_empty(self):
        self.add(self.old)
        self.assertEqual(D.owned_stream_names(self.new),[])
        self.assertEqual(self.owner.route("stream_handoff_list",{}),"legacy")

    def test_new_stream_routes_new_only_when_original_absent(self):
        self.add(self.new)
        self.assertEqual(self.owner.route("stream_handoff_list",{}),"native")
        self.assertEqual(self.owner.route("stream_handoff_status",{"session_id":self.sid}),"native")
        self.assertEqual(self.owner.route("stream_handoff_read",{"session_id":self.sid}),"native")

    def test_both_registries_nonempty_do_not_silently_omit_either(self):
        self.add(self.old,self.sid)
        self.add(self.new,self.sid2)
        with self.assertRaisesRegex(D.UnsafeProvenance,"two_active_stream"):
            self.owner.route("stream_handoff_list",{})
        self.assertEqual(self.owner.route("stream_handoff_read",{"session_id":self.sid}),"legacy")
        self.assertEqual(self.owner.route("stream_handoff_status",{"session_id":self.sid2}),"native")

    def test_exact_cross_controller_identity_collision_refused(self):
        self.add(self.old)
        self.add(self.new)
        with self.assertRaisesRegex(D.UnsafeProvenance,"ambiguous"):
            self.owner.route("stream_handoff_read",{"session_id":self.sid})
        with self.assertRaises(D.UnsafeProvenance):
            self.owner.route("stream_handoff_list",{})

    def test_unknown_old_id_routes_to_native_not_fake_old_status(self):
        self.add(self.old)
        self.assertEqual(self.owner.route("stream_handoff_read",{"session_id":self.sid2}),"native")

    def test_invalid_id_is_never_opened(self):
        self.add(self.old)
        for sid in ("../etc/passwd","stream-0","stream-ABC","other-"+"a"*64,42,None,""):
            self.assertIsNone(self.owner.route("stream_handoff_status",{"session_id":sid}))

    def test_symlink_directory_refused(self):
        original=self.add(self.old)
        original.parent.rename(original.parent.with_name("owned-hold"))
        link=original.parent
        link.symlink_to(original.parent.with_name("owned-hold"),target_is_directory=True)
        with self.assertRaises(OSError):
            self.owner.route("stream_handoff_status",{"session_id":self.sid})

    def test_symlink_request_refused(self):
        req=self.add(self.old)
        req.rename(req.with_name("held-request.json"))
        req.symlink_to(req.with_name("held-request.json"))
        with self.assertRaises(OSError):
            self.owner.route("stream_handoff_read",{"session_id":self.sid})

    def test_invalid_json_and_duplicate_key_are_refused(self):
        req=self.add(self.old)
        req.write_text('{"session_id":"'+self.sid+'","session_id":"'+self.sid+'"}')
        with self.assertRaises(D.UnsafeProvenance):
            self.owner.route("stream_handoff_status",{"session_id":self.sid})

    def test_wrong_original_request_identity_fails_closed(self):
        req=self.add(self.old)
        req.write_text(json.dumps({"session_id":self.sid2,"application_identities":[]}))
        with self.assertRaisesRegex(D.UnsafeProvenance,"mismatch"):
            self.owner.route("stream_handoff_status",{"session_id":self.sid})

    def test_group_writable_request_is_not_authoritative(self):
        req=self.add(self.old);req.chmod(0o660)
        with self.assertRaisesRegex(D.UnsafeProvenance,"stream_request_shape"):
            self.owner.route("stream_handoff_read",{"session_id":self.sid})

    def test_group_writable_stream_dir_is_not_authoritative(self):
        req=self.add(self.old);req.parent.chmod(0o770)
        with self.assertRaisesRegex(D.UnsafeProvenance,"not_private"):
            self.owner.route("stream_handoff_status",{"session_id":self.sid})

    def test_oversize_request_cannot_consume_unbounded_ram(self):
        req=self.add(self.old);req.write_bytes(b"x"*(D.MAX_METADATA+1))
        with self.assertRaisesRegex(D.UnsafeProvenance,"shape"):
            self.owner.route("stream_handoff_status",{"session_id":self.sid})

    def test_unknown_member_in_list_cannot_be_hidden(self):
        self.add(self.old)
        (self.old/"stream_handoffs"/"garbage.tmp").write_text("x")
        with self.assertRaisesRegex(D.UnsafeProvenance,"unknown_stream"):
            self.owner.route("stream_handoff_list",{})

    def test_list_overflow_refuses_whole_result(self):
        base=self.old/"stream_handoffs";base.mkdir(mode=0o700)
        for i in range(D.MAX_STREAM_SESSIONS+1):
            (base/f"stream-{i:064x}").mkdir(mode=0o700)
        with self.assertRaisesRegex(D.UnsafeProvenance,"stream_list_bound"):
            self.owner.route("stream_handoff_list",{})

    def test_default_mutating_stream_write_refused_without_network(self):
        c10=ToolContract.load(ROOT/"deploy/contracts/hepta-runtime-full-operator-v10.json",
            "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553")
        proxy=object.__new__(D.DualReadNativeProxy)
        proxy.contract=c10
        request={"jsonrpc":"2.0","id":"refused","method":"tools/call",
                 "params":{"name":"stream_handoff_write",
                           "arguments":{"session_id":self.sid,"request_id":"r","data_base64":"YQ=="}}}
        result=D.DualReadNativeProxy._dispatch(proxy,request)
        self.assertEqual(result["error"]["data"]["outcome"],"not_submitted")
        self.assertFalse(result["error"]["data"]["automatic_retry"])

    def test_optin_original_write_requires_original_registry(self):
        c4=ToolContract.load(ROOT/"deploy/contracts/hepta-runtime-full-operator-v4.json",
            "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1")
        c10=ToolContract.load(ROOT/"deploy/contracts/hepta-runtime-full-operator-v10.json",
            "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553")
        proxy=D.DualReadNativeProxy("http://127.0.0.1:8791/mcp","fake",c10,
                                   "http://127.0.0.1:8790/mcp","fake",c4,
                                   self.old,self.new,route_original_effects=True)
        proxy.legacy_ready=True
        calls=[]
        def stub(req,context,era,*,mutating):
            calls.append((req["params"]["name"],mutating))
            return {"jsonrpc":"2.0","id":req["id"],"result":{}}
        proxy._original=stub
        request={"jsonrpc":"2.0","id":"once","method":"tools/call",
                 "params":{"name":"stream_handoff_write",
                           "arguments":{"session_id":self.sid,"request_id":"r","data_base64":"YQ=="}}}
        refused=proxy._dispatch(request)
        self.assertEqual(refused["error"]["data"]["outcome"],"not_submitted")
        self.assertFalse(calls)
        self.add(self.old)
        yes=proxy._dispatch(request)
        self.assertIn("result",yes)
        self.assertEqual(calls,[("stream_handoff_write",True)])
        self.add(self.new)
        blocked=proxy._dispatch(request)
        self.assertEqual(blocked["error"]["data"]["outcome"],"not_submitted")
        self.assertEqual(len(calls),1)


if __name__=="__main__":
    unittest.main(verbosity=2)
