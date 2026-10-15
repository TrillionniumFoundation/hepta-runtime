#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Offline no-effects tests for the separate V10+V4 read-custody adapter."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0,str(ROOT/'deploy'))
import chatgpt_v10_dual_read as D


class OwnershipUnit(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="hepta-dual-read-")
        self.root=Path(self.tmp.name)
        self.old=self.root/"original"
        self.new=self.root/"candidate"
        for root in (self.old,self.new):
            root.mkdir(mode=0o700)
            for sub in ("jobs","terminals"):
                (root/sub).mkdir(mode=0o700)
        self.owners=D.OriginalOwner(self.old,self.new)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self,place,kind,identity,host="main",field=None):
        field=field or ("id" if kind=="jobs" else "session_id")
        p=place/kind/(identity+".json")
        p.write_text(json.dumps({field:identity,"host":host},separators=(",",":")))
        p.chmod(0o600)
        return p

    def test_unambiguous_legacy_job(self):
        identity="1a13acafe00-b2f-134a"
        self.write(self.old,"jobs",identity)
        self.assertEqual(self.owners.route("process_status",{"host":"main","job_id":identity}),"legacy")
        self.assertEqual(self.owners.route("process_read",{"host":"main","job_id":identity}),"legacy")
        self.assertEqual(self.owners.route("process_wait",{"host":"main","job_id":identity}),"legacy")

    def test_candidate_job_is_never_routed_to_v4(self):
        identity="1a13acafe00-b2f-134a"
        self.write(self.new,"jobs",identity)
        self.assertEqual(self.owners.route("process_status",{"host":"main","job_id":identity}),"native")

    def test_nonexistent_identity_does_not_try_legacy(self):
        self.assertEqual(self.owners.route("process_read",{"host":"main","job_id":"1a13acafe00-b2f-134a"}),"native")

    def test_legacy_pty_is_readable_only(self):
        identity="dpty-abcdef0123"
        self.write(self.old,"terminals",identity)
        self.assertEqual(self.owners.route("pty_read",{"host":"main","session_id":identity}),"legacy")
        self.assertIsNone(self.owners.route("pty_write",{"host":"main","session_id":identity}))
        self.assertIsNone(self.owners.route("pty_close",{"host":"main","session_id":identity}))

    def test_ambiguous_owner_refuses_instead_of_choosing(self):
        identity="1a13acafe00-b2f-134a"
        self.write(self.old,"jobs",identity)
        self.write(self.new,"jobs",identity)
        with self.assertRaisesRegex(D.UnsafeProvenance,"ambiguous"):
            self.owners.route("process_status",{"host":"main","job_id":identity})

    def test_host_mismatch_refuses(self):
        identity="1a13acafe00-b2f-134a"
        self.write(self.old,"jobs",identity,"rog")
        with self.assertRaisesRegex(D.UnsafeProvenance,"identity_mismatch"):
            self.owners.route("process_status",{"host":"main","job_id":identity})

    def test_duplicate_json_key_refuses(self):
        identity="1a13acafe00-b2f-134a"
        path=self.write(self.old,"jobs",identity)
        path.write_text('{"id":"'+identity+'","host":"main","host":"rog"}')
        with self.assertRaises(D.UnsafeProvenance):
            self.owners.route("process_status",{"host":"main","job_id":identity})

    def test_symlink_leaf_refuses(self):
        identity="1a13acafe00-b2f-134a"
        path=self.write(self.old,"jobs",identity)
        path.unlink()
        path.symlink_to(self.write(self.new,"jobs",identity))
        with self.assertRaises(OSError):
            self.owners.route("process_status",{"host":"main","job_id":identity})

    def test_world_writable_leaf_refuses(self):
        identity="1a13acafe00-b2f-134a"
        p=self.write(self.old,"jobs",identity)
        p.chmod(0o666)
        with self.assertRaisesRegex(D.UnsafeProvenance,"owner_record_shape"):
            self.owners.route("process_read",{"host":"main","job_id":identity})

    def test_oversize_metadata_refuses(self):
        identity="1a13acafe00-b2f-134a"
        p=self.write(self.old,"jobs",identity)
        p.write_bytes(b"x"*(D.MAX_METADATA+1))
        with self.assertRaises(D.UnsafeProvenance):
            self.owners.route("process_status",{"host":"main","job_id":identity})

    def test_nonprivate_root_refuses(self):
        self.old.chmod(0o775)
        with self.assertRaisesRegex(D.UnsafeProvenance,"state_root_not_private"):
            self.owners.route("process_status",{"host":"main","job_id":"1a13acafe00-b2f-134a"})

    def test_symlink_root_refuses(self):
        self.old.rename(self.root/"original-hold")
        self.old.symlink_to(self.root/"original-hold",target_is_directory=True)
        with self.assertRaises(OSError):
            self.owners.route("process_status",{"host":"main","job_id":"1a13acafe00-b2f-134a"})

    def test_path_injection_cannot_be_a_leaf(self):
        for key in ["../etc/passwd","evil/../../x","invalid space","a"*129,42,None,""]:
            self.assertIsNone(self.owners.route("process_read",{"host":"main","job_id":key}))

    def test_unknown_host_cannot_choose_an_owner(self):
        identity="1a13acafe00-b2f-134a"
        self.write(self.old,"jobs",identity)
        for host in ("raw-ssh-target","bogus",None,"../main"):
            self.assertIsNone(self.owners.route("process_status",{"host":host,"job_id":identity}))

    def test_mutating_v10_tools_are_refused_before_any_backend_lookup(self):
        from mcp_tool_contract import ToolContract
        c = ROOT / "deploy/contracts/hepta-runtime-full-operator-v10.json"
        contract = ToolContract.load(c, "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553")
        adapter = object.__new__(D.DualReadNativeProxy)
        adapter.contract = contract
        for name in ("process_start", "process_cancel", "pty_write", "pty_close", "host_signal"):
            request = {"jsonrpc": "2.0", "id": "never-dispatch-" + name,
                       "method": "tools/call",
                       "params": {"name": name, "arguments": {}}}
            result = D.DualReadNativeProxy._dispatch(adapter, request)
            self.assertEqual(result["error"]["data"]["outcome"], "not_submitted")
            self.assertFalse(result["error"]["data"]["automatic_retry"])
            self.assertFalse(result["error"]["data"]["original_request_replayed"])

    def test_state_roots_cannot_be_the_same(self):
        with self.assertRaises(D.UnsafeProvenance):
            D.OriginalOwner(self.old,self.old)


if __name__=="__main__":
    unittest.main(verbosity=2)
