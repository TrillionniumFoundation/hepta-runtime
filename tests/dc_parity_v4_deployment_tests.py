#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline failure/rollback helper tests; never touch live systemd or credentials."""
import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]

def load(name):
    spec=importlib.util.spec_from_file_location(name, ROOT / "deploy" / (name+".py"))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

A=load("activate_dc_parity_v4")
B=load("rollback_dc_parity_v4")

class DeploymentGuards(unittest.TestCase):
    def test_frozen_contract_additions_do_not_change_existing_tools(self):
        one=json.loads((ROOT/"deploy/contracts/hepta-runtime-full-operator-v1.json").read_text())
        four=json.loads((ROOT/"deploy/contracts/hepta-runtime-full-operator-v4.json").read_text())
        old={x["name"]:x for x in one["tools"]}
        new={x["name"]:x for x in four["tools"]}
        self.assertEqual(len(old),46)
        self.assertEqual(len(new),50)
        self.assertEqual({k:new[k] for k in old},old)
        self.assertEqual(set(new)-set(old),{
            "directory_create","directory_move","file_move","text_file_write"})
        self.assertEqual(A.NEW_CONTRACT_SHA,A.sha(ROOT/"deploy/contracts/hepta-runtime-full-operator-v4.json"))

    def test_backup_exclusive_create_private_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t)/"profile"
            A.private_backup(p,b"old")
            self.assertEqual(p.read_bytes(),b"old")
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            with self.assertRaises(FileExistsError):
                A.private_backup(p,b"new")
            self.assertEqual(p.read_bytes(),b"old")

    def test_atomic_profile_replace_uses_private_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t)/"profile"
            p.write_bytes(b"old");p.chmod(0o600)
            A.atomic(p,b"new")
            self.assertEqual(p.read_bytes(),b"new")
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            self.assertFalse(p.with_name(p.name+".hepta-v4-atomic").exists())

    def test_atomic_refuses_leftover_staging_file(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t)/"profile"
            p.write_bytes(b"original")
            tmp=p.with_name(p.name+".hepta-v4-atomic")
            tmp.write_bytes(b"unverified")
            with self.assertRaises(FileExistsError):
                A.atomic(p,b"candidate")
            self.assertEqual(p.read_bytes(),b"original")

    def test_rollback_restore_is_atomic_and_does_not_change_other_files(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t)/"target";unrelated=pathlib.Path(t)/"dc"
            p.write_bytes(b"v4");unrelated.write_bytes(b"keep")
            B.atomically_restore(p,b"v1")
            self.assertEqual(p.read_bytes(),b"v1")
            self.assertEqual(unrelated.read_bytes(),b"keep")
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)

    def test_wait_native_can_recover_from_one_transient_unavailable_read(self):
        with mock.patch.object(A,"service",return_value={"ActiveState":"active"}),\
             mock.patch.object(A,"catalog_count",side_effect=[ConnectionError("not ready"),50]) as counter,\
             mock.patch.object(A.time,"sleep",return_value=None):
            self.assertEqual(A.wait_native(50,timeout=1),50)
            self.assertEqual(counter.call_count,2)

    def test_installer_refuses_root_and_requires_exact_source(self):
        with mock.patch.object(A.os,"geteuid",return_value=0):
            with self.assertRaises(PermissionError):
                A.preflight()
        self.assertEqual(A.HEAD,"22986bab5e5c2b21f9dfd13befaee2046f7022cb")
        self.assertEqual(B.NEW_NATIVE_SHA,A.NEW_NATIVE_SHA)
        self.assertEqual(B.OLD_NATIVE_SHA,A.OLD_NATIVE_SHA)

if __name__=="__main__":
    unittest.main(verbosity=2)
