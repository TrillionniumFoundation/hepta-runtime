#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Private-file owner routing, race refusal and native empty-registry regressions."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import runtime_workflow_owner as W


class WorkflowOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-workflow-custody-")
        self.base = Path(self.temporary.name)
        self.old, self.new = self.base / "old", self.base / "new"
        for root in (self.old, self.new):
            root.mkdir(mode=0o700)
        self.owner = W.RuntimeWorkflowOwner(self.old, self.new)
        self.identity = "a" * 64
        self.scope = "b" * 64

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, root, kind="search", identity=None, owner=None, *, archive=False):
        identity = self.identity if identity is None else identity
        if kind == "audit":
            components, field = (("request-archive-v11" if archive else "request-audit",),
                                 "request_id")
        else:
            components, field = W.KINDS[kind]
        directory = root
        for component in components:
            directory = directory / component
            directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / (identity + ".json")
        path.write_text(json.dumps({field: identity, "owner": self.scope if owner is None else owner,
                                    "private_args": ["SECRET_SENTINEL_NEVER_RETURNED"]}))
        path.chmod(0o600)
        return path

    def test_closed_families_prove_predecessor_native_or_absent(self):
        for kind in (*W.KINDS, "audit"):
            with self.subTest(kind=kind):
                self.assertEqual(self.owner.owner(kind, self.identity), "absent")
                old = self.write(self.old, kind)
                self.assertEqual(self.owner.owner(kind, self.identity), "predecessor")
                old.unlink()
                self.write(self.new, kind)
                self.assertEqual(self.owner.owner(kind, self.identity), "native")
        self.assertNotIn("SECRET_SENTINEL", repr(self.owner.__dict__))

    def test_cross_controller_collision_refuses_every_family(self):
        for kind in (*W.KINDS, "audit"):
            with self.subTest(kind=kind):
                self.write(self.old, kind)
                self.write(self.new, kind)
                with self.assertRaisesRegex(W.UnsafeWorkflowOwner, "collision"):
                    self.owner.owner(kind, self.identity)

    def test_same_backend_hot_and_archived_audit_agree_on_owner(self):
        self.write(self.old, "audit")
        archive = self.write(self.old, "audit", archive=True)
        self.assertEqual(self.owner.owner("audit", self.identity), "predecessor")
        self.write(self.old, "audit", owner="c" * 64, archive=True)
        with self.assertRaisesRegex(W.UnsafeWorkflowOwner, "owner_disagreement"):
            self.owner.owner("audit", self.identity)
        archive.unlink()
        self.write(self.new, "audit", archive=True)
        with self.assertRaisesRegex(W.UnsafeWorkflowOwner, "collision"):
            self.owner.owner("audit", self.identity)

    def test_audit_archive_only_membership_and_mismatched_identity_refuse(self):
        path = self.write(self.new, "audit", archive=True)
        self.assertEqual(self.owner.owner("audit", self.identity), "native")
        record = json.loads(path.read_text())
        record["request_id"] = "d" * 64
        path.write_text(json.dumps(record))
        with self.assertRaises(W.UnsafeWorkflowOwner):
            self.owner.owner("audit", self.identity)

    def test_arguments_are_closed_before_any_filesystem_probe(self):
        for kind, identity in [(None, self.identity), ([], self.identity), ("arbitrary", self.identity),
                               ("search", "../escape"), ("search", "A" * 64),
                               ("search", "a" * 63), ("search", None), ("search", True)]:
            with self.subTest(kind=kind, identity=identity), self.assertRaises(W.UnsafeWorkflowOwner):
                self.owner.owner(kind, identity)

    def test_missing_whole_store_is_absent_but_missing_intents_is_partial_and_refused(self):
        self.assertEqual(self.owner.owner("request", self.identity), "absent")
        (self.old / "request-async-v9").mkdir(mode=0o700)
        with self.assertRaisesRegex(W.UnsafeWorkflowOwner, "partial_store"):
            self.owner.owner("request", self.identity)
        (self.old / "request-async-v9" / ".intents").mkdir(mode=0o700)
        self.assertEqual(self.owner.owner("request", self.identity), "absent")

    def test_leaf_symlink_hardlink_fifo_and_wide_modes_refuse(self):
        outside = self.base / "outside"
        outside.write_text("PRIVATE_SENTINEL")
        outside.chmod(0o600)
        path = self.write(self.old)
        for case in ("symlink", "hardlink", "fifo", "mode"):
            with self.subTest(case=case):
                path.unlink()
                if case == "symlink":
                    path.symlink_to(outside)
                elif case == "hardlink":
                    os.link(outside, path)
                elif case == "fifo":
                    os.mkfifo(path, 0o600)
                else:
                    path = self.write(self.old)
                    path.chmod(0o640)
                with self.assertRaises(W.UnsafeWorkflowOwner):
                    self.owner.owner("search", self.identity)
        self.assertEqual(outside.read_text(), "PRIVATE_SENTINEL")

    def test_malformed_duplicate_nonfinite_oversize_and_invalid_owners_refuse(self):
        path = self.write(self.old)
        records = ["", "{", "[]", ' {"id":"' + self.identity + '","owner":"' + self.scope
                   + '","owner":"' + self.scope + '"}',
                   json.dumps({"id": self.identity, "owner": self.scope, "n": float("nan")}),
                   json.dumps({"id": self.identity, "owner": "invalid"}),
                   json.dumps({"id": self.identity, "owner": True}),
                   json.dumps({"id": "c" * 64, "owner": self.scope}),
                   json.dumps({"id": self.identity, "owner": self.scope,
                               "large": "x" * W.MAX_RECORD_BYTES})]
        for record in records:
            with self.subTest(record=record[:70]):
                path.write_text(record)
                with self.assertRaises(W.UnsafeWorkflowOwner):
                    self.owner.owner("search", self.identity)

    def test_root_aliases_symlink_ancestors_and_replaced_private_root_refuse(self):
        with self.assertRaises(W.UnsafeWorkflowOwner):
            W.RuntimeWorkflowOwner(self.old, self.old)
        with self.assertRaises(W.UnsafeWorkflowOwner):
            W.RuntimeWorkflowOwner("relative", self.new)
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(W.UnsafeWorkflowOwner):
            W.RuntimeWorkflowOwner(alias / "old", self.new)
        self.old.rename(self.base / "held-old")
        self.old.mkdir(mode=0o700)
        with self.assertRaisesRegex(W.UnsafeWorkflowOwner, "root_identity_changed"):
            self.owner.owner("search", self.identity)

    def test_store_or_intents_symlink_and_nonprivate_directory_refuse(self):
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        (self.old / "search").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(W.UnsafeWorkflowOwner):
            self.owner.owner("search", self.identity)
        (self.old / "request-async-v9").mkdir(mode=0o700)
        (self.old / "request-async-v9" / ".intents").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(W.UnsafeWorkflowOwner):
            self.owner.owner("request", self.identity)
        path = self.write(self.new, "operation")
        path.parent.chmod(0o750)
        with self.assertRaises(W.UnsafeWorkflowOwner):
            self.owner.owner("operation", self.identity)

    def test_first_backend_leaf_mutation_while_second_is_examined_refuses(self):
        path = self.write(self.old)
        original = W._record
        calls = [0]
        def race(*arguments):
            calls[0] += 1
            result = original(*arguments)
            if calls[0] == 2:
                path.write_text(path.read_text() + " ")
            return result
        with mock.patch.object(W, "_record", side_effect=race):
            with self.assertRaisesRegex(W.UnsafeWorkflowOwner, "changed"):
                self.owner.owner("search", self.identity)

    def test_absent_store_creation_during_second_backend_probe_refuses(self):
        original = W._record
        calls = [0]
        def race(*arguments):
            calls[0] += 1
            result = original(*arguments)
            if calls[0] == 2:
                self.write(self.old)
            return result
        with mock.patch.object(W, "_record", side_effect=race):
            with self.assertRaisesRegex(W.UnsafeWorkflowOwner, "changed"):
                self.owner.owner("search", self.identity)

    def test_empty_native_effect_registries_allow_missing_and_trusted_empty_directories(self):
        self.owner.assert_native_effect_registries_empty()
        W.assert_native_effect_registries_empty(self.new)
        for folder in ("jobs", "terminals"):
            (self.new / folder).mkdir(mode=0o755)
        self.owner.assert_native_effect_registries_empty()
        W.assert_native_effect_registries_empty(self.new)

    def test_native_effect_registry_any_entry_or_unsafe_directory_refuses(self):
        for folder in ("jobs", "terminals"):
            path = self.new / folder
            path.mkdir(mode=0o700)
            member = path / "unexpected"
            member.write_text("no visibility omission")
            with self.assertRaisesRegex(W.UnsafeWorkflowOwner, "not_empty"):
                self.owner.assert_native_effect_registries_empty()
            member.unlink()
            path.chmod(0o777)
            with self.assertRaises(W.UnsafeWorkflowOwner):
                self.owner.assert_native_effect_registries_empty()
            path.chmod(0o700)
            path.rmdir()
            path.symlink_to(self.old, target_is_directory=True)
            with self.assertRaises(W.UnsafeWorkflowOwner):
                self.owner.assert_native_effect_registries_empty()
            path.unlink()

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "O_PATH"), "Linux O_PATH required")
    def test_real_landlock_denied_ancestor_listing_preserves_private_root_reads(self):
        if platform.machine() not in ("x86_64", "aarch64"):
            self.skipTest("Landlock syscall numbers are verified only for x86_64/aarch64")
        self.write(self.old)
        (self.new / "jobs").mkdir(mode=0o700)
        (self.new / "terminals").mkdir(mode=0o700)
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        # Landlock confines only this disposable child. Handle READ_DIR, grant
        # it solely below the two fixture roots, and retain no parent rule.
        program = r'''
import ctypes,errno,json,os,pathlib,sys
sys.path.insert(0,sys.argv[1])
import runtime_workflow_owner as W
libc=ctypes.CDLL(None,use_errno=True)
libc.syscall.restype=ctypes.c_long
CREATE,ADD,RESTRICT=444,445,446
READ_DIR=1<<3
abi=libc.syscall(CREATE,None,0,1)
if abi<0:
    code=ctypes.get_errno()
    if code in (errno.ENOSYS,errno.EOPNOTSUPP):raise SystemExit(77)
    raise OSError(code,'landlock ABI query')
class Ruleset(ctypes.Structure):_fields_=[('handled_access_fs',ctypes.c_uint64)]
class Beneath(ctypes.Structure):
    _pack_=1
    _fields_=[('allowed_access',ctypes.c_uint64),('parent_fd',ctypes.c_int32)]
attributes=Ruleset(READ_DIR)
ruleset=libc.syscall(CREATE,ctypes.byref(attributes),ctypes.sizeof(attributes),0)
if ruleset<0:raise OSError(ctypes.get_errno(),'landlock create')
old,new=map(pathlib.Path,sys.argv[2:4]);denied_final=sys.argv[6]=='deny-final'
for root in (old,) if denied_final else (old,new):
    descriptor=os.open(root,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    rule=Beneath(READ_DIR,descriptor)
    result=libc.syscall(ADD,ruleset,1,ctypes.byref(rule),0)
    os.close(descriptor)
    if result<0:raise OSError(ctypes.get_errno(),'landlock add')
if libc.prctl(38,1,0,0,0):raise OSError(ctypes.get_errno(),'no_new_privs')
if libc.syscall(RESTRICT,ruleset,0):raise OSError(ctypes.get_errno(),'landlock restrict')
os.close(ruleset)
def denied_root_listing():
    try:descriptor=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    except PermissionError:return True
    else:os.close(descriptor);raise AssertionError('ancestor listing unexpectedly allowed')
assert denied_root_listing()
if denied_final:
    try:W.RuntimeWorkflowOwner(old,new)
    except W.UnsafeWorkflowOwner:pass
    else:raise AssertionError('configured root read permission was bypassed')
    print('FINAL_ROOT_READ_REQUIRED')
else:
    owner=W.RuntimeWorkflowOwner(old,new)
    assert owner.owner('search',sys.argv[4])=='predecessor'
    owner.assert_native_effect_registries_empty()
    W.assert_native_effect_registries_empty(new)
    try:W.RuntimeWorkflowOwner(pathlib.Path(sys.argv[5])/'old',new)
    except W.UnsafeWorkflowOwner:pass
    else:raise AssertionError('O_PATH followed an ancestor symlink')
    assert denied_root_listing()
    print('PRIVATE_ROOTS_PASS_ANCESTORS_STILL_DENIED')
'''
        for scenario, expected in (("allow-private", "PRIVATE_ROOTS_PASS_ANCESTORS_STILL_DENIED"),
                                   ("deny-final", "FINAL_ROOT_READ_REQUIRED")):
            result = subprocess.run([sys.executable, "-c", program, str(ROOT / "deploy"),
                                     str(self.old), str(self.new), self.identity, str(alias), scenario],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 77:
                self.skipTest("kernel Landlock is unavailable or disabled")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
