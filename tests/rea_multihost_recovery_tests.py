#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Offline private-authority regressions; no Runtime, SSH or HTTP payload starts."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

RUNNER = Path(__file__).resolve().parents[1] / "scripts" / "rea_multihost_recovery.py"
SPEC = importlib.util.spec_from_file_location("rea_multihost_recovery_authority_subject", RUNNER)
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "private owner authority uses the POSIX no-follow contract")
class PrivateAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.resources = contextlib.ExitStack()
        self.addCleanup(self.resources.close)
        temporary = self.resources.enter_context(
            tempfile.TemporaryDirectory(prefix="rea-recovery-authority-"))
        self.parent = Path(temporary)
        self.root = self.parent / "private"
        self.run_id = "offline-owned-authority"
        self.source = b"# an offline fixture; never executed\n"
        self.resources.enter_context(mock.patch.object(
            SUBJECT, "platform_profile", return_value={"scope": "offline fixture"}))
        for module, name in ((SUBJECT, "run_command"), (SUBJECT.subprocess, "run"),
                             (SUBJECT.subprocess, "Popen"), (SUBJECT.os, "execv"),
                             (SUBJECT.socket, "socket")):
            self.resources.enter_context(mock.patch.object(
                module, name, side_effect=AssertionError("offline test attempted a payload")))

    def create_worker(self):
        return SUBJECT.create_root(self.root, self.run_id, self.source)

    def authority(self, role="worker", provision=False):
        return SUBJECT.private_authority(self.root, self.run_id, role, provision=provision)

    def content_snapshot(self, directory):
        return {path.name: (path.read_bytes(), SUBJECT.metadata(path.lstat()))
                for path in directory.iterdir() if path.is_file()}

    def expected_document(self, role):
        return {"schema": "hepta-effect-owner-fence-v1", "owner": "v4",
                "epoch": 1, "phase": "admitting",
                "state_root": str(self.root / (role + "-state")),
                "predecessor_state_root": None}

    def assert_ready(self, receipt, role="worker"):
        self.assertEqual(receipt["owner_document"], self.expected_document(role))
        self.assertEqual(receipt["role"], role)
        self.assertEqual(receipt["run_id"], self.run_id)
        self.assertIs(receipt["required_fence"], True)
        self.assertEqual(receipt["state_root"], str(self.root / (role + "-state")))
        self.assertEqual((self.root / (role + "-authority") / ".owner.lock").read_bytes(), b"")
        for name in (".owner.lock", ".owner.json"):
            info = (self.root / (role + "-authority") / name).lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(info.st_nlink, 1)

    def test_local_initialization_provisions_required_worker_authority(self):
        prepared = self.create_worker()
        before = prepared["authority_before"]
        self.assert_ready(before)
        self.assertEqual(before, self.authority())
        self.assertEqual((self.root / "runner.py").read_bytes(), self.source)

    def test_remote_bootstrap_finish_provisions_same_private_contract(self):
        self.root.mkdir(mode=0o700)
        SUBJECT.write_new(self.root / "runner.py", self.source, 0o500)
        with mock.patch.object(SUBJECT, "__file__", str(self.root / "runner.py")):
            prepared = SUBJECT.bootstrap_finish(self.run_id)
        self.assert_ready(prepared["authority_before"])
        self.assertEqual(prepared["authority_before"], self.authority())

    def test_controller_authority_is_bound_to_distinct_controller_state(self):
        worker = self.create_worker()["authority_before"]
        for name in ("controller-state", "controller-authority"):
            (self.root / name).mkdir(mode=0o700)
        SUBJECT.write_new(self.root / "controller-config.json",
                          SUBJECT.encoded({"state_dir": str(self.root / "controller-state")}))
        controller = self.authority("controller", provision=True)
        self.assert_ready(controller, "controller")
        self.assertEqual(controller, self.authority("controller"))
        self.assertNotEqual(controller["state_root"], worker["state_root"])
        self.assertEqual(worker, self.authority())

    def test_internal_authority_action_is_a_read_only_receipt(self):
        prepared = self.create_worker()["authority_before"]
        directory = self.root / "worker-authority"
        before = self.content_snapshot(directory)
        result = SUBJECT.host_action({"action": "authority", "root": str(self.root),
                                      "run_id": self.run_id})
        self.assertEqual(result, prepared)
        self.assertEqual(before, self.content_snapshot(directory))

    def test_reprovision_refuses_even_matching_existing_records(self):
        self.create_worker()
        directory = self.root / "worker-authority"
        before = self.content_snapshot(directory)
        with self.assertRaisesRegex(RuntimeError, "not empty"):
            self.authority(provision=True)
        self.assertEqual(before, self.content_snapshot(directory))

    def test_wrong_run_marker_and_unknown_role_do_not_touch_authority(self):
        self.create_worker()
        directory = self.root / "worker-authority"
        before = self.content_snapshot(directory)
        with self.assertRaisesRegex(RuntimeError, "no longer identifies"):
            SUBJECT.private_authority(self.root, "another-run", "worker", provision=True)
        with self.assertRaisesRegex(RuntimeError, "unknown private authority role"):
            self.authority("unowned", provision=True)
        self.assertEqual(before, self.content_snapshot(directory))
        self.assertFalse((self.root / "unowned-authority").exists())

    def test_configuration_cannot_rebind_authority_to_other_state(self):
        self.create_worker()
        document = self.expected_document("worker")
        path = self.root / "worker-config.json"
        config = json.loads(path.read_bytes())
        config["state_dir"] = str(self.parent / "some-other-state")
        path.write_bytes(SUBJECT.encoded(config))
        with self.assertRaisesRegex(RuntimeError, "differs from its actual configuration"):
            self.authority()
        self.assertEqual(json.loads(
            (self.root / "worker-authority" / ".owner.json").read_bytes()), document)

    def test_owner_document_contract_mutations_are_rejected(self):
        self.create_worker()
        path = self.root / "worker-authority" / ".owner.json"
        original = path.read_bytes()
        changes = {"schema": "another-schema", "owner": "v3", "epoch": 2,
                   "phase": "fenced", "state_root": str(self.parent / "other-state"),
                   "predecessor_state_root": str(self.parent / "old-state")}
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = self.expected_document("worker")
                changed[field] = value
                path.write_bytes(SUBJECT.encoded(changed))
                with self.assertRaisesRegex(RuntimeError, "bytes differ"):
                    self.authority()
                path.write_bytes(original)

    def test_readback_rejects_missing_records_without_repair(self):
        self.create_worker()
        directory = self.root / "worker-authority"
        for name in (".owner.lock", ".owner.json"):
            with self.subTest(name=name):
                path = directory / name
                original = path.read_bytes()
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    self.authority()
                self.assertFalse(path.exists())
                SUBJECT.write_new(path, original)

    def test_record_symlinks_are_rejected_without_following_target(self):
        self.create_worker()
        directory = self.root / "worker-authority"
        outside = self.parent / "untouched-record"
        outside.write_bytes(b"owned negative-control sentinel\n")
        before = outside.read_bytes(), SUBJECT.metadata(outside.lstat())
        for name in (".owner.lock", ".owner.json"):
            with self.subTest(name=name):
                path = directory / name
                original = path.read_bytes()
                path.unlink()
                path.symlink_to(outside)
                with self.assertRaises(OSError):
                    self.authority()
                self.assertEqual((outside.read_bytes(), SUBJECT.metadata(outside.lstat())), before)
                path.unlink()
                SUBJECT.write_new(path, original)

    def test_authority_directory_symlink_is_rejected(self):
        self.create_worker()
        directory = self.root / "worker-authority"
        retained = self.root / "retained-authority"
        directory.rename(retained)
        outside = self.parent / "outside-authority"
        outside.mkdir(mode=0o700)
        directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.authority(provision=True)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual({p.name for p in retained.iterdir()}, {".owner.lock", ".owner.json"})

    def test_authority_records_require_single_link(self):
        self.create_worker()
        directory = self.root / "worker-authority"
        for name in (".owner.lock", ".owner.json"):
            with self.subTest(name=name):
                source = directory / name
                extra = self.parent / "extra-link"
                os.link(source, extra)
                before = source.read_bytes()
                with self.assertRaisesRegex(RuntimeError, "single-link"):
                    self.authority()
                self.assertEqual(source.read_bytes(), before)
                extra.unlink()

    def test_private_directories_and_records_require_exact_modes(self):
        self.create_worker()
        cases = [(self.root, 0o755), (self.root / "worker-authority", 0o755),
                 (self.root / "worker-state", 0o755),
                 (self.root / "worker-authority" / ".owner.lock", 0o644),
                 (self.root / "worker-authority" / ".owner.json", 0o644)]
        for path, bad_mode in cases:
            with self.subTest(path=path.name):
                original_mode = stat.S_IMODE(path.lstat().st_mode)
                path.chmod(bad_mode)
                with self.assertRaises(RuntimeError):
                    self.authority()
                path.chmod(original_mode)

    def test_same_bytes_replaced_record_changes_readback_identity(self):
        self.create_worker()
        before = self.authority()
        path = self.root / "worker-authority" / ".owner.json"
        retained = self.root / "original-owner-record"
        path.rename(retained)
        SUBJECT.write_new(path, retained.read_bytes())
        after = self.authority()
        self.assertEqual(before["owner_document"], after["owner_document"])
        self.assertEqual(before["owner"]["sha256"], after["owner"]["sha256"])
        self.assertNotEqual(before["owner"]["ino"], after["owner"]["ino"])
        self.assertNotEqual(before, after)

    def test_partial_creation_is_retained_and_never_silently_repaired(self):
        self.create_worker()
        directory = self.root / "worker-authority"
        for path in directory.iterdir():
            path.unlink()
        real_write = SUBJECT.write_new

        def fail_owner(path, data, mode=0o600):
            if Path(path).name == ".owner.json":
                raise OSError("injected create failure")
            return real_write(path, data, mode)

        with mock.patch.object(SUBJECT, "write_new", side_effect=fail_owner):
            with self.assertRaisesRegex(OSError, "injected create failure"):
                self.authority(provision=True)
        self.assertEqual((directory / ".owner.lock").read_bytes(), b"")
        self.assertFalse((directory / ".owner.json").exists())
        with self.assertRaisesRegex(RuntimeError, "not empty"):
            self.authority(provision=True)
        with self.assertRaises(FileNotFoundError):
            self.authority()


if __name__ == "__main__":
    unittest.main()
