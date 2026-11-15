#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Synthetic admission-enrollment tests. No live services are touched."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "effect_owner_enrollment", ROOT / "deploy" / "effect_owner_enrollment.py")
assert SPEC and SPEC.loader
SPEC.loader.exec_module(__import__("sys").modules.setdefault(
    "effect_owner_enrollment", importlib.util.module_from_spec(SPEC)))
import effect_owner_enrollment as E

HASH = "a" * 64
DIRECTORY = "/authority/private-owner"
V4 = "/state/v4"
V10 = "/state/v10"
V11 = "/state/v11"


def healthy():
    return {
        "v4": {"pid": 12, "state_root": V4, "runtime_binary_sha256": HASH,
               "env": {"HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "1",
                       "HEPTA_EFFECT_OWNER_FENCE_DIR": DIRECTORY,
                       "HEPTA_EFFECT_OWNER_SELF": "v4"}},
        "v10": {"pid": 14, "state_root": V10, "runtime_binary_sha256": HASH,
                "env": {"HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "1"}},
        "v11": {"pid": 16, "state_root": V11, "runtime_binary_sha256": HASH,
                "env": {"HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "1",
                        "HEPTA_EFFECT_OWNER_FENCE_DIR": DIRECTORY,
                        "HEPTA_EFFECT_OWNER_SELF": "v11"}}}


def authority():
    return {"schema": E.SCHEMA, "owner": "v4", "phase": "admitting",
            "epoch": 17, "state_root": V4}


class EnrollmentTests(unittest.TestCase):
    def test_healthy_enrolled_controllers_are_only_ready_for_freeze(self):
        record = E.assess(healthy(), authority(), HASH)
        self.assertEqual(record["stage"], "READY_FOR_FROZEN_PHASE_TEST_ONLY")
        self.assertFalse(record["cutover_authorized"])
        self.assertTrue(record["all_fence_required"])
        self.assertEqual(record["checks_failed"], [])
        self.assertNotIn(DIRECTORY, json.dumps(record))
        self.assertNotIn(V4, json.dumps(record))

    def test_live_unfenced_controllers_cannot_claim_readiness(self):
        vals = healthy()
        for role in vals:
            vals[role]["env"] = {}
        result = E.assess(vals, None)
        self.assertEqual(result["stage"], "HOLD")
        self.assertFalse(result["all_fence_required"])
        self.assertIn("v4_fence_not_enforced", result["checks_failed"])
        self.assertIn("v11_fence_not_enforced", result["checks_failed"])
        self.assertIn("reviewed_binary_sha256_not_supplied", result["checks_failed"])

    def test_missing_service_and_wrong_pinned_binary_refuse(self):
        vals = healthy()
        vals["v4"]["runtime_binary_sha256"] = "b" * 64
        vals["v11"]["pid"] = 0
        r = E.assess(vals, authority(), HASH)
        self.assertIn("v4_unreviewed_binary", r["checks_failed"])
        self.assertIn("v11_controller_not_observed", r["checks_failed"])

    def test_shared_directory_and_state_identity_must_agree(self):
        vals = healthy()
        vals["v11"]["env"]["HEPTA_EFFECT_OWNER_FENCE_DIR"] = "/other"
        vals["v11"]["state_root"] = V4
        r = E.assess(vals, authority(), HASH)
        self.assertIn("controller_fence_root_not_shared", r["checks_failed"])
        self.assertIn("successor_state_not_independent", r["checks_failed"])

    def test_predecessor_must_explicitly_reject_new_effects(self):
        vals = healthy()
        vals["v10"]["env"]["HEPTA_EFFECT_OWNER_SELF"] = "v4"
        vals["v10"]["env"]["HEPTA_EFFECT_OWNER_FENCE_DIR"] = DIRECTORY
        vals["v10"]["state_root"] = V4
        r = E.assess(vals, authority(), HASH)
        self.assertIn("v10_must_not_claim_new_effect_owner", r["checks_failed"])
        self.assertIn("predecessor_state_aliases_effect_owner", r["checks_failed"])

    def test_wrong_owner_phase_or_state_refuse(self):
        for changes in ({"owner": "v11"}, {"phase": "unknown"},
                        {"state_root": "/other"}):
            with self.subTest(changes=changes):
                record = authority()
                record.update(changes)
                self.assertEqual(E.assess(healthy(), record, HASH)["stage"], "HOLD")

    def test_raw_environment_is_never_emitted_or_duplicate_accepted(self):
        raw = (b"SECRET_PASSWORD=SECRET-DO-NOT-PRINT\0"
               b"HEPTA_EFFECT_OWNER_FENCE_REQUIRED=1\0"
               b"HEPTA_EFFECT_OWNER_SELF=v4\0")
        parsed = E.selected_environ(raw)
        self.assertEqual(set(parsed), {
            "HEPTA_EFFECT_OWNER_FENCE_REQUIRED", "HEPTA_EFFECT_OWNER_SELF"})
        self.assertNotIn("SECRET-DO-NOT-PRINT", repr(parsed))
        with self.assertRaisesRegex(ValueError, "duplicate_fence_environment"):
            E.selected_environ(raw + b"HEPTA_EFFECT_OWNER_SELF=v11\0")

    def test_private_authority_rejects_untrusted_file_modes_and_links(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "authority"
            root.mkdir(mode=0o700)
            record = authority()
            owner = root / ".owner.json"
            lock = root / ".owner.lock"
            owner.write_text(json.dumps(record))
            lock.write_text("")
            owner.chmod(0o600)
            lock.chmod(0o600)
            self.assertEqual(E.inspect_authority(str(root))["owner"], "v4")
            lock.chmod(0o644)
            with self.assertRaises(ValueError):
                E.inspect_authority(str(root))
            lock.chmod(0o600)
            alias = root / ".owner.json.alias"
            os.link(owner, alias)
            with self.assertRaises(ValueError):
                E.inspect_authority(str(root))

    def test_authority_root_rebinding_fails_even_with_pinned_fd(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "owner"
            root.mkdir(mode=0o700)
            (root / ".owner.json").write_text(json.dumps(authority()))
            (root / ".owner.lock").write_text("")
            (root / ".owner.json").chmod(0o600)
            (root / ".owner.lock").chmod(0o600)
            checked = E.strict_json
            def swap(raw):
                original = checked(raw)
                root.rename(Path(base) / "old-owner")
                root.mkdir(mode=0o700)
                return original
            with mock.patch.object(E, "strict_json", side_effect=swap):
                with self.assertRaisesRegex(ValueError, "authority_root_rebound"):
                    E.inspect_authority(str(root))

    def test_config_parsing_rejects_duplicate_json_keys(self):
        with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
            E.strict_json(b'{"state_dir":"/s","state_dir":"/other"}')

    def test_internal_responses_do_not_authorize_cutover_on_any_path(self):
        self.assertFalse(E.assess(healthy(), authority(), HASH)["cutover_authorized"])
        self.assertFalse(E.assess(healthy(), authority(), None)["cutover_authorized"])
        self.assertFalse(E.assess({}, None)["cutover_authorized"])


if __name__ == "__main__":
    unittest.main()
