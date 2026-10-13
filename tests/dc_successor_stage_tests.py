#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline successor staging integrity, refusal and credential-boundary tests.

Fixtures use a real, tiny committed Git repository and inert executable bytes.
They neither start native binaries nor access services, SSH peers or credentials.
"""
import argparse
import contextlib
import copy
import errno
import hashlib
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import stage_dc_successor as S
from mcp_tool_contract import make_contract

V4_SHA = "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1"
NAMES = {
    "candidate-native", "chatgpt_full_operator.py", "mcp_tool_contract.py",
    "contract.json", "previous-contract.json", "rollback-native",
    "rollback-facade.py", "rollback-helper.py", "rollback-contract.json",
    "manifest.json", "candidate-commands.json", "candidate-profile-template.json",
    "native-dropin.conf", "activation-plan.json", "rollback-plan.json",
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def snapshot(root):
    """Include bytes, type and permissions so refusal proves no input mutation."""
    result = {}
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts:
            continue
        info = path.lstat()
        result[str(path.relative_to(root))] = (
            stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode),
            os.readlink(path) if path.is_symlink() else
            digest(path.read_bytes()) if path.is_file() else None,
        )
    return result


class SuccessorStage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-successor-stage-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        write(self.source / "src/main.rs", b"fn main() {}\n")
        write(self.source / "src/nested/fixture.py", b"VALUE = 1\n")
        write(self.source / "Cargo.toml", b'[package]\nname = "stage-fixture"\nversion = "0.0.0"\nedition = "2024"\n')
        write(self.source / "Cargo.lock", b"# fixture lock\nversion = 4\n")
        self.v4raw = (ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json").read_bytes()
        self.assertEqual(digest(self.v4raw), V4_SHA)
        write(self.source / "deploy/contracts/hepta-runtime-full-operator-v4.json", self.v4raw)
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=Offline fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--quiet", "-m", "committed offline source fixture")
        original_patch = mock.patch.object(S, "ORIGINAL_V4",
                                          self.source / "deploy/contracts/hepta-runtime-full-operator-v4.json")
        original_patch.start()
        self.addCleanup(original_patch.stop)
        identity = S.source_identity(self.source)
        self.identity = identity
        self.marker = self.root / "native-was-executed"
        native = write(self.inputs / "candidate-native",
                       ("#!/bin/sh\n: > '" + str(self.marker) + "'\nexit 97\n").encode(), 0o700)
        facade = write(self.inputs / "candidate-facade.py", b"# inert candidate facade\n")
        helper = write(self.inputs / "candidate-helper.py", b"# inert candidate helper\n")
        self.previous = json.loads((ROOT / "deploy/contracts/hepta-runtime-full-operator-v6.json").read_bytes())
        self.current = copy.deepcopy(self.previous)
        v4names = {tool["name"] for tool in json.loads(self.v4raw)["tools"]}
        self.extra_name = sorted({tool["name"] for tool in self.current["tools"]} - v4names)[0]
        next(t for t in self.current["tools"] if t["name"] == self.extra_name)["description"] += " Offline staged description revision."
        self.current["tools"].append({
            "name": "stage_fixture_probe", "description": "Offline fixture catalog addition.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {"readOnlyHint": True, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False},
        })
        contract = write(self.inputs / "contract.json", self.contract_bytes(self.current))
        previous = write(self.inputs / "previous-contract.json", self.contract_bytes(self.previous))
        self.live = self.root / "live"
        self.live.mkdir(mode=0o700)
        self.secret = "STAGE_TEST_SECRET_MUST_NEVER_BE_READ_OR_COPIED_97f019"
        self.secret_paths = []
        live_refs = {}
        for name in ("profile", "installed_manifest", "runtime_config", "unit_dropin"):
            path = write(self.live / name, (self.secret + ":" + name).encode())
            self.secret_paths.append(path)
            live_refs[name] = {"path": str(path), "sha256": digest(path.read_bytes())}
        token = write(self.live / "token", self.secret.encode())
        self.secret_paths.append(token)
        baseline_artifacts = {}
        for name, raw in (("native", b"#!/bin/sh\nexit 98\n"),
                          ("facade", b"# immutable rollback facade\n"),
                          ("helper", b"# immutable rollback helper\n"),
                          ("contract", self.v4raw)):
            path = write(self.inputs / ("baseline-" + name), raw, 0o700 if name == "native" else 0o600)
            baseline_artifacts[name] = {"path": str(path), "sha256": digest(raw)}
        self.baseline = {
            "schema": "hepta-installed-baseline-pins-v1", **baseline_artifacts,
            "live_files": live_refs,
            "state_directory": str(self.live / "state"),
            "auth_token_file": str(token),
        }
        pins = write(self.inputs / "baseline-pins.json", self.json_bytes(self.baseline))
        receipts = []
        for name in ("native-regression", "facade-regression", "six-host-observation"):
            raw = self.json_bytes({"name": name, "status": "UNVERIFIED", "qualification": False})
            path = write(self.inputs / (name + ".json"), raw)
            receipts.append([name, str(path), digest(raw)])
        workspace = self.root / "workspace"
        workspace.mkdir(mode=0o700)
        self.args = argparse.Namespace(
            source_root=self.source, source_head=identity["base_HEAD"],
            compiled_source_fingerprint=identity["source_code_fingerprint"],
            native=native, native_sha256=digest(native.read_bytes()),
            facade=facade, facade_sha256=digest(facade.read_bytes()),
            helper=helper, helper_sha256=digest(helper.read_bytes()),
            contract=contract, contract_sha256=digest(contract.read_bytes()),
            previous_contract=previous, previous_contract_sha256=digest(previous.read_bytes()),
            receipt=receipts, destination=self.root / "release",
            token_file=token, runtime_config=pathlib.Path(live_refs["runtime_config"]["path"]),
            controller_workspace=workspace, upstream="http://127.0.0.1:8790/mcp",
            baseline_pins=pins, baseline_pins_sha256=digest(pins.read_bytes()),
        )

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.source), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()

    @staticmethod
    def json_bytes(value):
        return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()

    def contract_bytes(self, value):
        return self.json_bytes(make_contract(value["tools"]))

    def update_contract(self, value, previous=False):
        field = "previous_contract" if previous else "contract"
        raw = self.contract_bytes(value)
        write(getattr(self.args, field), raw)
        setattr(self.args, field + "_sha256", digest(raw))

    def update_baseline(self):
        raw = self.json_bytes(self.baseline)
        write(self.args.baseline_pins, raw)
        self.args.baseline_pins_sha256 = digest(raw)

    def assert_refuses_without_mutation(self):
        before = snapshot(self.root)
        with self.assertRaises((ValueError, PermissionError, FileNotFoundError, FileExistsError, OSError)):
            S.stage(self.args)
        self.assertEqual(snapshot(self.root), before)
        self.assertFalse(self.args.destination.exists())
        self.assertFalse(self.marker.exists())

    def test_prepare_validates_without_creating_destination_or_modifying_inputs(self):
        before = snapshot(self.root)
        bundle = S.prepare_stage(self.args)
        self.assertIsInstance(bundle, dict)
        self.assertEqual(snapshot(self.root), before)
        self.assertFalse(self.args.destination.exists())
        self.assertFalse(self.marker.exists())

    def test_source_identity_uses_the_complete_independently_hashed_source_map(self):
        entries = {}
        for relative in ("Cargo.lock", "Cargo.toml", "src/main.rs", "src/nested/fixture.py"):
            raw = (self.source / relative).read_bytes()
            entries[relative] = {"bytes": len(raw), "sha256": digest(raw)}
        canonical = json.dumps(entries, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False).encode()
        self.assertEqual(self.identity["source_files"], entries)
        self.assertEqual(self.identity["source_code_fingerprint"], digest(canonical))
        self.assertIs(self.identity["dirty_source"], False)

    def test_staging_executes_only_git_identity_checks(self):
        original = subprocess.run
        original_popen = subprocess.Popen
        observed = []
        def check_argv(argv):
            self.assertIsInstance(argv, list)
            self.assertEqual(argv[:3], ["git", "-C", str(self.source)])
            allowed = {
                "rev-parse": ["rev-parse", "HEAD"],
                "diff": ["diff", "--name-only", "--no-renames", "-z", "HEAD", "--", "src", "Cargo.toml", "Cargo.lock"],
                "ls-files": ["ls-files", "--cached", "-z", "--", "src", "Cargo.toml", "Cargo.lock"],
            }
            self.assertIn(argv[3], allowed)
            self.assertEqual(argv[3:], allowed[argv[3]])
        def git_only(argv, *args, **kwargs):
            check_argv(argv)
            observed.append(argv[3])
            return original(argv, *args, **kwargs)
        def popen_git_only(argv, *args, **kwargs):
            check_argv(argv)
            return original_popen(argv, *args, **kwargs)
        with mock.patch.object(S.subprocess, "run", side_effect=git_only):
            with mock.patch.object(S.subprocess, "Popen", side_effect=popen_git_only):
                S.stage(self.args)
        self.assertEqual(observed.count("rev-parse"), 2)
        self.assertEqual(observed.count("diff"), 2)
        self.assertEqual(observed.count("ls-files"), 2)
        self.assertFalse(self.marker.exists())

    def test_stage_copies_exact_artifacts_with_private_modes_and_honest_hold(self):
        result = S.stage(self.args)
        dest = self.args.destination
        self.assertEqual({p.name for p in dest.iterdir()}, NAMES)
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o700)
        pairs = {
            "candidate-native": self.args.native, "chatgpt_full_operator.py": self.args.facade,
            "mcp_tool_contract.py": self.args.helper, "contract.json": self.args.contract,
            "previous-contract.json": self.args.previous_contract,
            **{"rollback-" + name + (".py" if name in ("facade", "helper") else ".json" if name == "contract" else ""):
               pathlib.Path(self.baseline[name]["path"]) for name in ("native", "facade", "helper", "contract")},
        }
        for name, origin in pairs.items():
            self.assertEqual((dest / name).read_bytes(), origin.read_bytes(), name)
        manifest = json.loads((dest / "manifest.json").read_bytes())
        for path in dest.iterdir():
            expected = 0o700 if path.name in ("candidate-native", "rollback-native") else 0o600
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path.name)
        for name, value in manifest["artifacts"].items():
            raw = (dest / name).read_bytes()
            self.assertEqual(value["sha256"], digest(raw), name)
            self.assertEqual(value["bytes"], len(raw), name)
            expected = "0700" if name in ("candidate-native", "rollback-native") else "0600"
            self.assertEqual(value["mode"], expected, name)
        self.assertEqual(manifest["schema"], "hepta-dc-successor-stage-v1")
        self.assertIs(manifest["staged"], True)
        self.assertIs(manifest["activated"], False)
        self.assertIs(manifest["full_dc_replacement_qualified"], False)
        self.assertEqual(manifest["plan_status"], "HOLD")
        self.assertEqual(manifest["source"]["base_HEAD"], self.identity["base_HEAD"])
        self.assertEqual(manifest["source"]["source_code_fingerprint"], self.identity["source_code_fingerprint"])
        self.assertEqual(result["manifest_sha256"], digest((dest / "manifest.json").read_bytes()))
        self.assertIs(manifest["receipts_execution_or_success_inferred"], False)
        self.assertFalse(self.marker.exists())

    def test_concrete_activation_and_rollback_plans_preserve_dynamic_inventory_and_rescue(self):
        S.stage(self.args)
        dest = self.args.destination
        activation = json.loads((dest / "activation-plan.json").read_bytes())
        rollback = json.loads((dest / "rollback-plan.json").read_bytes())
        commands = json.loads((dest / "candidate-commands.json").read_bytes())
        profile = json.loads((dest / "candidate-profile-template.json").read_bytes())
        for plan in (activation, rollback):
            self.assertEqual(plan["status"], "HOLD")
            self.assertIs(plan["performed"], False)
            self.assertIs(plan["inventory"]["fixed_historical_counts_used"], False)
            self.assertIs(plan["inventory"]["old_missing_nonce_auto_cancel_allowed"], False)
            self.assertIs(plan["inventory"]["old_job_archive_read_does_not_grant_cancel_authority"], True)
        self.assertEqual(activation["protected_rescue_unit"], "desktop-commander-remote.service")
        self.assertEqual(activation["baseline_live_files"], self.baseline["live_files"])
        self.assertEqual(activation["new_dropin_content"], str(dest / "native-dropin.conf"))
        self.assertEqual(activation["new_dropin_path"], str(self.live / "70-parity-successor.conf"))
        self.assertEqual(rollback["restore_exact_private_backups_of"],
                         {role: self.baseline["live_files"][role] for role in ("profile", "installed_manifest")})
        self.assertEqual(rollback["existing_dropin_preserved"], self.baseline["live_files"]["unit_dropin"])
        self.assertEqual(rollback["runtime_config_reference_unchanged"], self.baseline["live_files"]["runtime_config"])
        self.assertEqual(rollback["remove_only_activation_owned_successor_dropin"], activation["new_dropin_path"])
        updates = activation["installed_manifest_field_updates"]
        self.assertEqual(updates["release"], str(dest))
        self.assertEqual(updates["facade_sha256"], self.args.facade_sha256)
        self.assertEqual(updates["contract_sha256"], self.args.contract_sha256)
        self.assertEqual(updates["tools"], len(self.current["tools"]))
        self.assertIs(activation["preserve_other_installed_manifest_fields"], True)
        self.assertIs(rollback["restore_or_delete_state_directory"], False)
        self.assertIs(rollback["rollback_qualified_by_staging"], False)
        for role, reference in rollback["baseline_artifacts"].items():
            self.assertEqual(reference["sha256"], self.baseline[role]["sha256"])
            self.assertEqual(digest(pathlib.Path(reference["path"]).read_bytes()), reference["sha256"])
        self.assertIs(commands["commands_executed"], False)
        self.assertIn(str(self.args.runtime_config), commands["native_argv"])
        self.assertIn(str(self.args.token_file), commands["native_argv"])
        self.assertIs(profile["is_runnable_tunnel_profile"], False)
        self.assertIs(profile["candidate_profile_started"], False)
        self.assertIs(profile["live_profile_not_read"], True)

    def test_manifest_reports_real_delta_without_original_v4_drift(self):
        S.stage(self.args)
        manifest = json.loads((self.args.destination / "manifest.json").read_bytes())
        catalog = manifest["catalog"]
        self.assertIs(catalog["original_v4_definitions_exact"], True)
        self.assertEqual(catalog["tool_count"], len(self.current["tools"]))
        delta = catalog["delta_from_previous"]
        self.assertEqual(delta["added"], ["stage_fixture_probe"])
        self.assertEqual(delta["removed"], [])
        self.assertEqual(delta["changed"], [{"name": self.extra_name, "changed_fields": ["description"]}])
        baseline_delta = catalog["delta_from_v4"]
        v4names = {t["name"] for t in json.loads(self.v4raw)["tools"]}
        self.assertEqual(set(baseline_delta["added"]), {t["name"] for t in self.current["tools"]} - v4names)
        self.assertEqual(baseline_delta["removed"], [])
        self.assertEqual(baseline_delta["changed"], [])

    def test_late_missing_or_corrupt_receipt_leaves_destination_absent(self):
        self.args.receipt.append(["late-missing", str(self.inputs / "missing.json"), "0" * 64])
        self.assert_refuses_without_mutation()
        self.args.receipt.pop()
        self.args.receipt[-1][2] = "0" * 64
        self.assert_refuses_without_mutation()

    def test_each_candidate_or_baseline_pin_digest_is_enforced(self):
        for field in ("native_sha256", "facade_sha256", "helper_sha256", "contract_sha256",
                      "previous_contract_sha256", "baseline_pins_sha256"):
            with self.subTest(field=field):
                original = getattr(self.args, field)
                setattr(self.args, field, "0" * 64)
                self.assert_refuses_without_mutation()
                setattr(self.args, field, original)
        for name in ("native", "facade", "helper", "contract"):
            with self.subTest(baseline=name):
                original = self.baseline[name]["sha256"]
                self.baseline[name]["sha256"] = "0" * 64
                self.update_baseline()
                self.assert_refuses_without_mutation()
                self.baseline[name]["sha256"] = original
                self.update_baseline()

    def test_existing_destination_is_never_reused_or_repaired(self):
        self.args.destination.mkdir(mode=0o700)
        write(self.args.destination / "unchanged", b"existing release marker")
        before = snapshot(self.root)
        with self.assertRaises((FileExistsError, ValueError, PermissionError)):
            S.stage(self.args)
        self.assertEqual(snapshot(self.root), before)

    def test_late_publication_write_failure_cleans_only_the_new_release(self):
        original = os.open
        def fail_late(path, flags, *args, **kwargs):
            if path == "activation-plan.json" and flags & os.O_WRONLY:
                raise OSError(errno.EIO, "injected late offline write failure")
            return original(path, flags, *args, **kwargs)
        before = snapshot(self.root)
        with mock.patch.object(S.os, "open", side_effect=fail_late):
            with self.assertRaises(OSError):
                S.stage(self.args)
        self.assertEqual(snapshot(self.root), before)
        self.assertFalse(self.args.destination.exists())
        self.assertFalse(self.marker.exists())

    def test_candidate_input_final_and_parent_symlinks_are_refused(self):
        original = self.args.facade
        alias = self.inputs / "facade-alias.py"
        alias.symlink_to(original)
        self.args.facade = alias
        self.assert_refuses_without_mutation()
        parent_alias = self.root / "input-alias"
        parent_alias.symlink_to(self.inputs, target_is_directory=True)
        self.args.facade = parent_alias / original.name
        self.assert_refuses_without_mutation()

    def test_destination_parent_and_leaf_symlinks_are_refused(self):
        real = self.root / "real-output-parent"
        real.mkdir(mode=0o700)
        alias = self.root / "output-alias"
        alias.symlink_to(real, target_is_directory=True)
        self.args.destination = alias / "new-release"
        self.assert_refuses_without_mutation()
        target = write(real / "untouched", b"must remain unchanged")
        leaf = self.root / "release-leaf-alias"
        leaf.symlink_to(target)
        self.args.destination = leaf
        before = snapshot(self.root)
        with self.assertRaises((FileExistsError, ValueError, PermissionError, OSError)):
            S.stage(self.args)
        self.assertEqual(snapshot(self.root), before)

    def test_fifo_without_writer_is_refused_within_subprocess_deadline(self):
        fifo = self.inputs / "facade-fifo"
        os.mkfifo(fifo, 0o600)
        self.args.facade = fifo
        before = snapshot(self.root)
        command = [sys.executable, str(ROOT / "deploy/stage_dc_successor.py")]
        for key, value in vars(self.args).items():
            if key == "receipt":
                for receipt in value:
                    command.extend(["--receipt", *receipt])
            else:
                command.extend(["--" + key.replace("_", "-"), str(value)])
        # A timeout is a test failure; run() kills and reaps its child so the
        # regression cannot strand a test runner waiting for a FIFO writer.
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr), {
            "staged": False, "activated": False, "error_type": "ValueError"})
        self.assertEqual(result.stdout, "")
        self.assertEqual(snapshot(self.root), before)
        self.assertFalse(self.args.destination.exists())
        self.assertFalse(self.marker.exists())

    def test_hardlinked_or_other_writable_inputs_are_refused(self):
        linked = self.inputs / "facade-second-link"
        os.link(self.args.facade, linked)
        self.assert_refuses_without_mutation()
        linked.unlink()
        self.args.facade.chmod(0o622)
        self.assert_refuses_without_mutation()

    def test_foreign_uid_is_rejected_even_with_valid_digest(self):
        info = list(self.args.facade.stat())
        info[4] = 54321
        with mock.patch.object(S.os, "getuid", return_value=12345):
            with self.assertRaises(PermissionError):
                S.validate_inode(os.stat_result(info), "foreign fixture")

    def test_head_and_every_full_source_component_are_bound(self):
        self.args.source_head = "0" * 40
        self.assert_refuses_without_mutation()
        self.args.source_head = self.identity["base_HEAD"]
        for relative in ("src/main.rs", "src/nested/fixture.py", "Cargo.toml", "Cargo.lock"):
            with self.subTest(relative=relative):
                path = self.source / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n# changed after compile pin\n")
                self.assert_refuses_without_mutation()
                path.write_bytes(original)
        write(self.source / "src/untracked.rs", b"// uncommitted source\n")
        self.assert_refuses_without_mutation()

    def test_deleted_tracked_source_cannot_be_hidden_by_a_refreshed_compile_pin(self):
        (self.source / "src/nested/fixture.py").unlink()
        identity = S.source_identity(self.source)
        self.args.compiled_source_fingerprint = identity["source_code_fingerprint"]
        self.assert_refuses_without_mutation()

    def test_ignored_untracked_compile_input_cannot_claim_a_committed_fingerprint(self):
        write(self.source / ".gitignore", b"src/ignored.py\n")
        write(self.source / "src/ignored.py", b"UNCOMMITTED = True\n")
        self.args.compiled_source_fingerprint = S.source_identity(self.source)["source_code_fingerprint"]
        self.assert_refuses_without_mutation()

    def test_generated_noncode_lock_sidecar_does_not_invalidate_committed_source(self):
        write(self.source / "src/main.rs.hepta-lock", b"generated lock metadata\n")
        self.assertIs(S.source_identity(self.source)["dirty_source"], False)
        result = S.stage(self.args)
        self.assertIs(result["staged"], True)
        self.assertIs(result["activated"], False)

    def test_original_v4_definition_drift_and_tool_removal_are_refused(self):
        drift = copy.deepcopy(self.current)
        name = json.loads(self.v4raw)["tools"][0]["name"]
        next(t for t in drift["tools"] if t["name"] == name)["description"] += " forbidden drift"
        self.update_contract(drift)
        self.assert_refuses_without_mutation()
        removed = copy.deepcopy(self.current)
        removed["tools"] = [t for t in removed["tools"] if t["name"] != name]
        self.update_contract(removed)
        self.assert_refuses_without_mutation()

    def test_retained_tool_annotations_cannot_be_silently_changed(self):
        drift = copy.deepcopy(self.current)
        tool = next(t for t in drift["tools"] if t["name"] == self.extra_name)
        tool["annotations"]["idempotentHint"] = not tool["annotations"]["idempotentHint"]
        self.update_contract(drift)
        self.assert_refuses_without_mutation()

    def test_newer_schema_changes_and_removal_are_reported_truthfully_without_qualification(self):
        drift = copy.deepcopy(self.current)
        tool = next(t for t in drift["tools"] if t["name"] == self.extra_name)
        tool["inputSchema"].setdefault("properties", {})["stage_unreviewed"] = {"type": "string"}
        other = next(t["name"] for t in self.previous["tools"]
                     if t["name"] not in {v["name"] for v in json.loads(self.v4raw)["tools"]}
                     and t["name"] != self.extra_name)
        drift["tools"] = [t for t in drift["tools"] if t["name"] != other]
        self.update_contract(drift)
        S.stage(self.args)
        manifest = json.loads((self.args.destination / "manifest.json").read_bytes())
        delta = manifest["catalog"]["delta_from_previous"]
        self.assertEqual(delta["removed"], [other])
        self.assertEqual(delta["changed"], [{"name": self.extra_name,
                                           "changed_fields": ["description", "inputSchema"]}])
        self.assertIs(manifest["full_dc_replacement_qualified"], False)
        self.assertEqual(manifest["plan_status"], "HOLD")

    def test_previous_contract_cannot_lie_about_original_v4_definitions(self):
        previous = copy.deepcopy(self.previous)
        name = json.loads(self.v4raw)["tools"][0]["name"]
        next(t for t in previous["tools"] if t["name"] == name)["description"] += " forged previous"
        self.update_contract(previous, previous=True)
        self.assert_refuses_without_mutation()

    def test_secret_live_files_are_never_opened_copied_or_output(self):
        forbidden = {str(p) for p in self.secret_paths}
        def guarded(original):
            def call(path, *args, **kwargs):
                if isinstance(path, (str, bytes, os.PathLike)):
                    candidate = os.fsdecode(path)
                    if not os.path.isabs(candidate) and kwargs.get("dir_fd") is not None:
                        parent = os.readlink("/proc/self/fd/" + str(kwargs["dir_fd"]))
                        candidate = os.path.join(parent, candidate)
                    if candidate in forbidden:
                        raise AssertionError("stager opened a live credential/configuration file")
                return original(path, *args, **kwargs)
            return call
        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch("builtins.open", guarded(open)))
            stack.enter_context(mock.patch.object(io, "open", guarded(io.open)))
            stack.enter_context(mock.patch.object(os, "open", guarded(os.open)))
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(contextlib.redirect_stderr(output))
            S.stage(self.args)
        self.assertNotIn(self.secret, output.getvalue())
        for path in self.args.destination.iterdir():
            self.assertNotIn(self.secret.encode(), path.read_bytes(), path.name)
        manifest = json.loads((self.args.destination / "manifest.json").read_bytes())
        self.assertIs(manifest["live_files_accessed"], False)
        self.assertIs(manifest["credentials_copied"], False)
        self.assertFalse(self.marker.exists())

    def test_untrusted_publication_parent_refuses_before_creating_stage(self):
        original_fstat = os.fstat
        for reason in ("writable", "foreign_owner"):
            with self.subTest(reason=reason):
                parent = self.root / ("publication-parent-" + reason)
                parent.mkdir(mode=0o700)
                self.args.destination = parent / "release"
                if reason == "writable":
                    parent.chmod(0o777)
                pin = parent.stat()
                def untrusted_parent(descriptor):
                    info = original_fstat(descriptor)
                    if reason == "foreign_owner" and (info.st_dev, info.st_ino) == (pin.st_dev, pin.st_ino):
                        fields = list(info)
                        fields[4] = os.getuid() + 100000
                        return os.stat_result(fields)
                    return info
                before = snapshot(self.root)
                with mock.patch.object(os, "fstat", side_effect=untrusted_parent):
                    with self.assertRaisesRegex(PermissionError, "publication parent"):
                        S.stage(self.args)
                self.assertEqual(snapshot(self.root), before)
                self.assertFalse(self.args.destination.exists())
                self.assertFalse(self.marker.exists())

    def test_replaced_stage_directory_is_never_removed_during_failure_cleanup(self):
        original_stat = os.stat
        for empty in (True, False):
            with self.subTest(empty_replacement=empty):
                self.args.destination = self.root / ("race-stage-" + str(empty))
                destination = self.args.destination
                displaced = self.root / ("displaced-stage-" + str(empty))
                replaced = False
                def replace_before_path_check(path, *arguments, **kwargs):
                    nonlocal replaced
                    if path == destination.name and kwargs.get("dir_fd") is not None and not replaced:
                        try:
                            original_stat(destination / "manifest.json")
                        except FileNotFoundError:
                            pass
                        else:
                            destination.rename(displaced)
                            destination.mkdir(mode=0o700)
                            if not empty:
                                write(destination / "foreign-marker", b"replacement must survive")
                            replaced = True
                    return original_stat(path, *arguments, **kwargs)
                with mock.patch.object(os, "stat", side_effect=replace_before_path_check):
                    with self.assertRaisesRegex(ValueError, "pathname changed"):
                        S.stage(self.args)
                self.assertTrue(replaced)
                self.assertTrue(destination.is_dir())
                self.assertEqual(list(displaced.iterdir()), [])
                if empty:
                    self.assertEqual(list(destination.iterdir()), [])
                else:
                    self.assertEqual((destination / "foreign-marker").read_bytes(), b"replacement must survive")
                self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
