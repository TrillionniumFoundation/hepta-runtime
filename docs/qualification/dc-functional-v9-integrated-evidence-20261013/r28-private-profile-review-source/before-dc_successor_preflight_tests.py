#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline successor preflight integrity and secret-boundary regressions.

A tiny committed Git source and a real stage manifest provide immutable inputs.
All production inventory/service/process probes are synthetic and injected.
These tests never call live MCP, SSH, service control, or executable candidates.
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
import preflight_dc_successor as P
from mcp_tool_contract import ToolContract

HOSTS = ["main", "pocket4", "rog", "mac", "x230", "ai395"]
UNITS = ["hepta-runtime-operator.service", "hepta-openai-full-operator.service",
         "desktop-commander-remote.service"]
REFUSALS = (ValueError, OSError, PermissionError, RuntimeError)
V4_SHA = "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def write(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def tree_snapshot(root):
    """No-follow byte/type/mode/link snapshot; a FIFO cannot block this test."""
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts or "__pycache__" in relative.parts:
            continue
        info = path.lstat()
        content = os.readlink(path) if stat.S_ISLNK(info.st_mode) else (
            digest(path.read_bytes()) if stat.S_ISREG(info.st_mode) else None)
        result[relative.as_posix()] = (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode),
                                      info.st_uid, info.st_nlink, content)
    return result


def values_for_key(value, key):
    if isinstance(value, dict):
        for name, item in value.items():
            if name == key:
                yield item
            yield from values_for_key(item, key)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from values_for_key(item, key)


class SuccessorPreflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-preflight-offline-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.root.chmod(0o700)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        for relative, raw in {
            "src/main.rs": b"fn main() {}\n",
            "src/nested/input.py": b"VALUE = 1\n",
            "Cargo.toml": b'[package]\nname="preflight-fixture"\nversion="0.0.0"\nedition="2024"\n',
            "Cargo.lock": b"# fixture lock\nversion = 4\n",
        }.items():
            write(self.source / relative, raw)
        self.v4raw = (ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json").read_bytes()
        self.assertEqual(digest(self.v4raw), V4_SHA)
        self.frozen_v4 = write(self.source / "deploy/contracts/hepta-runtime-full-operator-v4.json",
                               self.v4raw)
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=Offline fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--quiet", "-m", "committed preflight fixture")
        self.identity = S.source_identity(self.source)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.live = self.root / "live"
        self.live.mkdir(mode=0o700)
        self.state = self.live / "state"
        self.state.mkdir(mode=0o700)
        self.marker = self.root / "candidate-was-executed"
        candidate = write(self.inputs / "candidate-native",
            ("#!/bin/sh\n: > '" + str(self.marker) + "'\nexit 91\n").encode(), 0o700)
        facade = write(self.inputs / "candidate-facade.py", b"# inert facade\n")
        helper = write(self.inputs / "candidate-helper.py", b"# inert helper\n")
        contract = write(self.inputs / "contract.json",
            (ROOT / "deploy/contracts/hepta-runtime-full-operator-v7.json").read_bytes())
        previous = write(self.inputs / "previous.json",
            (ROOT / "deploy/contracts/hepta-runtime-full-operator-v6.json").read_bytes())
        self.token_secret = "TOKEN_VALUE_MUST_NOT_LEAVE_MEMORY_9fe4c11"
        self.profile_secret = "PROFILE_PRIVATE_BACKUP_ONLY_56bf832"
        self.token = write(self.live / "token", self.token_secret.encode())
        config = encoded({"state_dir": str(self.state),
                          "hosts": {name: {"ssh_target": name} for name in HOSTS}})
        old_facade = write(self.inputs / "old-facade.py", b"# actual installed facade fixture\n")
        old_helper = write(self.inputs / "old-helper.py", b"# actual installed helper fixture\n")
        old_native = write(self.inputs / "old-native", b"#!/bin/sh\nexit 92\n", 0o700)
        old_contract = write(self.inputs / "old-contract.json", self.v4raw)
        installed = encoded({
            "schema": "offline-installed-manifest",
            "release": str(self.inputs),
            "facade_sha256": digest(old_facade.read_bytes()),
            "contract_sha256": V4_SHA,
            "tool_contract_catalog_sha256": ToolContract(json.loads(self.v4raw)).catalog_sha256,
            "tools": 50,
        })
        profile = encoded({"mcp": {"commands": [{"channel": "main", "command": "old facade"}]},
                           "tunnel": {"private_authentication": self.profile_secret}})
        refs = {}
        for role, raw in {
            "profile": profile, "installed_manifest": installed, "runtime_config": config,
            "unit_dropin": b"[Service]\nExecStart=\nExecStart=/installed/native mcp\n",
        }.items():
            path = write(self.live / role, raw)
            refs[role] = {"path": str(path), "sha256": digest(raw)}
        self.baseline = {
            "schema": "hepta-installed-baseline-pins-v1",
            "native": {"path": str(old_native), "sha256": digest(old_native.read_bytes())},
            "facade": {"path": str(old_facade), "sha256": digest(old_facade.read_bytes())},
            "helper": {"path": str(old_helper), "sha256": digest(old_helper.read_bytes())},
            "contract": {"path": str(old_contract), "sha256": V4_SHA},
            "live_files": refs, "state_directory": str(self.state),
            "auth_token_file": str(self.token),
        }
        pins = write(self.inputs / "baseline-pins.json", encoded(self.baseline))
        self.receipt_value = {
            "schema": "hepta-successor-real-target-temporary-controller-rollback-cohort-v1",
            "complete": True, "selected_hosts": HOSTS,
            "complete_six_configured_target_cohort": True, "sealed_inputs_stable": True,
            "candidate_binary_sha256": digest(candidate.read_bytes()),
            "candidate_contract_sha256": digest(contract.read_bytes()),
            "source_before": self.identity, "source_after": self.identity,
            "full_dc_replacement_qualified": False,
            "production_service_restarted": False, "production_rollback_tested": False,
            "chatgpt_originated": False, "app_refreshed": False, "DC_off_tested": False,
        }
        self.receipt = write(self.inputs / "rollback-six.json", encoded(self.receipt_value))
        stage_args = argparse.Namespace(
            source_root=self.source, source_head=self.identity["base_HEAD"],
            compiled_source_fingerprint=self.identity["source_code_fingerprint"],
            native=candidate, native_sha256=digest(candidate.read_bytes()),
            facade=facade, facade_sha256=digest(facade.read_bytes()),
            helper=helper, helper_sha256=digest(helper.read_bytes()),
            contract=contract, contract_sha256=digest(contract.read_bytes()),
            previous_contract=previous, previous_contract_sha256=digest(previous.read_bytes()),
            baseline_pins=pins, baseline_pins_sha256=digest(pins.read_bytes()),
            receipt=[["rollback-six", str(self.receipt), digest(self.receipt.read_bytes())]],
            destination=self.root / "stage", token_file=self.token,
            runtime_config=self.live / "runtime_config", controller_workspace=self.root,
            upstream="http://127.0.0.1:8790/mcp",
        )
        with mock.patch.object(S, "ORIGINAL_V4", self.frozen_v4):
            S.stage(stage_args)
        self.stage = stage_args.destination
        self.manifest_path = self.stage / "manifest.json"
        self.manifest = json.loads(self.manifest_path.read_bytes())
        self.args = argparse.Namespace(
            stage_manifest=self.manifest_path,
            stage_manifest_sha256=digest(self.manifest_path.read_bytes()),
            source_root=self.source, output_directory=self.root / "preflight-report",
            prepare_backups=False, backup_directory=None,
        )
        self.units = {}
        for index, unit in enumerate(UNITS, start=101):
            fragment = write(self.live / ("unit-" + str(index) + ".service"),
                             ("[Service]\nExecStart=/fixture/" + unit + "\n").encode())
            dropins = [refs["unit_dropin"]] if index == 101 else []
            self.units[unit] = {
                "ActiveState": "active", "SubState": "running", "MainPID": str(index),
                "InvocationID": "fixture-" + str(index),
                "ExecMainStartTimestampMonotonic": str(index * 1000),
                "exec_start_sha256": digest(("/fixture/" + unit).encode()),
                "dropins": copy.deepcopy(dropins),
                "fragment": {"path": str(fragment), "sha256": digest(fragment.read_bytes())},
            }
        self.processes = {index: {"pid": index, "uid": os.getuid(),
             "start_ticks": index * 1000,
             "exe_sha256": self.baseline["native"]["sha256"] if index == 101 else digest(str(index).encode())}
             for index in (101, 102, 103)}
        self.inventory = {
            "hosts": HOSTS, "jobs": [], "ptys": [], "streams": [],
            "jobs_complete": True, "ptys_complete": True, "streams_complete": True,
            "dispatch": {"native_complete": False, "facade_complete": False, "admission_frozen": False},
            "errors": [],
        }
        for module in (P, S):
            if hasattr(module, "ORIGINAL_V4"):
                patch = mock.patch.object(module, "ORIGINAL_V4", self.frozen_v4)
                patch.start()
                self.addCleanup(patch.stop)

    def git(self, *arguments):
        return subprocess.run(["git", "-C", str(self.source), *arguments], check=True,
             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()

    def prepare(self, inventory=None, units=None, processes=None):
        observed = self.inventory if inventory is None else inventory
        unit_data = self.units if units is None else units
        process_data = self.processes if processes is None else processes
        return P.prepare_preflight(self.args,
             service_probe=lambda: {"units": copy.deepcopy(unit_data)},
             inventory_probe=lambda manifest: copy.deepcopy(observed),
             process_probe=lambda pid: copy.deepcopy(process_data[int(pid)]))

    def repin_manifest(self):
        write(self.manifest_path, encoded(self.manifest))
        self.args.stage_manifest_sha256 = digest(self.manifest_path.read_bytes())

    def repin_receipt(self):
        write(self.receipt, encoded(self.receipt_value))
        for receipt in self.manifest["receipts"]:
            if receipt["path"] == str(self.receipt):
                receipt["sha256"] = digest(self.receipt.read_bytes())
                receipt["bytes"] = self.receipt.stat().st_size
        self.repin_manifest()

    def assert_refuses_without_writes(self):
        before = tree_snapshot(self.root)
        with self.assertRaises(REFUSALS):
            self.prepare()
        self.assertEqual(tree_snapshot(self.root), before)
        self.assertFalse(self.args.output_directory.exists())
        if self.args.backup_directory is not None:
            self.assertFalse(self.args.backup_directory.exists())
        self.assertFalse(self.marker.exists())

    def assert_hold(self, prepared, code=None):
        report = prepared["report"]
        self.assertEqual(report["status"], "HOLD")
        self.assertIs(report["validation_complete"], True)
        self.assertIs(report["activated"], False)
        self.assertIs(report["full_dc_replacement_qualified"], False)
        if code:
            self.assertIn(code, [row["code"] for row in report["blockers"]])
        return report

    def test_prepare_is_read_only_and_never_executes_candidates(self):
        before = tree_snapshot(self.root)
        prepared = self.prepare()
        self.assert_hold(prepared, "DISPATCH_INVENTORY_UNAVAILABLE")
        self.assertEqual(tree_snapshot(self.root), before)
        self.assertFalse(self.args.output_directory.exists())
        self.assertFalse(self.marker.exists())

    def test_only_git_identity_processes_run_with_injected_observation_probes(self):
        original = subprocess.run
        original_popen = subprocess.Popen
        calls = []
        def allow_git(argv, *a, **kw):
            self.assertIsInstance(argv, list)
            self.assertEqual(argv[:3], ["git", "-C", str(self.source)])
            self.assertIn(argv[3], ("rev-parse", "diff", "ls-files"))
            calls.append(argv)
            return original(argv, *a, **kw)
        def allow_git_popen(argv, *a, **kw):
            self.assertIsInstance(argv, list)
            self.assertEqual(argv[:3], ["git", "-C", str(self.source)])
            return original_popen(argv, *a, **kw)
        with mock.patch.object(subprocess, "run", side_effect=allow_git), \
             mock.patch.object(subprocess, "Popen", side_effect=allow_git_popen):
            self.assert_hold(self.prepare())
        self.assertTrue(calls)
        self.assertFalse(self.marker.exists())

    def test_manifest_pin_and_each_staged_artifact_are_rehashed(self):
        original = self.args.stage_manifest_sha256
        self.args.stage_manifest_sha256 = "0" * 64
        self.assert_refuses_without_writes()
        self.args.stage_manifest_sha256 = original
        for name in self.manifest["artifacts"]:
            with self.subTest(artifact=name):
                path = self.stage / name
                raw = path.read_bytes()
                write(path, raw + b"\nchanged\n", stat.S_IMODE(path.stat().st_mode))
                self.assert_refuses_without_writes()
                write(path, raw, int(self.manifest["artifacts"][name]["mode"], 8))

    def test_late_receipt_pin_failure_precedes_any_report_or_backup_directory(self):
        self.args.prepare_backups = True
        self.args.backup_directory = self.root / "private-packet"
        self.manifest["receipts"].append({
            "name": "late-missing", "path": str(self.inputs / "absent.json"),
            "sha256": "0" * 64, "bytes": 0, "source_mode": "0600"})
        self.repin_manifest()
        self.assert_refuses_without_writes()

    def test_tampered_receipt_bytes_cannot_be_hidden_by_success_counts(self):
        write(self.receipt, encoded({**self.receipt_value, "passed": 999999}))
        self.assert_refuses_without_writes()

    def test_head_and_entire_compile_input_map_must_match_the_stage(self):
        for relative in ("src/main.rs", "src/nested/input.py", "Cargo.toml", "Cargo.lock"):
            with self.subTest(source=relative):
                path = self.source / relative
                raw = path.read_bytes()
                write(path, raw + b"\nchanged\n")
                self.assert_refuses_without_writes()
                write(path, raw)
        self.manifest["source"]["base_HEAD"] = "0" * 40
        self.repin_manifest()
        self.assert_refuses_without_writes()

    def test_deleted_or_untracked_compile_source_cannot_requalify_by_rehashing(self):
        path = self.source / "src/nested/input.py"
        raw = path.read_bytes()
        path.unlink()
        self.manifest["source"] = S.source_identity(self.source)
        self.manifest["compiled_source_fingerprint_supplied"] = self.manifest["source"]["source_code_fingerprint"]
        self.repin_manifest()
        self.assert_refuses_without_writes()
        write(path, raw)
        write(self.source / "src/untracked.rs", b"// uncommitted\n")
        self.manifest["source"] = S.source_identity(self.source)
        self.manifest["compiled_source_fingerprint_supplied"] = self.manifest["source"]["source_code_fingerprint"]
        self.repin_manifest()
        self.assert_refuses_without_writes()

    def test_each_baseline_live_pointer_is_hash_bound(self):
        for role, reference in self.baseline["live_files"].items():
            with self.subTest(role=role):
                path = pathlib.Path(reference["path"])
                raw = path.read_bytes()
                write(path, raw + b"changed")
                self.assert_refuses_without_writes()
                write(path, raw)

    def test_actual_loaded_fragment_is_hash_bound(self):
        for reference in (self.units[UNITS[0]]["fragment"],):
            path = pathlib.Path(reference["path"])
            raw = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
            write(path, raw + b"changed", mode)
            self.assert_refuses_without_writes()
            write(path, raw, mode)

    def test_final_symlink_hardlink_and_unsafe_modes_refuse_even_valid_bytes(self):
        path = self.stage / "chatgpt_full_operator.py"
        raw = path.read_bytes()
        original = self.root / "unaltered-facade"
        write(original, raw)
        path.unlink()
        path.symlink_to(original)
        self.assert_refuses_without_writes()
        path.unlink()
        write(path, raw)
        link = self.root / "second-facade-link"
        os.link(path, link)
        self.assert_refuses_without_writes()
        link.unlink()
        path.chmod(0o622)
        self.assert_refuses_without_writes()

    def test_stage_manifest_parent_symlink_is_refused(self):
        alias = self.root / "stage-alias"
        alias.symlink_to(self.stage, target_is_directory=True)
        self.args.stage_manifest = alias / "manifest.json"
        self.assert_refuses_without_writes()

    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        path = self.stage / "chatgpt_full_operator.py"
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assert_refuses_without_writes()

    def test_foreign_owner_is_rejected_even_when_hash_matches(self):
        info = list((self.stage / "contract.json").stat())
        info[4] = 54321
        with mock.patch.object(S.os, "getuid", return_value=12345):
            with self.assertRaises(PermissionError):
                S.validate_inode(os.stat_result(info), "foreign preflight fixture")

    def test_unknown_or_legacy_job_binding_holds_without_cancel_or_replay(self):
        observed = copy.deepcopy(self.inventory)
        observed["jobs"] = [{"host": "main", "id": "legacy-17", "state": "owner_unknown",
                            "launch_nonce_present": False, "supervisor_binding_verified": False}]
        report = self.assert_hold(self.prepare(inventory=observed), "JOB_BINDING_UNKNOWN")
        self.assertNotIn(self.token_secret, json.dumps(report))
        self.assertFalse(self.marker.exists())

    def test_active_nonpersistent_pty_holds_even_when_every_count_looks_successful(self):
        observed = copy.deepcopy(self.inventory)
        observed["ptys"] = [{"host": "rog", "session_id": "controller-only",
                            "state": "running", "persistent_across_runtime_restart": False}]
        self.assert_hold(self.prepare(inventory=observed), "ACTIVE_NONPERSISTENT_PTY")

    def test_incomplete_stream_inventory_cannot_be_qualified_by_an_empty_list(self):
        observed = copy.deepcopy(self.inventory)
        observed["streams_complete"] = False
        self.assert_hold(self.prepare(inventory=observed), "STREAM_INVENTORY_INCOMPLETE")

    def test_unknown_inventory_errors_and_missing_hosts_preserve_hold(self):
        observed = copy.deepcopy(self.inventory)
        observed["hosts"] = HOSTS[:-1]
        observed["errors"] = [{"scope": "ai395", "error_type": "TimeoutError"}]
        report = self.assert_hold(self.prepare(inventory=observed))
        self.assertTrue(report["blockers"])

    def test_tool_or_local_pass_counts_never_authorize_activation_or_full_replacement(self):
        self.receipt_value.update({"passed": 999999, "tool_count": 999999,
                                  "full_dc_replacement_qualified": True})
        self.repin_receipt()
        report = self.assert_hold(self.prepare())
        self.assertIs(report["activated"], False)
        self.assertIs(report["full_dc_replacement_qualified"], False)

    def test_receipt_wrong_head_fingerprint_native_or_contract_remains_unbound(self):
        paths = (
            ("source_before", "base_HEAD", "0" * 40),
            ("source_before", "source_code_fingerprint", "0" * 64),
            (None, "candidate_binary_sha256", "0" * 64),
            (None, "candidate_contract_sha256", "0" * 64),
        )
        original = copy.deepcopy(self.receipt_value)
        for parent, key, value in paths:
            with self.subTest(binding=key):
                self.receipt_value = copy.deepcopy(original)
                (self.receipt_value[parent] if parent else self.receipt_value)[key] = value
                self.repin_receipt()
                report = self.assert_hold(self.prepare())
                self.assertTrue(report["receipts"])
                self.assertIn(False, list(values_for_key(report["receipts"], "bindings_valid")))

    def test_unrecognized_receipt_success_claim_is_not_compilation_or_business_proof(self):
        self.receipt_value = {"schema": "unknown-fixture-schema", "complete": True,
                              "passed": 999999, "full_dc_replacement_qualified": True}
        self.repin_receipt()
        report = self.assert_hold(self.prepare())
        self.assertIn(False, list(values_for_key(report["receipts"], "bindings_valid")))

    def test_report_and_backup_metadata_never_contain_token_or_private_profile_values(self):
        self.args.prepare_backups = True
        self.args.backup_directory = self.root / "private-packet"
        prepared = self.prepare()
        report = self.assert_hold(prepared)
        self.assertNotIn(self.token_secret, json.dumps(report))
        self.assertNotIn(self.profile_secret, json.dumps(report))
        self.assertNotIn(self.token_secret.encode(), b"".join(raw for raw, mode in prepared["backups"].values()))
        self.assertFalse(self.args.backup_directory.exists())
        self.assertFalse(self.args.output_directory.exists())

    def test_publish_creates_exact_byte_private_packet_and_keeps_token_reference_only(self):
        self.args.prepare_backups = True
        self.args.backup_directory = self.root / "private-packet"
        prepared = self.prepare()
        before = {path: path.read_bytes() for path in (self.token, self.live / "profile",
                   self.live / "installed_manifest", self.live / "unit_dropin")}
        P.publish(prepared, self.args)
        packet = self.args.backup_directory
        self.assertEqual(stat.S_IMODE(packet.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.args.output_directory.stat().st_mode), 0o700)
        self.assertEqual((packet / "profile.bin").read_bytes(), before[self.live / "profile"])
        self.assertEqual((packet / "installed-manifest.bin").read_bytes(),
                         before[self.live / "installed_manifest"])
        self.assertIn(before[self.live / "unit_dropin"], [p.read_bytes() for p in packet.glob("dropin-*.conf")])
        for path in packet.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertNotIn(self.token_secret.encode(), path.read_bytes())
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw)
        report_raw = (self.args.output_directory / "report.json").read_bytes()
        packet_metadata = (packet / "packet-manifest.json").read_bytes()
        packet_value = json.loads(packet_metadata)
        self.assertEqual(set(packet_value["restore_entries"]), set(prepared["backups"]))
        for name, reference in packet_value["restore_entries"].items():
            origin = pathlib.Path(reference["original_path"])
            self.assertEqual(reference["original_sha256"], digest(origin.read_bytes()))
            self.assertEqual(reference["original_mode"], format(stat.S_IMODE(origin.stat().st_mode), "04o"))
            self.assertEqual((packet / name).read_bytes(), origin.read_bytes())
        self.assertNotIn(self.token_secret.encode(), report_raw + packet_metadata)
        self.assertNotIn(self.profile_secret.encode(), report_raw + packet_metadata)
        self.assert_hold({"report": json.loads(report_raw)})
        self.assertFalse(self.marker.exists())

    def test_report_only_publication_does_not_create_any_private_backup(self):
        prepared = self.prepare()
        P.publish(prepared, self.args)
        self.assertEqual({p.name for p in self.args.output_directory.iterdir()}, {"report.json"})
        self.assertEqual(stat.S_IMODE((self.args.output_directory / "report.json").stat().st_mode), 0o600)
        self.assertEqual(prepared["backups"], {})

    def test_private_backup_destination_must_be_absent_and_outside_git_source(self):
        self.args.prepare_backups = True
        self.args.backup_directory = self.source / "packet"
        self.assert_refuses_without_writes()
        self.args.backup_directory = self.root / "existing-packet"
        self.args.backup_directory.mkdir(mode=0o700)
        marker = write(self.args.backup_directory / "untouched", b"owned original packet")
        before = tree_snapshot(self.root)
        with self.assertRaises(REFUSALS):
            self.prepare()
        self.assertEqual(tree_snapshot(self.root), before)
        self.assertEqual(marker.read_bytes(), b"owned original packet")

    def test_symlinked_output_parent_cannot_redirect_the_private_packet(self):
        real = self.root / "real-output"
        real.mkdir(mode=0o700)
        alias = self.root / "output-alias"
        alias.symlink_to(real, target_is_directory=True)
        self.args.output_directory = alias / "report"
        self.assert_refuses_without_writes()

    def test_existing_report_directory_is_never_reused_or_repaired(self):
        self.args.output_directory.mkdir(mode=0o700)
        marker = write(self.args.output_directory / "old-report", b"prior independent evidence")
        before = tree_snapshot(self.root)
        with self.assertRaises(REFUSALS):
            self.prepare()
        self.assertEqual(tree_snapshot(self.root), before)
        self.assertEqual(marker.read_bytes(), b"prior independent evidence")

    def test_publication_write_failure_removes_only_new_private_directories(self):
        self.args.prepare_backups = True
        self.args.backup_directory = self.root / "packet"
        prepared = self.prepare()
        before = tree_snapshot(self.root)
        original = os.open
        def fail_packet_manifest(path, flags, *a, **kw):
            if pathlib.Path(path).name == "packet-manifest.json" and flags & os.O_WRONLY:
                raise OSError(errno.EIO, "injected offline failure " + self.token_secret)
            return original(path, flags, *a, **kw)
        with mock.patch.object(os, "open", side_effect=fail_packet_manifest):
            with self.assertRaises(OSError):
                P.publish(prepared, self.args)
        self.assertEqual(tree_snapshot(self.root), before)
        self.assertFalse(self.args.output_directory.exists())
        self.assertFalse(self.args.backup_directory.exists())
        self.assertEqual(self.token.read_text(), self.token_secret)



    def test_protected_native_executable_pid_owner_and_start_identity_are_enforced(self):
        for field, bad in (("exe_sha256", "0" * 64), ("pid", 999),
                           ("uid", os.getuid() + 1), ("start_ticks", "not-integer")):
            with self.subTest(field=field):
                data = copy.deepcopy(self.processes)
                data[101][field] = bad
                before = tree_snapshot(self.root)
                with self.assertRaises(REFUSALS):
                    self.prepare(processes=data)
                self.assertEqual(tree_snapshot(self.root), before)

    def test_changing_protected_service_or_pid_during_observation_refuses(self):
        calls = 0
        def drifting_services():
            nonlocal calls
            calls += 1
            units = copy.deepcopy(self.units)
            if calls > 1:
                units[UNITS[0]]["InvocationID"] = "replacement-instance"
            return {"units": units}
        before = tree_snapshot(self.root)
        with self.assertRaises(REFUSALS):
            P.prepare_preflight(self.args, service_probe=drifting_services,
                inventory_probe=lambda manifest: copy.deepcopy(self.inventory),
                process_probe=lambda pid: copy.deepcopy(self.processes[int(pid)]))
        self.assertEqual(tree_snapshot(self.root), before)

    def test_token_cannot_be_treated_as_an_extra_loaded_dropin_or_fragment(self):
        self.args.prepare_backups = True
        self.args.backup_directory = self.root / "private-packet"
        reference = {"path": str(self.token), "sha256": digest(self.token.read_bytes())}
        original = copy.deepcopy(self.units)
        self.units[UNITS[1]]["dropins"].append(reference)
        self.assert_refuses_without_writes()
        self.units = copy.deepcopy(original)
        self.units[UNITS[1]]["fragment"] = reference
        self.assert_refuses_without_writes()

    def test_publish_cannot_redirect_a_validated_private_packet_into_git_source(self):
        self.args.prepare_backups = True
        self.args.backup_directory = self.root / "private-packet"
        prepared = self.prepare()
        self.args.backup_directory = self.source / "secret-packet"
        before = tree_snapshot(self.root)
        with self.assertRaises(REFUSALS):
            P.publish(prepared, self.args)
        self.assertEqual(tree_snapshot(self.root), before)
        self.assertFalse(self.args.backup_directory.exists())

    def test_untrusted_publication_parent_refuses_before_creating_packet(self):
        original_fstat = os.fstat
        for reason in ("writable", "foreign_owner"):
            with self.subTest(reason=reason):
                parent = self.root / ("publication-parent-" + reason)
                parent.mkdir(mode=0o700)
                packet = parent / "packet"
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
                before = tree_snapshot(self.root)
                with mock.patch.object(os, "fstat", side_effect=untrusted_parent):
                    with self.assertRaisesRegex(PermissionError, "publication parent"):
                        P.write_private_bundle(packet, {"report.json": (b"owned fixture", 0o600)})
                self.assertEqual(tree_snapshot(self.root), before)
                self.assertFalse(packet.exists())
                self.assertFalse(self.marker.exists())

    def test_replaced_publication_directory_is_never_removed_during_failure_cleanup(self):
        original_stat = os.stat
        for empty in (True, False):
            with self.subTest(empty_replacement=empty):
                packet = self.root / ("race-packet-" + str(empty))
                displaced = self.root / ("displaced-packet-" + str(empty))
                replaced = False
                def replace_before_path_check(path, *arguments, **kwargs):
                    nonlocal replaced
                    if path == packet.name and kwargs.get("dir_fd") is not None and not replaced:
                        try:
                            original_stat(packet / "owned.bin")
                        except FileNotFoundError:
                            pass
                        else:
                            packet.rename(displaced)
                            packet.mkdir(mode=0o700)
                            if not empty:
                                write(packet / "foreign-marker", b"replacement must survive")
                            replaced = True
                    return original_stat(path, *arguments, **kwargs)
                with mock.patch.object(os, "stat", side_effect=replace_before_path_check):
                    with self.assertRaisesRegex(ValueError, "pathname changed"):
                        P.write_private_bundle(packet, {"owned.bin": (b"owned fixture", 0o600)})
                self.assertTrue(replaced)
                self.assertTrue(packet.is_dir())
                self.assertEqual(list(displaced.iterdir()), [])
                if empty:
                    self.assertEqual(list(packet.iterdir()), [])
                else:
                    self.assertEqual((packet / "foreign-marker").read_bytes(), b"replacement must survive")
                self.assertFalse(self.marker.exists())

    def test_report_write_failure_preserves_verified_private_hold_packet_and_live_inputs(self):
        self.args.prepare_backups = True
        self.args.backup_directory = self.root / "private-packet"
        prepared = self.prepare()
        before = tree_snapshot(self.root)
        original = os.open
        def fail_report(path, flags, *a, **kw):
            if pathlib.Path(path).name == "report.json" and flags & os.O_WRONLY:
                raise OSError(errno.EIO, "injected offline report failure")
            return original(path, flags, *a, **kw)
        with mock.patch.object(os, "open", side_effect=fail_report):
            with self.assertRaises(OSError):
                P.publish(prepared, self.args)
        after = tree_snapshot(self.root)
        packet_prefix = self.args.backup_directory.relative_to(self.root).as_posix()
        self.assertEqual({key: value for key, value in after.items()
                          if key != packet_prefix and not key.startswith(packet_prefix + "/")}, before)
        self.assertFalse(self.args.output_directory.exists())
        self.assertTrue(self.args.backup_directory.is_dir())
        packet = json.loads((self.args.backup_directory / "packet-manifest.json").read_bytes())
        self.assertEqual(packet["status"], "HOLD")
        self.assertIs(packet["activation_performed"], False)
        self.assertIs(packet["token_copied"], False)
        for path in self.args.backup_directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(self.token_secret.encode(), path.read_bytes())

    def fake_transport(self, status=200, mismatched_id=False):
        records = []
        owner = self
        class Connection:
            def __init__(self, host, port=None, **kwargs):
                owner.assertEqual((host, port), ("127.0.0.1", 8790))
                owner.assertEqual(kwargs, {"timeout": 30})
                self.request_row = None
                self.closed = False
            def request(self, method, path, body=None, headers=None):
                owner.assertEqual((method, path), ("POST", "/mcp"))
                self.request_row = json.loads(body)
                records.append({"request": self.request_row, "headers": dict(headers)})
                owner.assertEqual(headers["X-Hepta-Runtime-Token"], owner.token_secret)
            def getresponse(self):
                connection = self
                class Response:
                    def __init__(self):
                        self.status = status
                    def getheader(self, key):
                        return "offline-session" if key.lower() == "mcp-session-id" else None
                    def read(self, limit):
                        q = connection.request_row
                        if "id" not in q:
                            raw = b""
                        else:
                            result = {"content": [{"type": "text", "text": '{"observed":true}'}]}
                            raw = encoded({"jsonrpc": "2.0", "id": q["id"] + 1 if mismatched_id else q["id"],
                                           "result": result})
                        owner.assertEqual(limit, P.MAX_RESPONSE + 1)
                        return raw[:limit]
                return Response()
            def close(self):
                self.closed = True
        return Connection, records

    def test_loopback_read_client_is_direct_fixed_endpoint_despite_proxy_environment(self):
        connection, records = self.fake_transport()
        with mock.patch.object(P.http.client, "HTTPConnection", connection), \
             mock.patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.invalid:8080",
                                          "HTTPS_PROXY": "http://proxy.invalid:8080",
                                          "ALL_PROXY": "http://proxy.invalid:8080",
                                          "NO_PROXY": ""}):
            client = P.LoopbackReadClient(self.token)
            self.assertEqual(client.call("host_list", {}), {"observed": True})
            client.close()
        self.assertEqual([r["request"]["method"] for r in records],
                         ["initialize", "notifications/initialized", "tools/call"])
        self.assertEqual(records[-1]["request"]["params"], {"name": "host_list", "arguments": {}})
        self.assertEqual(client.endpoint, "http://127.0.0.1:8790/mcp")
        self.assertIsNone(client._token)
        self.assertIsNone(client._session)

    def test_loopback_client_refuses_mutation_and_cancellation_without_http_submission(self):
        connection, records = self.fake_transport()
        with mock.patch.object(P.http.client, "HTTPConnection", connection):
            client = P.LoopbackReadClient(self.token)
            submitted = len(records)
            for name in ("process_start", "process_cancel", "pty_write", "pty_close",
                         "stream_handoff_attach", "text_editor"):
                with self.subTest(tool=name), self.assertRaises(ValueError):
                    client.call(name, {"secret": self.profile_secret})
                self.assertEqual(len(records), submitted)
            with self.assertRaises(ValueError):
                client.rpc("notifications/cancelled", {"requestId": 1})
            self.assertEqual(len(records), submitted)
            client.close()

    def test_loopback_client_never_follows_redirects_and_rejects_wrong_response_id(self):
        for status, mismatch in ((302, False), (200, True)):
            with self.subTest(status=status, mismatched_id=mismatch):
                connection, records = self.fake_transport(status=status, mismatched_id=mismatch)
                with mock.patch.object(P.http.client, "HTTPConnection", connection):
                    with self.assertRaises(ValueError):
                        P.LoopbackReadClient(self.token)
                self.assertEqual(len(records), 1)

    def test_http_token_descriptor_requires_exact_private_mode_and_no_link_aliases(self):
        self.token.chmod(0o640)
        with self.assertRaises(PermissionError):
            P.read_private_token(self.token)
        self.token.chmod(0o600)
        link = self.root / "token-hardlink"
        os.link(self.token, link)
        with self.assertRaises(ValueError):
            P.read_private_token(self.token)
        link.unlink()
        alias = self.root / "token-alias"
        alias.symlink_to(self.token)
        with self.assertRaises(OSError):
            P.read_private_token(alias)

    def test_http_token_format_is_bounded_and_cannot_inject_headers(self):
        for raw in (b"", b"header\nsecond-line", b"x" * 513, b"secret\xff"):
            with self.subTest(case=repr(raw[:20])):
                write(self.token, raw)
                with self.assertRaises((ValueError, UnicodeError)):
                    P.read_private_token(self.token)

    def test_default_inventory_omits_tool_output_and_retains_legacy_binding_hold(self):
        # These are owned temporary durable records, never the installed state.
        jobs = self.state / "jobs"
        jobs.mkdir(mode=0o700)
        for host in HOSTS:
            write(jobs / ("job-" + host + ".json"), encoded({"id": "job-" + host,
                "host": host, "command": self.profile_secret, "environment": {"TOKEN": self.token_secret}}))
        streams = self.state / "stream_handoffs"
        streams.mkdir(mode=0o700)
        (streams / ("stream-" + "a" * 64)).mkdir(mode=0o700)
        calls = []
        contract = json.loads(self.v4raw)
        owner = self
        class Client:
            def __init__(self, token_path):
                owner.assertEqual(str(token_path), str(owner.token))
            def rpc(self, method, arguments):
                owner.assertEqual((method, arguments), ("tools/list", {}))
                return {"tools": contract["tools"]}
            def call(self, name, args):
                calls.append((name, dict(args)))
                owner.assertIn(name, P.READ_TOOLS)
                if name == "host_list":
                    return {"hosts": [{"name": host, "ssh_target": owner.profile_secret} for host in HOSTS]}
                if name == "process_list":
                    return {"jobs": [{"id": "job-" + args["host"], "host": args["host"],
                                      "command": owner.profile_secret}],
                            "inventory_complete": True}
                if name == "process_status":
                    return {"state": "owner_unknown", "status_authoritative": False,
                            "stdout": owner.profile_secret, "environment": {"TOKEN": owner.token_secret}}
                if name == "pty_list":
                    return {"sessions": [], "has_more": False}
                if name == "stream_handoff_list":
                    return {"sessions": []}
                owner.fail("Unexpected read tool")
            def close(self):
                pass
        with mock.patch.object(P, "LoopbackReadClient", Client):
            observed = P.inventory_observation(self.manifest)
        self.assertEqual(set(observed["hosts"]), set(HOSTS))
        self.assertEqual(len(observed["jobs"]), len(HOSTS))
        self.assertTrue(observed["jobs_complete"])
        self.assertFalse(observed["streams_complete"])
        self.assertTrue(all(row["supervisor_binding_verified"] is False for row in observed["jobs"]))
        self.assertIn("JOB_BINDING_UNKNOWN", [row["code"] for row in P.inventory_holds(observed)])
        self.assertIn("STREAM_INVENTORY_INCOMPLETE", [row["code"] for row in P.inventory_holds(observed)])
        raw = json.dumps(observed)
        self.assertNotIn(self.token_secret, raw)
        self.assertNotIn(self.profile_secret, raw)
        self.assertTrue(calls)
        self.assertFalse(any("cancel" in name or "start" in name or "write" in name for name, args in calls))

    def test_missing_durable_registry_never_becomes_complete_empty_inventory(self):
        owner = self
        contract = json.loads(self.v4raw)
        class Client:
            def __init__(self, token_path):
                owner.assertEqual(str(token_path), str(owner.token))
            def rpc(self, method, arguments):
                owner.assertEqual((method, arguments), ("tools/list", {}))
                return {"tools": contract["tools"]}
            def call(self, name, args):
                owner.assertIn(name, P.READ_TOOLS)
                if name == "host_list":
                    return {"hosts": [{"name": host} for host in HOSTS]}
                if name == "process_list":
                    return {"jobs": [], "inventory_complete": True}
                if name == "pty_list":
                    return {"sessions": [], "has_more": False}
                if name == "stream_handoff_list":
                    return {"sessions": []}
                owner.fail("Unexpected read tool")
            def close(self):
                pass
        for missing in (set(), {"jobs"}, {"stream_handoffs"}, {"jobs", "stream_handoffs"}):
            with self.subTest(missing=sorted(missing)):
                for kind in ("jobs", "stream_handoffs"):
                    path = self.state / kind
                    if kind in missing:
                        if path.exists():
                            path.rmdir()
                    else:
                        path.mkdir(mode=0o700, exist_ok=True)
                before = tree_snapshot(self.root)
                with mock.patch.object(P, "LoopbackReadClient", Client):
                    observed = P.inventory_observation(self.manifest)
                self.assertEqual(observed["jobs_complete"], "jobs" not in missing)
                self.assertEqual(observed["streams_complete"], "stream_handoffs" not in missing)
                codes = {row["code"] for row in P.inventory_holds(observed)}
                if "jobs" in missing:
                    self.assertIn("JOB_INVENTORY_INCOMPLETE", codes)
                if "stream_handoffs" in missing:
                    self.assertIn("STREAM_INVENTORY_INCOMPLETE", codes)
                if missing:
                    self.assertIn({"scope": "registry", "error_type": "MissingDirectory"}, observed["errors"])
                self.assertIn("DISPATCH_INVENTORY_UNAVAILABLE", codes)
                self.assertIn("ADMISSION_NOT_FROZEN", codes)
                self.assertEqual(tree_snapshot(self.root), before)
                self.assertFalse(self.marker.exists())

    def test_default_inventory_records_error_types_without_exception_or_tool_payload(self):
        for kind in ("jobs", "stream_handoffs"):
            (self.state / kind).mkdir(mode=0o700)
        contract = json.loads(self.v4raw)
        owner = self
        class Client:
            def __init__(self, token_path):
                pass
            def rpc(self, method, arguments):
                return {"tools": contract["tools"]}
            def call(self, name, args):
                if name == "host_list":
                    return {"hosts": [{"name": host} for host in HOSTS]}
                raise TimeoutError(owner.token_secret + owner.profile_secret)
            def close(self):
                pass
        with mock.patch.object(P, "LoopbackReadClient", Client):
            observed = P.inventory_observation(self.manifest)
        raw = json.dumps(observed)
        self.assertNotIn(self.token_secret, raw)
        self.assertNotIn(self.profile_secret, raw)
        self.assertEqual({row["error_type"] for row in observed["errors"]}, {"TimeoutError"})
        self.assertFalse(observed["jobs_complete"])
        self.assertFalse(observed["ptys_complete"])
        self.assertIn("INVENTORY_OBSERVATION_ERROR", [row["code"] for row in P.inventory_holds(observed)])



    def test_pinned_ci_receipt_requires_exact_head_completed_success_and_repository_url(self):
        original = copy.deepcopy(self.receipt_value)
        good = {"headSha": self.identity["base_HEAD"], "status": "completed", "conclusion": "success",
                "url": "https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/12345678"}
        for patch, expected in ((good, True),
             ({**good, "headSha": "0" * 40}, False),
             ({**good, "status": "in_progress"}, False),
             ({**good, "conclusion": "failure"}, False),
             ({**good, "url": "https://github.com/other/project/actions/runs/12345678"}, False)):
            with self.subTest(receipt=patch):
                self.receipt_value = {**copy.deepcopy(original), **patch}
                self.repin_receipt()
                report = self.assert_hold(self.prepare())
                codes = {row["code"] for row in report["blockers"]}
                self.assertEqual("CI_SUCCESS_UNPROVEN" not in codes, expected)
                self.assertIs(report["full_dc_replacement_qualified"], False)
                self.assertIs(report["services_restarted"], False)

    def test_default_service_observation_runs_show_only_and_hashes_execstart_privately(self):
        calls = []
        def show(argv, *arguments, **kwargs):
            self.assertEqual(argv[:3], ["systemctl", "--user", "show"])
            self.assertIn(argv[3], UNITS)
            self.assertEqual(argv[4], "--no-pager")
            self.assertEqual(len(argv), 6)
            self.assertTrue(argv[5].startswith("--property="))
            calls.append(argv)
            info = self.units[argv[3]]
            fields = {key: info[key] for key in
                ("ActiveState", "SubState", "MainPID", "InvocationID", "ExecMainStartTimestampMonotonic")}
            fields["FragmentPath"] = info["fragment"]["path"]
            fields["DropInPaths"] = " ".join(row["path"] for row in info["dropins"])
            fields["ExecStart"] = "/fixture/facade --private-provider-auth=" + self.profile_secret
            return subprocess.CompletedProcess(argv, 0,
                stdout="\n".join(key + "=" + value for key, value in fields.items()) + "\n", stderr="")
        with mock.patch.object(P.subprocess, "run", side_effect=show):
            observed = P.service_observation(self.token)
        self.assertEqual(len(calls), 3)
        self.assertEqual(set(observed["units"]), set(UNITS))
        self.assertNotIn(self.profile_secret, json.dumps(observed))
        self.assertNotIn(self.token_secret, json.dumps(observed))
        expected = digest(("/fixture/facade --private-provider-auth=" + self.profile_secret).encode())
        self.assertTrue(all(row["exec_start_sha256"] == expected for row in observed["units"].values()))

    def test_cli_failure_diagnostic_is_type_only_and_never_calls_publish(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        parser = mock.Mock()
        parser.parse_args.return_value = self.args
        with mock.patch.object(P, "parser", return_value=parser), \
             mock.patch.object(P, "prepare_preflight",
                    side_effect=ValueError(self.token_secret + self.profile_secret)), \
             mock.patch.object(P, "publish") as publication, \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                P.main()
        self.assertEqual(caught.exception.code, 1)
        publication.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        result = json.loads(stderr.getvalue())
        self.assertEqual(result["status"], "HOLD")
        self.assertIs(result["validation_complete"], False)
        self.assertIs(result["activated"], False)
        self.assertEqual(result["error_type"], "ValueError")
        self.assertNotIn(self.token_secret, stderr.getvalue())
        self.assertNotIn(self.profile_secret, stderr.getvalue())



    def test_all_actual_baseline_artifacts_remain_exact_before_preflight(self):
        for role in ("native", "facade", "helper", "contract"):
            with self.subTest(baseline=role):
                path = pathlib.Path(self.baseline[role]["path"])
                raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
                write(path, raw + b"changed", mode)
                self.assert_refuses_without_writes()
                write(path, raw, mode)

    def test_inventory_sanitizer_drops_payloads_and_maps_untrusted_states_to_unknown(self):
        observed = copy.deepcopy(self.inventory)
        observed["jobs"] = [{"host": "main", "id": "job-main", "state": self.token_secret,
              "launch_nonce_present": False, "supervisor_binding_verified": False,
              "pid": True, "stdout": self.profile_secret, "environment": {"TOKEN": self.token_secret},
              "headers": {"Authorization": self.token_secret}}]
        observed["arguments"] = [self.profile_secret]
        report = self.assert_hold(self.prepare(inventory=observed), "JOB_BINDING_UNKNOWN")
        raw = json.dumps(report)
        self.assertNotIn(self.token_secret, raw)
        self.assertNotIn(self.profile_secret, raw)
        self.assertEqual(report["inventory"]["jobs"][0]["state"], "unknown")
        self.assertNotIn("pid", report["inventory"]["jobs"][0])



class PrivateHttpTokenDescriptor(unittest.TestCase):
    """Owned offline files only; this class never opens the installed token."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-token-reader-offline-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.root.chmod(0o700)
        self.token = self.root / "owned-token"
        self.raw = b"OFFLINE_PRIVATE_TOKEN_READER_FIXTURE_20261013\n"
        write(self.token, self.raw)
        self.value = self.raw.decode("ascii").strip()

    def test_owner_read_only_0400_and_0600_preserve_mode_inode_and_bytes_without_hashing(self):
        for mode in (0o400, 0o600):
            with self.subTest(mode=oct(mode)):
                self.token.chmod(mode)
                before = self.token.stat()
                with mock.patch.object(S, "snapshot", side_effect=AssertionError("snapshot forbidden")), \
                     mock.patch.object(P, "digest", side_effect=AssertionError("digest forbidden")), \
                     mock.patch.object(P.hashlib, "sha256", side_effect=AssertionError("hash forbidden")):
                    self.assertEqual(P.read_private_token(self.token), self.value)
                after = self.token.stat()
                self.assertEqual(self.token.read_bytes(), self.raw)
                self.assertEqual((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                                  after.st_ctime_ns, after.st_uid, after.st_nlink, after.st_mode),
                                 (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                                  before.st_ctime_ns, before.st_uid, before.st_nlink, before.st_mode))

    def test_group_other_executable_and_special_permission_bits_are_refused_before_read(self):
        for mode in (0o640, 0o604, 0o660, 0o600 | 0o100, 0o400 | 0o10,
                     0o400 | 0o1, 0o4600, 0o2600, 0o1600):
            with self.subTest(mode=oct(mode)):
                self.token.chmod(mode)
                with mock.patch.object(P.os, "read", side_effect=AssertionError("read forbidden")):
                    with self.assertRaises(PermissionError):
                        P.read_private_token(self.token)
        self.token.chmod(0o600)

    def test_private_parent_requires_current_owner_and_exact_0700(self):
        for mode in (0o750, 0o770, 0o755):
            with self.subTest(mode=oct(mode)):
                self.root.chmod(mode)
                try:
                    with mock.patch.object(P.os, "read", side_effect=AssertionError("read forbidden")):
                        with self.assertRaises(PermissionError):
                            P.read_private_token(self.token)
                finally:
                    self.root.chmod(0o700)
        original = os.fstat
        parent_inode = self.root.stat().st_ino

        def other_owner(fd):
            info = original(fd)
            if info.st_ino == parent_inode:
                fields = list(info)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return info

        with mock.patch.object(P.os, "fstat", side_effect=other_owner):
            with self.assertRaises(PermissionError):
                P.read_private_token(self.token)

    def test_other_owner_token_is_refused_before_read(self):
        original = os.fstat
        inode = self.token.stat().st_ino

        def other_owner(fd):
            info = original(fd)
            if info.st_ino == inode:
                fields = list(info)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return info

        with mock.patch.object(P.os, "fstat", side_effect=other_owner), \
             mock.patch.object(P.os, "read", side_effect=AssertionError("read forbidden")):
            with self.assertRaises(PermissionError):
                P.read_private_token(self.token)

    def test_single_link_and_final_symlink_are_refused(self):
        alias = self.root / "alias"
        os.link(self.token, alias)
        with mock.patch.object(P.os, "read", side_effect=AssertionError("read forbidden")):
            with self.assertRaises(ValueError):
                P.read_private_token(self.token)
        alias.unlink()
        alias.symlink_to(self.token)
        with self.assertRaises(OSError):
            P.read_private_token(alias)

    def test_symlink_parent_cannot_redirect_private_token(self):
        alias = self.root / "parent-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            P.read_private_token(alias / self.token.name)

    def test_fifo_and_directory_are_refused_with_nonblocking_descriptor(self):
        fifo = self.root / "owned-fifo"
        os.mkfifo(fifo, mode=0o600)
        original = os.open
        flags_seen = []

        def record_flags(path, flags, *args, **kwargs):
            if path == fifo.name:
                flags_seen.append(flags)
            return original(path, flags, *args, **kwargs)

        with mock.patch.object(P.os, "open", side_effect=record_flags):
            with self.assertRaises(ValueError):
                P.read_private_token(fifo)
        self.assertEqual(len(flags_seen), 1)
        self.assertTrue(flags_seen[0] & os.O_NONBLOCK)
        self.assertTrue(flags_seen[0] & os.O_NOFOLLOW)
        self.assertTrue(flags_seen[0] & os.O_CLOEXEC)
        directory = self.root / "owned-directory"
        directory.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            P.read_private_token(directory)

    def test_oversize_descriptor_is_refused_without_read(self):
        write(self.token, b"x" * 513)
        with mock.patch.object(P.os, "read", side_effect=AssertionError("read forbidden")):
            with self.assertRaises(ValueError):
                P.read_private_token(self.token)

    def test_bounded_short_reads_are_collected_and_descriptor_is_closed(self):
        original_read = os.read
        original_open = os.open
        token_fds = []

        def short_read(fd, count):
            return original_read(fd, min(count, 3))

        def record_open(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if path == self.token.name:
                token_fds.append(fd)
            return fd

        with mock.patch.object(P.os, "read", side_effect=short_read), \
             mock.patch.object(P.os, "open", side_effect=record_open):
            self.assertEqual(P.read_private_token(self.token), self.value)
        self.assertEqual(len(token_fds), 1)
        with self.assertRaises(OSError) as error:
            os.fstat(token_fds[0])
        self.assertEqual(error.exception.errno, errno.EBADF)

    def test_incomplete_and_appended_read_are_refused(self):
        original = os.read
        with mock.patch.object(P.os, "read", return_value=b""):
            with self.assertRaises(ValueError):
                P.read_private_token(self.token)
        first = True

        def append_during_read(fd, count):
            nonlocal first
            if first:
                first = False
                with self.token.open("ab") as writer:
                    writer.write(b"appended")
            return original(fd, count)

        with mock.patch.object(P.os, "read", side_effect=append_during_read):
            with self.assertRaises(ValueError):
                P.read_private_token(self.token)

    def test_same_size_content_change_cannot_hide_behind_restored_mtime(self):
        original = os.read
        before = self.token.stat()
        first = True

        def rewrite_during_read(fd, count):
            nonlocal first
            if first:
                first = False
                with self.token.open("r+b") as writer:
                    writer.write(b"Z" + self.raw[1:])
                    writer.flush()
                    os.fsync(writer.fileno())
                os.utime(self.token, ns=(before.st_atime_ns, before.st_mtime_ns))
            return original(fd, count)

        with mock.patch.object(P.os, "read", side_effect=rewrite_during_read):
            with self.assertRaises(ValueError):
                P.read_private_token(self.token)

    def test_replaced_path_and_changed_private_parent_are_refused(self):
        original = os.read
        first = True

        def replace_during_read(fd, count):
            nonlocal first
            if first:
                first = False
                replacement = write(self.root / "replacement", self.raw)
                os.replace(replacement, self.token)
            return original(fd, count)

        with mock.patch.object(P.os, "read", side_effect=replace_during_read):
            with self.assertRaises(ValueError):
                P.read_private_token(self.token)
        first = True

        def expose_parent_during_read(fd, count):
            nonlocal first
            if first:
                first = False
                self.root.chmod(0o750)
            return original(fd, count)

        try:
            with mock.patch.object(P.os, "read", side_effect=expose_parent_during_read):
                with self.assertRaises(ValueError):
                    P.read_private_token(self.token)
        finally:
            self.root.chmod(0o700)

    def test_invalid_format_and_all_refusals_close_token_descriptor(self):
        original = os.open
        for raw in (b"", b"two\nlines", b"\x00", b"bad\xff", b"x" * 257):
            with self.subTest(format_case=len(raw)):
                write(self.token, raw)
                token_fds = []

                def record_open(path, flags, *args, **kwargs):
                    fd = original(path, flags, *args, **kwargs)
                    if path == self.token.name:
                        token_fds.append(fd)
                    return fd

                with mock.patch.object(P.os, "open", side_effect=record_open):
                    with self.assertRaises((ValueError, UnicodeError)):
                        P.read_private_token(self.token)
                self.assertEqual(len(token_fds), 1)
                with self.assertRaises(OSError) as error:
                    os.fstat(token_fds[0])
                self.assertEqual(error.exception.errno, errno.EBADF)

if __name__ == "__main__":
    unittest.main(verbosity=2)
