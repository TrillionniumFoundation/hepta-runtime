#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Source-custody controls for joint qualification; no process or native execution."""
from __future__ import annotations

import copy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import py_compile
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "hia_native_helper_mcp_integration", Path(__file__).with_name("hia_native_helper_mcp_integration.py"))
integration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(integration)


def written(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return sha256(raw).hexdigest()


class ColdSourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.hepta = self.root / "selected-hepta"
        (self.hepta / "docs").mkdir(parents=True)
        (self.hepta / "tools").mkdir()
        self.source = self.hepta / "tools/compiler.py"
        self.source.write_bytes(b"compiler source A\n")
        self.contract_path = self.hepta / "docs/HIA_SELFHOST_CORE_SUPPORT.json"
        self.contract = {"schema": "hepta.hia.selfhost-core-support.v1", "profile": "fixture-profile",
                         "source_identity": {"files": {"tools/compiler.py": integration.digest(self.source)}}}
        contract_sha = written(self.contract_path, self.contract)
        self.sources = {**self.contract["source_identity"]["files"],
                        "docs/HIA_SELFHOST_CORE_SUPPORT.json": contract_sha}
        self.git("init", "-q", "--template=", "--initial-branch=fixture")
        self.git("add", "--", "tools/compiler.py", "docs/HIA_SELFHOST_CORE_SUPPORT.json")
        self.git("-c", "user.name=HIA test fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "source fixture")
        self.cold_path = self.root / "qualification.json"
        self.directory = self.cold_path.with_suffix(".cold")
        self.directory.mkdir()
        self.compiler = self.directory / "B3.bin"
        self.compiler.write_bytes(b"fixture compiler identity; never executable")
        self.compiler_sha = integration.digest(self.compiler)
        self.nested_path = self.directory / "qualification.json"
        self.nested = {"schema": "hepta.hia.selfhost-qualification.v6",
                       "status": "SELF_HOSTED_FIXED_CORE_PASS", "profile": self.contract["profile"],
                       "source_manifest": copy.deepcopy(self.sources),
                       "generations": [{"produced_image": str(self.compiler),
                                        "produced_sha256": self.compiler_sha} for _ in range(3)]}
        self.cold = {"schema": "hepta.hia.selfhost-cold-replay.v1", "status": "COLD_SELFHOST_REPLAY_PASS",
                     "profile": self.contract["profile"], "returncode": 0,
                     "qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3,
                     "source_manifest": copy.deepcopy(self.sources),
                     "nested_report": str(self.nested_path), "generation_sha256": [self.compiler_sha] * 3,
                     "checks": dict.fromkeys([
                         "export_manifest_matches_qualification", "isolated_python_without_site",
                         "nested_full_qualification_pass", "nested_process_exit_zero", "no_ancestor_git_identity",
                         "no_bytecode_cache_created", "no_inherited_home_or_python_cache",
                         "no_inherited_seed_or_successor_images", "origin_hashes_preserved",
                         "owned_process_tree_cleanup_confirmed", "source_export_hashes_preserved"], True)}
        self.save()

    def save(self):
        self.cold["nested_report_sha256"] = written(self.nested_path, self.nested)
        written(self.cold_path, self.cold)

    def git(self, *arguments):
        return subprocess.check_output(["git", "-C", str(self.hepta), *arguments], text=True).strip()

    def admit(self):
        return integration.admit_cold_compiler(self.hepta, self.cold_path)

    def test_matching_source_and_original_B3_have_explicit_retained_binding(self):
        compiler, raw, binding = self.admit()
        self.assertEqual(compiler, self.compiler)
        self.assertEqual(raw, self.cold_path.read_bytes())
        self.assertEqual(binding, {
            "profile": "fixture-profile", "compiler_sha256": self.compiler_sha,
            "source_manifest_sha256": sha256(integration.encoded(self.sources)).hexdigest(),
            "support_contract_sha256": self.sources["docs/HIA_SELFHOST_CORE_SUPPORT.json"],
            "nested_report_sha256": integration.digest(self.nested_path)})

    def test_older_source_cold_is_refused_even_when_all_compiler_bytes_match(self):
        self.cold["source_manifest"]["tools/compiler.py"] = sha256(b"previous source B\n").hexdigest()
        self.nested["source_manifest"] = copy.deepcopy(self.cold["source_manifest"])
        self.save()
        with self.assertRaisesRegex(RuntimeError, "different Hepta source"):
            self.admit()

    def test_old_profile_is_refused_even_when_source_map_and_compiler_match(self):
        self.cold["profile"] = self.nested["profile"] = "previous-profile"
        self.save()
        with self.assertRaisesRegex(RuntimeError, "support profile"):
            self.admit()

    def test_complete_manifest_requires_contract_pin_and_no_extra_source(self):
        for mutation in ("missing_source", "missing_contract", "extra_source"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.cold)
                if mutation == "missing_source":
                    changed["source_manifest"].pop("tools/compiler.py")
                elif mutation == "missing_contract":
                    changed["source_manifest"].pop("docs/HIA_SELFHOST_CORE_SUPPORT.json")
                else:
                    changed["source_manifest"]["foreign.py"] = "f" * 64
                written(self.cold_path, changed)
                with self.assertRaisesRegex(RuntimeError, "different Hepta source"):
                    self.admit()

    def test_current_file_drift_is_refused_before_any_compiler_can_be_selected(self):
        self.source.write_bytes(b"unrecorded actual source\n")
        with self.assertRaisesRegex(RuntimeError, "file differs from its source contract"):
            self.admit()

    def test_assume_unchanged_cannot_rebind_source_and_contract_to_an_old_commit(self):
        self.git("update-index", "--assume-unchanged", "tools/compiler.py", "docs/HIA_SELFHOST_CORE_SUPPORT.json")
        self.source.write_bytes(b"different source hidden from git status\n")
        self.contract["source_identity"]["files"]["tools/compiler.py"] = integration.digest(self.source)
        self.sources = {**self.contract["source_identity"]["files"],
                        "docs/HIA_SELFHOST_CORE_SUPPORT.json": written(self.contract_path, self.contract)}
        self.cold["source_manifest"] = copy.deepcopy(self.sources)
        self.nested["source_manifest"] = copy.deepcopy(self.sources)
        self.save()
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), "")
        with self.assertRaisesRegex(RuntimeError, "differs from its selected Git commit"):
            self.admit()

    def test_nested_source_and_profile_cannot_hide_behind_a_recomputed_report_hash(self):
        for field, changed in (("source_manifest", {}), ("profile", "other")):
            with self.subTest(field=field):
                original = self.nested[field]
                self.nested[field] = changed
                self.save()
                with self.assertRaisesRegex(RuntimeError, "nested qualification belongs to different source"):
                    self.admit()
                self.nested[field] = original

    def test_nested_report_must_retain_its_exact_bytes(self):
        self.nested_path.write_bytes(self.nested_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(RuntimeError, "nested report drifted"):
            self.admit()

    def test_compiler_bytes_and_both_generation_chains_must_match(self):
        for location in ("compiler", "outer", "nested"):
            with self.subTest(location=location):
                if location == "compiler":
                    self.compiler.write_bytes(b"substituted compiler")
                elif location == "outer":
                    self.cold["generation_sha256"][0] = "f" * 64
                else:
                    self.nested["generations"][0]["produced_sha256"] = "f" * 64
                self.save()
                with self.assertRaisesRegex(RuntimeError, "retained fixed-point generation chain"):
                    self.admit()
                self.compiler.write_bytes(b"fixture compiler identity; never executable")
                self.cold["generation_sha256"] = [self.compiler_sha] * 3
                self.nested["generations"][0]["produced_sha256"] = self.compiler_sha

    def test_nested_report_and_compiler_cannot_escape_the_original_cold_directory(self):
        outside = self.root / "foreign-B3.bin"
        outside.write_bytes(self.compiler.read_bytes())
        self.nested["generations"][-1]["produced_image"] = str(outside)
        self.save()
        with self.assertRaisesRegex(RuntimeError, "B3 must come from the original"):
            self.admit()
        other_report = self.root / "foreign-report.json"
        other_report.write_bytes(self.nested_path.read_bytes())
        self.cold["nested_report"] = str(other_report)
        written(self.cold_path, self.cold)
        with self.assertRaisesRegex(RuntimeError, "does not name its own source-only"):
            self.admit()

    def test_original_required_checks_and_unchanged_budgets_are_not_relaxed(self):
        for field, value in (("status", "FAIL"), ("returncode", False),
                             ("qualification_wall_limit_seconds", 181), ("cleanup_wall_limit_seconds", 4),
                             ("checks", {})):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.cold)
                changed[field] = value
                written(self.cold_path, changed)
                with self.assertRaisesRegex(RuntimeError, "cold qualification is incomplete"):
                    self.admit()

    def test_contract_paths_are_checked_before_reading_outside_selected_source(self):
        self.contract["source_identity"]["files"] = {"../outside": "a" * 64}
        written(self.contract_path, self.contract)
        with self.assertRaisesRegex(RuntimeError, "invalid source identity"):
            self.admit()

    def test_incomplete_nested_generation_chain_is_not_a_pass(self):
        self.nested["generations"].pop()
        self.save()
        with self.assertRaisesRegex(RuntimeError, "incomplete generation chain"):
            self.admit()


class NativeColdReadbackTests(unittest.TestCase):
    """Non-executable custody fixtures; no fixture claims native gate execution."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.hepta = self.root / "source"
        (self.hepta / "docs").mkdir(parents=True)
        (self.hepta / "examples").mkdir()
        self.source = self.hepta / "examples/fixture.hepta"
        self.source.write_bytes(b"non-executable fixture source\n")
        self.contract_path = self.hepta / "docs/HIA_SELFHOST_CORE_SUPPORT.json"
        checks = ["export_manifest_matches_qualification", "native_hia_toolchain_only",
                  "nested_full_qualification_pass", "nested_process_exit_zero", "no_ancestor_git_identity",
                  "no_bytecode_cache_created", "fresh_home_and_tmp", "no_inherited_target_or_successor_images",
                  "origin_hashes_preserved", "owned_process_tree_cleanup_confirmed", "source_export_hashes_preserved",
                  "all_independent_references_before_B0", "lossless_phase_archives_verified",
                  "all_19_families_both_compilers"]
        self.contract = {"schema": "hepta.hia.selfhost-core-support.v1", "profile": "native-reader-fixture",
                         "source_identity": {"files": {"examples/fixture.hepta": integration.digest(self.source)}},
                         "native_cold_qualification": {"schema": "hepta.hia.selfhost-cold-replay.v2",
                                                       "checks": checks}}
        self.sources = {**self.contract["source_identity"]["files"],
                        "docs/HIA_SELFHOST_CORE_SUPPORT.json": written(self.contract_path, self.contract)}
        self.git("init", "-q", "--template=", "--initial-branch=fixture")
        self.git("add", ".")
        self.git("-c", "user.name=HIA test fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "native reader fixture")
        self.cold = self.root / "cold"
        (self.cold / "qualification/base").mkdir(parents=True)
        self.compiler = self.cold / "qualification/base/B3.flat"
        self.compiler.write_bytes(b"non-executable fixture compiler")
        self.compiler_sha = integration.digest(self.compiler)
        self.report = {"schema": "hepta.hia.selfhost-cold-replay.v2", "status": "NATIVE_COLD_SELFHOST_REPLAY_PASS",
                       "profile": self.contract["profile"], "returncode": 0,
                       "source_manifest": dict(self.sources), "generation_sha256": [self.compiler_sha] * 3,
                       "qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3,
                       "checks": dict.fromkeys(checks, True)}
        self.report_path = self.cold / "final-cold.json"
        written(self.report_path, self.report)
        self.bootstrap = self.root / "post-cold"
        self.bootstrap.mkdir()
        self.tools = {name: b"never executable: " + name.encode() for name in (
            "hia-source-build", "hia-release-owner", "hia-subprocess", "hia-source-capture",
            "hia-release-build", "hia-source-bootstrap", "hia-release")}
        self.tools["cold-inputs.receipt"] = (b"HIASBIN1" + bytes.fromhex(self.compiler_sha)
            + bytes.fromhex(integration.digest(self.report_path)) + b"HIAADC01"
            + bytes.fromhex(self.compiler_sha) + struct.pack("<Q", len(self.sources)))
        self.source_manifest = self.manifest({name: (self.hepta / name).read_bytes() for name in self.sources})
        self.save_bootstrap()

    def git(self, *arguments):
        return subprocess.check_output(["git", "-C", str(self.hepta), *arguments], text=True).strip()

    @staticmethod
    def manifest(files):
        raw = b"HIASXM01" + struct.pack("<3Q", len(files), 1, 0)
        for name, value in sorted(files.items()):
            encoded_name = name.encode("ascii")
            raw += struct.pack("<2Q", len(encoded_name), len(value)) + sha256(value).digest() + encoded_name
        return raw

    def save_bootstrap(self):
        for name, value in self.tools.items():
            (self.bootstrap / name).write_bytes(value)
        tools = self.manifest(self.tools)
        (self.bootstrap / "source.manifest.hiasxm").write_bytes(self.source_manifest)
        (self.bootstrap / "toolchain.manifest.hiasxm").write_bytes(tools)
        (self.bootstrap / "build.receipt").write_bytes(b"HIASBOK1" + struct.pack(
            "<7Q", 1, 1, len(self.sources), len(self.tools), len(self.source_manifest), len(tools), 0)
            + sha256(self.source_manifest).digest() + sha256(tools).digest())

    def admit(self):
        return integration.admit_native_cold_compiler(self.hepta, self.report_path, self.bootstrap)

    def test_native_reader_binds_exact_source_cold_B3_and_installer(self):
        compiler, raw, binding = self.admit()
        self.assertEqual(compiler, self.compiler)
        self.assertEqual(raw, self.report_path.read_bytes())
        self.assertEqual(binding["admission_domain"], "native-v2-post-cold-HIAADC01")
        self.assertEqual(binding["compiler_sha256"], self.compiler_sha)
        self.assertEqual(binding["native_installer_sha256"], integration.digest(self.bootstrap / "hia-release"))
        self.assertEqual(binding["post_cold_inputs_receipt_sha256"],
                         integration.digest(self.bootstrap / "cold-inputs.receipt"))

    def test_native_and_hosted_domains_cannot_substitute_for_each_other(self):
        with self.assertRaisesRegex(RuntimeError, "cold qualification is incomplete"):
            integration.admit_cold_compiler(self.hepta, self.report_path)
        for field, value in (("schema", "hepta.hia.selfhost-cold-replay.v1"),
                             ("status", "COLD_SELFHOST_REPLAY_PASS"), ("returncode", False),
                             ("qualification_wall_limit_seconds", 181), ("cleanup_wall_limit_seconds", 4),
                             ("checks", {})):
            with self.subTest(field=field):
                changed = {**self.report, field: value}
                written(self.report_path, changed)
                with self.assertRaisesRegex(RuntimeError, "native cold qualification is incomplete"):
                    self.admit()
        written(self.report_path, self.report)
        for magic in (b"HIATBOK1", b"HIASBIK1"):
            receipt = self.bootstrap / "build.receipt"
            receipt.write_bytes(magic + receipt.read_bytes()[8:])
            with self.assertRaisesRegex(RuntimeError, "public receipt is absent or belongs to another domain"):
                self.admit()

    def test_foreign_source_or_compiler_fails_before_native_tools_can_be_used(self):
        self.source.write_bytes(b"foreign source")
        with self.assertRaisesRegex(RuntimeError, "file differs from its source contract"):
            self.admit()
        self.source.write_bytes(b"non-executable fixture source\n")
        self.compiler.write_bytes(b"foreign compiler")
        with self.assertRaisesRegex(RuntimeError, "compiler differs from the retained cold fixed-point"):
            self.admit()

    def test_unchanged_cold_and_source_cannot_hide_a_substituted_installer(self):
        (self.bootstrap / "hia-release").write_bytes(b"substituted installer")
        with self.assertRaisesRegex(RuntimeError, "installed tool differs from its receipt: hia-release"):
            self.admit()

    def test_forged_tool_manifest_still_must_bind_original_cold_inputs(self):
        original = self.tools["cold-inputs.receipt"]
        for offset in (0, 8, 40, 72, 80, 112):
            with self.subTest(offset=offset):
                changed = bytearray(original)
                changed[offset] ^= 1
                self.tools["cold-inputs.receipt"] = bytes(changed)
                self.save_bootstrap()
                with self.assertRaisesRegex(RuntimeError, "does not bind this report, B3 and source count"):
                    self.admit()

    def test_forged_public_receipt_does_not_accept_another_source_inventory(self):
        self.source_manifest = self.manifest({**{name: (self.hepta / name).read_bytes()
                                                 for name in self.sources},
                                              "foreign.hepta": b"unrelated"})
        self.save_bootstrap()
        with self.assertRaisesRegex(RuntimeError, "source manifest differs from the selected Git source"):
            self.admit()

    def test_manifest_binding_and_exact_tool_inventory_are_required(self):
        path = self.bootstrap / "toolchain.manifest.hiasxm"
        path.write_bytes(path.read_bytes() + b"trailing")
        with self.assertRaisesRegex(RuntimeError, "does not bind its retained manifests"):
            self.admit()
        self.tools["foreign-tool"] = b"unadmitted"
        self.save_bootstrap()
        with self.assertRaisesRegex(RuntimeError, "installed tool inventory differs"):
            self.admit()

    def test_receipts_and_tools_cannot_be_rebound_through_links(self):
        path = self.bootstrap / "hia-release"
        outside = self.root / "same-installer"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "symbolic links"):
            self.admit()
        path.unlink()
        path.hardlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "file type or extent"):
            self.admit()

    def test_manifest_refuses_truncation_duplicates_unsafe_paths_and_trailing_data(self):
        single = self.manifest({"source.hepta": b"fixture"})
        row = single[32:]
        duplicate = b"HIASXM01" + struct.pack("<3Q", 2, 1, 0) + row + row
        cases = [single[:-1], single + b"x", duplicate, self.manifest({"../source": b"x"}),
                 self.manifest({"/source": b"x"}), self.manifest({"a/.git/source": b"x"})]
        for raw in cases:
            with self.subTest(raw=raw[:32]):
                with self.assertRaisesRegex(RuntimeError, "native file manifest"):
                    integration.native_file_manifest(raw)


class NativeReleaseReadbackTests(unittest.TestCase):
    """Mocked native command responses test orchestration, never qualification."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.hepta = self.root / "source"
        source = self.hepta / "examples/hia_bootstrap/agent_identity.hepta"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"non-executable identity source fixture")
        self.bootstrap = self.root / "bootstrap"
        self.bootstrap.mkdir()
        (self.bootstrap / "hia-release").write_bytes(b"never-executable installer fixture")
        self.binding = {"native_installer_sha256": integration.digest(self.bootstrap / "hia-release"),
                        "compiler_sha256": sha256(b"fixture B3").hexdigest()}
        self.package = self.root / "store.hiapack"
        self.package.write_bytes(b"non-executable package fixture; no native build claimed")
        self.package_sha = integration.digest(self.package)
        self.finalize = {"schema": "hepta.hia.release-finalize.v1", "sha256": self.package_sha,
                         "bytes": self.package.stat().st_size, "files": 2,
                         "published": True, "source_attested": True}
        self.finalize_path = self.root / "finalize.json"
        written(self.finalize_path, self.finalize)
        self.output = self.root / "evidence"
        self.output.mkdir()
        self.image = b"non-executable helper fixture"
        self.manifest = {"schema": "hepta.hia.agent-identity-native.v1",
                         "image_path": "agent-identity.image.bin", "image_sha256": sha256(self.image).hexdigest(),
                         "compiler_sha256": self.binding["compiler_sha256"], "source_sha256": integration.digest(source)}

    def native_response_fixture(self, argv, **kwargs):
        self.assertEqual(argv, [str(self.bootstrap / "hia-release"), argv[1],
                               str(self.output / "installed-release"), self.package_sha])
        self.assertEqual(kwargs["env"]["PATH"], "")
        self.assertEqual(kwargs["input"], self.package.read_bytes())
        self.assertEqual(kwargs["timeout"], 180)
        if argv[1] == "install":
            release = self.output / "installed-release" / self.package_sha
            release.mkdir()
            (release / "agent-identity.image.bin").write_bytes(self.image)
            written(release / "agent-identity-manifest.json", self.manifest)
        value = {"schema": "hepta.hia.release-install.v1", "sha256": self.package_sha,
                 "files": 2, "bytes": self.package.stat().st_size, "published": argv[1] == "install"}
        return subprocess.CompletedProcess(argv, 0, integration.encoded(value), b"")

    def readback(self):
        return integration.native_release_identity(self.hepta, self.bootstrap, self.package,
                                                   self.finalize_path, self.output, self.binding)

    def test_formal_package_is_installed_then_verified_with_empty_PATH(self):
        # Three links are the documented native finalizer output, not a source
        # input defect. All bytes still have to match the publication receipt.
        for name in ("work-package", "authority-package"):
            (self.root / name).hardlink_to(self.package)
        with mock.patch.object(integration.subprocess, "run", side_effect=self.native_response_fixture) as run:
            manifest, record = self.readback()
        self.assertEqual([call.args[0][1] for call in run.call_args_list], ["install", "verify"])
        self.assertEqual(manifest.name, "agent-identity-manifest.json")
        self.assertEqual(record["package_sha256"], self.package_sha)
        self.assertEqual(record["manifest"], self.manifest)
        self.assertIs(record["whole_stack_rewritten_in_hia"], False)
        self.assertIs(record["production_activated"], False)

    def test_package_and_source_attestation_receipt_are_checked_before_execution(self):
        for field, value in (("sha256", "f" * 64), ("bytes", self.finalize["bytes"] + 1),
                             ("files", 0), ("files", True), ("published", False),
                             ("source_attested", False), ("schema", "hepta.hia.release-install.v1")):
            with self.subTest(field=field, value=value):
                written(self.finalize_path, {**self.finalize, field: value})
                with mock.patch.object(integration.subprocess, "run") as run:
                    with self.assertRaisesRegex(RuntimeError, "source-attested publication receipt"):
                        self.readback()
                run.assert_not_called()
                self.assertFalse((self.output / "installed-release").exists())

    def test_installer_drift_after_cold_admission_prevents_execution(self):
        (self.bootstrap / "hia-release").write_bytes(b"different fixture")
        with mock.patch.object(integration.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "installer changed after post-cold admission"):
                self.readback()
        run.assert_not_called()

    def test_failed_install_is_retained_and_never_retried_or_verified(self):
        failed = subprocess.CompletedProcess([], 14, b"partial original receipt", b"original refusal")
        with mock.patch.object(integration.subprocess, "run", return_value=failed) as run:
            with self.assertRaisesRegex(RuntimeError, "native release install did not complete"):
                self.readback()
        self.assertEqual(run.call_count, 1)
        self.assertEqual((self.output / "release-install.stdout.json").read_bytes(), failed.stdout)
        self.assertEqual((self.output / "release-install.stderr.log").read_bytes(), failed.stderr)

    def test_foreign_helper_compiler_is_refused_after_installation_readback(self):
        self.manifest["compiler_sha256"] = "a" * 64
        with mock.patch.object(integration.subprocess, "run", side_effect=self.native_response_fixture) as run:
            with self.assertRaisesRegex(RuntimeError, "helper differs from the selected source or admitted B3"):
                self.readback()
        self.assertEqual(run.call_count, 2)

    def test_verify_must_return_its_exact_original_package_and_false_publication(self):
        def changed(argv, **kwargs):
            result = self.native_response_fixture(argv, **kwargs)
            if argv[1] == "verify":
                value = json.loads(result.stdout)
                value["published"] = True
                result.stdout = integration.encoded(value)
            return result
        with mock.patch.object(integration.subprocess, "run", side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, "native release verify receipt differs"):
                self.readback()

    def test_receipt_json_rejects_duplicate_keys_and_non_JSON_numbers(self):
        for raw in (b'{"published":false,"published":true}', b'{"bytes":NaN}', b'{"bytes":Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(RuntimeError, "native JSON receipt"):
                    integration.native_json(raw)


class SourceImportBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "source"
        package = self.repo / "tools"
        package.mkdir(parents=True)
        (package / "__init__.py").write_bytes(b"")
        self.source = package / "fixture_gate.py"
        self.source.write_bytes(b"SOURCE_MARKER = 'source'\ndef admit_cold_build(a, b):\n    raise ValueError('invalid cold')\n")
        (self.repo / ".gitignore").write_text("__pycache__/\n")
        self.git("init", "-q", "--template=", "--initial-branch=fixture")
        self.git("add", ".")
        self.git("-c", "user.name=HIA test fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "import fixture")

    def git(self, *arguments):
        return subprocess.check_output(["git", "-C", str(self.repo), *arguments], text=True).strip()

    def child(self, code, *arguments):
        return subprocess.run([sys.executable, "-I", "-B", "-c", code,
                               str(Path(__file__).with_name("hia_native_helper_mcp_integration.py")),
                               str(self.repo), str(self.root / "private-cache"), *map(str, arguments)],
                              cwd=self.repo, capture_output=True, text=True)

    def test_clean_source_import_runs_with_a_new_empty_private_cache(self):
        code = ("import importlib.util,json,pathlib,sys;"
                "s=importlib.util.spec_from_file_location('integration',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                "cache=pathlib.Path(sys.argv[3]);"
                "m.prepare_source_imports([pathlib.Path(sys.argv[2])],cache);"
                "sys.path.insert(0,sys.argv[2]);from tools import fixture_gate;"
                "print(json.dumps({'marker':fixture_gate.SOURCE_MARKER,'prefix':sys.pycache_prefix,"
                "'cache_empty':not list(cache.rglob('*')),'dont_write':sys.dont_write_bytecode}))")
        result = self.child(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed, {"marker": "source", "prefix": str(self.root / "private-cache"),
                                    "cache_empty": True, "dont_write": True})
        self.assertEqual(integration.source_import_inventory(self.repo)["files"], 2)

    def test_real_ignored_timestamp_valid_pyc_is_rejected_before_import(self):
        original = self.source.read_bytes()
        cache = Path(importlib.util.cache_from_source(str(self.source)))
        cache.parent.mkdir()
        payload = self.root / "cache-input.txt"
        payload.write_bytes(original + b"\nSOURCE_MARKER = 'untrusted-cache'\n"
                            b"def admit_cold_build(a, b):\n    return True\n")
        py_compile.compile(str(payload), cfile=str(cache), dfile=str(self.source), doraise=True)
        info = self.source.stat()
        compiled = cache.read_bytes()
        cache.write_bytes(importlib.util.MAGIC_NUMBER
                          + struct.pack("<III", 0, int(info.st_mtime), info.st_size) + compiled[16:])
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(self.git("status", "--porcelain"), "")
        baseline = self.child("import json,sys;sys.path.insert(0,sys.argv[2]);from tools import fixture_gate;"
                              "print(json.dumps({'marker':fixture_gate.SOURCE_MARKER,"
                              "'invalid_cold_accepted':fixture_gate.admit_cold_build(b'fixture',b'not-json')}))")
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertEqual(json.loads(baseline.stdout), {"marker": "untrusted-cache", "invalid_cold_accepted": True})
        with self.assertRaisesRegex(RuntimeError, "compiled Python cache or extension shadow"):
            integration.source_identity(self.repo, self.git("rev-parse", "HEAD"))
        hardened = self.child("import importlib.util,pathlib,sys;"
                             "s=importlib.util.spec_from_file_location('integration',sys.argv[1]);"
                             "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                             "m.prepare_source_imports([pathlib.Path(sys.argv[2])],pathlib.Path(sys.argv[3]));"
                             "sys.path.insert(0,sys.argv[2]);from tools import fixture_gate;"
                             "print(fixture_gate.SOURCE_MARKER)")
        self.assertNotEqual(hardened.returncode, 0)
        self.assertIn("compiled Python cache or extension shadow", hardened.stderr)
        self.assertNotIn("untrusted-cache", hardened.stdout)
        self.assertFalse((self.root / "private-cache").exists())

    def test_untracked_imports_and_extension_shadows_are_refused(self):
        for name in ("tools/untracked.py", "json.py", "tools/fixture_gate.so", "tools/fixture_gate.pyd"):
            with self.subTest(name=name):
                shadow = self.repo / name
                shadow.write_bytes(b"never imported")
                try:
                    with self.assertRaisesRegex(RuntimeError, "source differs|extension shadow"):
                        integration.source_import_inventory(self.repo)
                finally:
                    shadow.unlink()

    def test_new_root_packages_and_directory_symlinks_are_refused(self):
        for filename in ("__init__.py", "namespace_child.py", "__init__.pyc", "__init__.so"):
            with self.subTest(filename=filename):
                package = self.repo / "z3"
                package.mkdir()
                shadow = package / filename
                shadow.write_bytes(b"never imported")
                try:
                    with self.assertRaisesRegex(RuntimeError, "source differs|extension shadow"):
                        integration.source_import_inventory(self.repo)
                finally:
                    shadow.unlink()
                    package.rmdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "__init__.py").write_bytes(b"never imported")
        (self.repo / "typing").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "root Python package directories cannot be symbolic links"):
            integration.source_import_inventory(self.repo)

    def test_actual_client_script_is_bound_even_when_git_status_hides_its_change(self):
        directory = self.repo / "tests"
        directory.mkdir()
        client = directory / "hia_native_helper_mcp_integration.py"
        client.write_bytes(b"CLIENT_MARKER = 'original'\n")
        self.git("add", "tests/hia_native_helper_mcp_integration.py")
        self.git("-c", "user.name=HIA test fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "client fixture")
        self.git("update-index", "--assume-unchanged", "tests/hia_native_helper_mcp_integration.py")
        client.write_bytes(b"CLIENT_MARKER = 'changed'\n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        with self.assertRaisesRegex(RuntimeError, "source differs from the selected Git commit"):
            integration.source_identity(self.repo, self.git("rev-parse", "HEAD"))

    def test_selected_namespace_wins_over_an_external_regular_tools_package(self):
        self.git("rm", "-q", "tools/__init__.py")
        self.git("-c", "user.name=HIA test fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "namespace fixture")
        site = self.root / "external-site"
        package = site / "tools"
        package.mkdir(parents=True)
        marker = self.root / "external-package-executed"
        (package / "__init__.py").write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n")
        (package / "fixture_gate.py").write_text("SOURCE_MARKER = 'external'\n")
        runtime = self.root / "runtime"
        subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(self.repo), str(runtime)], check=True)
        code = ("import importlib.util,json,pathlib,sys;"
                "s=importlib.util.spec_from_file_location('integration',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                "sys.path.insert(0,sys.argv[4]);sys.path.insert(0,sys.argv[2]);"
                "before=importlib.util.find_spec('tools').origin;"
                "m.prepare_source_imports([pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[5])],pathlib.Path(sys.argv[3]));"
                "from tools import fixture_gate;"
                "print(json.dumps({'before':before,'marker':fixture_gate.SOURCE_MARKER,'origin':fixture_gate.__file__}))")
        result = self.child(code, site, runtime)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"before": str(package / "__init__.py"),
                                                    "marker": "source", "origin": str(self.source)})
        self.assertFalse(marker.exists())

    def test_preloaded_repository_modules_are_refused(self):
        result = self.child("import importlib.util,pathlib,sys,types;"
                            "s=importlib.util.spec_from_file_location('integration',sys.argv[1]);"
                            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                            "sys.modules['tools']=types.ModuleType('tools');"
                            "m.prepare_source_imports([pathlib.Path(sys.argv[2])],pathlib.Path(sys.argv[3]))")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loaded before source admission", result.stderr)
        self.assertFalse((self.root / "private-cache").exists())


if __name__ == "__main__":
    unittest.main()
