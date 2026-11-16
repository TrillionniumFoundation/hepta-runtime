"""Actual-process controls for native artifact partitioning and evidence admission.

Small temporary programs test the reporting machinery. They never qualify a
production HIA image or stand in for a compiler cold replay.
"""
from __future__ import annotations

import copy
import fnmatch
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_pipeline as p
import hia_native_failure as failure
import qualify_hia_runtime_native as q
import hia_native_view_fixture_qualification as fixtures
import hia_native_runtime_mcp_fixtures as public_fixtures
import hia_native_service_pipeline as service


class NativePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-pipeline-reporting-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_prepare_refuses_stale_public_reader_before_starting_compiler(self):
        import hia_native_filesystem_public_pipeline as public
        output = self.root / "refused-source"
        with patch.object(q, "initial_report", return_value={}), \
             patch.object(public, "producer_sources", side_effect=ValueError("stale frozen reference reader")), \
             patch.object(q, "prepare_native") as compiler:
            with self.assertRaisesRegex(ValueError, "stale frozen reference reader"):
                p.prepare(output, self.root / "compiler", "source-refusal-control")
            compiler.assert_not_called()
        report = json.loads((output / "result.json").read_bytes())
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["phase"], "native_build")

    def public_fixture(self, name="public-owned"):
        output = self.root / name
        workdir = output / "runtime-mcp/files/workdir"
        workdir.mkdir(parents=True)
        raw = workdir / os.fsdecode(b"raw-\xff")
        raw.write_bytes(b"complete\0\xff\n")
        raw.chmod(0o640)
        os.setxattr(raw, "user.hepta-retention", b"attribute\0\xff")
        os.link(raw, workdir / "hard")
        os.symlink(b"missing-\xff", os.fsencode(workdir / "link"))
        os.mkfifo(workdir / "fifo", 0o600)
        return output, {"reporting_fixture_only": True, "semantic_calls": 0}

    def test_public_fixture_roundtrip_preserves_bytes_xattrs_and_this_replay_inodes(self):
        output, binding = self.public_fixture()
        before = public_fixtures.snapshot(output, public_fixtures.NATIVE)
        admitted = public_fixtures.retired(output, "native", binding, str(output), create=True)
        self.assertEqual((admitted["files"], admitted["fifos"], admitted["hardlink_groups"]), (2, 1, 1))
        self.assertFalse((output / "runtime-mcp/files").exists())
        with public_fixtures.restored_native(output, admitted, binding, str(output)) as restored:
            self.assertEqual(public_fixtures.logical(restored), public_fixtures.logical(before))
            root = output / "runtime-mcp/files/workdir"
            item = root / os.fsdecode(b"raw-\xff")
            self.assertEqual(item.read_bytes(), b"complete\0\xff\n")
            self.assertEqual(os.getxattr(item, "user.hepta-retention"), b"attribute\0\xff")
            self.assertEqual(item.stat().st_ino, (root / "hard").stat().st_ino)
            # Exercise the replay's private rename boundary with real inodes;
            # this mechanical fixture executes no HIA or Rust semantics.
            held = root.with_name("held-for-reporting-test")
            original_inode = root.stat().st_ino
            root.rename(held)
            root.mkdir()
            (root / "temporary").write_bytes(b"separate original execution tree")
            shutil.rmtree(root)
            held.rename(root)
            self.assertEqual(root.stat().st_ino, original_inode)
        result = public_fixtures.retained_reconstruction(output, admitted, str(output))
        self.assertTrue(result["this_replay_before_after_inode_identity_preserved"])
        self.assertIs(result["source_inodes_recreated"], False)
        self.assertEqual(public_fixtures.retired(output, "native", binding, str(output)), admitted)

    def test_public_fixture_rejects_external_hardlinks_and_symlink_roots(self):
        output, binding = self.public_fixture()
        outside = self.root / "unrelated"
        outside.write_bytes(b"preserve unrelated owner")
        alias = output / "runtime-mcp/files/external-hardlink"
        os.link(outside, alias)
        with self.assertRaisesRegex(ValueError, "hardlink leaves"):
            public_fixtures.retired(output, "native", binding, str(output), create=True)
        self.assertEqual(outside.read_bytes(), b"preserve unrelated owner")
        alias.unlink()
        source = output / "runtime-mcp/files"
        source.rename(output / "runtime-mcp/held")
        source.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "not a directory"):
            public_fixtures.retired(output, "native", binding, str(output), create=True)
        self.assertTrue(source.is_symlink())
        self.assertEqual(outside.read_bytes(), b"preserve unrelated owner")

    def test_public_fixture_refuses_physical_and_resigned_metadata_changes_before_restore(self):
        output, binding = self.public_fixture()
        admitted = public_fixtures.retired(output, "native", binding, str(output), create=True)
        archive = output / "runtime-mcp/retired-fixtures.bin.gz"
        original = archive.read_bytes()
        archive.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "archive differs"):
            public_fixtures.retired(output, "native", binding, str(output))
        archive.write_bytes(original)
        receipt = output / "runtime-mcp/retired-fixtures.json"
        original = receipt.read_bytes()
        for field in ("path_hex", "link_group", "nlink", "mode", "xattrs"):
            changed = public_fixtures.decode(original)
            files = [row for row in changed["entries"] if row["kind"] == "file"]
            if field == "path_hex":
                files[0][field] = b"runtime-mcp/files/../outside".hex()
            elif field == "link_group":
                files[0][field] = b"runtime-mcp/files/outside".hex()
            elif field == "nlink":
                files[0][field] += 1
            elif field == "mode":
                for row in files:
                    row[field] ^= 0o040
            else:
                for row in files:
                    row[field] = {}
            receipt.write_bytes(public_fixtures.encoded(changed))
            with self.subTest(field=field), self.assertRaises(ValueError):
                with public_fixtures.restored_native(output, admitted, binding, str(output)):
                    self.fail("altered archive reached reconstruction")
            self.assertFalse((output / "runtime-mcp/files").exists())
            self.assertFalse((output / public_fixtures.RESTORE).exists())
        receipt.write_bytes(original)
        self.assertEqual(public_fixtures.retired(output, "native", binding, str(output)), admitted)

    def test_public_fixture_relocated_readers_never_reconstruct_an_old_origin(self):
        output, binding = self.public_fixture()
        origin = str(output)
        admitted = public_fixtures.retired(output, "native", binding, origin, create=True)
        with public_fixtures.restored_native(output, admitted, binding, origin):
            pass
        expected = public_fixtures.retained_reconstruction(output, admitted, origin)
        moved = self.root / "relocated-output"
        shutil.copytree(output, moved)
        shutil.rmtree(output)
        with patch.object(public_fixtures, "populate", side_effect=AssertionError("reader started reconstruction")):
            self.assertEqual(public_fixtures.retired(moved, "native", binding, origin), admitted)
            self.assertEqual(public_fixtures.retained_reconstruction(moved, admitted, origin), expected)
            with self.assertRaisesRegex(ValueError, "exact admitted native execution origin"):
                with public_fixtures.restored_native(moved, admitted, binding, origin):
                    self.fail("relocated evidence started original execution")
        self.assertFalse(output.exists())
        self.assertFalse((moved / "runtime-mcp/files").exists())
    def test_ci_path_filters_cover_every_required_source_for_push_and_pull_request(self):
        workflow = (ROOT / ".github/workflows/hia-runtime-native.yml").read_text()
        events = workflow.split("\npermissions:", 1)[0]
        push, pull_request = events.split("  pull_request:\n", 1)
        parse = lambda text: re.findall(r"^      - '([^']+)'$", text, re.MULTILINE)
        push, pull_request = parse(push), parse(pull_request)
        self.assertEqual(push, pull_request)
        self.assertEqual(len(push), len(set(push)))
        uncovered = [name for name in q.sources() if not any(fnmatch.fnmatchcase(name, pattern) for pattern in push)]
        self.assertEqual(uncovered, [], "required source changes must trigger the actual native gate")

    def test_service_original_inventory_keeps_streams_outside_all_workdir_fixtures(self):
        output = self.root / "actual"; output.mkdir()
        outside = self.root / "outside"; outside.mkdir()
        sentinel = outside / "keep"; sentinel.write_bytes(b"external fixture target")
        folder = output / "workdir-original"; folder.mkdir()
        streams = {}
        for domain in ("probe-v1", "public", "regex"):
            fixture = folder / domain / "fixture"; fixture.mkdir(parents=True)
            (fixture / "link").symlink_to(outside, target_is_directory=True)
            (fixture / "ordinary").write_bytes(b"transient live state")
            retained = folder / domain / "stdout.bin"
            retained.write_bytes(domain.encode())
            streams[retained.relative_to(output).as_posix()] = service.sha(domain.encode())
        target = folder / "target"; target.mkdir()
        (target / "generated-link").symlink_to(outside, target_is_directory=True)
        result = service.retained_files(output, folder, service.WORKDIR_ORIGINAL_FIXTURES + ("workdir-original/target",))
        self.assertEqual(result, streams)
        self.assertEqual(sentinel.read_bytes(), b"external fixture target")

    def test_service_original_inventory_refuses_unknown_or_replaced_fixture_links(self):
        output = self.root / "actual"; output.mkdir()
        folder = output / "workdir-original"; folder.mkdir()
        outside = self.root / "outside"; outside.mkdir()
        unknown = folder / "undeclared-link"
        unknown.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory is not owned"):
            service.retained_files(output, folder, service.WORKDIR_ORIGINAL_FIXTURES)
        unknown.unlink()
        declared = folder / "probe-v1/fixture"; declared.parent.mkdir()
        declared.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory is not owned"):
            service.retained_files(output, folder, service.WORKDIR_ORIGINAL_FIXTURES)
        self.assertTrue(declared.is_symlink())

    def test_service_fixture_retirement_preserves_external_targets_and_exact_receipt(self):
        output = self.root / "actual"; output.mkdir()
        folder = output / "workdir-native/regex"; folder.mkdir(parents=True)
        fixture = folder / "fixture"; fixture.mkdir()
        denied = fixture / "denied"; denied.mkdir()
        (denied / "state").write_bytes(b"closed fixture")
        outside = self.root / "outside"; outside.mkdir()
        sentinel = outside / "keep"; sentinel.write_bytes(b"must remain")
        (fixture / "directory-link").symlink_to(outside, target_is_directory=True)
        (fixture / "file-link").symlink_to(sentinel)
        denied.chmod(0)
        self.addCleanup(lambda: denied.chmod(0o700) if denied.exists() else None)
        receipt = output / "workdir-native/retired-fixtures.json"
        evidence = {"status": "PASS", "actual_corpus_sha256": "a" * 64}
        fixtures = ("workdir-native/regex/fixture",)
        result = service.retire_fixtures(output, fixtures, receipt, evidence, create=True)
        self.assertFalse(fixture.exists())
        self.assertEqual(sentinel.read_bytes(), b"must remain")
        self.assertEqual(result, service.retire_fixtures(output, fixtures, receipt, evidence))
        with self.assertRaisesRegex(ValueError, "evidence differs"):
            service.retire_fixtures(output, fixtures, receipt, dict(evidence, actual_corpus_sha256="b" * 64))
        fixture.mkdir()
        with self.assertRaisesRegex(ValueError, "reappeared"):
            service.retire_fixtures(output, fixtures, receipt, evidence)

    def test_service_fixture_retirement_checks_every_target_before_removal(self):
        output = self.root / "actual"; output.mkdir()
        fixture = output / "safe/fixture"; fixture.mkdir(parents=True)
        sentinel = fixture / "keep"; sentinel.write_bytes(b"not admitted")
        with self.assertRaisesRegex(ValueError, "path escaped"):
            service.retire_fixtures(output, ("safe/fixture", "../outside/fixture"), output / "receipt.json", {}, create=True)
        self.assertEqual(sentinel.read_bytes(), b"not admitted")
        outside = self.root / "outside/fixture"; outside.mkdir(parents=True)
        link = output / "replaced/fixture"; link.parent.mkdir()
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "not an owned directory"):
            service.retire_fixtures(output, ("safe/fixture", "replaced/fixture"), output / "receipt.json", {}, create=True)
        self.assertEqual(sentinel.read_bytes(), b"not admitted")
        self.assertFalse((output / "receipt.json").exists())

    def test_partition_is_complete_unique_and_keeps_evidence_dependencies(self):
        partitions = p.partition_tests()
        flat = [name for tests in partitions.values() for name in tests]
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(set(flat), set(q.native_tests()))
        for ordered in (("test_view_regex_search.py", "test_view_regex_search_native_evidence.py"),
                        ("test_runtime_mcp.py", "test_runtime_mcp_evidence.py",
                         "test_view_regex_search_public.py", "test_view_regex_search_public_evidence.py",
                         "test_runtime_mcp_raw_value.py", "test_runtime_mcp_raw_value_evidence.py")):
            positions = [partitions["view"].index(name) for name in ordered]
            self.assertEqual(positions, sorted(positions))
        self.assertEqual(set(partitions), {"batch_planning", "batch_effects", "text", "shell", "view_components", "view", "json", "execution", "config", "system", "storage"})
        self.assertEqual(partitions["storage"], q.storage_pipeline.TESTS)
        config = next(row for row in q.MODULES if row["key"] == "runtime_config")
        span = next(row for row in q.MODULES if row["key"] == "runtime_config_span")
        self.assertEqual(partitions["config"],
                         (config["test"], *config["additional_tests"],
                          span["test"], *span["additional_tests"]))
        self.assertTrue(set(partitions["config"]).isdisjoint(partitions["json"]))
        self.assertEqual((len(partitions["batch_planning"]), len(partitions["batch_effects"])), (4, 23))
        self.assertEqual(partitions["batch_planning"] + partitions["batch_effects"],
            ("test_batch_edit_params.py", "test_batch_plan_input.py", "test_batch_plan.py", "test_batch_plan_evidence.py", "test_batch_apply.py",
             "test_batch_apply_contract.py", "test_batch_apply_artifacts.py", "test_batch_apply_evidence.py",
             "test_batch_diff.py",
             "test_atomic_write_policy.py", "test_atomic_write_kernel.py", "test_atomic_write_boundary.py",
             "test_atomic_write_evidence.py", "test_shared_atomic.py", "test_write_chain_controller.py",
             "test_write_chain_files.py", "test_write_chain_kernel.py", "test_write_chain_concurrency.py",
             "test_write_chain_evidence.py", "test_batch_write_controller.py", "test_batch_render.py",
             "test_utf8_probe.py", "test_batch_write_files.py", "test_batch_write_kernel.py",
             "test_batch_write_concurrency.py", "test_batch_write_wide.py", "test_batch_write_evidence.py"))
        self.assertEqual(partitions["system"][:3],
                         ("test_filesystem_parity_state.py", "test_filesystem_parity_build.py",
                          "test_filesystem_parity_kernel.py"))
        self.assertEqual(len(flat), 225)
        self.assertLess(partitions['view'].index('test_runtime_mcp.py'),
                        partitions['view'].index('test_filesystem_public.py'))
        self.assertNotIn('test_filesystem_public_original_evidence.py', flat)
        workflow = (q.ROOT / '.github/workflows/hia-runtime-native.yml').read_text()
        self.assertIn("if: matrix.group == 'system' || matrix.group == 'shell' || matrix.group == 'config' || matrix.group == 'view'", workflow)
        self.assertEqual(partitions['config'][-2:], ('test_config_span.py', 'test_config_span_evidence.py'))
        for bad in ("missing", "duplicate", "unknown", "new_module", "split_ordered"):
            changed = copy.deepcopy(p.PARTITIONS)
            modules = q.MODULES
            if bad == "missing":
                changed["text"] = changed["text"][1:]
            elif bad == "duplicate":
                changed["text"] += ("batch_apply",)
            elif bad == "unknown":
                changed["text"] += ("unregistered",)
            elif bad == "new_module":
                modules += ({"key": "unpartitioned", "test": "unpartitioned.py"},)
            else:
                modules = tuple(dict(row, additional_tests=()) if row["key"] == "serde_json" else
                                dict(row, additional_tests=("test_serde_json_transport.py", "test_json_evidence.py"))
                                if row["key"] == "runtime_bytes" else row for row in modules)
            with self.subTest(bad=bad), patch.object(q, "MODULES", modules), self.assertRaises(ValueError):
                p.partition_tests(changed)

    def test_filesystem_export_requires_retirement_before_artifact_inventory(self):
        output = self.root / "filesystem-shard"
        capture = output / "filesystem-parity/native/captures-v1"
        capture.mkdir(parents=True)
        native_bytes = b"complete reporting-fixture result\x00\xff"
        (capture / "retained.bin").write_bytes(native_bytes)
        outside = self.root / "outside"
        outside.write_bytes(b"unrelated bytes")
        fixture = capture / "private-target"
        fixture.mkdir()
        (fixture / "alias").symlink_to(outside)
        report = {"checks": [{"name": "test_filesystem_parity_kernel.py"}],
                  "qualification_shard": {"reporting_fixture_only": True}}
        destination = self.root / "filesystem-export"
        retirement = output / "filesystem-parity/retired-fixtures.json"

        def retire(actual_output, actual_report, *, create):
            self.assertEqual((actual_output, actual_report, create), (output, report, True))
            self.assertEqual((capture / "retained.bin").read_bytes(), native_bytes)
            self.assertTrue((fixture / "alias").is_symlink())
            # Only tests dispatch ordering. The actual filesystem evidence
            # helper separately admits retained bytes before touching targets.
            (fixture / "alias").unlink()
            fixture.rmdir()
            retirement.write_text('{"reporting_fixture_only":true}\n')
            return {"reporting_fixture_only": True}

        with patch.object(q, "filesystem_parity_retirement", side_effect=retire) as called:
            p.export_shard(output, destination, {"files": {}}, report)
        called.assert_called_once_with(output, report, create=True)
        self.assertEqual((destination / "data/filesystem-parity/native/captures-v1/retained.bin").read_bytes(),
                         native_bytes)
        self.assertEqual((destination / "data/filesystem-parity/retired-fixtures.json").read_bytes(),
                         retirement.read_bytes())
        self.assertFalse((destination / "data/filesystem-parity/native/captures-v1/private-target").exists())
        self.assertEqual(outside.read_bytes(), b"unrelated bytes")

    def test_filesystem_export_refuses_unadmitted_kernel_and_skips_unrelated_shards(self):
        output = self.root / "filesystem-failed-shard"
        output.mkdir()
        (output / "retained.bin").write_bytes(b"preserve actual failure")
        report = {"checks": [{"name": "test_filesystem_parity_kernel.py"}], "qualification_shard": {}}
        destination = self.root / "filesystem-refused-export"
        with patch.object(q, "filesystem_parity_retirement", side_effect=ValueError("native evidence incomplete")), \
                self.assertRaisesRegex(ValueError, "native evidence incomplete"):
            p.export_shard(output, destination, {"files": {}}, report)
        self.assertEqual(list((destination / "data").iterdir()), [])
        self.assertEqual((output / "retained.bin").read_bytes(), b"preserve actual failure")
        for name in ("test_filesystem_parity_state.py", "test_filesystem_parity_build.py", "unrelated.py"):
            with self.subTest(name=name), patch.object(q, "filesystem_parity_retirement") as called:
                selected = dict(report, checks=[{"name": name}])
                p.export_shard(output, self.root / (name + "-export"), {"files": {}}, selected)
                called.assert_not_called()

    def test_public_view_chain_stays_complete_before_fixture_retirement(self):
        partitions = p.partition_tests()
        self.assertEqual(partitions["view_components"], (
            "test_view_render.py", "test_view_transport.py", "test_view_render_growth.py",
            "test_view_render_growth_evidence.py", "test_view_cache.py", "test_view_cache_evidence.py",
            "test_history.py", "test_history_evidence.py", "test_session_workdir.py", "test_session_evidence.py"))
        self.assertEqual(len(partitions["view"]), 20)
        self.assertTrue(set(partitions["view_components"]).isdisjoint(partitions["view"]))
        public = ("view_read", "view_params", "view_call", "runtime_mcp", "filesystem_public")
        for moved in public:
            changed = copy.deepcopy(p.PARTITIONS)
            changed["view"] = tuple(key for key in changed["view"] if key != moved)
            changed["view_components"] += (moved,)
            with self.subTest(moved=moved), self.assertRaisesRegex(ValueError, "public View"):
                p.partition_tests(changed)
        changed = copy.deepcopy(p.PARTITIONS)
        changed["view"] = tuple(reversed(changed["view"]))
        with self.assertRaisesRegex(ValueError, "public View"):
            p.partition_tests(changed)

    def test_complete_local_create_evidence_stays_after_its_producers(self):
        item = q.local_create_spec_qualification.MODULE
        tests = (item["test"], *item["additional_tests"])
        actual = p.partition_tests()["system"]
        self.assertEqual(tuple(name for name in actual if name in tests), tests)
        changed = dict(item)
        changed["additional_tests"] = tuple(reversed(item["additional_tests"]))
        modules = tuple(changed if row["key"] == item["key"] else row for row in q.MODULES)
        with patch.object(q, "MODULES", modules), self.assertRaisesRegex(ValueError, "producer and evidence"):
            p.partition_tests()

    def test_workflow_requires_all_partitions_with_unchanged_process_and_job_limits(self):
        workflow = (ROOT / ".github/workflows/hia-runtime-native.yml").read_text()
        block = workflow.split("\n  native:\n", 1)[1].split("\n  native_collect:\n", 1)[0]
        groups = re.search(r"^        group: \[([^\]]+)\]$", block, re.MULTILINE)
        self.assertIsNotNone(groups)
        self.assertEqual(tuple(value.strip() for value in groups[1].split(",")), tuple(p.PARTITIONS))
        self.assertEqual(block.count("    timeout-minutes: 15\n"), 1)
        self.assertIn("      fail-fast: false\n", block)
        self.assertIn("    needs: prepare\n", block)
        self.assertEqual(block.count('--prepared-sha256 "${{ needs.prepare.outputs.prepared_sha256 }}"'), 1)
        self.assertEqual(block.count('--invocation "${{ github.run_id }}-${{ github.run_attempt }}"'), 1)
        self.assertIn('name: hia-native-build-${{ github.event.pull_request.head.sha || github.sha }}-${{ github.run_attempt }}', block)
        self.assertIn('name: hia-native-shard-${{ github.event.pull_request.head.sha || github.sha }}-${{ github.run_attempt }}-${{ matrix.group }}', block)
        originals = re.findall(r"^  original_([a-z]+):$", workflow, re.MULTILINE)
        self.assertEqual(originals, ["bytes", "state", "services", "json", "config", "system", "batch", "storage"])
        original_workflow = (ROOT / ".github/workflows/hia-runtime-original-shard.yml").read_text()
        self.assertEqual(original_workflow.count("    timeout-minutes: 45\n"), 1)
        changed = copy.deepcopy(p.PARTITIONS)
        changed["json"] += changed["config"]
        changed["config"] = ()
        with self.assertRaisesRegex(ValueError, "independent partition"):
            p.partition_tests(changed)

    def test_batch_families_cannot_be_recombined_or_move_evidence_across_jobs(self):
        for change in ("recombine", "move_apply", "split_plan_evidence"):
            changed = copy.deepcopy(p.PARTITIONS)
            modules = q.MODULES
            if change == "recombine":
                changed["batch"] = changed.pop("batch_planning") + changed.pop("batch_effects")
            elif change == "move_apply":
                changed["batch_planning"] += ("batch_apply",)
                changed["batch_effects"] = changed["batch_effects"][1:]
            else:
                modules = tuple(dict(row, additional_tests=()) if row["key"] == "batch_plan" else
                                dict(row, additional_tests=(*row.get("additional_tests", ()), "test_batch_plan_evidence.py"))
                                if row["key"] == "batch_apply" else row for row in modules)
            with self.subTest(change=change), patch.object(q, "MODULES", modules), self.assertRaises(ValueError):
                p.partition_tests(changed)

    def test_failure_diagnostics_survive_denied_fixtures_without_mutation(self):
        source = self.root / "failed"; source.mkdir()
        denied = source / "atomic-write-original/native-kernel/0012-denied-parent/fixture/denied"
        denied.mkdir(parents=True)
        (denied / "private.json").write_bytes(b"not diagnostic evidence")
        denied.chmod(0)
        self.addCleanup(denied.chmod, 0o700)
        report = {"status": "FAIL", "failure": "original comparison refused",
                  "checks": [{"name": "atomic-write-rust-compare", "exit_code": 1, "timed_out": False}]}
        (source / "result.json").write_text(json.dumps(report))
        nested = source / "atomic-write-original/result.json"
        nested.write_text('{"status":"FAIL","failure":"kernel observation mismatch"}')
        raw = b"actual stderr: \xff\x00\n"
        (source / "atomic-write-rust-compare.stderr").write_bytes(raw)
        outside = self.root / "outside.json"; outside.write_bytes(b"outside")
        (source / "escape.json").symlink_to(outside)
        (source / "escape-directory").symlink_to(self.root, target_is_directory=True)
        before = {path: path.read_bytes() for path in
                  (source / "result.json", nested, source / "atomic-write-rust-compare.stderr", outside)}
        destination = self.root / "diagnostics"
        receipt = failure.capture(source, destination)
        self.assertEqual(receipt["original_status"], "FAIL")
        self.assertEqual(receipt["failed_checks"][0]["name"], "atomic-write-rust-compare")
        self.assertFalse(receipt["qualification_admitted"])
        self.assertTrue(receipt["diagnostic_subset_only"])
        self.assertEqual((destination / "data/atomic-write-rust-compare.stderr").read_bytes(), raw)
        self.assertEqual((destination / "data/atomic-write-original/result.json").read_bytes(), before[nested])
        self.assertFalse((destination / "data/escape.json").exists())
        self.assertFalse((destination / "data/escape-directory").exists())
        self.assertFalse((destination / "data/atomic-write-original/native-kernel/0012-denied-parent/fixture").exists())
        self.assertEqual(denied.stat().st_mode & 0o7777, 0)
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        self.assertTrue(any(row["path"].endswith("/fixture") for row in receipt["skipped"]))
        self.assertTrue(any(row["path"] == "escape.json" for row in receipt["errors"]))
        with self.assertRaises(FileExistsError):
            failure.capture(source, destination)
        with self.assertRaisesRegex(ValueError, "separate"):
            failure.capture(source, source / "nested-diagnostics")

    def test_original_failure_capture_keeps_raw_domains_and_excludes_live_cargo_cache(self):
        source = self.root / "partial-original"; source.mkdir()
        target = source / "connection-original/target/release/deps"
        target.mkdir(parents=True)
        (target / "rmetaFZWET8").symlink_to(self.root / "already-retired-cargo-temporary")
        retained = {
            "connection-original/project/src/main.rs": b"// exact original source\n",
            "connection-original/project/Cargo.lock": b"version = 4\n",
            "connection-original/requests.bin": b"\x00\xff\x80\n",
            "connection-original/partial-output.bin.gz": b"complete captured gzip bytes\x00",
            "connection-original/build.stderr.log": b"actual interrupted compiler log\xff",
        }
        for name, raw in retained.items():
            path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        destination = self.root / "stable-diagnostics"
        receipt = failure.capture(source, destination)
        self.assertEqual(receipt["capture_errors"], 0)
        self.assertEqual(set(receipt["files"]), set(retained))
        for name, raw in retained.items():
            self.assertEqual((destination / "data" / name).read_bytes(), raw)
            self.assertEqual((source / name).read_bytes(), raw)
        self.assertTrue(any(row["path"] == "connection-original/target" for row in receipt["skipped"]))
        self.assertFalse((destination / "data/connection-original/target").exists())
        self.assertTrue((target / "rmetaFZWET8").is_symlink())

    def test_transport_mode_restore_requires_all_exact_owned_bytes(self):
        folder = self.root / "data"; folder.mkdir()
        for name in ("a.elf", "b.bin"):
            (folder / name).write_bytes(b"\x7fELF" + name.encode())
            (folder / name).chmod(0o700)
        files, _ = p.inventory(folder)
        for name in files:
            (folder / name).chmod(0o644)
        p.verify_files(folder, files, restore_modes=True)
        self.assertEqual((folder / "a.elf").stat().st_mode & 0o7777, 0o700)
        (folder / "a.elf").chmod(0o644)
        (folder / "b.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            p.verify_files(folder, files, restore_modes=True)
        self.assertEqual((folder / "a.elf").stat().st_mode & 0o7777, 0o644)

    def test_file_lock_corpus_producer_cannot_move_after_or_away_from_service(self):
        suites = p.partition_tests()["text"]
        ordered = q.file_lock_pipeline.ORDERED_SUITES
        self.assertEqual(tuple(name for name in suites if name in ordered), ordered)
        for mutation in ("split", "reverse"):
            changed = copy.deepcopy(p.PARTITIONS)
            if mutation == "split":
                changed["text"] = tuple(key for key in changed["text"] if key != "file_lock_service")
                changed["system"] += ("file_lock_service",)
            else:
                changed["text"] = tuple("file_lock_service" if key == "file_locks" else
                                        "file_locks" if key == "file_lock_service" else key
                                        for key in changed["text"])
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "file-lock"):
                p.partition_tests(changed)

    def test_diagnostic_capture_resources_and_controls_stay_in_order(self):
        suites = p.partition_tests()["execution"]
        expected = q.serde_error_pipeline.TESTS
        self.assertEqual(tuple(name for name in suites if name in expected), expected)
        for changed in (expected[::-1], (expected[0], expected[2], expected[1])):
            modules = tuple(dict(row, test=changed[0], additional_tests=changed[1:])
                            if row["key"] == "serde_error" else row for row in q.MODULES)
            with self.subTest(order=changed), patch.object(q, "MODULES", modules), \
                    self.assertRaisesRegex(ValueError, "producer and evidence"):
                p.partition_tests()

    def test_diagnostic_launcher_and_completed_outer_receipt_are_exact(self):
        source = self.root / "source"; source.mkdir()
        output = self.root / "output"; output.mkdir()
        launcher = source / "fixed_launcher.py"
        launcher.write_text("import json,sys\nassert sys.argv[1:]==['--phase','base']\n"
                            "print(json.dumps({'reporting_fixture':True}))\n")
        name = q.serde_error_pipeline.TESTS[0]
        command = [sys.executable, "-I", "-B", str(launcher), "--phase", "base"]
        report = {"phase": "native_components", "checks": []}
        with patch.object(q, "ROOT", source), \
                patch.object(q.serde_error_pipeline, "test_commands", return_value={name: command}):
            for changed in (command + ["--skip"], command[:-1] + ["controls"],
                            [sys.executable, "-I", "-B", str(source / "tests/hia_native" / name)]):
                with self.subTest(command=changed), self.assertRaisesRegex(ValueError, "source-owned"):
                    q.run_native_checks(output, report, (name,), q.qualification_env(),
                        parallel_tests=(), ordered_groups=(), commands={name: changed})
                self.assertEqual(report["checks"], [])
            q.run_native_checks(output, report, (name,), q.qualification_env(),
                parallel_tests=(), ordered_groups=(), commands={name: command})
        row, summary = q.serde_error_pipeline.complete(source, output, report, name,
                                                       command, q.completed_test_summary)
        self.assertEqual(summary, {"reporting_fixture": True})
        for field, changed in (("command", command + ["extra"]), ("timeout_seconds", 181),
                               ("elapsed_seconds", 180.01), ("timed_out", True), ("exit_code", 1)):
            broken = copy.deepcopy(report); broken["checks"][0][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                q.serde_error_pipeline.complete(source, output, broken, name,
                                                command, q.completed_test_summary)

    def test_artifact_path_symlink_and_special_mode_refusals(self):
        folder = self.root / "data"; folder.mkdir()
        (folder / "plain").write_bytes(b"real")
        files, _ = p.inventory(folder)
        for name in ("../outside", "/absolute", "a/../plain", "./plain", "a//plain", "a\\plain", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                p.relative_path(name)
        altered = copy.deepcopy(files); altered["plain"]["mode"] = 0o4755
        with self.assertRaisesRegex(ValueError, "permission bits"):
            p.verify_files(folder, altered, restore_modes=True)
        altered = copy.deepcopy(files); altered["plain"]["bytes"] = True
        with self.assertRaises(ValueError):
            p.verify_files(folder, altered)
        (folder / "link").symlink_to(folder / "plain")
        with self.assertRaises(ValueError):
            p.inventory(folder)
        (folder / "link").unlink()
        (folder / "subdir").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            p.inventory(folder)

    def test_duplicate_json_fields_are_never_accepted(self):
        path = self.root / "receipt.json"
        path.write_text('{"status":"FAIL","status":"PASS"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            p.read_json(path)

    def actual_fixture(self):
        source = self.root / "source"
        tests = source / "tests/hia_native"; tests.mkdir(parents=True)
        output = self.root / "output"; output.mkdir()
        (output / "empty-evidence/before").mkdir(parents=True)
        (output / "empty-evidence/after").mkdir()
        script = tests / "check.py"
        script.write_text("import json,sys\nprint(json.dumps({'actual_reporting_fixture':True}))\n"
                          "print('retained fixture stderr',file=sys.stderr)\n")
        prepared = {"status": "NATIVE_BUILD_READY", "phase": "native_build_complete",
                    "native_components_status": "PENDING", "source_sha256": {"fixture": "unchanged"},
                    "whole_runtime_replaced": False, "checks": [{"name": "compiler-full-cold",
                        "command": ["synthetic-cold-identity-only", "--output", str(output / "compiler-cold.json")]}]}
        report = copy.deepcopy(prepared)
        report.update(status="RUNNING", phase="native_components", native_components_status="RUNNING",
            qualification_shard={"group": "text", "invocation": "reporting-fixture", "prepared_sha256": "a" * 64,
                                 "tests": ["check.py"]})
        with patch.object(q, "ROOT", source):
            q.run_native_checks(output, report, ("check.py",), p.q.qualification_env(),
                                parallel_tests=(), ordered_groups=(), timeout=180)
        report.update(status="NATIVE_SHARD_PASS", phase="native_shard_complete", native_components_status="PARTIAL",
                      shard_elapsed_seconds=report["checks"][-1]["elapsed_seconds"], shard_finished_at="fixture")
        destination = self.root / "export"
        p.export_shard(output, destination, {"files": {}}, report)
        return source, prepared, report, destination

    def admit_fixture(self, source, prepared, destination):
        with patch.object(q, "ROOT", source), patch.object(p, "partition_tests", return_value={"text": ("check.py",)}), \
                patch.object(q, "native_commands", return_value={}):
            return p.admit_shard(destination / "data", destination / "shard.json", destination / "shard-report.json",
                                 prepared, "a" * 64, "reporting-fixture", "text", exact_files=True)

    def reseal_fixture(self, destination, report):
        q.save_report(destination / "shard-report.json", report)
        seal = p.read_json(destination / "shard.json")
        seal["report_sha256"] = p.digest(destination / "shard-report.json")
        seal["files"] = p.inventory(destination / "data")[0]
        q.save_report(destination / "shard.json", seal)

    def test_actual_completed_process_survives_transport_and_admission(self):
        source, prepared, report, destination = self.actual_fixture()
        receipt, admitted = self.admit_fixture(source, prepared, destination)
        self.assertEqual(report, admitted)
        self.assertEqual(admitted["checks"][-1]["exit_code"], 0)
        self.assertGreater(admitted["checks"][-1]["stderr_bytes"], 0)
        self.assertEqual(set(receipt["files"]), {"check.py.stdout", "check.py.stderr"})
        # Extra bytes are refused even when the required process files remain.
        (destination / "data/undeclared").write_bytes(b"not admitted")
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.admit_fixture(source, prepared, destination)

    def test_actual_empty_evidence_directories_survive_artifact_transport(self):
        source, prepared, _, destination = self.actual_fixture()
        receipt = p.read_json(destination / "shard.json")
        self.assertEqual(receipt["schema"], "hepta.runtime.native-shard.v2")
        self.assertEqual(set(receipt["directories"]),
                         {"empty-evidence", "empty-evidence/before", "empty-evidence/after"})
        before = destination / "data/empty-evidence/before"
        after = destination / "data/empty-evidence/after"
        before.rmdir(); after.rmdir()
        self.admit_fixture(source, prepared, destination)
        self.assertTrue(before.is_dir() and after.is_dir())
        before.rmdir(); before.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.admit_fixture(source, prepared, destination)
        before.unlink(); before.mkdir()
        (destination / "data/undeclared-empty").mkdir()
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.admit_fixture(source, prepared, destination)

    def test_rehashed_report_cannot_hide_failed_partial_or_relabelled_process(self):
        source, prepared, report, destination = self.actual_fixture()
        mutations = {
            "failed": lambda r: r["checks"][-1].update(exit_code=9),
            "timed_out": lambda r: r["checks"][-1].update(timed_out=True),
            "started": lambda r: r["checks"][-1].update(start_error={"message": "missing"}),
            "larger_limit": lambda r: r["checks"][-1].update(timeout_seconds=181),
            "boolean_code": lambda r: r["checks"][-1].update(exit_code=False),
            "nan_elapsed": lambda r: r["checks"][-1].update(elapsed_seconds=float("nan")),
            "command": lambda r: r["checks"][-1]["command"].append("--skip"),
            "omitted": lambda r: r["checks"].pop(),
            "duplicate": lambda r: r["checks"].append(copy.deepcopy(r["checks"][-1])),
            "source": lambda r: r["source_sha256"].update(fixture="different"),
            "summary": lambda r: r["checks"][-1].update(summary={"invented": True}),
            "promoted": lambda r: r.update(whole_runtime_replaced=True),
            "boolean_retyped": lambda r: r.update(whole_runtime_replaced=0),
            "cold": lambda r: r["checks"][0].update(name="different-cold"),
            "group": lambda r: r["qualification_shard"].update(group="batch"),
            "invocation": lambda r: r["qualification_shard"].update(invocation="other-run"),
            "unreported_failure": lambda r: r.update(native_parallel_drain_errors=[{"failed": True}]),
        }
        for name, change in mutations.items():
            altered = copy.deepcopy(report); change(altered)
            self.reseal_fixture(destination, altered)
            with self.subTest(mutation=name), self.assertRaises(ValueError):
                self.admit_fixture(source, prepared, destination)
        self.reseal_fixture(destination, report)
        self.admit_fixture(source, prepared, destination)

    def test_physical_output_corruption_is_refused_even_after_manifest_rehash(self):
        source, prepared, report, destination = self.actual_fixture()
        for name in ("check.py.stdout", "check.py.stderr"):
            path = destination / "data" / name; original = path.read_bytes()
            path.write_bytes(original + b"changed")
            self.reseal_fixture(destination, report)
            with self.subTest(path=name), self.assertRaisesRegex(ValueError, "output bytes differ"):
                self.admit_fixture(source, prepared, destination)
            path.write_bytes(original)
        self.reseal_fixture(destination, report)
        self.admit_fixture(source, prepared, destination)

    def test_stale_build_hash_and_cross_invocation_fail_before_execution(self):
        output = self.root / "prepared"; output.mkdir()
        q.save_report(output / p.BUILD_SEAL, {"schema": "hepta.runtime.native-build.v1",
            "context": {"invocation": "another-workflow"}, "files": {}, "directories": [], "partitions": {}})
        with self.assertRaisesRegex(ValueError, "workflow build SHA256"):
            p.admit_prepared(output, self.root, "f" * 64, "expected")
        with self.assertRaisesRegex(ValueError, "source, invocation"):
            p.admit_prepared(output, self.root, p.digest(output / p.BUILD_SEAL), "expected")

    def test_missing_or_duplicate_shards_cannot_reach_evidence_owners(self):
        source, prepared, report, destination = self.actual_fixture()
        shards = self.root / "shards"; shards.mkdir()
        for group in p.PARTITIONS:
            shutil.copytree(destination, shards / group)
        output = self.root / "collect"; output.mkdir()
        with patch.object(p, "admit_prepared", return_value=({"files": {}}, prepared, object())), \
                patch.object(p, "admit_shard", return_value=(p.read_json(destination / "shard.json"), report)), \
                patch.object(q, "collect_native_evidence") as evidence:
            with self.assertRaisesRegex(ValueError, "duplicate or unknown"):
                p.collect(output, self.root, "a" * 64, "reporting-fixture", shards)
            evidence.assert_not_called()
            self.assertEqual(p.read_json(output / "result.json")["status"], "FAIL")
            for missing in ("config", "batch_planning", "batch_effects"):
                with self.subTest(missing=missing):
                    shutil.rmtree(shards / missing)
                    with self.assertRaisesRegex(ValueError, "exactly " + str(len(p.PARTITIONS))):
                        p.collect(output, self.root, "a" * 64, "reporting-fixture", shards)
                    evidence.assert_not_called()
                    shutil.copytree(destination, shards / missing)

    def test_all_actual_partitions_merge_once_and_retained_bytes_stay_binding(self):
        from contextlib import ExitStack
        from datetime import datetime, timezone
        source = self.root / "source"
        tests = source / "tests/hia_native"; tests.mkdir(parents=True)
        output = self.root / "aggregate"; output.mkdir()
        artifacts = self.root / "shards"; artifacts.mkdir()
        registry = {group: (group + "_fixture.py",) for group in p.PARTITIONS}
        names = tuple(name for group in registry.values() for name in group)
        prepared = {"status": "NATIVE_BUILD_READY", "phase": "native_build_complete",
            "native_components_status": "PENDING", "compiler_checkout": str(self.root / "compiler"),
            "started_at": datetime.now(timezone.utc).isoformat(), "whole_runtime_replaced": False,
            "source_sha256": {"synthetic_reporting_fixture": "unchanged"},
            "checks": [{"name": "compiler-full-cold", "command":
                       ["synthetic-cold-identity-only", "--output", str(output / "compiler-cold.json")]}]}
        for group, (name,) in registry.items():
            (tests / name).write_text("import json\nprint(json.dumps({'actual_reporting_group':" + repr(group) + "}))\n")
            run = self.root / group; run.mkdir()
            report = copy.deepcopy(prepared)
            report.update(status="RUNNING", phase="native_components", native_components_status="RUNNING",
                qualification_shard={"group": group, "invocation": "all-actual-processes",
                                     "prepared_sha256": "b" * 64, "tests": [name]})
            with patch.object(q, "ROOT", source):
                q.run_native_checks(run, report, (name,), q.qualification_env(), parallel_tests=(),
                                    ordered_groups=(), timeout=180)
            report.update(status="NATIVE_SHARD_PASS", phase="native_shard_complete", native_components_status="PARTIAL",
                          shard_elapsed_seconds=report["checks"][-1]["elapsed_seconds"], shard_finished_at="fixture")
            p.export_shard(run, artifacts / group, {"files": {}}, report)
        def finish(_, report, builder):
            report.update(status="NATIVE_COMPONENTS_PASS", native_components_status="PASS")
        with ExitStack() as stack:
            stack.enter_context(patch.object(q, "ROOT", source))
            stack.enter_context(patch.object(p, "partition_tests", return_value=registry))
            stack.enter_context(patch.object(q, "native_tests", return_value=names))
            stack.enter_context(patch.object(q, "native_commands", return_value={}))
            stack.enter_context(patch.object(p, "admit_prepared", return_value=({"files": {}}, prepared, object())))
            evidence = stack.enter_context(patch.object(q, "collect_native_evidence"))
            stack.enter_context(patch.object(q, "finish_native", side_effect=finish))
            result = p.collect(output, self.root / "compiler", "b" * 64, "all-actual-processes", artifacts)
            self.assertEqual(result["checks"], 1 + len(p.PARTITIONS))
            evidence.assert_called_once()
            report = p.read_json(output / "result.json")
            self.assertEqual([row["name"] for row in report["checks"][1:]], list(names))
            p.verify_pipeline_receipts(output, report)
            # A native row cannot be counted a second time as a later phase.
            duplicated = copy.deepcopy(report); duplicated["checks"].append(report["checks"][1])
            with self.assertRaisesRegex(ValueError, "aggregate process records"):
                p.verify_pipeline_receipts(output, duplicated)
            # Complete raw shard reports remain binding after collection.
            saved = output / "qualification-shards/text/shard-report.json"
            original = saved.read_bytes(); saved.write_bytes(original + b" ")
            with self.assertRaisesRegex(ValueError, "retained shard receipt changed"):
                p.verify_pipeline_receipts(output, report)
            saved.write_bytes(original)
            path = output / (names[0] + ".stderr"); path.write_bytes(b"later corruption")
            with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
                p.verify_pipeline_receipts(output, report)


    def test_view_fixture_retirement_retains_lossless_content_before_removal(self):
        output = self.root / "output"
        caller = output / "view-call/caller/files-0"
        public = output / "runtime-mcp/files"
        regex = output / "view-regex-search/files-30072"
        caller.mkdir(parents=True)
        public.mkdir(parents=True)
        regex.mkdir(parents=True)
        outside = self.root / "outside.bin"
        outside.write_bytes(b"untouched outside fixture")
        content = b"complete native fixture\0\xff"
        raw = caller / os.fsdecode(b"invalid-\xff")
        raw.write_bytes(content)
        (caller / "empty.bin").write_bytes(b"")
        (caller / "outside-link").symlink_to(outside)
        (caller / "empty-directory").mkdir()
        os.link(raw, public / "same-inode.bin")
        (regex / "regex-result.bin").write_bytes(content)
        names = ("runtime-mcp/files", "view-call/caller/files-0", "view-regex-search/files-30072")
        evidence = {"kind": "synthetic pipeline reporting control", "native_calls": 0}
        proof = fixtures.retire_fixtures(output, names, evidence, create=True)
        self.assertEqual(proof["regular_files"], 4)
        self.assertEqual(proof["symlinks"], 1)
        self.assertEqual(proof["content_bytes"], len(content) * 3)
        self.assertEqual(proof["semantic_invocations_added"], 0)
        self.assertFalse(caller.exists())
        self.assertFalse(public.exists())
        self.assertFalse(regex.exists())
        self.assertEqual(outside.read_bytes(), b"untouched outside fixture")
        self.assertEqual(fixtures.retire_fixtures(output, names, evidence), proof)
        self.assertEqual(set(p.inventory(output)[0]), {fixtures.RECEIPT, fixtures.ARCHIVE})
        with self.assertRaisesRegex(ValueError, "complete admitted execution"):
            fixtures.retire_fixtures(output, names, {"different": "evidence"})
        receipt = output / fixtures.RECEIPT
        original = receipt.read_bytes()
        altered = json.loads(original)
        row = next(item for item in altered["entries"] if item["kind"] == "file" and item["bytes"])
        row["sha256"] = "f" * 64
        receipt.write_bytes(fixtures.encoded(altered))
        with self.assertRaisesRegex(ValueError, "complete retained fixture file content"):
            fixtures.retire_fixtures(output, names, evidence)
        receipt.write_bytes(original)
        caller.mkdir()
        with self.assertRaisesRegex(ValueError, "reappeared"):
            fixtures.retire_fixtures(output, names, evidence)

    def test_view_fixture_retirement_refuses_alias_roots_and_wider_paths(self):
        output = self.root / "output"
        target = self.root / "outside"
        target.mkdir()
        (target / "keep").write_bytes(b"keep")
        alias = output / "view-call/caller/files-0"
        alias.parent.mkdir(parents=True)
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            fixtures.retire_fixtures(output, ("view-call/caller/files-0",), {}, create=True)
        self.assertEqual((target / "keep").read_bytes(), b"keep")
        self.assertTrue(alias.is_symlink())
        self.assertFalse((output / fixtures.ARCHIVE).exists())
        for name in ("../outside", "view-call", "view-call/caller", "runtime-mcp/sessions",
                     "view-regex-search", "view-regex-search/files-30064",
                     "view-regex-search/files-30071", "view-regex-search/files-30271",
                     "view-regex-search/files-39999", "view-regex-search/files-40001"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "owned test domain"):
                fixtures.retire_fixtures(output, (name,), {}, create=True)



class ShellProcessPipelineTests(unittest.TestCase):
    """Small actual reporting processes; none of these replace native OS cases."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-shell-pipeline-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def registry_report(self):
        captures = {}
        for item in q.capture_gate.MODULES:
            relative = "build/" + item["name"] + "/manifest.json"
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"qualification_unit_fixture": true}\n')
            captures[item["key"]] = {"manifest": relative, "sha256": q.sha(path)}
        prepare = self.root / captures["shell_capture_prepare"]["manifest"]
        top = {"children": {}, "child_origins": {child: "provided" for child in q.capture_gate.LEAF_KINDS}}
        for child in q.capture_gate.LEAF_KINDS:
            path = self.root / captures["shell_capture_" + child]["manifest"]
            top[child + "_manifest"] = str(path)
            top[child + "_manifest_sha256"] = q.sha(path)
            top["children"][child] = {"manifest": str(path),
                "manifest_pin": {"bytes": path.stat().st_size, "sha256": q.sha(path)}}
        prepare.write_text(json.dumps(top) + "\n")
        captures["shell_capture_prepare"]["sha256"] = q.sha(prepare)
        return {"phase": "native_components", "checks": [], "modules": {
            "shell_process": {"manifest": "build/shell-process/manifest.json"},
            "shell_background_text": {"manifest": "build/modules/shell-background-text/manifest.json"},
            "shell_outcome": {"manifest": "build/shell-outcome/manifest.json"},
            "shell_output_io": {"manifest": "build/shell-output/manifest.json"},
            "shell_foreground": {"manifest": "build/shell-foreground/manifest.json"},
            **captures}}

    def test_shell_registry_keeps_process_text_and_original_domains_distinct(self):
        import compare_hia_runtime_rust as original
        from check_hia_native_inventory import inspect
        self.assertEqual(len(q.MODULES), 87)
        self.assertEqual(len(q.native_tests()), 225)
        self.assertEqual(len(original.RECIPES), 81)
        self.assertEqual(q.SHELL_PROCESS_TESTS, (
            "shell_process_state.py", "shell_process_transport.py",
            "hia_native_shell_process_qualification.py", "shell_process_evidence_controls.py"))
        shell = p.partition_tests()["shell"]
        required = (*q.SHELL_PROCESS_TESTS, q.SHELL_BACKGROUND_TEST,
                    q.SHELL_OUTCOME_TEST, q.SHELL_OUTPUT_TEST, *q.SHELL_FOREGROUND_TESTS,
                    *q.capture_gate.TESTS)
        self.assertEqual(tuple(name for name in shell if name in required), required)
        self.assertEqual(len(shell), 19)
        self.assertTrue(set(shell).isdisjoint(p.partition_tests()["text"]))
        self.assertIn("test_shell_native.py", shell)
        self.assertNotIn("shell_process", original.NEW_COMPONENTS)
        self.assertNotIn("shell_background_text", original.NEW_COMPONENTS)
        self.assertIs(original.RECIPES["shell_process"], original.compare_shell_process)
        self.assertIs(original.RECIPES["shell_background_text"], original.compare_shell_background)
        self.assertNotIn("shell_outcome", original.NEW_COMPONENTS)
        self.assertNotIn("shell_output_io", original.NEW_COMPONENTS)
        self.assertIs(original.RECIPES["shell_outcome"], original.compare_shell_outcome)
        self.assertIs(original.RECIPES["shell_output_io"], original.compare_shell_output)
        self.assertNotIn("shell_foreground", original.NEW_COMPONENTS)
        self.assertIs(original.RECIPES["shell_foreground"], original.compare_shell_foreground)
        inventory = inspect(ROOT)
        self.assertEqual(len(inventory["native_sources"]), 195)
        self.assertEqual(inventory["legacy_tool_count"], 125)
        self.assertEqual(inventory["native_production_tool_count"], 0)
        self.assertIs(inventory["whole_runtime_replaced"], False)
        self.assertIs(inventory["production_activated"], False)

    def test_shell_source_closure_includes_every_new_owner_producer_and_reader(self):
        source = q.sources()
        for relative in (
                "native/shell_process.hepta", "native/shell_process_packer.hepta",
                "native/shell_background_text.hepta",
                "native/shell_outcome.hepta", "native/shell_outcome_reuse.json",
                "native/shell_output_io.hepta", "native/shell_output_packer.hepta",
                "native/shell_output_layout.json",
                "native/shell_foreground_controller.hepta", "native/shell_foreground_packer.hepta",
                "native/shell_foreground_layout.json",
                "scripts/hia_native_shell_process_build.py",
                "scripts/hia_native_shell_process_qualification.py",
                "scripts/hia_native_shell_process_reference.py",
                "scripts/hia_native_shell_process_evidence.py",
                "scripts/hia_native_shell_outcome_build.py", "scripts/hia_native_shell_outcome_qualification.py",
                "scripts/hia_native_shell_output_build.py", "scripts/hia_native_shell_output_qualification.py",
                "scripts/shell_output_adapter.S", "scripts/hia_native_failure_evidence.py",
                "scripts/hia_native_shell_foreground_build.py", "scripts/hia_native_shell_foreground_qualification.py",
                "scripts/shell_foreground_adapter.S",
                "scripts/shell_process_adapter.S", "scripts/qualify_hia_shell_process.py",
                ".github/workflows/hia-runtime-shell-process.yml",
                "tests/hia_native/shell_process_state.py",
                "tests/hia_native/shell_process_transport.py",
                "tests/hia_native/shell_process_cases.py",
                "tests/hia_native/shell_process_evidence_controls.py",
                "tests/hia_native/shell_background_text.py",
                "tests/hia_native/shell_outcome_state.py", "tests/hia_native/shell_outcome_cases.py",
                "tests/hia_native/shell_output_io.py", "tests/hia_native/shell_output_original_io.py",
                "tests/hia_native/shell_foreground_controller.py", "tests/hia_native/shell_foreground_io.py",
                "src/mcp/fs/background.rs", "src/mcp/fs/background_tests.rs"):
            with self.subTest(relative=relative):
                self.assertEqual(source.get(relative), q.sha(ROOT / relative))

    def test_shell_output_launchers_reject_partial_or_foreign_builds_before_execution(self):
        report = self.registry_report()
        commands = {**q.shell_outcome_test_commands(self.root, report),
                    **q.shell_output_test_commands(self.root, report),
                    **q.shell_foreground_test_commands(self.root, report),
                    **q.capture_gate.test_commands(self.root, report)}
        for name, command in commands.items():
            variants = [command + ["--case", "normal"], command + ["--verify", "/foreign"]]
            for option in ("--native-manifest", "--outcome-manifest", "--output"):
                if option in command:
                    foreign = list(command)
                    foreign[foreign.index(option) + 1] = str(self.root / "foreign")
                    variants.append(foreign)
                    index = command.index(option)
                    variants.append(command[:index] + command[index + 2:])
            for mutated in variants:
                with self.subTest(name=name, argv=mutated), patch.object(q, "record_check") as run:
                    with self.assertRaisesRegex(ValueError, "source-owned suite"):
                        q.run_native_checks(self.root, report, (name,), q.qualification_env(),
                            parallel_tests=(), ordered_groups=(), commands={name: mutated})
                    run.assert_not_called()
        self.assertEqual(report["checks"], [])

    def test_capture_source_and_original_recipes_are_mandatory(self):
        import compare_hia_runtime_rust as original
        source = q.sources()
        for item in q.capture_gate.MODULES:
            key = item["key"]
            self.assertIn(key, original.RECIPES)
            self.assertNotIn(key, original.NEW_COMPONENTS)
            self.assertIn(key, p.PARTITIONS["shell"])
            for relative in (item["source"], *item.get("companion_sources", ())):
                self.assertEqual(source.get(relative), q.sha(ROOT / relative))
        for name in q.capture_gate.SCRIPTS:
            relative = "scripts/" + name
            self.assertEqual(source.get(relative), q.sha(ROOT / relative))
        for relative in q.capture_gate.ORACLE_SOURCES:
            self.assertEqual(source.get(relative), q.sha(ROOT / relative))
        for name in (*q.capture_gate.TESTS, "shell_capture_path_cases.py"):
            relative = "tests/hia_native/" + name
            self.assertEqual(source.get(relative), q.sha(ROOT / relative))

    def test_capture_manifest_is_bound_to_this_run_and_its_actual_bytes(self):
        gate = q.capture_gate
        report = self.registry_report()
        for key in gate.KEYS:
            expected = self.root / report["modules"][key]["manifest"]
            self.assertEqual(gate.manifest_for(self.root, report, key), expected)
            absolute = json.loads(json.dumps(report))
            absolute["modules"][key]["manifest"] = str(expected)
            self.assertEqual(gate.manifest_for(self.root, absolute, key), expected)
            for field, value, reason in (("sha256", "0" * 64, "identity differs"),
                    ("manifest", str(self.root / "foreign/manifest.json"), "registered build")):
                altered = json.loads(json.dumps(report)); altered["modules"][key][field] = value
                with self.subTest(key=key, field=field), patch.object(gate, "suite") as load:
                    with self.assertRaisesRegex(ValueError, reason):
                        gate.native_evidence(self.root, altered, key)
                    load.assert_not_called()
                    with self.assertRaisesRegex(ValueError, reason):
                        gate.test_commands(self.root, altered)
                    with self.assertRaisesRegex(ValueError, reason):
                        gate.original_commands(self.root, altered, key, Path("/selected/rustc"))
    def test_capture_progress_requires_every_case_and_exact_protocol(self):
        gate = q.capture_gate
        for kind in ("mkdir", "file", "prepare"):
            specs = gate.original_case_specs(kind)
            rows = [{"case": spec["name"], "status": "ORIGINAL_PAIR_PASS", "syscalls": 0}
                    for spec in specs] + [{"status": "PASS"}]
            name = "shell-capture-" + kind + "-rust-compare"
            encoded = lambda values: b"\n".join(json.dumps(row).encode() for row in values) + b"\n"
            self.assertEqual(q.process_summary(name, encoded(rows)), {"status": "PASS"})
            wrong_type = json.loads(json.dumps(rows)); wrong_type[0]["syscalls"] = False
            wrong_order = json.loads(json.dumps(rows)); wrong_order[:2] = reversed(wrong_order[:2])
            extra_field = json.loads(json.dumps(rows)); extra_field[0]["hidden_error"] = "failed"
            for variant in (rows[1:], rows[:-1], rows + [rows[-1]], [rows[0], *rows],
                            wrong_type, wrong_order, extra_field):
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    q.process_summary(name, encoded(variant))

    def test_prepare_rejects_rehashed_foreign_leaf_bindings(self):
        gate = q.capture_gate
        report = self.registry_report()
        key = "shell_capture_prepare"
        path = self.root / report["modules"][key]["manifest"]
        original = json.loads(path.read_bytes())
        for child in gate.LEAF_KINDS:
            foreign = self.root / "another-gate/build" / ("shell-capture-" + child) / "manifest.json"
            foreign.parent.mkdir(parents=True)
            foreign.write_bytes((self.root / report["modules"]["shell_capture_" + child]["manifest"]).read_bytes())
            for mutation in ("coherent_foreign_child", "child_pin", "unregistered_child", "fresh_child"):
                altered = json.loads(json.dumps(original))
                if mutation == "coherent_foreign_child":
                    altered[child + "_manifest"] = str(foreign)
                    altered["children"][child]["manifest"] = str(foreign)
                elif mutation == "child_pin":
                    altered["children"][child]["manifest_pin"]["bytes"] += 1
                elif mutation == "unregistered_child":
                    del altered["children"][child]
                else:
                    altered["child_origins"][child] = "fresh"
                path.write_text(json.dumps(altered) + "\n")
                report["modules"][key]["sha256"] = q.sha(path)
                with self.subTest(child=child, mutation=mutation), patch.object(gate, "suite") as load:
                    with self.assertRaises(ValueError):
                        gate.test_commands(self.root, report)
                    with self.assertRaises(ValueError):
                        gate.original_commands(self.root, report, key, Path("/selected/rustc"))
                    load.assert_not_called()
        path.write_text(json.dumps(original) + "\n")
        report["modules"][key]["sha256"] = q.sha(path)
        self.assertEqual(gate.manifest_for(self.root, report, key), path)

    def test_prepare_native_progress_retains_every_count_record(self):
        gate = q.capture_gate
        specs = gate.suite("shell_capture_prepare_io.py").case_specs()
        self.assertEqual(len(specs), 15)
        self.assertEqual(len(gate.original_case_specs("prepare")), 14)
        rows = [{"name": spec["name"], "status": "PASS", "counts": {"entries": 1}}
                for spec in specs] + [{"status": "PASS"}]
        encode = lambda values: b"\n".join(json.dumps(row).encode() for row in values) + b"\n"
        name = "shell_capture_prepare_io.py"
        self.assertEqual(gate.progress_records(name, encode(rows)), rows)
        changed = json.loads(json.dumps(rows)); changed[0]["result"] = changed[0].pop("counts")
        reordered = json.loads(json.dumps(rows)); reordered[:2] = reversed(reordered[:2])
        for variant in (rows[1:], rows[:-1], rows + [rows[-1]], changed, reordered):
            with self.subTest(variant=variant[:1]), self.assertRaises(ValueError):
                gate.progress_records(name, encode(variant))

    def test_capture_final_output_is_bound_to_independently_read_results(self):
        gate = q.capture_gate
        name = "shell_capture_path.py"
        expected = [{"status": "PASS", "counts": {"semantic_cases": 49075},
                     "whole_runtime_replaced": False}]
        target = self.root / (name + ".stdout")
        target.write_text(json.dumps(expected[0]) + "\n")
        gate.bind_process_output(self.root, name, expected)
        for altered in ({**expected[0], "whole_runtime_replaced": 0},
                        {**expected[0], "counts": {"semantic_cases": 1}}):
            target.write_text(json.dumps(altered) + "\n")
            with self.assertRaisesRegex(ValueError, "independent evidence"):
                gate.bind_process_output(self.root, name, expected)
        for raw in (b'{"status":"FAIL","status":"PASS"}\n',
                    b'{"status":"PASS","count":NaN}\n', b'{"status":"PASS"}\n{}\n'):
            with self.assertRaises(ValueError):
                q.process_summary(name, raw)

    def test_shell_output_original_recipe_requires_same_gate_process_and_outcome(self):
        import compare_hia_runtime_rust as original
        report = self.registry_report()
        order = original.rust_recipe_order(report)
        self.assertLess(order.index("shell_process"), order.index("shell_outcome"))
        self.assertLess(order.index("shell_outcome"), order.index("shell_output_io"))
        self.assertLess(order.index("shell_output_io"), order.index("shell_foreground"))
        for missing in ("shell_process", "shell_outcome", "shell_output_io"):
            incomplete = json.loads(json.dumps(report))
            del incomplete["modules"][missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "producer must precede"):
                original.rust_recipe_order(incomplete)

    def progress_rows(self, original=False):
        module = q._shell_test_module("shell_process_cases.py")
        rows = [{"name": row["name"], "status": "PASS", "duration_ns": 1, "error": None}
                for row in module.specs()]
        rows.reverse()  # Completion order need not equal declaration order.
        rows.append({"status": "ORIGINAL_COMPARISON_PASS" if original else "NATIVE_ONLY_PASS",
                     "case_count": 38, "report": str(self.root / "actual-case-report.json")})
        return rows

    def actual_progress(self, folder, rows, *, original=False, raw=None):
        folder.mkdir()
        program = folder / "progress.py"
        data = raw if raw is not None else b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in rows)
        program.write_text("import sys\nsys.stdout.buffer.write(" + repr(data) + ")\n")
        name = "shell-process-rust-compare" if original else q.SHELL_PROCESS_TESTS[2]
        report = {"phase": "reporting-regression", "checks": []}
        q.record_check(folder, report, name=name,
                       command=[sys.executable, "-I", "-B", str(program),
                                "--output", str(folder / "case-output")], timeout=2)
        return name, report

    def test_actual_shell_progress_requires_all_38_successful_case_records(self):
        for original in (False, True):
            folder = self.root / ("original" if original else "native")
            rows = self.progress_rows(original)
            rows[-1]["report"] = str(folder / "case-output/report.json")
            name, report = self.actual_progress(folder, rows, original=original)
            row, summary = q.completed_test_summary(folder, report, name)
            q.shell_completed_process(folder, report, name, row["command"],
                phase="reporting-regression", timeout=2,
                status="ORIGINAL_COMPARISON_PASS" if original else "NATIVE_ONLY_PASS")
            wrong_command = list(row["command"])
            wrong_command[-1] = str(folder / "foreign-case-output")
            changed = copy.deepcopy(report)
            changed["checks"][0]["command"] = wrong_command
            with self.assertRaisesRegex(ValueError, "different output directory"):
                q.shell_completed_process(folder, changed, name, wrong_command,
                    phase="reporting-regression", timeout=2,
                    status="ORIGINAL_COMPARISON_PASS" if original else "NATIVE_ONLY_PASS")
            self.assertEqual(row["exit_code"], 0)
            self.assertEqual(summary["case_count"], 38)
            self.assertEqual(summary["status"], "ORIGINAL_COMPARISON_PASS" if original else "NATIVE_ONLY_PASS")

    def test_trailing_pass_cannot_cover_actual_missing_duplicate_or_failed_progress(self):
        changes = {
            "missing": lambda rows: rows.pop(0),
            "duplicate": lambda rows: rows.__setitem__(0, dict(rows[1])),
            "failed": lambda rows: rows[0].update(status="FAIL", error="actual failure"),
            "unknown": lambda rows: rows[0].update(name="unregistered"),
            "boolean_duration": lambda rows: rows[0].update(duration_ns=True),
            "negative_duration": lambda rows: rows[0].update(duration_ns=-1),
            "extra_field": lambda rows: rows[0].update(ignored=False),
            "wrong_scope": lambda rows: rows[-1].update(status="ORIGINAL_COMPARISON_PASS"),
            "relative_report": lambda rows: rows[-1].update(report="report.json"),
            "boolean_count": lambda rows: rows[-1].update(case_count=True),
            "extra_pass": lambda rows: rows.append(dict(rows[-1])),
        }
        for label, change in changes.items():
            rows = self.progress_rows()
            change(rows)
            folder = self.root / label
            name, report = self.actual_progress(folder, rows)
            with self.subTest(label=label), self.assertRaises(ValueError):
                q.completed_test_summary(folder, report, name)
            self.assertNotIn("summary", report["checks"][0])
            self.assertEqual(report["checks"][0]["exit_code"], 0)
            self.assertTrue((folder / (name + ".stdout")).is_file())

        rows = self.progress_rows()
        raw = b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in rows)
        raw = raw.replace(b'"status": "PASS"', b'"status": "FAIL", "status": "PASS"', 1)
        folder = self.root / "duplicate-json-field"
        name, report = self.actual_progress(folder, rows, raw=raw)
        with self.assertRaisesRegex(ValueError, "duplicate real-OS shell progress field"):
            q.completed_test_summary(folder, report, name)

    def io_progress_rows(self, output_io):
        module = q._shell_test_module(q.SHELL_OUTPUT_TEST if output_io else q.SHELL_FOREGROUND_TESTS[1])
        specifications = module.specs() if output_io else module.specifications()
        rows = [{"case": case["name"], "status": "NATIVE_IO_PASS" if output_io else "ACTUAL_NATIVE_PASS"}
                for case in specifications]
        if output_io:
            for row in rows:
                row.update(effects=1, outcome=True)
        summary = {"schema": "hepta.runtime.shell-output-io-read.v1" if output_io else
                   "hepta.runtime.shell-foreground-io-read.v1", "status": "PASS",
                   "cases": len(rows), "retired_fixtures": len(rows), "complete_registered_corpus": True,
                   "actual_native_process_wait": not output_io, "native_phase_cases_added_by_reference": 0}
        if output_io:
            summary.update(effects=len(rows), io_only=False)
        return rows + [summary]

    def actual_io_progress(self, folder, name, rows, raw=None):
        folder.mkdir()
        wire = raw if raw is not None else b"".join((json.dumps(row) + "\n").encode() for row in rows)
        program = folder / "progress.py"
        program.write_text("import sys\nsys.stdout.buffer.write(" + repr(wire) + ")\n")
        report = {"phase": "reporting-regression", "checks": []}
        q.record_check(folder, report, name=name, command=[sys.executable, "-I", "-B", str(program)], timeout=2)
        return report

    def test_actual_io_progress_binds_every_case_and_complete_final_reader_result(self):
        for output_io, names in ((True, (q.SHELL_OUTPUT_TEST, "shell-output-native")),
                                 (False, (q.SHELL_FOREGROUND_TESTS[1], "shell-foreground-native"))):
            for name in names:
                rows = self.io_progress_rows(output_io)
                folder = self.root / name
                report = self.actual_io_progress(folder, name, rows)
                _, summary = q.completed_test_summary(folder, report, name)
                self.assertEqual(summary, rows[-1])
                q.bind_shell_io_progress(folder, name, rows[-1], rows[:-1])
                wrong = copy.deepcopy(rows[-1]); wrong["unrecorded_claim"] = True
                with self.assertRaisesRegex(ValueError, "final stdout differs"):
                    q.bind_shell_io_progress(folder, name, wrong, rows[:-1])
                wrong = copy.deepcopy(rows[:-1]); wrong[0]["unrecorded_claim"] = True
                with self.assertRaisesRegex(ValueError, "case stdout differs"):
                    q.bind_shell_io_progress(folder, name, rows[-1], wrong)

    def test_actual_io_trailing_pass_cannot_cover_malformed_or_incomplete_progress(self):
        mutations = {
            "missing": lambda rows: rows.pop(0),
            "duplicate": lambda rows: rows.__setitem__(0, dict(rows[1])),
            "reordered": lambda rows: rows.__setitem__(slice(0, 2), list(reversed(rows[:2]))),
            "failed": lambda rows: rows[0].update(status="FAIL"),
            "unknown": lambda rows: rows[0].update(case="not-registered"),
            "extra_field": lambda rows: rows[0].update(ignored=False),
            "boolean_count": lambda rows: rows[-1].update(cases=True),
            "boolean_retired": lambda rows: rows[-1].update(retired_fixtures=True),
            "partial": lambda rows: rows[-1].update(complete_registered_corpus=False),
            "wrong_wait": lambda rows: rows[-1].update(actual_native_process_wait="true"),
            "new_semantics": lambda rows: rows[-1].update(native_phase_cases_added_by_reference=1),
            "extra_summary": lambda rows: rows.append(dict(rows[-1])),
        }
        for output_io, name in ((True, q.SHELL_OUTPUT_TEST), (False, q.SHELL_FOREGROUND_TESTS[1])):
            changes = dict(mutations)
            if output_io:
                changes.update({"boolean_effects": lambda rows: rows[0].update(effects=True),
                                "zero_effects": lambda rows: rows[0].update(effects=0),
                                "integer_outcome": lambda rows: rows[0].update(outcome=1),
                                "wrong_total": lambda rows: rows[-1].update(effects=1),
                                "io_only": lambda rows: rows[-1].update(io_only=True)})
            for label, change in changes.items():
                rows = self.io_progress_rows(output_io); change(rows)
                folder = self.root / (name + "-" + label)
                report = self.actual_io_progress(folder, name, rows)
                with self.subTest(suite=name, mutation=label), self.assertRaises(ValueError):
                    q.completed_test_summary(folder, report, name)
                self.assertNotIn("summary", report["checks"][0])
                self.assertEqual(report["checks"][0]["exit_code"], 0)

    def test_actual_io_progress_refuses_duplicate_json_fields_and_nonfinite_values(self):
        for output_io, name in ((True, q.SHELL_OUTPUT_TEST), (False, q.SHELL_FOREGROUND_TESTS[1])):
            rows = self.io_progress_rows(output_io)
            raw = b"".join((json.dumps(row) + "\n").encode() for row in rows)
            bad = raw.replace(b'"status": ', b'"status": "FAIL", "status": ', 1)
            folder = self.root / (name + "-duplicate-json")
            report = self.actual_io_progress(folder, name, rows, raw=bad)
            with self.assertRaisesRegex(ValueError, "duplicate shell IO progress field"):
                q.completed_test_summary(folder, report, name)
            rows[-1]["extra"] = float("nan")
            folder = self.root / (name + "-nonfinite-json")
            report = self.actual_io_progress(folder, name, rows)
            with self.assertRaisesRegex(ValueError, "nonfinite shell IO progress value"):
                q.completed_test_summary(folder, report, name)

    def test_shell_launcher_refuses_partial_or_foreign_cli_before_start(self):
        report = self.registry_report()
        name = q.SHELL_PROCESS_TESTS[2]
        commands = q.shell_process_test_commands(self.root, report)
        command = commands[name]
        self.assertEqual(command[3], str(ROOT / "scripts/hia_native_shell_process_qualification.py"))
        self.assertEqual(command[command.index("--output") + 1], str(self.root / "shell-process/native-os"))
        mutations = [
            command + ["--case", "only-one"],
            command + ["--oracle-executable", "/different/reference"],
            command[:-2],
            [*command[:3], str(ROOT / "tests/hia_native/shell_process_cases.py"), *command[4:]],
        ]
        wrong_output = list(command)
        wrong_output[wrong_output.index("--output") + 1] = str(self.root / "foreign")
        mutations.append(wrong_output)
        for bad in mutations:
            with self.subTest(command=bad), patch.object(q, "record_check") as launch:
                with self.assertRaisesRegex(ValueError, "source-owned suite"):
                    q.run_native_checks(self.root, report, (name,), q.qualification_env(),
                        parallel_tests=(), ordered_groups=(), commands={name: bad})
                launch.assert_not_called()

    def test_actual_control_process_starts_only_after_fixture_retirement(self):
        source = self.root / "source"
        tests = source / "tests/hia_native"
        tests.mkdir(parents=True)
        name = q.SHELL_PROCESS_TESTS[3]
        (tests / name).write_text(
            "from pathlib import Path\nimport json,sys\n"
            "folder=Path(sys.argv[sys.argv.index('--output')+1])\n"
            "assert (folder.parent/'native-os'/'retired').read_bytes()==b'complete snapshot'\n"
            "print(json.dumps({'status':'PASS','actual_retirement_order_fixture':True}))\n")
        output = self.root / "output"
        output.mkdir()
        (output / "shell-process/native-os").mkdir(parents=True)
        def retirement(folder, report):
            (folder / "shell-process/native-os/retired").write_bytes(b"complete snapshot")
        report = self.registry_report()
        with patch.object(q, "ROOT", source), patch.object(q, "retire_shell_process_native", side_effect=retirement) as retire:
            commands = q.shell_process_test_commands(output, report)
            q.run_native_checks(output, report, (name,), q.qualification_env(),
                                parallel_tests=(), ordered_groups=(), commands={name: commands[name]})
            retire.assert_called_once_with(output, report)
        self.assertEqual(report["checks"][0]["exit_code"], 0)
        self.assertIs(report["checks"][0]["summary"]["actual_retirement_order_fixture"], True)

        refused = self.root / "refused"
        refused.mkdir()
        report = self.registry_report()
        with patch.object(q, "ROOT", source), patch.object(q, "retire_shell_process_native", side_effect=ValueError("unreaped child")):
            commands = q.shell_process_test_commands(refused, report)
            with self.assertRaisesRegex(ValueError, "unreaped child"):
                q.run_native_checks(refused, report, (name,), q.qualification_env(),
                                    parallel_tests=(), ordered_groups=(), commands={name: commands[name]})
        self.assertFalse((refused / (name + ".stdout")).exists())
        self.assertEqual(report["checks"], [])

    def test_shell_completed_record_rejects_retyped_or_recounted_actual_receipts(self):
        program = self.root / "pass.py"
        program.write_text("import json\nprint(json.dumps({'status':'PASS'}))\n")
        name = "shell-reporting-fixture"
        command = [sys.executable, "-I", "-B", str(program)]
        report = {"phase": "native_components", "checks": []}
        q.record_check(self.root, report, name=name, command=command, timeout=180)
        q.shell_completed_process(self.root, report, name, command, phase="native_components", timeout=180)
        changes = {
            "boolean_exit": {"exit_code": False},
            "short_stdout": {"stdout_bytes": 0},
            "boolean_stderr": {"stderr_bytes": False},
            "negative_elapsed": {"elapsed_seconds": -1},
            "nan_elapsed": {"elapsed_seconds": float("nan")},
            "empty_start_error": {"start_error": {}},
            "changed_phase": {"phase": "original_rust_comparison"},
            "larger_deadline": {"timeout_seconds": 181},
        }
        for name_mutation, values in changes.items():
            altered = copy.deepcopy(report)
            altered["checks"][0].update(values)
            with self.subTest(mutation=name_mutation), self.assertRaises(ValueError):
                q.shell_completed_process(self.root, altered, name, command,
                                          phase="native_components", timeout=180)

    def test_original_commands_require_one_fresh_build_and_separate_os_fixtures(self):
        import compare_hia_runtime_rust as original
        report = self.registry_report()
        rustc = self.root / "selected/rustc"
        cargo = self.root / "selected/cargo"
        with patch.object(original, "executable", return_value=cargo):
            commands = original.shell_process_original_commands(self.root, report, rustc)
        build = commands["shell-process-rust-build"]
        compare = commands["shell-process-rust-compare"]
        background = commands["shell-background-rust-compare"]
        build_output = self.root / "shell-process-original/build"
        self.assertEqual(build[build.index("--output") + 1], str(build_output))
        self.assertEqual(compare[compare.index("--oracle-build-manifest") + 1], str(build_output / "result.json"))
        self.assertEqual(compare[compare.index("--output") + 1], str(self.root / "shell-process-original/cases"))
        self.assertEqual(background[background.index("--reference-build") + 1], str(build_output))
        self.assertEqual(background[background.index("--background-corpus") + 1],
                         str(self.root / "shell-background-text/native"))
        self.assertNotIn("--offline", build)
        self.assertNotIn("--case", compare)


    def test_original_dependency_order_survives_actual_sorted_json_round_trip(self):
        import compare_hia_runtime_rust as original
        program = self.root / "original-reporting-fixture.py"
        program.write_text(
            "from pathlib import Path\nimport json,sys\n"
            "kind=sys.argv[1];root=Path(sys.argv[2])\n"
            "if kind=='producer': (root/'fresh-build').write_bytes(b'complete')\n"
            "elif kind=='consumer':\n"
            " assert (root/'fresh-build').read_bytes()==b'complete'\n"
            " (root/'compared').write_bytes(b'complete')\n"
            "print(json.dumps({'status':'PASS','actual_reporting_role':kind}))\n")
        report = {"phase": "original_rust_comparison", "checks": [],
                  "modules": {"shell_process": {}, "shell_background_text": {}, "system_entropy": {}},
                  "original_rust_comparisons": {}, "whole_runtime_replaced": False}
        q.save_report(self.root / "round-trip.json", report)
        report = json.loads((self.root / "round-trip.json").read_bytes())
        self.assertEqual(next(iter(report["modules"])), "shell_background_text")

        def recipe(kind, name):
            def run(output, report, rustc, *, report_path=None):
                q.record_check(output, report, name=name,
                    command=[sys.executable, "-I", "-B", str(program), kind, str(self.root)],
                    timeout=2, report_path=report_path)
                return {"status": "PASS", "actual_reporting_role": kind}
            return run
        recipes = {
            "shell_process": recipe("producer", "process-producer-fixture"),
            "shell_background_text": recipe("consumer", "background-consumer-fixture"),
            "system_entropy": recipe("worker", "independent-worker-fixture")}
        parallel = {"system_entropy": ("independent-worker.execution.json", ("independent-worker-fixture",))}
        with patch.object(original, "RECIPES", recipes), patch.object(original, "PARALLEL_RUST_RECIPES", parallel):
            original.run_rust_recipes(self.root, report, Path(sys.executable))
        names = [row["name"] for row in report["checks"]]
        self.assertLess(names.index("process-producer-fixture"), names.index("background-consumer-fixture"))
        self.assertEqual((self.root / "compared").read_bytes(), b"complete")
        self.assertEqual(set(report["original_rust_comparisons"]), set(recipes))
        private = json.loads((self.root / "independent-worker.execution.json").read_bytes())
        self.assertEqual(private["checks"][0]["name"], "independent-worker-fixture")
        self.assertEqual(private["checks"][0]["exit_code"], 0)
        with self.assertRaisesRegex(ValueError, "producer must precede"):
            original.rust_recipe_order({"modules": {"shell_background_text": {}}})
        with self.assertRaisesRegex(ValueError, "module inventory"):
            original.rust_recipe_order({"modules": {"unregistered": {}}})
        expected_order = original.rust_recipe_order(report)
        with patch.object(original, "MODULES", tuple(reversed(original.MODULES))):
            self.assertEqual(original.rust_recipe_order(report), expected_order)
        reversed_recipes = dict(reversed(tuple(original.RECIPES.items())))
        with patch.object(original, "RECIPES", reversed_recipes), self.assertRaisesRegex(ValueError, "producer must precede"):
            original.rust_recipe_order(report)



if __name__ == "__main__":
    unittest.main()
