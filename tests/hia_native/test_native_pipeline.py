"""Actual-process controls for native artifact partitioning and evidence admission.

Small temporary programs test the reporting machinery. They never qualify a
production HIA image or stand in for a compiler cold replay.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
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


class NativePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-pipeline-reporting-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_runtime_sparse_checkouts_include_declared_source_closure(self):
        import hia_native_text_publication_pipeline as text_publication
        required = set(q.sources()) | set(q.PACKERS) | set(text_publication.source_names(ROOT))
        for item in q.MODULES:
            required.add(item['source'])
            required.update(item.get('companion_sources', ()))
        self.assertIn('authoring/diagnostics.json', required)
        expression = r'(?ms)^      - name: Checkout exact runtime source\n(.*?)(?=^      - |\Z)'

        def check(workflow):
            checkouts = list(re.finditer(expression, workflow))
            self.assertEqual(len(checkouts), 3)
            for checkout in checkouts:
                body = checkout.group(1)
                self.assertIn('          path: runtime\n', body)
                self.assertNotIn('sparse-checkout-cone-mode: false', body)
                selection = re.search(r'(?m)^          sparse-checkout: \|\n((?:            [^\n]+\n)+)', body)
                self.assertIsNotNone(selection)
                roots = [Path(line.strip()) for line in selection.group(1).splitlines()]
                self.assertEqual(len(roots), len(set(roots)))
                self.assertTrue(all(not path.is_absolute() and '..' not in path.parts for path in roots))
                # Cone mode keeps root files, files in selected ancestors,
                # and the complete subtree of each selected directory.
                for name in sorted(required):
                    parent = Path(name).parent
                    included = parent == Path('.') or any(
                        parent == root or root in parent.parents or parent in root.parents
                        for root in roots)
                    self.assertTrue(included, 'sparse checkout excludes declared source: ' + name)
            push, pull = workflow.split('  pull_request:', 1)
            for trigger in (push, pull.split('\nconcurrency:', 1)[0]):
                self.assertIn("      - 'authoring/diagnostics.json'", trigger)
            return checkouts

        workflow = (ROOT / '.github/workflows/hia-runtime-native.yml').read_text()
        checkouts = check(workflow)
        for index, checkout in enumerate(checkouts):
            changed = checkout.group(0).replace('\n            authoring\n', '\n', 1)
            self.assertNotEqual(changed, checkout.group(0))
            candidate = workflow[:checkout.start()] + changed + workflow[checkout.end():]
            with self.subTest(checkout=index), self.assertRaisesRegex(AssertionError, 'authoring/diagnostics.json'):
                check(candidate)

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

    def test_partition_is_complete_unique_and_keeps_evidence_dependencies(self):
        partitions = p.partition_tests()
        flat = [name for tests in partitions.values() for name in tests]
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(set(flat), set(q.native_tests()))
        for ordered in (("test_view_regex_search.py", "test_view_regex_search_native_evidence.py"),
                        ("test_runtime_mcp.py", "test_runtime_mcp_evidence.py",
                         "test_view_regex_search_public.py", "test_view_regex_search_public_evidence.py")):
            positions = [partitions["view"].index(name) for name in ordered]
            self.assertEqual(positions, sorted(positions))
        self.assertEqual(tuple(partitions["batch"]),
            ("test_batch_edit_params.py", "test_batch_plan_input.py", "test_batch_plan.py", "test_batch_plan_evidence.py", "test_batch_apply.py",
             "test_batch_apply_contract.py", "test_batch_apply_artifacts.py", "test_batch_apply_evidence.py",
             "test_batch_diff.py",
             "test_batch_call_native.py", "test_batch_call_packing.py", "test_batch_call_async.py",
             "test_atomic_write_policy.py", "test_atomic_write_kernel.py", "test_atomic_write_boundary.py",
             "test_atomic_write_evidence.py", "test_view_cache.py", "test_view_cache_evidence.py",
             "test_history.py", "test_history_evidence.py"))
        self.assertEqual(partitions["system"][:3],
                         ("test_filesystem_parity_state.py", "test_filesystem_parity_build.py",
                          "test_filesystem_parity_kernel.py"))
        self.assertEqual(len(flat), 147)
        self.assertEqual({name: len(tests) for name, tests in partitions.items()},
                         {'batch': 20, 'text': 35, 'view': 22, 'json': 16, 'config': 17, 'system': 37})
        text_suites = ('test_text_publication_native.py', 'test_text_publication_corpus.py',
                       'test_text_publication_pipeline_evidence.py')
        positions = [partitions['text'].index(name) for name in text_suites]
        self.assertEqual(positions, list(range(positions[0], positions[0] + 3)))
        registry_suites = ('test_request_registry.py', 'test_request_registry_sdk.py', 'test_request_registry_evidence.py')
        positions = [partitions['text'].index(name) for name in registry_suites]
        self.assertEqual(positions, list(range(positions[0], positions[0] + 3)))
        self.assertNotIn('test_request_registry_original_evidence.py', flat)
        self.assertEqual(partitions['system'][-2:],('test_session_workdir.py','test_session_evidence.py'))
        self.assertLess(partitions['view'].index('test_runtime_mcp.py'),
                        partitions['view'].index('test_filesystem_public.py'))
        self.assertNotIn('test_filesystem_public_original_evidence.py', flat)
        workflow = (q.ROOT / '.github/workflows/hia-runtime-native.yml').read_text()
        self.assertIn("if: matrix.group == 'system' || matrix.group == 'config' || matrix.group == 'view'", workflow)
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

    def test_text_export_validates_complete_evidence_before_retiring_owned_fixtures(self):
        output = self.root / 'text-shard'
        output.mkdir()
        (output / 'whole.bin').write_bytes(b'complete retained Text stream\x00\xff')
        fixture = output / 'live'
        fixture.mkdir()
        (fixture / 'loop').symlink_to(fixture)
        report = {'checks': [{'name': 'test_text_publication_native.py'}], 'qualification_shard': {}}
        observed = []
        def admit(actual_output, actual_report):
            self.assertEqual((actual_output, actual_report), (output, report))
            observed.append('admit')
            return {'reporting_fixture_only': True}
        def retire(actual_output, actual_report, *, create):
            self.assertEqual((actual_output, actual_report, create), (output, report, True))
            self.assertEqual(observed, ['admit'])
            observed.append('retire')
            (fixture / 'loop').unlink(); fixture.rmdir()
            return {'reporting_fixture_only': True}
        with patch.object(q, 'text_publication_evidence', side_effect=admit), \
             patch.object(q, 'text_publication_retirement', side_effect=retire):
            p.export_shard(output, self.root / 'text-export', {'files': {}}, report)
        self.assertEqual(observed, ['admit', 'retire'])
        self.assertEqual((self.root / 'text-export/data/whole.bin').read_bytes(), (output / 'whole.bin').read_bytes())
        with patch.object(q, 'text_publication_evidence', side_effect=ValueError('complete Text evidence absent')), \
             patch.object(q, 'text_publication_retirement') as retirement, \
             self.assertRaisesRegex(ValueError, 'complete Text evidence absent'):
            p.export_shard(output, self.root / 'text-refused', {'files': {}}, report)
        retirement.assert_not_called()

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
            shutil.rmtree(shards / "config")
            with self.assertRaisesRegex(ValueError, "exactly " + str(len(p.PARTITIONS))):
                p.collect(output, self.root, "a" * 64, "reporting-fixture", shards)
            evidence.assert_not_called()

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



if __name__ == "__main__":
    unittest.main()
