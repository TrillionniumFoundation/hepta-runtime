"""Refuse incomplete or consistently rehashed evidence from real fence runs."""
from pathlib import Path
import copy
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_effect_fence_qualification as q
from hia_native_build import json_bytes

COUNTS = {"accepted_evidence_objects": 0, "completion_refusals": 0, "worker_trace_refusals": 0,
          "kernel_trace_refusals": 0, "artifact_refusals": 0, "process_refusals": 0,
          "new_native_calls": 0, "new_original_calls": 0}


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(os.environ["HIA_FENCE_QUALIFICATION_OUTPUT"]).resolve(strict=True)
        cls.report = q.object_at(cls.output / "result.json")
        cls.reference = Path(os.environ.get("HIA_REFERENCE_RUNTIME", ROOT)).resolve(strict=True)
        cls.evidence = q.native_evidence(ROOT, cls.output, cls.report, reference_root=cls.reference)
        COUNTS["accepted_evidence_objects"] += 1

    def test_01_complete_current_real_receipts_are_accepted(self):
        self.assertEqual(self.evidence["status"], "PASS")
        self.assertEqual(self.evidence["native_suite_groups"], 31)
        self.assertEqual(self.evidence["actual_native_executable_processes"], 128)
        self.assertEqual(self.evidence["actual_native_executable_frames"], 49757)
        self.assertEqual(self.evidence["actual_native_owner_semantic_responses"], 249)
        self.assertEqual(self.evidence["actual_native_packer_calls"], 98)
        self.assertFalse(self.evidence["production_activated"])

    def test_02_exact_completed_counts_include_no_skips(self):
        original = q.object_at(self.output / q.FOLDER / "async/report.json")
        cases = [("status", "FAIL"), ("tests_run", 6), ("tests_run", 7.0), ("tests_run", True),
            ("failures", 1), ("errors", 1), ("skipped", 1), ("expected_failures", 1),
            ("unexpected_successes", 1), ("failures", False)]
        for key, value in cases:
            modified = dict(original, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                q.completion(modified, 7)
            COUNTS["completion_refusals"] += 1

    def test_03_real_worker_custody_cannot_be_relabelled(self):
        original = q.object_at(self.output / q.FOLDER / "worker/cache-blocked-sigill.json")
        for mode in range(10):
            modified = copy.deepcopy(original)
            armed = next(e for e in modified["events"] if e["kind"] == "armed_fixed_owner_ud2")
            fault = next(e for e in modified["events"] if e["kind"] == "actual_kernel_sigill")
            retired = next(e for e in modified["events"] if e["kind"] == "retire_after_clear_tid")
            if mode == 0: modified["all_owned_tasks_reaped"] = False
            elif mode == 1: armed["cache_held"] = 0
            elif mode == 2: armed["borrowed_fds"].append(armed["owned_fds"][0])
            elif mode == 3: fault["restored_original_instruction"] = False
            elif mode == 4: fault["worker_signal_mask"] = 8
            elif mode == 5: retired["clear_tid"] = 1
            elif mode == 6: retired["job_id"] += 1
            elif mode == 7: retired["address"] += 4096
            elif mode == 8: retired["parent_mask"] = 0
            else: next(e for e in modified["events"] if e["kind"] == "worker_sys_exit")["status"] = 1
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                q.worker_trace_evidence(ROOT, modified, mode="cache", inherited=True,
                                       artifact=self.evidence["profiles"]["production"])
            COUNTS["worker_trace_refusals"] += 1
        original_kernel = q.object_at(self.output / q.FOLDER / "kernel/owner_replace.json")
        for backend in ("native", "original"):
            modified = copy.deepcopy(original_kernel)
            if backend == "native":
                extra = str(max(map(int, modified["exit_statuses"])) + 1)
                modified["exit_statuses"][extra] = 0
            with self.subTest(kernel_backend=backend), self.assertRaises(ValueError):
                q.kernel_trace_evidence(ROOT, modified, "owner_replace", q.DEFAULT_ELF, backend=backend)
            COUNTS["kernel_trace_refusals"] += 1

    def test_04_consistent_artifact_rehash_does_not_replace_the_hia_owner(self):
        with tempfile.TemporaryDirectory(prefix="hia-fence-evidence-") as temporary:
            output = Path(temporary)
            for name in self.evidence["artifact_sha256"]:
                path = output / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(self.output / name, path)
            original = copy.deepcopy(self.report)
            bundle_path = output / original["modules"]["effect_fence"]["manifest"]
            bundle = q.object_at(bundle_path)
            path = output / "build" / bundle["members"]["production"]["manifest"]
            metadata = q.object_at(path)
            for mode in range(10):
                changes = {}
                data = copy.deepcopy(metadata)
                if mode == 0:
                    data["compiler_commit"] = "0" * 40
                elif mode == 1:
                    leaf = path.parent / data["members"][1]["manifest"]
                    module = q.object_at(leaf)
                    image = leaf.parent / module["image"]
                    raw = bytearray(q.read(image)); raw[0] ^= 1
                    changes[image] = bytes(raw)
                    module["image_sha256"] = q.sha(raw)
                    changes[leaf] = json_bytes(module)
                    data["members"][1]["manifest_sha256"] = q.sha(changes[leaf])
                    data["members"][1]["image_sha256"] = q.sha(raw)
                elif mode == 2:
                    frame = path.parent / "pack.input.bin"
                    raw = bytearray(q.read(frame)); raw[-1] ^= 1
                    changes[frame] = bytes(raw)
                    data["pack_input_sha256"] = q.sha(raw)
                elif mode == 3:
                    record = path.parent / "pack.receipt.json"
                    value = q.object_at(record); value["source_unchanged"] = False
                    changes[record] = json_bytes(value)
                    data["pack_receipt"] = value
                elif mode == 4:
                    image = path.parent / data["executable"]
                    raw = bytearray(q.read(image)); raw[176] ^= 1
                    changes[image] = bytes(raw)
                    data["elf_sha256"] = q.sha(raw)
                elif mode == 5:
                    leaf = path.parent / data["members"][0]["manifest"]
                    record = leaf.parent / "module.receipt.json"
                    value = q.object_at(record); value["abi_status"] = False
                    changes[record] = json_bytes(value)
                    build = leaf.parent / "build.json"
                    value_build = q.object_at(build); value_build["compile_receipt"] = value
                    changes[build] = json_bytes(value_build)
                    for item in (record, build):
                        data["members"][0]["compile_files"][item.name] = {"bytes": len(changes[item]), "sha256": q.sha(changes[item])}
                else:
                    packing = mode >= 8
                    item = path.parent / "pack.stdout.log" if packing else path.parent / "member0/module.stdout.log"
                    value = q.object_at(item)
                    if mode % 2 == 0: value = {}
                    else: del value["source_sha256"]
                    changes[item] = json_bytes(value)
                    if not packing:
                        data["members"][0]["compile_files"][item.name] = {"bytes": len(changes[item]), "sha256": q.sha(changes[item])}
                changes[path] = json_bytes(data)
                new_bundle = copy.deepcopy(bundle)
                new_bundle["members"]["production"]["manifest_sha256"] = q.sha(changes[path])
                if mode == 4:
                    new_bundle["members"]["production"]["executable_sha256"] = data["elf_sha256"]
                raw_bundle = json_bytes(new_bundle)
                new_path = output / "build/effect-fence-bundles" / q.sha(raw_bundle) / "manifest.json"
                created = not new_path.exists()
                if created:
                    new_path.parent.mkdir()
                    new_path.write_bytes(raw_bundle)
                else:
                    self.assertEqual(new_path.read_bytes(), raw_bundle)
                new_report = copy.deepcopy(original)
                new_report["modules"]["effect_fence"].update(manifest=str(new_path.relative_to(output)), sha256=q.sha(raw_bundle))
                saved = {item: q.read(item) for item in changes}
                modes = {item: stat.S_IMODE(item.stat().st_mode) for item in changes}
                try:
                    for item, raw in changes.items():
                        item.chmod(modes[item] | stat.S_IWUSR)
                        item.write_bytes(raw)
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        q.artifact_evidence(ROOT, output, new_report)
                    COUNTS["artifact_refusals"] += 1
                finally:
                    for item, raw in saved.items():
                        item.write_bytes(raw); item.chmod(modes[item])
                    if created:
                        new_path.unlink(); new_path.parent.rmdir()

    def test_05_actual_process_failures_and_truncated_completion_refuse(self):
        name = "test_fence_async.py"
        for mode in range(5):
            modified = copy.deepcopy(self.report)
            check = next(item for item in modified["checks"] if item["name"] == name)
            if mode == 0: modified["checks"].append(copy.deepcopy(check))
            elif mode == 1: check["exit_code"] = 1
            elif mode == 2: check["timed_out"] = True
            elif mode == 3: check["summary"]["status"] = "FAIL"
            else: modified["checks"].remove(check)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                q.completed_process(self.output, modified, name)
            COUNTS["process_refusals"] += 1
        with tempfile.TemporaryDirectory(prefix="hia-fence-completion-") as temporary:
            output = Path(temporary)
            modified = copy.deepcopy(self.report)
            check = next(item for item in modified["checks"] if item["name"] == name)
            stdout = q.read(self.output / (name + ".stdout"))
            stderr = q.read(self.output / (name + ".stderr"))[:-1]
            (output / (name + ".stdout")).write_bytes(stdout)
            (output / (name + ".stderr")).write_bytes(stderr)
            check.update(stderr_sha256=q.sha(stderr), stderr_bytes=len(stderr))
            with self.assertRaises(ValueError):
                q.process_evidence(ROOT, output, modified, q.completed_process, name, 7)
            COUNTS["process_refusals"] += 1


if __name__ == "__main__":
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests))
    exact = result.testsRun == 5 and not any((result.failures, result.errors, result.skipped,
        result.expectedFailures, result.unexpectedSuccesses)) and COUNTS == {
        "accepted_evidence_objects": 1, "completion_refusals": 10, "worker_trace_refusals": 10,
        "kernel_trace_refusals": 2, "artifact_refusals": 10, "process_refusals": 6,
        "new_native_calls": 0, "new_original_calls": 0}
    report = {"schema": "hepta.effect-fence.evidence-tests.v1", "status": "PASS" if result.wasSuccessful() and exact else "FAIL",
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses), "counts": COUNTS,
        "elapsed_seconds": time.monotonic() - started,
        "sources": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in
            (Path(__file__), ROOT / "scripts/hia_native_effect_fence_qualification.py")}}
    target = Path(os.environ["HIA_FENCE_EVIDENCE_REPORT"])
    if target.exists(): raise AssertionError("evidence test report already exists")
    target.write_bytes(json_bytes(report))
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(not (result.wasSuccessful() and exact))
