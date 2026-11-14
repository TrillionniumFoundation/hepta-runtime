"""Reject incomplete and consistently rehashed authority qualification evidence.

These are verifications of retained observations and owned mutated files.
There are no native calls or original Rust executions in this suite.
"""
from pathlib import Path
import base64
import copy
import gzip
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests/hia_native"))
import hia_native_authority_qualification as q
from authority_native_harness import inspect_loaded

COUNTS = {key: 0 for key in q.EVIDENCE_COUNTS}
CONTROLS = []


def write_json(path, value):
    path.write_bytes(q.json_bytes(value))


def mutate_json(path, change):
    value = json.loads(path.read_bytes())
    change(value)
    write_json(path, value)


def refresh_kernel(folder):
    raw = (folder / "kernel-cases.json").read_bytes()
    mutate_json(folder / "kernel-report.json", lambda value: value.update(cases_sha256=q.digest(raw), cases_bytes=len(raw)))


def refresh_capture(folder):
    inventory = q.object_at(folder / "retained-files.json")
    for name in inventory:
        raw = (folder / name).read_bytes()
        inventory[name] = {"bytes": len(raw), "sha256": q.digest(raw)}
    write_json(folder / "retained-files.json", inventory)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ["HIA_AUTHORITY_ELF_MANIFEST"]).resolve(strict=True)
        cls.probe_manifest = Path(os.environ["HIA_AUTHORITY_PROBE_MANIFEST"]).resolve(strict=True)
        cls.scope_manifest = Path(os.environ["HIA_SCOPE_MANIFEST"]).resolve(strict=True)
        cls.build_root = cls.manifest.parents[2]
        cls.compiler = q.object_at(cls.manifest)["compiler_sha256"]
        cls.temporary = tempfile.TemporaryDirectory(prefix="authority-evidence-controls-")
        cls.folder = Path(cls.temporary.name)
        cls.fixture = cls.folder / "fixture"
        packed = q.read(ROOT / "tests/hia_native/authority_receipt_fixture.json.gz")
        assert len(packed) < 1 << 20
        files = json.loads(gzip.decompress(packed))
        assert type(files) is dict and len(files) == 107
        for name, value in files.items():
            relative = Path(name)
            assert not relative.is_absolute() and ".." not in relative.parts and relative.as_posix() == name
            raw = base64.b64decode(value, validate=True)
            path = cls.fixture / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream: stream.write(raw)
        cls.artifact = q.composition_artifacts(ROOT, cls.build_root, cls.manifest, cls.compiler)
        cls.probe = q.probe_artifacts(ROOT, cls.build_root, cls.probe_manifest, cls.compiler)
        cls.binary_hash = "b157e78536ee099c2bf9a684009227a637df5e11d940278af7ddaf881fcdbfa8"
        cls.original_files = {str(p): q.sha(p) for p in
            (cls.manifest, cls.probe_manifest, cls.scope_manifest,
             cls.manifest.parent / "native-authority.elf")}

    @classmethod
    def tearDownClass(cls):
        assert all(q.sha(Path(name)) == expected for name, expected in cls.original_files.items())
        cls.temporary.cleanup()

    def cloned(self, name, source):
        target = self.folder / name
        shutil.copytree(source, target)
        return target

    def refused(self, name, callback, *, loaded=False):
        with self.assertRaises((ValueError, AssertionError)):
            callback()
        COUNTS["mutation_refusals"] += 1
        if loaded:
            COUNTS["rehashed_loaded_image_refusals"] += 1
        CONTROLS.append({"case": name, "refused": True, "actual_loaded_file_substitution": loaded})

    def test_complete_actual_receipts_are_accepted(self):
        accepted = [
            lambda: q.composition_artifacts(ROOT, self.build_root, self.manifest, self.compiler),
            lambda: q.probe_artifacts(ROOT, self.build_root, self.probe_manifest, self.compiler),
            lambda: q.controller_evidence(ROOT, self.fixture / "controller"),
            lambda: q.kernel_evidence(ROOT, self.fixture / "capture/native-kernel", self.probe["executable_sha256"]),
            lambda: q.kernel_evidence(ROOT, self.fixture / "capture/original-kernel", self.binary_hash, original=True),
            lambda: q.transport_evidence(ROOT, self.fixture / "capture/authority-transport",
                                         self.artifact["executable_sha256"], self.fixture / "controller"),
            lambda: q.packer_evidence(ROOT, self.fixture / "packer.json", self.artifact),
            lambda: q.captured_original_evidence(ROOT, self.fixture / "capture", self.fixture / "controller",
                                                 self.artifact, self.probe),
        ]
        for number, callback in enumerate(accepted):
            with self.subTest(number=number):
                self.assertEqual(callback()["status"], "PASS")
                COUNTS["accepted_evidence_objects"] += 1

    def test_controller_source_counts_loaded_images_and_domain(self):
        mutations = [
            ("controller-count", lambda value: value["native_report"]["counts"].update(native_public_requests=111)),
            ("controller-completion", lambda value: value["native_report"].update(tests_run=7)),
            ("controller-root-image", lambda value: value["native_report"]["loaded_artifacts"]["members"][0].update(image_sha256="0" * 64)),
            ("controller-kdf-image", lambda value: value["native_report"]["loaded_artifacts"]["members"][2].update(image_sha256="0" * 64)),
            ("controller-entropy-image", lambda value: value["native_report"]["loaded_artifacts"]["members"][7].update(image_sha256="0" * 64)),
            ("controller-domain", lambda value: value.update(raw_sha256="0" * 64)),
            ("controller-predeclared-controls", lambda value: value["predetermined_control_contexts"][0].update(selected_before_startup=False)),
        ]
        for label, change in mutations:
            folder = self.cloned(label, self.fixture / "controller")
            mutate_json(folder / "native-corpus.json", change)
            self.refused(label, lambda folder=folder: q.controller_evidence(ROOT, folder))

    def test_kernel_complete_case_and_actual_effect_provenance(self):
        for index, label in enumerate(("kernel-completion", "kernel-source", "kernel-result", "kernel-missing-case",
                                       "kernel-executable", "kernel-effect-order", "kernel-span", "kernel-random-domain")):
            folder = self.cloned(label, self.fixture / "capture/native-kernel")
            if index == 0:
                mutate_json(folder / "kernel-report.json", lambda value: value.update(tests_run=4))
            elif index == 1:
                mutate_json(folder / "kernel-report.json", lambda value: value["sources"].update(authority_loader_supervisor_py="0" * 64))
            else:
                cases = json.loads((folder / "kernel-cases.json").read_bytes())
                if index == 2:
                    cases[0]["code"] ^= 1
                elif index == 3:
                    cases.pop()
                elif index == 7:
                    owner = next(row for row in cases if row["kind"] == "owner" and row["output_bytes"] == 32)
                    owner["output_hex"] = "00" * 32
                    owner["normal_random_bytes_compared"] = True
                else:
                    case = next(row for row in cases if row["supervisor"] == "observe" and row["kind"] == "token")
                    trace = case["trace"]
                    if index == 4:
                        trace["executable_sha256"] = "0" * 64
                    elif index == 5:
                        trace["events"][0], trace["events"][1] = trace["events"][1], trace["events"][0]
                    else:
                        event = next(item for item in trace["events"] if item["action"] == "read")
                        event["descriptor_offset_before"] = 4099
                    write_json(folder / f'trace-{case["ordinal"]:03d}.json', trace)
                write_json(folder / "kernel-cases.json", cases)
                refresh_kernel(folder)
            self.refused(label, lambda folder=folder: q.kernel_evidence(ROOT, folder, self.probe["executable_sha256"]))

    def test_transport_actual_custody_and_no_runtime_claim(self):
        labels = ("transport-completion", "transport-new-rust-claim", "transport-executable",
                  "transport-erasure", "transport-order", "transport-responses", "transport-wire", "transport-reaping")
        for index, label in enumerate(labels):
            folder = self.cloned(label, self.fixture / "capture/authority-transport")
            if index < 2:
                mutate_json(folder / "transport-report.json",
                    (lambda value: value.update(tests_run=5)) if index == 0 else
                    (lambda value: value.update(new_rust_replay_claimed=True)))
            else:
                cases = json.loads((folder / "transport-cases.json").read_bytes())
                if index == 5:
                    cases[0]["responses"] -= 1
                elif index == 6:
                    cases[0]["input_sha256"] = "0" * 64
                else:
                    ordinal, case = next((number, row) for number, row in enumerate(cases, 1) if row.get("trace"))
                    trace = case["trace"]
                    if index == 2: trace["executable_sha256"] = "0" * 64
                    elif index == 3: trace["native_cleanup"]["private_workspaces_zero"] = False
                    elif index == 4: trace["events"][0], trace["events"][1] = trace["events"][1], trace["events"][0]
                    elif index == 7: trace["owned_process_reaped"] = False
                    write_json(folder / f"trace-{ordinal:03d}.json", trace)
                write_json(folder / "transport-cases.json", cases)
            self.refused(label, lambda folder=folder: q.transport_evidence(ROOT, folder,
                self.artifact["executable_sha256"], self.fixture / "controller"))

    def test_captured_original_execution_cannot_be_relabelled(self):
        labels = ("original-owner-count", "original-generated-source", "original-process-failure",
                  "original-binary", "original-dependency", "original-kernel-domain")
        for index, label in enumerate(labels):
            folder = self.cloned(label, self.fixture / "capture")
            if index == 0:
                mutate_json(folder / "authority-comparison.json", lambda value: value["original_controller"].update(rows=121))
            elif index == 1:
                path = folder / "generated/original_authority_reference.rs"
                path.write_bytes(path.read_bytes() + b"\n")
            elif index == 2:
                mutate_json(folder / "cargo-build.receipt.json", lambda value: value.update(exit_code=1))
            elif index in (3, 4):
                change = (lambda value: value.update(binary_sha256="0" * 64)) if index == 3 else (
                    lambda value: value.update(all_registry_versions_and_checksums_match_baseline=False))
                mutate_json(folder / "original-build.json", change)
                mutate_json(folder / "authority-comparison.json", lambda value:
                    value.update(original_build=q.object_at(folder / "original-build.json")))
            else:
                sub = folder / "original-kernel"
                mutate_json(sub / "kernel-cases.json", lambda value: value[0].update(code=0xffffffff))
                refresh_kernel(sub)
            refresh_capture(folder)
            self.refused(label, lambda folder=folder: q.captured_original_evidence(ROOT, folder,
                self.fixture / "controller", self.artifact, self.probe))

    def test_actual_compiler_and_packed_files_are_bound(self):
        folder = self.cloned("build-mutations", self.build_root)
        manifest = folder / self.manifest.relative_to(self.build_root)
        executable = manifest.parent / "native-authority.elf"
        executable.chmod(0o700)
        original_manifest, original_elf = manifest.read_bytes(), executable.read_bytes()
        labels = ("compiled-missing-commit", "compiled-wrong-commit", "compiled-receipt",
                  "packed-table-rehashed", "packed-image-rehashed", "packed-pointer-rehashed")
        provenance = q.object_at(ROOT / "native/authority_packer_provenance.json")
        for index, label in enumerate(labels):
            modified = json.loads(original_manifest)
            restore = None
            if index == 0:
                del modified["compiler_commit"]
                write_json(manifest, modified)
            elif index == 1:
                modified["compiler_commit"] = "0" * 40
                write_json(manifest, modified)
            elif index == 2:
                name = "composition-" + q.PACKER_SHA[:24]
                path = folder / "modules" / name / "module.receipt.json"
                restore = path, path.read_bytes()
                mutate_json(path, lambda value: value.update(source_unchanged=False))
            else:
                raw = bytearray(original_elf)
                descriptor = provenance["metadata_offset"] + 64
                if index == 3:
                    raw[descriptor + 16] ^= 1
                elif index == 4:
                    raw[struct.unpack_from("<Q", raw, descriptor)[0] + 17] ^= 1
                else:
                    raw[provenance["metadata_hole"]] ^= 1
                executable.write_bytes(raw)
                modified["executable_sha256"] = q.digest(raw)
                modified.pop("layout", None)
                write_json(manifest, modified)
            self.refused(label, lambda: q.composition_artifacts(ROOT, folder, manifest, self.compiler))
            manifest.write_bytes(original_manifest); executable.write_bytes(original_elf)
            if restore is not None: restore[0].write_bytes(restore[1])

    def test_consistently_rehashed_real_loaded_leaf_images_are_rejected(self):
        for index in (2, 7):
            folder = self.cloned("loaded-leaf-" + str(index), self.scope_manifest.parent)
            manifest = folder / self.scope_manifest.name
            parent = q.object_at(manifest)
            path = folder / f"module_{index:02d}.json"
            child = q.object_at(path)
            image = folder / child["image"]
            raw = bytearray(image.read_bytes()); raw[len(raw) // 2] ^= 1; image.write_bytes(raw)
            child["image_sha256"] = q.digest(raw); write_json(path, child)
            parent["members"][index]["image_sha256"] = q.digest(raw)
            parent["members"][index]["manifest_sha256"] = q.sha(path)
            write_json(manifest, parent)
            self.refused("rehashed-loaded-" + str(index), lambda manifest=manifest:
                inspect_loaded(self.manifest.parent / "module_00.json", self.manifest.parent / "module_08.json", manifest),
                loaded=True)


if __name__ == "__main__":
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "hepta.runtime.authority-evidence.tests.v1",
        "tests_run": result.testsRun, "expected_tests": 7, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
        "counts": COUNTS, "expected_counts": q.EVIDENCE_COUNTS, "counts_match": COUNTS == q.EVIDENCE_COUNTS,
        "sources": {name: q.sha(ROOT / name) for name in q.EVIDENCE_SOURCES},
        "manifest_sha256": q.sha(Path(os.environ["HIA_AUTHORITY_ELF_MANIFEST"])),
        "probe_manifest_sha256": q.sha(Path(os.environ["HIA_AUTHORITY_PROBE_MANIFEST"])),
        "elapsed_seconds": round(time.monotonic() - started, 6), "controls": CONTROLS,
        "whole_runtime_replaced": False}
    passed = result.wasSuccessful() and result.testsRun == 7 and report["counts_match"] and all(report[name] == 0 for name in
        ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"))
    report["status"] = "PASS" if passed else "FAIL"
    if os.environ.get("HIA_AUTHORITY_EVIDENCE_REPORT"):
        path = Path(os.environ["HIA_AUTHORITY_EVIDENCE_REPORT"])
        with path.open("x") as stream: stream.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if passed else 1)
