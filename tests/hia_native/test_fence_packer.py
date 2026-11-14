"""Actual frozen HIA packing, image admission and real cached-builder refusals."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import stat
import struct
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule
from hia_native_effect_fence_build import build_effect_fence, inspect_embedded

COUNTS = {"native_calls": 0, "successful_packs": 0, "admission_refusals": 0,
          "capacity_refusals": 0, "cache_admissions": 0, "cache_refusals": 0}


class PackerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifests = [Path(os.environ[name]).resolve(strict=True) for name in
                         ("HIA_FENCE_ASYNC_MANIFEST", "HIA_FENCE_ASYNC_SINGLE_MANIFEST")]
        cls.metadata = [json.loads(path.read_bytes()) for path in cls.manifests]
        cls.modules = []
        for path, data in zip(cls.manifests, cls.metadata):
            packer = path.parent / data["packer_manifest"]
            cls.modules.append(NativeModule(packer, manifest_sha256=hashlib.sha256(packer.read_bytes()).hexdigest()))
        cls.frame = (cls.manifests[0].parent / "pack.input.bin").read_bytes()
        if cls.frame != (cls.manifests[1].parent / "pack.input.bin").read_bytes():
            raise AssertionError("queue fixture must contain the same five HIA images")
        cls.profile = json.loads((ROOT / "native/effect_fence_profile.json").read_bytes())
        cls.images = [cls.frame[64 + sum(m["image_bytes"] for m in cls.profile["members"][:index]):
                                64 + sum(m["image_bytes"] for m in cls.profile["members"][:index + 1])]
                      for index in range(5)]
        cls.size = cls.metadata[0]["elf_bytes"]

    @classmethod
    def tearDownClass(cls):
        for module in cls.modules:
            module.close()

    def call(self, frame, expected, *, capacity=None, workspace=4096, module=0):
        capacity = self.size if capacity is None else capacity
        code, output, _ = self.modules[module].invoke_raw(frame, output_capacity=capacity,
            workspace_capacity=workspace, output_fill=0xa5)
        COUNTS["native_calls"] += 1
        self.assertEqual(code, expected)
        if code in (0xffffffff, 0xfffffffe):
            self.assertEqual(output, b"\xa5" * capacity)
            COUNTS["admission_refusals" if code == 0xffffffff else "capacity_refusals"] += 1
        else:
            COUNTS["successful_packs"] += 1
            self.assertEqual(output[code:], b"\xa5" * (capacity - code))
        return output[:code] if code < 0xffff0000 else None

    def test_01_exact_two_profiles_and_actual_embedded_images(self):
        for index, name in enumerate(("production", "queue_fixture")):
            raw = self.call(self.frame, self.size, module=index, capacity=self.size + 1)
            self.assertEqual(raw, (self.manifests[index].parent / self.metadata[index]["executable"]).read_bytes())
            inspect_embedded(raw, self.images, self.profile, self.profile["profiles"][name])
        self.assertNotEqual(self.metadata[0]["elf_sha256"], self.metadata[1]["elf_sha256"])
        self.assertEqual([m["worker_limit"] for m in self.metadata], [512, 1])

    def test_02_malformed_frames_preserve_output(self):
        cases = [self.frame[:size] for size in range(64)]
        cases += [b"X" + self.frame[1:], self.frame[:-1], self.frame + b"X"]
        for at in (48, 56):
            raw = bytearray(self.frame)
            struct.pack_into("<Q", raw, at, 1)
            cases.append(bytes(raw))
        for at in range(8, 48, 8):
            for value in (0, (1 << 64) - 1):
                raw = bytearray(self.frame)
                struct.pack_into("<Q", raw, at, value)
                cases.append(bytes(raw))
        self.assertEqual(len(cases), 79)
        for case in cases:
            self.call(case, 0xffffffff)

    def test_03_every_actual_image_is_hashed_before_output(self):
        at = 64
        for image in self.images:
            for offset in (0, len(image) - 1):
                raw = bytearray(self.frame)
                raw[at + offset] ^= 1
                self.call(bytes(raw), 0xffffffff)
            at += len(image)
        swapped = [self.images[1], self.images[0], *self.images[2:]]
        frame = b"HFFPACK2" + b"".join(struct.pack("<Q", len(image)) for image in swapped)
        frame += bytes(16) + b"".join(swapped)
        self.call(frame, 0xffffffff)

    def test_04_short_output_and_workspace_are_atomic(self):
        for capacity in (0, 1, 8192, self.size - 1):
            self.call(self.frame, 0xfffffffe, capacity=capacity)
        for workspace in (0, 4095):
            self.call(self.frame, 0xfffffffe, workspace=workspace)

    def test_05_real_cached_build_requires_source_image_receipt_and_compiler(self):
        hepta = Path(os.environ["HIA_HEPTA_DIR"]).resolve(strict=True)
        original_root = Path(os.environ["HIA_BUILD_ROOT"]).resolve(strict=True)
        self.assertEqual(self.manifests[0].parents[2], original_root)
        with tempfile.TemporaryDirectory(prefix="hia-fence-real-cache-") as temporary:
            root = Path(temporary)
            shutil.copytree(original_root / "bootstrap", root / "bootstrap")
            folder = root / "effect-fence" / self.manifests[0].parent.name
            folder.parent.mkdir()
            shutil.copytree(self.manifests[0].parent, folder)
            manifest = folder / "manifest.json"
            before = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in root.rglob("*") if p.is_file()}
            self.assertEqual(build_effect_fence(hepta, root, source_root=ROOT), manifest)
            COUNTS["cache_admissions"] += 1
            original = manifest.read_bytes()
            for mode in ("missing_commit", "wrong_commit", "changed_elf", "changed_image",
                         "bool_packer_status", "changed_compile_receipt", "empty_compile_stdout",
                         "missing_compile_stdout_field", "empty_pack_stdout", "missing_pack_stdout_field"):
                changed = {}
                data = json.loads(original)
                if mode == "missing_commit":
                    del data["compiler_commit"]
                elif mode == "wrong_commit":
                    data["compiler_commit"] = "0" * 40
                elif mode == "changed_elf":
                    path = folder / data["executable"]
                    raw = bytearray(path.read_bytes()); raw[176] ^= 1
                    changed[path] = bytes(raw)
                    data["elf_sha256"] = hashlib.sha256(raw).hexdigest()
                elif mode == "changed_image":
                    path = folder / data["members"][1]["manifest"]
                    module = json.loads(path.read_bytes())
                    image = path.parent / module["image"]
                    raw = bytearray(image.read_bytes()); raw[0] ^= 1
                    changed[image] = bytes(raw)
                    module["image_sha256"] = hashlib.sha256(raw).hexdigest()
                    changed[path] = (json.dumps(module, sort_keys=True) + "\n").encode()
                    data["members"][1]["manifest_sha256"] = hashlib.sha256(changed[path]).hexdigest()
                elif mode == "bool_packer_status":
                    path = folder / "pack.receipt.json"
                    report = json.loads(path.read_bytes()); report["abi_status"] = False
                    changed[path] = (json.dumps(report, sort_keys=True) + "\n").encode()
                    data["pack_receipt"] = report
                elif mode == "changed_compile_receipt":
                    member = data["members"][0]
                    path = (folder / member["manifest"]).parent
                    report = json.loads((path / "module.receipt.json").read_bytes())
                    report["forbidden_compiler_modules_loaded"] = ["hepta.semantic_fallback"]
                    build = json.loads((path / "build.json").read_bytes()); build["compile_receipt"] = report
                    for name, value in (("module.receipt.json", report), ("build.json", build)):
                        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
                        changed[path / name] = raw
                        member["compile_files"][name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                else:
                    packing = "pack_stdout" in mode
                    member = data["members"][0]
                    path = folder / "pack.stdout.log" if packing else (folder / member["manifest"]).parent / "module.stdout.log"
                    value = json.loads(path.read_bytes())
                    if mode.startswith("empty_"): value = {}
                    else: del value["source_sha256"]
                    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
                    changed[path] = raw
                    if not packing:
                        member["compile_files"][path.name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                changed[manifest] = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
                saved = {path: path.read_bytes() for path in changed}
                modes = {path: stat.S_IMODE(path.stat().st_mode) for path in changed}
                try:
                    for path, raw in changed.items():
                        # Only the independently copied owned cache is made
                        # writable for the predeclared corruption control.
                        path.chmod(modes[path] | stat.S_IWUSR)
                        path.write_bytes(raw)
                    with self.subTest(case=mode), self.assertRaises(ValueError):
                        build_effect_fence(hepta, root, source_root=ROOT)
                    self.assertEqual({path: path.read_bytes() for path in changed}, changed)
                    COUNTS["cache_refusals"] += 1
                finally:
                    for path, raw in saved.items():
                        path.write_bytes(raw)
                        path.chmod(modes[path])
            self.assertEqual({str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in root.rglob("*") if p.is_file()}, before)


if __name__ == "__main__":
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PackerTests))
    exact = result.testsRun == 5 and not any((result.failures, result.errors, result.skipped,
        result.expectedFailures, result.unexpectedSuccesses)) and COUNTS == {
        "native_calls": 98, "successful_packs": 2, "admission_refusals": 90,
        "capacity_refusals": 6, "cache_admissions": 1, "cache_refusals": 10}
    report = {"schema": "hepta.effect-fence.packer-qualification.v1",
        "status": "PASS" if result.wasSuccessful() and exact else "FAIL",
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses), "counts": COUNTS,
        "elapsed_seconds": time.monotonic() - started,
        "cached_bootstrap_scope": "development_fixed_point; no fresh cold replay",
        "sources": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (
            Path(__file__), ROOT / "scripts/hia_native_effect_fence_build.py",
            ROOT / "scripts/hia_native_build.py", ROOT / "scripts/hia_native_loader.py",
            ROOT / "native/effect_fence_profile.json")}}
    path = Path(os.environ["HIA_FENCE_PACKER_REPORT"])
    if path.exists():
        raise AssertionError("packer evidence must not overwrite prior results")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(not (result.wasSuccessful() and exact))
