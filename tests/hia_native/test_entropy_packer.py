"""Actual HIA ELF packing and refusal of malformed test-only native effects."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(os.environ.get("HIA_REFERENCE_RUNTIME", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule
sys.path.insert(0, str(Path(__file__).resolve().parent))
from entropy_test_support import completion_counts

COUNTS = {"native_packer_calls": 0, "native_executables": 0,
          "malformed_effect_refusals": 0, "admission_refusals": 0,
          "capacity_refusals": 0, "dirty_return_refusals": 0,
          "cached_builder_admissions": 0, "cached_builder_commit_refusals": 0}


class EntropyPacker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(os.environ["HIA_ENTROPY_MANIFEST"])
        cls.manifest = path.resolve(strict=True)
        cls.metadata = json.loads(path.read_text())
        manifest = path.parent / cls.metadata["packer_manifest"]
        cls.module = NativeModule(manifest, manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())
        assert cls.module.metadata["source_sha256"] == cls.metadata["packer_source_sha256"]
        cls.temporary = tempfile.TemporaryDirectory(prefix="hepta-entropy-packer-controls-")
        cls.directory = Path(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls.module.close()
        cls.temporary.cleanup()

    def pack(self, image, capacity=1 << 20):
        frame = b"HIAENTP1" + struct.pack("<Q", len(image)) + image
        code, output, work = self.module.invoke_raw(frame, output_capacity=capacity,
                                                    workspace_capacity=0, output_fill=0xa5)
        COUNTS["native_packer_calls"] += 1
        self.assertEqual(work, b"")
        if code < 0xffff0000:
            self.assertLessEqual(code, capacity)
            self.assertEqual(output[code:], b"\xa5" * (capacity - code))
            return output[:code]
        self.assertEqual(code, 0xfffffffe)
        self.assertEqual(output, b"\xa5" * capacity)
        COUNTS["capacity_refusals"] += 1
        return None

    def execute(self, image, expected):
        executable = self.pack(image)
        number = COUNTS["native_executables"]
        path = self.directory / (str(number) + ".elf")
        path.write_bytes(executable)
        path.chmod(0o500)
        log = self.directory / (str(number) + ".json")
        supervisor = Path(__file__).parent / "entropy_backend_supervisor.py"
        run = subprocess.run([sys.executable, "-B", str(supervisor), "--mode", "observe", "--log", str(log),
                              "--", str(path)], input=b"HRENT001" + struct.pack("<QQ", 0, 0),
                             capture_output=True, timeout=10)
        COUNTS["native_executables"] += 1
        self.assertEqual((run.returncode, run.stdout, run.stderr),
                         (expected, bytes(4) if expected == 0 else b"", b""))
        self.assertEqual(json.loads(log.read_text()), {
            "events": [], "owned_child_reaped": True,
            "executable_sha256": hashlib.sha256(executable).hexdigest()})

    def test_exact_capacity_and_elf_structure(self):
        image = b"\x31\xc0\xc3"
        elf = self.pack(image)
        self.assertEqual(elf[:7], b"\x7fELF\x02\x01\x01")
        self.assertEqual(struct.unpack_from("<HH", elf, 16), (2, 62))
        self.assertEqual(struct.unpack_from("<Q", elf, 24)[0], 0x4000b0)
        self.assertEqual(struct.unpack_from("<QQ", elf, 96), (len(elf), len(elf)))
        self.assertEqual(elf[-len(image):], image)
        self.assertEqual(self.pack(image, len(elf)), elf)
        self.assertIsNone(self.pack(image, len(elf) - 1))
        self.assertIsNone(self.pack(b"x" * ((1 << 20) - 16)))
        self.execute(image, 0)

    def test_invalid_packer_frames_preserve_output(self):
        valid = b"HIAENTP1" + struct.pack("<Q", 3) + b"\x31\xc0\xc3"
        cases = [valid[:n] for n in range(17)] + [valid + b"x", b"x" * len(valid)]
        for request in cases:
            code, output, work = self.module.invoke_raw(request, output_capacity=2048,
                                                        workspace_capacity=0, output_fill=0xa5)
            COUNTS["native_packer_calls"] += 1
            self.assertEqual((code, output, work), (0xffffffff, b"\xa5" * 2048, b""))
            COUNTS["admission_refusals"] += 1

    def test_dirty_high_return_bits_are_rejected(self):
        self.execute(b"\x48\xb8" + struct.pack("<Q", 1 << 32) + b"\xc3", 2)
        COUNTS["dirty_return_refusals"] += 1

    def test_cached_builder_requires_the_exact_top_level_compiler_commit(self):
        from hia_native_entropy_build import build_entropy
        hepta = Path(os.environ["HIA_HEPTA_DIR"]).resolve(strict=True)
        original_root = Path(os.environ["HIA_BUILD_ROOT"]).resolve(strict=True)
        bootstrap = original_root / "bootstrap"
        bootstrap_receipt = json.loads((bootstrap / "bootstrap.json").read_bytes())
        self.assertEqual(bootstrap_receipt["qualification"], "development_fixed_point")
        self.assertIs(bootstrap_receipt["matching_source_cold_qualified"], False)
        key = hashlib.sha256((ROOT / "native/entropy_policy.hepta").read_bytes()
                             + (ROOT / "native/entropy_packer.hepta").read_bytes()).hexdigest()
        self.assertEqual(self.manifest.parent, original_root / "entropy" / key)
        isolated = self.directory / "copied-real-cache"
        isolated.mkdir()
        shutil.copytree(bootstrap, isolated / "bootstrap")
        copied = isolated / "entropy" / key
        copied.parent.mkdir()
        shutil.copytree(self.manifest.parent, copied)
        cache_manifest = copied / "manifest.json"
        original_manifest = cache_manifest.read_bytes()
        snapshot = {p.relative_to(isolated).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in isolated.rglob("*") if p.is_file()}
        self.assertEqual(build_entropy(hepta, isolated, source_root=ROOT), cache_manifest)
        self.assertEqual(cache_manifest.read_bytes(), original_manifest)
        COUNTS["cached_builder_admissions"] += 1
        for kind in ("missing", "different"):
            with self.subTest(compiler_commit=kind):
                metadata = json.loads(original_manifest)
                if kind == "missing":
                    del metadata["compiler_commit"]
                else:
                    metadata["compiler_commit"] = "0" * 40
                modified = (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode()
                cache_manifest.write_bytes(modified)
                with self.assertRaisesRegex(ValueError, "native entropy manifest contract differs"):
                    build_entropy(hepta, isolated, source_root=ROOT)
                self.assertEqual(cache_manifest.read_bytes(), modified)
                cache_manifest.write_bytes(original_manifest)
                COUNTS["cached_builder_commit_refusals"] += 1
        self.assertEqual({p.relative_to(isolated).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in isolated.rglob("*") if p.is_file()}, snapshot)

    def test_bad_effect_fields_cannot_reach_getrandom(self):
        base = {256: int.from_bytes(b"HIAENT02", "little"), 264: 1, 272: 512, 280: 32,
                288: 0, 296: 2, 304: 0, 312: 0, 320: 0, 328: 0}
        cases = [(256, 0), (264, 0), (264, 2), (264, (1 << 64) - 1),
                 (272, 511), (272, 640), (272, (1 << 64) - 1),
                 (280, 0), (280, 129), (280, (1 << 64) - 1), (272, 639),
                 (288, 1), (296, 1), (304, 1), (312, 1), (320, 1), (328, 1)]
        for offset, value in cases:
            fields = dict(base)
            fields[offset] = value
            code = b"".join(b"\x48\xb8" + struct.pack("<Q", value) + b"\x49\x89\x80" + struct.pack("<I", offset)
                            for offset, value in fields.items())
            code += b"\xb8\xf0\xff\xff\xff\xc3"
            self.execute(code, 2)
            COUNTS["malformed_effect_refusals"] += 1


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=2)
    report = {"schema": "hepta.runtime.entropy-packer-test.v1",
              **completion_counts(result.result, 5),
              "scope": "actual HIA packer, malformed native effect images, and copied real compiler/artifact cache",
              "cached_bootstrap_scope": "development_fixed_point; no new cold qualification",
              "counts": COUNTS}
    target = os.environ.get("HIA_ENTROPY_PACKER_REPORT")
    if target:
        path = Path(target)
        assert not path.exists(), "entropy evidence must not overwrite a previous run"
        path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["status"] == "PASS" else 1)
