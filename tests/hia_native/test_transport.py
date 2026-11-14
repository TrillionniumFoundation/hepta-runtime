"""Actual HIA image, persistent descriptor transport and code-pin controls."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild, check_dependency
from hia_native_loader import NativeModule, NativeCapacityError


class NativeTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        hepta = os.environ.get("HIA_HEPTA_DIR")
        build_root = os.environ.get("HIA_BUILD_ROOT")
        if not hepta or not build_root:
            raise RuntimeError("HIA_HEPTA_DIR and HIA_BUILD_ROOT are required; no native test is skipped")
        cls.builder = NativeBuild(hepta, build_root)
        cls.builder.bootstrap()
        cls.manifests = {}
        for name, transport in (("echo", "stdio"), ("sequence", "stdio"), ("echo", "filter")):
            source = ROOT / "tests" / "hia_native" / (name + ".hepta")
            label = "transport-" + name + "-" + transport
            target = Path(build_root) / "modules" / label / "manifest.json"
            if target.exists():
                metadata = json.loads(target.read_bytes())
                packer = ROOT / "native" / ("stdio_packer.hepta" if transport == "stdio" else "filter_packer.hepta")
                if (metadata["source_sha256"] != sha256(source.read_bytes()).hexdigest()
                    or metadata["standalone"]["packer_source_sha256"] != sha256(packer.read_bytes()).hexdigest()):
                    raise RuntimeError("transport test build source changed; use a new build workspace")
            else:
                target = cls.builder.compile(label, source, standalone=transport)
            cls.manifests[(name, transport)] = target

    def executable(self, name="echo", transport="stdio"):
        manifest = self.manifests[(name, transport)]
        meta = json.loads(manifest.read_bytes())
        path = manifest.parent / meta["standalone"]["path"]
        self.assertEqual(sha256(path.read_bytes()).hexdigest(), meta["standalone"]["sha256"])
        self.assertFalse(meta["standalone"]["inspection"]["dynamic_loader"])
        self.assertFalse(meta["standalone"]["inspection"]["libc"])
        return path

    def run_native(self, wire, *, name="echo", transport="stdio", args=()):
        with tempfile.TemporaryDirectory(prefix="hia-native-empty-") as empty:
            return subprocess.run([str(self.executable(name, transport)), *args], input=wire,
                capture_output=True, timeout=20, cwd=empty, env={"PATH": ""})

    def load(self, manifest=None):
        path = manifest or self.manifests[("echo", "stdio")]
        return NativeModule(path, manifest_sha256=sha256(path.read_bytes()).hexdigest())

    def test_native_persistent_frames_notifications_and_final_unterminated_frame(self):
        for source, expected in ((b"", b""), (b"one\ntwo\nlast", b"one\ntwo\nlast\n"),
                                 (b"one\n\ntwo\n", b"one\ntwo\n"), (b"a\r\nb\n", b"a\r\nb\n")):
            with self.subTest(source=source):
                row = self.run_native(source)
                self.assertEqual((row.returncode, row.stdout, row.stderr), (0, expected, b""))

    def test_native_session_state_persists_and_new_process_starts_fresh(self):
        for _ in range(2):
            row = self.run_native(b"first\nsecond\nthird", name="sequence")
            self.assertEqual((row.returncode, row.stdout, row.stderr), (0, b"1\n2\n3\n", b""))
        with self.load(self.manifests[("sequence", "stdio")]) as native:
            with native.session(output_capacity=1, workspace_capacity=1) as session:
                self.assertEqual([session.invoke(b"x") for _ in range(3)], [b"1", b"2", b"3"])
            with native.session(output_capacity=1, workspace_capacity=1) as session:
                self.assertEqual(session.invoke(b"x"), b"1")

    def test_native_fragmented_pipe_reads_return_before_input_eof(self):
        process = subprocess.Popen([str(self.executable())], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": ""})
        try:
            process.stdin.write(b"par"); process.stdin.flush()
            self.assertEqual(select.select([process.stdout], [], [], 0.05)[0], [])
            process.stdin.write(b"tial\nsecond\ntrailing"); process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 5)[0])
            self.assertEqual(process.stdout.readline(), b"partial\n")
            self.assertEqual(process.stdout.readline(), b"second\n")
            process.stdin.close(); process.stdin = None
            output, error = process.communicate(timeout=5)
            self.assertEqual((process.returncode, output, error), (0, b"trailing\n", b""))
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)

    def test_exact_maximum_line_and_plus_one_refusal_with_empty_output(self):
        wire = b"a" * (8 << 20)
        accepted = self.run_native(wire + b"\n")
        self.assertEqual((accepted.returncode, accepted.stdout, accepted.stderr), (0, wire + b"\n", b""))
        refused = self.run_native(wire + b"a")
        self.assertEqual((refused.returncode, refused.stdout, refused.stderr), (3, b"", b""))

    def test_filter_is_one_shot_opaque_bytes_and_requires_no_runtime(self):
        wire = b"\0binary\xff\ncontent\n"
        row = self.run_native(wire, transport="filter")
        self.assertEqual((row.returncode, row.stdout, row.stderr), (0, wire, b""))
        usage = self.run_native(b"", args=("unexpected",))
        self.assertEqual((usage.returncode, usage.stdout, usage.stderr), (64, b"", b""))

    def test_real_descriptor_io_failure(self):
        with open("/dev/full", "wb", buffering=0) as full:
            result = subprocess.run([str(self.executable())], input=b"message\n", stdout=full,
                stderr=subprocess.PIPE, timeout=5, env={"PATH": ""})
        self.assertEqual((result.returncode, result.stderr), (4, b""))

    def test_loader_uses_native_result_full_buffers_and_immutable_code(self):
        with self.load() as module:
            self.assertEqual(module.invoke(b"abc", output_capacity=3, workspace_capacity=0), b"abc")
            with self.assertRaises(NativeCapacityError):
                module.invoke(b"abc", output_capacity=2, workspace_capacity=0)
            code, output, workspace = module.invoke_raw(b"abc", output_capacity=2,
                workspace_capacity=4, output_fill=0xA5, workspace_fill=0x5A)
            self.assertEqual((code, output, workspace), (0xFFFFFFFE, b"\xa5" * 2, b"\x5a" * 4))
            address = module._address
            maps = Path("/proc/self/maps").read_text().splitlines()
            row = next(line for line in maps if int(line.split("-", 1)[0], 16) <= address < int(line.split("-", 1)[1].split()[0], 16))
            self.assertEqual(row.split()[1][:3], "r-x")
        with self.assertRaisesRegex(RuntimeError, "closed"):
            module.invoke(b"", output_capacity=0, workspace_capacity=0)

    def test_image_source_and_manifest_tampering_refuse_before_call(self):
        original = self.manifests[("echo", "stdio")]
        for member in ("image", "source"):
            with tempfile.TemporaryDirectory(prefix="hia-native-pin-") as folder:
                root = Path(folder)
                metadata = json.loads(original.read_bytes())
                for name in ("image", "source"):
                    shutil.copy2(original.parent / metadata[name], root / metadata[name])
                manifest = root / "manifest.json"
                manifest.write_bytes(original.read_bytes())
                changed = root / metadata[member]
                changed.write_bytes(changed.read_bytes() + b"x")
                with self.assertRaisesRegex(ValueError, "identity mismatch"):
                    self.load(manifest)
        with self.assertRaisesRegex(ValueError, "manifest identity"):
            NativeModule(original, manifest_sha256="0" * 64)

    def test_warm_image_does_not_hide_changed_source(self):
        original = self.manifests[("echo", "stdio")]
        with tempfile.TemporaryDirectory(prefix="hia-native-warm-") as folder:
            root = Path(folder); metadata = json.loads(original.read_bytes())
            for member in ("image", "source"):
                shutil.copy2(original.parent / metadata[member], root / metadata[member])
            manifest = root / "manifest.json"; manifest.write_bytes(original.read_bytes())
            with self.load(manifest) as native:
                self.assertEqual(native.invoke(b"warm", output_capacity=4, workspace_capacity=0), b"warm")
                source = root / metadata["source"]; source.write_bytes(source.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "source changed"):
                    native.invoke(b"warm", output_capacity=4, workspace_capacity=0)

    def test_pinned_dependency_and_compiler_fixed_point_are_actual_bytes(self):
        identity = check_dependency(Path(os.environ["HIA_HEPTA_DIR"]).resolve())
        receipt = json.loads((self.builder.root / "bootstrap" / "bootstrap.json").read_bytes())
        self.assertEqual(receipt["dependency"], identity)
        self.assertFalse(receipt["matching_source_cold_qualified"])
        generations = [(self.builder.root / "bootstrap" / (name + ".image.bin")).read_bytes() for name in ("B1", "B2", "B3")]
        self.assertTrue(generations[0] == generations[1] == generations[2])
        for row in receipt["generation_receipts"]:
            self.assertEqual(row["forbidden_compiler_modules_loaded"], [])

    def test_cached_compiler_drift_is_refused_before_another_compilation(self):
        with tempfile.TemporaryDirectory(prefix="hia-compiler-drift-") as folder:
            target = Path(folder) / "bootstrap"
            target.mkdir()
            for name in ("B1.image.bin", "B2.image.bin", "B3.image.bin", "bootstrap.json"):
                shutil.copy2(self.builder.root / "bootstrap" / name, target / name)
            builder = NativeBuild(os.environ["HIA_HEPTA_DIR"], folder)
            compiler = builder.bootstrap()
            compiler.write_bytes(compiler.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "compiler image changed"):
                builder.bootstrap()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hepta")
    parser.add_argument("--build-root")
    options, remaining = parser.parse_known_args()
    if options.hepta: os.environ["HIA_HEPTA_DIR"] = options.hepta
    if options.build_root: os.environ["HIA_BUILD_ROOT"] = options.build_root
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
