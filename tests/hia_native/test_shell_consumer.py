"""Physical admission controls; synthetic bytes never qualify a HIA owner."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_shell_consumer as c


class ShellConsumerAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-shell-consumer-control-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "output"
        self.source = self.root / "source"
        self.output.mkdir()
        self.source.mkdir()
        for name in c.SOURCES:
            self.write(self.source / name, ("synthetic reporting source " + name).encode())
        build = self.output / "build"
        self.write(build / "bootstrap/bootstrap.json", b"synthetic bootstrap receipt")
        for name in ("B1", "B2", "B3"):
            self.write(build / "bootstrap" / (name + ".image.bin"), b"synthetic identical compiler")
        self.compiler = c.pin(build / "bootstrap/B3.image.bin")["sha256"]
        self.modules = {}
        for key, name, source in (
            ("shell_process", "shell-process", "native/shell_process.hepta"),
            ("shell_output_io", "shell-output", "native/shell_output_io.hepta"),
            ("shell_outcome", "shell-outcome", "native/shell_outcome.hepta"),
            ("shell_foreground", "shell-foreground", "native/shell_foreground_controller.hepta"),
        ):
            self.modules[key] = {"manifest": "build/" + name + "/manifest.json",
                                "source": source, "builder": key}
        for key in ("shell_process", "shell_output_io"):
            self.json(build / ("shell-process" if key == "shell_process" else "shell-output") / "manifest.json",
                      {"synthetic_static_member": key})
            self.modules[key]["sha256"] = c.pin(self.output / self.modules[key]["manifest"])["sha256"]
        self.make_pair("build")
        self.prepared = {"modules": copy.deepcopy(self.modules),
            "source_sha256": {n: c.pin(self.source / n)["sha256"] for n in c.SOURCES},
            "compiler_image_sha256": self.compiler,
            "compiler_bootstrap_sha256": c.pin(build / "bootstrap/bootstrap.json")["sha256"]}
        self.json(self.output / "prepared-report.json", self.prepared)
        self.write(self.output / "native-build.json", b"immutable synthetic reporting seal")
        self.expected = c.pin(self.output / "native-build.json")["sha256"]
        shutil.copytree(build / "bootstrap", self.output / c.DIRECTORY / "bootstrap")
        self.make_pair(c.DIRECTORY)
        current = c.bound_modules(self.output, self.prepared["modules"])
        images, host = c.unchanged_images(self.output, self.output, self.prepared,
                                         c.original_modules(self.output, self.prepared), current)
        self.receipt = {"schema": c.SCHEMA, "status": "CONSUMER_BUILD_READY",
            "recorded_output": str(self.output), "prepared_sha256": self.expected,
            "prepared_report_sha256": c.pin(self.output / "prepared-report.json")["sha256"],
            "compiler_image_sha256": self.compiler,
            "compiler_bootstrap_sha256": self.prepared["compiler_bootstrap_sha256"],
            "sources": self.prepared["source_sha256"],
            "prepared_modules": {k: self.prepared["modules"][k] for k in c.MEMBERS},
            "consumer_modules": current,
            "bootstrap_files": c.files(build / "bootstrap"), "unchanged_images": images,
            "host_dependencies": host, "files": c.files(self.output / c.DIRECTORY), **c.SCOPE}
        self.seal()

    def write(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def json(self, path, value):
        self.write(path, c.nb.json_bytes(value))

    def make_pair(self, base):
        outcome = self.output / base / "shell-outcome"
        self.write(outcome / "owner.o", b"synthetic identical HIA outcome object")
        om = {"compiler_sha256": self.compiler, "object": "owner.o",
              "allocator": {"synthetic_retained_allocator": base},
              "linker": {"synthetic_retained_linker": base}}
        self.json(outcome / "manifest.json", om)
        self.modules["shell_outcome"]["sha256"] = c.pin(outcome / "manifest.json")["sha256"]
        fg = self.output / base / "shell-foreground"
        fm = {"compiler_sha256": self.compiler, "interpreter": {"synthetic_retained_loader": base}}
        for name in ("bundle.o", "adapter.o", "adapter.text.bin", "outcome.o"):
            self.write(fg / name, ("synthetic identical " + name).encode())
        for name in ("controller", "packer"):
            rel = "modules/shell-foreground-" + name
            self.write(self.output / base / rel / "module.image.bin", ("synthetic HIA " + name).encode())
            self.json(self.output / base / rel / "manifest.json",
                      {"compiler_sha256": self.compiler, "image": "module.image.bin"})
            fm[name + "_manifest"] = rel + "/manifest.json"
        for name, key in (("process", "shell_process"), ("output", "shell_output_io")):
            fm[name + "_manifest"] = str(self.output / self.modules[key]["manifest"])
            fm[name + "_manifest_sha256"] = self.modules[key]["sha256"]
        fm["outcome_manifest"] = str(outcome / "manifest.json")
        fm["outcome_manifest_sha256"] = c.pin(outcome / "manifest.json")["sha256"]
        self.json(fg / "manifest.json", fm)
        self.modules["shell_foreground"]["sha256"] = c.pin(fg / "manifest.json")["sha256"]

    def seal(self):
        self.json(self.output / c.MANIFEST, self.receipt)
        self.binding = {"manifest": c.MANIFEST, "sha256": c.pin(self.output / c.MANIFEST)["sha256"]}

    def read(self, **kwargs):
        return c.read(self.output, self.prepared, self.binding, self.expected,
                      source_root=self.source, **kwargs)

    def test_complete_declaration_survives_partial_transport_without_executing_or_granting_semantics(self):
        before = c.files(self.output)
        with patch.object(c.foreground, "admit_execution", side_effect=AssertionError("execution")):
            proof = self.read()
            data = self.root / "transport"
            shutil.copytree(self.output / c.DIRECTORY, data / c.DIRECTORY)
            self.assertEqual(self.read(data_root=data), proof)
        self.assertEqual(c.files(self.output), before)
        self.assertIsNone(proof["complete_builds"])
        self.assertIs(proof["semantic_qualification_granted_by_consumer_build"], False)
        with self.assertRaisesRegex(ValueError, "outcome build ABI"):
            self.read(full=True)
        with self.assertRaisesRegex(ValueError, "exact recorded output"):
            self.read(data_root=data, full=True)

    def test_report_substitutes_exactly_two_members(self):
        proof = self.read()
        report = {"modules": copy.deepcopy(self.prepared["modules"]), "shell_consumer_build": self.binding}
        report["modules"].update(proof["modules"])
        c.admit_report(self.output, self.prepared, report, self.expected, source_root=self.source)
        for key in ("shell_process", "shell_outcome"):
            changed = copy.deepcopy(report)
            changed["modules"][key]["sha256"] = "0" * 64
            with self.subTest(member=key), self.assertRaises(ValueError):
                c.admit_report(self.output, self.prepared, changed, self.expected, source_root=self.source)
        del report["modules"]["shell_output_io"]
        with self.assertRaisesRegex(ValueError, "complete module registry"):
            c.admit_report(self.output, self.prepared, report, self.expected, source_root=self.source)

    def test_resigned_receipt_cannot_change_scope_source_origin_or_original_module(self):
        baseline = copy.deepcopy(self.receipt)
        for field in ("whole_runtime_replaced", "sources", "recorded_output", "prepared_modules",
                      "compiler_image_sha256", "prepared_sha256", "bootstrap_files"):
            self.receipt = copy.deepcopy(baseline)
            if field == "whole_runtime_replaced":
                self.receipt[field] = True
            elif isinstance(self.receipt[field], dict):
                self.receipt[field] = {}
            else:
                self.receipt[field] = "0" * 64
            self.seal()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read()
        self.receipt = baseline
        self.seal()
        self.read()

    def test_resigned_consumer_inventory_cannot_hide_a_changed_hia_object(self):
        path = self.output / c.DIRECTORY / "shell-outcome/owner.o"
        path.write_bytes(path.read_bytes() + b"extra byte")
        self.receipt["files"] = c.files(self.output / c.DIRECTORY, {"consumer.json"})
        self.receipt["unchanged_images"]["outcome.object"] = {
            k: v for k, v in c.pin(path).items() if k != "mode"}
        self.seal()
        with self.assertRaisesRegex(ValueError, "changed prepared HIA"):
            self.read()

    def test_missing_file_symlink_and_wrong_prepared_seal_are_refused(self):
        path = self.output / c.DIRECTORY / "shell-foreground/bundle.o"
        raw = path.read_bytes()
        path.unlink()
        with self.assertRaises(ValueError):
            self.read()
        outside = self.root / "external"
        outside.write_bytes(raw)
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "ordinary"):
            self.read()
        path.unlink()
        path.write_bytes(raw)
        self.read()
        with patch.object(c.outcome, "build_shell_outcome", side_effect=AssertionError("compiled")):
            with self.assertRaisesRegex(ValueError, "unchanged admitted prepared seal"):
                c.build(self.output, self.root, self.prepared, "0" * 64, source_root=self.source)

    def test_live_admission_rejects_equal_version_different_allocator_and_loader_bytes(self):
        fg = c.foreground
        allocator, allocator_pin, version = c.outcome.loaded_allocator()
        loader = fg.interpreter_path()
        outcome = self.root / "execution-outcome.json"
        self.json(outcome, {"allocator": {"runtime_version": version}})
        manifest = self.root / "execution-foreground.json"
        metadata = {"allocator": {"path": str(allocator), "pin": allocator_pin},
                    "interpreter": {"path": str(loader), "pin": fg.pin(loader)},
                    "outcome_manifest": str(outcome)}
        self.json(manifest, metadata)
        proof = {"synthetic_complete_reader_boundary": True}
        with patch.object(fg, "read_evidence", return_value=proof):
            self.assertIs(fg.admit_execution(manifest), proof)
            wrong = dict(allocator_pin, sha256="0" * 64)
            with patch.object(c.outcome, "loaded_allocator", return_value=(allocator, wrong, version)):
                with self.assertRaisesRegex(ValueError, "actual loader/allocator"):
                    fg.admit_execution(manifest)
            metadata["interpreter"]["pin"]["sha256"] = "0" * 64
            self.json(manifest, metadata)
            with self.assertRaisesRegex(ValueError, "actual loader/allocator"):
                fg.admit_execution(manifest)


if __name__ == "__main__":
    unittest.main()
