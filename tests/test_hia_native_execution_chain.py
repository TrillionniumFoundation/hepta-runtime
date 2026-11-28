#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Synthetic native construction custody controls, never execution receipts."""
from hashlib import sha256
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "native_execution_chain", Path(__file__).with_name("hia_native_execution_chain.py"))
chain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(chain)


def file_manifest(rows):
    return b"HIASXM01" + struct.pack("<3Q", len(rows), 1, 0) + b"".join(
        struct.pack("<2Q", len(name), row["bytes"]) + bytes.fromhex(row["sha256"]) + name.encode("ascii")
        for name, row in sorted(rows.items()))


class NativeConstructionReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source, self.output = self.root / "source", self.root / "output"
        self.source.mkdir()
        self.output.mkdir()
        self.recipe = "examples/hia_bootstrap/cold_build_recipe.hiadat"
        self.authority = "examples/hia_bootstrap/cold_build_sources.hiadat"
        self.plan = "examples/hia_bootstrap/cold_build_plans/00-reader-fixture.hiacases"
        names = sorted([self.recipe, self.authority, self.plan])
        for name in names:
            (self.source / name).parent.mkdir(parents=True, exist_ok=True)
        authority = b"HIATBS01" + struct.pack("<3Q", 1, len(names), 0)
        authority += b"".join(struct.pack("<Q", len(name)) + name.encode("ascii") + bytes((-len(name)) % 8)
                              for name in names)
        (self.source / self.authority).write_bytes(authority)
        (self.source / self.plan).write_bytes(b"HIAQPL01" + struct.pack("<3Q", 3, 0, 0) + b"non-executable plan custody fixture")
        publications = []
        for name in ("hia-cold", "hia-source-bootstrap"):
            publications.append(struct.pack("<8Q", len(name), len(name), 0o500, 1, 64 * 1024 * 1024, 0, 0, 0)
                                + name.encode().ljust(64, b"\0") + name.encode().ljust(192, b"\0"))
            target = self.output / name
            target.write_bytes(b"non-executable construction output fixture " + name.encode())
            target.chmod(0o500)
        raw = b"HIATBR01" + struct.pack("<15Q", 1, 1, 2, 2, len(names), 128, 192, 448, 1088, 0, 0, 0, 0, 0, 0)
        raw += struct.pack("<8Q", 0, names.index(self.plan), 0, 2, 0, 2, 0, 0) + bytes(256) + b"".join(publications)
        (self.source / self.recipe).write_bytes(raw)
        self.sources = {name: sha256((self.source / name).read_bytes()).hexdigest() for name in names}
        source_rows = {name: chain.observer.pin(self.source / name) for name in names}
        self.tools = {name: chain.observer.pin(self.output / name) for name in ("hia-cold", "hia-source-bootstrap")}
        (self.output / "source.manifest.hiasxm").write_bytes(file_manifest(source_rows))
        (self.output / "toolchain.manifest.hiasxm").write_bytes(file_manifest(self.tools))
        self.write_receipt()
        stage = self.output / "build-evidence/s0"
        stage.mkdir(parents=True)
        journal = b"non-executable stage journal custody fixture"
        (stage / "evidence.hiaqj").write_bytes(journal)
        (stage / "driver.receipt").write_bytes(b"HIAQOK01" + struct.pack("<3Q", 3, (self.source / self.plan).stat().st_size, len(journal))
                                              + sha256(journal).digest())

    def write_receipt(self):
        source = (self.output / "source.manifest.hiasxm").read_bytes()
        tools = (self.output / "toolchain.manifest.hiasxm").read_bytes()
        (self.output / "build.receipt").write_bytes(b"HIATBOK1" + struct.pack("<7Q", 1, 1, 3, 2, len(source), len(tools), 0)
                                                  + sha256(source).digest() + sha256(tools).digest())

    def admit(self):
        return chain.admit_construction(self.source, self.output, self.sources, magic=b"HIATBOK1", recipe=self.recipe)

    def test_physical_manifest_and_stage_journal_match_the_frozen_recipe(self):
        tools, record = self.admit()
        self.assertEqual(tools, self.tools)
        self.assertEqual(record["stages"][0]["nodes"], 3)

    def test_changed_tool_bytes_and_mode_are_refused(self):
        path = self.output / "hia-cold"
        raw = path.read_bytes()
        path.chmod(0o700)
        path.write_bytes(raw + b"foreign executable")
        path.chmod(0o500)
        with self.assertRaisesRegex(RuntimeError, "bound manifest"):
            self.admit()
        path.chmod(0o700)
        path.write_bytes(raw)
        with self.assertRaisesRegex(RuntimeError, "bound manifest"):
            self.admit()

    def test_self_consistent_extra_manifest_tool_is_not_in_the_frozen_recipe(self):
        tools = dict(self.tools)
        tools["foreign-entry"] = tools["hia-cold"]
        (self.output / "toolchain.manifest.hiasxm").write_bytes(file_manifest(tools))
        self.write_receipt()
        with self.assertRaisesRegex(RuntimeError, "tool inventory"):
            self.admit()

    def test_substituted_or_missing_stage_evidence_is_refused(self):
        path = self.output / "build-evidence/s0/evidence.hiaqj"
        path.write_bytes(b"different successful-looking stage journal")
        with self.assertRaisesRegex(RuntimeError, "physical plan or journal"):
            self.admit()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.admit()

    def test_changed_recipe_or_plan_cannot_replace_frozen_source(self):
        for name in (self.recipe, self.plan):
            path = self.source / name
            raw = path.read_bytes()
            path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "changed after source admission"):
                self.admit()
            path.write_bytes(raw)

    def test_missing_prebuild_observation_never_falls_back_to_cold_only(self):
        with self.assertRaisesRegex(RuntimeError, "complete distribution and prebuild"):
            chain.admit_chain(hepta=self.source, source="1" * 40, distribution=self.source,
                distribution_commit="2" * 40, staging=self.output, toolchain=self.output,
                prebuild_execution=None, cold_report=self.output / "final-cold.json", cold_execution=self.output,
                post=self.output, post_execution=self.output)


if __name__ == "__main__":
    unittest.main()
