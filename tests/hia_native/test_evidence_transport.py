#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent controls for complete, immutable native evidence transport."""
from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "hia_native_evidence_transport", ROOT / "scripts/hia_native_evidence_transport.py")
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)


class EvidenceTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-evidence-transport-controls-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o750)
        (self.source / "private").mkdir(mode=0o700)
        (self.source / "empty").mkdir(mode=0o500)
        (self.source / "private/tool").write_bytes(b"#!/bin/sh\nexit 0\n")
        (self.source / "private/tool").chmod(0o751)
        os.link(self.source / "private/tool", self.source / "linked-tool")
        (self.source / "independent-copy").write_bytes(b"#!/bin/sh\nexit 0\n")
        (self.source / "independent-copy").chmod(0o640)
        (self.source / "odd : name\n\t\u96ea").write_bytes(bytes(range(256)) * 3)
        (self.source / ".hidden").write_bytes(b"\0secret-looking fixture bytes\n")
        (self.source / "empty-file").write_bytes(b"")
        self.context = transport.binding("a" * 40, "12345-1", "b" * 64)
        self.count = 0

    def destination(self, prefix):
        self.count += 1
        return self.root / (prefix + "-" + str(self.count))

    def package(self):
        output = self.destination("transport")
        result = transport.pack(self.source, output, self.context)
        return output / "evidence.tar.gz", result

    def restore(self, archive, expected=None, context=None):
        destination = self.destination("restored")
        result = transport.unpack(archive, destination, context or self.context,
                                  expected or hashlib.sha256(archive.read_bytes()).hexdigest())
        return destination, result

    def rewrite(self, archive, transform):
        with tarfile.open(archive, "r:gz") as reader:
            members = []
            for member in reader.getmembers():
                stream = reader.extractfile(member)
                members.append([member, stream.read() if stream is not None else b""])
        transform(members)
        output = self.destination("changed").with_suffix(".tar.gz")
        with gzip.GzipFile(filename=str(output), mode="wb", compresslevel=1, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as writer:
                for member, data in members:
                    member.size = len(data)
                    writer.addfile(member, io.BytesIO(data))
        return output

    def mutate_inventory(self, members, function):
        for member, data in members:
            if member.name in ("inventory-before.json", "inventory-after.json"):
                value = transport.unique_json(data)
                function(value)
                members[members.index([member, data])][1] = transport.encode(value)

    def test_complete_tree_modes_names_empty_members_and_hardlinks_round_trip(self):
        before = transport.inventory(self.source, self.context)
        archive, packed = self.package()
        restored, result = self.restore(archive, packed["archive"]["sha256"])
        self.assertEqual(transport.inventory(self.source, self.context), before)
        self.assertEqual(transport.inventory(restored, self.context)["entries"], before["entries"])
        self.assertEqual(packed["files"], 6)
        self.assertEqual(packed["entries"], 9)
        self.assertEqual(packed["inventory_before_sha256"], packed["inventory_after_sha256"])
        self.assertTrue(result["complete_inventory_verified"])
        self.assertEqual(os.stat(restored / "linked-tool").st_ino,
                         os.stat(restored / "private/tool").st_ino)
        self.assertNotEqual(os.stat(restored / "independent-copy").st_ino,
                            os.stat(restored / "private/tool").st_ino)
        self.assertEqual(stat.S_IMODE(os.stat(restored / "private/tool").st_mode), 0o751)
        self.assertEqual((restored / "odd : name\n\t\u96ea").read_bytes(), bytes(range(256)) * 3)

    def test_transport_deduplicates_bytes_without_removing_any_paths(self):
        for index in range(24):
            (self.source / ("duplicate-" + str(index))).write_bytes(b"#!/bin/sh\nexit 0\n")
        archive, report = self.package()
        self.assertEqual(report["files"], 30)
        self.assertEqual(report["unique_objects"], 4)
        restored, _ = self.restore(archive)
        inodes = {os.stat(restored / ("duplicate-" + str(index))).st_ino for index in range(24)}
        self.assertEqual(len(inodes), 24)
        self.assertEqual(transport.inventory(restored, self.context)["entries"],
                         transport.inventory(self.source, self.context)["entries"])

    def test_original_pipeline_inventory_is_unchanged_by_transport(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import hia_native_pipeline as original
        before = original.inventory(self.source)
        archive, _ = self.package()
        restored, _ = self.restore(archive)
        self.assertEqual(original.inventory(restored), before)

    def test_wrong_independent_archive_hash_is_rejected_before_output(self):
        archive, _ = self.package()
        target = self.destination("rejected")
        with self.assertRaisesRegex(ValueError, "independent producer SHA256"):
            transport.unpack(archive, target, self.context, "0" * 64)
        self.assertFalse(target.exists())

    def test_other_invocation_source_or_native_seal_cannot_restore(self):
        archive, _ = self.package()
        for key in self.context:
            context = dict(self.context)
            context[key] = "different"
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, "binding differs"):
                self.restore(archive, context=context)

    def test_source_symlink_and_special_node_are_rejected_without_dereference(self):
        outside = self.root / "outside"
        outside.write_bytes(b"outside must remain untouched")
        path = self.source / "unadmitted"
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "not a regular file or real directory"):
            self.package()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "not a regular file or real directory"):
            self.package()
        self.assertEqual(outside.read_bytes(), b"outside must remain untouched")

    def test_source_file_mutation_after_initial_inventory_is_rejected(self):
        original = transport.add_member
        def change(archive, name, size, stream):
            original(archive, name, size, stream)
            if name == "inventory-before.json":
                (self.source / ".hidden").write_bytes(b"changed after capture")
        with mock.patch.object(transport, "add_member", side_effect=change):
            with self.assertRaisesRegex(ValueError, "source identity changed"):
                self.package()

    def test_terminal_inventory_addition_and_identical_inode_replacement_are_rejected(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                count = 0
                original = transport.inventory
                def change(root, context):
                    nonlocal count
                    count += 1
                    if count == 2:
                        if replacement:
                            target = self.root / "replacement"
                            target.write_bytes((self.source / ".hidden").read_bytes())
                            os.replace(target, self.source / ".hidden")
                        else:
                            (self.source / "after-capture").write_bytes(b"new")
                    return original(root, context)
                with mock.patch.object(transport, "inventory", side_effect=change):
                    with self.assertRaisesRegex(ValueError, "inventory changed during packing"):
                        self.package()
                if not replacement:
                    (self.source / "after-capture").unlink()

    def test_missing_duplicate_and_extra_archive_members_are_rejected(self):
        archive, _ = self.package()
        def missing(members):
            members.pop(1)
        def duplicate(members):
            members.insert(2, copy.deepcopy(members[1]))
        def extra(members):
            row = tarfile.TarInfo("../escape")
            members.append([row, b"escape"])
        for transform in (missing, duplicate, extra):
            with self.subTest(transform=transform.__name__):
                changed = self.rewrite(archive, transform)
                with self.assertRaises(ValueError):
                    self.restore(changed)
        self.assertFalse((self.root / "escape").exists())

    def test_archive_links_and_traversal_member_names_are_rejected(self):
        archive, _ = self.package()
        for kind in ("symlink", "hardlink", "path"):
            def change(members):
                member = members[1][0]
                if kind == "path":
                    member.name = "/tmp/hia-transport-escape"
                else:
                    member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                    member.linkname = "../../escape"
                    members[1][1] = b""
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.restore(self.rewrite(archive, change))

    def test_inventory_traversal_and_file_ancestors_are_rejected(self):
        archive, _ = self.package()
        def traversal(value):
            value["entries"]["../escape"] = value["entries"].pop(".hidden")
            value["capture"]["../escape"] = value["capture"].pop(".hidden")
        def ancestor(value):
            value["entries"]["private"] = copy.deepcopy(value["entries"][".hidden"])
            value["capture"]["private"] = copy.deepcopy(value["capture"][".hidden"])
        for change in (traversal, ancestor):
            def transform(members):
                self.mutate_inventory(members, change)
            with self.subTest(change=change.__name__), self.assertRaises(ValueError):
                self.restore(self.rewrite(archive, transform))

    def test_object_bytes_and_declared_sizes_are_independently_verified(self):
        archive, _ = self.package()
        def bytes_change(members):
            for member, data in members[1:-1]:
                if data:
                    index = next(i for i, pair in enumerate(members) if pair[0] is member)
                    members[index][1] = bytes([data[0] ^ 1]) + data[1:]
                    return
        def size_change(members):
            for member, data in members[1:-1]:
                if data:
                    index = next(i for i, pair in enumerate(members) if pair[0] is member)
                    members[index][1] = data + b"\0"
                    return
        for transform in (bytes_change, size_change):
            with self.subTest(transform=transform.__name__), self.assertRaises(ValueError):
                self.restore(self.rewrite(archive, transform))

    def test_before_and_after_inventories_must_be_exactly_equal(self):
        archive, _ = self.package()
        def change(members):
            value = transport.unique_json(members[-1][1])
            value["capture"]["."]["ctime_ns"] += 1
            members[-1][1] = transport.encode(value)
        with self.assertRaisesRegex(ValueError, "before and after inventories differ"):
            self.restore(self.rewrite(archive, change))

    def test_duplicate_inventory_json_fields_are_rejected(self):
        archive, _ = self.package()
        def change(members):
            for index in (0, len(members) - 1):
                members[index][1] = members[index][1].replace(b'{"binding":', b'{"schema":"duplicate","binding":', 1)
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            self.restore(self.rewrite(archive, change))

    def test_truncated_stream_and_hidden_trailing_payload_are_rejected(self):
        archive, _ = self.package()
        truncated = self.destination("truncated")
        truncated.write_bytes(archive.read_bytes()[:-16])
        with self.assertRaises((EOFError, OSError, ValueError, tarfile.TarError)):
            self.restore(truncated)
        extra = self.destination("trailing")
        extra.write_bytes(archive.read_bytes() + gzip.compress(b"undeclared trailing payload"))
        with self.assertRaisesRegex(ValueError, "unexpected bytes"):
            self.restore(extra)

    def test_existing_or_symlinked_destinations_never_overwrite(self):
        archive, _ = self.package()
        existing = self.root / "existing"
        existing.mkdir()
        (existing / "keep").write_bytes(b"keep")
        with self.assertRaisesRegex(ValueError, "fresh physical"):
            transport.unpack(archive, existing, self.context, hashlib.sha256(archive.read_bytes()).hexdigest())
        alias = self.root / "alias"
        alias.symlink_to(existing, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "fresh physical"):
            transport.unpack(archive, alias, self.context, hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual((existing / "keep").read_bytes(), b"keep")

    def test_source_root_and_archive_symlinks_are_rejected(self):
        alias = self.root / "source-alias"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "physical and owned"):
            transport.pack(alias, self.destination("transport"), self.context)
        archive, _ = self.package()
        link = self.root / "archive-alias"
        link.symlink_to(archive)
        with self.assertRaisesRegex(ValueError, "owned regular"):
            self.restore(link)


if __name__ == "__main__":
    unittest.main(verbosity=2)
