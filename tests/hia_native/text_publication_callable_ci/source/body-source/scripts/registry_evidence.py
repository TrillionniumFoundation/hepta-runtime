#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bind every used current-target registry source byte to its locked crate archive."""
from __future__ import annotations
from pathlib import Path, PurePosixPath
import tomllib
import hashlib
import tarfile
from common import decode, owned, pin, require, sha, source_evidence


def inventory(source, output, *, capture=False):
    source, output = Path(source), Path(output)
    source_evidence(source)
    target = {(p["name"], p["version"]): p for p in tomllib.loads(owned(source, "target/Cargo.lock").read_text())["package"] if p.get("source")}
    locked = [p for p in tomllib.loads(owned(output, "reference/Cargo.lock").read_text())["package"] if p.get("source")]
    exact = [dict(name=p["name"],version=p["version"],source=p["source"],checksum=p["checksum"]) for p in locked]
    require(len({(p["name"],p["version"]) for p in exact}) == len(exact), "duplicate retained registry package")
    for row in exact:
        original = target.get((row["name"], row["version"]))
        require(original is not None and all(original[k] == row[k] for k in row), "retained crate differs from exact current target")
    metadata = decode(owned(output, "processes/cargo-metadata.stdout").read_bytes())
    packages = [p for p in metadata["packages"] if p.get("source") is not None]
    by_key = {(p["name"], p["version"]): p for p in packages}
    require(len(by_key) == len(packages) == len(exact), "actual registry closure changed")
    origins = decode(owned(output, "ORIGIN.json").read_bytes())
    origin = Path(origins["output"])
    result = []
    for row in exact:
        selected = by_key[row["name"], row["version"]]
        require(selected["source"] == row["source"], "actual registry source changed")
        original_manifest = Path(selected["manifest_path"])
        require(original_manifest.is_relative_to(origin / "cargo-home/registry/src"), "actual registry source escaped fresh Cargo home")
        relative = original_manifest.parent.relative_to(origin).as_posix()
        root = output / relative
        crate_name = row["name"] + "-" + row["version"]
        archives = list((output / "cargo-home/registry/cache").glob("*/" + crate_name + ".crate"))
        require(len(archives) == 1, "exact used crate archive absent/ambiguous")
        archive = archives[0]
        require(pin(archive)["sha256"] == row["checksum"], "locked crate checksum differs")
        files = {}
        with tarfile.open(archive, "r:gz") as stream:
            seen = set()
            for member in stream:
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and ".." not in name.parts and name.parts and name.parts[0] == crate_name,
                    "crate member path invalid")
                if member.isdir():
                    continue
                require(member.isfile() and member.name not in seen, "crate member kind/duplicate invalid")
                seen.add(member.name)
                child = PurePosixPath(*name.parts[1:]).as_posix()
                require(child and child != ".", "crate file missing relative path")
                raw = stream.extractfile(member).read()
                actual = owned(root, child).read_bytes()
                require(len(raw) == member.size and actual == raw, "actual registry file differs from locked archive: " + crate_name + "/" + child)
                files[child] = dict(bytes=len(raw), sha256=sha(raw))
        actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
        extras = actual - set(files)
        require(extras <= {".cargo-ok", ".cargo-checksum.json"}, "unbound registry generated files: " + repr(extras))
        generated = {}
        for child in sorted(extras):
            raw = owned(root, child).read_bytes()
            value = decode(raw)
            if child == ".cargo-ok":
                require(value == {"v": 1}, "Cargo extraction marker changed")
            else:
                require(set(value) == {"files", "package"} and value["package"] == row["checksum"] and type(value["files"]) is dict, "Cargo checksum metadata changed")
                require(not value["files"] or value["files"] == {name: item["sha256"] for name, item in files.items()}, "Cargo per-file checksum metadata changed")
            generated[child] = pin(root / child)
        require(set(files) <= actual, "used registry source file missing")
        result.append(dict(**row, archive=archive.relative_to(output).as_posix(), archive_pin=pin(archive),
                           source_path=relative, files=files, generated=generated))
    return dict(packages=result, metadata=pin(output / "processes/cargo-metadata.stdout"),
                used_registry_packages=len(result), full_crate_and_source_bytes_verified=True)
