#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Byte-only source custody and shared evidence formats."""
from __future__ import annotations
from pathlib import Path, PurePosixPath
import hashlib
import importlib.util
import json
import stat
import tomllib

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
HEPTA = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
B3 = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
SCOPE = dict(original_types_compared=True, original_handler_executed=False,
             sdk_protocol_executed=False, public_route_registered=False,
             asynchronous_runtime_qualified=False, whole_runtime_qualified=False)
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def decode(raw):
    def unique(items):
        out = {}
        for key, value in items:
            require(key not in out, "duplicate evidence key")
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite evidence")))


def owned(root, relative):
    require(type(relative) is str and relative and PurePosixPath(relative).as_posix() == relative
        and not PurePosixPath(relative).is_absolute() and ".." not in PurePosixPath(relative).parts,
        "invalid relative evidence path")
    p = Path(root) / relative
    require(p.resolve() == p.absolute() and stat.S_ISREG(p.lstat().st_mode), "ordinary owned file required: " + str(p))
    return p


_PIN_CACHE = {}

def pin(path):
    p = Path(path)
    before = p.stat()
    key = (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid,
           before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    require(stat.S_ISREG(before.st_mode), "ordinary retained file required")
    if key not in _PIN_CACHE:
        with p.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = p.stat()
        actual = (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
                  after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        require(actual == key, "retained file changed during complete byte read")
        _PIN_CACHE[key] = digest
    return dict(bytes=before.st_size, sha256=_PIN_CACHE[key])


def source_evidence(root):
    root = Path(root)
    manifest = decode(owned(root, "SOURCE_MANIFEST.json").read_bytes())
    rows = manifest["files"]
    require(len({row["path"] for row in rows}) == len(rows), "duplicate source path")
    expected = {row["path"] for row in rows} | {"SOURCE_MANIFEST.json"}
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    require(actual == expected, "source file set changed")
    files = {}
    for row in rows:
        path = owned(root, row["path"]); raw = path.read_bytes()
        got = dict(bytes=len(raw), sha256=sha(raw))
        require(got == {k: row[k] for k in got}, "source byte pin changed: " + row["path"])
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["git_blob"], "source Git object changed")
        require(row["mode"] == "100644" and not (path.stat().st_mode & 0o111), "source mode changed")
        files[row["path"]] = got
    target = owned(root, "target/binary.rs").read_bytes()
    proof = decode(owned(root, "reference/source_manifest.json").read_bytes())
    require(proof["target_commit"] == TARGET and proof["target_source_sha256"] == sha(target), "reference target changed")
    start, end = proof["target_span"]
    fragment = target[start:end]
    require(sha(fragment) == proof["target_span_sha256"], "original declaration slice changed")
    actual = owned(root, "reference/src/original.rs").read_bytes()
    require(actual.rstrip(b"\n") == fragment, "original typed declarations edited")
    tests = owned(root, "target/binary_tests.rs").read_bytes()
    require(sha(tests) == proof["target_tests_sha256"], "original tests target changed")
    start, end = proof["tests_span"]
    fragment = tests[start:end]
    require(sha(fragment) == proof["tests_span_sha256"] and owned(root, "reference/src/original_tests.rs").read_bytes().rstrip(b"\n") == fragment, "original test bodies changed")
    original = tomllib.loads(owned(root, "target/Cargo.lock").read_text())
    selected = tomllib.loads(owned(root, "reference/Cargo.lock").read_text())
    by_key = {(p["name"], p["version"]): p for p in original["package"] if p.get("source", "").startswith("registry+")}
    registry = [p for p in selected["package"] if "source" in p]
    require(len(registry) == 17, "current exact registry closure changed")
    for row in registry:
        old = by_key[row["name"], row["version"]]
        require(all(row[k] == old[k] for k in ("name", "version", "source", "checksum")), "target registry version/checksum changed")
    return dict(manifest=pin(root / "SOURCE_MANIFEST.json"), files=files, target=TARGET,
                registry=[{k: p[k] for k in ("name", "version", "source", "checksum")} for p in registry])


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded
