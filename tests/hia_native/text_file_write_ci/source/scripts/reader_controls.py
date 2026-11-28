#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Physical retained-evidence rejection controls; no native or Rust execution."""
from __future__ import annotations
from pathlib import Path
import gzip
import hashlib
import json
import os
import shutil
from common import canonical, decode, pin, require, sha


def replace(path, raw):
    temp = path.with_name(path.name + ".new")
    with temp.open("xb") as stream:
        stream.write(raw)
    temp.chmod(path.stat().st_mode & 0o777)
    os.replace(temp, path)


def create(source, output, controls):
    from run_ci import read_all
    from readonly import guarded, snapshot
    source, output, controls = Path(source), Path(output), Path(controls)
    require(not controls.exists(), "reader controls output must be fresh")
    controls.mkdir(parents=True)
    outcomes = []
    original_before = snapshot([output])
    for name in ("case-count", "module-image", "original-wire", "source-byte", "crate-archive", "retained-growth"):
        clone = controls / name
        shutil.copytree(output, clone, copy_function=shutil.copy2)
        changed = []
        def mutate(path, raw):
            before = pin(path); replace(path, raw)
            changed.append(dict(path=path.relative_to(clone).as_posix(), before=before, after=pin(path)))
        if name == "case-count":
            path = clone / "native/capture-result.json"
            value = decode(path.read_bytes()); value["cases"] += 1; mutate(path, canonical(value))
        elif name == "module-image":
            path = clone / "build/modules/text-file-write-params/module.image.bin"
            raw = bytearray(path.read_bytes()); raw[0] ^= 1; mutate(path, bytes(raw))
        elif name == "original-wire":
            path = clone / "processes/original.stdout"
            rows = [decode(x) for x in path.read_bytes().splitlines()]
            row = next(x for x in rows if x["result"].get("ok"))
            raw = bytearray.fromhex(row["result"]["frame_hex"]); raw[16] = 3 if raw[16] == 1 else 1
            row["result"]["frame_hex"] = raw.hex(); mutate(path, b"".join(canonical(x) for x in rows))
            path = clone / "processes/original.json"
            receipt = decode(path.read_bytes()); receipt["streams"]["stdout"] = pin(clone / "processes/original.stdout")
            mutate(path, canonical(receipt))
        elif name == "source-byte":
            path = clone / "source/native/text_file_write_params.hepta"
            mutate(path, path.read_bytes() + b"\n")
        elif name == "crate-archive":
            path = sorted((clone / "cargo-home/registry/cache").glob("*/*.crate"))[0]
            raw = bytearray(path.read_bytes()); raw[-1] ^= 1; mutate(path, bytes(raw))
        else:
            path = clone / "native/calls.jsonl"
            rows = [decode(x) for x in path.read_bytes().splitlines()]
            raw = bytearray(gzip.decompress((clone / "native/calls.bin.gz").read_bytes()))
            row = next(x for x in rows if x["owner"] == 2 and x["label"] == "semantic" and x["workspace_capacity"] == 65536)
            start = row["offset"]; at = start + 64 + row["input_bytes"] + row["workspace_capacity"] + 2 * row["output_capacity"]
            raw[at] ^= 1
            row["after_sha256"] = sha(raw[at:at+row["workspace_capacity"]])
            row["record_sha256"] = sha(raw[start:start+row["bytes"]])
            mutate(path, b"".join(canonical(x) for x in rows))
            mutate(clone / "native/calls.bin.gz", gzip.compress(raw, compresslevel=1, mtime=0))
        before = {item["path"]: pin(clone / item["path"]) for item in changed}
        def reject():
            try:
                read_all(clone / "source", clone)
            except (ValueError, AssertionError, EOFError) as error:
                return dict(name=name, rejected=True, error_type=type(error).__name__, error=str(error), changes=changed)
            raise RuntimeError("physical evidence control unexpectedly passed: " + name)
        result = guarded(reject, roots=[clone])
        outcome = result["evidence"]
        (controls / (name + "-readonly.json")).write_bytes(canonical(result))
        require(before == {path: pin(clone / path) for path in before}, "reader changed mutated evidence")
        outcomes.append(outcome)
    require(original_before == snapshot([output]), "physical controls changed original evidence metadata/bytes")
    result = dict(status="PHYSICAL_READER_CONTROLS_PASS", controls=outcomes,
                  original_capture_unchanged=True, native_executed=False, rust_executed=False)
    (controls / "controls.json").write_bytes(canonical(result))
    # Re-read the intact complete evidence after every physical clone has been checked.
    intact = read_all(source, output)
    require(intact["status"] == "COMPLETE_TYPED_COMPARISON_PASS", "intact capture changed during physical controls")
    return result


def verify(source, output, controls):
    from run_ci import read_all
    source, output, controls = Path(source), Path(output), Path(controls)
    report = decode((controls / "controls.json").read_bytes())
    names = ("case-count", "module-image", "original-wire", "source-byte", "crate-archive", "retained-growth")
    require(report["status"] == "PHYSICAL_READER_CONTROLS_PASS" and [row["name"] for row in report["controls"]] == list(names), "physical reader control domain changed")
    files = {p.relative_to(output).as_posix(): p for p in output.rglob("*") if p.is_file()}
    actual = []
    for row in report["controls"]:
        clone = controls / row["name"]
        clone_files = {p.relative_to(clone).as_posix(): p for p in clone.rglob("*") if p.is_file()}
        require(set(files) == set(clone_files), "physical control cloned file set changed")
        changes = {item["path"]: item for item in row["changes"]}
        require(len(changes) == len(row["changes"]) and changes, "physical mutation is absent/duplicated")
        for path, original in files.items():
            before, after = pin(original), pin(clone_files[path])
            require((original.stat().st_mode & 0o777) == (clone_files[path].stat().st_mode & 0o777), "physical clone mode changed")
            if path in changes:
                require(changes[path]["before"] == before and changes[path]["after"] == after and before != after, "physical declared mutation differs from actual retained bytes")
            else:
                require(before == after, "unlisted physical clone mutation")
        try:
            read_all(clone / "source", clone)
        except (ValueError, AssertionError, EOFError) as error:
            require(type(error).__name__ == row["error_type"] and str(error) == row["error"], "physical clone no longer produces its retained refusal")
        else:
            raise ValueError("physical clone unexpectedly accepted")
        proof = decode((controls / (row["name"] + "-readonly.json")).read_bytes())
        require(proof["status"] == "READONLY_PASS" and proof["before"] == proof["after"] and len(proof["probes"]) == 11
            and all(item["rejected"] is True for item in proof["probes"]) and proof["evidence"] == row, "physical reader custody proof changed")
        actual.append(dict(name=row["name"], rejected=True, changed_files=len(changes)))
    return dict(status="PHYSICAL_READER_CONTROLS_PASS", controls=actual, complete_clone_bytes_checked=True)
