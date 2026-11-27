#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Admit and stage a pinned native bootstrap distribution without compiling it.

F is the frozen Hepta source commit. D is its direct child, adding only the
declared distribution. These checks establish transport/source custody; the
native prebuild still has to rebuild and compare all seven initial roots.
"""
from __future__ import annotations

import argparse
from hashlib import sha1, sha256
import importlib.util
import json
from pathlib import Path
import re
import subprocess


SPEC = importlib.util.spec_from_file_location(
    "hia_native_helper_mcp_integration", Path(__file__).with_name("hia_native_helper_mcp_integration.py"))
custody = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(custody)

PREFIX = "native/bootstrap/linux-x86_64"
ROOT_NAMES = ("hia-seed-assembly", "hia-seed-projector", "hia-seed-backend",
              "hia-seed-filter-pack", "hia-cold-qualification-driver",
              "hia-independent-subprocess", "hia-cold-process-owner")
ENTRY = "hia-cold-build"
REQUIRED_SOURCES = {
    "docs/HIA_NATIVE_SOURCE_AUTHORITY.json",
    "examples/hia_bootstrap/cold_build_sources.hiadat",
    "examples/hia_bootstrap/cold_build_recipe.hiadat",
    "examples/hia_bootstrap/cold_build_entry.hepta",
    "examples/hia_bootstrap/cold_build_entry_packer.hepta",
}
MIB = 1024 * 1024


def relative_name(value):
    custody.require(type(value) is str and len(value) <= 4095
        and re.fullmatch(r"[A-Za-z0-9_./-]+", value) is not None
        and all(part not in {"", ".", "..", ".git", "__pycache__"} for part in value.split("/")),
        "bootstrap distribution contains an unsafe relative path")
    return value


def pin_row(value, maximum, *, executable=False):
    fields = {"path", "bytes", "sha256"} if executable else {"bytes", "sha256"}
    custody.require(type(value) is dict and set(value) == fields
        and type(value.get("bytes")) is int
        and (1 if executable else 0) <= value["bytes"] <= maximum
        and type(value.get("sha256")) is str
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
        and value["sha256"] != "0" * 64, "bootstrap distribution has an invalid file extent or pin")
    return value


def git_tree(root):
    raw = subprocess.check_output(["git", "--no-replace-objects", "-C", str(root),
                                   "ls-tree", "-r", "-z", "HEAD"])
    rows = {}
    for item in raw.split(b"\0"):
        if item:
            metadata, name = item.split(b"\t", 1)
            mode, kind, pin = metadata.split()
            rows[name.decode("utf-8")] = (mode.decode(), kind.decode(), pin.decode())
    return rows


def checked_file(root, name, row, maximum, *, executable=False):
    relative_name(name)
    pin_row(row, maximum, executable=executable)
    raw = custody.ordinary_bytes(root / name, maximum, allow_empty=not executable)
    custody.require(len(raw) == row["bytes"] and sha256(raw).hexdigest() == row["sha256"],
                    "bootstrap distribution file differs from its manifest: " + name)
    return raw


def blob_identity(raw, mode):
    value = sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0")
    value.update(raw)
    return mode, "blob", value.hexdigest()


def admit_distribution(hepta, distribution, expected_source, expected_distribution):
    source = custody.source_identity(hepta, expected_source)
    published = custody.source_identity(distribution, expected_distribution)
    commit = subprocess.check_output(["git", "--no-replace-objects", "-C", str(distribution),
                                      "cat-file", "commit", expected_distribution])
    parents = [line[7:].decode("ascii") for line in commit.split(b"\n\n", 1)[0].splitlines()
               if line.startswith(b"parent ")]
    custody.require(parents == [expected_source],
                    "bootstrap distribution must be a direct child of the frozen source commit")
    source_tree, distribution_tree = git_tree(hepta), git_tree(distribution)
    prefix = PREFIX + "/"
    custody.require(not any(name.startswith(prefix) for name in source_tree)
        and {name: row for name, row in distribution_tree.items() if not name.startswith(prefix)} == source_tree,
        "bootstrap distribution changed files outside its sole added directory")
    root = distribution / PREFIX
    manifest_bytes = custody.ordinary_bytes(root / "manifest.json", MIB)
    manifest = custody.native_json(manifest_bytes)
    custody.require(type(manifest) is dict
        and set(manifest) == {"schema", "target", "source", "source_files", "executables", "evidence"}
        and manifest["schema"] == "hepta.hia.native-bootstrap-distribution.v1"
        and manifest["target"] == "linux-x86_64"
        and manifest["source"] == {"repository": "TrillionniumFoundation/Hepta", **source},
        "bootstrap distribution does not bind this exact frozen source and target")
    source_files, executables, evidence = (manifest[name] for name in ("source_files", "executables", "evidence"))
    custody.require(type(source_files) is dict and REQUIRED_SOURCES <= set(source_files)
        and len(source_files) <= 4096, "bootstrap distribution omits required source authority or entry files")
    custody.require(type(executables) is dict and set(executables) == {*ROOT_NAMES, ENTRY},
                    "bootstrap distribution must contain exactly seven initial roots and one entry")
    custody.require(type(evidence) is dict and 1 <= len(evidence) <= 4096,
                    "bootstrap distribution must retain its original construction evidence")
    contract, sources = custody.admit_hepta_source_contract(hepta)
    custody.require(type(contract.get("native_cold_qualification")) is dict
        and contract["native_cold_qualification"].get("schema") == "hepta.hia.selfhost-cold-replay.v2",
        "bootstrap distribution requires the frozen native source contract")
    authority = custody.native_json(custody.ordinary_bytes(hepta / "docs/HIA_NATIVE_SOURCE_AUTHORITY.json", MIB))
    custody.require(type(authority) is dict and set(authority) == {"schema", "paths"}
        and authority["schema"] == "hepta.hia.native-source-authority.v1"
        and type(authority["paths"]) is list and 1 <= len(authority["paths"]) <= 4096
        and all(type(name) is str for name in authority["paths"])
        and authority["paths"] == sorted(sources),
        "native source authority differs from the complete frozen source contract")
    total_source_bytes = sum((hepta / name).stat().st_size for name in sources)
    custody.require(total_source_bytes <= 2 * 1024 * MIB,
                    "native source export exceeds the public two-GiB capture boundary")
    for name, row in source_files.items():
        custody.require(name in sources, "bootstrap distribution names source outside the frozen native authority")
        checked_file(hepta, name, row, 64 * MIB)
    declared = {"manifest.json": blob_identity(manifest_bytes, "100644")}
    for name, row in executables.items():
        maximum = MIB if name == ENTRY else 64 * MIB
        pin_row(row, maximum, executable=True)
        custody.require(row["path"] == "bin/" + name,
                        "bootstrap executable path differs from its fixed root name")
        raw = checked_file(root, row["path"], row, maximum, executable=True)
        declared[row["path"]] = blob_identity(raw, "100755")
    evidence_bytes = 0
    for name, row in evidence.items():
        relative_name(name)
        custody.require(name != "manifest.json" and name != "bin" and not name.startswith("bin/"),
                        "bootstrap evidence overlaps an executable or its manifest")
        raw = checked_file(root, name, row, 64 * MIB)
        evidence_bytes += len(raw)
        custody.require(evidence_bytes <= 2 * 1024 * MIB,
                        "bootstrap construction evidence exceeds the two-GiB transport boundary")
        declared[name] = blob_identity(raw, "100644")
    actual_files, actual_directories = set(), set()
    for path in root.rglob("*"):
        custody.require(not path.is_symlink(), "bootstrap distribution paths cannot be symbolic links")
        relative = path.relative_to(root).as_posix()
        (actual_directories if path.is_dir() else actual_files).add(relative)
    expected_directories = {parent.as_posix() for name in declared for parent in Path(name).parents
                            if parent != Path(".")}
    custody.require(actual_files == set(declared) and actual_directories == expected_directories,
                    "bootstrap distribution has missing or undeclared files or directories")
    actual_blobs = {prefix + name: row for name, row in declared.items()}
    custody.require(actual_blobs == {name: row for name, row in distribution_tree.items() if name.startswith(prefix)},
                    "bootstrap distribution bytes or executable modes differ from the pinned Git tree")
    binding = {"source": source, "distribution": published,
               "manifest_sha256": sha256(manifest_bytes).hexdigest(), "manifest_bytes": len(manifest_bytes),
               "native_source_count": len(sources), "native_source_bytes": total_source_bytes,
               "source_manifest_sha256": sha256(custody.encoded(sources)).hexdigest(),
               "executables": executables, "evidence": evidence}
    return binding, sources


def stage_distribution(hepta, distribution, expected_source, expected_distribution, output):
    binding, sources = admit_distribution(hepta, distribution, expected_source, expected_distribution)
    custody.require(not output.exists() and not any(path.is_symlink() for path in (output, *output.parents)),
                    "bootstrap staging requires a fresh ordinary output path")
    output.mkdir(mode=0o700)
    (output / "bootstrap").mkdir(mode=0o700)
    (output / "source").mkdir(mode=0o700)
    for name, row in binding["executables"].items():
        maximum = MIB if name == ENTRY else 64 * MIB
        raw = checked_file(distribution / PREFIX, row["path"], row, maximum, executable=True)
        target = output / ENTRY if name == ENTRY else output / "bootstrap" / name
        target.write_bytes(raw)
        target.chmod(0o500)
        custody.require(sha256(custody.ordinary_bytes(target, maximum)).hexdigest() == row["sha256"],
                        "staged bootstrap executable differs from its captured bytes")
    for name, pin in sources.items():
        raw = custody.ordinary_bytes(hepta / name, 64 * MIB, allow_empty=True)
        custody.require(sha256(raw).hexdigest() == pin, "native source changed while staging: " + name)
        target = output / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(raw)
        target.chmod(0o400)
        custody.require(sha256(custody.ordinary_bytes(target, 64 * MIB, allow_empty=True)).hexdigest() == pin,
                        "staged native source differs from its captured bytes")
    following, following_sources = admit_distribution(hepta, distribution, expected_source, expected_distribution)
    custody.require(following == binding and following_sources == sources,
                    "bootstrap distribution or frozen source changed while staging")
    return {**binding, "staged": {"source": str(output / "source"), "bootstrap": str(output / "bootstrap"),
                                 "entry": str(output / ENTRY)}}


def admit_staged_distribution(hepta, distribution, expected_source, expected_distribution, output):
    """Re-admit actual staged bytes from F/D, never from a self-reported receipt."""
    binding, sources = admit_distribution(hepta, distribution, expected_source, expected_distribution)
    output = Path(output).absolute()
    custody.require(not any(path.is_symlink() for path in (output, *output.parents)) and output.is_dir(),
                    "native bootstrap staging must remain an ordinary directory")
    expected = {ENTRY, *("bootstrap/" + name for name in ROOT_NAMES),
                *("source/" + name for name in sources)}
    actual_files, actual_directories = set(), set()
    for path in output.rglob("*"):
        custody.require(not path.is_symlink(), "native bootstrap staging contains a symbolic link")
        relative = path.relative_to(output).as_posix()
        (actual_directories if path.is_dir() else actual_files).add(relative)
    directories = {parent.as_posix() for name in expected for parent in Path(name).parents
                   if parent != Path(".")}
    custody.require(actual_files == expected and actual_directories == directories,
                    "native bootstrap staging has missing or undeclared paths")
    for name, row in binding["executables"].items():
        path = output / ENTRY if name == ENTRY else output / "bootstrap" / name
        raw = custody.ordinary_bytes(path, MIB if name == ENTRY else 64 * MIB)
        custody.require(len(raw) == row["bytes"] and sha256(raw).hexdigest() == row["sha256"]
                        and path.stat().st_mode & 0o7777 == 0o500,
                        "staged native executable differs from its admitted distribution: " + name)
    for name, pin in sources.items():
        path = output / "source" / name
        raw = custody.ordinary_bytes(path, 64 * MIB, allow_empty=True)
        custody.require(sha256(raw).hexdigest() == pin and path.stat().st_mode & 0o7777 == 0o400,
                        "staged native source differs from its frozen source: " + name)
    return {**binding, "staged": {"source": str(output / "source"), "bootstrap": str(output / "bootstrap"),
                                 "entry": str(output / ENTRY)}}, sources


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--distribution", required=True, type=Path)
    parser.add_argument("--expected-hepta-source", required=True)
    parser.add_argument("--expected-distribution", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    report_path = args.report.absolute()
    custody.require(not report_path.exists() and report_path.parent.is_dir()
        and not any(path.is_symlink() for path in (report_path, *report_path.parents)),
        "bootstrap distribution requires a fresh ordinary admission report in an existing directory")
    report = {"schema": "hepta.runtime.native-bootstrap-distribution-admission.v1", "status": "HOLD",
              "scope": "pinned artifact transport and exact source copy; no compiler or seed construction",
              "fresh_native_cold_qualified": False, "whole_native_qualified": False}
    try:
        report["binding"] = stage_distribution(args.hepta.resolve(), args.distribution.resolve(),
            args.expected_hepta_source, args.expected_distribution, args.output.absolute())
        report["status"] = "BOOTSTRAP_DISTRIBUTION_ADMITTED"
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        custody.write_json(report_path, report)
    print(json.dumps({"status": report["status"], "report_sha256": custody.digest(report_path)}, sort_keys=True))


if __name__ == "__main__":
    main()
