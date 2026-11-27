#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify a fixed Runtime/Hepta candidate through real stdio MCP and loopback SSH.

This is an explicitly disposable GitHub-hosted-runner integration. The worker
journal and JSON adapter remain hosted Python; the scalar identity helper and
emitted workload images execute actual HIA machine code. It does not establish
production deployment, unfamiliar-model learning, or net optimization benefit.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha1, sha256
from importlib.machinery import PathFinder
from importlib.util import module_from_spec
import json
import os
from pathlib import Path
import pwd
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback


# Hepta's generate_hia_cold_build_entry.postverify captures each installed tool
# with this bound; the post-cold entry reuses that same native capture path.
# A packed source-builder ELF contains three separately bounded 1 MiB flats,
# so the flat compiler bound is not a bound on the complete executable.
NATIVE_INSTALLED_TOOL_CAPTURE_BYTES = 64 * 1024 * 1024


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    with Path(path).open("w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def record(stream, event):
    stream.write(encoded(event) + b"\n")
    stream.flush()
    os.fsync(stream.fileno())


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(("HEPTA_HIA_", "HIA_TRANSPORT_"))
            and key not in {"PYTHONPATH", "PYTHONHOME"}}


def source_import_inventory(root):
    """Refuse cache/extension shadows and bind importable source to Git bytes."""
    root = root.resolve()
    top = subprocess.check_output(["git", "--no-replace-objects", "-C", str(root),
                                    "ls-tree", "-z", "HEAD"])
    tracked_directories = set()
    for entry in top.split(b"\0"):
        if entry:
            metadata, name = entry.split(b"\t", 1)
            if metadata.split(b" ")[1] == b"tree":
                tracked_directories.add(name.decode("utf-8"))
    subtrees = {"hepta", "tools", "deploy", "tests"}
    for path in root.iterdir():
        if path.name.isidentifier() and path.is_dir():
            require(not path.is_symlink(), "root Python package directories cannot be symbolic links")
            # These build outputs are never inserted as import roots. All new
            # package names and explicit packages can otherwise shadow imports.
            if path.name not in {"target", "build", "dist"}:
                initializer = any(item.name.startswith("__init__.")
                                  and item.suffix.lower() in {".py", ".pyc", ".pyo", ".so", ".pyd"}
                                  for item in path.iterdir())
                if path.name not in tracked_directories or initializer:
                    subtrees.add(path.name)
    entries = subprocess.check_output(["git", "--no-replace-objects", "-C", str(root),
                                       "ls-tree", "-r", "-z", "HEAD", "--", *sorted(subtrees)])
    entries += top
    tracked = {}
    for entry in entries.split(b"\0"):
        if entry:
            metadata, raw_name = entry.split(b"\t", 1)
            mode, kind, blob = metadata.split(b" ")
            name = raw_name.decode("utf-8")
            if kind == b"blob" and name.endswith(".py"):
                require(mode in {b"100644", b"100755"}, "Python source must be a tracked ordinary file")
                tracked[name] = blob.decode("ascii")
    candidates = [path for path in root.iterdir() if not path.is_dir()]
    for name in subtrees:
        directory = root / name
        require(not directory.is_symlink(), "source import directories cannot be symbolic links")
        if directory.is_dir():
            candidates.extend(directory.rglob("*"))
    actual, identities = {}, {}
    for path in candidates:
        require(not path.is_symlink(), "source import paths cannot be symbolic links")
        if path.is_dir():
            continue
        require(path.suffix.lower() not in {".pyc", ".pyo", ".so", ".pyd"},
                "compiled Python cache or extension shadow in source tree: " + str(path.relative_to(root)))
        if path.suffix == ".py":
            name = path.relative_to(root).as_posix()
            raw = path.read_bytes()
            actual[name] = sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            identities[name] = sha256(raw).hexdigest()
    require(actual == tracked, "importable Python source differs from the selected Git commit")
    return {"files": len(identities), "source_sha256": sha256(encoded(identities)).hexdigest()}


def prepare_source_imports(roots, cache):
    require(sys.flags.isolated == 1 and sys.dont_write_bytecode is True,
            "joint qualification and consumer require Python -I -B")
    require(not any(name in {"hepta", "tools", "hia_mcp_catalog"}
                    or name.startswith(("hepta.", "tools.")) for name in sys.modules),
            "repository Python modules were loaded before source admission")
    inventories = [source_import_inventory(root) for root in roots]
    # -B prevents writes but still reads timestamp-valid bytecode. A fresh
    # private prefix also prevents reuse of caches outside the selected trees.
    cache.mkdir(mode=0o700)
    sys.pycache_prefix = str(cache.resolve())
    # The first root is the explicitly selected Hepta checkout. Runtime's
    # tools directory is inventoried too, but never becomes a tools fallback.
    tool_root = roots[0].resolve()
    if (tool_root / "tools").is_dir() and not (tool_root / "tools/__init__.py").exists():
        # A later regular site package beats an earlier namespace directory in
        # Python's default search. Select this namespace before any tool code.
        spec = PathFinder.find_spec("tools", [str(tool_root)])
        require(spec is not None and spec.loader is None
                and list(spec.submodule_search_locations or []) == [str(tool_root / "tools")],
                "selected tools namespace differs from the admitted source")
        sys.modules["tools"] = module_from_spec(spec)
    return inventories


def source_identity(root, expected):
    require(re.fullmatch(r"[0-9a-f]{40}", expected) is not None,
            "source identity must be a complete commit")
    actual = subprocess.check_output(["git", "--no-replace-objects", "-C", str(root), "rev-parse", "HEAD"],
                                     text=True).strip()
    require(actual == expected, "checked-out source differs from the frozen candidate")
    dirty = subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
        text=True)
    require(not dirty, "tracked source changed during qualification")
    tree = subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True).strip()
    source_import_inventory(root)
    return {"commit": actual, "tree": tree}


def admit_hepta_source_contract(hepta):
    """Bind the complete source closure to actual files and immutable Git blobs."""
    contract_name = "docs/HIA_SELFHOST_CORE_SUPPORT.json"
    contract_bytes = ordinary_bytes(hepta / contract_name, 64 * 1024 * 1024)
    contract = json.loads(contract_bytes)
    require(type(contract) is dict
            and contract.get("schema") == "hepta.hia.selfhost-core-support.v1"
            and type(contract.get("profile")) is str
            and type(contract.get("source_identity")) is dict
            and type(contract["source_identity"].get("files")) is dict
            and bool(contract["source_identity"]["files"]),
            "selected Hepta source contract is incomplete")
    sources = dict(contract["source_identity"]["files"])
    require(contract_name not in sources, "source contract cannot recursively pin itself")
    sources[contract_name] = sha256(contract_bytes).hexdigest()
    actual_blobs = {}
    for name, expected in sources.items():
        require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_./-]+", name) is not None
                and not name.startswith("/")
                and all(part not in {"", ".", ".."} for part in name.split("/"))
                and type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
                "selected Hepta source contract contains an invalid source identity")
        raw = ordinary_bytes(hepta / name, 64 * 1024 * 1024, allow_empty=True)
        require(sha256(raw).hexdigest() == expected,
                "selected Hepta file differs from its source contract: " + name)
        actual_blobs[name] = sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    # Git status deliberately trusts assume-unchanged/skip-worktree entries.
    # Compare the actual source closure with the selected immutable Git objects.
    tree = subprocess.check_output(["git", "--no-replace-objects", "-C", str(hepta),
                                    "ls-tree", "-r", "-z", "HEAD", "--", *sorted(sources)])
    expected_blobs = {}
    for entry in tree.split(b"\0"):
        if entry:
            metadata, name = entry.split(b"\t", 1)
            mode, kind, blob = metadata.split(b" ")
            require(mode in {b"100644", b"100755"} and kind == b"blob",
                    "selected Hepta source closure must contain tracked ordinary files")
            expected_blobs[name.decode("ascii")] = blob.decode("ascii")
    require(actual_blobs == expected_blobs,
            "actual Hepta source closure differs from its selected Git commit")
    return contract, sources


def admit_cold_compiler(hepta, cold_report):
    """Admit the retained hosted-v1 domain without treating native-v2 as v1."""
    contract, sources = admit_hepta_source_contract(hepta)
    contract_name = "docs/HIA_SELFHOST_CORE_SUPPORT.json"

    cold_bytes = cold_report.read_bytes()
    cold = json.loads(cold_bytes)
    required_checks = {
        "export_manifest_matches_qualification", "isolated_python_without_site",
        "nested_full_qualification_pass", "nested_process_exit_zero", "no_ancestor_git_identity",
        "no_bytecode_cache_created", "no_inherited_home_or_python_cache",
        "no_inherited_seed_or_successor_images", "origin_hashes_preserved",
        "owned_process_tree_cleanup_confirmed", "source_export_hashes_preserved"}
    require(type(cold) is dict and cold.get("schema") == "hepta.hia.selfhost-cold-replay.v1"
            and cold.get("status") == "COLD_SELFHOST_REPLAY_PASS"
            and type(cold.get("returncode")) is int and cold["returncode"] == 0
            and cold.get("qualification_wall_limit_seconds") == 180
            and cold.get("cleanup_wall_limit_seconds") == 3
            and type(cold.get("checks")) is dict and set(cold["checks"]) == required_checks
            and all(value is True for value in cold["checks"].values()),
            "unchanged-budget cold qualification is incomplete; native integration remains HOLD")
    require(cold.get("profile") == contract["profile"] and cold.get("source_manifest") == sources,
            "cold qualification belongs to different Hepta source or support profile")
    cold_directory = cold_report.resolve().with_suffix(".cold")
    nested_path = Path(cold["nested_report"]).resolve()
    require(nested_path.is_relative_to(cold_directory),
            "cold report does not name its own source-only qualification")
    nested_bytes = nested_path.read_bytes()
    require(sha256(nested_bytes).hexdigest() == cold["nested_report_sha256"],
            "cold nested report drifted")
    nested = json.loads(nested_bytes)
    require(type(nested) is dict and nested.get("schema") == "hepta.hia.selfhost-qualification.v6"
            and nested.get("status") == "SELF_HOSTED_FIXED_CORE_PASS"
            and nested.get("profile") == contract["profile"] and nested.get("source_manifest") == sources
            and type(nested.get("generations")) is list and len(nested["generations"]) == 3,
            "cold nested qualification belongs to different source or an incomplete generation chain")
    compiler = Path(nested["generations"][-1]["produced_image"]).resolve()
    require(compiler.is_relative_to(cold_directory),
            "B3 must come from the original cold qualification")
    compiler_sha = digest(compiler)
    require(cold.get("generation_sha256") == [compiler_sha] * 3
            and all(row.get("produced_sha256") == compiler_sha for row in nested["generations"]),
            "cold compiler bytes differ from the retained fixed-point generation chain")
    binding = {"profile": contract["profile"], "source_manifest_sha256": sha256(encoded(sources)).hexdigest(),
               "support_contract_sha256": sources[contract_name], "compiler_sha256": compiler_sha,
               "nested_report_sha256": cold["nested_report_sha256"]}
    return compiler, cold_bytes, binding


def ordinary_bytes(path, maximum, *, single_link=True, allow_empty=False):
    """Read a bounded ordinary file without following any symlink."""
    path = Path(path).absolute()
    require(not any(part.is_symlink() for part in (path, *path.parents)),
            "native receipt paths cannot contain symbolic links")
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and (not single_link or before.st_nlink == 1)
            and (0 if allow_empty else 1) <= before.st_size <= maximum,
            "native receipt file type or extent differs from its bounded contract")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                "native receipt file changed while opening")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                              value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    require(len(raw) == before.st_size and identity(before) == identity(after)
            == identity(path.stat(follow_symlinks=False)),
            "native receipt file changed while reading")
    return raw


def native_file_manifest(raw):
    """Decode exact HIASXM01 bytes; this is custody readback, not execution proof."""
    require(len(raw) >= 32 and raw[:8] == b"HIASXM01",
            "native file manifest has an invalid header")
    count, version, reserved = struct.unpack_from("<3Q", raw, 8)
    require(version == 1 and reserved == 0 and 1 <= count <= 4096,
            "native file manifest has an invalid count or version")
    rows, cursor, previous = {}, 32, b""
    for _ in range(count):
        require(cursor + 48 <= len(raw), "native file manifest record is truncated")
        extent, size = struct.unpack_from("<2Q", raw, cursor)
        pin = raw[cursor + 16:cursor + 48].hex()
        cursor += 48
        require(1 <= extent <= 4095 and cursor + extent <= len(raw)
                and size <= 64 * 1024 * 1024 and pin != "0" * 64,
                "native file manifest record has an invalid bound or digest")
        name = raw[cursor:cursor + extent]
        require(re.fullmatch(rb"[A-Za-z0-9_./-]+", name) is not None
                and all(part not in {b"", b".", b"..", b".git", b"__pycache__"}
                        for part in name.split(b"/")) and name > previous,
                "native file manifest paths must be safe, unique and sorted")
        rows[name.decode("ascii")] = {"bytes": size, "sha256": pin}
        previous, cursor = name, cursor + extent
    require(cursor == len(raw), "native file manifest contains trailing bytes")
    return rows


def native_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "native JSON receipt contains a duplicate key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise RuntimeError("native JSON receipt contains a non-JSON number: " + value)

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def admit_native_cold_compiler(hepta, cold_report, source_bootstrap):
    """Read back the actual source-bound native post-cold admission outputs.

    The workflow executes hia-source-bootstrap before this observer. Its HIA
    recipe owns the strict sixty-phase report admission and compiler use. These
    retained files bind that operation to this source, report, B3 and installer;
    synthetic unit fixtures exercise only this external custody reader.
    """
    contract, sources = admit_hepta_source_contract(hepta)
    native = contract.get("native_cold_qualification")
    require(type(native) is dict and native.get("schema") == "hepta.hia.selfhost-cold-replay.v2",
            "native integration requires the selected native-v2 source contract")
    cold_bytes = ordinary_bytes(cold_report, 64 * 1024 * 1024)
    cold = native_json(cold_bytes)
    require(cold_report.name == "final-cold.json" and type(cold) is dict
            and cold.get("schema") == "hepta.hia.selfhost-cold-replay.v2"
            and cold.get("status") == "NATIVE_COLD_SELFHOST_REPLAY_PASS"
            and type(cold.get("returncode")) is int and cold["returncode"] == 0
            and type(cold.get("qualification_wall_limit_seconds")) is int
            and cold["qualification_wall_limit_seconds"] == 180
            and type(cold.get("cleanup_wall_limit_seconds")) is int
            and cold["cleanup_wall_limit_seconds"] == 3
            and type(cold.get("checks")) is dict and len(cold["checks"]) == 14
            and set(cold["checks"]) == set(native.get("checks", []))
            and all(value is True for value in cold["checks"].values()),
            "unchanged-budget native cold qualification is incomplete; integration remains HOLD")
    require(cold.get("profile") == contract["profile"] and cold.get("source_manifest") == sources,
            "native cold qualification belongs to different Hepta source or support profile")
    compiler = cold_report.parent / "qualification/base/B3.flat"
    compiler_sha = sha256(ordinary_bytes(compiler, 1024 * 1024)).hexdigest()
    require(cold.get("generation_sha256") == [compiler_sha] * 3,
            "native compiler differs from the retained cold fixed-point chain")
    receipt = ordinary_bytes(source_bootstrap / "build.receipt", 128)
    require(len(receipt) == 128 and receipt[:8] == b"HIASBOK1",
            "native post-cold public receipt is absent or belongs to another domain")
    version, stages, source_count, tool_count, source_size, tool_size, reserved = struct.unpack_from(
        "<7Q", receipt, 8)
    require(version == 1 and 1 <= stages <= 64 and reserved == 0
            and source_count == len(sources) and 1 <= tool_count <= 4096,
            "native post-cold receipt counts or version differ")
    source_raw = ordinary_bytes(source_bootstrap / "source.manifest.hiasxm", 1024 * 1024)
    tool_raw = ordinary_bytes(source_bootstrap / "toolchain.manifest.hiasxm", 1024 * 1024)
    require((len(source_raw), len(tool_raw)) == (source_size, tool_size)
            and sha256(source_raw).digest() == receipt[64:96]
            and sha256(tool_raw).digest() == receipt[96:128],
            "native post-cold receipt does not bind its retained manifests")
    source_rows, tool_rows = native_file_manifest(source_raw), native_file_manifest(tool_raw)
    require(source_rows == {name: {"bytes": (hepta / name).stat().st_size, "sha256": pin}
                            for name, pin in sources.items()},
            "native post-cold source manifest differs from the selected Git source")
    expected_tools = {"cold-inputs.receipt", "hia-source-build", "hia-release-owner",
                      "hia-subprocess", "hia-source-capture", "hia-release-build",
                      "hia-source-bootstrap", "hia-release"}
    require(set(tool_rows) == expected_tools and len(tool_rows) == tool_count,
            "native post-cold installed tool inventory differs")
    for name, row in tool_rows.items():
        raw = ordinary_bytes(source_bootstrap / name, NATIVE_INSTALLED_TOOL_CAPTURE_BYTES)
        require(len(raw) == row["bytes"] and sha256(raw).hexdigest() == row["sha256"],
                "native post-cold installed tool differs from its receipt: " + name)
    inputs = ordinary_bytes(source_bootstrap / "cold-inputs.receipt", 120)
    expected = (b"HIASBIN1" + bytes.fromhex(compiler_sha) + sha256(cold_bytes).digest()
                + b"HIAADC01" + bytes.fromhex(compiler_sha) + struct.pack("<Q", len(sources)))
    require(inputs == expected,
            "native post-cold admission does not bind this report, B3 and source count")
    binding = {"profile": contract["profile"], "compiler_sha256": compiler_sha,
               "source_manifest_sha256": sha256(encoded(sources)).hexdigest(),
               "support_contract_sha256": sources["docs/HIA_SELFHOST_CORE_SUPPORT.json"],
               "cold_report_sha256": sha256(cold_bytes).hexdigest(),
               "admission_domain": "native-v2-post-cold-HIAADC01",
               "post_cold_build_receipt_sha256": sha256(receipt).hexdigest(),
               "post_cold_source_manifest_sha256": sha256(source_raw).hexdigest(),
               "post_cold_tool_manifest_sha256": sha256(tool_raw).hexdigest(),
               "post_cold_inputs_receipt_sha256": sha256(inputs).hexdigest(),
               "native_installer_sha256": tool_rows["hia-release"]["sha256"]}
    return compiler, cold_bytes, binding


def native_execution_observer():
    """Load this Runtime's independently inventoried external trace reader."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "selected_runtime_native_execution_trace", Path(__file__).with_name("hia_native_execution_trace.py"))
    observer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observer)
    return observer


def admit_native_execution_observations(source, cold_report, source_bootstrap,
                                       cold_execution, post_execution):
    """Require original traced cold/post executions before using their products."""
    require(cold_execution is not None and post_execution is not None,
            "native qualification requires retained cold and post execution observations")
    observer = native_execution_observer()
    return {
        "cold": observer.admit_execution(cold_execution, source=source, stage="cold",
            expected_result=cold_report, owner_receipt=cold_report.parent / "process-owner.receipt"),
        "post": observer.admit_execution(post_execution, source=source, stage="post",
            expected_result=source_bootstrap / "build.receipt",
            owner_receipt=source_bootstrap / "process-owner.receipt")}


def native_release_identity(hepta, source_bootstrap, package, finalize_receipt, output, binding):
    """Install and independently verify the formal source-bound native package."""
    # The finalizer intentionally retains three links to its published package.
    # Capture the bytes and identity; do not impose the single-link input rule
    # used by the post-cold manifests and installed helper files on this output.
    package_bytes = ordinary_bytes(package, 256 * 1024 * 1024, single_link=False)
    package_sha = sha256(package_bytes).hexdigest()
    finalize_bytes = ordinary_bytes(finalize_receipt, 4096)
    finalize = native_json(finalize_bytes)
    require(type(finalize) is dict
            and set(finalize) == {"schema", "sha256", "bytes", "files", "published", "source_attested"}
            and finalize["schema"] == "hepta.hia.release-finalize.v1"
            and finalize["sha256"] == package_sha and type(finalize["bytes"]) is int
            and finalize["bytes"] == len(package_bytes)
            and type(finalize["files"]) is int and 1 <= finalize["files"] <= 384
            and finalize["published"] is True and finalize["source_attested"] is True,
            "native release package lacks its exact complete source-attested publication receipt")
    installer = source_bootstrap / "hia-release"
    require(sha256(ordinary_bytes(installer, NATIVE_INSTALLED_TOOL_CAPTURE_BYTES)).hexdigest()
            == binding["native_installer_sha256"],
            "native release installer changed after post-cold admission")
    installed_root = output / "installed-release"
    installed_root.mkdir(mode=0o700)
    receipts = {}
    for operation in ("install", "verify"):
        result = subprocess.run([str(installer), operation, str(installed_root), package_sha],
                                input=package_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={"PATH": "", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}, timeout=180)
        (output / ("release-" + operation + ".stdout.json")).write_bytes(result.stdout)
        (output / ("release-" + operation + ".stderr.log")).write_bytes(result.stderr)
        require(result.returncode == 0, "native release " + operation + " did not complete")
        receipt = native_json(result.stdout)
        require(type(receipt) is dict and type(receipt.get("files")) is int
                and type(receipt.get("bytes")) is int and type(receipt.get("published")) is bool
                and receipt == {"schema": "hepta.hia.release-install.v1", "sha256": package_sha,
                            "files": finalize["files"], "bytes": len(package_bytes),
                            "published": operation == "install"},
                "native release " + operation + " receipt differs from the actual package")
        receipts[operation] = receipt
    release = installed_root / package_sha
    manifest = release / "agent-identity-manifest.json"
    manifest_bytes = ordinary_bytes(manifest, 4096)
    value = native_json(manifest_bytes)
    image_sha = sha256(ordinary_bytes(release / "agent-identity.image.bin", 1024 * 1024)).hexdigest()
    require(value == {"schema": "hepta.hia.agent-identity-native.v1",
                      "source_sha256": digest(hepta / "examples/hia_bootstrap/agent_identity.hepta"),
                      "image_path": "agent-identity.image.bin", "image_sha256": image_sha,
                      "compiler_sha256": binding["compiler_sha256"]},
            "formal release identity helper differs from the selected source or admitted B3")
    record = {"schema": "hepta.runtime.native-release-readback.v1", "status": "NATIVE_RELEASE_READBACK_PASS",
              "package_sha256": package_sha, "package_bytes": len(package_bytes),
              "finalize_receipt_sha256": sha256(finalize_bytes).hexdigest(),
              "finalize": finalize, "native_installer_sha256": binding["native_installer_sha256"],
              "installation": receipts, "manifest": value,
              "manifest_sha256": sha256(manifest_bytes).hexdigest(), "production_activated": False,
              "whole_agent_protocol_and_persistence_replaced": False, "whole_stack_rewritten_in_hia": False}
    return manifest, record


def consumer_main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--import-cache", type=Path, required=True)
    args = parser.parse_args(argv)
    prepare_source_imports([args.hepta], args.import_cache)
    sys.path.insert(0, str(args.hepta))
    from hepta.hia_native_helpers import native_helpers_scope
    from hepta.hia_agent_service import HIAAgentService
    with native_helpers_scope(str(args.bundle), args.bundle_sha256):
        service = HIAAgentService(args.state_root, artifact_roots=[args.artifact_root])
        try:
            for raw in sys.stdin.buffer:
                request = json.loads(raw)
                try:
                    action = request["action"]
                    if action == "probe":
                        from hepta.hia_agent_identity_native import installed_agent_identity
                        image = installed_agent_identity(os.environ["HEPTA_HIA_AGENT_IDENTITY_MANIFEST"])
                        result = {"u64_max": image.uint64("18446744073709551615"),
                                  "u64_overflow": image.uint64("18446744073709551616"),
                                  "lowercase_digest": image.digest("a" * 64),
                                  "uppercase_digest": image.digest("A" * 64),
                                  "installation": service.identities}
                    elif action == "acquire":
                        result = service.acquire_slot(request["slot"])
                    elif action == "invoke":
                        result = service.invoke_lease(request["lease"], "transform", [9])
                    elif action == "release":
                        result = service.release_slot(request["lease"])
                    elif action == "inspect":
                        result = service.inspect_slot(request["slot"])
                    elif action == "exit":
                        break
                    else:
                        raise ValueError("unknown consumer action")
                    response = {"ok": True, "result": result}
                except Exception as exc:
                    response = {"ok": False, "error": {"type": type(exc).__name__,
                                "code": getattr(exc, "code", None), "message": str(exc)}}
                sys.stdout.buffer.write(encoded(response) + b"\n")
                sys.stdout.buffer.flush()
        finally:
            service.close()


class Consumer:
    def __init__(self, command, *, cwd, env, output, journal):
        self.log = (output / "consumer.stderr.log").open("xb")
        self.process = subprocess.Popen(command, cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
            bufsize=0, start_new_session=True)
        self.pending = b""
        self.journal = journal

    def call(self, action, **arguments):
        request = {"action": action, **arguments}
        record(self.journal, {"phase": "consumer_intent", "request": request})
        self.process.stdin.write(encoded(request) + b"\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 30
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "consumer observation timed out; preserve the original lease")
            ready, _, _ = select.select([self.process.stdout], [], [], min(remaining, 1))
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 65536)
                require(bool(chunk), "consumer exited without a complete response")
                self.pending += chunk
                require(len(self.pending) <= 1024 * 1024, "consumer response exceeds bound")
            elif self.process.poll() is not None:
                raise RuntimeError("consumer exited before its response")
        line, self.pending = self.pending.split(b"\n", 1)
        response = json.loads(line)
        record(self.journal, {"phase": "consumer_response",
                             "request": request, "response": response})
        return response

    def result(self, action, **arguments):
        response = self.call(action, **arguments)
        require(response["ok"] is True, "consumer rejected: " + json.dumps(response))
        return response["result"]

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write(encoded({"action": "exit"}) + b"\n")
            self.process.stdin.flush()
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=10)
        self.log.close()


class DisposableSSH:
    """Own only this runner's temporary agent, localhost daemon and host-key entry."""

    def __init__(self, private, output, environment):
        self.private = private
        self.output = output
        self.env = dict(environment)
        self.agent = self.daemon = None
        self.streams = []
        self.known = None
        self.known_before = None
        self.known_after = None
        self.known_mode = None
        self.created_ssh_dir = False
        self.linger_enabled_here = False
        self.commands = []

    def run(self, argv, *, timeout=30, check=True):
        result = subprocess.run([str(x) for x in argv], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        event = {"argv": [str(x) for x in argv], "returncode": result.returncode,
                 "stdout": result.stdout.decode("utf-8", "replace"),
                 "stderr": result.stderr.decode("utf-8", "replace")}
        self.commands.append(event)
        write_json(self.output / "ssh-setup.json", self.commands)
        if check:
            require(result.returncode == 0, "disposable SSH setup failed: " + json.dumps(event))
        return result

    def start(self):
        user = pwd.getpwuid(os.getuid())
        require(user.pw_uid != 0, "the integration requires a non-root runner identity")
        for name in ("client_key", "host_key"):
            self.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                      "-f", self.private / name])
        authorized = self.private / "authorized_keys"
        authorized.write_bytes((self.private / "client_key.pub").read_bytes())
        authorized.chmod(0o600)
        with socket.socket() as bound:
            bound.bind(("127.0.0.1", 0))
            self.port = bound.getsockname()[1]
        self.target = "ssh://" + user.pw_name + "@127.0.0.1:" + str(self.port)

        ssh_dir = Path(user.pw_dir) / ".ssh"
        require(not ssh_dir.is_symlink(), "refuse a linked SSH configuration directory")
        if not ssh_dir.exists():
            ssh_dir.mkdir(mode=0o700)
            self.created_ssh_dir = True
        self.known = ssh_dir / "known_hosts"
        require(not self.known.is_symlink(), "refuse a linked known_hosts file")
        if self.known.exists():
            require(stat.S_ISREG(self.known.stat().st_mode), "known_hosts must be a regular file")
            self.known_before = self.known.read_bytes()
            self.known_mode = stat.S_IMODE(self.known.stat().st_mode)
        original = self.known_before or b""
        hostkey = (self.private / "host_key.pub").read_text().split()
        entry = ("[127.0.0.1]:" + str(self.port) + " " + " ".join(hostkey[:2]) + "\n").encode()
        self.known_after = original + (b"\n" if original and not original.endswith(b"\n") else b"") + entry
        self.known.write_bytes(self.known_after)
        self.known.chmod(0o600)

        agent_log = (self.output / "ssh-agent.log").open("xb")
        self.streams.append(agent_log)
        self.env["SSH_AUTH_SOCK"] = str(self.private / "agent.sock")
        self.env.pop("SSH_AGENT_PID", None)
        self.agent = subprocess.Popen(
            ["ssh-agent", "-D", "-a", self.env["SSH_AUTH_SOCK"]],
            stdout=agent_log, stderr=subprocess.STDOUT, env=self.env)
        deadline = time.monotonic() + 10
        while not Path(self.env["SSH_AUTH_SOCK"]).exists():
            require(self.agent.poll() is None and time.monotonic() < deadline,
                    "disposable ssh-agent did not start")
            time.sleep(0.05)
        self.run(["ssh-add", self.private / "client_key"])

        linger = self.run(["loginctl", "show-user", user.pw_name, "-p", "Linger", "--value"],
                          check=False)
        if linger.returncode != 0 or linger.stdout.strip() != b"yes":
            self.run(["sudo", "-n", "loginctl", "enable-linger", user.pw_name])
            self.linger_enabled_here = True
        self.run(["sudo", "-n", "systemctl", "start", "user@" + str(user.pw_uid) + ".service"])
        self.run(["sudo", "-n", "mkdir", "-p", "/run/sshd"])

        config = self.private / "sshd_config"
        config.write_text("\n".join([
            "Port " + str(self.port), "ListenAddress 127.0.0.1",
            "HostKey " + str(self.private / "host_key"),
            "AuthorizedKeysFile " + str(authorized),
            "PidFile " + str(self.private / "sshd.pid"),
            "AllowUsers " + user.pw_name, "PermitRootLogin no",
            "PasswordAuthentication no", "KbdInteractiveAuthentication no",
            "PubkeyAuthentication yes", "AuthenticationMethods publickey",
            "UsePAM yes", "StrictModes yes", "AllowTcpForwarding no",
            "AllowAgentForwarding no", "X11Forwarding no", "PermitTunnel no",
            "LogLevel VERBOSE", "PrintMotd no", "PrintLastLog no", "UseDNS no",
        ]) + "\n")
        self.run(["sudo", "-n", "/usr/sbin/sshd", "-t", "-f", config])
        daemon_log = (self.output / "sshd.log").open("xb")
        self.streams.append(daemon_log)
        self.daemon = subprocess.Popen(
            ["sudo", "-n", "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
            stdout=daemon_log, stderr=subprocess.STDOUT, env=self.env,
            start_new_session=True)
        deadline = time.monotonic() + 10
        while True:
            require(self.daemon.poll() is None and time.monotonic() < deadline,
                    "disposable sshd did not listen")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        self.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                  "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
                  self.target, "/usr/bin/true"])
        # Exercise the same user-systemd resource controls required by the
        # existing owner, without enabling its detached fallback.
        unit = "hia-integration-probe-" + str(user.pw_uid) + "-" + str(self.port)
        probe = ("env XDG_RUNTIME_DIR=/run/user/" + str(user.pw_uid)
                 + " DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + str(user.pw_uid)
                 + "/bus /usr/bin/systemd-run --user --quiet --collect --wait --unit="
                 + unit + " --property=CPUQuota=100% --property=MemoryMax=67108864"
                 + " /usr/bin/true")
        self.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                  "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
                  self.target, probe])
        return self

    def close(self):
        errors = []
        for process, privileged in ((self.daemon, True), (self.agent, False)):
            if process is not None and process.poll() is None:
                try:
                    if privileged:
                        self.run(["sudo", "-n", "/bin/kill", "-TERM", str(process.pid)])
                    else:
                        process.terminate()
                    process.wait(timeout=10)
                except Exception as exc:
                    errors.append(type(exc).__name__ + ": " + str(exc))
        if self.daemon is not None and self.daemon.poll() is not None:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    errors.append("the disposable SSH listener still accepts connections")
            except OSError:
                pass
        if self.known_after is not None:
            if self.known.exists() and self.known.read_bytes() == self.known_after:
                if self.known_before is None:
                    self.known.unlink()
                else:
                    self.known.write_bytes(self.known_before)
                    self.known.chmod(self.known_mode)
            else:
                errors.append("known_hosts changed outside this test; preserved instead of overwriting")
        if self.created_ssh_dir:
            try:
                self.known.parent.rmdir()
            except OSError:
                pass
        if self.linger_enabled_here:
            result = self.run(["sudo", "-n", "loginctl", "disable-linger",
                               pwd.getpwuid(os.getuid()).pw_name], check=False)
            if result.returncode:
                errors.append("unable to restore the runner's original linger setting")
        for stream in self.streams:
            stream.close()
        return errors


def generic_call(transport, name, arguments, journal):
    record(journal, {"phase": "owner_intent", "tool": name, "arguments": arguments})
    result = transport.rpc("tools/call", {"name": name, "arguments": arguments})
    record(journal, {"phase": "owner_response", "tool": name, "result": result})
    require(result.get("isError") is not True, "owner tool rejected " + name + ": " + json.dumps(result))
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    for item in result.get("content", []):
        if item.get("type") == "text":
            try:
                value = json.loads(item["text"])
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    raise RuntimeError("owner tool returned no complete JSON observation")


def job_ids(transport, journal):
    result = generic_call(transport, "process_list", {"host": "loopback"}, journal)
    require(result.get("inventory_complete") is True, "job inventory was incomplete")
    return sorted(job["id"] for job in result["jobs"])


def invocation_matches(result, lease):
    require(result.get("status") == "returned" and result.get("values") == [16]
            and result.get("termination_confirmed") is True
            and result.get("generation") == lease["generation"]
            and result.get("artifact") == lease["artifact"],
            "native consumer did not execute the exact retained generation")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--expected-runtime-source", required=True)
    parser.add_argument("--expected-hepta-source", required=True)
    parser.add_argument("--cold-report", type=Path, required=True)
    parser.add_argument("--native-source-bootstrap", type=Path)
    parser.add_argument("--cold-execution", type=Path)
    parser.add_argument("--post-execution", type=Path)
    parser.add_argument("--release-execution", type=Path)
    parser.add_argument("--native-release-package", type=Path)
    parser.add_argument("--native-release-receipt", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-disposable-sshd", action="store_true")
    args = parser.parse_args(argv)
    native_arguments = (args.native_source_bootstrap, args.native_release_package, args.native_release_receipt)
    require(all(native_arguments) or not any(native_arguments),
            "native integration requires its complete post-cold, package and publication inputs")
    require(sys.flags.isolated == 1 and sys.dont_write_bytecode is True,
            "joint qualification requires Python -I -B")
    require(args.allow_disposable_sshd and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "this test requires an explicitly authorized disposable GitHub-hosted runner")
    require(sys.platform == "linux" and os.uname().machine == "x86_64",
            "the selected image contract is Linux x86_64 LP64")
    os.umask(0o077)
    output = args.output.resolve()
    require(output.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()),
            "evidence must live in this runner's temporary directory")
    output.mkdir(mode=0o700)
    private = output.with_name(output.name + ".private")
    private.mkdir(mode=0o700)
    report = {"schema": "hepta.runtime.hia-native-helper-integration.v1",
              "status": "STARTED", "checks": {}, "transport_sessions": [],
              "scope": {"transport": "actual_stdio_mcp_to_existing_owner_over_loopback_openssh",
                        "native_helpers": ["HEPTA_HIA_AGENT_IDENTITY_MANIFEST"],
                        "worker_json_and_journal": "hosted_python",
                        "production_deployed": False,
                        "whole_worker_native": False,
                        "fresh_model_learning_test": False,
                        "net_optimization_benefit_proved": False}}
    journal = (output / "calls.jsonl").open("xb")
    ssh = transport = consumer = client = None
    config_path = None
    cleanup_errors = []
    started = time.monotonic_ns()
    env = clean_environment()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    runtime = args.runtime.resolve()
    hepta = args.hepta.resolve()
    runtime_source = args.runtime_source.resolve()
    state_root = private / "worker-state"
    inputs = output / "inputs"
    inputs.mkdir(mode=0o700)

    def save():
        report["elapsed_ns"] = str(time.monotonic_ns() - started)
        if client is not None:
            report["calls"] = client.records
        write_json(output / "report.json", report)

    def close_transport():
        nonlocal transport
        if transport is not None:
            report["transport_sessions"].append({
                "initialize": transport.initialized, "protocol": transport.protocol_records,
                "stderr": transport.stderr()})
            transport.close()
            transport = None
            save()

    def open_transport(config_path):
        check_import_sources()
        from tools.hia_agent_native_transport import MCPStdio
        return MCPStdio([str(runtime), "mcp", "--path", str(output),
                         "--runtime-config", str(config_path)],
                        cwd=runtime_source, env=ssh.env, timeout=180)

    def check_import_sources():
        observed = [source_import_inventory(root) for root in (hepta, runtime_source)]
        require(observed == report["python_source_imports"],
                "Python import sources changed during qualification")

    def checked_call(tool, arguments):
        check_import_sources()
        response = transport.call(tool, arguments)
        check_import_sources()
        return response

    try:
        save()
        report["sources"] = {
            "runtime": source_identity(runtime_source, args.expected_runtime_source),
            "hepta": source_identity(hepta, args.expected_hepta_source)}
        report["runtime_binary_sha256"] = digest(runtime)
        report["client_sha256"] = digest(__file__)
        report["python"] = {"executable": sys.executable, "version": sys.version}
        report["python_source_imports"] = prepare_source_imports(
            [hepta, runtime_source], private / "qualification-import-cache")
        sys.path.insert(0, str(hepta))
        from tools.hia_agent_native_qualification import ToolClient, Session, scripted_loop, campaign_binding
        if args.native_source_bootstrap is not None:
            compiler, cold_bytes, report["cold_source_binding"] = admit_native_cold_compiler(
                hepta, args.cold_report, args.native_source_bootstrap)
            report["native_execution_observations"] = admit_native_execution_observations(
                args.expected_hepta_source, args.cold_report, args.native_source_bootstrap,
                args.cold_execution, args.post_execution)
            require(args.release_execution is not None and args.native_release_receipt is not None
                    and args.native_release_receipt.absolute()
                    == (args.release_execution / "stdout").absolute(),
                    "native release requires its retained original execution observation")
            report["native_execution_observations"]["release"] = native_execution_observer().admit_execution(
                args.release_execution, source=args.expected_hepta_source, stage="release")
            manifest, report["native_build"] = native_release_identity(
                hepta, args.native_source_bootstrap, args.native_release_package,
                args.native_release_receipt, output, report["cold_source_binding"])
        else:
            compiler, cold_bytes, report["cold_source_binding"] = admit_cold_compiler(hepta, args.cold_report)
            from tools.build_hia_agent_identity import build
            manifest = build(output / "native-helper", compiler, args.cold_report.resolve())
            report["native_build"] = json.loads((manifest.parent / "build.json").read_bytes())
        bundle = output / "native-helpers.json"
        write_json(bundle, {"schema": "hepta.hia.native-helpers.v1",
            "target": "linux-x86_64-lp64", "abi": "hia-byte-six-argument-v1",
            "helpers": [{"selector": "HEPTA_HIA_AGENT_IDENTITY_MANIFEST",
                         "manifest_path": str(manifest), "manifest_sha256": digest(manifest)}]})
        bundle_sha = digest(bundle)
        worker_command = [sys.executable, "-B", "-E", "-s", "-m", "hepta.hia_agent_worker",
            "--installation-manifest", "--native-helpers-manifest", str(bundle),
            "--expected-native-helpers-sha256", bundle_sha]
        installed = subprocess.run(worker_command, cwd=hepta, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        (output / "installation.stdout.json").write_bytes(installed.stdout)
        (output / "installation.stderr.log").write_bytes(installed.stderr)
        require(installed.returncode == 0, "real worker rejected the installed native helper")
        pins = json.loads(installed.stdout)
        require(pins["native_helpers_sha256"] == bundle_sha, "installation omitted selected helper")
        require(pins["catalog_sha256"] == digest(hepta / "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json")
                == digest(runtime_source / "src/mcp/hia_tool_catalog.json"),
                "Runtime and Hepta do not share exactly the same catalog bytes")
        report["installation"] = pins
        report["cold_report_sha256"] = sha256(cold_bytes).hexdigest()
        report["checks"]["common_catalog_and_native_installation"] = True
        save()

        ssh = DisposableSSH(private, output, env)
        ssh.start()
        config = {"state_dir": str(private / "controller-state"),
            "controller_workspace_roots": [str(output)],
            "hosts": {"loopback": {
                "execution_mode": "operator", "ssh_target": ssh.target,
                "platform": "linux", "remote_state_dir": str(private / "owner-state"),
                "allow_execute": True, "allow_write": True, "allow_job_network": True,
                "allow_detached_fallback": False,
                "allowed_read_path_prefixes": [str(hepta), str(output), str(private),
                                                str(Path(sys.executable).parent), "/usr/bin"],
                "allowed_write_path_prefixes": [str(private), str(output)]}},
            "hia_worker": {"host": "loopback", "python_executable": sys.executable,
                "working_directory": str(hepta), "state_root": str(state_root),
                "artifact_roots": [str(inputs)], **pins,
                "native_helpers_manifest": str(bundle),
                "timeout_seconds": 120, "memory_max_bytes": 1073741824}}
        config_path = output / "runtime-config.json"
        write_json(config_path, config)
        consumer = Consumer(
            [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--consumer",
             "--hepta", str(hepta), "--bundle", str(bundle), "--bundle-sha256", bundle_sha,
             "--state-root", str(state_root), "--artifact-root", str(inputs),
             "--import-cache", str(private / "consumer-import-cache")],
            cwd=hepta, env=ssh.env, output=output, journal=journal)
        probe = consumer.result("probe")
        require(probe == {"u64_max": 18446744073709551615, "u64_overflow": None,
                          "lowercase_digest": True, "uppercase_digest": False,
                          "installation": pins}, "native identity byte guards did not execute as specified")
        report["native_identity_probe"] = probe
        report["checks"]["actual_identity_image_accept_and_reject"] = True
        transport = open_transport(config_path)
        listing = transport.list_tools()
        report["tools_list"] = listing
        sys.path.insert(0, str(runtime_source / "deploy"))
        from hia_mcp_catalog import freeze, verify_native
        verify_native(listing)
        frozen_contract = json.loads(
            (runtime_source / "deploy/contracts/hepta-hia-agent-native-v1.json").read_bytes())
        require(frozen_contract == freeze(), "frozen HIA family contract differs from registered tools")
        report["checks"]["actual_tools_list_and_frozen_family_contract_match"] = True
        catalog_path = hepta / "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"
        expected_tools = {tool["name"] for tool in json.loads(catalog_path.read_bytes())["tools"]}
        require(expected_tools <= {tool["name"] for tool in listing}, "MCP omitted registered HIA tools")
        lease_evidence = {}

        def qualified_call(tool, arguments):
            if tool != "hia_rollback":
                return checked_call(tool, arguments)
            lease = consumer.result("acquire", slot=arguments["target_slot"])
            require(lease["generation"] == arguments["expected_current"]["generation"],
                    "consumer did not pin the currently adopted generation")
            before = consumer.result("invoke", lease=lease)
            invocation_matches(before, lease)
            response = checked_call(tool, arguments)
            require(response["status"] == "completed", "MCP rollback was not completed")
            retained = consumer.result("invoke", lease=lease)
            invocation_matches(retained, lease)
            following = consumer.result("acquire", slot=arguments["target_slot"])
            require(following["generation"] == arguments["retained_generation"]
                    and following["artifact"] != lease["artifact"],
                    "new lease did not observe the retained baseline after rollback")
            after = consumer.result("invoke", lease=following)
            invocation_matches(after, following)
            released = consumer.result("release", lease=lease)
            following_released = consumer.result("release", lease=following)
            require(released["released"] is True and following_released["released"] is True,
                    "consumer lease release was not durable")
            refused = consumer.call("invoke", lease=lease)
            require(refused.get("ok") is False
                    and refused.get("error", {}).get("code") == "E_HIA_LEASE",
                    "released lease remained callable")
            lease_evidence.update(before=before, retained_after_rollback=retained,
                                  following_generation=after, released=released,
                                  released_lease_refusal=refused)
            report["lease_consumption"] = lease_evidence
            save()
            return response

        client = ToolClient(qualified_call, catalog_path=catalog_path,
                            journal=lambda event: record(journal, event))
        campaign = campaign_binding("native-helper-" + args.expected_runtime_source[:12]
                                    + "-" + args.expected_hepta_source[:12])
        report["campaign"] = campaign
        session = Session(client, prefix=campaign["request_prefix"])
        report["scenario"] = scripted_loop(session, target_slot=campaign["target_slot"])
        require(len(lease_evidence) > 0, "scripted qualification did not exercise a consumer lease")
        report["checks"]["eleven_tool_scripted_loop"] = True
        report["checks"]["native_lease_survives_rollback_and_release_refuses"] = True
        save()

        original = next(row for row in client.records if row["tool"] == "hia_artifact"
                        and row.get("response", {}).get("status") == "completed")
        ids_before = job_ids(transport, journal)
        owner_key = "hia-agent-" + sha256(encoded(
            {"tool": original["tool"], "key": original["arguments"]["request_key"]})).hexdigest()
        records = [json.loads(path.read_bytes())
                   for path in (private / "controller-state" / "jobs").glob("*.json")]
        matching = [row for row in records if row.get("idempotency_key") == owner_key]
        require(len(matching) == 1, "original mutation must have one durable owner record")
        owner = matching[0]
        require(owner["id"] in ids_before, "MCP inventory omitted the original operation")
        report["original_operation"] = owner
        retained_output = generic_call(transport, "process_read",
            {"host": "loopback", "job_id": owner["id"], "limit": 16384}, journal)
        require(retained_output.get("job_id") == owner["id"]
                and retained_output.get("stdout", {}).get("eof") is True
                and retained_output["stdout"].get("offset") == 0,
                "original worker report was not retained completely")
        retained_report = json.loads(bytes.fromhex(retained_output["stdout"]["bytes_hex"]))
        expected_profile_sha = sha256(encoded(config["hia_worker"])).hexdigest()
        bound_request = {"schema": "hia-agent-worker-request-v1", "tool": original["tool"],
                         "arguments": original["arguments"], "profile_sha256": expected_profile_sha,
                         "catalog_sha256": pins["catalog_sha256"]}
        expected_request_sha = sha256(encoded(bound_request)).hexdigest()
        require(retained_report.get("schema") == "hia-agent-worker-report-v1"
                and retained_report.get("complete") is True
                and retained_report.get("request_sha256") == expected_request_sha
                and retained_report.get("profile_sha256") == expected_profile_sha
                and retained_report.get("tool") == original["tool"]
                and retained_report.get("response") == original["response"]
                and all(retained_report.get(key) == value for key, value in pins.items()),
                "retained worker report lost its original request, profile or native-image binding")
        report["retained_original_worker_report"] = retained_report
        report["checks"]["actual_request_profile_and_helper_bound_report_retained"] = True
        close_transport()
        transport = open_transport(config_path)
        replay = checked_call(original["tool"], original["arguments"])
        require(replay == original["response"], "restart replay changed the original domain response")
        require(job_ids(transport, journal) == ids_before, "restart replay launched a second job")
        observation = generic_call(transport, "process_status",
            {"host": "loopback", "job_id": owner["id"]}, journal)
        require(observation.get("job_id") == owner["id"]
                and observation.get("state") == "succeeded"
                and observation.get("exit_code") == 0
                and observation.get("terminal_publication_confirmed") is True,
                "the original completed job lacks a bound terminal owner observation")
        report["old_operation_observation"] = observation
        report["replayed_response"] = replay
        report["checks"]["restart_exact_replay_without_new_job"] = True
        report["checks"]["old_operation_observed_through_native_owner"] = True
        save()

        close_transport()
        wrong = copy.deepcopy(config)
        wrong["hia_worker"]["native_helpers_sha256"] = "0" * 64 if bundle_sha != "0" * 64 else "1" * 64
        wrong_path = output / "wrong-native-pin-config.json"
        write_json(wrong_path, wrong)
        transport = open_transport(wrong_path)
        wrong_arguments = {"section": "manifest"}
        unknown = checked_call("hia_describe", wrong_arguments)
        require(unknown.get("status") == "unknown"
                and unknown.get("error", {}).get("retry_action") == "observe_original"
                and isinstance(unknown.get("operation", {}).get("job_id"), str),
                "wrong helper pin must retain an UNKNOWN original operation")
        unknown_ids = job_ids(transport, journal)
        repeated = checked_call("hia_describe", wrong_arguments)
        require(repeated.get("operation") == unknown["operation"]
                and repeated.get("status") == "unknown"
                and job_ids(transport, journal) == unknown_ids,
                "same failed request launched another job or lost UNKNOWN")
        close_transport()
        transport = open_transport(wrong_path)
        after_restart = checked_call("hia_describe", wrong_arguments)
        require(after_restart.get("operation") == unknown["operation"]
                and after_restart.get("status") == "unknown"
                and job_ids(transport, journal) == unknown_ids,
                "UNKNOWN operation identity changed across runtime restart")
        failed_observation = generic_call(transport, "process_status",
            {"host": "loopback", "job_id": unknown["operation"]["job_id"]}, journal)
        require(failed_observation.get("job_id") == unknown["operation"]["job_id"]
                and failed_observation.get("state") == "failed"
                and failed_observation.get("exit_code") == 2
                and failed_observation.get("terminal_publication_confirmed") is True,
                "wrong-pin failure lacks a confirmed original worker exit")
        failed_output = generic_call(transport, "process_read",
            {"host": "loopback", "job_id": unknown["operation"]["job_id"], "limit": 16384},
            journal)
        report["wrong_pin_original_failure"] = {"response": unknown,
            "repeat": repeated, "after_restart": after_restart,
            "owner_status": failed_observation, "owner_output": failed_output}
        report["checks"]["wrong_pin_unknown_keeps_original_job_across_restart"] = True
        report["sources_after"] = {
            "runtime": source_identity(runtime_source, args.expected_runtime_source),
            "hepta": source_identity(hepta, args.expected_hepta_source)}
        require(report["sources_after"] == report["sources"], "candidate source identity drifted")
        report["checks"]["fixed_candidate_source_preserved"] = True
        report["status"] = "PASS"
    except BaseException as exc:
        report["status"] = "HOLD"
        report["error"] = {"type": type(exc).__name__, "message": str(exc),
                           "traceback": traceback.format_exc()}
    finally:
        # On an interrupted scenario, reconcile only this fresh controller's
        # original job IDs. Cancellation observations never turn HOLD into PASS.
        if report["status"] != "PASS" and transport is not None:
            try:
                cleanup_jobs = job_ids(transport, journal)
                for job_id in cleanup_jobs:
                    status = generic_call(transport, "process_status",
                        {"host": "loopback", "job_id": job_id}, journal)
                    if status.get("terminal_publication_confirmed") is not True:
                        generic_call(transport, "process_cancel",
                            {"host": "loopback", "job_id": job_id}, journal)
                        observed = generic_call(transport, "process_wait",
                            {"host": "loopback", "job_id": job_id, "timeout_seconds": 30}, journal)
                        if observed.get("terminal_publication_confirmed") is not True:
                            cleanup_errors.append("original job termination unconfirmed: " + job_id)
                report["cleanup_original_job_ids"] = cleanup_jobs
            except Exception as exc:
                cleanup_errors.append("original job reconciliation: " + str(exc))
        if consumer is not None:
            try:
                consumer.close()
            except Exception as exc:
                cleanup_errors.append("consumer: " + str(exc))
        try:
            close_transport()
        except Exception as exc:
            cleanup_errors.append("MCP: " + str(exc))
        if ssh is not None:
            try:
                cleanup_errors.extend(ssh.close())
            except Exception as exc:
                cleanup_errors.append("SSH: " + str(exc))
        report["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            report["status"] = "HOLD"
        save()
        journal.close()
    print(json.dumps({"status": report["status"], "output": str(output / "report.json"),
                      "checks": report["checks"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--consumer":
        consumer_main(sys.argv[2:])
    else:
        raise SystemExit(main())
