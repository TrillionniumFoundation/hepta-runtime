#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Finite revision-4 Java API checks; explicitly not Rust/MCP/provider qualification.

Uses an already pinned development installation and an owned ELF; no installation,
target execution, shared-service restart or retry. All eight bounded calls and
their complete stdout/stderr remain in a fresh private workspace.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import time


REQUIRED_V4_GPL = {
    "GPL/DemanglerGnu/Module.manifest": "ca76258f330d1096cb616df83a4213593a574c907d02eb47b0926ccc5359bd7b",
    "GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_41": "0dfec5481a933e9cb2a7ef025040dd3a817d0085bc3bee166ce69ce7de759ad9"
}


def digest(path, deadline):
    path = Path(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and path.resolve(strict=True) == path, path
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            assert time.monotonic() < deadline, "campaign identity deadline exceeded"
            result.update(block)
    after = path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), path
    return result.hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def verify_installation(profile, deadline):
    engine = profile["ghidra_engine"]
    assert engine["engine_version"] == "12.1.4"
    assert engine["release_archive_sha256"] == "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
    manifest_path = Path(engine["manifest_path"])
    assert manifest_path.stat().st_size <= 8 * 1024 * 1024
    assert digest(manifest_path, deadline) == engine["manifest_sha256"]
    manifest = json.loads(manifest_path.read_text())
    assert manifest["schema"] == "hepta.rea.ghidra-installation.v1"
    assert manifest["engine_version"] == engine["engine_version"]
    assert manifest["release_archive_sha256"] == engine["release_archive_sha256"]
    installed = Path(engine["installation_root"])
    files = manifest["files"]
    assert 0 < len(files) <= 20000
    actual = set()
    subtrees = ("Ghidra", "GPL") if engine.get("bridge_revision") == 4 else ("Ghidra",)
    for subtree in subtrees:
        directory = installed / subtree
        assert directory.is_dir() and not directory.is_symlink()
        for path in directory.rglob("*"):
            assert not path.is_symlink(), path
            if path.is_file():
                actual.add(str(path.relative_to(installed)))
            else:
                assert path.is_dir(), path
    if engine.get("bridge_revision") == 4:
        assert all(files.get(name) == expected for name, expected in REQUIRED_V4_GPL.items())
    assert actual == set(files), "installed Ghidra file inventory changed"
    total = 0
    jars = []
    for name, expected in sorted(files.items()):
        assert name.startswith(tuple(part + "/" for part in subtrees)) and ".." not in Path(name).parts and "\\" not in name
        path = installed / name
        total += path.stat().st_size
        assert total <= 8 * 1024 * 1024 * 1024
        assert digest(path, deadline) == expected, path
        for priority, prefix in enumerate(("Ghidra/Framework/", "Ghidra/Configurations/", "Ghidra/Features/", "Ghidra/Processors/")):
            if name.startswith(prefix) and "/lib/" in name and name.endswith(".jar"):
                jars.append((priority, str(path)))
    java = Path(engine["java_home"])
    for name, expected in engine["runtime_files"].items():
        assert not Path(name).is_absolute() and ".." not in Path(name).parts
        assert digest(java / name, deadline) == expected, name
    assert profile["backend_executable"] == str(java / "bin/java")
    assert digest(java / "bin/java", deadline) == profile["backend_sha256"]
    return ":".join(path for _, path in sorted(jars)), {"files": len(files), "bytes": total}


def child_limits():
    os.nice(10)
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))


def run_java(arguments, work, label, deadline):
    started = time.monotonic()
    timeout = min(60, deadline - started)
    assert timeout > 0
    with (work / (label + ".stdout")).open("xb") as stdout, (work / (label + ".stderr")).open("xb") as stderr:
        child = subprocess.Popen(arguments, cwd=work, stdout=stdout, stderr=stderr,
                                 start_new_session=True, preexec_fn=child_limits)
        record = {"command": arguments, "pid": child.pid, "timeout_seconds": timeout}
        save(work / (label + ".start.json"), record)
        try:
            record["exit_code"] = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
            # Signal only while the original direct child is still unreaped/live.
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)
            record["exit_code"] = child.returncode
        finally:
            record["elapsed_seconds"] = time.monotonic() - started
            save(work / (label + ".terminal.json"), record)
    for suffix in ("stdout", "stderr"):
        assert (work / (label + "." + suffix)).stat().st_size <= 8 * 1024 * 1024
    assert not record.get("timed_out"), record
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="existing development static-provider config")
    parser.add_argument("--profile", default="owned_ghidra")
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-sha256", required=True)
    parser.add_argument("--entry", default="0x401106")
    parser.add_argument("--interior", default="0x401107")
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    deadline = started + 600
    root = args.workspace.absolute()
    root.mkdir(mode=0o700, exist_ok=False)
    assert root.resolve(strict=True) == root
    os.umask(0o077)
    profile = json.loads(args.config.read_text())["rea_static_profiles"][args.profile]
    assert profile["ghidra_engine"].get("bridge_revision") == 4, "current API harness requires the explicit GPL-bound revision-4 profile"
    receipt = {"schema": "hepta.rea.ghidra-v4-api-checks.v1", "scope": "java_api_only",
               "rust_mcp_provider_qualified": False, "original_npm_parity_qualified": False,
               "targets_executed": 0, "qualified": False, "calls": [], "checks": []}
    try:
        receipt["config_sha256"] = digest(args.config, deadline)
        classpath, install = verify_installation(profile, deadline)
        receipt["installation_before"] = install
        receipt["engine"] = profile["ghidra_engine"]
        assert digest(args.fixture, deadline) == args.fixture_sha256
        assert args.fixture.stat().st_size <= 8 * 1024 * 1024
        fixture = root / "owned.elf"
        fixture.write_bytes(args.fixture.read_bytes())
        fixture.chmod(0o400)
        receipt["fixture_sha256"] = digest(fixture, deadline)
        assert receipt["fixture_sha256"] == args.fixture_sha256
        source = args.source_dir / "rea_ghidra_analysis_1214_v4.java"
        receipt["bridge_sha256"] = digest(source, deadline)
        receipt["java_sha256"] = digest(Path(profile["backend_executable"]), deadline)
        source_before = source.read_bytes()
        java = profile["backend_executable"]
        queries = [("functions", "functions", "-"), ("function-entry", "function", args.entry),
                   ("function-interior", "function", args.interior), ("xrefs-entry", "xrefs", args.entry),
                   ("xrefs-interior", "xrefs", args.interior), ("decompile-entry", "decompile", args.entry),
                   ("decompile-interior", "decompile", args.interior), ("not-found", "function", "0x0")]
        observations = {}
        for label, operation, selected in queries:
            home = root / label
            home.mkdir(mode=0o700)
            command = [java, "-Xmx512m", "-XX:MaxMetaspaceSize=256m", "-XX:ReservedCodeCacheSize=64m",
                       "-XX:CompressedClassSpaceSize=64m", "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1",
                       "-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-Djava.awt.headless=true",
                       "-Duser.home=" + str(home), "-Djava.io.tmpdir=" + str(home), "--class-path", classpath,
                       "--source", "25", str(source), profile["ghidra_engine"]["installation_root"],
                       str(fixture), "65536", operation, selected]
            outcome = run_java(command, home, "java", deadline)
            receipt["calls"].append({"label": label, **outcome})
            raw = (home / "java.stdout").read_bytes()
            error = (home / "java.stderr").read_bytes()
            if label == "not-found":
                assert outcome["exit_code"] != 0 and not raw
                assert b"no containing internal analyzed function" in error
                receipt["checks"].append("unmapped_selector_has_complete_retained_error")
                continue
            assert outcome["exit_code"] == 0, (label, error.decode(errors="replace"))
            value = json.loads(raw)
            assert value["schema"] == "hepta.rea.ghidra-analysis.v2" and value["bridge_revision"] == 4
            assert value["analysis_profile"] == "hepta.ghidra.12.1.4.elf-x86_64-default-functions.v1"
            assert value["language_id"] == "x86:LE:64:default" and value["compiler_spec_id"] == "gcc"
            assert value["analysis_options_sha256"] == "a5531d741cf6e4e42215ea1f4268049600b80c3a03ab7d3586bd3a7bbb7acd75"
            assert value["analysis_option_count"] == 146 and value["analysis_options_unchanged"] is True
            assert len(value["enabled_analyzers"]) == 26 and len(value["disabled_analyzers"]) == 4
            assert value["no_return_repair_applied"] is False
            assert value["decompilation_scope"] == "explicit_selected_function" and value["auto_analysis_may_decompile"] is True
            assert value["native_child_cleanup_scope"] == "private_bridge_jvm_all_descendants"
            assert value["native_helper_observation_scope"] == "live_descendants_at_phase_boundaries"
            assert value["native_child_cleanup_confirmed"] is True
            assert value["observed_native_children"] == len(value["native_children"])
            assert all(child["exit_confirmed"] is True and child["final_state"] in ("absent", "identity_changed")
                       for child in value["native_children"])
            assert operation != "decompile" or value["observed_native_decompiler_children"] > 0
            assert value["engine_version"] == "12.1.4" and value["source_sha256"] == args.fixture_sha256
            assert value["target_executed"] is False and value["external_libraries_loaded"] is False
            assert value["analysis_completed"] is True and value["project_saved"] is False
            observations[label] = value
            save(root / (label + ".json"), value)
            assert sum(path.stat().st_size for path in root.rglob("*") if path.is_file()) <= 128 * 1024 * 1024
        for operation in ("function", "xrefs", "decompile"):
            entry, interior = (observations[operation + "-" + kind] for kind in ("entry", "interior"))
            assert entry["function_address_requested"] == args.entry and interior["function_address_requested"] == args.interior
            assert entry["function_resolution"] == "entry" and interior["function_resolution"] == "containing"
            assert entry["function"] == interior["function"]
            body = entry["function"]
            assert body["entry_address"] == args.entry and body["body_ranges_complete"] is True
            assert body["body_range_count"] == len(body["body_ranges"])
            assert any(int(r["min_address"], 16) <= int(args.interior, 16) <= int(r["max_address"], 16) for r in body["body_ranges"])
            for field in ({"xrefs": ("incoming_references", "outgoing_references"),
                           "decompile": ("c_code", "c_code_sha256", "c_code_complete")}.get(operation, ())):
                assert entry[field] == interior[field], (operation, field)
            if operation == "decompile":
                assert entry["c_code_complete"] is True and interior["native_child_cleanup_confirmed"] is True
                assert entry["observed_native_children"] > 0 and interior["observed_native_children"] > 0
                assert hashlib.sha256(entry["c_code"].encode()).hexdigest() == entry["c_code_sha256"]
            receipt["checks"].append(operation + "_entry_and_interior_agree_with_original_selectors_retained")
        listing = observations["functions"]
        assert listing["function_inventory_scope"] == "internal_and_external_separate"
        assert listing["function_scan_complete"] is True and listing["external_function_scan_complete"] is True
        assert listing["returned_functions"] == listing["scanned_functions"] == len(listing["functions"])
        assert listing["returned_external_functions"] == listing["scanned_external_functions"] == len(listing["external_functions"])
        assert listing["external_functions"] and all(row["entry_address"].startswith("EXTERNAL:0x") for row in listing["external_functions"])
        receipt["inventory"] = {"internal": listing["returned_functions"], "external": listing["returned_external_functions"]}
        receipt["checks"].append("external_inventory_is_explicit_and_separately_counted")
        receipt["installation_after"] = verify_installation(profile, deadline)[1]
        assert receipt["installation_before"] == receipt["installation_after"]
        assert source.read_bytes() == source_before and digest(args.fixture, deadline) == args.fixture_sha256
        assert digest(args.config, deadline) == receipt["config_sha256"]
        receipt["checks"].append("installed_manifest_jre_bridge_and_input_identity_unchanged")
        receipt["qualified"] = True
    except Exception as error:
        receipt["failure"] = repr(error)
        raise
    finally:
        receipt["elapsed_seconds"] = time.monotonic() - started
        save(root / "receipt.json", receipt)
        print(json.dumps({key: value for key, value in receipt.items() if key not in ("calls", "engine")}), flush=True)


if __name__ == "__main__":
    main()
