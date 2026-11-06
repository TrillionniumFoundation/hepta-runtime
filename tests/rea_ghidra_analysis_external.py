#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Real bounded Ghidra analysis/decompilation through the original durable owner."""
import argparse
import hashlib
import re
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import zipfile
from rea_java_external import Mcp, digest, private_write, set_fence
from rea_engine_cleanup_assertions import (assert_owner_cleanup, signal_original_worker, wait_source_java,
                                           assert_original_processes_stopped, assert_original_group_membership)
from rea_java_kernel_probe import java_observation, process_identity, run_observed_worker

RELEASE_SHA = "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"
RELEASES = {
    "12.2": (RELEASE_SHA, 2, "rea_ghidra_inventory_v2.java", "rea_ghidra_analysis_bridge.java"),
    "12.1.4": ("ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db", 3,
               "rea_ghidra_inventory_1214_v3.java", "rea_ghidra_analysis_1214_v3.java"),
}


REQUIRED_V4_GPL = {
    "GPL/DemanglerGnu/Module.manifest": "ca76258f330d1096cb616df83a4213593a574c907d02eb47b0926ccc5359bd7b",
    "GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_41": "0dfec5481a933e9cb2a7ef025040dd3a817d0085bc3bee166ce69ce7de759ad9"
}


def verify_v4_release_members(archive, installed, files, release_sha):
    assert digest(archive) == release_sha
    prefix = "ghidra_12.1.4_PUBLIC/"
    with zipfile.ZipFile(archive) as source:
        members = {}
        for member in source.infolist():
            if member.is_dir() or not member.filename.startswith(prefix):
                continue
            relative = member.filename[len(prefix):]
            if not relative.startswith(("Ghidra/", "GPL/")):
                continue
            assert relative not in members, relative
            members[relative] = member
        assert set(members) == set(files), "release and installed two-subtree inventory differ"
        total = 0
        for name, expected in sorted(files.items()):
            member = members[name]
            assert member.file_size == (installed / name).stat().st_size
            total += member.file_size
            assert total <= 8 * 1024 * 1024 * 1024
            result = hashlib.sha256()
            with source.open(member) as stream:
                for data in iter(lambda: stream.read(1024 * 1024), b""):
                    result.update(data)
            assert result.hexdigest() == expected, name
    return {"schema": "hepta.rea.ghidra-release-members.v1", "subtrees": ["Ghidra", "GPL"],
            "release_archive_sha256": release_sha, "file_count": len(files), "bytes": total,
            "all_archive_members_equal": True, "required_gpl_members": REQUIRED_V4_GPL}


def live_java(unit, mode, deadline):
    arguments = ["systemctl"] + (["--user"] if mode == "operator" else [])
    while time.monotonic() < deadline:
        current = subprocess.run(arguments + ["show", unit, "--property=ControlGroup", "--value"],
                                 check=True, capture_output=True, text=True, timeout=10).stdout.strip()
        if current:
            assert current.endswith("/" + unit + ".service"), current
            group = Path("/sys/fs/cgroup") / current.lstrip("/")
            try:
                for pid in (group / "cgroup.procs").read_text().split():
                    value = java_observation(int(pid))
                    if value is not None:
                        return value
            except FileNotFoundError:
                pass
        time.sleep(0.1)
    raise TimeoutError("Ghidra Java source process did not become observable")



def live_native_decompiler(unit, mode, deadline):
    arguments = ["systemctl"] + (["--user"] if mode == "operator" else [])
    while time.monotonic() < deadline:
        current = subprocess.run(arguments + ["show", unit, "--property=ControlGroup", "--value"],
                                 check=True, capture_output=True, text=True, timeout=10).stdout.strip()
        if current:
            assert current.endswith("/" + unit + ".service"), current
            group = Path("/sys/fs/cgroup") / current.lstrip("/")
            try:
                pids = [int(pid) for pid in (group / "cgroup.procs").read_text().split()]
                observed = []
                found = False
                for pid in pids:
                    try:
                        start = process_identity(pid)
                        executable = os.readlink(f"/proc/{pid}/exe")
                        flags = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
                        if Path(executable).name in ("decompile", "java"):
                            item = {"pid": pid, "start_time": start, "executable": executable,
                                    "NoNewPrivs": flags.get("NoNewPrivs", "").strip(),
                                    "Seccomp": flags.get("Seccomp", "").strip()}
                            assert item["NoNewPrivs"] == "1" and item["Seccomp"] == "2", item
                            assert start == process_identity(pid), item
                            observed.append(item)
                            found |= Path(executable).name == "decompile"
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                if found:
                    return {"unit": unit, "control_group": current, "owned_processes": observed}
            except FileNotFoundError:
                pass
        time.sleep(0.01)
    raise TimeoutError("original job did not expose a live native decompiler child")



def assert_revision_four_cleanup(value, selected_decompile):
    assert value["decompilation_scope"] == "explicit_selected_function"
    assert value["auto_analysis_may_decompile"] is True
    assert value["native_child_cleanup_scope"] == "private_bridge_jvm_all_descendants"
    assert value["native_helper_observation_scope"] == "live_descendants_at_phase_boundaries"
    assert value["native_child_cleanup_confirmed"] is True
    children = value["native_children"]
    assert value["observed_native_children"] == len(children) <= 64
    decompilers = sum(Path(child["command"]).name == "decompile" for child in children)
    assert value["observed_native_decompiler_children"] == decompilers
    assert not selected_decompile or decompilers > 0
    assert value["observed_explicit_decompiler_candidates"] == sum(child["explicit_decompiler_candidate"] for child in children)
    after = []
    for child in children:
        assert child["role_attribution"] == "phase_and_executable_inference"
        assert child["exit_confirmed"] is True and child["final_state"] in ("absent", "identity_changed")
        assert child["start_instant"] and str(int(child["start_ticks"])) == child["start_ticks"]
        try:
            raw = Path(f"/proc/{child['pid']}/stat").read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            state = {"pid": child["pid"], "expected_start_ticks": child["start_ticks"],
                     "current_start_ticks": fields[19], "state": fields[0]}
            assert fields[19] != child["start_ticks"], state
        except FileNotFoundError:
            state = {"pid": child["pid"], "expected_start_ticks": child["start_ticks"], "absent": True}
        after.append(state)
    return after


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--ghidra-home", type=Path, required=True)
    parser.add_argument("--engine-version", choices=tuple(RELEASES), default="12.2")
    parser.add_argument("--bridge-revision", type=int, choices=(2, 3, 4),
                        help="explicit revision; 4 requires Ghidra 12.1.4 and adds containment/external inventory")
    parser.add_argument("--release-archive", type=Path,
                        help="original release ZIP; required for the explicit 12.1.4 profile")
    parser.add_argument("--fixture", type=Path,
                        help="reuse the exact benign hepta_leaf/hepta_caller ELF used by the original provider")
    parser.add_argument("--fixture-sha256")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--execution-mode", choices=("operator", "isolated"), required=True)
    parser.add_argument("--allow-local-ssh", action="store_true")
    args = parser.parse_args()
    assert args.allow_local_ssh
    original_runtime, java_home, ghidra_home = (path.resolve(strict=True) for path in
                                               (args.runtime, args.java_home, args.ghidra_home))
    release_sha, revision, inventory_bridge, analysis_bridge = RELEASES[args.engine_version]
    if args.bridge_revision == 4 and args.engine_version == "12.1.4":
        revision = 4
        inventory_bridge = "rea_ghidra_inventory_1214_v4.java"
        analysis_bridge = "rea_ghidra_analysis_1214_v4.java"
    elif args.bridge_revision is not None and args.bridge_revision != revision:
        parser.error("bridge revision does not match the selected fixed Ghidra release")
    properties = (ghidra_home / "Ghidra/application.properties").read_text().splitlines()
    assert [line for line in properties if line.startswith("application.version=")] == [
        "application.version=" + args.engine_version]
    assert args.engine_version != "12.1.4" or args.release_archive is not None
    if args.release_archive is not None:
        assert digest(args.release_archive.resolve(strict=True)) == release_sha
    assert (args.fixture is None) == (args.fixture_sha256 is None)
    if args.fixture is not None:
        assert re.fullmatch("[0-9a-f]{64}", args.fixture_sha256)
        assert digest(args.fixture.resolve(strict=True)) == args.fixture_sha256
    root = args.workspace.absolute()
    root.mkdir(mode=0o700, exist_ok=False)
    root = root.resolve(strict=True)
    runtime = root / "hepta-runtime-qualified"
    shutil.copyfile(original_runtime, runtime)
    runtime.chmod(0o500)
    for name in ("controller-state", "jobs", "authority"):
        (root / name).mkdir(mode=0o700)
    private_write(root / "authority/.owner.lock", b"")
    set_fence(root, "admitting")
    source = root / "owned.c"
    private_write(source, b"__attribute__((noinline)) int hepta_leaf(int value) { return value * 7 + 11; }\n__attribute__((noinline)) int hepta_caller(int value) { return hepta_leaf(value) + 5; }\nint main(int argc, char **argv) { return hepta_caller(argc); }\n")
    artifact = root / "owned.elf"
    if args.fixture is None:
        subprocess.run(["/usr/bin/cc", "-no-pie", "-O0", "-fno-inline", "-fno-stack-protector", str(source), "-o", str(artifact)],
                       check=True, capture_output=True, timeout=30)
    else:
        shutil.copyfile(args.fixture, artifact)
        artifact.chmod(0o500)
        assert digest(artifact) == args.fixture_sha256
    cancellation_source = root / "owned_cancel.c"
    private_write(cancellation_source, (
        "__attribute__((noinline)) unsigned hepta_cancel(unsigned value) { unsigned result=value;\n" +
        "\n".join(f"result = (result ^ {index+1}u) * 1664525u + (value & 255u);" for index in range(2048)) +
        "\nreturn result; }\nint main(void) { return (int)hepta_cancel(3); }\n").encode())
    cancellation_artifact = root / "owned_cancel.elf"
    subprocess.run(["/usr/bin/cc", "-no-pie", "-O0", "-fno-inline", "-fno-stack-protector", str(cancellation_source), "-o", str(cancellation_artifact)],
                   check=True, capture_output=True, timeout=30)
    files = {}
    subtrees = ("Ghidra", "GPL") if revision == 4 else ("Ghidra",)
    for subtree in subtrees:
        directory = ghidra_home / subtree
        assert directory.is_dir() and not directory.is_symlink()
        for path in sorted(directory.rglob("*")):
            assert not path.is_symlink()
            if path.is_file():
                files[str(path.relative_to(ghidra_home))] = digest(path)
            else:
                assert path.is_dir(), path
    if revision == 4:
        assert all(files.get(name) == expected for name, expected in REQUIRED_V4_GPL.items())
        binding = verify_v4_release_members(args.release_archive, ghidra_home, files, release_sha)
        private_write(root / "ghidra-release-members.json", binding)
    manifest = {"schema": "hepta.rea.ghidra-installation.v1", "engine_version": args.engine_version,
                "release_archive_sha256": release_sha, "files": files}
    manifest_path = root / "ghidra-installation.json"
    private_write(manifest_path, manifest)
    components = ["release", "lib/modules", "lib/server/libjvm.so", "lib/libjava.so",
                  "lib/libzip.so", "lib/libnio.so", "lib/libjli.so"]
    version_result = subprocess.run([str(java_home / "bin/java"), "--version"], check=True,
                                    capture_output=True, timeout=10, env={"LC_ALL": "C"})
    assert not version_result.stderr
    version = version_result.stdout.decode().splitlines()[0]
    profile = {"host": "local", "runtime_executable": str(runtime), "runtime_sha256": digest(runtime),
               "provider": "ghidra", "backend_executable": str(java_home / "bin/java"),
               "backend_sha256": digest(java_home / "bin/java"), "backend_version": version,
               "working_directory": str(root), "input_roots": [str(root)], "allowed_operations": ["inventory", "functions", "function", "decompile", "xrefs"],
               "max_artifact_bytes": 8388608, "max_output_bytes": 65536, "timeout_seconds": 120,
               "memory_max_bytes": 1610612736,
               "ghidra_engine": {"bridge_revision": revision, "java_home": str(java_home), "installation_root": str(ghidra_home),
                                 "manifest_path": str(manifest_path), "manifest_sha256": digest(manifest_path),
                                 "engine_version": args.engine_version, "release_archive_sha256": release_sha,
                                 "runtime_files": {name: digest(java_home / name) for name in sorted(components)}}}
    config = {"state_dir": str(root / "controller-state"), "controller_workspace_roots": [str(root)],
              "hosts": {"local": {"ssh_target": "localhost", "platform": "linux", "execution_mode": args.execution_mode,
                                  "remote_state_dir": str(root / "jobs"), "allow_execute": True, "allow_write": True,
                                  "allow_job_network": args.execution_mode == "operator", "allow_detached_fallback": False,
                                  "allowed_cwd_prefixes": [] if args.execution_mode == "operator" else [str(root)],
                                  "allowed_read_path_prefixes": [str(root), str(java_home), str(ghidra_home)],
                                  "allowed_write_path_prefixes": [str(root)]}},
              "rea_static_profiles": {"owned_ghidra": profile, "owned_ghidra_timeout": dict(profile, timeout_seconds=20)}}
    private_write(root / "config.json", config)
    nm = subprocess.run(["/usr/bin/nm", "-n", str(artifact)], check=True, capture_output=True, text=True, timeout=10).stdout
    private_write(root / "gnu-nm.txt", nm.encode())
    symbols = {parts[2]: "0x" + format(int(parts[0], 16), "x") for line in nm.splitlines()
               if len(parts := line.split()) == 3 and re.fullmatch("[0-9a-fA-F]+", parts[0])}
    leaf, caller = symbols["hepta_leaf"], symbols["hepta_caller"]
    cancel_nm = subprocess.run(["/usr/bin/nm", "-n", str(cancellation_artifact)], check=True, capture_output=True, text=True, timeout=10).stdout
    private_write(root / "gnu-nm-cancel.txt", cancel_nm.encode())
    cancel_address = next("0x" + format(int(parts[0], 16), "x") for line in cancel_nm.splitlines()
                          if len(parts := line.split()) == 3 and parts[2] == "hepta_cancel")
    objdump = subprocess.run(["/usr/bin/objdump", "-d", str(artifact)], check=True, capture_output=True, text=True, timeout=10).stdout
    private_write(root / "gnu-objdump.txt", objdump.encode())
    expected_call_sites = ["0x" + format(int(line.split(":")[0].strip(), 16), "x") for line in objdump.splitlines()
                           if "<hepta_leaf>" in line and "call" in line]
    assert expected_call_sites

    result = {"schema": "hepta.rea.ghidra-analysis-qualification.v1", "workspace": str(root),
              "runtime_sha256": profile["runtime_sha256"], "backend_sha256": profile["backend_sha256"],
              "backend_version": version, "ghidra_engine": profile["ghidra_engine"],
              "release_archive_verified": args.release_archive is not None,
              "original_fixture_sha256": args.fixture_sha256,
              "execution_mode": args.execution_mode, "isolated_host_qualification": args.execution_mode == "isolated",
              "targets_run_by_provider": 0, "rea_full_parity": False, "checks": [],
              "independent_symbol_entries": {"hepta_leaf": leaf, "hepta_caller": caller},
              "independent_call_sites": expected_call_sites, "job_ids": {}}
    server = None
    original_hash = digest(artifact)
    try:
        server = Mcp(runtime, root)
        admitted_profiles = {item["profile"]: item for item in server.call("rea_static_profiles", {})["profiles"]}
        admitted = admitted_profiles["owned_ghidra"]
        def request(key, operation, path=artifact, address=None):
            value = {"profile": "owned_ghidra", "profile_sha256": admitted["profile_sha256"],
                     "idempotency_key": key, "operation": operation, "artifact_path": str(path),
                     "artifact_sha256": digest(path)}
            if address is not None:
                value["function_address"] = address
            return value
        inventory = request("owned-ghidra-inventory-v2", "inventory")
        normal = request("owned-ghidra-functions", "functions")
        selected = request("owned-ghidra-decompile", "decompile", address=leaf)
        get_function = request("owned-ghidra-function", "function", address=leaf)
        get_xrefs = request("owned-ghidra-xrefs", "xrefs", address=leaf)
        requests = {"inventory_v2": inventory, "functions": normal, "function": get_function, "decompile": selected, "xrefs": get_xrefs}
        private_write(root / "requests.json", requests)
        inventory_start = server.call("rea_static_start", inventory)
        inventory_result = server.complete(inventory)
        private_write(root / "inventory-v2-result.json", {"initial": inventory_start, "result": inventory_result})
        assert inventory_result["process_succeeded"] is True, inventory_result
        inventory_observation = json.loads(inventory_result["report"]["stdout"])
        assert inventory_observation["schema"] == "hepta.rea.ghidra-observation.v2" and inventory_observation["bridge_revision"] == revision
        assert inventory_observation["engine_version"] == args.engine_version
        assert inventory_observation["auto_analysis_performed"] is False and inventory_observation["source_sha256"] == original_hash
        assert inventory_result["report"]["bridge_sha256"] == digest(Path(__file__).resolve().parents[1] / "src/mcp" / inventory_bridge)
        result["job_ids"]["inventory_v2"] = inventory_start["job"]["id"]
        result["checks"].append("explicit_revision_named_byte_provider_uses_pinned_engine_profile_and_bridge")
        first = server.call("rea_static_start", normal)
        private_write(root / "functions-initial-job.json", first)
        assert first["job"].get("launch_state") != "launch_unknown", first
        replay = server.call("rea_static_start", normal)
        assert replay["job"]["id"] == first["job"]["id"] and replay["reused"] is True
        completed = server.complete(normal)
        assert completed["process_succeeded"] is True, completed
        observation = json.loads(completed["report"]["stdout"])
        assert completed["report"]["bridge_sha256"] == digest(Path(__file__).resolve().parents[1] / "src/mcp" / analysis_bridge)
        assert observation["bridge_revision"] == revision
        assert observation["schema"] == ("hepta.rea.ghidra-analysis.v2" if revision == 4 else "hepta.rea.ghidra-analysis.v1")
        if revision == 4:
            assert observation["analysis_profile"] == "hepta.ghidra.12.1.4.elf-x86_64-default-functions.v1"
            assert observation["language_id"] == "x86:LE:64:default" and observation["compiler_spec_id"] == "gcc"
            assert observation["analysis_options_sha256"] == "a5531d741cf6e4e42215ea1f4268049600b80c3a03ab7d3586bd3a7bbb7acd75"
            assert observation["analysis_option_count"] == 146 and observation["analysis_options_unchanged"] is True
            assert len(observation["enabled_analyzers"]) == 26 and len(observation["disabled_analyzers"]) == 4
            assert observation["no_return_repair_applied"] is False
            result.setdefault("native_helper_checks", {})["functions"] = assert_revision_four_cleanup(observation, False)
        assert observation["engine_version"] == args.engine_version
        assert observation["analysis_completed"] is True and observation["auto_analysis_performed"] is True
        assert observation["decompilation_performed"] is False
        assert observation["source_sha256"] == original_hash
        entries = {row["entry_address"]: row for row in observation["functions"]}
        assert entries[leaf]["name"] == "hepta_leaf" and entries[caller]["name"] == "hepta_caller", observation
        assert observation["instruction_count_after_analysis"] > 0
        assert observation["function_scan_complete"] is True
        if revision == 4:
            assert observation["function_inventory_scope"] == "internal_and_external_separate"
            external = observation["external_functions"]
            assert external and observation["external_function_scan_complete"] is True, observation
            assert observation["scanned_external_functions"] == observation["returned_external_functions"] == len(external)
            assert observation["omitted_external_functions_in_scan"] == 0
            assert all(row["external"] is True and row["entry_address"].startswith("EXTERNAL:0x") for row in external)
            result["checks"].append("separate_external_function_inventory_retains_address_space_and_complete_counts")
        assert completed["report"]["network_syscalls_denied"] is True
        private_write(root / "functions-result.json", completed)
        result["job_ids"]["functions"] = first["job"]["id"]
        result["checks"].append("dynamic_library_elf_named_bytes_real_analysis_and_independent_nm_entries")
        for operation, query in [("function", get_function), ("xrefs", get_xrefs), ("decompile", selected)]:
            initial = server.call("rea_static_start", query)
            result["job_ids"][operation] = initial["job"]["id"]
            private_write(root / f"{operation}-initial-job.json", initial)
            actual = server.complete(query)
            private_write(root / f"{operation}-result.json", actual)
            assert actual["process_succeeded"] is True, actual
            value = json.loads(actual["report"]["stdout"])
            if revision == 4:
                result.setdefault("native_helper_checks", {})[operation] = assert_revision_four_cleanup(value, operation == "decompile")
            assert value["function"]["entry_address"] == leaf and value["function_address_requested"] == leaf, value
            assert value["source_sha256"] == original_hash and value["target_executed"] is False
            assert value["external_libraries_loaded"] is False and value["project_saved"] is False
            if operation == "xrefs":
                observed = {row["from_address"] for row in value["incoming_references"] if row["call"]}
                assert set(expected_call_sites).issubset(observed), (expected_call_sites, value)
                result["checks"].append("analyzed_incoming_call_xrefs_match_independent_gnu_objdump")
            if operation == "decompile":
                assert value["decompilation_completed"] is True and value["native_child_cleanup_confirmed"] is True
                assert value["observed_native_children"] >= 1, value
                assert value["c_code_complete"] is True, value
                assert hashlib.sha256(value["c_code"].encode()).hexdigest() == value["c_code_sha256"]
                assert "hepta_leaf" in value["c_code"] and "7" in value["c_code"], value
                decompilation = actual
                result["checks"].append("actual_native_decompiler_selected_function_complete_c_digest_and_child_cleanup")
        server.close()
        server = Mcp(runtime, root)
        assert server.call("rea_static_start", selected)["job"]["id"] == result["job_ids"]["decompile"]
        assert server.complete(selected) == decompilation
        result["checks"].append("controller_restart_returns_original_decompilation_without_relaunch")
        conflict = dict(selected, function_address=caller)
        conflict_response = server.raw("rea_static_start", conflict)
        private_write(root / "same-key-conflict.json", {"request": conflict, "call_tool_result": conflict_response})
        assert conflict_response.get("isError") is True
        for index, bad in enumerate([dict(selected, function_address="0x0" + leaf[2:]),
                    {key: val for key, val in selected.items() if key != "function_address"},
                    dict(normal, function_address=leaf), dict(selected, flags="caller-script")]):
            rejected = server.raw("rea_static_start", bad)
            private_write(root / f"invalid-selector-{index}.json", {"request": bad, "call_tool_result": rejected})
            assert rejected.get("isError") is True, (bad, rejected)
        result["checks"].append("changed_content_same_key_and_invalid_or_extra_selectors_refused")
        if revision == 4:
            interior_address = hex(int(leaf, 16) + 1)
            for operation in ("function", "xrefs", "decompile"):
                interior = request("owned-ghidra-interior-" + operation, operation, address=interior_address)
                initial = server.call("rea_static_start", interior)
                actual = server.complete(interior)
                private_write(root / f"interior-{operation}.json", {"request": interior, "initial": initial, "result": actual})
                assert actual["process_succeeded"] is True, actual
                value = json.loads(actual["report"]["stdout"])
                result.setdefault("native_helper_checks", {})["interior_" + operation] = assert_revision_four_cleanup(value, operation == "decompile")
                assert value["function_address_requested"] == interior_address
                assert value["function"]["entry_address"] == leaf and value["function_resolution"] == "containing"
                assert value["function"]["body_ranges_complete"] is True
                ranges = value["function"]["body_ranges"]
                assert value["function"]["body_range_count"] == len(ranges)
                assert any(int(row["min_address"], 16) <= int(interior_address, 16) <= int(row["max_address"], 16) for row in ranges)
                if operation == "decompile":
                    exact = json.loads(decompilation["report"]["stdout"])
                    assert value["c_code"] == exact["c_code"] and value["c_code_sha256"] == exact["c_code_sha256"]
                elif operation == "xrefs":
                    exact = json.loads(json.loads((root / "xrefs-result.json").read_text())["report"]["stdout"])
                    for field in ("incoming_references", "outgoing_references"):
                        assert value[field] == exact[field], field
                result["job_ids"]["interior_" + operation] = initial["job"]["id"]
            result["checks"].append("interior_function_xrefs_and_decompile_resolve_exact_body_and_preserve_original_selector")
            no_function = request("owned-ghidra-no-function", "function", address="0x0")
            initial = server.call("rea_static_start", no_function)
            actual = server.complete(no_function)
            private_write(root / "no-function-refusal.json", {"request": no_function, "initial": initial, "result": actual})
            assert actual["process_succeeded"] is False and actual["report"]["backend_success"] is False, actual
            assert actual["report"]["summary"]["mapping_supported"] is False
            assert "no containing internal analyzed function" in actual["report"]["stderr"]
            result["checks"].append("unmapped_address_is_retained_backend_error_without_successful_facts")
        else:
            interior = request("owned-ghidra-interior", "decompile", address=hex(int(leaf, 16) + 1))
            refused_start = server.call("rea_static_start", interior)
            refused = server.complete(interior)
            private_write(root / "interior-refusal.json", {"request": interior, "initial": refused_start, "result": refused})
            assert refused["process_succeeded"] is False and refused["report"]["backend_success"] is False, refused
            assert refused["report"]["summary"]["mapping_supported"] is False, refused
            assert "exact internal analyzed function entry" in refused["report"]["stderr"], refused
            result["checks"].append("interior_address_is_real_backend_failure_without_successful_facts")
        cancellation = request("owned-ghidra-live-decompiler-cancel", "decompile", cancellation_artifact, cancel_address)
        private_write(root / "cancel-request.json", cancellation)
        active = server.call("rea_static_start", cancellation)
        private_write(root / "cancel-initial-job.json", active)
        result["job_ids"]["cancel"] = active["job"]["id"]
        native = live_native_decompiler(active["job"]["unit"], args.execution_mode, time.monotonic() + 110)
        native["original_group"] = assert_original_group_membership(active["job"], runtime, args.execution_mode, native["owned_processes"])
        private_write(root / "live-native-decompiler.json", native)
        set_fence(root, "frozen")
        assert server.call("rea_static_status", cancellation)["job"]["id"] == active["job"]["id"]
        cancel = server.call("rea_static_cancel", cancellation)
        assert cancel["cancellation_requested"] is True and cancel["termination_confirmed"] is False
        terminal_output = server.complete(cancellation)
        terminal = server.call("rea_static_status", cancellation)
        assert terminal_output["process_succeeded"] is False, terminal_output
        assert terminal["status"]["state"] in ("cancelled", "failed"), terminal
        deadline = time.monotonic() + 10
        for item in native["owned_processes"]:
            while process_identity(item["pid"]) == item["start_time"]:
                assert time.monotonic() < deadline, ("original owned engine descendant survived", item)
                time.sleep(0.05)
        assert server.complete(selected) == decompilation
        set_fence(root, "admitting")
        assert server.call("rea_static_start", cancellation)["job"]["id"] == active["job"]["id"]
        private_write(root / "cancellation-result.json", {"cancel": cancel, "terminal": terminal,
                                                         "result": terminal_output, "original_native": native,
                                                         "all_observed_original_processes_gone": True})
        result["cancel_terminal_state"] = terminal["status"]["state"]
        result["checks"].append("frozen_original_owner_cancel_during_real_native_decompilation_and_no_relaunch")
        assert digest(artifact) == original_hash and digest(cancellation_artifact) == cancellation["artifact_sha256"]
        result["cancel_scratch_cleanup"] = assert_owner_cleanup(terminal_output, terminal, active["job"], root)
        server.close()
        server = Mcp(runtime, root)
        assert server.complete(cancellation) == terminal_output
        assert_owner_cleanup(server.complete(cancellation), server.call("rea_static_status", cancellation), active["job"], root)
        result["checks"].append("cancelled_scratch_cleaned_by_original_owner_and_receipt_survives_controller_restart")

        crashed_request = request("owned-ghidra-live-worker-crash", "decompile", cancellation_artifact, cancel_address)
        crashed_start = server.call("rea_static_start", crashed_request)
        crashed_native = live_native_decompiler(crashed_start["job"]["unit"], args.execution_mode, time.monotonic() + 110)
        crashed_native["original_group"] = assert_original_group_membership(crashed_start["job"], runtime, args.execution_mode, crashed_native["owned_processes"])
        killed = signal_original_worker(crashed_start["job"], runtime, args.execution_mode, signal.SIGKILL)
        crashed_output = server.complete(crashed_request)
        crashed_terminal = server.call("rea_static_status", crashed_request)
        assert crashed_output["process_succeeded"] is False and crashed_terminal["status"]["state"] == "failed"
        crashed_cleanup = assert_owner_cleanup(crashed_output, crashed_terminal, crashed_start["job"], root)
        stopped = assert_original_processes_stopped(crashed_native["owned_processes"] + [killed])
        server.close()
        server = Mcp(runtime, root)
        assert server.complete(crashed_request) == crashed_output
        replay_crashed = server.call("rea_static_start", crashed_request)
        assert replay_crashed["job"]["id"] == crashed_start["job"]["id"] and replay_crashed["reused"] is True
        private_write(root / "worker-crash-result.json", {"request":crashed_request, "initial":crashed_start,
                      "native":crashed_native, "worker_signal":killed, "stopped":stopped,
                      "result":crashed_output, "terminal":crashed_terminal})
        result["job_ids"]["worker_crash"] = crashed_start["job"]["id"]
        result["worker_crash_scratch_cleanup"] = crashed_cleanup
        result["checks"].append("live_native_decompiler_worker_sigkill_original_group_cleanup_and_restart_readback")

        timeout_request = request("owned-ghidra-original-owner-timeout", "decompile", cancellation_artifact, cancel_address)
        timeout_request.update(profile="owned_ghidra_timeout", profile_sha256=admitted_profiles["owned_ghidra_timeout"]["profile_sha256"])
        timeout_start = server.call("rea_static_start", timeout_request)
        timeout_java = wait_source_java(timeout_start["job"], args.execution_mode, timeout=18)
        stopped_worker = signal_original_worker(timeout_start["job"], runtime, args.execution_mode, signal.SIGSTOP)
        # Freeze only this original worker so its in-process deadline cannot
        # win the race. The existing durable owner's 25-second timeout and
        # original-group escalation must terminate it without a harness kill.
        server.close()
        server = Mcp(runtime, root)
        assert server.call("rea_static_status", timeout_request)["job"]["id"] == timeout_start["job"]["id"]
        timeout_output = server.complete(timeout_request)
        timeout_terminal = server.call("rea_static_status", timeout_request)
        assert timeout_output["process_succeeded"] is False and timeout_terminal["status"]["state"] == "timed_out"
        timeout_cleanup = assert_owner_cleanup(timeout_output, timeout_terminal, timeout_start["job"], root)
        timeout_stopped = assert_original_processes_stopped([timeout_java, stopped_worker])
        timeout_replay = server.call("rea_static_start", timeout_request)
        assert timeout_replay["job"]["id"] == timeout_start["job"]["id"] and timeout_replay["reused"] is True
        private_write(root / "owner-timeout-result.json", {"request":timeout_request, "initial":timeout_start,
                      "java":timeout_java, "worker_signal":stopped_worker, "stopped":timeout_stopped,
                      "result":timeout_output, "terminal":timeout_terminal})
        result["job_ids"]["owner_timeout"] = timeout_start["job"]["id"]
        result["timeout_scratch_cleanup"] = timeout_cleanup
        result["checks"].append("live_java_stopped_worker_original_owner_timeout_cleanup_and_restart_readback")
        result["qualified"] = True
    except Exception as error:
        result["qualified"] = False
        result["failure"] = repr(error)
        raise
    finally:
        if server is not None:
            server.close()
        private_write(root / "qualification.json", result)
        print("REA_GHIDRA_ANALYSIS_QUALIFICATION " + json.dumps(result, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
