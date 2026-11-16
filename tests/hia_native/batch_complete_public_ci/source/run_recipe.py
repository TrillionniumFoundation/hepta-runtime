#!/usr/bin/env python3
"""Fresh complete public Batch fixture and zero-execution evidence reread."""
from pathlib import Path
import argparse
import json
import math
import os
import shutil
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from receipt_support import ROOT, PIN, regular, read_json, put, require, process, check_process
import source_check
import read_builds
import read_public
import read_stdio
import lane_guard
import retire_fixture

TARGET = source_check.TARGET
NAMES = ("target-identity", "target-prefetch", "native-build", "original-build", "evidence-controls")
TIMEOUTS = dict.fromkeys(NAMES, 180)
TIMEOUTS["native-build"] = 600
DOMAINS = {"typed-legacy": 417, "typed-modern": 417, "filesystem": 926, "session": 17}
STDIO = {"legacy": 15, "modern": 13}
FLAGS = ("complete_current_sdk_router", "catalog_batch_advertised", "full_async_cancellation_qualified",
    "remote_sftp_qualified", "whole_runtime_replaced")


def commands(producer, hepta, target, rust_bin):
    producer = Path(producer)
    source = producer / "source"
    return {
        "native-build": [str(source / "build_public.py"), "--hepta", hepta, "--output", str(producer / "native")],
        "original-build": [str(source / "original-reference/build_reference.py"), "--rust-bin", rust_bin,
            "--target", target, "--core", str(source / "original-reference/core"), "--output", str(producer / "original")],
        "evidence-controls": [str(source / "check_evidence.py"), "--output", str(producer)],
    }


def check_lane(folder, kind, role, domain, binary, producer, source):
    folder, producer, source = Path(folder), Path(producer), Path(source)
    row = read_json(folder.parent / (folder.name + ".lane.json"))
    report = read_json(folder / "result.json")
    module = "qualify_public.py" if kind == "private" else "qualify_stdio.py"
    relative = ("public" if kind == "private" else "stdio") + "/" + domain + "/" + role
    fixture = producer / "workspaces" / (("private-" if kind == "private" else "stdio-") + domain)
    require(row["schema"] == "hepta.runtime.batch-public-lane-guard.v1" and row["status"] == "PASS"
        and row["execution_kind"] == "in_process_recording_driver" and row["kind"] == kind
        and row["role"] == role and row["domain"] == domain and row["fixture"] == report["fixture"] == str(fixture)
        and row["output"] == str(producer / relative) and row["binary"] == report["binary"]["path"] == str(binary)
        and row["driver"] == module and row["driver_pin"] == PIN(regular(source / module))
        and type(row["owner_pid"]) is int and row["owner_pid"] > 0
        and row["outer_lane_deadline_seconds"] == 180 and row["per_exchange_deadline_seconds"] == 60
        and row["alarm_fired"] is False and row["cleanup_in_recording_driver"] is True
        and read_public.number(row["elapsed_seconds"], 180) and row["elapsed_seconds"] < 180
        and report["elapsed_seconds"] <= row["elapsed_seconds"]
        and row["capture"] == PIN(regular(folder / "result.json")), "complete lane guard and actual capture")
    stdout = None
    for name in ("stdout", "stderr"):
        filename = folder.name + ".lane." + name
        raw = regular(folder.parent / filename)
        require(row[name] == {"path": filename, **PIN(raw)}, "complete lane driver stream")
        if name == "stderr":
            require(raw == b"", "recording-driver diagnostics")
        else:
            stdout = read_public.decode(raw)
    keys = ("status", "role", "domain", "case_count", "completed_cases", "elapsed_seconds") if kind == "private" \
        else ("status", "role", "era", "case_count", "completed_cases")
    require(stdout == {key: report[key] for key in keys}, "actual recording-driver completion stream")
    retire_fixture.verify(folder, report)
    return row


def core(output, *, require_final=True):
    output = Path(output).absolute()
    report = read_json(output / "result.json")
    require(report["schema"] == "hepta.runtime.batch-public-complete-recipe.v1"
        and report["target_commit"] == TARGET
        and report["status"] in (("PASS",) if require_final else ("VERIFYING", "PASS"))
        and report["fresh_original_build"] is True and report["ordinary_public_batch_fixture_qualified"] is True
        and report["new_version_not_lost_private91"] is True and report["lost_private91_evidence_reused"] is False,
        "complete public fixture recipe identity")
    require(all(report[key] is False for key in FLAGS), "fixture qualification boundary inflated")
    source = output / "source"
    profile = source_check.check(source)
    require(profile == source_check.check(ROOT)
        and report["source_profile"] == PIN(regular(source / "source-profile.json")), "executed source snapshot")
    require(report["process_names"] == list(NAMES) and report["private_domains"] == DOMAINS
        and report["stdio_domains"] == STDIO, "complete fixed recipe/process domain")
    producer = Path(report["producer_root"])
    require(producer.is_absolute(), "absolute recipe producer identity")
    expected_commands = commands(producer, report["hepta_root"], report["target_root"], report["rust_bin"])
    records = {}
    for name in NAMES[:-1]:
        row, streams = check_process(output / "processes", name, timeout=TIMEOUTS[name])
        if name in expected_commands:
            require(row["argv"] == [report["python"], "-B", *expected_commands[name]]
                and row["cwd"] == str(producer), "complete build process command/cwd")
        elif name == "target-identity":
            require(row["argv"] == ["git", "-C", report["target_root"], "rev-parse", "HEAD"]
                and row["cwd"] == str(producer) and streams["stdout"] == (TARGET + "\n").encode(),
                "independent current target checkout")
        else:
            require(name == "target-prefetch" and row["argv"] == [str(Path(report["rust_bin"]) / "cargo"), "fetch", "--locked"]
                and row["cwd"] == report["target_root"], "independent target lock prefetch")
        require(row["controlled_env"] == {"PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "PYTHONPATH": ""}
            and streams["stdin"] == b"", "complete recipe environment/input")
        records[name] = (row, streams)
    native = read_builds.native(output / "native", source)
    original = read_builds.original(output / "original", source / "original-reference")
    summaries = {
        "native-build": ("native/BUILD.json", ("status", "actual_hia_compiles", "fresh_member_compiles",
            "reverified_private_members", "graphs")),
        "original-build": ("original/BUILD.json", ("status", "fresh_original_build", "binaries",
            "actual_target_sdk", "actual_target_tokio", "actual_reference_executions")),
    }
    for name, (relative, keys) in summaries.items():
        actual = read_json(output / relative)
        require(read_public.decode(records[name][1]["stdout"]) == {key: actual[key] for key in keys}
            and records[name][1]["stderr"] == b"", "complete actual build-runner output")
    graph = read_json(output / "native/BUILD.json")["graphs"]
    original_binary = original["binaries"]["hepta-batch-sdk-current-original-oracle"]
    original_pin = {key: original_binary[key] for key in ("bytes", "sha256")}
    old_binary = producer / "original/bin/hepta-batch-sdk-current-original-oracle"
    private, stdio = {}, {}
    lane_pid = None
    for kind, domains, result in (("private", DOMAINS, private), ("stdio", STDIO, stdio)):
        graph_kind = "private" if kind == "private" else "public"
        new_binary = producer / "native" / graph[graph_kind]["elf"]
        parent = output / ("public" if kind == "private" else "stdio")
        for domain, count in domains.items():
            left, right = parent / domain / "native", parent / domain / "original"
            for role, folder, binary in (("native", left, new_binary), ("original", right, old_binary)):
                guard = check_lane(folder, kind, role, domain, binary, producer, source)
                lane_pid = guard["owner_pid"] if lane_pid is None else lane_pid
                require(guard["owner_pid"] == lane_pid == report["lane_owner_pid"], "persistent recording-driver owner")
            if kind == "private":
                value = read_public.compare(left, right, source, native_binary=graph[graph_kind]["elf_pin"],
                    original_binary=original_pin)
                require(value["actual_rows_per_provider"] == count, "complete private public-input cohort")
            else:
                value = read_stdio.compare(left, right, source, graph[graph_kind]["elf_pin"], original_pin)
                require(value["actual_exchanges_per_provider"] == count, "complete real stdio cohort")
            require(value == read_json(parent / domain / "comparison.json"), "retained complete comparison differs")
            result[domain] = value
            retired = output / "workspaces" / (("private-" if kind == "private" else "stdio-") + domain)
            require(not retired.exists() and not retired.is_symlink(), "completed live fixture remains in output")
    return {"schema": "hepta.runtime.batch-public-complete-readonly.v1", "status": "PASS",
        "target_commit": TARGET, "fresh_original_build": True, "native_build": native, "original_build": original,
        "private": private, "stdio": stdio, "source_files": len(profile["files"]),
        "actual_runtime_root_processes": 12, "actual_private_rows_per_provider": sum(DOMAINS.values()),
        "actual_stdio_exchanges_per_provider": sum(STDIO.values()), "reader_process_launches": 0,
        "ordinary_public_batch_fixture_qualified": True, **dict.fromkeys(FLAGS, False)}


def verify(output):
    result = core(output)
    output = Path(output)
    report = read_json(output / "result.json")
    row, streams = check_process(output / "processes", "evidence-controls", timeout=180)
    command = commands(report["producer_root"], report["hepta_root"], report["target_root"], report["rust_bin"])["evidence-controls"]
    require(row["argv"] == [report["python"], "-B", *command] and row["cwd"] == report["producer_root"]
        and row["controlled_env"] == {"PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "PYTHONPATH": ""}
        and streams["stdin"] == streams["stderr"] == b"", "actual strict-reader controls process")
    from check_evidence import verify as read_controls
    result["evidence_controls"] = read_controls(output)
    require(read_public.decode(streams["stdout"]) == result["evidence_controls"], "complete strict-control output")
    return result


def run(hepta, target, rust_bin, output):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "fresh native/current Rust recipe is CI-only")
    hepta, target, rust_bin = (Path(value).resolve(strict=True) for value in (hepta, target, rust_bin))
    output = Path(output).absolute()
    source_check.check(ROOT)
    output.mkdir(parents=True, exist_ok=False)
    source_check.snapshot(ROOT, output / "source")
    report = {"schema": "hepta.runtime.batch-public-complete-recipe.v1", "status": "RUNNING",
        "target_commit": TARGET, "producer_root": str(output), "python": sys.executable,
        "hepta_root": str(hepta), "target_root": str(target), "rust_bin": str(rust_bin),
        "source_profile": PIN(regular(ROOT / "source-profile.json")), "process_names": list(NAMES),
        "private_domains": DOMAINS, "stdio_domains": STDIO, "lane_owner_pid": os.getpid(),
        "fresh_original_build": False, "ordinary_public_batch_fixture_qualified": False,
        "new_version_not_lost_private91": True, "lost_private91_evidence_reused": False, **dict.fromkeys(FLAGS, False)}
    put(output / "result.json", report)
    expected_commands = commands(output, str(hepta), str(target), str(rust_bin))
    environment = {"PYTHONPATH": ""}
    try:
        process(output / "processes", "target-identity", ["git", "-C", target, "rev-parse", "HEAD"], cwd=output, env=environment)
        process(output / "processes", "target-prefetch", [rust_bin / "cargo", "fetch", "--locked"], cwd=target, env=environment)
        for name in ("native-build", "original-build"):
            process(output / "processes", name, [sys.executable, "-B", *expected_commands[name]], cwd=output,
                env=environment, timeout=TIMEOUTS[name])
        graphs = read_json(output / "native/BUILD.json")["graphs"]
        old = output / "original/bin/hepta-batch-sdk-current-original-oracle"
        old_pin = PIN(regular(old))
        for kind, domains in (("private", DOMAINS), ("stdio", STDIO)):
            graph_kind = "private" if kind == "private" else "public"
            new = output / "native" / graphs[graph_kind]["elf"]
            for domain in domains:
                parent = output / ("public" if kind == "private" else "stdio") / domain
                fixture = output / "workspaces" / (("private-" if kind == "private" else "stdio-") + domain)
                for role, binary in (("native", new), ("original", old)):
                    folder = parent / role
                    lane_guard.run(kind, role, binary, fixture, folder, domain)
                    if kind == "private":
                        read_public.inspect(folder, ROOT, expected_binary=PIN(regular(binary)))
                    else:
                        read_stdio.inspect(folder, ROOT, PIN(regular(binary)))
                    retire_fixture.retire(folder)
                value = read_public.compare(parent / "native", parent / "original", ROOT,
                    native_binary=graphs[graph_kind]["elf_pin"], original_binary=old_pin) if kind == "private" \
                    else read_stdio.compare(parent / "native", parent / "original", ROOT,
                        graphs[graph_kind]["elf_pin"], old_pin)
                put(parent / "comparison.json", value)
        report.update(status="VERIFYING", fresh_original_build=True, ordinary_public_batch_fixture_qualified=True)
        put(output / "result.json", report)
        checked = core(output, require_final=False)
        put(output / "core-verification.json", checked)
        process(output / "processes", "evidence-controls", [sys.executable, "-B", *expected_commands["evidence-controls"]],
            cwd=output, env=environment, timeout=180)
        report.update(status="PASS")
        put(output / "result.json", report)
        result = verify(output)
        put(output / "verification.json", result)
        # The exact executed binary remains in both admitted paths. Only this
        # isolated, completed Cargo target's non-evidence intermediates retire.
        binary = regular(output / "original/target/release/hepta-batch-sdk-current-original-oracle")
        target_dir = output / "original/target"
        require(target_dir.resolve(strict=True) == target_dir, "owned Rust intermediates directory")
        shutil.rmtree(target_dir)
        (target_dir / "release").mkdir(parents=True)
        (target_dir / "release/hepta-batch-sdk-current-original-oracle").write_bytes(binary)
        require(verify(output) == result, "intermediate retirement changed admitted evidence")
        return result
    except BaseException as error:
        report.update(status="FAIL", failure=repr(error))
        put(output / "result.json", report)
        raise


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase", choices=("all", "core", "verify"), required=True)
    p.add_argument("--hepta", type=Path)
    p.add_argument("--target", type=Path)
    p.add_argument("--rust-bin", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = run(a.hepta, a.target, a.rust_bin, a.output) if a.phase == "all" else \
        core(a.output, require_final=False) if a.phase == "core" else verify(a.output)
    print(json.dumps({"status": "BATCH_PUBLIC_COMPLETE_FIXTURE_PASS", "fresh_original_build": result["fresh_original_build"],
        "actual_private_rows_per_provider": result["actual_private_rows_per_provider"],
        "actual_stdio_exchanges_per_provider": result["actual_stdio_exchanges_per_provider"],
        "actual_runtime_root_processes": result["actual_runtime_root_processes"],
        "reader_process_launches": result["reader_process_launches"],
        "ordinary_public_batch_fixture_qualified": True, **dict.fromkeys(FLAGS, False)}, sort_keys=True))
