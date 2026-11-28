#!/usr/bin/env python3
"""Separately budgeted actual-executable identity recovery negative control.

Run only after the unchanged primary MCP protocol has passed. A private ELF copy
retains every original byte and receives one non-loaded trailing marker. The
original CI package stays immutable. Recovery must reject new model work because
the complete executable hash differs while its original time/boot window is live.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
PRIMARY_SHA = "283e535c10a2065e797baf44c9232db3adac26d09fa6c47c285ce855fd1cc198"
primary_path = HERE / "late_quote_mcp.py"
if hashlib.sha256(primary_path.read_bytes()).hexdigest() != PRIMARY_SHA:
    raise ValueError("frozen primary driver identity differs")
spec = importlib.util.spec_from_file_location("qualified_late_quote_driver", primary_path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
t, require = m.t, m.require
MARKER = b"\nHEPTA_OWNED_EXE_IDENTITY_NEGATIVE_CONTROL_V1\n"
BUDGET = {
    "server_starts": 2, "rpc_wire_calls": 12, "tool_calls": 5,
    "roundtrip_wire_calls": 1, "roundtrip_new_intents": 1,
    "recover_wire_calls": 2, "crash_attempts": 1,
    "complete_and_partial_forward_upper_bound": 5,
    "pure_compiler_invocation_upper_bound": 2,
    "wall_seconds": 180, "server_cpu_seconds": 60,
    "server_address_space_bytes": 2 * 1024**3,
    "server_tokio_worker_threads": 2, "optimizer_steps": 0,
    "automatic_retry": False,
}
t.BUDGET = BUDGET


def digest_stream(stream, size):
    h = hashlib.sha256()
    while size:
        part = stream.read(min(size, 1024 * 1024))
        require(bool(part), "short executable read")
        size -= len(part)
        h.update(part)
    return h.hexdigest()


def executable_pin(path, prefix_bytes=None):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, "canonical executable required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and 0 < before.st_size <= 512 * 1024**2 and os.access(path, os.X_OK),
                "owned bounded executable required")
        with os.fdopen(fd, "rb", closefd=False) as f:
            whole = digest_stream(f, before.st_size)
            f.seek(0)
            header = f.read(64)
            require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01", "ELF64 little-endian executable required")
            fields = struct.unpack("<16sHHIQQQIHHHHHH", header)
            _, kind, machine, version, entry, phoff, _, _, ehsize, phsize, phnum, _, _, _ = fields
            require(kind in (2, 3) and machine == 62 and version == 1 and ehsize == 64
                    and phsize == 56 and 1 <= phnum <= 256
                    and phoff + phnum * phsize <= before.st_size, "bounded x86-64 ELF program headers required")
            f.seek(phoff)
            table = f.read(phnum * phsize)
            require(len(table) == phnum * phsize, "short program header table")
            segments = []
            for i in range(phnum):
                ptype, flags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", table, i * phsize)
                if ptype != 1:
                    continue
                require(filesz <= memsz and offset + filesz <= before.st_size, "invalid load segment")
                f.seek(offset)
                segments.append({"index": i, "flags": flags, "offset": offset, "virtual_address": vaddr,
                                 "physical_address": paddr, "file_bytes": filesz, "memory_bytes": memsz,
                                 "alignment": align, "sha256": digest_stream(f, filesz)})
            require(bool(segments), "no ELF load segments")
            result = {"path": str(path), "bytes": before.st_size, "sha256": whole,
                      "elf_header_sha256": t.digest(header), "program_headers_sha256": t.digest(table),
                      "entry_point": entry, "load_segments": segments}
            if prefix_bytes is not None:
                require(0 < prefix_bytes <= before.st_size, "invalid original prefix")
                f.seek(0)
                result["original_prefix_bytes"] = prefix_bytes
                result["original_prefix_sha256"] = digest_stream(f, prefix_bytes)
                result["trailing_bytes_sha256"] = t.digest(f.read())
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "executable changed during inspection")
        return result
    finally:
        os.close(fd)


def append_private_copy(original, destination):
    source = executable_pin(original)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o700)
    try:
        with open(original, "rb") as src, os.fdopen(fd, "wb", closefd=False) as out:
            while block := src.read(1024 * 1024):
                out.write(block)
            out.write(MARKER)
            out.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    shadow = executable_pin(destination, source["bytes"])
    require(executable_pin(original) == source, "original CI executable changed")
    require(shadow["sha256"] != source["sha256"] and shadow["bytes"] == source["bytes"] + len(MARKER)
            and shadow["original_prefix_sha256"] == source["sha256"]
            and shadow["trailing_bytes_sha256"] == t.digest(MARKER), "private marker copy differs")
    for field in ("elf_header_sha256", "program_headers_sha256", "entry_point", "load_segments"):
        require(source[field] == shadow[field], "loaded ELF code or metadata changed")
    require(all(row["offset"] + row["file_bytes"] <= source["bytes"] for row in shadow["load_segments"]),
            "marker is included in a loaded ELF segment")
    return {"original": source, "negative_control_copy": shadow,
            "all_original_file_bytes_unchanged": True, "all_load_segments_unchanged": True,
            "marker_outside_load_segments": True, "qualified_release_modified": False,
            "copy_is_not_a_new_ci_qualified_binary": True}


def window_sample(saved, minimum_remaining_seconds=0):
    with open("/proc/sys/kernel/random/boot_id", "rb") as f:
        raw = f.read(65)
    require(len(raw) <= 64, "native boot ID read exceeded bound")
    boot = raw.decode("ascii").strip()
    now_boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    now_wall = time.time_ns() // 1_000_000
    original = saved["native_boot_clock"]
    elapsed = now_boot - original["boottime_nanoseconds"]
    wall_left = saved["expires_unix_ms"] - now_wall
    boot_left = 60_000_000_000 - elapsed
    require(boot == original["boot_id"] and 0 <= elapsed < 60_000_000_000
            and saved["created_unix_ms"] <= now_wall < saved["expires_unix_ms"]
            and min(wall_left / 1000, boot_left / 1e9) > minimum_remaining_seconds,
            "same-boot original window is no longer live; identity causal control failed")
    return {"boot_id": boot, "boottime_nanoseconds": now_boot, "unix_ms": now_wall,
            "original_wall_remaining_ms": wall_left, "original_boottime_remaining_ns": boot_left,
            "minimum_required_remaining_seconds": minimum_remaining_seconds}


def process_executable(server, expected):
    process = server.process
    require(process.poll() is None, "owned process is no longer live")
    path = Path("/proc") / str(process.pid) / "exe"
    target = str(path.resolve(strict=True))
    require(target == expected["path"], "owned process loaded a different executable")
    with open(path, "rb") as f:
        info = os.fstat(f.fileno())
        require(info.st_size == expected["bytes"], "loaded executable size differs")
        sha = digest_stream(f, info.st_size)
    require(sha == expected["sha256"] and process.poll() is None, "actual loaded executable hash differs")
    return {"owned_pid": process.pid, "proc_exe_target": target, "actual_exe_sha256": sha,
            "actual_exe_bytes": info.st_size}


def plan(args):
    root = args.root.resolve(strict=True)
    require(root == args.root and stat.S_IMODE(root.stat().st_mode) == 0o700
            and root.stat().st_uid == os.geteuid() and sys.platform == "linux", "owned canonical Linux 0700 root required")
    require(not any(root.iterdir()), "fresh isolated negative-control root required")
    admission = t.parse(t.read(args.ci_admission))
    require(admission["schema"] == "hepta.late-quote.operator-ci-admission.v1"
            and admission["exact_head_conclusion"] == "success"
            and admission["prospective_merge_conclusion"] == "success", "both actual CI lanes must pass")
    identity = t.package_check(args.binary, args.package_manifest, admission["source_commit"], admission["source_tree"])
    require(all(identity[key] == admission[key] for key in ("binary_sha256", "package_manifest_sha256"))
            and str(identity["ci_run_id"]) == str(admission["ci_run_id"]), "original admission differs")
    primary = t.parse(t.read(args.primary_result, private=True))
    require(primary["status"] == "PASS" and primary["ci_identity"] == identity
            and primary["full_function_inverse_verified"] is True, "unchanged primary qualification must pass first")
    for name in ("workspace", "state", "credentials", "evidence", "negative-control-bin"):
        (root / name).mkdir(mode=0o700)
    t.write_bytes_once(root / "credentials" / "operator-a.token", secrets.token_hex(32).encode())
    policy = {"state_dir": str(root / "state"), "controller_workspace_roots": [str(root / "workspace")],
              "hosts": {"denied": {"ssh_target": "never-connect-exe-identity-control",
                  "remote_state_dir": str(root / "no-remote"), "allow_execute": False,
                  "allow_pty": False, "allow_write": False, "allow_job_network": False}}}
    policy_sha = t.write_once(root / "policy.json", policy)
    case = m.case_from_cli("same-sha-identity-control", args.case.resolve(strict=True), root)
    copy = append_private_copy(args.binary, root / "negative-control-bin" / "hepta-runtime-marker")
    sockets = [socket.socket(), socket.socket()]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        ports = [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()
    value = {"schema": "hepta.late-quote.executable-negative-control-plan.v1", "root": str(root),
             "binary": str(args.binary), "package_manifest": str(args.package_manifest), "identity": identity,
             "ci_admission": m.file_pin(args.ci_admission), "primary_result": m.file_pin(args.primary_result),
             "driver": m.file_pin(Path(__file__)), "primary_driver": m.file_pin(primary_path),
             "transport": m.file_pin(m.transport), "copy_inspection": copy,
             "case": case, "ports": ports, "policy_sha256": policy_sha, "budget": BUDGET,
             "prepared_without_native_execution": True, "separate_from_primary_forward_budget": True,
             "causal_guard": "same boot, unchanged loaded ELF bytes/source, both original clocks live before and after recovery, Restored uncharged; actual complete executable SHA must be the only changed guard"}
    sha = t.write_once(root / "plan.json", value)
    print(json.dumps({"plan": str(root / "plan.json"), "sha256": sha, "native_execution_performed": False}))


def run(args):
    raw = t.read(args.plan)
    require(t.digest(raw) == args.plan_sha256, "negative-control plan changed")
    p = t.parse(raw)
    require(p["schema"] == "hepta.late-quote.executable-negative-control-plan.v1" and p["budget"] == BUDGET,
            "wrong independent protocol/budget")
    root = Path(p["root"])
    require(args.plan.parent == root and root.is_absolute() and root.resolve(strict=True) == root, "canonical root changed")
    for directory in (root, *(root / name for name in ("workspace", "state", "credentials", "evidence", "negative-control-bin"))):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and directory.resolve(strict=True) == directory
                and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(), "owned private directory changed")
    require(not any((root / "state").iterdir()) and not any((root / "evidence").iterdir()), "uncertain execution may not restart")
    require(len(p["ports"]) == 2 and len(set(p["ports"])) == 2
            and all(type(port) is int and 1024 <= port <= 65535 for port in p["ports"]), "two distinct loopback ports required")
    for name in ("driver", "primary_driver", "transport", "ci_admission", "primary_result"):
        m.pinned(p[name])
    require(t.digest(t.read(root / "policy.json")) == p["policy_sha256"], "fixed denied-remote policy changed")
    require(t.package_check(Path(p["binary"]), Path(p["package_manifest"]), p["identity"]["source_commit"],
                            p["identity"]["source_tree"]) == p["identity"], "original qualified release changed")
    copy = p["copy_inspection"]
    require(executable_pin(copy["original"]["path"]) == copy["original"]
            and executable_pin(copy["negative_control_copy"]["path"], copy["original"]["bytes"])
            == copy["negative_control_copy"], "prepared executable identities changed")
    case = p["case"]
    for pin in case["original_inputs"].values():
        m.pinned(pin)
    require(t.digest(t.read(Path(case["source_path"]), private=True)) == case["parent_sha256"], "owned source differs")
    token = t.read(root / "credentials" / "operator-a.token", private=True).decode()
    require(len(token) == 64 and all(c in "0123456789abcdef" for c in token), "private owner token shape")
    rec = t.Recorder(root, p, {"a": token})
    rec.record("execution-intent.json", {"plan_sha256": args.plan_sha256, "budget": BUDGET,
               "primary_protocol_unchanged": True, "negative_control_only": True})
    servers, failure = [], None
    result = {"status": "INCOMPLETE", "separate_from_primary_forward_budget": True,
              "scientific_holdout_claim": False, "copy_is_not_a_ci_qualified_binary": True}
    try:
        first = t.Server(rec, "original-qualified", "a", p["ports"][0]); servers.append(first)
        original_process = process_executable(first, copy["original"])
        client = m.Client(first, "client")
        opened = m.prepare(client, case)
        boundary = m.crash_once(first, client, case, opened)
        require(boundary["phase_records_before_kill"]["late-restored-charge.json"] is None
                and boundary["phase_records_before_kill"]["late-restored-result.json"] is None,
                "Restored already charged, so executable identity would not be isolated")
        directory = root / "state" / "weight-cohort-journal-v1" / opened["prepared"]["journal_id"]
        saved = t.parse(t.read(directory / "late-intent.json", private=True))
        require(saved["plan"]["running_executable_sha256"] == copy["original"]["sha256"]
                and saved["plan"]["evaluator_source"] == opened["prepared"]["parent_function"]["evaluator_source_sha256"],
                "original durable source/executable identity differs")
        before_start = window_sample(saved, 20)
        rec.plan = dict(p, binary=copy["negative_control_copy"]["path"])
        changed = t.Server(rec, "changed-exe-recovery", "a", p["ports"][1]); servers.append(changed)
        changed_process = process_executable(changed, copy["negative_control_copy"])
        changed_client = m.Client(changed, "client")
        before = window_sample(saved, 15)
        rec.record("causal-guard-before-recovery.json", {"original_process": original_process,
                   "changed_process": changed_process, "before_start": before_start, "before_recovery": before,
                   "restored_phase_originally_uncharged": True, "original_elf_bytes_and_source_unchanged": True})
        recovered = m.recover_case(changed_client, case, opened, 0)
        after = window_sample(saved)
        errors = recovered["errors"]
        require(len(errors) == 1 and errors[0]["stage"] == "original_window_restored_forward"
                and errors[0]["error"] == "saved source or executable differs; inverse only, no new model work",
                "recovery was not refused specifically by the executable/source guard")
        require(recovered["research_roundtrip_verified"] is False
                and recovered["fresh_restored_complete_outputs_equal"] is False
                and recovered["restored_evaluation"] is None
                and recovered["reused_original_result"] is False,
                "identity drift recovery falsely claimed new model qualification")
        for name, old_sha in boundary["phase_records_before_kill"].items():
            path = directory / name
            new_sha = t.digest(t.read(path, private=True)) if path.exists() else None
            require(new_sha == old_sha, "identity drift recovery charged/replayed a model phase")
        rec.record("identity-drift-recovery.json", {"result": recovered, "window_after_recovery": after,
                   "new_forward_calls": 0, "new_phase_charges": 0, "inverse_only": True})
        before_effects = m.effects(root)
        repeated = m.recover_case(changed_client, case, opened, 0)
        require(m.effects(root) == before_effects, "repeat identity-drift recovery rewrote durable weight state")
        rec.record("repeat-recovery.json", repeated)
        completed = recovered["attempt_ledger"]["completed_forward_calls_with_durable_results"]
        require(completed <= BUDGET["complete_and_partial_forward_upper_bound"], "independent forward cap exceeded")
        result.update(status="PASS", source_identity=p["identity"], executable_copy_inspection=copy,
                      actual_original_process=original_process, actual_changed_process=changed_process,
                      windows={"before_start": before_start, "before_recovery": before, "after_recovery": after},
                      no_new_model_forward_or_charge_due_to_executable_identity=True,
                      weights_graph_route_initial_state_and_evaluator_restored=True,
                      all_previous_phase_files_unchanged=True, complete_forward_results_observed=completed,
                      charged_partial_forward_work_may_be_unobserved=recovered["attempt_ledger"]["unobserved_partial_work_possible"],
                      source_bound_complete_and_partial_forward_upper_bound=5,
                      compiler_invocations_prepare_plus_first_roundtrip=2,
                      prepare_preflight_seconds=opened["prepared"]["source_admission_and_preparation_wall_seconds"],
                      roundtrip_preflight_seconds=saved["preparation_wall_seconds"], optimizer_steps=0,
                      actual_sigkill_count=1, original_qualified_executable_unchanged=True,
                      live_service_or_model_activated=False)
    except BaseException as error:
        failure = error
        result.update(status="FAIL_OR_INCOMPLETE", error_type=type(error).__name__, message=str(error), automatic_retry=False)
    finally:
        cleanup = []
        shutdowns = []
        for item in reversed(servers):
            try:
                item.stop(kill=result["status"] != "PASS")
            except BaseException as error:
                cleanup.append({"stage": "stop", "server": item.label, "error": type(error).__name__, "message": str(error)})
        for item in servers:
            try:
                shutdowns.append(t.parse(t.read(rec.evidence_root / (item.label + "-shutdown.json"))))
            except BaseException as error:
                cleanup.append({"stage": "shutdown_receipt", "server": item.label, "error": type(error).__name__})
        try:
            require(executable_pin(copy["original"]["path"]) == copy["original"], "original qualified executable changed")
        except BaseException as error:
            cleanup.append({"stage": "original_immutable", "error": type(error).__name__, "message": str(error)})
        sigkills = sum(row["signals_sent"].count("SIGKILL") for row in shutdowns)
        if result["status"] == "PASS" and sigkills != 1:
            cleanup.append({"stage": "signals", "message": "exactly one actual owned SIGKILL required"})
        if cleanup:
            result.update(status="FAIL_OR_INCOMPLETE", cleanup_errors=cleanup)
        result.update(actual_request_counts=rec.counts, observed_owned_process_sigkill_count=sigkills,
                      observed_total_wall_seconds=time.monotonic() - rec.started, budget=BUDGET)
        rec.record("RESULT.json", result)
    if failure is not None:
        raise failure
    require(result["status"] == "PASS", "independent owned-process cleanup did not qualify")
    print(json.dumps({"status": "PASS", "result": str(rec.evidence_root / "RESULT.json"), "new_recovery_forwards": 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("plan")
    for name in ("root", "binary", "package-manifest", "ci-admission", "primary-result", "case"):
        p.add_argument("--" + name, type=Path, required=True)
    p.set_defaults(function=plan)
    p = commands.add_parser("run")
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--plan-sha256", required=True)
    p.set_defaults(function=run)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
