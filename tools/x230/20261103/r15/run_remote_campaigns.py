#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run two arena1 native ABBA campaigns and one six-host recovery after a pinned successful local report.
The caller must hold forwarded SSH_AUTH_SOCK until this foreground process exits.
New persistent evidence stays in R15; three approved private socket parents are
temporary. No compilation, stage/RPC retry, service mutation, or remote cleanup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
import run_local_campaigns as pipeline

ROOT, HERE, QUAL, SOURCE = pipeline.ROOT, pipeline.HERE, pipeline.QUAL, pipeline.SOURCE
OUT = ROOT / "remote-campaigns-01"
READY = ROOT / "independent-audit-tools/remote-orchestrator-ready-01.json"
LOCAL_READY_SHA = "f321182f6bd94b948b22948e524b5eaa0c42d08436e49ed9bf778f8a27196960"
LOCAL_SCRIPT_SHA = "c7c25cdf0edc705f254101e89ef4786e54f744ed34097ff5fc9a6957d01f8508"
PROFILE = Path("/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json")
PROFILE_SHA = "fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08"
FROZEN = Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01")
FROZEN_SHA = {
    "1a16a4035ad-b1270-1.json": "a8982325aea4833461e2b6a76ca83f846b80b99a227298e97a0b279e2d9dfdb8",
    "1a16a403e55-b1270-2.json": "bbb8a86161837ff0f197b345c25bc66224e3404473dea2ac46d1f44f3af43609",
    "1a16a4046ac-b1270-3.json": "4badc323518a6db1567162a2d7ef5d1209aa88375aba201ec6f3aab34bec61a8",
    "1a16a40534e-b1270-4.json": "79e18b1a42d84f8024b692dfd98a9f06fa1d6886bf5dc230248cfbde674f011c",
    "1a16a405d21-b1270-5.json": "9c89c598f35f6bc94572852fcc03feed6e8c798ee34db5095bd3b48813562dc6",
    "1a16a40671b-b1270-6.json": "5b737330fa5a75a458138e1848a044d2a77c062175d8eb9694a510ff20b53cde"}
NATIVE_OUTPUTS = {version: ROOT / ("native-" + version + "-r15-01") for version in ("r14", "r11")}
RECOVERY = ROOT / "cancel-recovery-01"
SOCKET_PARENTS = {"r14": Path("/home/qian/h15n1"), "r11": Path("/home/qian/h15n2"),
                  "recovery": Path("/home/qian/h15c1")}
SOCKET_IDENTITIES = {}


def socket_identity(path):
    info = path.lstat()
    pipeline.require(path.resolve() == path and stat.S_ISDIR(info.st_mode)
                     and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                     "socket parent is not a direct account-owned private directory")
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)}


def create_socket_parent(key):
    path = SOCKET_PARENTS[key]
    pipeline.require(not os.path.lexists(path), "socket parent already exists; no reuse")
    pipeline.require(len(os.fsencode(path)) + 49 + 9 + 17 + 1 <= 108,
                     "OpenSSH temporary socket path budget exceeded")
    path.mkdir(mode=0o700, exist_ok=False)
    SOCKET_IDENTITIES[key] = socket_identity(path)
    pipeline.REPORT.setdefault("socket_parents", {})[key] = {"path": str(path), **SOCKET_IDENTITIES[key]}
    pipeline.save()
    return path


def retire_empty_socket_parents():
    result = []
    for key, original in SOCKET_IDENTITIES.items():
        path = SOCKET_PARENTS[key]
        item = {"path": str(path), "created_identity": original, "removed_empty": False}
        try:
            pipeline.require(socket_identity(path) == original, "created socket-parent identity changed")
            children = list(path.iterdir())
            item["remaining_entry_names"] = sorted(p.name for p in children)
            if not children:
                path.rmdir()
                item["removed_empty"] = True
            else:
                item["retained_reason"] = "Only empty owned parents are removed; retained entries are not guessed or signalled."
        except (OSError, RuntimeError) as error:
            item["cleanup_error"] = type(error).__name__ + ": " + str(error)
        result.append(item)
    return result


def native_commands(version):
    directory = NATIVE_OUTPUTS[version]
    return [
        ("native-" + version + "-r15", [
            "/usr/bin/python3", "-B", str(HERE / "run_native_observation.py"),
            "--baseline", str(pipeline.BASELINES[version][0] / "hepta-runtime"),
            "--candidate", str(QUAL / "hepta-runtime"), "--candidate-arena-max", "1",
            "--profile-template", str(PROFILE), "--frozen-jobs", str(FROZEN),
            "--socket-parent", str(SOCKET_PARENTS[version]), "--out", str(directory),
            "--calls", "96", "--concurrency", "1", "4", "8", "--workers", "2",
            "--order", "ABBA", "--warmup-calls", "24"], 1800),
        ("analyze-native-" + version + "-r15", [
            "/usr/bin/python3", "-B", str(HERE / "analyze_native_observation.py"),
            "--report", str(directory / "report.json"), "--output",
            str(directory / "independent-summary.json")], 180)]


def recovery_commands():
    return [
        ("six-host-cancel-recovery", [
            "/usr/bin/python3", "-B", str(HERE / "run_six_host_cancel_recovery.py"),
            "--candidate", str(QUAL / "hepta-runtime"), "--candidate-arena-max", "1",
            "--profile-template", str(PROFILE), "--frozen-jobs", str(FROZEN),
            "--socket-parent", str(SOCKET_PARENTS["recovery"]), "--out", str(RECOVERY),
            "--workers", "2", "--interrupt-host", "rog"], 900),
        ("verify-six-host-cancel-recovery", [
            "/usr/bin/python3", "-B", str(HERE / "verify_cancel_recovery.py"),
            "--report", str(RECOVERY / "report.json"), "--output",
            str(RECOVERY / "independent-summary.json")], 180)]


def verify_remote_ready(expected):
    ready = pipeline.bound_json(READY, expected, "remote-orchestrator-ready.json")
    pipeline.require(ready.get("success") is True and ready.get("formal_workloads_started") is False
                     and ready["local_orchestrator_ready_sha256"] == LOCAL_READY_SHA,
                     "remote orchestration manifest differs")
    pipeline.require(len(ready["files"]) == 1 and ready["files"][0]["path"] == str(Path(__file__).resolve()),
                     "unexpected remote orchestration entry")
    pipeline.bind(ready["files"][0]["path"], ready["files"][0]["sha256"])
    pipeline.bind(HERE / "run_local_campaigns.py", LOCAL_SCRIPT_SHA)


def verify_local_gate(expected):
    path = ROOT / "local-campaigns-01/report.json"
    local = pipeline.bound_json(path, expected, "local-campaigns.json")
    pipeline.require(local.get("schema") == "hepta-x230-r15-local-campaigns/v1"
                     and local.get("success") is True and local.get("finished_utc")
                     and local.get("state") == "completed" and not local.get("error")
                     and local.get("automatic_retries") == 0
                     and local.get("compilation_started") is False
                     and local.get("local_orchestrator_ready_sha256") == LOCAL_READY_SHA,
                     "local pipeline is not terminal, successful, and reviewed")
    expected_stages = [name for name, unused, timeout in
        pipeline.qualification_commands() + pipeline.cancel_commands("r14") + pipeline.cancel_commands("r11")]
    pipeline.require([s["name"] for s in local["stages"]] == expected_stages
                     and all(s.get("returncode") == 0 for s in local["stages"]),
                     "not all six local stages passed")
    qualification_binding = local["configuration_qualification"]
    pipeline.require(qualification_binding["path"] == str(pipeline.CONFIG_QUAL / "report.json"),
                     "configuration qualification path differs")
    configuration = pipeline.bound_json(qualification_binding["path"], qualification_binding["sha256"],
                                       "configuration-qualification.json")
    pipeline.require(configuration.get("success") is True and configuration["runtime_sha256"] == pipeline.CANDIDATE_SHA
                     and configuration["local_orchestrator_ready_sha256"] == LOCAL_READY_SHA
                     and configuration["configuration_ready_sha256"] == pipeline.CONFIG_READY_SHA
                     and configuration["tooling_install_sha256"] == pipeline.TOOLING_SHA
                     and configuration["allocator_environment"] == {"MALLOC_ARENA_MAX": "1"}
                     and configuration["tests"] == {"passed": 1637, "failed": 0, "ignored": 33, "selected": 1670, "retries": 0},
                     "arena1 complete configuration qualification differs")
    for field in ("summary", "audit"):
        pipeline.bind(configuration[field]["path"], configuration[field]["sha256"])
    gate = local["performance_gate_wait"]
    pipeline.require(gate.get("passed") is True and gate.get("wait_attempts") == 1
                     and gate["gate"]["path"] == str(pipeline.PERF_GATE), "local performance gate was not passed once")
    release = pipeline.bound_json(pipeline.PERF_GATE, gate["gate"]["sha256"], "performance-release.json")
    pipeline.validate_perf_gate(release, qualification_binding["sha256"], LOCAL_READY_SHA)
    expected_paths = {str(directory / name) for directory in pipeline.CAMPAIGNS.values()
                      for name in ("report.json", "independent-summary.json", "independent-summary.md")}
    pipeline.require({item["path"] for item in local["retained_result_files"]} == expected_paths,
                     "local campaign result list is incomplete")
    for item in local["retained_result_files"]:
        pipeline.bind(item["path"], item["sha256"])
    for version in ("r14", "r11"):
        pipeline.validate_cancel(version)
    pipeline.REPORT["local_gate"] = {"path": str(path), "sha256": expected, "success": True,
                                    "configuration_qualification_sha256": qualification_binding["sha256"]}
    pipeline.REPORT["configuration_qualification"] = qualification_binding
    return local, configuration


def bind_remote_inputs():
    profile = pipeline.bound_json(PROFILE, PROFILE_SHA, "profile-template.json")
    for name in ("ssh_config", "known_hosts"):
        pipeline.bind(profile[name], profile[name + "_sha256"])
    pipeline.require({path.name for path in FROZEN.glob("*.json")} == set(FROZEN_SHA),
                     "six frozen original descriptors differ")
    for name, expected in FROZEN_SHA.items():
        pipeline.bind(FROZEN / name, expected)
    pipeline.REPORT["remote_input_bindings"] = {"profile_sha256": PROFILE_SHA, "frozen_original_sha256": FROZEN_SHA}


def validate_native(version):
    directory = NATIVE_OUTPUTS[version]
    raw_path, summary_path = directory / "report.json", directory / "independent-summary.json"
    raw, summary = json.loads(raw_path.read_bytes()), json.loads(summary_path.read_bytes())
    expected = {"A": pipeline.BASELINES[version][1], "B": pipeline.CANDIDATE_SHA}
    pipeline.require(raw.get("passed") is True and raw["binary_sha256"] == expected
                     and summary.get("verified") is True and summary["binary_sha256"] == expected
                     and summary["original_sha256"] == pipeline.sha(raw_path)
                     and summary["measured_calls"] == 1152 and summary["warmup_calls"] == 288
                     and summary["preflight_restart_calls"] == 72 and summary["total_calls"] == 1512
                     and summary["failed_calls"] == 0
                     and summary["allocator_environment_verification"]["verified"] is True
                     and summary["allocator_environment_verification"]["controllers_with_live_environment"] == 8
                     and [item["concurrency"] for item in summary["cases"]] == [1, 4, 8],
                     "native complete matrix/counts/independent summary differ")
    variants = raw["allocator_configuration"]["variants"]
    pipeline.require(variants["A"]["environment"] == {}
                     and variants["B"]["environment"] == {"MALLOC_ARENA_MAX": "1"},
                     "native allocator comparison differs")
    for path in (raw_path, summary_path):
        pipeline.bind(path)
    pipeline.REPORT.setdefault("native_results", {})[version] = {
        "raw": pipeline.record(raw_path), "analysis": pipeline.record(summary_path),
        "binary_sha256": expected, "allocator_environment_verification": summary["allocator_environment_verification"],
        "transport_envelope_limit": "DTO and response hashes are retained without complete envelope bodies; no independent envelope rehash is claimed."}
    pipeline.save()


def validate_recovery():
    raw_path, summary_path = RECOVERY / "report.json", RECOVERY / "independent-summary.json"
    raw, summary = json.loads(raw_path.read_bytes()), json.loads(summary_path.read_bytes())
    pipeline.require(raw.get("passed") is True and summary.get("verified") is True
                     and raw["candidate_sha256"] == summary["candidate_sha256"] == pipeline.CANDIDATE_SHA
                     and summary["source_sha256"] == pipeline.sha(raw_path)
                     and summary["native_calls"] == 90 and summary["independent_ssh_calls"] == 36
                     and summary["new_starts"] == 6 and summary["same_key_lookups"] == 12
                     and summary["cancellations"] == 12 and summary["automatic_rpc_retries"] == 0
                     and summary["allocator_environment_verification"]["verified"] is True
                     and summary["allocator_environment_verification"]["controllers_with_live_environment"] == 3
                     and len(summary["hosts"]) == 6
                     and all(item["execution_count"] == 1 and item["restart_terminal_bytes_unchanged"] is True
                             for item in summary["hosts"].values())
                     and raw["allocator_configuration"]["variants"]["candidate"]["environment"] == {"MALLOC_ARENA_MAX": "1"},
                     "six-host arena1 recovery completeness/binding differs")
    for path in (raw_path, summary_path):
        pipeline.bind(path)
    pipeline.REPORT["recovery_result"] = {"raw": pipeline.record(raw_path), "analysis": pipeline.record(summary_path),
        "native_calls": 90, "independent_ssh_calls": 36, "new_starts": 6, "same_key_lookups": 12,
        "cancellations": 12, "allocator_environment_verification": summary["allocator_environment_verification"]}
    pipeline.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-ready-sha256", required=True)
    parser.add_argument("--local-report-sha256", required=True,
                        help="SHA256 of the completed successful local report; no waiting/retry")
    args = parser.parse_args()
    os.umask(0o077)
    pipeline.require(ROOT.resolve() == ROOT, "R15 root is not direct")
    OUT.mkdir(mode=0o700, exist_ok=False)
    (OUT / "logs").mkdir(mode=0o700)
    (OUT / "bindings").mkdir(mode=0o700)
    pipeline.OUT = OUT
    pipeline.REPORT.clear()
    pipeline.BOUND.clear()
    report = pipeline.REPORT
    started = time.monotonic()
    report.update({"schema": "hepta-x230-r15-remote-campaigns/v1", "success": False, "state": "preflight",
        "started_utc": pipeline.utc(), "driver_sha256": pipeline.sha(__file__),
        "driver_process": pipeline.proc_info(os.getpid()), "source": str(SOURCE),
        "qualification": str(QUAL / "report.json"), "remote_orchestrator_ready_sha256": args.expected_ready_sha256,
        "expected_local_report_sha256": args.local_report_sha256,
        "automatic_retries": 0, "compilation_started": False, "rust_source_modified": False,
        "production_service_mutations": 0, "remote_cleanup_operations": 0,
        "candidate_allocator_environment": {"MALLOC_ARENA_MAX": "1"},
        "stages": [], "environment_before": pipeline.telemetry(),
        "remote_effect_scope": "Two read-only observation ABBA blocks; then six fresh private canary jobs, own controller crash, same-key reuse, concurrent cancellation and own ROG transport interruption.",
        "monitor_scope": "Five-second compiler/known competing optimization/archive snapshots; cannot rule out all background activity."})
    pipeline.save()
    try:
        verify_remote_ready(args.expected_ready_sha256)
        local, configuration = verify_local_gate(args.local_report_sha256)
        pipeline.require(not pipeline.same_process(local["driver_process"]),
                         "local driver generation is still alive; wait for its foreground/durable job to finish")
        pipeline.require(all(not os.path.lexists(path) for path in
                             [*NATIVE_OUTPUTS.values(), RECOVERY, *SOCKET_PARENTS.values()]),
                         "native/recovery/socket outputs already exist; no resume or retry")
        qualification, unused = pipeline.establish_binding(LOCAL_READY_SHA)
        pipeline.require(configuration["r14_qualification_sha256"] == report["gate"]["r14_qualification_sha256"]
                         and configuration["source_manifest_sha256"] == report["gate"]["source_map_sha256"]
                         and configuration["artifacts_sha256"] == report["gate"]["retained_artifacts_sha256"],
                         "local complete qualification no longer matches frozen R14")
        bind_remote_inputs()
        agent = os.environ.get("SSH_AUTH_SOCK", "")
        pipeline.require(agent.startswith("/"), "a held current forwarded SSH_AUTH_SOCK is required")
        pipeline.ACTIVE_ENV = {**pipeline.ENV, "SSH_AUTH_SOCK": agent}
        import x230_observation_benchmark as bench
        agent_before = bench.agent_identity(agent)
        report["held_ssh_agent"] = {"identity": agent_before, "preserved_in_child_environment": True,
                                   "full_environment_retained": False}
        report["bound_inputs"] = list(pipeline.BOUND.values())
        pipeline.save()
        for version in ("r14", "r11"):
            pipeline.check_binding(qualification["source_tested"])
            pipeline.contamination_check(performance=True)
            pipeline.require(bench.agent_identity(agent) == agent_before, "held SSH agent changed")
            create_socket_parent(version)
            for name, command, timeout in native_commands(version):
                pipeline.run_stage(name, command, timeout, performance=True)
            validate_native(version)
            pipeline.check_binding(qualification["source_tested"])
        pipeline.require(bench.agent_identity(agent) == agent_before, "held SSH agent changed before recovery")
        create_socket_parent("recovery")
        for name, command, timeout in recovery_commands():
            pipeline.run_stage(name, command, timeout, performance=True)
        validate_recovery()
        pipeline.require(bench.agent_identity(agent) == agent_before, "held SSH agent changed after recovery")
        pipeline.check_binding(qualification["source_tested"], deep=True)
        report["held_ssh_agent"]["unchanged_after"] = True
        report["success"], report["state"] = True, "completed"
    except BaseException as error:
        report["success"], report["state"] = False, "failed"
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
        pipeline.event("pipeline_stopped", error_type=type(error).__name__, reason=str(error)[:3000])
    finally:
        report["owned_socket_parent_cleanup"] = retire_empty_socket_parents()
        report["bound_inputs"] = list(pipeline.BOUND.values())
        report["environment_after"] = pipeline.telemetry()
        report["finished_utc"], report["seconds"] = pipeline.utc(), time.monotonic() - started
        report["retained_result_files"] = []
        for directory in [*NATIVE_OUTPUTS.values(), RECOVERY]:
            for name in ("report.json", "independent-summary.json"):
                path = directory / name
                if path.is_file():
                    report["retained_result_files"].append(pipeline.record(path))
        pipeline.save()
        pipeline.event("pipeline_finished", success=report["success"], report=str(OUT / "report.json"))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, pipeline.interrupted)
    signal.signal(signal.SIGINT, pipeline.interrupted)
    sys.exit(main())
