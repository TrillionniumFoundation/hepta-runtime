#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""A53 binding-only copy of the original eight-stage six-host native driver.

Original driver SHA-256: 6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9.
All eight workloads, thresholds, timeouts, original-agent/SSH trust checks,
qualification reconstruction, EOF/descendant cleanup and no-retry rules remain.
A40 remains the pinned baseline. The internal A41 arm and R07 constant names
are legacy protocol aliases; this file binds them explicitly to qualified A53.
FINAL_BINDINGS_READY=False refuses execution before any output directory exists.
No unqualified source, old A52 binary, two-host profile or earlier pass is accepted.
"""

import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time


DEV_ROOT = Path("/home/qian/hepta-runtime-optimization-20261023")
HISTORY = DEV_ROOT / "a28-a31-budget-r01-g0"
FINAL_BINDINGS_READY = True
PARENT_NATIVE_DRIVER_SHA = "6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9"
A40_QUALIFICATION_SHA = "1a72fbc56c4659a42416baddfaba66c17c39bdd74aeb8d12793b8789a6398719"
R07_QUALIFICATION_SHA = "ab3a37ceb97667694c201d9b62556398e04e805010c8492af6a8f6f51486a72b"
R07_SOURCE_MAP_SHA = "91962e89b203621686cfa0d77567b13bd246092a99345681674bbafd46388c35"
R07_RELEASE_SHA = "5855f6fb044745eba0bf0885b0430bc5a5bb03f68310cce50d961947925c03c6"
HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
SCRIPTS = (
    "x230_small_archive_benchmark.py",
    "x230_inherited_pipe_canary_a40.py",
    "x230_six_running_recovery_canary.py",
    "x230_file_pool_benchmark.py",
    "x230_observation_benchmark.py",
)
STAGE_LAYOUT = (
    ("small-archive-abba", "small", "A40/A41", 300),
    ("inherited-pipe-canary", "pipe", "A41", 400),
    ("six-running-controller-recovery", "recovery", "A41", 480),
    ("file-abba-0-A40", "file_abba", "A40", 250),
    ("file-abba-1-A41", "file_abba", "A41", 250),
    ("file-abba-2-A41", "file_abba", "A41", 250),
    ("file-abba-3-A40", "file_abba", "A40", 250),
    ("file-soak-A41-trace-off", "soak", "A41", 900),
)
TRACE_PREFIX = b"HEPTA_OBSERVATION_TIMING "


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def direct(path, exists=True):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts, "absolute direct path required: " + str(path))
    need(path.resolve(strict=exists) == path, "symlink/indirect path refused: " + str(path))
    if not exists:
        need(path.parent.is_dir() and not os.path.lexists(path), "fresh path required: " + str(path))
    return path


def receipt(path, contents=False):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode), "not a regular file: " + str(path))
        digest, size, chunks = hashlib.sha256(), 0, []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
            if contents:
                chunks.append(block)
        need(size == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             "file changed during complete read: " + str(path))
        row = {"path": str(path), "bytes": size, "sha256": digest.hexdigest(), "identity": list(stamp(before))}
        return (row, b"".join(chunks)) if contents else row
    finally:
        os.close(fd)


def source_map(root):
    direct(root)
    result = {}
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(), "source symlink: " + str(path))
        if path.is_file():
            result[str(path.relative_to(root))] = receipt(path)["sha256"]
    return result


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value):
    temporary = path.with_name(path.name + ".next")
    create(temporary, canonical(value))
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_qualification(path, label, output):
    path = direct(path)
    report_receipt, raw = receipt(path, contents=True)
    value = json.loads(raw)
    create(output / (label + "-qualification.original.json"), raw)
    need(value.get("schema") == "runtime-candidate-qualification/v1"
         and value.get("qualified") is True and value.get("current_stage") == "complete"
         and not value.get("error"), label + " qualification is not final and successful")
    source = direct(Path(value["source"]))
    tested = value.get("source_tested")
    need(isinstance(tested, dict) and tested and tested == value.get("source_after"),
         label + " tested/after source maps differ")
    need(source_map(source) == tested, label + " current source does not match tested source")
    stages = value["stages"]
    need(all(row.get("returncode") == 0 for row in stages), label + " qualification contains a failed stage")
    by_name = {row["name"]: row for row in stages}
    need(len(by_name) == len(stages) and {"fmt-check", "clippy", "test", "release"} <= set(by_name),
         label + " required qualification stages missing/duplicated")
    logs = {}
    for name, stage in by_name.items():
        need(re.fullmatch(r"[a-z0-9-]+", name), "unexpected qualification log name")
        log = path.parent / (name + ".log")
        info = receipt(log)
        need(info["sha256"] == stage["log_sha256"], label + " original qualification log changed: " + name)
        logs[name] = info
    artifacts = {}
    for key, stage_name, is_test in (("binary", "release", False), ("test_binary", "test", True)):
        artifact = value[key]
        need(artifact.get("cached") is False, label + " artifact fresh=false receipt missing: " + key)
        binary = direct(Path(artifact["path"]))
        info = receipt(binary)
        need(info["sha256"] == artifact["sha256"] and os.access(binary, os.X_OK),
             label + " qualified executable changed/not executable: " + key)
        matches = []
        with Path(logs[stage_name]["path"]).open() as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (isinstance(event, dict) and event.get("reason") == "compiler-artifact"
                        and event.get("target", {}).get("name") == "hepta-runtime"
                        and event.get("profile", {}).get("test") is is_test):
                    matches.append(event)
        need(len(matches) == 1, label + " ambiguous/missing original compiler artifact: " + key)
        event = matches[0]
        need(event.get("fresh") is False and event.get("manifest_path") == str(source / "Cargo.toml")
             and event["target"].get("src_path") == artifact["compiler_source"],
             label + " original compiler artifact not fresh=false/source-bound: " + key)
        artifacts[key] = {**info, "fresh": False, "compiler_source": artifact["compiler_source"],
                          "compiler_profile": event["profile"]}
    return {"label": label, "report": report_receipt, "source": str(source), "source_map": tested,
            "source_map_sha256": hashlib.sha256(canonical(tested)).hexdigest(),
            "source_files": len(tested), "logs": logs, **artifacts}


def assert_bundle_unchanged(bundle):
    need(source_map(Path(bundle["source"])) == bundle["source_map"], bundle["label"] + " source changed")
    for row in [bundle["report"], bundle["binary"], bundle["test_binary"], *bundle["logs"].values()]:
        need(receipt(Path(row["path"]))["sha256"] == row["sha256"],
             bundle["label"] + " qualification input changed: " + row["path"])


def input_manifest(args):
    paths = [direct(args.profile_template)]
    profile = json.loads(receipt(paths[0], contents=True)[1])
    need(profile.get("schema") == "hepta-observation-ssh-pool/v1"
         and profile.get("allow_bounded_cached_authentication") is True, "unsupported profile template")
    for key in ("ssh_config", "known_hosts"):
        path = direct(Path(profile[key]))
        need(receipt(path)["sha256"] == profile[key + "_sha256"], "historical SSH pin changed: " + key)
        paths.append(path)
    direct(args.frozen_jobs)
    originals = sorted(args.frozen_jobs.glob("*.json"))
    need(len(originals) == 6, "exactly six frozen source records required")
    hosts = []
    for path in originals:
        row = json.loads(receipt(direct(path), contents=True)[1])
        need(path.name == row["id"] + ".json" and row["launch_state"] == "launched"
             and row["execution_mode"] == "operator" and row["system_jobctl"] is False,
             "frozen source job identity/backend mismatch")
        need(re.fullmatch("HEPTA-A16-ONCE-" + re.escape(row["host"]) + "-[0-9a-f]{24}", row["args"][-1]),
             "frozen synthetic source marker mismatch")
        hosts.append(row["host"])
    need(tuple(sorted(hosts)) == HOSTS, "frozen six-host membership differs")
    paths.extend(originals)
    return {str(path): receipt(path) for path in paths}


def check_manifest(manifest):
    for path, row in manifest.items():
        need(receipt(Path(path))["sha256"] == row["sha256"], "pinned input changed: " + path)


def host_load():
    """Local load evidence, without commands, command lines, or workload changes."""
    value = {"utc": utc(), "monotonic_ns": time.monotonic_ns(), "hostname": socket.gethostname(),
             "loadavg_1_5_15": list(os.getloadavg()), "processes": [], "errors": []}
    required = {"loadavg", "stat", "meminfo", "uptime"}
    for name in sorted(required | {"diskstats", "pressure/cpu", "pressure/io", "pressure/memory"}):
        try:
            value[name] = Path("/proc", name).read_text()
        except OSError as error:
            value["errors"].append({"path": "/proc/" + name, "error": str(error), "required": name in required})
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            text = (directory / "stat").read_text()
            closing = text.rfind(") ")
            fields = text[closing + 2:].split()
            value["processes"].append({"pid": int(directory.name), "comm": text[text.find("(") + 1:closing],
                "state": fields[0], "ppid": int(fields[1]), "start_ticks": int(fields[19]),
                "cpu_ticks": int(fields[11]) + int(fields[12]), "threads": int(fields[17]),
                "rss_pages": int(fields[21])})
        except (FileNotFoundError, ProcessLookupError):
            pass
        except (OSError, ValueError, IndexError) as error:
            value["errors"].append({"pid": int(directory.name), "error": str(error), "required": False})
    value["processes"].sort(key=lambda row: row["pid"])
    value["required_fields_present"] = required <= value.keys()
    return value


def run_owned(argv, env, cwd, stdout, stderr, budget, row, checkpoint):
    """One helper, no Popen.wait/poll: only a real waitpid proves its reap."""
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=stdout, stderr=stderr, start_new_session=True)
    row.update(executed=True, execution_count=1, helper_pid=child.pid, original_child_reaped=False,
               signals=[], timed_out=False, cleanup_grace_seconds=60, forced_reap_grace_seconds=10)
    handle = None
    started = time.monotonic()
    deadline = started + budget
    interrupt_at = kill_at = None
    custody = True
    try:
        handle = os.pidfd_open(child.pid, 0)
        row["pidfd_opened"] = True
        checkpoint()
        while True:
            try:
                observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    need(observed.si_pid == child.pid, "unexpected waitid child identity")
                    waited, status = os.waitpid(child.pid, os.WNOHANG)
                    need(waited == child.pid, "waitpid did not reap the observed original child")
                    child.returncode = os.waitstatus_to_exitcode(status)
                    row.update(original_child_reaped=True, returncode=child.returncode,
                               raw_wait_status=status, actual_waitpid=waited)
                    break
            except InterruptedError:
                continue
            except ChildProcessError as error:
                custody = False
                row["custody_error"] = type(error).__name__ + ": " + str(error)
                raise RuntimeError("original helper ECHILD; exit and cleanup are unknown") from error
            now = time.monotonic()
            if interrupt_at is None and now >= deadline:
                row["timed_out"] = True
                signal.pidfd_send_signal(handle, signal.SIGINT)
                interrupt_at = now
                row["signals"].append({"signal": "SIGINT", "target": "original_helper_pidfd", "at_seconds": now - started})
                checkpoint()
            elif interrupt_at is not None and kill_at is None and now >= interrupt_at + 60:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
                kill_at = now
                row["signals"].append({"signal": "SIGKILL", "target": "original_helper_pidfd", "at_seconds": now - started})
                checkpoint()
            elif kill_at is not None and now >= kill_at + 10:
                raise RuntimeError("original helper still not reaped after bounded forced cleanup")
            time.sleep(.1)
    except BaseException as error:
        row["execution_error"] = type(error).__name__ + ": " + str(error)
        # No group or enumerated-PID signals. A keyboard interrupt also gives
        # this helper's finally block one bounded opportunity to close its own
        # separately-sessioned controllers. ECHILD never authorizes a signal.
        if custody and not row["original_child_reaped"] and kill_at is None:
            for signum, grace in ((signal.SIGINT, 60), (signal.SIGKILL, 10)):
                try:
                    observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    already_interrupted = signum == signal.SIGINT and interrupt_at is not None
                    if observed is None and not already_interrupted:
                        if handle is not None:
                            signal.pidfd_send_signal(handle, signum)
                        else:
                            # Unreaped direct child; no other thread/reaper is
                            # used by this driver, and no reused PID is accepted.
                            os.kill(child.pid, signum)
                        row["signals"].append({"signal": signal.Signals(signum).name,
                            "target": "original_helper_pidfd" if handle is not None else "original_unreaped_child",
                            "at_seconds": time.monotonic() - started})
                    until = interrupt_at + grace if already_interrupted else time.monotonic() + grace
                    while True:
                        waited, status = os.waitpid(child.pid, os.WNOHANG)
                        if waited == child.pid:
                            child.returncode = os.waitstatus_to_exitcode(status)
                            row.update(original_child_reaped=True, returncode=child.returncode,
                                       raw_wait_status=status, actual_waitpid=waited)
                            break
                        need(waited == 0, "unexpected cleanup waitpid identity")
                        if time.monotonic() >= until:
                            break
                        time.sleep(.1)
                    if row["original_child_reaped"]:
                        break
                except ChildProcessError as cleanup:
                    custody = False
                    row["custody_error"] = type(cleanup).__name__ + ": " + str(cleanup)
                    break
                except BaseException as cleanup:
                    row.setdefault("cleanup_errors", []).append(type(cleanup).__name__ + ": " + str(cleanup))
                    break
        raise
    finally:
        row["helper_elapsed_seconds"] = time.monotonic() - started
        row["custody_retained_until_reap"] = custody and row["original_child_reaped"]
        if handle is not None:
            os.close(handle)
        stdout.flush()
        stderr.flush()
        os.fsync(stdout.fileno())
        os.fsync(stderr.fileno())


def artifact_manifest(directory):
    """Inventory all original regular files; never edit/delete stage evidence."""
    files = {}
    if directory.is_dir():
        for path in sorted(directory.rglob("*")):
            need(not path.is_symlink(), "stage output symlink refused: " + str(path))
            if path.is_file():
                files[str(path.relative_to(directory))] = receipt(path)
    return files


def validate_stage(stage, value, output, expected):
    checks, details = {}, {}

    def check(name, condition):
        checks[name] = bool(condition)

    kind = stage["kind"]
    try:
        check("report_has_no_error", not value.get("error"))
        if kind == "small":
            check("schema", value["schema"] == "hepta-x230-small-archive-abba/v1")
            check("complete_comparison", value["complete"] is True and value["comparison_valid"] is True)
            check("binary_binding", value["inputs"]["A"]["sha256"] == expected["A40"]
                  and value["inputs"]["B"]["sha256"] == expected["A41"])
            check("fixed_abba", value["order"] == ["A", "B", "B", "A"] and len(value["rounds"]) == 4)
            check("full_4096_coverage", value["measured_planned"] == value["measured_attempted"] == 4096
                  and value["measured_per_round"] == 1024 and value["measured_unexecuted"] == 0
                  and value["measured_coverage"]["successes"] == 4096
                  and value["measured_coverage"]["failures"] == 0)
            check("unchanged_inputs", value["inputs_unchanged"] is True and value["script_unchanged"] is True)
            for index, item in enumerate(value["rounds"]):
                check("round_" + str(index), item["complete"] is True and item["originals_unchanged"] is True
                      and item["arm"] == ["A", "B", "B", "A"][index]
                      and len(item["seeds"]) == 64 and len(item["warmup"]) == 8 and len(item["measured"]) == 1024
                      and len(item["validation"]) == 10
                      and all(row["okay"] is True for key in ("seeds", "warmup", "measured", "validation") for row in item[key])
                      and item["shutdown"]["original_child_reaped"] is True
                      and item["shutdown"]["waited"]["exit_code"] == 0
                      and not item["shutdown"]["errors"] and item["shutdown"]["reader_error"] is None
                      and not item["shutdown"]["unmatched"])
            info, raw = receipt(output / "calls.jsonl", contents=True)
            calls = [json.loads(line) for line in raw.splitlines()]
            check("original_calls_journal", info["sha256"] == value["calls_file"]["sha256"]
                  and len(calls) == 4424 and all(row["okay"] is True for row in calls))
            details.update(measured_calls=4096, total_tool_calls=4424, concurrency=1, records_per_round=64,
                           scope="native stdio MCP hot small-archive guard; not large-archive/C4 performance")
        elif kind == "pipe":
            wanted = [(host, case) for host in ("x230", "mac") for case in ("natural", "staggered", "timeout")]
            if stage["cancel_during_drain"]:
                wanted.append(("x230", "cancel"))
            check("schema", value["schema"] == "hepta-native-inherited-pipe-canary/v2")
            check("passed", value["passed"] is True and value["candidate_sha256"] == expected["A41"])
            check("exact_case_coverage", [tuple(x) for x in value["planned_cases"]] == wanted
                  and [(x["host"], x["case"]) for x in value["cases"]] == wanted
                  and all(x["passed"] is True and x["start_submitted_once"] is True for x in value["cases"]))
            check("exact_originals", all(value[key] is True for key in (
                "binary_unchanged", "agent_unchanged", "source_records_unchanged", "exact_original_controller_records")))
            check("fixture_only_effects", all(value[key] == 0 for key in (
                "automatic_retries", "harness_remote_signals", "service_mutations", "remote_deletions"))
                  and len({x["job_id"] for x in value["cases"]}) == len(wanted))
            check("shutdown", value["shutdown"]["exit_code"] == 0
                  and value["shutdown"]["stdio_reader_alive"] is False
                  and value["shutdown"]["wire_capture"]["complete"] is True
                  and not value["shutdown"]["observed_descendant_survivors"])
            if stage["cancel_during_drain"]:
                case = value["cases"][-1]
                check("single_fixture_cancel", value["cancel_during_drain_requested"] is True
                      and case["unreaped_leader_proof"]["ready"] is True and case["cancel_submitted_once"] is True)
            details.update(cases=wanted, original_job_ids=[x["job_id"] for x in value["cases"]])
        elif kind == "recovery":
            check("schema", value["schema"] == "hepta-six-running-controller-recovery/v1")
            check("passed", value["passed"] is True and value["candidate_sha256"] == expected["A41"])
            check("six_original_hosts", tuple(sorted(value["hosts"])) == HOSTS
                  and len({x["job_id"] for x in value["hosts"].values()}) == 6)
            check("originals_preserved", all(value[key] is True for key in (
                "source_originals_unchanged", "binary_unchanged", "current_agent_unchanged",
                "distinct_reported_hostnames", "controller_records_unchanged_after_shutdown")))
            check("exact_launch_reuse_count", value["new_start_call_count"] == value["same_key_lookup_call_count"] == 6)
            check("no_retry_cleanup_or_service_change", all(value[key] == 0 for key in (
                "automatic_rpc_retries", "remote_cleanup_operations", "production_service_mutations")))
            check("all_original_calls_passed", all(x["okay"] is True for x in value["native_calls"] + value["ssh_calls"]))
            check("owned_controller_crash_and_shutdown", value["intentional_crash"]["exit_code"] == -signal.SIGKILL
                  and value["shutdown"]["exit_code"] == 0 and not value["shutdown"]["observed_descendant_survivors"]
                  and not value["final_controller_record_errors"])
            details["original_job_ids"] = {host: row["job_id"] for host, row in value["hosts"].items()}
        else:
            check("schema", value["schema"] == "hepta-x230-file-pool-abba/v1")
            check("complete_bound_binary", value["complete"] is True and value["binary_sha256"] == expected[stage["arm"]])
            check("pool_on_only", value["order"] == ["on"] and len(value["rounds"]) == 1
                  and value["rounds"][0]["index"] == 0 and value["rounds"][0]["mode"] == "on")
            check("read_only_and_unchanged", value["remote_writes"] is False
                  and value["binary_unchanged"] is True and value["agent_unchanged"] is True)
            item = value["rounds"][0]
            cells = item["cells"]
            want_concurrency = [1, 4, 8] if kind == "file_abba" else [8]
            check("fixed_calls_concurrency", value["calls_per_cell"] == 96 and value["concurrency"] == want_concurrency
                  and bool(cells) and all(x["calls"] == x["success"] == 96 and x["seconds"] > 0 for x in cells))
            if kind == "file_abba":
                check("one_complete_fixed_iteration", [(x["iteration"], x["concurrency"]) for x in cells] == [(0, x) for x in want_concurrency])
            else:
                check("complete_soak_iterations", [(x["iteration"], x["concurrency"]) for x in cells] == [(i, 8) for i in range(len(cells))]
                      and stage["helper_elapsed_seconds"] >= 600)
            check("warmup_negative_coverage", len(item["warmup"]) == len(item["negative"]) == 12
                  and all(x["okay"] is True for x in item["warmup"] + item["negative"])
                  and Counter((x["host"], x["expected_error"]) for x in item["negative"])
                  == Counter((host, reason) for host in HOSTS for reason in ("stale_version", "outside_root")))
            shutdown = item["shutdown"]
            check("shutdown", shutdown["exit_code"] == 0 and not shutdown["observed_descendant_survivors"]
                  and shutdown["reader_error"] is None and shutdown["unmatched_responses"] == 0)
            info, raw = receipt(output / "calls.jsonl", contents=True)
            calls = [json.loads(line) for line in raw.splitlines()]
            measured = [x for x in calls if x["phase"] == "measured"]
            check("all_original_call_rows", info["sha256"] == value["calls_sha256"]
                  and len(calls) == len(measured) + 24 and len(measured) == 96 * len(cells)
                  and all(x["okay"] is True and x["round"] == 0 and x["mode"] == "on" for x in calls))
            expected_keys = {(x["iteration"], x["concurrency"], i) for x in cells for i in range(96)}
            check("no_missing_or_repeated_measured_row", len(measured) == len(expected_keys)
                  and {(x["iteration"], x["concurrency"], x["index"]) for x in measured} == expected_keys
                  and all(x["host"] == HOSTS[(x["index"] // 2) % 6]
                          and x["tool"] == ("file_info" if x["index"] % 2 == 0 else "binary_read") for x in measured))
            traces, malformed, phases, dropped = 0, 0, Counter(), 0
            trace_path = output / "round-0-on" / "controller" / "stderr.log"
            with trace_path.open("rb") as stream:
                for line in stream:
                    if not line.startswith(TRACE_PREFIX):
                        continue
                    traces += 1
                    match = re.search(rb" phase=(\S+).* dropped_total=(\d+)\n$", line)
                    if match:
                        phases[match[1].decode("ascii")] += 1
                        dropped = max(dropped, int(match[2]))
                    else:
                        malformed += 1
            check("requested_trace_mode_observed", traces > 0 if stage["trace"] else traces == 0)
            details.update(measured_calls=len(measured), warmup_calls=12, negative_calls=12,
                measured_cell_seconds=sum(x["seconds"] for x in cells),
                cells=[{key: item for key, item in x.items() if key != "resources"} for x in cells],
                sampled_resource_peaks=shutdown["resources"].get("peaks", {}),
                resource_observation_error_count=len(shutdown["resources"].get("errors", [])),
                resource_errors_retained_in_original_report=True,
                waited_process_tree_cpu_seconds=item["waited_process_tree_cpu_seconds"],
                trace={"requested": stage["trace"], "lines": traces, "malformed_lines": malformed,
                       "phase_counts": dict(phases), "last_observed_dropped_total": dropped,
                       "complete_event_capture_proven": False,
                       "limits": "bounded diagnostic sink can drop and does not promise exit flush; phases overlap"},
                scope="native stdio MCP file_info/binary_read of six immutable 44-48 byte synthetic outputs; not bulk bandwidth")
    except (KeyError, IndexError, TypeError, ValueError, OSError) as error:
        checks["report_contract_readable"] = False
        details["contract_error"] = type(error).__name__ + ": " + str(error)
    return {"passed": bool(checks) and all(checks.values()), "assertions": checks, "details": details}


def make_plan(args, bundles, nonce, cancel):
    binaries = {label: bundle["binary"]["path"] for label, bundle in bundles.items()}
    stages = []
    for index, (name, kind, arm, timeout) in enumerate(STAGE_LAYOUT):
        output = args.out / name
        socket_parent = args.socket_parent / ("s" + str(index))
        trace = name.endswith("trace-on")
        shared = ["--candidate", binaries.get(arm, binaries["A41"]), "--profile-template", str(args.profile_template),
                  "--frozen-jobs", str(args.frozen_jobs), "--socket-parent", str(socket_parent)]
        if kind == "small":
            script = SCRIPTS[0]
            arguments = ["--baseline", binaries["A40"], "--candidate", binaries["A41"], "--measured", "1024", "--workers", "2"]
        elif kind == "pipe":
            script = SCRIPTS[1]
            output = DEV_ROOT / ("a53-native-" + nonce + "-inherited-pipe")
            arguments = shared + ["--expected-binary-sha256", bundles["A41"]["binary"]["sha256"]]
            if cancel:
                arguments.append("--cancel-during-drain")
        elif kind == "recovery":
            script = SCRIPTS[2]
            output = DEV_ROOT / ("a53-native-" + nonce + "-six-running")
            arguments = shared + ["--workers", "2"]
        else:
            script = SCRIPTS[3]
            arguments = shared + ["--calls", "96", "--concurrency"] + (["1", "4", "8"] if kind == "file_abba" else ["8"])
            arguments += ["--soak-seconds", "1" if kind == "file_abba" else "600"]
        direct(output, exists=False)
        stages.append({"index": index, "name": name, "kind": kind, "arm": arm,
            "budget_seconds": timeout, "output": str(output), "socket_parent": None if kind == "small" else str(socket_parent),
            "script": str(args.tools_dir / script), "script_sha256": receipt(args.tools_dir / script)["sha256"],
            "argv": ["/usr/bin/python3", "-B", "-s", str(args.tools_dir / script), *arguments, "--out", str(output)],
            "trace": trace, "cancel_during_drain": cancel if kind == "pipe" else False,
            "status": "unexecuted", "executed": False, "execution_count": 0})
    return stages


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qualification", "out", "baseline-qualification", "tools-dir", "socket-parent"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--profile-template", type=Path, default=HISTORY / "profile/profile.json")
    parser.add_argument("--frozen-jobs", type=Path, default=HISTORY / "round-0-A/state/jobs")
    args = parser.parse_args(argv)
    need(FINAL_BINDINGS_READY, "A53 actual qualification/source/release binding pending; native not started")
    os.umask(0o077)
    args.out = direct(args.out, exists=False)
    args.out.mkdir(mode=0o700)
    report = {"schema": "hepta-a53-native-validation-series/v1", "passed": False, "complete": False,
        "started_utc": utc(), "phase": "preflight", "nonce": secrets.token_hex(12),
        "automatic_retries": False, "performance_stages_sequential": True, "other_workloads_stopped": False,
        "production_services_changed": False, "remote_cleanup_by_driver": False,
        "parent_native_driver_sha256": PARENT_NATIVE_DRIVER_SHA,
        "planned_stage_count": 8, "stage_arm_versions": {"A40": "A40", "A41": "A53-bounded-direct-ssh"},
        "trace_diagnostic_outcome": "not_planned_feature_removed",
        "trace_diagnostic_pass_claimed": False, "historical_r06_nine_stage_result_modified": False,
        "scope": "qualified release binaries, native stdio MCP, fresh fixture canaries and source-bound descriptive performance",
        "not_covered": ["65,536-record internal algorithm benchmark", "bulk transfer bandwidth", "power loss", "host reboot", "production owner transfer"],
        "stages": [{"name": name, "kind": kind, "arm": arm, "budget_seconds": budget,
                    "status": "unexecuted", "executed": False, "execution_count": 0}
                   for name, kind, arm, budget in STAGE_LAYOUT]}
    report_path = args.out / "report.json"
    bundles, tools, inputs = {}, {}, {}
    driver = receipt(direct(Path(__file__).absolute()))
    report["driver"] = driver

    def checkpoint():
        report["unexecuted"] = [x["name"] for x in report["stages"] if not x["executed"]]
        save(report_path, report)

    def check_agent():
        need(list(stamp(Path(report["agent_socket"]["path"]).stat())) == report["agent_socket"]["identity"],
             "original forwarded agent socket identity changed")

    checkpoint()
    try:
        need(sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(os, "WNOWAIT")
             and hasattr(signal, "pidfd_send_signal"), "Linux waitid/WNOWAIT and pidfd are required")
        probe = os.pidfd_open(os.getpid(), 0)
        os.close(probe)
        direct(DEV_ROOT)
        args.tools_dir = direct(args.tools_dir)
        args.socket_parent = direct(args.socket_parent, exists=False)
        # Same conservative temporary OpenSSH path calculation as fresh_profile;
        # include this driver's per-stage /sN directory before creating anything.
        need(len(os.fsencode(args.socket_parent / "s8")) + 49 + 9 + 17 + 1 <= 108,
             "socket parent too long with per-stage child; choose a shorter fresh absolute path")
        need(args.socket_parent != args.out and not args.socket_parent.is_relative_to(args.out),
             "socket root must be separate from retained stage evidence")
        for name in SCRIPTS:
            path = direct(args.tools_dir / name)
            tools[str(path)] = receipt(path)
        inherited_source = (args.tools_dir / SCRIPTS[1]).read_text()
        cancel = '"--cancel-during-drain"' in inherited_source or "'--cancel-during-drain'" in inherited_source
        report["cancel_during_drain_supported_and_selected"] = cancel
        bundles["A40"] = load_qualification(args.baseline_qualification, "A40", args.out)
        bundles["A41"] = load_qualification(args.qualification, "A41", args.out)
        candidate = bundles["A41"]
        candidate_compact = json.dumps(candidate["source_map"], sort_keys=True, separators=(",", ":")).encode()
        need(bundles["A40"]["report"]["sha256"] == A40_QUALIFICATION_SHA
             and candidate["report"]["sha256"] == R07_QUALIFICATION_SHA
             and candidate["source_files"] == 175
             and hashlib.sha256(candidate_compact).hexdigest() == R07_SOURCE_MAP_SHA
             and candidate["binary"]["sha256"] == R07_RELEASE_SHA,
             "fixed A40/A53 qualification/source/release identity differs")
        report["a53_binding"] = {"qualification_sha256": R07_QUALIFICATION_SHA,
            "source_map_compact_sha256": R07_SOURCE_MAP_SHA, "qualified_release_sha256": R07_RELEASE_SHA}
        need(bundles["A40"]["binary"]["sha256"] != bundles["A41"]["binary"]["sha256"],
             "A40 and A41 are the same executable; cross-version comparison is not defined")
        for bundle in bundles.values():
            source = Path(bundle["source"])
            need(not args.out.is_relative_to(source) and not args.socket_parent.is_relative_to(source),
                 "validation output/socket paths must not mutate a qualified source tree")
        inputs = input_manifest(args)
        agent = Path(os.environ.get("SSH_AUTH_SOCK", ""))
        need(agent.is_absolute() and stat.S_ISSOCK(agent.stat().st_mode), "current forwarded SSH_AUTH_SOCK is required")
        report["agent_socket"] = {"path": str(agent), "identity": list(stamp(agent.stat()))}
        report["qualifications"] = bundles
        report["tools"] = tools
        report["frozen_inputs"] = inputs
        report["python"] = receipt(direct(Path("/usr/bin/python3").resolve(strict=True)))
        report["environment"] = {"hostname": socket.gethostname(), "python_version": sys.version,
            "uname": list(os.uname()), "trace_inherited": os.environ.get("HEPTA_OBSERVATION_TRACE"),
            "trace_policy": "unset for all eight stages; removed r07 trace diagnostic is not a passing result",
            "load_scope": "local controller /proc endpoint snapshots; observation errors or active compiler/heptabao refused; no continuous or remote-host load guarantee",
            "cache_policy": "source/binary/input hashes before each stage; normal helper warmups; no cache drops, load suppression or host reconfiguration"}
        args.socket_parent.mkdir(mode=0o700)
        report["socket_parent"] = str(args.socket_parent)
        report["stages"] = make_plan(args, bundles, report["nonce"], cancel)
        expected = {label: bundle["binary"]["sha256"] for label, bundle in bundles.items()}
        report["phase"] = "ready"
        checkpoint()
        for stage in report["stages"]:
            report["phase"] = stage["name"]
            stage.update(status="checking_inputs", started_utc=utc(), start_monotonic_ns=time.monotonic_ns())
            checkpoint()
            try:
                for bundle in bundles.values():
                    assert_bundle_unchanged(bundle)
                check_manifest(tools)
                check_manifest(inputs)
                check_agent()
                need(receipt(Path(driver["path"]))["sha256"] == driver["sha256"], "driver changed during run")
                output = direct(Path(stage["output"]), exists=False)
                if stage["socket_parent"]:
                    direct(Path(stage["socket_parent"]), exists=False).mkdir(mode=0o700)
                before = args.out / (stage["name"] + ".hostload-before.json")
                load = host_load()
                create(before, canonical(load))
                stage["hostload_before"] = receipt(before)
                busy = [row for row in load["processes"] if row["comm"] in
                        ("cargo", "cargo-clippy", "clippy-driver", "rustc", "heptabao_server")
                        and row["state"] not in ("Z", "X", "x")]
                stage["hostload_before_gate"] = {
                    "clear": load["required_fields_present"] and not load["errors"] and not busy,
                    "matching_live_processes": busy,
                    "scope": "local endpoint snapshot only; no continuous or remote-host load guarantee"}
                stage["environment_gate_failed"] = not stage["hostload_before_gate"]["clear"]
                need(stage["hostload_before_gate"]["clear"],
                     "before-stage environment gate failed: busy/incomplete local snapshot; helper not started")
                env = dict(os.environ)
                for key in ("HEPTA_OBSERVATION_TRACE", "PYTHONPATH", "PYTHONHOME"):
                    env.pop(key, None)
                env["PYTHONDONTWRITEBYTECODE"] = "1"
                env["PYTHONNOUSERSITE"] = "1"
                if stage["trace"]:
                    env["HEPTA_OBSERVATION_TRACE"] = "1"
                stage["status"] = "running"
                checkpoint()
                with (args.out / (stage["name"] + ".stdout")).open("xb") as stdout, (args.out / (stage["name"] + ".stderr")).open("xb") as stderr:
                    run_owned(stage["argv"], env, args.tools_dir, stdout, stderr,
                              stage["budget_seconds"], stage, checkpoint)
                stage_report = output / "report.json"
                validation = {"passed": False, "assertions": {"primary_report_exists": False}}
                if stage_report.exists():
                    info, raw = receipt(stage_report, contents=True)
                    stage["original_report"] = info
                    validation = validate_stage(stage, json.loads(raw), output, expected)
                    stage["validation"] = validation
                need(stage["original_child_reaped"] and stage["returncode"] == 0 and not stage["timed_out"],
                     "helper failed/timed out; no successful subset or retry is admitted")
                need(validation["passed"], "stage report integrity/coverage assertions failed: "
                     + ", ".join(k for k, v in validation["assertions"].items() if not v))
                check_manifest(tools)
                check_manifest(inputs)
                check_agent()
                stage["status"] = "passed"
            except BaseException as error:
                stage["status"] = "failed"
                stage["error"] = type(error).__name__ + ": " + str(error)
                report["failed_stage"] = stage["name"]
                raise
            finally:
                stage["finished_utc"] = utc()
                stage["end_monotonic_ns"] = time.monotonic_ns()
                evidence_errors = []
                for stream in ("stdout", "stderr"):
                    path = args.out / (stage["name"] + "." + stream)
                    if path.exists():
                        try:
                            stage[stream] = receipt(path)
                        except BaseException as error:
                            evidence_errors.append(str(error))
                try:
                    after = args.out / (stage["name"] + ".hostload-after.json")
                    load = host_load()
                    create(after, canonical(load))
                    stage["hostload_after"] = receipt(after)
                    busy = [row for row in load["processes"] if row["comm"] in
                            ("cargo", "cargo-clippy", "clippy-driver", "rustc", "heptabao_server")
                            and row["state"] not in ("Z", "X", "x")]
                    stage["hostload_after_gate"] = {
                        "clear": load["required_fields_present"] and not load["errors"] and not busy,
                        "matching_live_processes": busy,
                        "scope": "local endpoint snapshot only; no continuous or remote-host load guarantee"}
                    if not stage["hostload_after_gate"]["clear"]:
                        stage["environment_gate_failed"] = True
                        # Preserve the real child result and all original stage
                        # artifacts even when this endpoint invalidates the run.
                        evidence_errors.append("after-stage environment gate failed: busy/incomplete local snapshot; business validation preserved")
                    manifest = artifact_manifest(Path(stage["output"]))
                    path = args.out / (stage["name"] + ".artifacts.json")
                    create(path, canonical(manifest))
                    stage["original_artifacts_manifest"] = receipt(path)
                    stage["original_artifact_count"] = len(manifest)
                    stage["retained_report_files"] = {name: info for name, info in manifest.items()
                        if Path(name).name.startswith("report") and Path(name).suffix == ".json"}
                    if "report.json" in manifest and "original_report" not in stage:
                        stage["original_report"] = manifest["report.json"]
                except BaseException as error:
                    evidence_errors.append(type(error).__name__ + ": " + str(error))
                if evidence_errors:
                    stage["evidence_errors"] = evidence_errors
                    stage["status"] = "failed"
                    report["failed_stage"] = stage["name"]
                checkpoint()
                print(json.dumps({"stage": stage["name"], "status": stage["status"], "report": stage["output"] + "/report.json",
                                  "returncode": stage.get("returncode"), "timed_out": stage.get("timed_out", False)}), flush=True)
            need(stage["status"] == "passed", "stage evidence incomplete; later stages remain unexecuted")
        for bundle in bundles.values():
            assert_bundle_unchanged(bundle)
        check_manifest(tools)
        check_manifest(inputs)
        check_agent()
        final_inputs = input_manifest(args)
        need(set(final_inputs) == set(inputs), "frozen profile/job input file set changed")
        need(receipt(Path(driver["path"]))["sha256"] == driver["sha256"], "driver changed")
        for stage in report["stages"]:
            for key in ("stdout", "stderr", "original_report", "original_artifacts_manifest", "hostload_before", "hostload_after"):
                pinned = stage[key]
                need(receipt(Path(pinned["path"]))["sha256"] == pinned["sha256"],
                     "earlier stage evidence changed: " + stage["name"] + "/" + key)
            expected_artifacts = json.loads(Path(stage["original_artifacts_manifest"]["path"]).read_bytes())
            actual_artifacts = artifact_manifest(Path(stage["output"]))
            need({name: item["sha256"] for name, item in actual_artifacts.items()}
                 == {name: item["sha256"] for name, item in expected_artifacts.items()},
                 "earlier original stage artifact set/content changed: " + stage["name"])
        report["final_input_integrity_passed"] = True
        stages = report["stages"]
        report["integrity_assertions"] = {
            "both_final_qualifications_fresh_false_and_current_sources_verified": True,
            "all_qualifications_binaries_sources_tools_and_frozen_inputs_unchanged": True,
            "all_eight_planned_stages_passed_once": len(stages) == 8 and all(x["status"] == "passed" and x["execution_count"] == 1 for x in stages),
            "strict_serial_order": all(stages[i]["end_monotonic_ns"] <= stages[i + 1]["start_monotonic_ns"] for i in range(len(stages) - 1)),
            "every_original_helper_reaped_without_timeout": all(x.get("custody_retained_until_reap") and not x.get("timed_out") for x in stages),
            "every_stage_has_original_stdout_stderr_report_and_full_artifact_hashes": all(all(key in x for key in (
                "stdout", "stderr", "original_report", "original_artifacts_manifest", "hostload_before", "hostload_after")) for x in stages),
            "all_native_report_coverage_assertions_passed": all(x["validation"]["passed"] for x in stages),
            "every_original_artifact_set_and_content_rechecked_at_series_end": True,
            "every_stage_endpoint_host_gate_clear": all(
                x.get("hostload_before_gate", {}).get("clear") is True
                and x.get("hostload_after_gate", {}).get("clear") is True for x in stages),
            "same_forwarded_agent_socket_held_throughout": True,
            "canary_outputs_are_nonce_bound_direct_optimization_children": all(
                Path(x["output"]).parent == DEV_ROOT and report["nonce"] in Path(x["output"]).name
                for x in stages if x["kind"] in ("pipe", "recovery")),
            "cross_version_file_abba_is_pool_on_trace_off": [x["arm"] for x in stages if x["kind"] == "file_abba"] == ["A40", "A41", "A41", "A40"]
                and all(not x["trace"] for x in stages if x["kind"] == "file_abba"),
            "all_eight_stages_have_trace_disabled": all(not x["trace"] for x in stages),
            "no_unexecuted_stages": all(x["executed"] for x in stages),
        }
        need(all(report["integrity_assertions"].values()), "final completeness assertion failed")
        comparison = {}
        for concurrency in (1, 4, 8):
            arms = {}
            for arm in ("A40", "A41"):
                selected = [cell for stage in stages if stage["kind"] == "file_abba" and stage["arm"] == arm
                            for cell in stage["validation"]["details"]["cells"] if cell["concurrency"] == concurrency]
                count, seconds = sum(x["calls"] for x in selected), sum(x["seconds"] for x in selected)
                arms[arm] = {"calls": count, "cell_seconds": seconds, "calls_per_second": count / seconds}
            comparison[str(concurrency)] = {**arms, "candidate_rate_change_percent": 100 * (arms["A41"]["calls_per_second"] / arms["A40"]["calls_per_second"] - 1)}
        report["descriptive_file_abba"] = {"concurrency": comparison,
            "method": "total measured calls / total measured cell wall time per arm; includes both original ABBA rounds",
            "performance_adoption_claimed": False,
            "limits": "one short ABBA block, six synthetic 44-48 byte files, uncontrolled outside load; removed trace diagnostic is not measured or credited as passing"}
        report.update(complete=True, passed=True, phase="complete")
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        report["phase"] = "failed"
        report["passed"] = report["complete"] = False
        for stage in report["stages"]:
            if not stage["executed"]:
                stage["unexecuted_reason"] = "series stopped at " + report.get("failed_stage", "preflight/final integrity") + "; no retry"
        report.setdefault("integrity_assertions", {})["complete_native_validation_proven"] = False
    finally:
        report["finished_utc"] = utc()
        report["unexecuted_count"] = sum(not x["executed"] for x in report["stages"])
        checkpoint()
        print(json.dumps({"report": str(report_path), "passed": report["passed"], "complete": report["complete"],
            "failed_stage": report.get("failed_stage"), "unexecuted": report["unexecuted"], "error": report.get("error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    def stop_requested(signum, frame):
        raise KeyboardInterrupt("driver received signal " + str(signum))
    signal.signal(signal.SIGTERM, stop_requested)
    raise SystemExit(main())
