#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Abrupt death and read-only recovery of six existing completed job identities.

Only this script's directly owned controller is killed. No remote workload,
service, host or observed descendant is signalled. Existing completed jobs are
read before and after the controller death using the same private state.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time


def load_driver():
    path = Path(__file__).resolve().with_name("x230_observation_benchmark.py")
    spec = importlib.util.spec_from_file_location("x230_observation_driver", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("observation driver is unavailable")
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    return driver, path


bench, DRIVER_PATH = load_driver()


def sampled_descendants(controller):
    with controller.resources.lock:
        return sorted((pid, born) for pid, born in controller.resources.seen
                      if pid != controller.child.pid)


def alive_generations(generations):
    alive, errors = [], []
    for pid, born in generations:
        try:
            if bench.process_stat(pid)[0] == born:
                alive.append({"pid": pid, "birth_ticks": born})
        except (FileNotFoundError, ProcessLookupError):
            pass
        except OSError as error:
            errors.append({"pid": pid, "birth_ticks": born,
                           "error_type": type(error).__name__})
    return alive, errors


def socket_artifacts(parent, pid):
    """Observe only the exact controller PID namespace; never remove entries."""
    rows = []
    for path in sorted(parent.glob(f"hp-o-{pid}-*")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        row = {"path": str(path), "identity": bench.identity(info), "entries": []}
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            try:
                entries = sorted(path.iterdir())
            except FileNotFoundError:
                continue
            for entry in entries:
                try:
                    entry_info = entry.lstat()
                except FileNotFoundError:
                    continue
                row["entries"].append({"name": entry.name,
                                       "identity": bench.identity(entry_info),
                                       "socket": stat.S_ISSOCK(entry_info.st_mode)})
                bench.need(len(row["entries"]) <= 128, "socket observation exceeds bound")
        rows.append(row)
        bench.need(len(rows) <= 16, "controller socket directory count exceeds bound")
    return rows


def metadata_unchanged(jobs, directory):
    paths = sorted((directory / "state/jobs").glob("*.json"))
    expected = sorted(job["id"] + ".json" for job in jobs)
    source_ok = all(bench.read_file(job["path"], 65536) == job["record_bytes"] for job in jobs)
    copy_ok = (sorted(path.name for path in paths) == expected
               and all(bench.read_file(directory / "state/jobs" / (job["id"] + ".json"), 65536)
                       == job["record_bytes"] for job in jobs))
    return {"source_originals_unchanged": source_ok, "private_originals_unchanged": copy_ok,
            "private_job_record_count": len(paths), "no_new_private_job_identity": copy_ok}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--profile-template", type=Path, required=True)
    parser.add_argument("--frozen-jobs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--socket-parent", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--settle-seconds", type=float, default=30)
    args = parser.parse_args()
    bench.need(1 <= args.workers <= 32 and 0 <= args.settle_seconds <= 60,
               "invalid bounded recovery dimensions")
    args.out = args.out.absolute()
    args.socket_parent = args.socket_parent.absolute()
    args.candidate = args.candidate.absolute()
    bench.need(args.out.resolve() == args.out and not args.out.exists(),
               "output must be a fresh direct path")
    args.out.mkdir(mode=0o700)
    directory = args.out / "fixture"
    jobs, binary_sha = [], None
    report = {
        "schema": "hepta-x230-controller-abrupt-readonly-recovery/v1",
        "started_unix": time.time(), "passed": False, "read_only_recovery_passed": False,
        "effect_starts": 0, "remote_mutation_tool_calls": 0, "automatic_rpc_retries": 0,
        "signal_scope": "one directly owned Popen controller, birth ticks verified",
        "descendant_signals_sent": 0, "socket_artifacts_deleted": 0,
        "scope": "abrupt controller death followed by read-only recovery of six completed jobs",
        "not_covered": ["running workload recovery", "new launches", "target reboot",
                        "service restart", "physical power loss", "WAN partition"],
    }
    path = args.out / "report.json"
    active = None
    try:
        bench.save_report(path, report)
        jobs = bench.load_jobs(args.frozen_jobs)
        agent = os.environ.get("SSH_AUTH_SOCK", "")
        bench.need(agent.startswith("/"), "current held SSH_AUTH_SOCK required")
        agent_before = bench.agent_identity(agent)
        binary_sha = bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024))
        profile, profile_receipt = bench.fresh_profile(
            args.profile_template, args.out / "profile", args.socket_parent, agent)
        config = bench.fixture(directory, jobs)
        report.update(binary_sha256=binary_sha, profile=profile_receipt,
                      driver_sha256=bench.digest(bench.read_file(DRIVER_PATH, 262144)),
                      six_originals=[{"host": job["host"], "job_id": job["id"],
                                      "record_sha256": job["record_sha256"],
                                      "stdout_sha256": bench.digest(job["expected"])} for job in jobs])
        first = directory / "before-death"
        first.mkdir(mode=0o700)
        active = bench.Controller(args.candidate, config, profile, first, args.workers)
        report["initial_startup"] = active.startup
        report["before_checks"] = [active.call(tool, job, "before_owned_controller_death")
                                   for job in jobs for tool in ("process_status", "process_read")]
        bench.need(all(row["okay"] for row in report["before_checks"]),
                   "six original status/output checks failed before death")
        report["metadata_before_death"] = metadata_unchanged(jobs, directory)
        bench.need(all(report["metadata_before_death"][key] for key in
                       ("source_originals_unchanged", "private_originals_unchanged")),
                   "original metadata changed before death")
        pid, birth = active.child.pid, active.birth
        generations = sampled_descendants(active)
        report["socket_artifacts_before_death"] = socket_artifacts(args.socket_parent, pid)
        report["sampled_descendants_before_death"] = [
            {"pid": child, "birth_ticks": born} for child, born in generations]
        bench.need(active.child.poll() is None, "owned controller already exited")
        bench.need(bench.process_stat(pid)[0] == birth, "owned controller identity changed")
        parent = int(next(line.split()[1] for line in Path(f"/proc/{pid}/status")
                          .read_text().splitlines() if line.startswith("PPid:")))
        bench.need(parent == os.getpid(), "signal target is not our direct child")
        report["death_intent"] = {"pid": pid, "birth_ticks": birth, "parent_pid": parent,
                                  "signal": "SIGKILL", "at_unix": time.time()}
        bench.save_report(path, report)
        # This direct child remains unreaped and no other thread polls it, so its
        # PID cannot be reused between the checked identity and this signal.
        bench.need(bench.process_stat(pid)[0] == birth, "controller changed before signal")
        os.kill(pid, signal.SIGKILL)
        report["controller_death_exit_code"] = active.child.wait(timeout=10)
        generations = sorted(set(generations) | set(sampled_descendants(active)))
        report["death_cleanup"] = active.close()
        generations = sorted(set(generations) | set(sampled_descendants(active)))
        active = None
        bench.need(report["controller_death_exit_code"] == -signal.SIGKILL,
                   "controller did not terminate by the requested SIGKILL")
        bench.need(report["death_cleanup"]["reader_error"] is None
                   and report["death_cleanup"]["unmatched_responses"] == 0,
                   "original controller retained a protocol framing or unmatched-response error")
        deadline = time.monotonic() + args.settle_seconds
        while True:
            alive, errors = alive_generations(generations)
            if not alive or time.monotonic() >= deadline:
                break
            time.sleep(.2)
        report["descendant_observation"] = {
            "sampled_generations": len(generations), "settle_limit_seconds": args.settle_seconds,
            "remaining": alive, "observation_errors": errors,
            "all_sampled_descendants_exited": not alive and not errors,
            "sampling_is_not_exhaustive_process_containment_proof": True}
        report["old_socket_artifacts_after_death"] = socket_artifacts(args.socket_parent, pid)
        report["metadata_after_death"] = metadata_unchanged(jobs, directory)
        bench.save_report(path, report)
        bench.need(bench.agent_identity(agent) == agent_before, "SSH agent identity changed")
        bench.need(bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024)) == binary_sha,
                   "candidate changed before recovery")
        restart = directory / "after-death"
        restart.mkdir(mode=0o700)
        active = bench.Controller(args.candidate, config, profile, restart, args.workers)
        report["recovery_startup"] = active.startup
        report["after_checks"] = [active.call(tool, job, "same_original_after_controller_death")
                                  for job in jobs for tool in ("process_status", "process_read")]
        report["recovery_shutdown"] = active.close()
        active = None
        report["metadata_after_recovery"] = metadata_unchanged(jobs, directory)
        report["old_socket_artifacts_after_recovery"] = socket_artifacts(args.socket_parent, pid)
        bench.need(all(row["okay"] for row in report["after_checks"]),
                   "original status/output hashes failed after controller death")
        bench.need(all(report["metadata_after_recovery"][key] for key in
                       ("source_originals_unchanged", "private_originals_unchanged")),
                   "original metadata changed after recovery")
        shutdown = report["recovery_shutdown"]
        bench.need(shutdown["exit_code"] == 0 and shutdown["shutdown_method"] == "stdin_eof"
                   and not shutdown["observed_descendant_survivors"]
                   and shutdown["reader_error"] is None and shutdown["unmatched_responses"] == 0,
                   "recovery controller failed normal shutdown")
        bench.need(bench.agent_identity(agent) == agent_before, "SSH agent changed after recovery")
        report["read_only_recovery_passed"] = True
        report["passed"] = report["descendant_observation"]["all_sampled_descendants_exited"]
        report["abrupt_cleanup_complete"] = (report["passed"]
                                              and not report["old_socket_artifacts_after_recovery"])
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
        report["passed"] = False
    finally:
        if active is not None:
            try:
                report["interrupted_shutdown"] = active.close()
            except BaseException as error:
                report["cleanup_error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
            report["passed"] = False
        report["finished_unix"] = time.time()
        try:
            bench.need(len(jobs) == 6 and directory.is_dir(), "preflight fixture was not completed")
            report["metadata_final"] = metadata_unchanged(jobs, directory)
            report["binary_hash_unchanged"] = (binary_sha is not None and
                bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024)) == binary_sha)
            final_valid = (report["metadata_final"]["source_originals_unchanged"]
                           and report["metadata_final"]["private_originals_unchanged"]
                           and report["binary_hash_unchanged"])
        except BaseException as error:
            report["final_check_error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
            final_valid = False
        if not final_valid:
            report["passed"] = report["read_only_recovery_passed"] = False
        try:
            bench.save_report(path, report)
        except BaseException as error:
            report["passed"] = False
            report["report_save_error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
            # Never delete or overwrite a failed atomic-write staging file.
            # Retain a separate final failure receipt where storage still works.
            fallback = args.out / f"report-final-{os.getpid()}-{time.time_ns()}.json"
            try:
                bench.create_file(fallback, bench.canonical(report))
                path = fallback
                descriptor = os.open(args.out, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except BaseException as fallback_error:
                report["fallback_save_error"] = {
                    "type": type(fallback_error).__name__, "reason": str(fallback_error)[:1000]}
                try:
                    print(json.dumps({"unsaved_recovery_report": report}), file=sys.stderr, flush=True)
                except BaseException:
                    # A broken error stream must not replace the original failure.
                    pass
    print(json.dumps({"report": str(path), "passed": report["passed"],
                      "read_only_recovery_passed": report["read_only_recovery_passed"],
                      "abrupt_cleanup_complete": report.get("abrupt_cleanup_complete"),
                      "error": report.get("error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
