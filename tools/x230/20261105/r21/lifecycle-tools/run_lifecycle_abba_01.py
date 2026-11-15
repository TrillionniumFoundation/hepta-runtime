#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One finite A/B/B/A sequence of the existing six-host recovery canary.

Each round is followed once by the original independent raw auditor. All raw
artifacts are retained. No uncertain effect is retried. The caller owns the
forwarded agent and the qualification/quiescence gate around this invocation.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
import summarize_lifecycle_abba_01 as evidence

ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r21")
OUTPUT = ROOT / "lifecycle-abba-01"
BASELINE = Path("/home/qian/hepta-runtime-optimization-20261104-r19/qualification-02/hepta-runtime")
CANDIDATE = ROOT / "qualification-01/hepta-runtime"
BASELINE_SHA = "adab5f27f89b3cac6adaec916110a48d80697db9667e3bd7ee0fc713fe770a09"
HEX = re.compile(r"[0-9a-f]{64}\Z")
need = evidence.need
fingerprint = evidence.fingerprint
TOOLS = Path(__file__).resolve().parent


def identity(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    end = raw.rfind(") ")
    fields = raw[end + 2:].split()
    need(end > 0 and len(fields) >= 20 and int(raw.split("(", 1)[0]) == pid,
         "malformed owned child identity")
    return {"pid": pid, "start_ticks": int(fields[19]), "state": fields[0], "process_group": int(fields[2])}


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def save(path, value):
    temporary = path.with_name(path.name + ".next")
    evidence.create(temporary, evidence.canonical(value))
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "candidate", "profile-template", "topology", "frozen-jobs", "out", "socket-prefix"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-baseline-sha256", "expected-candidate-sha256", "expected-tools-manifest-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--workers", type=int, choices=(2,), default=2)
    parser.add_argument("--arena-max", type=int, choices=(1,), default=1)
    args = parser.parse_args()
    out = args.out.absolute()
    need(sys.platform == "linux" and out == OUTPUT and out.resolve() == out and not os.path.lexists(out),
         "fresh canonical R21 lifecycle output required")
    need(args.baseline.absolute() == BASELINE and args.candidate.absolute() == CANDIDATE
         and args.expected_baseline_sha256 == BASELINE_SHA
         and all(HEX.fullmatch(value) for value in (args.expected_baseline_sha256,
              args.expected_candidate_sha256, args.expected_tools_manifest_sha256)), "binary/tool binding arguments differ")
    prefix = args.socket_prefix.absolute()
    need(prefix.parent == Path("/home/qian") and re.fullmatch(r"[A-Za-z0-9_-]{1,12}", prefix.name)
         and prefix.resolve() == prefix and not os.path.lexists(prefix), "fresh short socket naming prefix required")
    socket_paths = [prefix.with_name(prefix.name + f"-{n}-{arm}") for n, arm in enumerate("ABBA")]
    need(all(not os.path.lexists(path) and path.resolve() == path for path in socket_paths),
         "a derived round socket directory already exists")
    need(os.environ.get("SSH_AUTH_SOCK", "").startswith("/"), "held forwarded SSH agent required")
    out.mkdir(mode=0o700)
    report_path = out / "report.json"
    report = {"schema": "hepta-r21-lifecycle-abba-control/v1", "passed": False,
              "order": "ABBA", "round_count": 4, "started_realtime_ns": time.time_ns(),
              "stages": [], "rounds": [], "automatic_retries": 0,
              "cleanup_scope": "owned stage session; original canary owns Controller/SSH cleanup; failures require review",
              "remote_target_timeout_seconds": 240, "socket_directories": [str(p) for p in socket_paths]}

    def checkpoint():
        save(report_path, report)

    def snapshot():
        manifest = evidence.verify_tools(TOOLS, args.expected_tools_manifest_sha256)
        paths = sorted(args.frozen_jobs.absolute().glob("*.json"))
        need(len(paths) == 6, "six frozen fixture records required")
        value = {"tools_manifest": fingerprint(TOOLS / "lifecycle-tools-manifest-01.json"),
                 "tools": {name: fingerprint(TOOLS / name) for name in sorted(manifest["files"])},
                 "baseline": fingerprint(BASELINE), "candidate": fingerprint(CANDIDATE),
                 "profile_template": fingerprint(args.profile_template.absolute()),
                 "topology": fingerprint(args.topology.absolute()),
                 "frozen_jobs": [fingerprint(path) for path in paths]}
        need(value["baseline"]["sha256"] == args.expected_baseline_sha256
             and value["candidate"]["sha256"] == args.expected_candidate_sha256, "runtime bytes differ")
        return value

    def run_stage(name, argv, timeout):
        stdout_path, stderr_path = out / (name + ".stdout"), out / (name + ".stderr")
        row = {"name": name, "argv": argv, "timeout_seconds": timeout,
               "started_realtime_ns": time.time_ns(), "start_monotonic_ns": time.monotonic_ns(),
               "returncode": None, "pid": None, "start_ticks": None,
               "waited_and_reaped": False, "proc_absent": False, "cleanup_signals": [],
               "automatic_retry": False}
        report["stages"].append(row)
        checkpoint()
        child = None
        primary = None
        try:
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                         cwd=TOOLS, start_new_session=True)
                row["pid"] = child.pid
                birth = identity(child.pid)
                need(birth is not None and birth["process_group"] == child.pid, "owned stage PID/session missing")
                row["start_ticks"] = birth["start_ticks"]
                checkpoint()
                row["returncode"] = child.wait(timeout=timeout)
                row["waited_and_reaped"] = True
                need(row["returncode"] == 0, name + " returned nonzero")
        except BaseException as error:
            primary = error
            row["error"] = {"type": type(error).__name__, "reason": str(error)[:2000]}
            if isinstance(error, subprocess.TimeoutExpired):
                row["timed_out"] = True
        finally:
            if child is not None:
                try:
                    if child.poll() is None:
                        # SIGINT lets the existing Python canary execute its own
                        # except/finally cleanup. Escalation never targets an unrelated PID.
                        for sig, seconds in ((signal.SIGINT, 45), (signal.SIGTERM, 10), (signal.SIGKILL, 10)):
                            current = identity(child.pid)
                            need(current is not None and current["start_ticks"] == row["start_ticks"]
                                 and current["process_group"] == child.pid, "child identity changed before signal")
                            os.killpg(child.pid, sig)
                            row["cleanup_signals"].append({"signal": sig.name, "realtime_ns": time.time_ns()})
                            try:
                                child.wait(timeout=seconds)
                                break
                            except subprocess.TimeoutExpired:
                                continue
                    row["returncode"] = child.wait(timeout=1)
                    row["waited_and_reaped"] = True
                    current = identity(child.pid)
                    row["proc_absent"] = current is None or current["start_ticks"] != row["start_ticks"]
                    row["owned_process_group_absent"] = not group_present(child.pid)
                    if not row["proc_absent"] or not row["owned_process_group_absent"]:
                        raise RuntimeError("owned stage identity/session remains")
                except BaseException as error:
                    row["cleanup_error"] = {"type": type(error).__name__, "reason": str(error)[:2000]}
                    if primary is None:
                        primary = error
            row["end_monotonic_ns"] = time.monotonic_ns()
            row["finished_realtime_ns"] = time.time_ns()
            for stream, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                try:
                    if path.exists():
                        row[stream] = fingerprint(path)
                except BaseException as error:
                    row.setdefault("finalization_errors", []).append({"stream": stream,
                        "type": type(error).__name__, "reason": str(error)[:2000]})
                    if primary is None:
                        primary = error
            try:
                checkpoint()
            except BaseException as error:
                if primary is None:
                    primary = error
        if primary is not None:
            raise primary
        return row

    before = None
    try:
        checkpoint()
        before = snapshot()
        report.update(baseline=before["baseline"], candidate=before["candidate"], tools_manifest=before["tools_manifest"])
        plan = {"schema": "hepta-r21-lifecycle-plan/v1", "order": "ABBA", "round_count": 4,
                "new_jobs_per_round": 6, "phase_concurrency": 6, "workers": 2, "arena_max": 1,
                "interrupt_host": "rog", "phases": list(evidence.PHASES), "inputs": before,
                "socket_directories": [str(p) for p in socket_paths],
                "fixed_scope": "original small workload/start/live/crash/reuse/cancel/restart; no maximum-load search"}
        evidence.create(out / "plan.json", evidence.canonical(plan))
        report["plan"] = fingerprint(out / "plan.json")
        checkpoint()
        for number, arm in enumerate("ABBA"):
            need(snapshot() == before, "input changed between rounds")
            directory = out / f"round-{number}-{arm}"
            socket_paths[number].mkdir(mode=0o700)
            binary = BASELINE if arm == "A" else CANDIDATE
            argv = ["/usr/bin/python3", "-B", str(TOOLS / "run_six_host_cancel_recovery_timed.py"),
                    "--candidate", str(binary), "--profile-template", str(args.profile_template.absolute()),
                    "--topology", str(args.topology.absolute()), "--frozen-jobs", str(args.frozen_jobs.absolute()),
                    "--socket-parent", str(socket_paths[number]), "--out", str(directory),
                    "--workers", "2", "--candidate-arena-max", "1", "--interrupt-host", "rog"]
            run_stage(f"canary-{number}-{arm}", argv, 600)
            run_stage(f"audit-{number}-{arm}", ["/usr/bin/python3", "-B", str(TOOLS / "verify_cancel_recovery.py"),
                      "--report", str(directory / "report.json"),
                      "--output", str(directory / "independent-summary.json")], 180)
            raw, audit = (json.loads(evidence.read(directory / name))
                          for name in ("report.json", "independent-summary.json"))
            binary_sha = before["baseline" if arm == "A" else "candidate"]["sha256"]
            need(raw["passed"] is True and audit["verified"] is True
                 and raw["candidate_sha256"] == audit["candidate_sha256"] == binary_sha,
                 "round output identity/result differs")
            need(snapshot() == before, "input changed during round/audit")
            phase_files = [fingerprint(directory / ("phase-" + name + ".json")) for name in evidence.PHASES]
            report["rounds"].append({"index": number, "arm": arm, "directory": directory.name,
                "report": fingerprint(directory / "report.json"),
                "independent_analysis": fingerprint(directory / "independent-summary.json"), "phase_files": phase_files})
            checkpoint()
        index = {"schema": "hepta-r21-lifecycle-round-index/v1", "closed": True,
                 "order": "ABBA", "round_count": 4, "rounds": report["rounds"],
                 "baseline": before["baseline"], "candidate": before["candidate"],
                 "tools_manifest": before["tools_manifest"], "plan": report["plan"],
                 "closed_realtime_ns": time.time_ns(), "automatic_retries": 0}
        evidence.create(out / "round-index.json", evidence.canonical(index))
        report["round_index"] = fingerprint(out / "round-index.json")
        checkpoint()
        run_stage("summary", ["/usr/bin/python3", "-B", str(TOOLS / "summarize_lifecycle_abba_01.py"),
                  "--index", str(out / "round-index.json"), "--output", str(out / "summary.json")], 180)
        summary = json.loads(evidence.read(out / "summary.json"))
        need(summary["verified"] is True and summary["round_count"] == 4, "aggregate did not verify")
        report["summary"] = fingerprint(out / "summary.json")
        need(snapshot() == before, "final input/tool identity changed")
        report["inputs_unchanged"] = True
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
        report["passed"] = False
        report["uncertain_effects_are_not_retried"] = True
    finally:
        if before is not None:
            try:
                report["inputs_unchanged"] = snapshot() == before
                report["passed"] = report["passed"] and report["inputs_unchanged"]
            except BaseException as error:
                report["input_finalization_error"] = {"type": type(error).__name__, "reason": str(error)[:2000]}
                report["passed"] = False
        report["finished_realtime_ns"] = time.time_ns()
        checkpoint()
    print(json.dumps({"passed": report["passed"], "report": str(report_path), "error": report.get("error")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
