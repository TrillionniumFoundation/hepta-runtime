#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Held-agent parent for one qualified R36 normal lifecycle ABBA.

The unchanged Mac holder transmits these bytes on stdin and supplies their SHA.
All actual qualification/terminal/observation identities are bound in a fresh
input receipt; no future candidate binary identity is predicted here.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02")
BASE = Path("/home/qian/hepta-runtime-optimization-20261105-r24")
TOOLS = ROOT / "lifecycle-tools-01"
HELPERS = ROOT / "tools-01/r36_campaign.py"
OUT = ROOT / "lifecycle-campaign-01"
ABBA = ROOT / "lifecycle-abba-01"
TOOL_TESTS = ROOT / "lifecycle-tool-tests-01"
SOCKET_PREFIX = Path("/home/qian/s36lc1")
BASELINE_SHA = "bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13"
HEX = re.compile(r"[0-9a-f]{64}\Z")
CAMPAIGN_SECONDS = 3300
OBSERVATION_RECONCILIATION = {'path': '/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/observation-summary-reconciliation-02.json', 'bytes': 3700, 'sha256': '7b8aaa538fc46bddf091b574bb9ef64246d2e453fec26fcf1ac4795f7a5bf11c'}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def bootstrap_read(path, expected=None):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "indirect bootstrap input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 262144,
             "unsafe bootstrap input")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(262145)
        after = os.fstat(fd)
        fields = ("st_dev","st_ino","st_size","st_mode","st_uid","st_mtime_ns","st_ctime_ns")
        need(len(raw) == before.st_size and tuple(getattr(before,k) for k in fields)
             == tuple(getattr(after,k) for k in fields) == tuple(getattr(path.lstat(),k) for k in fields),
             "bootstrap input changed")
    finally:
        os.close(fd)
    identity = {"path":str(path),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
    if expected is not None:
        need(identity == {key:expected[key] for key in identity}, "bootstrap input identity differs")
    return identity, raw


def terminal_qualification(value, job_id):
    need(value.get("job_id") == job_id and value.get("state") == "succeeded"
         and type(value.get("exit_code")) is int and value["exit_code"] == 0
         and all(value.get(key) is False for key in ("automatic_retry","timed_out","cancelled"))
         and all(value.get(key) is True for key in ("output_complete","output_durable","terminal_publication_confirmed"))
         and type(value.get("terminal_publication_protocol")) is int and value["terminal_publication_protocol"] == 1
         and value.get("log_synced") == {"stdout":True,"stderr":True}
         and value.get("log_errors") == {"stdout":None,"stderr":None}
         and value.get("log_truncated") == {"stdout":False,"stderr":False},
         "original qualification job is not a fully witnessed successful terminal receipt")


def completed_observation(value, summary=None):
    need(value["schema"] == "hepta-r25-observation-campaign-control/v1"
         and all(value.get(key) is True for key in ("passed","observation_gate_passed","inputs_unchanged",
             "source_inputs_unchanged","baseline_source_inputs_unchanged","correctness_stages_completed","baseline_enablement_verified",
             "measurement_attribution_valid"))
         and value.get("finished_utc") and type(value["automatic_retries"]) is int and value["automatic_retries"] == 0,
         "normal observation campaign did not close and pass")
    need(value["stages"] and all(row["passed"] is True and type(row["returncode"]) is int and row["returncode"] == 0
         and row["waited_and_reaped"] is True and row["owned_process_absent"] is True
         and row["owned_process_group_absent"] is True for row in value["stages"]),
         "observation campaign stage ownership did not close")
    if summary is not None:
        need(summary["schema"] == "hepta-r25-observation-gates/v1"
             and all(summary[key] is True for key in ("evidence_verified","correctness_verified","observation_gate_passed"))
             and summary["rejection_reasons"] == [], "independent observation gate did not pass")


def reconciled_observation(parent, inputs, bind):
    """Read the sealed original failure and the actual stage-7-only completion."""
    need(inputs["observation_reconciliation"] == OBSERVATION_RECONCILIATION,
         "only the sealed OBS02 stage-7 reconciliation is authorized")
    identity, raw = bind(OBSERVATION_RECONCILIATION["path"], OBSERVATION_RECONCILIATION, retain=True)
    reconciliation = json.loads(raw)
    need(reconciliation["schema"] == "hepta-r36-observation-stage7-reconciliation/v1"
         and reconciliation["attempt"] == "02", "different observation reconciliation")
    files = reconciliation["files"]
    retained = {label: bind(item["path"], item, retain=True)[1] for label, item in files.items()}
    value = json.loads(retained["original_parent"])
    summary = json.loads(retained["corrected_summary"])
    need(files["original_parent"] == inputs["observation_campaign"]
         and files["original_parent"]["path"] == str(ROOT / "campaign-02/report.json")
         and value["schema"] == "hepta-r25-observation-campaign-control/v1"
         and value["attempt"] == "02" and value["passed"] is False and value["observation_gate_passed"] is False
         and "summary" not in value and value["finished_utc"] and value["automatic_retries"] == 0
         and value["launcher_sha256"] == inputs["campaign_helpers"]["sha256"]
         and value["input_receipt"]["path"] == str(ROOT / "campaign-inputs-02.json")
         and all(value.get(key) is True for key in ("inputs_unchanged", "source_inputs_unchanged",
             "baseline_source_inputs_unchanged", "baseline_enablement_verified", "measurement_attribution_valid"))
         and value["quiescence"]["passed"] is True,
         "original observation failure or qualified inputs differ")
    names = ["native-observation", "native-audit", "native-boundary", "boundary-audit", "cancel-recovery", "recovery-audit"]
    need([row["name"] for row in value["stages"]] == names + ["observation-summary"], "original seven stages differ")
    parent.r36_owner_closed_stages(value["stages"][:6], names)
    last = value["stages"][-1]
    need(last["passed"] is False and last["returncode"] == 1 and last["timed_out"] is False
         and all(last[key] is True for key in ("waited_and_reaped", "owned_process_absent", "owned_process_group_absent"))
         and all(row["cleanup_signals"] == [] for row in value["stages"])
         and last["output_bindings"] == [] and last["stderr"] == files["original_summary_stderr"]
         and last["stdout"] == files["original_summary_stdout"] and retained["original_summary_stdout"] == b""
         and retained["original_summary_stderr"].endswith(b"ValueError: historical six-machine topology differs\n")
         and value["error"] == last["error"] == {"type": "RuntimeError", "reason":
             "observation-summary returned nonzero; original output retained"},
         "only the closed stage-7 topology identity failure can be reconciled")
    change = reconciliation["source_change"]
    before = ('TOPOLOGY_SHA = "' + change["before"] + '"').encode()
    after = ('TOPOLOGY_SHA = "' + change["after"] + '"').encode()
    need(change["constant"] == "TOPOLOGY_SHA" and change["after"] == parent.TOPOLOGY_SHA
         and retained["original_summary_source"].count(before) == 1
         and retained["original_summary_source"].replace(before, after) == retained["corrected_summary_source"]
         and files["original_summary_source"]["path"] == last["argv"][2],
         "summary correction changes more than the frozen topology identity")
    need(summary["schema"] == "hepta-r25-observation-gates/v1"
         and all(summary[key] is True for key in ("evidence_verified", "correctness_verified",
             "performance_gates_passed", "observation_gate_passed"))
         and summary["rejection_reasons"] == [] and summary["thresholds"] == value["thresholds"]
         and summary["binary_sha256"] == {arm: value["binaries"][arm]["hepta-runtime"]["sha256"] for arm in ("A", "B")},
         "corrected summary did not pass the unchanged original gates")
    labels = ("native_report", "native_analysis", "boundary_report", "boundary_analysis", "lifecycle_report", "lifecycle_analysis")
    for label, stage in zip(labels, value["stages"][:6]):
        need(stage["output_bindings"] == [summary["evidence"][label]], "summary used different original stage evidence")
        item = summary["evidence"][label]
        bind(item["path"], item)
    holder = json.loads(retained["original_holder"])
    need(holder["passed"] is False and holder["remote_returncode"] == 1 and holder["automatic_ssh_retries"] == 0
         and holder.get("foreground_timed_out", False) is False
         and all(holder[key] is True for key in ("owned_agent_reaped", "owned_agent_directory_absent_after_context",
             "owned_agent_socket_absent_after_context"))
         and holder["remote_script_sha256"] == value["launcher_sha256"]
         and holder["foreground_argv"][-4:] == ["--launcher-sha256", value["launcher_sha256"], "--inputs", value["input_receipt"]["path"]],
         "original holder failed for another reason or its owned agent did not close")
    terminal = json.loads(retained["original_terminal"])
    parent.r36_owner_native_terminal(terminal, reconciliation["original_job_id"], state="failed", exit_code=1)
    streams = parent.r36_owner_native_streams(json.loads(retained["original_read"]), terminal)
    holder_lines = [json.loads(line) for line in streams["stdout"].splitlines()]
    need(streams["stderr"] == b"" and len(holder_lines) == 2
         and holder_lines[0] == {"phase": "owned_agent_ready", "identity_count": 5, "remote_script_sha256": value["launcher_sha256"]}
         and holder_lines[1] == {"passed": False, "remote_returncode": 1, "owned_agent_reaped": True,
             "report": "/Users/qianqi/work/hepta-runtime-r36-validation-scratch-cold-02-observation-holder-02/report.json"},
         "original holder terminal/readback differs")
    terminal = json.loads(retained["repair_terminal"])
    parent.r36_owner_native_terminal(terminal, reconciliation["repair_job_id"])
    streams = parent.r36_owner_native_streams(json.loads(retained["repair_read"]), terminal)
    need(streams["stderr"] == b"" and json.loads(streams["stdout"]) == {"evidence_verified": True,
         "observation_gate_passed": True, "rejection_reasons": [], "output": files["corrected_summary"]["path"]},
         "corrected summary native terminal/readback differs")
    start = json.loads(retained["repair_start"])
    expected = list(last["argv"])
    expected[2], expected[-1] = files["corrected_summary_source"]["path"], files["corrected_summary"]["path"]
    need(start["audit_recorded"] is True and start["reused"] is False and start["launch"]["ok"] is True
         and start["job"]["id"] == reconciliation["repair_job_id"] and start["job"]["launch_state"] == "launched"
         and start["job"]["launch_error"] is None and start["job"]["cwd"] == str(ROOT)
         and start["job"]["env_keys"] == [] and start["job"]["executable"] == expected[0]
         and start["job"]["args"] == expected[1:], "repair reran other work or changed summary arguments")
    proof = {"reconciliation": identity, "original_parent": files["original_parent"], "original_parent_passed": False,
             "corrected_summary": files["corrected_summary"], "original_job_id": reconciliation["original_job_id"],
             "repair_job_id": reconciliation["repair_job_id"], "source_change": change}
    return files["original_parent"], value, files["corrected_summary"], summary, proof


def verify_completed_observation_monitor(parent, observed, inputs, bind):
    """Apply the original full monitor verification to the sealed OBS02 directory."""
    expected_output = ROOT / "campaign-02"
    need(observed["attempt"] == "02" and observed["input_receipt"]["path"] == str(ROOT / "campaign-inputs-02.json"),
         "fixed OBS02 monitored input required")
    COMPILER_MONITOR_LIMITS = parent.COMPILER_MONITOR_LIMITS
    COMPILER_MONITOR_PATHS = parent.COMPILER_MONITOR_PATHS
    bind_compiler_monitor_inputs = parent.bind_compiler_monitor_inputs
    monitor_module = parent.monitor_module
    need(observed.get("measurement_attribution_valid") is True,
         "observation compiler monitoring did not authorize performance attribution")
    monitor = observed["compiler_monitor"]
    need(monitor["passed"] is True and monitor["monitor_sources_unchanged"] is True
         and monitor["limits"] == COMPILER_MONITOR_LIMITS, "completed compiler monitor gate differs")
    raw, proof = bind_compiler_monitor_inputs(inputs, bind)
    need(monitor["sources"] == proof["sources"], "observation monitor source set differs")
    need(monitor["ledger"]["path"] == str(expected_output / "compiler-monitor.json")
         and monitor["independent_audit"]["path"] == str(expected_output / "compiler-monitor.audit.json"),
         "completed compiler monitor evidence paths differ")
    ledger_identity, ledger_raw = bind(monitor["ledger"]["path"], monitor["ledger"], retain=True,
                                       maximum=16 * 1024 * 1024)
    audit_identity, audit_raw = bind(monitor["independent_audit"]["path"], monitor["independent_audit"], retain=True)
    ledger, audit = json.loads(ledger_raw), json.loads(audit_raw)
    need(ledger["source_bindings"] == proof, "retained compiler ledger source binding differs")
    validator = monitor_module("_r26_bound_prior_monitor_validator", raw["validator"], COMPILER_MONITOR_PATHS["validator"])
    validation = validator.validate(ledger, COMPILER_MONITOR_LIMITS,
        monitor["guarded_body_start_monotonic_ns"], monitor["guarded_body_end_monotonic_ns"])
    need(validation["passed"] is True and audit == {
        "schema": "hepta-r26-compiler-monitor-audit/v1", "ledger": ledger_identity,
        "validator": proof["sources"]["validator"], "validation": validation,
        "monitor_sources_unchanged": True, "source_recheck_errors": []}, "independent compiler monitor ledger verification failed")
    return {"passed": True, "ledger": ledger_identity, "independent_audit": audit_identity,
            "validator": proof["sources"]["validator"], "validation": validation}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher-sha256", required=True)
    parser.add_argument("--inputs", type=Path, default=ROOT / "lifecycle-inputs-01.json")
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0 and HEX.fullmatch(args.launcher_sha256),
         "Linux operator and original holder SHA required")
    need(args.inputs.absolute() == ROOT / "lifecycle-inputs-01.json", "single frozen input receipt path required")
    input_identity, input_raw = bootstrap_read(args.inputs)
    inputs = json.loads(input_raw)
    need(inputs["schema"] == "hepta-r25-lifecycle-inputs/v1" and inputs["attempt"] == "01"
         and inputs["launcher_sha256"] == args.launcher_sha256, "input schema/holder receipt differs")
    helper_identity, _ = bootstrap_read(HELPERS, inputs["campaign_helpers"])
    spec = importlib.util.spec_from_file_location("r25_bound_campaign_helpers", HELPERS)
    parent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parent)
    need(Path(parent.__file__).resolve() == HELPERS, "helper module path differs")
    parent.require_r36_preparation_seal()
    checked, create, save = parent.checked, parent.create, parent.save
    process_identity, group_present = parent.process_identity, parent.group_present
    machine_snapshot, utc = parent.machine_snapshot, parent.utc
    parent.private_directory(OUT, create_new=True)
    out = OUT
    report_path = out / "report.json"
    deadline = time.monotonic() + CAMPAIGN_SECONDS
    report = {"schema":"hepta-r36-normal-lifecycle-campaign-control/v1","passed":False,"adoption_passed":False,
              "adoption_scope":parent.R36_ADOPTION_SCOPE,"saturated_cancellation_verified":False,
              "open_blockers":parent.R36_OPEN_BLOCKERS,
              "started_utc":utc(),"launcher_sha256":args.launcher_sha256,
              "launcher_identity_origin":"Original Mac holder SHA of transmitted stdin bytes",
              "input_receipt":input_identity,"campaign_helpers":helper_identity,
              "input_bindings":[],"stages":[],"automatic_retries":0,"production_services_modified":False,
              "inputs_unchanged":False,"source_inputs_unchanged":False,"baseline_source_inputs_unchanged":False,
              "candidate_binary_sha256":None,"campaign_budget_seconds":CAMPAIGN_SECONDS}
    create(out / "inputs.json", input_raw)
    candidate_source = baseline_source = None
    bench = agent_identity = None
    compiler_monitor = monitor_validator = monitor_proof = None
    monitored_body_start = None
    agent = os.environ.get("SSH_AUTH_SOCK", "")

    def checkpoint():
        save(report_path, report)

    def bind(path, expected=None, retain=False, maximum=128*1024*1024):
        result = checked(path, expected, maximum, retain)
        report["input_bindings"].append(result[0] if retain else result)
        return result

    def unchanged():
        need(checked(args.inputs) == input_identity and checked(HELPERS) == helper_identity,
             "parent input/helper identity changed")
        for item in report["input_bindings"]:
            need(checked(item["path"], item) == item, "bound campaign prerequisite changed")
        need(bench.agent_identity(agent) == agent_identity, "held forwarded agent changed")
        if candidate_source is not None:
            need(parent.source_inputs(parent.SOURCE) == candidate_source, "qualified candidate source changed")
        if baseline_source is not None:
            need(parent.source_inputs(BASE / "source") == baseline_source, "qualified baseline source changed")

    def run_stage(spec):
        remaining = deadline - time.monotonic() - 160
        need(remaining > 0, "campaign deadline exhausted before a new stage")
        timeout = min(spec["timeout_seconds"], remaining)
        row = dict(spec, effective_timeout_seconds=timeout, started_utc=utc(), start_monotonic_ns=time.monotonic_ns(),
                   returncode=None, waited_and_reaped=False, cleanup_signals=[], machine_before=machine_snapshot(),
                   cleanup_scope="owned stage process group only; independent controller sessions are proved by original reports/audits")
        report["stages"].append(row)
        checkpoint()
        stdout_path, stderr_path = out / (spec["name"] + ".stdout"), out / (spec["name"] + ".stderr")
        child, birth, primary = None, None, None
        print(json.dumps({"stage": spec["name"], "status": "started", "out": str(out)}), flush=True)
        try:
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                child = subprocess.Popen(spec["argv"], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                         cwd=ROOT, start_new_session=True)
                row["pid"] = child.pid
                birth = process_identity(child.pid)
                need(birth is not None and birth["process_group"] == child.pid, "owned stage identity unavailable")
                row["identity"] = birth
                checkpoint()
                row["returncode"] = child.wait(timeout=timeout)
                row["waited_and_reaped"] = True
                need(row["returncode"] == 0, spec["name"] + " returned nonzero; original output retained")
        except BaseException as error:
            primary = error
            row["error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
            row["timed_out"] = isinstance(error, subprocess.TimeoutExpired)
        finally:
            if child is not None:
                try:
                    if child.poll() is None:
                        # Leave time for the original 30+10+10 second Controller
                        # close path, reader join and an in-flight RPC. Even a
                        # reaped stage group does not prove its separate runtime
                        # sessions are gone; failures retain that uncertainty.
                        for sig, seconds in ((signal.SIGINT, 120), (signal.SIGTERM, 10), (signal.SIGKILL, 10)):
                            need(birth is not None and process_identity(child.pid) == birth, "owned stage identity changed before cleanup")
                            os.killpg(child.pid, sig)
                            row["cleanup_signals"].append({"signal": sig.name, "utc": utc()})
                            try:
                                child.wait(timeout=seconds)
                                break
                            except subprocess.TimeoutExpired:
                                continue
                    row["returncode"] = child.wait(timeout=1)
                    row["waited_and_reaped"] = True
                    row["owned_process_absent"] = process_identity(child.pid) is None
                    row["owned_process_group_absent"] = not group_present(child.pid)
                    need(row["owned_process_absent"] and row["owned_process_group_absent"], "owned stage/session remains; no next stage")
                except BaseException as error:
                    row["cleanup_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
                    primary = primary or error
            row["finished_utc"] = utc()
            row["end_monotonic_ns"] = time.monotonic_ns()
            row["elapsed_seconds"] = (row["end_monotonic_ns"] - row["start_monotonic_ns"]) / 1e9
            row["machine_after"] = machine_snapshot()
            for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                if path.exists():
                    row[name] = checked(path)
            row["output_bindings"] = [checked(Path(path)) for path in spec["outputs"] if Path(path).is_file()]
            row["passed"] = primary is None and len(row["output_bindings"]) == len(spec["outputs"])
            if not row["passed"] and spec["name"] in {"normal-lifecycle-abba"}:
                row["independent_controller_cleanup"] = "unknown; stage-group absence is insufficient and no workload is retried"
            checkpoint()
            print(json.dumps({"stage": spec["name"], "passed": row["passed"], "returncode": row["returncode"]}), flush=True)
        if primary is not None:
            raise primary
        need(row["passed"], "expected stage output missing")

    try:
        checkpoint()
        compiler_monitor, monitor_validator, monitor_proof = parent.prepare_compiler_monitor(inputs, bind)
        monitor_ready = compiler_monitor.start()
        monitored_body_start = time.monotonic_ns()
        need(monitor_ready, "initial compiler monitor sample failed; no lifecycle fixture submitted")
        report["compiler_monitor_scope"] = parent.COMPILER_MONITOR_POLICY["guarded_interval"]
        report["machine_initial"] = machine_snapshot()
        report["candidate_release"] = "R36"
        report["candidate_preparation_gate"] = parent.bind_r36_candidate_preparation(inputs, bind)
        _, terminal_raw = bind(ROOT / "qualification-terminal-status-01.json", inputs["qualification_terminal_status"], retain=True)
        terminal_qualification(json.loads(terminal_raw), inputs["qualification_terminal_status"]["job_id"])
        report["qualification_original_job_terminal_verified"] = True
        observation_identity, observation, summary_identity, observation_summary, reconciliation_proof = reconciled_observation(parent, inputs, bind)
        report["observation_reconciliation"] = reconciliation_proof
        report["observation_compiler_monitor_gate"] = verify_completed_observation_monitor(parent, observation, inputs, bind)
        _, prior_input_raw = bind(observation["input_receipt"]["path"], observation["input_receipt"], retain=True)
        prior_inputs = json.loads(prior_input_raw)
        need(all(inputs[name] == prior_inputs[name] for name in ("qualification_preparation",
             "qualification_terminal_status", "qualification_launcher", "qualification_input", "candidate_patch")),
             "lifecycle qualification differs from the completed observation input")
        report["binaries"] = {"A":{},"B":{}}
        for name in parent.BINARY_NAMES:
            report["binaries"]["A"][name] = bind(BASE / "qualification-01" / name, observation["binaries"]["A"][name])
            report["binaries"]["B"][name] = bind(parent.CANDIDATE_DIR / name, inputs["candidate_binaries"][name])
        need(report["binaries"] == observation["binaries"]
             and report["binaries"]["A"]["hepta-runtime"]["sha256"] == BASELINE_SHA,
             "actual runtime artifacts differ from accepted observation arms")
        report["candidate_binary_sha256"] = report["binaries"]["B"]["hepta-runtime"]["sha256"]
        candidate_source = parent.source_inputs(parent.SOURCE)
        baseline_source = parent.source_inputs(BASE / "source")
        need(candidate_source["sha256"] == inputs["source_inputs_sha256"] == observation["source_inputs_sha256"]
             and baseline_source["sha256"] == observation["baseline_source_inputs_sha256"], "source differs from completed observation campaign")
        qualifications = {}
        for arm, records, source in (("A",prior_inputs["baseline"]["qualification_reports"],BASE/"source"),
                                     ("B",[inputs["qualification_report"]],parent.SOURCE)):
            qualified = []
            for item in records:
                _, raw = bind(item["path"], item, retain=True)
                value = json.loads(raw)
                parent.verify_composed_qualification(value, source, report["binaries"][arm])
                need(value.get("finished_utc") and value["source_after"] == parent.qualification_projection(
                    baseline_source if arm == "A" else candidate_source), "qualified source does not match current bytes")
                qualified.append(value)
            need(qualified, "missing actual composed qualification")
            qualifications[arm] = True
        report["qualified_source_maps_match_current_inputs"] = qualifications
        for label in ("campaign_report", "publication_readback"):
            item = prior_inputs["baseline"][label]
            _, raw = bind(item["path"], item, retain=True)
            if label == "campaign_report":
                old_campaign = json.loads(raw)
            else:
                old_publication = json.loads(raw)
        parent.verify_baseline_enablement(old_campaign, old_publication, report["binaries"]["A"],
            prior_inputs["baseline"]["publication_readback"]["commit"], prior_inputs["baseline"]["campaign_report"]["sha256"])
        manifest_identity, manifest_raw = bind(TOOLS / "lifecycle-tools-manifest-01.json", inputs["tools_manifest"], retain=True)
        manifest = json.loads(manifest_raw)
        need(manifest["schema"] == "hepta-r25-lifecycle-tools/v1" and len(manifest["files"]) == 27,
             "frozen lifecycle tool set differs")
        for name, item in sorted(manifest["files"].items()):
            need(Path(name).name == name and name not in {".","..","lifecycle-tools-manifest-01.json"}, "unsafe tool member")
            bind(TOOLS / name, item, maximum=262144)
        bind(parent.PROFILE, parent.PROFILE_SHA)
        bind(parent.TOPOLOGY, parent.TOPOLOGY_SHA)
        frozen = sorted(parent.FROZEN_JOBS.glob("*.json"))
        need(len(frozen) == 6, "six frozen fixture originals required")
        for path in frozen:
            bind(path, maximum=65536)
        for path in (ABBA,TOOL_TESTS,SOCKET_PREFIX):
            need(not os.path.lexists(path) and path.resolve() == path, "fresh lifecycle/gate/socket output required")
        for number, arm in enumerate("ABBA"):
            path = SOCKET_PREFIX.with_name(SOCKET_PREFIX.name + f"-{number}-{arm}")
            need(not os.path.lexists(path), "derived ABBA socket directory exists")
        need(agent.startswith("/"), "held forwarded SSH agent required")
        sys.path.insert(0,str(TOOLS))
        import x230_observation_benchmark as imported_bench
        bench = imported_bench
        need(Path(bench.__file__).resolve() == TOOLS / "x230_observation_benchmark.py", "unexpected benchmark helper")
        agent_identity = bench.agent_identity(agent)
        report["agent_identity"] = agent_identity
        report["source_inputs_sha256"] = candidate_source["sha256"]
        report["baseline_source_inputs_sha256"] = baseline_source["sha256"]
        create(out / "source-inputs.json", parent.canonical(candidate_source))
        create(out / "baseline-source-inputs.json", parent.canonical(baseline_source))
        report["source_inputs"] = checked(out / "source-inputs.json")
        report["baseline_source_inputs"] = checked(out / "baseline-source-inputs.json")
        common = ["--profile-template",str(parent.PROFILE),"--topology",str(parent.TOPOLOGY),"--frozen-jobs",str(parent.FROZEN_JOBS)]
        plan = [
            {"name":"lifecycle-tool-tests","argv":["/usr/bin/python3","-B",str(TOOLS/"run_lifecycle_tool_tests.py"),"--out",str(TOOL_TESTS)],
             "timeout_seconds":120,"outputs":[str(TOOL_TESTS/"report.json")]},
            {"name":"normal-lifecycle-abba","argv":["/usr/bin/python3","-B",str(TOOLS/"run_lifecycle_abba_01.py"),
                "--baseline",str(BASE/"qualification-01/hepta-runtime"),"--candidate",str(parent.CANDIDATE),
                "--expected-baseline-sha256",BASELINE_SHA,"--expected-candidate-sha256",report["candidate_binary_sha256"],
                "--expected-tools-manifest-sha256",manifest_identity["sha256"],*common,"--out",str(ABBA),
                "--socket-prefix",str(SOCKET_PREFIX),"--workers","2","--arena-max","1"],
             "timeout_seconds":1500,"outputs":[str(ABBA/"report.json"),str(ABBA/"round-index.json"),str(ABBA/"summary.json"),str(ABBA/"gates.json")]},
        ]
        report["stage_plan"] = plan
        create(out / "plan.json", parent.canonical({"schema":"hepta-r25-lifecycle-parent-plan/v1", "stage_plan":plan,
            "binaries":report["binaries"],"source_inputs_sha256":candidate_source["sha256"],"tools_manifest":manifest_identity,
            "observation_campaign":observation_identity,"automatic_retries":0}))
        report["plan"] = checked(out / "plan.json")
        cooling = {"seconds_planned":parent.QUIESCENCE_SECONDS,"checks":[],"start_monotonic_ns":time.monotonic_ns()}
        report["quiescence"] = cooling
        until = time.monotonic() + parent.QUIESCENCE_SECONDS
        while True:
            busy = parent.compiler_activity()
            cooling["checks"].append({"machine":machine_snapshot(),"compiler_processes":busy})
            checkpoint()
            need(not busy, "compiler overlaps lifecycle campaign; no workload submitted")
            remaining = until-time.monotonic()
            if remaining <= 0:
                break
            print(json.dumps({"stage":"quiescence","remaining_seconds":round(remaining,1)}),flush=True)
            time.sleep(min(15,remaining))
        cooling.update(end_monotonic_ns=time.monotonic_ns(),passed=True)
        for stage in plan:
            unchanged()
            need(not parent.compiler_activity(), "compiler overlaps lifecycle stage")
            run_stage(stage)
            if stage["name"] == "lifecycle-tool-tests":
                tests = json.loads(checked(TOOL_TESTS/"report.json",retain=True)[1])
                need(tests["passed"] is True and tests["tests_run"] == 14 and tests["skipped"] == tests["errors"] == tests["failures"] == 0,
                     "all 14 native harness tests must pass before remote fixtures")
        unchanged()
        normal = json.loads(checked(ABBA/"report.json",retain=True)[1])
        gates = json.loads(checked(ABBA/"gates.json",retain=True)[1])
        need(normal["passed"] is True and normal["inputs_unchanged"] is True and gates["verified"] is True and gates["passed"] is True,
             "normal lifecycle nonregression did not pass")
        report.update(passed=True,adoption_passed=True,inputs_unchanged=True,source_inputs_unchanged=True,
            baseline_source_inputs_unchanged=True,normal_lifecycle_gate=checked(ABBA/"gates.json"),
            observation_gate_verified=True)
    except BaseException as error:
        report.update(passed=False,adoption_passed=False,uncertain_effects_are_not_retried=True,
                      error={"type":type(error).__name__,"reason":str(error)[:4000]})
        create(out / "campaign.error.txt", traceback.format_exc().encode())
    finally:
        if bench is not None and agent_identity is not None:
            try:
                unchanged()
                report["inputs_unchanged"] = True
            except BaseException as error:
                report.update(passed=False,adoption_passed=False,inputs_unchanged=False,
                              finalization_error={"type":type(error).__name__,"reason":str(error)[:3000]})
        for key, source, before in (("source_inputs_unchanged",parent.SOURCE,candidate_source),
                                    ("baseline_source_inputs_unchanged",BASE/"source",baseline_source)):
            if before is not None:
                try:
                    report[key] = parent.source_inputs(source) == before
                    if not report[key]:
                        report["passed"] = report["adoption_passed"] = False
                except BaseException as error:
                    report[key] = False
                    report["passed"] = report["adoption_passed"] = False
                    report[key+"_error"] = str(error)[:2000]
        monitored_body_end = time.monotonic_ns()
        parent.finish_compiler_monitor(compiler_monitor, monitor_validator, monitor_proof,
            monitored_body_start, monitored_body_end, out, report, "adoption_passed")
        report["finished_utc"] = utc()
        report["machine_final"] = machine_snapshot()
        checkpoint()
        print(json.dumps({"passed":report["passed"],"adoption_passed":report["adoption_passed"],
                          "error":report.get("error"),"report":str(report_path)}),flush=True)
    return 0 if report["passed"] else 1


def interrupted(signum, _frame):
    raise RuntimeError("lifecycle campaign interrupted by signal " + str(signum))


if __name__ == "__main__":
    os.umask(0o077)
    for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        signal.signal(signum,interrupted)
    raise SystemExit(main())
