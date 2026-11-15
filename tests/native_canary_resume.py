#!/usr/bin/env python3
"""Reconcile an interrupted checked canary by reading its two original jobs only.

This helper has no start/cancel operation. It preserves the failed first report,
uses the original request files, and writes a separate observation receipt.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


ENTRY = "HEPTA_NATIVE_CHECKED_FIXTURE_ENTRY"
SCHEMA = "hepta-native-process-library-canary/v1"
TERMINAL = {"succeeded", "failed", "cancelled", "timed_out"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def create(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def event_value(event):
    if "response" in event:
        return event["response"]
    if event.get("exit") == 0:
        return json.loads(event["stdout"])
    return None


def proof(status, job_id):
    require(isinstance(status, dict) and status.get("job_id") == job_id,
            "terminal status does not identify the original job")
    require(status.get("state") in TERMINAL and status.get("status_authoritative") is not False
            and status.get("effect_outcome") != "unknown" and status.get("outcome") != "unknown",
            "original job remains pending or unknown; no automatic retry or new effect")
    require(type(status.get("terminal_publication_protocol")) is int
            and status["terminal_publication_protocol"] == 1
            and all(status.get(key) is True for key in
                    ("terminal_publication_confirmed", "output_complete", "output_durable")),
            "original terminal output lacks a complete durable publication witness")
    nonce = status.get("launch_nonce")
    require(isinstance(nonce, str) and re.fullmatch(r"[0-9a-fA-F]{32}", nonce) is not None,
            "original terminal launch nonce is invalid")
    code, timeout, cancelled = (status.get(key) for key in ("exit_code", "timed_out", "cancelled"))
    require(type(code) is int and -(2**31) <= code < 2**31
            and type(timeout) is bool and type(cancelled) is bool,
            "terminal exit code or outcome flags are missing")
    expected = "timed_out" if timeout else "cancelled" if cancelled else "succeeded" if code == 0 else "failed"
    require(status["state"] == expected, "terminal outcome flags disagree with state")
    stamp = status.get("at_unix_ms")
    require(type(stamp) is int and stamp >= 0, "terminal publication time is missing")
    result = {"state": expected, "exit_code": code, "launch_nonce": nonce, "at_unix_ms": stamp}
    for name in ("stdout", "stderr"):
        size = status.get("log_bytes", {}).get(name, {}).get("stored")
        require(type(size) is int and 0 <= size <= 16384
                and status.get("log_bytes", {}).get(name, {}).get("seen") == size
                and status.get("log_truncated", {}).get(name) is False
                and name in status.get("log_errors", {}) and status["log_errors"][name] is None
                and status.get("log_synced", {}).get(name) is True,
                "terminal stream is incomplete, truncated, unsynced, or exceeds this small canary budget")
        result[name + "_bytes"] = size
    return result


def witness_files(root, kind):
    marker, attempts = root / "work" / (kind + ".marker"), root / "work" / (kind + ".attempts")
    require(marker.read_bytes() == b"one execution\n", "original execution marker changed")
    pids = attempts.read_text().splitlines()
    require(len(pids) == 1 and pids[0].isdigit(), "original worker does not have exactly one attempt")
    return {"attempt_pids": pids, "files": [
        {"path": str(path), "sha256": sha256(path), "device": path.stat().st_dev,
         "inode": path.stat().st_ino, "mtime_ns": path.stat().st_mtime_ns}
        for path in (marker, attempts)]}


def prepare(args):
    report_path = args.resume_report.resolve(strict=True)
    require(sha256(report_path) == args.expected_report_sha256, "first report SHA256 changed")
    report = load(report_path)
    require(report.get("schema") == SCHEMA and report.get("passed") is False
            and report.get("checked_native_entry") is True and report.get("owner_fence_required") is True
            and report.get("entry_fixture_only") is True and report.get("systemd_scope") == "user",
            "require the original interrupted checked native canary, not a replacement report")
    root = Path(report["root"]).resolve(strict=True)
    require(report_path == root / "report.json", "run on the original canary root, not a copied report")
    binary = args.driver.resolve(strict=True)
    require(sha256(binary) == report.get("binary_sha256"), "driver differs from the original exact binary")
    config_path = root / "config.json"
    config = load(config_path)
    host = config.get("hosts", {}).get("native-local-test", {})
    require(config.get("state_dir") == str(root / "state")
            and config.get("controller_workspace_roots") == [str(root / "work")]
            and set(config.get("hosts", {})) == {"native-local-test"}
            and host.get("remote_state_dir") == str(root / "target")
            and host.get("execution_mode") == "operator" and host.get("platform") == "linux"
            and host.get("allow_detached_fallback") is False,
            "original configuration no longer identifies the private systemd fixture")
    authority = root / "authority"
    owner_path = authority / ".owner.json"
    require(load(owner_path) == {"schema": "hepta-effect-owner-fence-v1", "owner": "v4", "epoch": 1,
                                "phase": "admitting", "state_root": str(root / "state"),
                                "predecessor_state_root": None}, "original private owner fence changed")
    require((authority / ".owner.lock").is_file(), "original owner lock is absent; no authority is created")
    environment = os.environ.copy()
    fence = {"HEPTA_EFFECT_OWNER_FENCE_DIR": str(authority), "HEPTA_EFFECT_OWNER_SELF": "v4",
             "HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "1"}
    environment.update(fence)
    requests = [(path, load(path)) for path in sorted((root / "requests").glob("[0-9][0-9][0-9].json"))]
    events = report["events"]
    originals = {}
    for kind in ("resume", "cancel"):
        params = {"host": "native-local-test", "executable": "/usr/bin/python3",
                  "args": [str(root / "work/worker.py"), str(root / "work"), kind],
                  "cwd": str(root / "work"), "stdin": "native exact stdin\n", "timeout_seconds": 45,
                  "idempotency_key": "native-library-" + root.name + "-" + kind, "nice": 10}
        matched = [path for path, value in requests if value == params]
        require(bool(matched), "original " + kind + " request is absent; no new request will be admitted")
        starts = [(index, event_value(event)) for index, event in enumerate(events)
                  if event.get("action") in ("start", "start-hold")
                  and (event.get("exit") == 0 or "response" in event)]
        starts = [(index, value) for index, value in starts
                  if value.get("job", {}).get("idempotency_key") == params["idempotency_key"]
                  and value.get("reused") is False]
        require(len(starts) == 1, "original " + kind + " does not have exactly one recorded launch")
        index, started = starts[0]
        job = started["job"]
        require(started.get("launch", {}).get("backend") == "systemd"
                and job.get("host") == params["host"] and job.get("args") == params["args"]
                and job.get("executable") == params["executable"] and job.get("cwd") == params["cwd"]
                and job.get("ssh_target") == host.get("ssh_target")
                and job.get("remote_job_dir") == str(root / "target/jobs" / job["id"])
                and isinstance(job.get("request_digest"), str)
                and re.fullmatch(r"[0-9a-f]{64}", job["request_digest"]) is not None,
                "original launch receipt does not bind the full private request")
        originals[kind] = {"request": str(matched[0]), "request_sha256": sha256(matched[0]),
                           "params": params, "job": job, "original_start_event_index": index}
    resume_id, cancel_id = (originals[kind]["job"]["id"] for kind in ("resume", "cancel"))
    require(resume_id != cancel_id and report.get("original_job_id") == resume_id,
            "original fixture identities disagree")
    require(report.get("owned_controller_sigkill", {}).get("exit") == -9
            and report["owned_controller_sigkill"].get("stderr", "").count(ENTRY) == 1
            and report.get("running_after_controller_death", {}).get("job_id") == resume_id
            and report["running_after_controller_death"].get("state") == "running"
            and report.get("execution_count") == 1,
            "first report has no completed original-controller restart proof")
    reuse = report.get("same_key_reuse", {})
    require(reuse.get("job", {}).get("id") == resume_id and reuse.get("reused") is True
            and reuse.get("retried_launch") is False, "first same-key reuse proof is absent")
    require(any(event.get("driver_action") == "start-checked" and event.get("exit") == 0
                and event.get("entry_calls") == 0 and event_value(event) == reuse for event in events),
            "first same-key reuse did not record zero entries")
    require(any(event.get("driver_action") == "start-checked" and event.get("exit") != 0
                and event.get("entry_calls") == 0 and "different request" in event.get("stderr", "")
                for event in events), "first changed-payload rejection proof is absent")
    require(proof(report.get("completed_original"), resume_id)["state"] == "succeeded",
            "first report did not complete the resume branch")
    require(events[originals["cancel"]["original_start_event_index"]].get("entry_calls") == 1,
            "original cancel workload did not record exactly one checked entry")
    cancellations = [(index, event_value(event)) for index, event in enumerate(events)
                     if event.get("action") == "cancel" and event.get("exit") == 0]
    cancellations = [(index, value) for index, value in cancellations
                     if value.get("job_id") == cancel_id and value.get("automatic_retry") is False
                     and value.get("result") in {"stop_requested", "term_sent", "kill_sent"}]
    require(len(cancellations) == 1, "original cancellation was not uniquely acknowledged; observe manually")
    require(any(value == {"host": "native-local-test", "job_id": cancel_id, "grace_seconds": 2}
                for _, value in requests), "original cancellation request file is absent")
    inputs = [report_path, config_path, binary, owner_path] + [path for path, _ in requests]
    return report, root, binary, config_path, environment, fence, originals, cancellations[0], inputs


def observe_value(value, original):
    require(isinstance(value, dict) and value.get("observation_only") is True
            and value.get("reused") is True and value.get("retried_launch") is False
            and "launch" in value and value["launch"] is None,
            "observation lost its original no-launch contract")
    job, expected = value.get("job", {}), original["job"]
    for key in ("id", "host", "idempotency_key", "request_digest", "request_fingerprint", "ssh_target",
                "remote_job_dir", "execution_mode", "executable", "args", "cwd", "env_keys", "unit", "system_jobctl"):
        require(key in expected and job.get(key) == expected[key], "observation changed original job " + key)
    return proof(value.get("status"), expected["id"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resume-report", required=True, type=Path)
    parser.add_argument("--expected-report-sha256", required=True)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--call-timeout-seconds", type=float, default=30)
    args = parser.parse_args()
    require(0 < args.call_timeout_seconds <= 60, "read-only call timeout must be in (0, 60]")
    report, root, binary, config, environment, fence, originals, cancellation, inputs = prepare(args)
    receipt_path = args.receipt.absolute()
    require(receipt_path.parent.resolve(strict=True) == root and receipt_path.name != "report.json",
            "new continuation receipt must be inside the original private root")
    requests_dir = receipt_path.with_suffix(".requests")
    require(not receipt_path.exists() and not requests_dir.exists(), "continuation output already exists; preserve it")
    frozen = {str(path): sha256(path) for path in inputs}
    record = {"schema": "hepta-native-process-canary-read-continuation/v1",
              "scope": "fresh read-only reconciliation of two previously launched original jobs",
              "original_report": str(args.resume_report.resolve()), "original_report_sha256": args.expected_report_sha256,
              "original_report_passed": False, "original_report_error": report.get("error"),
              "started_unix_ms": time.time_ns() // 1_000_000, "complete": False,
              "new_execution_submitted": False, "new_cancellation_submitted": False,
              "hepta_finaluse_qualification": False, "entry_fixture_only": True,
              "owner_fence_environment": fence, "inputs_sha256": frozen,
              "original_jobs": originals, "events": [], "jobs": {},
              "original_cancel_ack_event_index": cancellation[0], "original_cancel_ack": cancellation[1],
              "original_cancel_running_observation": any(event.get("action") == "status"
                  and event.get("exit") == 0 and event_value(event).get("job_id") == originals["cancel"]["job"]["id"]
                  and event_value(event).get("state") == "running" for event in report["events"]),
              "cancellation_end_to_end_seconds": None,
              "limitations": ["The failed first report remains failed and byte-for-byte unchanged.",
                  "New read timings are not the original cancel completion time or first-run latency.",
                  "No missing historical status, marker timestamp, or entry event is reconstructed.",
                  "Runtime observation may append its own audit records; it submits no workload or cancellation.",
                  "This is a private systemd fixture, not production FinalUse or host-reboot qualification."]}
    create(receipt_path, record)
    requests_dir.mkdir(mode=0o700)

    def invoke(kind, action, path):
        require(action in {"observe", "read"}, "continuation only permits observation and output read")
        row = {"kind": kind, "action": action, "request": str(path), "request_sha256": sha256(path),
               "started_unix_ms": time.time_ns() // 1_000_000}
        record["events"].append(row)
        save(receipt_path, record)
        started = time.monotonic_ns()
        try:
            result = subprocess.run([str(binary), str(config), action, str(path)], capture_output=True,
                                    text=True, timeout=args.call_timeout_seconds, env=environment, check=False)
        except subprocess.TimeoutExpired as error:
            row.update({"result": "observation_timeout", "stdout": (error.stdout or b"").decode(errors="replace"),
                        "stderr": (error.stderr or b"").decode(errors="replace")})
            raise ValueError("read-only controller timed out; original identity retained and no automatic retry") from None
        finally:
            row["wall_micros"] = (time.monotonic_ns() - started) // 1000
        row.update({"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                    "entry_calls": result.stderr.count(ENTRY)})
        require(result.returncode == 0 and row["entry_calls"] == 0,
                "original observation failed or unexpectedly consumed entry; stop without replay")
        value = json.loads(result.stdout)
        row["response"] = value
        save(receipt_path, record)
        return value

    try:
        for kind in ("resume", "cancel"):
            original = originals[kind]
            before = witness_files(root, kind)
            if kind == "resume":
                require(before["attempt_pids"] == report["worker_attempt_pids"], "original resume attempt identity changed")
            first = invoke(kind, "observe", Path(original["request"]))
            witness = observe_value(first, original)
            expected_state = "succeeded" if kind == "resume" else "cancelled"
            require(witness["state"] == expected_state, "original " + kind + " ended in another outcome")
            if kind == "resume":
                require(witness == proof(report["completed_original"], original["job"]["id"]),
                        "resume publication changed since the first report")
            read_path = requests_dir / (kind + "-read.json")
            create(read_path, {"host": original["params"]["host"], "job_id": original["job"]["id"],
                               "stdout_offset": 0, "stderr_offset": 0, "limit": 16384})
            output = invoke(kind, "read", read_path)
            require(output.get("job_id") == original["job"]["id"], "read returned another original identity")
            streams = {}
            for name in ("stdout", "stderr"):
                page = output.get(name, {})
                raw = page.get("bytes_hex")
                require(isinstance(raw, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2})*", raw) is not None,
                        "read has no lossless byte encoding")
                body = bytes.fromhex(raw)
                require(page.get("offset") == 0 and page.get("next_offset") == len(body)
                        and page.get("size") == len(body) == witness[name + "_bytes"]
                        and page.get("eof") is True, "read is not the entire original terminal stream")
                digest = hashlib.sha256(body).hexdigest()
                if kind == "resume":
                    require(digest == report["output_sha256"][name], "resume output differs from first receipt")
                streams[name] = {"bytes": len(body), "sha256": digest, "bytes_hex": raw}
            last = invoke(kind, "observe", Path(original["request"]))
            require(observe_value(last, original) == witness, "original terminal publication changed during read")
            require(witness_files(root, kind) == before, "worker attempt/marker changed during read continuation")
            record["jobs"][kind] = {"job_id": original["job"]["id"], "terminal": first["status"],
                                     "terminal_proof": witness, "streams": streams, "current_worker_witness": before,
                                     "publication_stable_during_read": True, "read_entry_calls": 0}
            save(receipt_path, record)
        require(all(sha256(Path(path)) == digest for path, digest in frozen.items()),
                "original report, input, driver or owner record changed during continuation")
        record["complete"] = True
    except (Exception, KeyboardInterrupt) as error:
        record["error"] = str(error)
    finally:
        record["finished_unix_ms"] = time.time_ns() // 1_000_000
        record["original_report_unchanged"] = sha256(args.resume_report) == args.expected_report_sha256
        save(receipt_path, record)
    print(json.dumps({"complete": record["complete"], "receipt": str(receipt_path),
                      "original_report_unchanged": record["original_report_unchanged"],
                      "jobs": {kind: value["job_id"] for kind, value in record["jobs"].items()},
                      "error": record.get("error")}, indent=2))
    return 0 if record["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
