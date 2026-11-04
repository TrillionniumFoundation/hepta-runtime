#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify a fixed one-second native capture deadline through the original job.

This is an opt-in, same-host authored fixture test. It neither changes production
services nor increases the manifest deadline to obtain a passing outcome.
"""
import argparse
import hashlib
import importlib
import json
import platform
from pathlib import Path
import shutil
import sys
import time


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--expected-runtime-sha256", required=True)
    parser.add_argument("--source-qualification", type=Path)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--helper-directory", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--allow-owned-browser", action="store_true")
    parser.add_argument("--allow-local-ssh", action="store_true")
    args = parser.parse_args()
    assert args.allow_owned_browser and args.allow_local_ssh, "Explicit owned-browser and local-SSH flags are required"
    assert sys.platform == "linux", "This qualification requires Linux same-host jobs"
    helpers = args.helper_directory.resolve(strict=True)
    sys.path.insert(0, str(helpers))
    browser = importlib.import_module("rea_browser_external")
    common = importlib.import_module("rea_java_external")
    assert Path(browser.__file__).resolve() == helpers / "rea_browser_external.py"
    assert Path(common.__file__).resolve() == helpers / "rea_java_external.py"
    Mcp, fixture = common.Mcp, browser.fixture
    terminal, original_output = browser.terminal, browser.original_output
    no_owned_browser = browser.no_owned_browser
    private_write, set_fence = common.private_write, common.set_fence
    helper_sources = {str(path): digest(path) for path in [
        helpers / "rea_browser_external.py", helpers / "rea_java_external.py", Path(__file__).resolve()]}
    selected_runtime = args.runtime.resolve(strict=True)
    assert digest(selected_runtime) == args.expected_runtime_sha256, "Selected runtime SHA mismatch"
    root = args.workspace.absolute()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    runtime = root / "hepta-runtime-qualified"
    shutil.copyfile(selected_runtime, runtime)
    runtime.chmod(0o500)
    assert digest(runtime) == args.expected_runtime_sha256
    source_provenance = None
    if args.source_qualification is not None:
        source = args.source_qualification.resolve(strict=True)
        value = json.loads(source.read_text())
        assert value["qualified"] is True and value["capture_implementation"] == "native-rust"
        assert value["runtime_sha256"] == args.expected_runtime_sha256
        source_provenance = {"qualification_path": str(source), "qualification_sha256": digest(source),
                             "recorded_runtime_sha256": value["runtime_sha256"],
                             "recorded_native_source_sha256": value["helper_sources"],
                             "scope": "Historical native source identity recorded with the selected qualified binary; no current-source substitution."}
    for name in ("controller-state", "jobs", "authority"):
        (root / name).mkdir(mode=0o700)
    private_write(root / "authority/.owner.lock", b"")
    set_fence(root, "admitting")
    config = {
        "state_dir": str(root / "controller-state"), "controller_workspace_roots": [str(root)],
        "hosts": {"local": {"ssh_target": "localhost", "platform": "linux", "execution_mode": "operator",
                           "remote_state_dir": str(root / "jobs"),
                           "allow_execute": True, "allow_write": True, "allow_job_network": True,
                           "allow_detached_fallback": False, "allowed_cwd_prefixes": [],
                           "allowed_read_path_prefixes": [str(root)], "allowed_write_path_prefixes": [str(root)]}}}
    private_write(root / "config.json", config)
    manifest, output = fixture(root, "deadline-fixture", slow=True)
    declared = json.loads(manifest.read_text())
    assert declared["requests"] == ["/text"] * 32
    assert declared["resources"][0]["delay_ms"] == 2000
    declared["timeout_seconds"] = 1
    private_write(manifest, declared)
    manifest_sha = digest(manifest)
    resource_pins = {}
    for resource in declared["resources"]:
        for phase in ("before", "after"):
            source = resource.get(phase, resource["before"])
            path = manifest.parent / source["file"]
            assert digest(path) == source["sha256"]
            resource_pins[str(path)] = digest(path)
    request = {"host": "local", "executable": str(runtime),
               "args": ["rea-browser-capture", "--manifest", str(manifest), "--expected-sha256", manifest_sha,
                        "--output-directory", str(output)],
               "cwd": str(root), "env": {}, "timeout_seconds": 100,
               "idempotency_key": "owned-native-browser-deadline-one-second",
               "nice": 10, "cpu_quota_percent": 100, "memory_max_bytes": 1024 * 1024 * 1024}
    request_path = root / "deadline-request.json"
    private_write(request_path, request)
    result = {
        "schema": "hepta.rea.native-browser-deadline-qualification.v1",
        "workspace": str(root), "qualified": False, "host_system": platform.platform(),
        "execution_mode": "operator", "runtime_sha256": args.expected_runtime_sha256,
        "runtime_path": str(runtime), "helper_sources": helper_sources,
        "source_provenance": source_provenance,
        "manifest_path": str(manifest), "manifest_sha256": manifest_sha,
        "manifest_timeout_seconds": 1, "outer_job_timeout_seconds": 100,
        "slow_request_count": 32, "slow_resource_delay_ms": 2000,
        "request_path": str(request_path), "request_sha256": digest(request_path),
        "resource_sha256": resource_pins,
        "process_level_network_isolation": False,
        "changed_session_descendants_covered": False,
        "deadline_phase_more_specific_than_native_capture_observed": False,
        "checks": [],
    }
    server, active = None, None
    try:
        server = Mcp(runtime, root)
        started_at = time.monotonic()
        admission = server.call("process_start", request)
        active = admission["job"]["id"]
        result["original_job_id"] = active
        private_write(root / "deadline-admission.json", admission)
        assert admission["job"].get("launch_state") != "launch_unknown", admission
        stopped = terminal(server, active, timeout=100)
        result["capture_observed_elapsed_seconds"] = time.monotonic() - started_at
        logs = original_output(server, active)
        private_write(root / "deadline-terminal.json", {"status": stopped, "output": logs})
        assert stopped["job_id"] == active
        assert stopped["state"] == "failed" and stopped["exit_code"] != 0, stopped
        assert stopped.get("timed_out") is False, "Outer process deadline fired; not the manifest deadline"
        assert stopped.get("cancelled") is False, "A cancellation is not native deadline evidence"
        assert stopped.get("output_complete") is True
        assert "fixed browser capture deadline exceeded" in logs["stderr"], logs
        events = [json.loads(line) for line in logs["stdout"].splitlines()]
        starts = [value for value in events if value.get("phase") == "browser_started"]
        assert len(starts) == 1, ("one actual original Chrome start required", events)
        assert starts[0]["implementation"] == "native-rust"
        assert not any(value.get("phase") == "complete" for value in events), events
        started = starts[0]
        private_write(root / "deadline-original-browser.json", started)
        no_owned_browser(started["profile"], started["browser_pgid"])
        assert not list(output.rglob("*.har")) if output.exists() else True
        assert not (output / "capture-receipt.json").exists()
        assert not list(manifest.parent.glob(".hepta-private-capture-*"))
        result["checks"].extend([
            "exact_one_second_manifest_and_two_second_resource_delay_under_100_second_outer_job",
            "original_job_failed_with_explicit_native_capture_deadline_stderr_not_outer_timeout_or_other_startup_failure",
            "one_actual_original_chrome_start_and_no_complete_capture_event",
            "original_chrome_process_group_has_no_live_members_and_private_profile_removed",
            "no_har_or_success_receipt_published"])
        reused = server.call("process_start", request)
        assert reused["reused"] is True and reused["job"]["id"] == active
        reused_status = terminal(server, active)
        reused_logs = original_output(server, active)
        assert reused_logs == logs
        assert reused_status["state"] == stopped["state"] and reused_status["exit_code"] == stopped["exit_code"]
        assert sum(json.loads(line).get("phase") == "browser_started"
                   for line in reused_logs["stdout"].splitlines()) == 1
        no_owned_browser(started["profile"], started["browser_pgid"])
        private_write(root / "deadline-reused.json", {"admission": reused, "terminal": reused_status,
                                                      "original_logs_identical": True})
        result["checks"].append("same_key_reuses_original_failed_job_and_identical_logs_without_new_chrome")
        result.update(terminal_state=stopped["state"], exit_code=stopped["exit_code"],
                      outer_job_timed_out=stopped["timed_out"], original_browser=started,
                      original_stderr_sha256=hashlib.sha256(logs["stderr"].encode()).hexdigest(),
                      original_stdout_sha256=hashlib.sha256(logs["stdout"].encode()).hexdigest(),
                      no_owned_browser_or_profile=True, successful_output_published=False)
        active = None
        assert digest(manifest) == manifest_sha and json.loads(manifest.read_text())["timeout_seconds"] == 1
        assert digest(request_path) == result["request_sha256"]
        assert digest(runtime) == args.expected_runtime_sha256
        assert {name: digest(name) for name in resource_pins} == resource_pins
        assert {name: digest(name) for name in helper_sources} == helper_sources
        server.close()
        server = None
        result["qualified"] = True
    except BaseException as error:
        result["failure"] = repr(error)
        raise
    finally:
        if server is not None:
            if active is not None:
                try:
                    state = server.call("process_status", {"host": "local", "job_id": active})
                    if state.get("state") not in ("succeeded", "failed", "cancelled", "timed_out"):
                        server.call("process_cancel", {"host": "local", "job_id": active, "grace_seconds": 10})
                        terminal(server, active)
                except Exception as error:
                    result.setdefault("cleanup_unknown", []).append({"job_id": active, "error": repr(error)})
            try:
                server.close()
            except Exception as error:
                result["qualified"] = False
                result.setdefault("cleanup_unknown", []).append({"controller_close_error": repr(error)})
        private_write(root / "qualification.json", result)
        print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
