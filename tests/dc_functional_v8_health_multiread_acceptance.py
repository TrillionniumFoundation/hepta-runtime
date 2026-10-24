#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Prepared V8 health and multi-read cohorts, serial disposable controllers.

Health uses only fixed read-only SSH probes from pinned administrator config.
Multi-read creates nonce-owned disposable test files, then grants native read
capability only. No installed service, business path, policy, DC or Refresh is
changed. Unknown prepare ACKs retain the same reference without retry.
"""
import argparse
import ast
import contextlib
import datetime
import hashlib
import http.client
import importlib.util
import json
import math
import os
import pathlib
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from dc_parity_release_six_host_acceptance import HOSTS, services

HEALTH_KEYS = {"schema", "host", "platform", "transport", "status", "reachable",
               "authenticated", "ssh_roundtrip_ms", "timeout_ms", "measurement",
               "diagnostics_redacted"}
HEALTH_STATUS = {"healthy", "timeout", "ssh_failed", "transport_error", "invalid_response"}
MEASUREMENT = ("SSH invocation roundtrip including connection setup or reuse, authentication, "
               "remote shell startup and fixed response; not ICMP RTT.")
READ_TOOLS = {"host_health", "host_list", "read_multiple_files"}
MAX_RESPONSE = 2 * 1024 * 1024


def sha(path):
    with pathlib.Path(path).open("rb") as reader:
        return hashlib.file_digest(reader, "sha256").hexdigest()


def import_pinned(name, path, expected):
    if sha(path) != expected:
        raise ValueError("explicit acceptance helper SHA differs")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HealthSchemaError(AssertionError):
    pass


class UnhealthyHostError(AssertionError):
    pass


class HealthMetricError(AssertionError):
    pass


def safe_health_observation(name, value):
    """No arbitrary strings, banners, destinations or error values are saved."""
    is_dict = isinstance(value, dict)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    safe = {"host": name, "response_sha256": hashlib.sha256(raw).hexdigest(),
            "schema_fields_exact": is_dict and set(value) == HEALTH_KEYS}
    if not is_dict:
        return safe
    for key, allowed in (("schema", {"hepta-host-health-v1"}), ("host", {name}),
                         ("platform", {"linux", "macos"}), ("transport", {"ssh"}),
                         ("status", HEALTH_STATUS)):
        safe[key] = value.get(key) if isinstance(value.get(key), str) and value.get(key) in allowed else "unexpected"
    for key in ("reachable", "authenticated", "diagnostics_redacted"):
        safe[key] = value.get(key) if isinstance(value.get(key), bool) else None
    for key in ("ssh_roundtrip_ms", "timeout_ms"):
        v = value.get(key)
        safe[key] = v if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v >= 0 else None
    safe["measurement_verified"] = value.get("measurement") == MEASUREMENT
    return safe


def validate_health(name, value):
    if (not isinstance(value, dict) or set(value) != HEALTH_KEYS
            or value["schema"] != "hepta-host-health-v1" or value["host"] != name
            or value["platform"] != ("macos" if name == "mac" else "linux")
            or value["transport"] != "ssh" or not isinstance(value["status"], str) or value["status"] not in HEALTH_STATUS
            or type(value["reachable"]) is not bool or type(value["authenticated"]) is not bool
            or type(value["timeout_ms"]) is not int or value["timeout_ms"] != 10000 or value["measurement"] != MEASUREMENT
            or value["diagnostics_redacted"] is not True):
        raise HealthSchemaError("native fixed health schema differs")
    healthy = value["status"] == "healthy"
    if value["reachable"] is not healthy or value["authenticated"] is not healthy:
        raise HealthSchemaError("native health status/reachability/authentication invariants differ")
    elapsed = value["ssh_roundtrip_ms"]
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0 or (healthy and elapsed >= 11000):
        raise HealthMetricError("bounded fixed SSH roundtrip metric differs")
    if not healthy:
        raise UnhealthyHostError("native fixed health probe returned a nonhealthy typed status")
    return value


class StrictReadClient:
    """Direct local socket, matched response identity, bounded body, no proxy."""
    def __init__(self, port, token):
        self.port = port
        self._token = token
        self._session = None
        self._counter = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                 "clientInfo": {"name": "hepta-v8-readonly-cohort", "version": "1"}})
        self.rpc("notifications/initialized", {}, notify=True)

    def rpc(self, method, params, notify=False):
        if method not in {"initialize", "notifications/initialized", "tools/list", "tools/call"}:
            raise ValueError("readonly cohort RPC method refused")
        if method == "tools/call" and params.get("name") not in READ_TOOLS:
            raise ValueError("mutating native tool refused")
        self._counter += 1
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            request["id"] = self._counter
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "X-Hepta-Runtime-Token": self._token, "MCP-Protocol-Version": "2025-06-18"}
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=35)
        try:
            connection.request("POST", "/mcp", body=json.dumps(request).encode(), headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            if not 200 <= response.status < 300 or len(raw) > MAX_RESPONSE:
                raise ValueError("bounded disposable-controller HTTP response unavailable")
            sid = response.getheader("Mcp-Session-Id")
            if sid:
                if not 0 < len(sid) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in sid):
                    raise ValueError("native session identity malformed")
                if self._session and sid != self._session:
                    raise ValueError("native session identity changed")
                self._session = sid
            if notify:
                return None
            text = raw.decode("utf-8")
            rows = [json.loads(line[5:].strip()) for line in text.splitlines()
                    if line.startswith("data:") and line[5:].strip()]
            if not rows:
                rows = [json.loads(text)]
            matches = [row for row in rows if row.get("jsonrpc") == "2.0" and type(row.get("id")) is type(request["id"]) and row.get("id") == request["id"]]
            if len(matches) != 1 or "error" in matches[0] or "result" not in matches[0]:
                raise ValueError("native response identity malformed or refused")
            return matches[0]["result"]
        finally:
            connection.close()

    def call(self, name, args, denied=False):
        result = self.rpc("tools/call", {"name": name, "arguments": args})
        text = "\n".join(item.get("text", "") for item in result.get("content", []) if item.get("type") == "text")
        if denied:
            if result.get("isError") is not True:
                raise AssertionError("negative readonly case was accepted")
            return text
        if result.get("isError"):
            raise ValueError("native readonly tool returned an error")
        return json.loads(text)

    def close(self):
        self._token = None
        self._session = None


def private_parent():
    parent = pathlib.Path.home() / ".local/state/hepta-runtime-acceptance"
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private cohort recovery parent refused")
    return parent


def private_json(path, value):
    temp = path.with_name(path.name + ".next")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as writer:
        json.dump(value, writer, ensure_ascii=False, sort_keys=True, indent=2)
        writer.write("\n"); writer.flush(); os.fsync(writer.fileno())
    if path.exists():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError("owned receipt identity changed")
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def failure_detail(error, phase, fixture_helper, token="", private=""):
    result = {"phase": phase, "error_type": type(error).__name__,
              "frames": [{"file": f.filename, "line": f.lineno, "function": f.name}
                         for f in traceback.extract_tb(error.__traceback__)]}
    if isinstance(error, fixture_helper.TargetOperationError):
        result["transport"] = error.diagnostic(token, private)
    return result


@contextlib.contextmanager
def controller(binary, hosts, base, label, contract, fixture_helper, report, destination, save):
    folder = base / label
    folder.mkdir(mode=0o700)
    workspace = folder / "workspace"; workspace.mkdir(mode=0o700)
    token_value = secrets.token_hex(32)
    token_path = folder / "token"
    fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as writer:
        writer.write(token_value); writer.flush(); os.fsync(writer.fileno())
    config_path = folder / "runtime.json"
    private_json(config_path, {"state_dir": str(folder / "state"),
                 "controller_workspace_roots": [str(workspace)], "hosts": hosts})
    with socket.socket() as channel:
        channel.bind(("127.0.0.1", 0)); port = channel.getsockname()[1]
    process = None
    client = None
    raw_log = folder / "controller.raw.log"
    info = {"label": label, "private_directory": str(folder), "auth_token_value_saved": False,
            "stopped": False, "candidate_binary_sha256": sha(binary)}
    report["controllers"].append(info); save()
    try:
        with raw_log.open("xb") as log:
            process = subprocess.Popen([str(binary), "mcp", "--path", str(workspace),
                "--bind", "127.0.0.1:" + str(port), "--runtime-config", str(config_path),
                "--auth-token-file", str(token_path)], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        info["pid"] = process.pid; save()
        for _ in range(80):
            if process.poll() is not None:
                raise RuntimeError("owned readonly controller exited")
            try:
                client = StrictReadClient(port, token_value)
                break
            except (OSError, RuntimeError, ValueError):
                time.sleep(.1)
        else:
            raise TimeoutError("owned readonly controller did not become ready")
        contract.verify(client.rpc("tools/list", {})["tools"])
        info["exact_approved_native_catalog_verified"] = True; save()
        yield client
    finally:
        if client is not None:
            client.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=10)
        info["stopped"] = process is None or process.poll() is not None
        if raw_log.exists():
            sanitized = destination / (label + "-controller.log")
            fd = os.open(sanitized, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as writer:
                writer.write(fixture_helper.redacted(raw_log.read_bytes(), token_value, base))
                writer.flush(); os.fsync(writer.fileno())
            info["redacted_log"] = {"path": str(sanitized), "sha256": sha(sanitized)}
            raw_log.unlink()
        save()


def populate_multiread(ssh, item, fixture_helper, multi_path):
    """Reuse frozen fixture DATA only; replace its unsafe remote mkdtemp."""
    tree = ast.parse(multi_path.read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "create_fixture")
    call = next(n for n in ast.walk(function) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id == "target_python")
    old_source = ast.literal_eval(call.args[1])
    lines = []
    for line in old_source.splitlines():
        if line.startswith("base=pathlib.Path"):
            continue
        if line.startswith("root=base/'workspace';root.mkdir"):
            line = "root=base/'workspace'"
        lines.append(line)
    source = fixture_helper.fixture_guard(item) + "\n" + "\n".join(lines) + "\n"
    ast.parse(source)
    result = fixture_helper.target_python(ssh, source)
    if (not isinstance(result, dict) or set(result) != {"base", "root", "text", "sha256"}
            or result["base"] != item["base"] or result["root"] != item["root"]
            or result["sha256"] != hashlib.sha256(result["text"].encode()).hexdigest()):
        raise ValueError("same-nonce bounded fixture data acknowledgement differs")
    return {**item, "text": result["text"], "sha256": result["sha256"]}


def parser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, type=pathlib.Path)
    ap.add_argument("--binaryexpectedSHA", "--expected-candidate-sha256", dest="expected_binary_sha", required=True)
    ap.add_argument("--contract", required=True, type=pathlib.Path)
    ap.add_argument("--expected-contract-sha256", required=True)
    ap.add_argument("--HEAD", "--expected-head", dest="expected_head", required=True)
    ap.add_argument("--FP", "--expected-source-fingerprint", dest="expected_fp", required=True)
    ap.add_argument("--expected-fixture-helper-sha256", required=True)
    ap.add_argument("--expected-loader-sha256", required=True)
    ap.add_argument("--expected-tool-helper-sha256", required=True)
    ap.add_argument("--expected-multiread-helper-sha256", required=True)
    ap.add_argument("--runtime-config", required=True, type=pathlib.Path)
    ap.add_argument("--expected-runtime-config-sha256", required=True)
    ap.add_argument("--receipt-dir", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--mode", choices=("health", "multi-read", "both"), default="both")
    ap.add_argument("--hosts", nargs="+", choices=[name for name, _ in HOSTS], default=[name for name, _ in HOSTS])
    ap.add_argument("--max-workers", type=int, choices=[1], default=1)
    return ap


def main():
    args = parser().parse_args()
    if len(args.hosts) != len(set(args.hosts)):
        raise ValueError("duplicate fixed host selection")
    binary = args.binary.resolve(strict=True)
    if sha(binary) != args.expected_binary_sha or not os.access(binary, os.X_OK):
        raise ValueError("candidate native differs from explicit release SHA")
    fixture_path = ROOT / "tests/dc_functional_v8_signal_audit_acceptance.py"
    fixture_helper = import_pinned("hepta_v8_pinned_fixture", fixture_path, args.expected_fixture_helper_sha256)
    multi_path = ROOT / "tests/multi_read_six_host_acceptance.py"
    multi = import_pinned("hepta_v8_pinned_multiread_cases", multi_path, args.expected_multiread_helper_sha256)
    contract = fixture_helper.load_reviewed_v8(args.contract, args.expected_contract_sha256,
                     args.expected_loader_sha256, args.expected_tool_helper_sha256)
    source_before = fixture_helper.source_identity()
    if source_before["base_HEAD"] != args.expected_head or source_before["source_code_fingerprint"] != args.expected_fp:
        raise ValueError("current compile inputs differ from explicit source/build pins")
    raw_config = args.runtime_config.read_bytes()
    if len(raw_config) > 1024 * 1024 or hashlib.sha256(raw_config).hexdigest() != args.expected_runtime_config_sha256:
        raise ValueError("pinned administrator runtime config differs")
    source_config = json.loads(raw_config)
    selected = [(name, ssh) for name, ssh in HOSTS if name in args.hosts]
    for name, ssh in selected:
        host = source_config["hosts"][name]
        if host["ssh_target"] != ssh or host.get("platform", "linux") != ("macos" if name == "mac" else "linux"):
            raise ValueError("administrator six-host logical authority differs")
    baseline = services()
    if any(value.get("ActiveState") != "active" or value.get("MainPID") == "0" for value in baseline.values()):
        raise ValueError("protected Runtime/facade/DC must remain active")
    helpers_before = fixture_helper.sealed_harness_inputs()
    for path in (pathlib.Path(__file__).resolve(), multi_path, ROOT / "tests/host_health_acceptance.py"):
        helpers_before[path.relative_to(ROOT).as_posix()] = {"bytes": path.stat().st_size, "sha256": sha(path)}
    destination = args.receipt_dir.absolute()
    if destination.exists() or destination.is_symlink() or args.out.exists() or args.out.is_symlink():
        raise ValueError("fresh absent receipt destinations required")
    destination.mkdir(mode=0o700)
    base = pathlib.Path(tempfile.mkdtemp(prefix="hepta-v8-readonly-cohort-", dir=private_parent()))
    base.chmod(0o700)
    report = {"schema": "hepta-v8-pinned-health-multiread-native-cohort-v1",
              "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "origin": "local_native_disposable_controller_real_configured_targets",
              "source_before": source_before, "source_HEAD_is_compiled_code_claim": False,
              "expected_build_source_fingerprint": args.expected_fp, "binary_sha256": args.expected_binary_sha,
              "contract_sha256": args.expected_contract_sha256, "contract_catalog_sha256": contract.catalog_sha256,
              "runtime_config_sha256": args.expected_runtime_config_sha256,
              "helpers_before": helpers_before, "selected_hosts": [name for name, _ in selected],
              "selected_modes": ["health", "multi-read"] if args.mode == "both" else [args.mode],
              "max_workers": 1, "protected_services_before": baseline,
              "installed_service_changed": False, "dc_changed": False, "model_origin": False,
              "full_dc_replacement_qualified": False, "complete": False, "complete_both_readonly_cohorts": False,
              "health_results": [], "multi_read_results": [], "failures": [], "controllers": [],
              "cleanup": [], "private_recovery_directory": str(base)}
    fixtures = {}
    def save():
        private_json(args.out.absolute(), report)
    save()
    try:
        if args.mode in ("health", "both"):
            health_hosts = {name: {"ssh_target": ssh, "platform": "macos" if name == "mac" else "linux",
                "remote_state_dir": source_config["hosts"][name]["remote_state_dir"],
                "allow_execute": False, "allow_pty": False, "allow_write": False} for name, ssh in selected}
            with controller(binary, health_hosts, base, "health", contract, fixture_helper, report, destination, save) as client:
                caps = client.call("host_list", {})["hosts"]
                assert all(not row["allow_execute"] and not row["allow_pty"] and not row["allow_write"] for row in caps)
                report["health_capabilities_disabled"] = True; save()
                schema = contract.by_name["host_health"]
                assert schema["annotations"]["readOnlyHint"] is True
                assert set(schema["inputSchema"]["properties"]) == {"host"}
                assert schema["inputSchema"]["additionalProperties"] is False
                error = client.call("host_health", {"host": "unknown-private-destination"}, denied=True)
                assert "unknown-private-destination" not in error
                client.call("host_health", {"host": "127.0.0.1"}, denied=True)
                for key, value in (("address", "127.0.0.1"), ("command", "id"), ("timeout_seconds", 3600)):
                    client.call("host_health", {"host": selected[0][0], key: value}, denied=True)
                report["health_schema_and_caller_overrides_rejected"] = True; save()
                for name, _ in selected:
                    row = {"host": name, "complete": False, "automatic_retry": False}
                    report["health_results"].append(row); save()
                    try:
                        value = client.call("host_health", {"host": name})
                        # Save BEFORE any schema/status assertion. A nonhealthy
                        # native response and a harness schema bug are distinguishable.
                        row["observation"] = safe_health_observation(name, value); save()
                        validate_health(name, value)
                        row["complete"] = True
                    except Exception as error:
                        row["failure"] = failure_detail(error, "health:" + name, fixture_helper)
                        report["failures"].append(row["failure"])
                    save()
                    print("HEALTH", name, "complete", row["complete"], flush=True)
                if all(row["complete"] for row in report["health_results"]):
                    # Same bounded readonly capability on a genuine new authenticated client.
                    reconnect = StrictReadClient(client.port, client._token)
                    try:
                        value = reconnect.call("host_health", {"host": selected[0][0]})
                        report["health_reconnect_observation"] = safe_health_observation(selected[0][0], value); save()
                        validate_health(selected[0][0], value)
                        report["health_reconnect_complete"] = True
                    finally:
                        reconnect.close()
                else:
                    report["health_reconnect_skipped"] = "A first probe failed; no health request replay/retry"
                    save()
        if args.mode in ("multi-read", "both"):
            # Persist ALL same-nonce references before any target call.
            for name, ssh in selected:
                fixtures[name] = fixture_helper.planned_fixture(name, ssh, secrets.token_hex(16))
                fixture_helper.save_fixture_record(base / ("fixture-plan-" + name + ".json"), fixtures[name])
            report["planned_fixture_references"] = [dict(fixtures[name]) for name, _ in selected]; save()
            for name, ssh in selected:
                fixture_helper.prepare_fixture(ssh, fixtures[name], base / ("fixture-plan-" + name + ".json"))
                fixtures[name] = populate_multiread(ssh, fixtures[name], fixture_helper, multi_path)
            hosts = {name: {"ssh_target": ssh, "platform": "macos" if name == "mac" else "linux",
                     "execution_mode": "operator", "remote_state_dir": fixtures[name]["base"] + "/state",
                     "allow_execute": False, "allow_pty": False, "allow_write": False,
                     "allowed_read_path_prefixes": [fixtures[name]["root"]], "allowed_write_path_prefixes": []}
                     for name, ssh in selected}
            first = selected[0][0]
            hosts["isolated-fixture"] = {**hosts[first], "execution_mode": "isolated"}
            with controller(binary, hosts, base, "multi-read", contract, fixture_helper, report, destination, save) as client:
                annotations = contract.by_name["read_multiple_files"]["annotations"]
                assert annotations["readOnlyHint"] is True and annotations["destructiveHint"] is False
                for name, _ in selected:
                    result = multi.qualify_host(client, name, fixtures[name])
                    report["multi_read_results"].append(result); save()
                    print("MULTI_READ", name, "complete", result["complete"], "checks", result["passed"], flush=True)
                client.call("read_multiple_files", {"host": "isolated-fixture",
                    "paths": [fixtures[first]["root"] + "/a.txt"]}, denied=True)
                client.call("read_multiple_files", {"host": "unregistered",
                    "paths": [fixtures[first]["root"] + "/a.txt"]}, denied=True)
                report["isolated_and_unknown_hosts_denied"] = True; save()
    except Exception as error:
        report["failures"].append(failure_detail(error, "cohort", fixture_helper))
        save()
    finally:
        for name, ssh in selected:
            item = fixtures.get(name)
            if item is None:
                continue
            row = {"host": name, "removed": False}
            try:
                if not item["prepare_attempted"]:
                    row.update(removed=True, remote_create_never_attempted=True)
                elif not item["prepare_confirmed"]:
                    row["reconcile_readonly"] = item.get("reconcile_readonly")
                    row["removed"] = isinstance(row["reconcile_readonly"], dict) and row["reconcile_readonly"].get("present") is False
                    row["same_reference_retained"] = item["base"]
                else:
                    fixture_helper.owned_query(ssh, item, "remove")
                    row["removed"] = True
            except Exception as error:
                row["failure"] = failure_detail(error, "cleanup:" + name, fixture_helper)
                row["same_reference_retained"] = item["base"]
            report["cleanup"].append(row)
        report["fixture_recovery"] = [dict(fixtures[name]) for name, _ in selected if name in fixtures]
        try:
            report["protected_services_after"] = services()
            report["protected_services_stable"] = report["protected_services_after"] == baseline
            report["source_after"] = fixture_helper.source_identity()
            helpers_after = fixture_helper.sealed_harness_inputs()
            for path in (pathlib.Path(__file__).resolve(), multi_path, ROOT / "tests/host_health_acceptance.py"):
                helpers_after[path.relative_to(ROOT).as_posix()] = {"bytes": path.stat().st_size, "sha256": sha(path)}
            report["helpers_after"] = helpers_after
            report["sealed_inputs_stable"] = (helpers_before == helpers_after and report["source_after"] == source_before
                and sha(binary) == args.expected_binary_sha and sha(args.contract) == args.expected_contract_sha256
                and sha(args.runtime_config) == args.expected_runtime_config_sha256)
        except Exception as error:
            report["failures"].append(failure_detail(error, "final_seals", fixture_helper))
            report["sealed_inputs_stable"] = False
        health_complete = (len(report["health_results"]) == len(selected)
            and all(row["complete"] for row in report["health_results"]) and report.get("health_reconnect_complete") is True
            and report.get("health_schema_and_caller_overrides_rejected") is True)
        multi_complete = (len(report["multi_read_results"]) == len(selected)
            and all(row["complete"] for row in report["multi_read_results"])
            and report.get("isolated_and_unknown_hosts_denied") is True
            and len(report["cleanup"]) == len(selected) and all(row["removed"] for row in report["cleanup"]))
        report["health_selected_complete"] = health_complete
        report["multi_read_selected_complete"] = multi_complete
        report["complete"] = (not report["failures"] and report.get("sealed_inputs_stable") is True
            and report.get("protected_services_stable") is True and all(row["stopped"] for row in report["controllers"])
            and (args.mode == "multi-read" or health_complete) and (args.mode == "health" or multi_complete))
        report["complete_both_readonly_cohorts"] = report["complete"] and args.mode == "both" and len(selected) == len(HOSTS)
        if report["complete"]:
            shutil.rmtree(base)
            report["private_authentication_removed"] = True
        else:
            private_json(base / "recovery.json", {"schema": "hepta-v8-readonly-owned-recovery-v1",
                "targets": report.get("fixture_recovery", []), "controllers": report["controllers"],
                "credentials_in_metadata": False, "automatic_retry": False, "do_not_commit": True})
            report["private_authentication_removed"] = False
        save()
    print("READONLY_COHORT_COMPLETE", report["complete"], "BOTH_SIX", report["complete_both_readonly_cohorts"], flush=True)
    if not report["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
