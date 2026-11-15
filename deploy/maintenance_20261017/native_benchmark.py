#!/usr/bin/env python3
"""Low-load direct MCP acceptance probe; Python standard library only.

Creates at most one timestamp/sleep probe for each of six fixed hosts. Requests
are durably recorded before submission. There are no automatic write retries,
session reconnects, redirects, proxy use, or generated replacement keys. The
second start batch repeats exactly the tool name/arguments of the first batch;
JSON-RPC IDs remain unique within the session.

Use distinct, operator-chosen prefixes and receipt paths for a fresh old/new
comparison. A reused initial key is reported and is ineligible as a fresh-start
measurement. An existing receipt is never overwritten or automatically resumed.
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse


PROTOCOL = "2025-11-25"
HOSTS = ("main", "rog", "ai395", "pocket4", "x230", "mac")
CALL_TIMEOUT = 30.0
POLL_SECONDS = 60.0
POLL_INTERVAL = 1.0
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
TERMINAL = frozenset(("succeeded", "failed", "timed_out", "cancelled"))
PROBE_CODE = (
    "import json,time; "
    "start_unix_ns=time.time_ns(); start_monotonic_ns=time.monotonic_ns(); "
    "time.sleep(0.05); "
    "end_monotonic_ns=time.monotonic_ns(); end_unix_ns=time.time_ns(); "
    "print(json.dumps({'probe':'hepta-native-six-host-v1',"
    "'start_unix_ns':start_unix_ns,'end_unix_ns':end_unix_ns,"
    "'start_monotonic_ns':start_monotonic_ns,"
    "'end_monotonic_ns':end_monotonic_ns,"
    "'elapsed_ns':end_monotonic_ns-start_monotonic_ns},"
    "sort_keys=True,separators=(',',':')),flush=True)"
)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def catalog_summary(tools):
    ordered = sorted(tools, key=lambda tool: tool["name"])
    return {"count": len(ordered), "canonicalcatalogSHA": hashlib.sha256(
        canonical(ordered)).hexdigest(), "tool_names": [t["name"] for t in ordered],
        "canonicalization": "tools sorted by name; JSON sort_keys=true, compact "
        "separators, ensure_ascii=false, UTF-8; SHA-256 of that complete array"}


class ProbeError(Exception):
    pass


class Receipt:
    def __init__(self, path, initial, token):
        self.path = Path(path).absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.secrets = [token]
        self.data = initial
        # Reserve without following or replacing an existing receipt/symlink.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(str(self.path), flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps(self.clean(initial), indent=2,
                                    ensure_ascii=False).encode("utf-8") + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        self._sync_parent()

    def clean(self, value):
        if isinstance(value, str):
            for secret in self.secrets:
                if secret:
                    value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, list):
            return [self.clean(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                compact = str(key).lower().replace("-", "").replace("_", "")
                if compact in ("token", "xheptaruntimetoken", "mcpsessionid",
                               "sessionid", "authorization", "byteshex", "stderr"):
                    continue
                result[self.clean(str(key))] = self.clean(item)
            return result
        return value

    def add_secret(self, value):
        with self.lock:
            if value and value not in self.secrets:
                self.secrets.append(value)

    def _sync_parent(self):
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        fd = os.open(str(self.path.parent), flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _save(self):
        fd, temporary = tempfile.mkstemp(prefix=self.path.name + ".",
                                         suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(json.dumps(self.clean(self.data), indent=2,
                                        ensure_ascii=False, allow_nan=False)
                             .encode("utf-8") + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, str(self.path))
            self._sync_parent()
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def update(self, **values):
        with self.lock:
            self.data.update(values)
            self._save()

    def add_calls(self, calls):
        with self.lock:
            self.data["calls"].extend(calls)
            self._save()

    def finish_call(self, call_id, values):
        with self.lock:
            for call in self.data["calls"]:
                if call["call_id"] == call_id:
                    call.update(values)
                    self._save()
                    return
            raise ProbeError("missing prepared call in receipt")

    def batch(self, summary):
        with self.lock:
            self.data["batches"].append(summary)
            self._save()


def parse_endpoint(value):
    endpoint = urllib.parse.urlsplit(value)
    if (endpoint.scheme not in ("http", "https") or
            endpoint.hostname not in ("127.0.0.1", "::1", "localhost") or
            endpoint.username is not None or endpoint.password is not None or
            endpoint.query or endpoint.fragment or endpoint.path != "/mcp"):
        raise ProbeError("endpoint must be a loopback http(s) URL ending /mcp, "
                         "without credentials, query, or fragment")
    _ = endpoint.port  # Validate its syntax before any network request.
    return endpoint


def decode_tool(result):
    if not isinstance(result, dict):
        raise ProbeError("tools/call result must be an object")
    structured = result.get("structuredContent")
    text_blocks = [item.get("text", "") for item in result.get("content", [])
                   if isinstance(item, dict) and item.get("type") == "text"]
    if isinstance(structured, dict):
        payload = structured
    else:
        text = "\n".join(text_blocks)
        try:
            payload = json.loads(text)
        except (ValueError, TypeError):
            if result.get("isError") is True:
                payload = {"error_text": text[:8192]}
            else:
                raise ProbeError("tool response is not a JSON object")
    if not isinstance(payload, dict):
        raise ProbeError("tool response payload must be an object")
    return payload, result.get("isError") is True


class Client:
    def __init__(self, endpoint, token, receipt):
        self.endpoint = endpoint
        self.token = token
        self.receipt = receipt
        self.sid = None
        self.sequence = 0
        self.started = time.monotonic()

    def prepare(self, method, params, phase, host=None, notification=False):
        self.sequence += 1
        call_id = "native-bench-%04d" % self.sequence
        request = {"jsonrpc": "2.0", "method": method}
        if not notification:
            request["id"] = call_id
        if params is not None:
            request["params"] = params
        wire = canonical(request)
        return {"call_id": call_id, "phase": phase, "host": host,
                "prepared_at_utc": utc_now(),
                "state": "intent_persisted_before_network",
                "request": request, "request_sha256": hashlib.sha256(wire).hexdigest()}

    def _transport(self, prepared, timeout):
        request = prepared["request"]
        deadline = time.monotonic() + timeout
        endpoint = self.endpoint
        connection_type = (http.client.HTTPSConnection if endpoint.scheme == "https"
                           else http.client.HTTPConnection)
        kwargs = {"timeout": timeout}
        if endpoint.scheme == "https":
            kwargs["context"] = ssl.create_default_context()
        connection = connection_type(endpoint.hostname, endpoint.port, **kwargs)
        active_socket = None
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream",
                   "X-Hepta-Runtime-Token": self.token,
                   "MCP-Protocol-Version": PROTOCOL}
        if self.sid:
            headers["Mcp-Session-Id"] = self.sid
        metadata = {"sid_present": bool(self.sid)}

        def remaining():
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("MCP request deadline exceeded")
            if active_socket is not None:
                active_socket.settimeout(left)
            return left

        try:
            remaining()
            connection.connect()
            active_socket = connection.sock
            remaining()
            connection.request("POST", endpoint.path, body=canonical(request), headers=headers)
            remaining()
            response = connection.getresponse()
            sid = response.getheader("Mcp-Session-Id")
            if sid:
                self.receipt.add_secret(sid)
                if request["method"] == "initialize" and self.sid is None:
                    self.sid = sid
                elif sid != self.sid:
                    raise ProbeError("server changed MCP session ID; refusing reconnect")
            metadata.update(http_status=response.status,
                            content_type=response.getheader("Content-Type", "")
                            .split(";", 1)[0].strip().lower(),
                            sid_present=bool(self.sid))
            if "id" not in request and response.status in (200, 202, 204):
                metadata["response_bytes"] = 0
                return None, metadata
            if response.status != 200:
                raise ProbeError("MCP HTTP status %d (redirects/retries disabled)" %
                                 response.status)
            is_sse = metadata["content_type"] == "text/event-stream"
            raw = bytearray()
            pending = b""
            event_lines = []

            def event_result():
                if not event_lines:
                    return None
                data = b"\n".join(event_lines).decode("utf-8")
                event_lines[:] = []
                # Native SSE may prime the stream with an empty data event plus
                # id/retry fields. Heartbeats carry no JSON-RPC message.
                if not data.strip() or data == "[DONE]":
                    return None
                value = json.loads(data)
                if isinstance(value, dict) and value.get("id") == request.get("id"):
                    return value
                return None

            while True:
                remaining()
                # read1 permits an absolute deadline check between network reads
                # and does not wait for EOF on a long-lived SSE response stream.
                chunk = response.read1(65536)
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ProbeError("MCP response exceeded bounded reader size")
                if is_sse:
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        line = line.rstrip(b"\r")
                        if not line:
                            value = event_result()
                            if value is not None:
                                metadata["response_bytes"] = len(raw)
                                return value, metadata
                        elif line.startswith(b"data:"):
                            event_lines.append(line[5:].lstrip(b" "))
                if response.isclosed():
                    break
            metadata["response_bytes"] = len(raw)
            if is_sse:
                if pending.startswith(b"data:"):
                    event_lines.append(pending[5:].lstrip(b" ").rstrip(b"\r"))
                value = event_result()
                if value is None:
                    raise ProbeError("SSE ended without this request's JSON-RPC response")
            else:
                value = json.loads(raw.decode("utf-8"))
            return value, metadata
        finally:
            connection.close()

    def execute(self, prepared, timeout=CALL_TIMEOUT, barrier=None, deadline=None):
        if barrier is not None:
            barrier.wait(timeout=10)
        started = time.monotonic()
        fields = {"network_attempt_started_at_utc": utc_now(),
                  "start_offset_seconds": started - self.started}
        payload = None
        ok = False
        try:
            if deadline is not None:
                timeout = min(timeout, deadline - started)
                if timeout <= 0:
                    raise TimeoutError("batch deadline passed; request not submitted")
            response, metadata = self._transport(prepared, timeout)
            fields.update(metadata)
            request = prepared["request"]
            if "id" not in request:
                fields["response"] = {"notification_accepted": True}
                ok = True
            else:
                if (not isinstance(response, dict) or response.get("jsonrpc") != "2.0"
                        or response.get("id") != request["id"]):
                    raise ProbeError("mismatched or malformed JSON-RPC response")
                if "error" in response:
                    fields["response"] = {"rpc_error": response["error"]}
                elif "result" not in response:
                    raise ProbeError("JSON-RPC response lacks result/error")
                elif request["method"] == "tools/call":
                    payload, is_error = decode_tool(response["result"])
                    # Never retain text-encoded duplicate content, stderr, or hex.
                    if request["params"]["name"] == "process_read":
                        projected = {key: payload[key] for key in ("job_id", "host")
                                     if key in payload}
                        stdout = payload.get("stdout")
                        if isinstance(stdout, dict):
                            projected["stdout"] = {key: stdout[key] for key in
                                ("text", "offset", "next_offset", "size", "eof")
                                if key in stdout}
                        if is_error:
                            projected["error_text"] = payload.get("error_text", "tool error")
                    else:
                        projected = payload
                    fields["response"] = {"mcp_is_error": is_error, "payload": projected}
                    ok = not is_error
                else:
                    payload = response["result"]
                    if request["method"] == "tools/list" and isinstance(payload, dict):
                        fields["response"] = catalog_summary(payload.get("tools", []))
                        fields["response"]["has_next_cursor"] = bool(payload.get("nextCursor"))
                    else:
                        fields["response"] = payload
                    ok = True
            fields["state"] = "response_received" if ok else "error_response_received"
        except Exception as exc:
            fields["state"] = "exception_uncertain" if prepared["phase"] in (
                "initial_start", "exact_reuse") else "observation_exception"
            fields["exception"] = {"type": type(exc).__name__, "message": str(exc)[:8192]}
        ended = time.monotonic()
        fields.update(completed_at_utc=utc_now(), elapsed_seconds=ended - started,
                      end_offset_seconds=ended - self.started, ok=ok,
                      sid_present=bool(self.sid))
        # Any receipt persistence failure propagates and prevents subsequent batches.
        self.receipt.finish_call(prepared["call_id"], fields)
        return {"ok": ok, "payload": payload, "call_id": prepared["call_id"],
                "host": prepared["host"], "elapsed_seconds": ended - started,
                "started": started, "ended": ended}

    def single(self, method, params, phase, notification=False):
        prepared = self.prepare(method, params, phase, notification=notification)
        self.receipt.add_calls([prepared])
        return self.execute(prepared)

    def batch(self, phase, specifications, timeout=CALL_TIMEOUT, deadline=None):
        prepared = [self.prepare("tools/call", {"name": tool, "arguments": arguments},
                                 phase, host) for host, tool, arguments in specifications]
        if not prepared:
            return []
        # All exact requests and keys reach durable storage before any thread sends.
        self.receipt.add_calls(prepared)
        barrier = threading.Barrier(len(prepared) + 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(prepared)) as pool:
            futures = [pool.submit(self.execute, item, timeout, barrier, deadline)
                       for item in prepared]
            released = time.monotonic()
            barrier.wait(timeout=10)
            results = [future.result() for future in futures]
        finished = time.monotonic()
        network_elapsed = max(item["ended"] for item in results) - released
        ordered = sorted(item["elapsed_seconds"] for item in results)
        summary = {"phase": phase, "calls": len(results),
                   "successful_responses": sum(item["ok"] for item in results),
                   "batch_elapsed_seconds": network_elapsed,
                   "batch_elapsed_including_result_receipt_io_seconds": finished - released,
                   "submission_spread_seconds": max(item["started"] for item in results) -
                                                min(item["started"] for item in results),
                   "latency_p50_seconds": ordered[math.ceil(len(ordered) * .50) - 1],
                   "latency_p95_seconds": ordered[math.ceil(len(ordered) * .95) - 1],
                   "quantile_method": "nearest-rank; six calls is a small sample",
                   "call_ids": [item["call_id"] for item in results]}
        if phase in ("initial_start", "exact_reuse"):
            summary["observed_calls_per_second"] = len(results) / network_elapsed
        self.receipt.batch(summary)
        return results


def bound_job(payload, host, arguments):
    if not isinstance(payload, dict):
        return None
    job = payload.get("job")
    if not isinstance(job, dict) or not isinstance(job.get("id"), str) or not job["id"]:
        return None
    expected = ("host", "idempotency_key", "executable", "args")
    if any(job.get(key) != arguments.get(key) for key in expected) or job["host"] != host:
        return None
    return job


def run(client, receipt, arguments):
    initialized = client.single("initialize", {
        "protocolVersion": PROTOCOL, "capabilities": {},
        "clientInfo": {"name": "hepta-native-six-host-acceptance", "version": "1.0"}},
        "initialize")
    if (not initialized["ok"] or not isinstance(initialized["payload"], dict)
            or initialized["payload"].get("protocolVersion") != PROTOCOL or not client.sid):
        raise ProbeError("initialize did not confirm requested protocol and MCP session")
    receipt.update(sid_present=True)
    ready = client.single("notifications/initialized", None, "initialized", notification=True)
    if not ready["ok"]:
        raise ProbeError("initialized notification failed; no probes submitted")

    tools = []
    cursor = None
    seen_cursors = set()
    for _ in range(100):
        page = client.single("tools/list", {} if cursor is None else {"cursor": cursor},
                             "tools_list")
        payload = page["payload"]
        if (not page["ok"] or not isinstance(payload, dict) or
                not isinstance(payload.get("tools"), list)):
            raise ProbeError("tools/list failed; no probes submitted")
        tools.extend(payload["tools"])
        cursor = payload.get("nextCursor")
        if not cursor:
            break
        if not isinstance(cursor, str) or cursor in seen_cursors:
            raise ProbeError("invalid/repeated tools/list cursor")
        seen_cursors.add(cursor)
    else:
        raise ProbeError("tools/list exceeded bounded pagination")
    catalog = catalog_summary(tools)
    if len(set(catalog["tool_names"])) != catalog["count"]:
        raise ProbeError("duplicate canonical tool names")
    receipt.update(catalog=catalog)
    if not {"process_start", "process_status", "process_read"}.issubset(catalog["tool_names"]):
        raise ProbeError("native process tools absent; no probes submitted")

    initial = client.batch("initial_start", [(host, "process_start", arguments[host])
                                             for host in HOSTS])
    jobs = {}
    confirmed = {}
    original_payloads = {}
    for result in initial:
        host = result["host"]
        payload = result["payload"]
        job = bound_job(payload, host, arguments[host]) if result["ok"] else None
        if job:
            jobs[host] = job["id"]
            original_payloads[host] = payload
        confirmed[host] = bool(job and job.get("launch_state") == "launched" and
                               isinstance(payload.get("reused"), bool) and
                               payload.get("retried_launch") is not True)
    initial_fresh = all(confirmed.values()) and all(
        original_payloads[host]["reused"] is False for host in HOSTS)
    receipt.update(owned_jobs=jobs, original_confirmed=confirmed,
                   initial_all_fresh=initial_fresh,
                   initial_uncertain_hosts=[host for host in HOSTS if not confirmed[host]])

    reuse_checks = {host: False for host in HOSTS}
    if all(confirmed.values()) and len(set(jobs.values())) == len(HOSTS):
        repeated = client.batch("exact_reuse", [(host, "process_start", arguments[host])
                                                 for host in HOSTS])
        for result in repeated:
            host = result["host"]
            payload = result["payload"]
            job = bound_job(payload, host, arguments[host]) if result["ok"] else None
            reuse_checks[host] = bool(job and job["id"] == jobs[host] and
                job.get("launch_state") == "launched" and payload.get("reused") is True and
                payload.get("retried_launch") is not True)
        receipt.update(reuse_assertions=reuse_checks,
                       exact_reuse_definition="identical tools/call name and arguments; "
                       "only the unique JSON-RPC request ID differs")
    else:
        receipt.update(reuse_assertions=reuse_checks,
                       reuse_batch_skipped="initial results uncertain/unbound or IDs not unique; "
                       "no automatic write retry or replacement key")

    pending = dict(jobs)
    terminal = {}
    last_states = {}
    poll_started = time.monotonic()
    deadline = poll_started + POLL_SECONDS
    while pending and time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        results = client.batch("terminal_poll", [(host, "process_status", {
            "host": host, "job_id": job_id}) for host, job_id in pending.items()],
            timeout=max(.001, min(CALL_TIMEOUT, remaining)), deadline=deadline)
        for result in results:
            payload = result["payload"]
            host = result["host"]
            if not result["ok"] or not isinstance(payload, dict):
                continue
            if payload.get("job_id", jobs[host]) != jobs[host]:
                last_states[host] = "mismatched_job_id"
                continue
            state = payload.get("state")
            last_states[host] = state
            if (state in TERMINAL and payload.get("status_authoritative") is not False
                    and result["ended"] <= deadline):
                terminal[host] = payload
                pending.pop(host, None)
        receipt.update(terminal_statuses=terminal, last_observed_states=last_states,
                       pending_terminal_hosts=list(pending))
        if pending:
            time.sleep(max(0, min(POLL_INTERVAL, deadline - time.monotonic())))
    receipt.update(poll_elapsed_seconds=time.monotonic() - poll_started,
                   poll_deadline_seconds=POLL_SECONDS, pending_terminal_hosts=list(pending))

    # One bounded read per owned job; these probes print one short JSON line.
    reads = client.batch("stdout_read", [(host, "process_read", {
        "host": host, "job_id": job_id, "stdout_offset": 0, "stderr_offset": 0,
        "limit": 4096}) for host, job_id in jobs.items()])
    stdout_checks = {host: False for host in HOSTS}
    for result in reads:
        host = result["host"]
        payload = result["payload"]
        if not result["ok"] or not isinstance(payload, dict) or payload.get("job_id") != jobs[host]:
            continue
        stdout = payload.get("stdout")
        if not isinstance(stdout, dict) or not isinstance(stdout.get("text"), str):
            continue
        try:
            value = json.loads(stdout["text"])
            numeric = ("start_unix_ns", "end_unix_ns", "start_monotonic_ns",
                       "end_monotonic_ns", "elapsed_ns")
            stdout_checks[host] = bool(isinstance(value, dict) and
                value.get("probe") == "hepta-native-six-host-v1" and
                all(type(value.get(key)) is int for key in numeric) and
                value["start_unix_ns"] > 0 and value["end_unix_ns"] > 0 and
                value["elapsed_ns"] == value["end_monotonic_ns"] - value["start_monotonic_ns"] and
                value["elapsed_ns"] >= 50_000_000 and stdout.get("offset") == 0 and
                stdout.get("eof") is True and stdout.get("next_offset") == stdout.get("size"))
        except (ValueError, TypeError, KeyError):
            pass
    terminal_checks = {host: bool(host in terminal and terminal[host].get("state") == "succeeded"
                                  and terminal[host].get("exit_code") == 0) for host in HOSTS}
    checks = {"all_original_bindings_confirmed": all(confirmed.values()),
              "six_distinct_job_ids": len(jobs) == 6 and len(set(jobs.values())) == 6,
              "all_exact_reuses_same_id_without_relaunch": all(reuse_checks.values()),
              "all_succeeded_with_exit_zero": all(terminal_checks.values()),
              "all_stdout_probes_valid": all(stdout_checks.values()),
              "all_terminal_within_poll_deadline": not pending and len(terminal) == 6}
    passed = all(checks.values())
    receipt.update(finished_at_utc=utc_now(), status="passed" if passed else "failed",
                   checks=checks, stdout_assertions=stdout_checks,
                   terminal_assertions=terminal_checks,
                   fresh_start_comparison_eligible=bool(passed and initial_fresh))
    return passed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--key-prefix", required=True)
    parser.add_argument("--output", required=True)
    options = parser.parse_args(argv)
    receipt = None
    try:
        endpoint = parse_endpoint(options.endpoint)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}", options.key_prefix):
            raise ProbeError("key prefix must be 1..120 ASCII letters/digits/_.:-, "
                             "starting with a letter or digit")
        token = Path(options.token_file).read_text(encoding="utf-8").strip()
        if not token or any(char in token for char in ("\r", "\n", "\0")):
            raise ProbeError("token file must contain one nonempty header-safe token")
        arguments = {host: {"host": host, "executable": "/usr/bin/python3",
            "args": ["-c", PROBE_CODE], "idempotency_key": options.key_prefix + "-" + host,
            "timeout_seconds": 10} for host in HOSTS}
        initial = {"schema": "hepta-native-six-host-acceptance/v1", "created_at_utc": utc_now(),
                   "endpoint": options.endpoint, "protocol_requested": PROTOCOL,
                   "sid_present": False, "status": "running", "key_prefix": options.key_prefix,
                   "probe_plan": arguments, "calls": [], "batches": [],
                   "limits": {"maximum_unique_probe_jobs": 6, "maximum_start_calls": 12,
                              "automatic_write_retries": 0, "poll_seconds": POLL_SECONDS,
                              "request_timeout_seconds": CALL_TIMEOUT,
                              "stdout_read_limit_bytes": 4096},
                   "interpretation": "Six low-load probe calls per write batch. Rates/quantiles "
                   "describe this direct-MCP sample including native dispatch and transport. "
                   "They are not a sustained throughput limit or SLA. Cross-host wall clocks "
                   "are not assumed synchronized. Fresh old/new comparisons require distinct "
                   "operator-chosen key prefixes and equivalent registry/load conditions. "
                   "Intent persistence occurs before the timed network batches; result-receipt "
                   "I/O is reported separately. Unknown starts are never automatically retried.",
                   "response_projection": "Tool JSON is decoded once; process_read saves only "
                   "stdout text/cursors and job identity. No raw MCP content, stderr, bytes_hex, "
                   "token, session ID, or authentication headers are saved. tools/list saves "
                   "count/names/canonical full-catalog SHA-256 rather than duplicate schemas."}
        receipt = Receipt(options.output, initial, token)
        passed = run(Client(endpoint, token, receipt), receipt, arguments)
        print(json.dumps(receipt.clean({"status": receipt.data["status"],
                          "receipt": str(receipt.path), "sid_present": receipt.data["sid_present"],
                          "catalog": receipt.data.get("catalog"),
                          "checks": receipt.data.get("checks"),
                          "fresh_start_comparison_eligible": receipt.data.get(
                              "fresh_start_comparison_eligible")}), sort_keys=True))
        return 0 if passed else 1
    except Exception as exc:
        if receipt is not None:
            failure = {"type": type(exc).__name__, "message": str(exc)[:8192]}
            try:
                receipt.update(status="aborted", fatal=failure, finished_at_utc=utc_now())
                print(json.dumps(receipt.clean({"status": "aborted", "fatal": failure,
                    "receipt": str(receipt.path)}), sort_keys=True), file=sys.stderr)
            except Exception:
                print("Benchmark aborted; receipt update failed. No automatic retries.", file=sys.stderr)
        else:
            # Avoid echoing a token-file path, token, or unsanitized setup exception.
            print("Benchmark setup refused (%s); check CLI, private token file, and an unused "
                  "receipt path. No requests submitted." % type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
