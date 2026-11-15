#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Controlled Linux ABBA comparison of native weight-client validation paths.

Accepts two already-built, SHA-256-pinned binaries and a real worker/Python.
Runs four deliberately rejected, never-sent paths, then optionally bounded
success/error responses from one private Unix socket. No model is loaded and
no existing service, runtime profile or source file is modified. Uses stdlib.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

MAX_FRAME = 1024 * 1024
MAX_REQUEST = 64 * 1024 + 1
MAX_BINARY = 2 * 1024 * 1024 * 1024
MAX_PACKAGE = 32 * 1024 * 1024
SESSION = "controlled-identity-benchmark"
ROUTES = ("baseline", "candidate")
STAGES = {
    "request_validation": ("INVALID_REQUEST",
                           "weight request session, operation or fields differ from the fixed contract"),
    "client_hash": ("IDENTITY_MISMATCH",
                    "running native client SHA-256 differs from the installed profile"),
    "worker_hash": ("IDENTITY_MISMATCH",
                    "worker entry SHA-256 differs from the installed profile"),
    "package_hash": ("IDENTITY_MISMATCH",
                     "worker package SHA-256 differs from the installed profile"),
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def save_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(json.dumps(value, sort_keys=True, indent=2).encode() + b"\n")
    temporary.replace(path)


def environment():
    result = {key: os.environ[key] for key in ("PATH", "HOME", "USER", "LOGNAME", "LANG") if key in os.environ}
    result.update(RUST_LOG="error", OMP_NUM_THREADS="1", MKL_NUM_THREADS="1",
                  OPENBLAS_NUM_THREADS="1", NUMEXPR_NUM_THREADS="1",
                  VECLIB_MAXIMUM_THREADS="1", GOTO_NUM_THREADS="1",
                  PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1")
    return result


def metadata(value):
    return {"device": value.st_dev, "inode": value.st_ino, "bytes": value.st_size,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns,
            "mode": stat.S_IMODE(value.st_mode)}


def stable_hash(path, maximum, destination=None):
    """Hash full bytes from one FD; compare FD and selected path before/after."""
    digest = hashlib.sha256()
    consumed = 0
    with Path(path).open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise RuntimeError(f"identity input is not a bounded regular file: {path}")
        with destination.open("xb") if destination is not None else nullcontext() as copied:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                consumed += len(block)
                if consumed > maximum:
                    raise RuntimeError(f"identity input grew beyond its byte budget: {path}")
                digest.update(block)
                if copied is not None:
                    copied.write(block)
            if copied is not None:
                copied.flush()
                os.fsync(copied.fileno())
        after = os.fstat(source.fileno())
        selected = Path(path).stat()
    if (consumed != before.st_size or metadata(before) != metadata(after)
            or metadata(before) != metadata(selected)):
        raise RuntimeError(f"identity input changed while hashing: {path}")
    return {"path": str(path), "sha256": digest.hexdigest(), **metadata(before)}


def package_identity(worker):
    root = worker.parent

    def names():
        result = sorted(item.name for item in (root / "weight_runtime").iterdir()
                        if item.name.endswith(".py"))
        if len(result) >= 256:
            raise RuntimeError("worker package exceeds the native source-file limit")
        return result

    selected = names()
    files = {}
    total = 0
    for name in [worker.name] + ["weight_runtime/" + name for name in selected]:
        value = stable_hash(root / name, MAX_PACKAGE - total)
        files[name] = value
        total += value["bytes"]
    if selected != names():
        raise RuntimeError("worker package entries changed while hashing")
    digests = {name: value["sha256"] for name, value in files.items()}
    return {"worker_sha256": files[worker.name]["sha256"],
            "package_sha256": hashlib.sha256(canonical(digests)).hexdigest(),
            "total_bytes": total, "files": files}


def bounded_bytes(path, maximum):
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise RuntimeError(f"oversized trace: {path}")
    return value


def read_json(raw, frame=True):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate JSON member")
            result[name] = value
        return result

    def nonfinite(value):
        raise ValueError(f"non-finite JSON number: {value}")

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("non-finite JSON number")
        return result

    if frame and (len(raw) > MAX_FRAME or not raw.endswith(b"\n") or raw.count(b"\n") != 1):
        raise RuntimeError("expected one bounded newline-terminated JSON frame")
    result = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite,
                        parse_float=finite_float)
    if not isinstance(result, dict):
        raise RuntimeError("expected a JSON object")
    return result


def process_call(command, request, traces, label):
    request_path = traces / (label + ".request.jsonl")
    stdout_path = traces / (label + ".stdout.jsonl")
    stderr_path = traces / (label + ".stderr.txt")
    request_path.write_bytes(request)
    with request_path.open("rb") as incoming, stdout_path.open("xb") as outgoing, stderr_path.open("xb") as errors:
        started = time.perf_counter_ns()
        child = subprocess.Popen(command, stdin=incoming, stdout=outgoing, stderr=errors, env=environment())
        try:
            pidfd = os.pidfd_open(child.pid)
        except BaseException:
            child.kill()
            child.wait()
            raise
        timed_out = threading.Event()

        def expire():
            timed_out.set()
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass

        timer = threading.Timer(65, expire)
        timer.daemon = True
        timer.start()
        try:
            _, status, usage = os.wait4(child.pid, 0)
            elapsed = (time.perf_counter_ns() - started) / 1_000_000
            child.returncode = os.waitstatus_to_exitcode(status)
        except BaseException:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status, _ = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            raise
        finally:
            timer.cancel()
            timer.join()
            os.close(pidfd)
    return {"wall_ms": elapsed, "client_user_cpu_ms": usage.ru_utime * 1000,
            "client_system_cpu_ms": usage.ru_stime * 1000,
            "client_total_cpu_ms": (usage.ru_utime + usage.ru_stime) * 1000,
            "client_wait4_lifetime_peak_rss_kib": usage.ru_maxrss,
            "exit_code": child.returncode, "timed_out": timed_out.is_set(),
            "request_trace": str(request_path), "stdout_trace": str(stdout_path),
            "stderr_trace": str(stderr_path)}


def large_response(identifier, success, byte_budget):
    if success:
        prefix = b'{"id":' + canonical(identifier) + b',"ok":true,"result":{"values":['
        suffix = b']}}\n'
    else:
        prefix = (b'{"id":' + canonical(identifier) + b',"ok":false,"error":'
                  b'{"code":"CONTROLLED_WORKER_ERROR","message":"controlled bounded response",'
                  b'"details":{"values":[')
        suffix = b']}}}\n'
    count = (byte_budget - len(prefix) - len(suffix) + 1) // 5
    if count < 1:
        raise RuntimeError("large response budget cannot hold the fixture envelope")
    result = prefix + b"0.25," * (count - 1) + b"0.25" + suffix
    if len(result) > byte_budget or len(result) > MAX_FRAME:
        raise RuntimeError("fixture exceeds response budget")
    return result, count


class SocketFixture:
    """A single private listener; each large sample has one owned responder."""
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hwid-", dir="/tmp")
        root = Path(self.temporary.name)
        root.chmod(0o700)
        self.path = root / "worker.sock"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.path.chmod(0o600)
        self.listener.listen(8)
        self.listener.setblocking(False)
        self.observations = []
        self.thread = None
        self.stop = threading.Event()

    def reject_pending(self):
        """Called after child reap, so a prior connect cannot still be in flight."""
        unexpected = 0
        while True:
            try:
                connection, _ = self.listener.accept()
            except BlockingIOError:
                break
            with connection:
                unexpected += 1
                self.observations.append({"unexpected_connection": True})
        if unexpected:
            raise RuntimeError(f"unexpected additional socket connections: {unexpected}")

    def start(self, request, response, observed_path):
        if self.thread is not None:
            raise RuntimeError("previous fixture responder was not joined")
        observation = {"request_sha256_expected": hashlib.sha256(request).hexdigest(),
                       "response_sha256_expected": hashlib.sha256(response).hexdigest(),
                       "response_bytes": len(response), "connections": 0,
                       "status": "waiting", "request_trace": str(observed_path)}
        self.observations.append(observation)

        def serve():
            try:
                deadline = time.monotonic() + 65
                while not self.stop.is_set():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("fixture accept deadline")
                    ready, _, _ = select.select([self.listener], [], [], 0.1)
                    if not ready:
                        continue
                    connection, _ = self.listener.accept()
                    break
                else:
                    raise RuntimeError("fixture cancelled before accept")
                observation["connections"] = 1
                with connection:
                    connection.settimeout(30)
                    parts = []
                    length = 0
                    while True:
                        part = connection.recv(min(65536, MAX_REQUEST + 1 - length))
                        if not part:
                            break
                        parts.append(part)
                        length += len(part)
                        if length > MAX_REQUEST:
                            raise RuntimeError("fixture received an oversized request")
                    raw = b"".join(parts)
                    observed_path.write_bytes(raw)
                    observation["request_sha256_observed"] = hashlib.sha256(raw).hexdigest()
                    if raw != request:
                        raise RuntimeError("fixture request differs from the original single request")
                    connection.sendall(response)
                    connection.shutdown(socket.SHUT_WR)
                observation["status"] = "response_sent_once"
            except BaseException as error:
                observation["status"] = "failed"
                observation["error"] = f"{type(error).__name__}: {error}"

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        return observation

    def finish(self):
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("fixture responder did not finish after child exit")
        self.thread = None
        self.reject_pending()
        if self.observations[-1]["status"] != "response_sent_once":
            raise RuntimeError(f"fixture failed: {self.observations[-1]}")

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
        self.listener.close()
        self.temporary.cleanup()
        if self.thread is not None and self.thread.is_alive():
            raise RuntimeError("fixture responder remained alive during cleanup")


class Benchmark:
    def __init__(self, args):
        self.args = args
        self.output = Path(args.output).resolve()
        self.output.mkdir(mode=0o700)
        self.traces = self.output / "traces"
        self.traces.mkdir(mode=0o700)
        (self.output / "bin").mkdir(mode=0o700)
        self.python = Path(os.path.abspath(args.python))  # Preserve venv selection.
        self.worker = Path(args.worker).resolve(strict=True)
        self.binaries = {}
        self.inputs = {}
        self.samples = []
        self.fixture = None
        self.report = {
            "schema": "hepta.weight.client-identity-benchmark.v1", "status": "initializing",
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scope": {
                "not_sent": "four cumulative startup/validation exit paths; exact errors and zero socket connections required",
                "stage_differences": "descriptive whole-process differences; not isolated hash or parser timings",
                "large_response": "fresh native client -> same private deterministic Unix fixture -> byte-identical stdout -> exit",
                "engine": "real worker/package pins verified; fixture supplies replies; no model or Python compute backend is measured",
                "wall_boundary": "perf_counter immediately before Popen through wait4 reap; includes process creation, exec, validation, transport and stdout",
                "wall_excludes": "fixture preparation, driver trace validation, input hashing, result persistence and final input recheck",
                "cpu_boundary": "wait4 direct-child user+system CPU, including its threads; excludes driver and fixture CPU",
                "rss_boundary": "wait4 lifetime ru_maxrss in KiB, may include inherited pre-exec peak; cannot represent post-exec or steady-state memory",
                "cache_state": "fresh processes; copied/hashed inputs warm an uncontrolled OS file cache; no cold-cache claim",
                "order": "per-stage A,B then B,A; even round count forms complete ABBA blocks; no warmup exclusions",
                "retry_policy": "no resubmission or retry after failure; raw traces and failed sample retained",
                "source_labels": "caller-supplied revision/manifest labels require external build provenance; binary content hashes are measured",
            },
            "environment": {"kernel": platform.release(), "machine": platform.machine(),
                            "cpu_count": os.cpu_count(), "cpu_affinity": sorted(os.sched_getaffinity(0)),
                            "load_average_start": os.getloadavg(), "driver_python": sys.version,
                            "native_child_env": environment()},
            "requested": {"samples_per_route_per_stage": args.samples,
                          "large_response_byte_budget": args.large_response_bytes,
                          "large_response_enabled": not args.skip_large_response},
            "inputs": self.inputs, "samples": self.samples,
        }
        self.flush()

    def flush(self):
        save_json(self.output / "results.json", self.report)

    def prepare(self):
        self.inputs["driver"] = stable_hash(Path(__file__).resolve(), 8 * 1024 * 1024)
        self.inputs["python"] = stable_hash(self.python, MAX_BINARY)
        for route in ROUTES:
            source = Path(getattr(self.args, route + "_binary")).resolve(strict=True)
            expected = getattr(self.args, route + "_sha256")
            captured = self.output / "bin" / ("hepta-runtime-" + route)
            source_identity = stable_hash(source, MAX_BINARY, captured)
            if source_identity["sha256"] != expected:
                raise RuntimeError(f"{route} source binary differs from required SHA-256")
            captured.chmod(0o500)
            captured_identity = stable_hash(captured, MAX_BINARY)
            if captured_identity["sha256"] != expected:
                raise RuntimeError(f"{route} captured binary differs from required SHA-256")
            self.binaries[route] = captured
            self.inputs[route] = {"source": source_identity, "captured": captured_identity,
                                  "expected_sha256": expected,
                                  "source_revision": getattr(self.args, route + "_source_revision"),
                                  "source_manifest_sha256": getattr(self.args, route + "_source_manifest_sha256")}
        self.identity = package_identity(self.worker)
        self.inputs["worker_package"] = self.identity
        stdout = self.traces / "worker-print-identity.stdout.json"
        stderr = self.traces / "worker-print-identity.stderr.txt"
        with stdout.open("xb") as outgoing, stderr.open("xb") as errors:
            completed = subprocess.run([str(self.python), str(self.worker), "--print-identity"],
                                       stdin=subprocess.DEVNULL, stdout=outgoing, stderr=errors,
                                       env=environment(), timeout=30, check=False)
        if completed.returncode != 0:
            raise RuntimeError("real Python/worker --print-identity failed")
        declared = read_json(bounded_bytes(stdout, MAX_FRAME), frame=False)
        for name in ("worker_sha256", "package_sha256"):
            if declared.get(name) != self.identity[name]:
                raise RuntimeError(f"worker self-reported {name} differs from independent full-content identity")
        self.inputs["worker_reported_identity"] = declared
        self.fixture = SocketFixture()
        self.report["fixture"] = {"socket": str(self.fixture.path), "uid": os.getuid(),
                                  "directory_mode": "0700", "socket_mode": "0600",
                                  "observations": self.fixture.observations}
        self.report["status"] = "running"
        self.flush()

    def command(self, route, stage):
        pins = {"client": self.inputs[route]["expected_sha256"],
                "worker": self.identity["worker_sha256"], "package": self.identity["package_sha256"]}
        if stage in ("client_hash", "worker_hash", "package_hash"):
            pins[stage.removesuffix("_hash")] = "0" * 64
        command = [str(self.binaries[route]), "weight-client", "--socket", str(self.fixture.path),
                   "--session-id", SESSION, "--worker-path", str(self.worker),
                   "--expected-client-sha256", pins["client"],
                   "--expected-worker-sha256", pins["worker"],
                   "--expected-package-sha256", pins["package"],
                   "--timeout-ms", "30000", "--connect-timeout-ms", "5000"]
        return command, pins

    def sample(self, stage, route, round_index, position):
        letter = "A" if route == "baseline" else "B"
        identifier = f"{stage}-{letter}-{round_index:02d}"
        request = canonical({"id": identifier, "session_id": SESSION + "-wrong" if stage == "request_validation" else SESSION,
                             "op": "inspect", "params": {}}) + b"\n"
        label = f"{stage}-{round_index:02d}-{position}-{route}"
        command, pins = self.command(route, stage)
        record = {"stage": stage, "route": route, "round": round_index, "position": position,
                  "request_id": identifier, "request_sha256": hashlib.sha256(request).hexdigest(),
                  "binary_sha256": self.inputs[route]["expected_sha256"], "supplied_pins": pins,
                  "source_revision": self.inputs[route]["source_revision"], "status": "running"}
        self.samples.append(record)
        try:
            self.fixture.reject_pending()
            if stage not in STAGES:
                expected, count = large_response(identifier, stage == "large_success", self.args.large_response_bytes)
                expected_path = self.traces / (label + ".expected.jsonl")
                expected_path.write_bytes(expected)
                record["expected_response_trace"] = str(expected_path)
                record["fixture_value_count"] = count
                record["socket_observation"] = self.fixture.start(
                    request, expected, self.traces / (label + ".socket-request.jsonl"))
            record.update(process_call(command, request, self.traces, label))
            raw = bounded_bytes(Path(record["stdout_trace"]), MAX_FRAME)
            errors = bounded_bytes(Path(record["stderr_trace"]), MAX_FRAME)
            record.update(response_sha256=hashlib.sha256(raw).hexdigest(), response_bytes=len(raw),
                          stderr_sha256=hashlib.sha256(errors).hexdigest(), stderr_bytes=len(errors))
            if record["timed_out"]:
                record["operation_state"] = "unknown"
                raise RuntimeError("owned client timed out; request is not resubmitted")
            reply = read_json(raw)
            record.update(response_id=reply.get("id"), ok=reply.get("ok"),
                          error_code=reply.get("error", {}).get("code"))
            if stage in STAGES:
                self.fixture.reject_pending()
                code, message = STAGES[stage]
                desired = {"id": None if stage == "request_validation" else identifier, "ok": False,
                           "error": {"code": code, "message": message, "details": {
                               "operation_state": "not_sent", "automatic_retry": False,
                               "observation": "weight_status/weight_read on the original request job"}}}
                if (reply != desired or reply.get("ok") is not False or record["exit_code"] != 1
                        or reply["error"]["details"]["automatic_retry"] is not False):
                    raise RuntimeError("client did not stop at the exact intended not_sent validation boundary")
                record.update(operation_state="not_sent", socket_connections=0)
            else:
                self.fixture.finish()
                if raw != expected or record["exit_code"] != (0 if stage == "large_success" else 1):
                    raise RuntimeError("large response bytes or worker-error exit status changed")
                record["socket_connections"] = 1
            record["status"] = "validated"
        except BaseException as error:
            record["status"] = "failed"
            record["failure"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            self.flush()

    def check_inputs(self):
        checks = []
        self.report["final_full_content_checks"] = checks
        for name in ("driver", "python"):
            if name in self.inputs:
                prior = self.inputs[name]
                current = stable_hash(Path(prior["path"]), MAX_BINARY)
                checks.append({"input": name, "unchanged": current == prior, "after": current})
        for route in ROUTES:
            if route in self.inputs:
                for kind in ("source", "captured"):
                    prior = self.inputs[route][kind]
                    current = stable_hash(Path(prior["path"]), MAX_BINARY)
                    checks.append({"input": route + "." + kind, "unchanged": current == prior, "after": current})
        if "worker_package" in self.inputs:
            current = package_identity(self.worker)
            checks.append({"input": "worker_package", "unchanged": current == self.identity, "after": current})
        if any(not item["unchanged"] for item in checks):
            raise RuntimeError("input identity changed during the comparison")

    def summarize(self):
        result = {}
        for stage in dict.fromkeys(sample["stage"] for sample in self.samples):
            result[stage] = {}
            for route in ROUTES:
                selected = [sample for sample in self.samples if sample["stage"] == stage
                            and sample["route"] == route and sample["status"] == "validated"]
                metrics = {"validated_samples": len(selected)}
                for name in ("wall_ms", "client_user_cpu_ms", "client_system_cpu_ms", "client_total_cpu_ms"):
                    values = sorted(sample[name] for sample in selected)
                    if values:
                        metrics[name] = {"p50": values[math.ceil(len(values) * 0.5) - 1],
                                         "p95": values[math.ceil(len(values) * 0.95) - 1],
                                         "min": values[0], "max": values[-1]}
                result[stage][route] = metrics
        self.report["summary_nearest_rank_percentiles"] = result

    def run(self):
        failures = []
        try:
            self.prepare()
            stages = list(STAGES)
            if not self.args.skip_large_response:
                stages += ["large_success", "large_worker_error"]
            for stage in stages:
                for round_index in range(self.args.samples):
                    order = ROUTES if round_index % 2 == 0 else tuple(reversed(ROUTES))
                    for position, route in enumerate(order):
                        self.sample(stage, route, round_index, position)
        except BaseException as error:
            failures.append(f"{type(error).__name__}: {error}")
        finally:
            if self.fixture is not None:
                try:
                    self.fixture.close()
                    self.report["fixture"]["cleanup"] = "closed_and_removed"
                except BaseException as error:
                    failures.append(f"fixture cleanup: {type(error).__name__}: {error}")
            try:
                self.check_inputs()
            except BaseException as error:
                failures.append(f"final input check: {type(error).__name__}: {error}")
            self.summarize()
            self.report.update(status="failed" if failures else "succeeded", failures=failures,
                               finished_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                               load_average_end=os.getloadavg())
            self.flush()
        return 1 if failures else 0


def sha_argument(value):
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("expected exactly 64 lowercase SHA-256 hex characters")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for route in ROUTES:
        parser.add_argument("--" + route + "-binary", required=True)
        parser.add_argument("--" + route + "-sha256", required=True, type=sha_argument)
        parser.add_argument("--" + route + "-source-revision", required=True)
        parser.add_argument("--" + route + "-source-manifest-sha256", type=sha_argument)
    parser.add_argument("--python", required=True, help="real worker Python; venv path is preserved")
    parser.add_argument("--worker", required=True, help="real worker.py with its complete weight_runtime package")
    parser.add_argument("--output", required=True, help="new private evidence directory; must not already exist")
    parser.add_argument("--samples", type=int, default=10, help="even sample count per route and stage, 2..40")
    parser.add_argument("--large-response-bytes", type=int, default=768 * 1024)
    parser.add_argument("--skip-large-response", action="store_true")
    args = parser.parse_args()
    if args.samples < 2 or args.samples > 40 or args.samples % 2:
        parser.error("--samples must be an even integer from 2 through 40 for complete ABBA blocks")
    if not 4096 <= args.large_response_bytes <= MAX_FRAME:
        parser.error("--large-response-bytes must be between 4096 and 1048576, including the newline")
    if sys.platform != "linux" or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        parser.error("Linux wait4 and pidfd support are required")
    os.umask(0o077)
    benchmark = Benchmark(args)
    status = benchmark.run()
    print(json.dumps({"status": benchmark.report["status"], "results": str(benchmark.output / "results.json"),
                      "samples": len(benchmark.samples), "failures": benchmark.report["failures"]}, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
