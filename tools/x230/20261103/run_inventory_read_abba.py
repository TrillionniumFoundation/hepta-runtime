#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One ABBA block per local inventory case, with a fresh libtest process per arm.

Uses identical 128-receipt fixtures across both builds. No remote work or service
changes. Input/binary hashes are observed; matching build provenance is separate.
Plain preserves the original long argument bytes. Escaped repeats newline,
quote and backslash text at the same decoded byte length to exercise owned-string
fallback. Serialized fixtures must stay below the runtime's 128 MiB source cap;
use --payload-style escaped --payload-bytes 65536 for that diagnostic.
"""
import argparse
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time


TEST = "mcp::runtime::jobs::inventory_read_bench::guarded_inventory_reads_benchmark"
BENCH = "src/mcp/runtime/jobs_inventory_read_bench.rs"
PAYLOADS = (1024, 65536, 786432)
WIDTHS = (1, 4, 8)
MODES = ("list", "page")
RECORDS = 128
MAX_FIXTURE_BYTES = 128 * 1024 * 1024
NATIVE_RSS_FORMAT = '{"maxrss_kib":%M,"exit_code":%x}'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            result.update(chunk)
    return result.hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def checkpoint(output, report):
    temporary = output / "report.json.tmp"
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(output / "report.json")


def source_map(root):
    files = [root / name for name in ("Cargo.toml", "Cargo.lock")]
    files.extend(root / name for name in ("build.rs", "rust-toolchain", "rust-toolchain.toml")
                 if (root / name).exists())
    for directory in ("src", "examples", ".cargo"):
        if (root / directory).is_dir():
            files.extend(path for path in (root / directory).rglob("*") if path.is_file())
    need(all(not path.is_symlink() for path in files), "source symlink refused")
    return {str(path.relative_to(root)): digest(path) for path in sorted(files)}


def payload_text(payload, style):
    need(type(payload) is int and payload > 0, "payload size must be a positive integer")
    need(style in ("plain", "escaped"), "unknown payload style")
    if style == "plain":
        return "x" * payload
    pattern = 'line="a"\\\n'
    text = (pattern * ((payload + len(pattern) - 1) // len(pattern)))[:payload]
    need(len(text.encode("utf-8")) == payload, "decoded argument size differs")
    return text


def fixture_record(index, argument):
    return {
        "execution_mode": "operator", "system_jobctl": False,
        "id": f"inventory-bench-{index:04}", "host": "main" if index % 2 == 0 else "other",
        "created_unix_ms": index + 1, "ssh_target": "never-connect.invalid",
        "unit": "inventory-bench-unit", "remote_job_dir": "/never-launch/inventory-bench",
        "executable": "/usr/bin/true", "args": [argument, 'escaped\n中文\\"'],
        "cwd": None, "env_keys": ["EXAMPLE"],
        "idempotency_key": f"inventory-key-{index:04}", "request_fingerprint": 1,
        "request_digest": "a" * 64, "launch_state": "launched", "launch_error": None,
    }


def fixture_bytes(payload, style):
    # Only the encoded first argument changes. Count every metadata row without
    # constructing or writing a full 128-record large-payload fixture.
    extra = len(canonical(payload_text(payload, style))) - len(canonical(""))
    return sum(len(canonical(fixture_record(index, ""))) for index in range(RECORDS)) + RECORDS * extra


def check_fixture_budget(payload, style):
    total = fixture_bytes(payload, style)
    need(total < MAX_FIXTURE_BYTES,
         f"{style} {payload}-byte payload produces {total} source bytes, exceeding the "
         "128 MiB inventory bound; select --payload-bytes 65536 for escaped input")
    return total


def fixture(parent, payload, style="plain"):
    expected_bytes = check_fixture_budget(payload, style)
    argument = payload_text(payload, style)
    root = parent / str(payload)
    root.mkdir(mode=0o700)
    jobs = root / "jobs"
    jobs.mkdir(mode=0o700)
    files = {}
    for index in range(RECORDS):
        identity = f"inventory-bench-{index:04}"
        record = fixture_record(index, argument)
        raw = canonical(record)
        path = jobs / (identity + ".json")
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o600)
        files[path.name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    manifest = {"schema": "hepta-inventory-bench-fixture/v1", "records": RECORDS,
                "payload_bytes": payload, "payload_style": style, "files": files}
    need(sum(row["bytes"] for row in files.values()) == expected_bytes, "fixture size accounting differs")
    (root / "fixture.json").write_bytes(canonical(manifest))
    return {"path": str(root), "manifest": manifest, "payload_style": style,
            "manifest_sha256": digest(root / "fixture.json"),
            "bytes": sum(row["bytes"] for row in files.values())}


def prepare_native_rss_launcher(path):
    need(path.is_absolute(), "native RSS launcher must be an explicit absolute path")
    resolved = path.resolve(strict=True)
    need(resolved.is_file() and os.access(resolved, os.X_OK), "native RSS launcher is not executable")
    return {"path": str(resolved), "sha256": digest(resolved), "usage_format": NATIVE_RSS_FORMAT}


def verify_native_rss(process, benchmark=None):
    native = process["native_rss"]
    need(not native.get("error"), "native RSS evidence unavailable: " + str(native.get("error")))
    need(native["launcher_sha256_before"] == native["launcher_sha256_after"] == native["launcher_sha256"],
         "native RSS launcher changed during execution")
    need(type(native.get("exit_code")) is int and native["exit_code"] == 0
         and process["exit_code"] == 0, "native RSS child or launcher failed")
    need(type(native.get("maxrss_kib")) is int and native["maxrss_kib"] >= 0,
         "invalid native RSS peak")
    if benchmark is not None:
        need(benchmark["process_lifetime_maxrss_kib"] <= native["maxrss_kib"],
             "Rust early RSS peak exceeds native final child peak")


def launch(argv, environment, output, name, timeout, native_rss_launcher=None):
    stdout, stderr = output / (name + ".stdout"), output / (name + ".stderr")
    command = argv
    native = None
    if native_rss_launcher is not None:
        launcher = Path(native_rss_launcher["path"])
        before = digest(launcher)
        need(before == native_rss_launcher["sha256"], "native RSS launcher changed before execution")
        usage_path = output / (name + ".native-rss.json")
        # Reserve a new private receipt; GNU time may truncate only this fresh file.
        with usage_path.open("xb"):
            pass
        command = [str(launcher), "-o", str(usage_path), "-f", NATIVE_RSS_FORMAT, "--", *argv]
        native = {"source": "gnu_time_direct_child", "launcher_path": str(launcher),
                  "launcher_sha256": native_rss_launcher["sha256"],
                  "launcher_sha256_before": before, "usage_format": NATIVE_RSS_FORMAT}
    started = time.monotonic()
    signals = []
    interrupted = None
    timed_out = False
    with stdout.open("xb") as out, stderr.open("xb") as err:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                 env=environment, start_new_session=True)
        kill_after = None
        while True:
            try:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    child.returncode = os.waitstatus_to_exitcode(status)
                    break
                now = time.monotonic()
                if not signals and now - started >= timeout:
                    timed_out = True
                    os.killpg(child.pid, signal.SIGTERM)
                    signals.append("SIGTERM")
                    kill_after = now + 2
                elif kill_after is not None and now >= kill_after:
                    os.killpg(child.pid, signal.SIGKILL)
                    signals.append("SIGKILL")
                    kill_after = None
                time.sleep(0.02)
            except KeyboardInterrupt:
                interrupted = "KeyboardInterrupt"
                if not signals:
                    os.killpg(child.pid, signal.SIGTERM)
                    signals.append("SIGTERM")
                    kill_after = time.monotonic() + 2
    result = {
        "argv": argv, "pid": child.pid, "exit_code": child.returncode,
        "elapsed_seconds": time.monotonic() - started, "timed_out": timed_out,
        "interrupted": interrupted, "signals": signals, "original_child_reaped": True,
        "wait4": {"user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
                  "maxrss_kib": usage.ru_maxrss, "major_faults": usage.ru_majflt,
                  "minor_faults": usage.ru_minflt, "input_blocks": usage.ru_inblock,
                  "output_blocks": usage.ru_oublock},
        "stdout": {"file": stdout.name, "sha256": digest(stdout), "bytes": stdout.stat().st_size},
        "stderr": {"file": stderr.name, "sha256": digest(stderr), "bytes": stderr.stat().st_size},
    }
    if native is not None:
        # Keep wrapper wait4 even when final native usage is missing or malformed.
        # The caller records this process result before refusing failed evidence.
        result["launcher_argv"] = command
        result["wait4_scope"] = "GNU time wrapper; may retain the Python parent RSS floor"
        result["native_rss"] = native
        try:
            native["launcher_sha256_after"] = digest(launcher)
            raw = usage_path.read_bytes()
            native["usage"] = {"file": usage_path.name, "bytes": len(raw),
                               "sha256": hashlib.sha256(raw).hexdigest()}
            native["usage_text"] = raw.decode("utf-8")
            parsed = json.loads(raw)
            need(type(parsed) is dict and set(parsed) == {"maxrss_kib", "exit_code"},
                 "invalid native RSS usage schema")
            native.update(parsed)
        except Exception as error:
            native["error"] = f"{type(error).__name__}: {error}"
    return result, stdout.read_text()


def parse(stdout, case, expected_fixture, calls):
    records = []
    for line in stdout.splitlines():
        match = re.search(r"INVENTORY_READ_BENCH (\{.*\})$", line)
        if match:
            records.append(json.loads(match[1]))
    need(len(records) == 1, "exactly one benchmark result required")
    row = records[0]
    need(re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", stdout),
         "exact libtest completion absent")
    need(row.get("schema") == "hepta-inventory-read-bench/v1" and row.get("records") == RECORDS,
         "benchmark schema/record count changed")
    need(all(row.get(key) == value for key, value in case.items()), "benchmark case changed")
    need(row.get("calls_per_worker") == calls and row.get("failures") == 0
         and row.get("successes") == case["concurrency"] * calls,
         "benchmark call count/failures differ")
    need(row.get("physical_read_workers") == 4 and row.get("tokio_workers") == 2
         and row.get("remote_effects") == 0, "worker count or effect scope changed")
    need(row.get("fixture_sha256") == expected_fixture["manifest_sha256"]
         and row.get("fixture_bytes") == expected_fixture["bytes"]
         and row.get("fixture_unchanged") is True
         and row.get("public_identity_checked_each_call") is True,
         "fixture or returned identities unverified")
    need(re.fullmatch(r"[0-9a-f]{64}", row.get("response_sha256", "")), "response digest missing")
    latencies = row.get("latencies", [])
    need([(item.get("worker"), item.get("call")) for item in latencies]
         == list(itertools.product(range(case["concurrency"]), range(calls))),
         "raw latency samples missing, duplicated or reordered")
    values = [item["latency_ms"] for item in latencies]
    values += [row.get(key) for key in
               ("wall_seconds", "user_cpu_seconds", "system_cpu_seconds", "process_lifetime_maxrss_kib")]
    need(all(type(value) in (float, int) and math.isfinite(value) and value >= 0 for value in values)
         and row["wall_seconds"] > 0, "invalid latency/CPU/RSS value")
    return row


def percentile(values, quantile):
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * quantile) - 1]


def aggregate(samples):
    results = []
    use_native_rss = any("native_rss" in row.get("process", {}) for row in samples)
    if use_native_rss:
        need(all("native_rss" in row.get("process", {}) for row in samples),
             "mixed native and wrapper-wait4 RSS samples refused")
        need(len({(row["process"]["native_rss"]["launcher_path"],
                   row["process"]["native_rss"]["launcher_sha256"]) for row in samples}) == 1,
             "mixed native RSS launcher identities refused")
        for row in samples:
            verify_native_rss(row["process"], row["benchmark"])
    cases = list(dict.fromkeys((row["mode"], row["payload_bytes"], row["concurrency"]) for row in samples))
    for mode, payload, concurrency in cases:
        selected = [row for row in samples if
                    (row["mode"], row["payload_bytes"], row["concurrency"]) == (mode, payload, concurrency)]
        need([row["arm"] for row in selected] == list("ABBA") and all(row["passed"] for row in selected),
             "incomplete ABBA case cannot be summarized")
        need(len({row["benchmark"]["response_sha256"] for row in selected}) == 1,
             "baseline/candidate response bytes differ")
        styles = {row.get("payload_style", "plain") for row in selected}
        need(len(styles) == 1, "mixed payload styles cannot form one ABBA comparison")
        arms = {}
        for arm in "AB":
            members = [row for row in selected if row["arm"] == arm]
            calls = sum(row["benchmark"]["successes"] for row in members)
            wall = sum(row["benchmark"]["wall_seconds"] for row in members)
            cpu = sum(row["benchmark"]["user_cpu_seconds"] + row["benchmark"]["system_cpu_seconds"]
                      for row in members)
            latency = [item["latency_ms"] for row in members for item in row["benchmark"]["latencies"]]
            rss = [row["process"]["native_rss"]["maxrss_kib"] for row in members] if use_native_rss else [
                row["process"]["wait4"]["maxrss_kib"] for row in members]
            arms[arm] = {"processes": len(members), "calls": calls, "wall_seconds": wall,
                         "calls_per_second": calls / wall, "cpu_ms_per_call": 1000 * cpu / calls,
                         "p50_ms": percentile(latency, .5), "p95_ms": percentile(latency, .95),
                         "max_ms": max(latency), "whole_child_maxrss_kib": rss,
                         "median_whole_child_maxrss_kib": statistics.median(rss)}
            if use_native_rss:
                arms[arm]["rss_source"] = "gnu_time_direct_child"
                arms[arm]["wrapper_wait4_maxrss_kib"] = [
                    row["process"]["wait4"]["maxrss_kib"] for row in members]
        changes = {}
        for key in ("calls_per_second", "cpu_ms_per_call", "p50_ms", "p95_ms", "median_whole_child_maxrss_kib"):
            changes[key + "_percent"] = 100 * (arms["B"][key] / arms["A"][key] - 1) if arms["A"][key] else None
        results.append({"mode": mode, "payload_bytes": payload, "payload_style": styles.pop(),
                        "concurrency": concurrency,
                        "arms": arms, "candidate_change": changes})
    return results


def run(args, output, report):
    native_rss_launcher = None
    if getattr(args, "native_rss_launcher", None) is not None:
        native_rss_launcher = prepare_native_rss_launcher(args.native_rss_launcher)
        report["native_rss_launcher"] = native_rss_launcher
        report["rss_measurement"] = "gnu_time_direct_child"
        report["rss_note"] = (
            "GNU time direct libtest child maxrss in Linux KiB; includes fixture checks/warmup; "
            "wrapper wait4 is retained separately and may include the Python parent RSS floor; "
            "Rust early RSS must not exceed the native final child peak")
    variants = {}
    for arm, label in (("A", "baseline"), ("B", "candidate")):
        binary = getattr(args, label).resolve(strict=True)
        root = getattr(args, label + "_source").resolve(strict=True)
        expected = getattr(args, label + "_sha256")
        need(not output.is_relative_to(root), "output cannot be inside a source tree")
        need(re.fullmatch(r"[0-9a-f]{64}", expected) and digest(binary) == expected, label + " binary pin differs")
        sources = source_map(root)
        variants[arm] = {"binary": str(binary), "sha256": expected, "source": str(root), "source_map": sources}
        (output / (label + "-source-map.json")).write_bytes(canonical(sources))
    report["variants"] = variants
    need(variants["A"]["sha256"] != variants["B"]["sha256"], "baseline and candidate binary are identical")
    need(variants["A"]["source_map"][BENCH] == variants["B"]["source_map"][BENCH], "benchmark modules differ")

    def verify_inputs():
        for item in variants.values():
            need(digest(item["binary"]) == item["sha256"], "benchmark binary changed")
            need(source_map(Path(item["source"])) == item["source_map"], "compiler inputs changed")

    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("HEPTA_", "SSH_", "RUST_TEST_"))}
    environment.update(RUST_TEST_THREADS="1", TOKIO_WORKER_THREADS="2")
    report["enumerations"] = []
    for arm, item in variants.items():
        result, text = launch([item["binary"], "--ignored", "--list", "--format", "terse"],
                              environment, output, arm + "-enumeration", args.timeout, native_rss_launcher)
        report["enumerations"].append({"arm": arm, **result})
        need(result["exit_code"] == 0 and not result["timed_out"] and not result["interrupted"]
             and text.splitlines().count(TEST + ": test") == 1, "exact ignored benchmark unavailable")
        if native_rss_launcher is not None:
            verify_native_rss(result)
    with tempfile.TemporaryDirectory(prefix="hepta-inventory-abba-") as directory:
        parent = Path(directory).resolve()
        required = sum(check_fixture_budget(payload, args.payload_style)
                       for payload in args.payload_bytes) + 16 * 1024 * 1024
        need(shutil.disk_usage(parent).free > 2 * required, "insufficient temporary fixture space")
        fixtures = {payload: fixture(parent, payload, args.payload_style) for payload in args.payload_bytes}
        report["fixtures"] = fixtures
        for payload, item in fixtures.items():
            (output / f"fixture-{payload}-manifest.json").write_bytes(canonical(item["manifest"]))
        for sample in report["samples"]:
            verify_inputs()
            sample["executed"] = True
            checkpoint(output, report)
            case = {key: sample[key] for key in ("mode", "payload_bytes", "concurrency")}
            item = fixtures[case["payload_bytes"]]
            env = {**environment,
                   "HEPTA_INVENTORY_BENCH_MODE": case["mode"],
                   "HEPTA_INVENTORY_BENCH_PAYLOAD_BYTES": str(case["payload_bytes"]),
                   "HEPTA_INVENTORY_BENCH_CONCURRENCY": str(case["concurrency"]),
                   "HEPTA_INVENTORY_BENCH_CALLS_PER_WORKER": str(args.calls_per_worker),
                   "HEPTA_INVENTORY_BENCH_FIXTURE": item["path"],
                   "HEPTA_INVENTORY_BENCH_FIXTURE_SHA256": item["manifest_sha256"]}
            try:
                process, text = launch([variants[sample["arm"]]["binary"], "--ignored", "--exact", TEST,
                                        "--nocapture", "--test-threads=1"], env, output,
                                       f"sample-{sample['index']:03}-{sample['arm']}", args.timeout,
                                       native_rss_launcher)
                sample["process"] = process
                need(process["exit_code"] == 0 and not process["timed_out"] and not process["interrupted"],
                     "benchmark child failed/timed out/interrupted; no retry")
                sample["benchmark"] = parse(text, case, item, args.calls_per_worker)
                if native_rss_launcher is not None:
                    verify_native_rss(process, sample["benchmark"])
                sample["passed"] = True
                verify_inputs()
            except (Exception, KeyboardInterrupt) as error:
                sample["passed"] = False
                sample["error"] = f"{type(error).__name__}: {error}"
                raise
            finally:
                checkpoint(output, report)
                print(json.dumps({key: sample.get(key) for key in
                                  ("index", "arm", "mode", "payload_bytes", "payload_style",
                                   "concurrency", "passed", "error")}), flush=True)
        verify_inputs()
        report["statistics"] = aggregate(report["samples"])
    report["temporary_fixtures_removed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("baseline", "candidate"):
        parser.add_argument("--" + label, type=Path, required=True)
        parser.add_argument("--" + label + "-sha256", required=True)
        parser.add_argument("--" + label + "-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--payload-bytes", type=int, nargs="+", choices=PAYLOADS, default=list(PAYLOADS))
    parser.add_argument("--payload-style", choices=("plain", "escaped"), default="plain",
                        help="long argument encoding; escaped 768 KiB is refused by the source byte bound")
    parser.add_argument("--concurrency", type=int, nargs="+", choices=WIDTHS, default=list(WIDTHS))
    parser.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES))
    parser.add_argument("--calls-per-worker", type=int, choices=range(1, 33), default=4)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--native-rss-launcher", type=Path,
                        help="optional absolute GNU time path, e.g. /usr/bin/time; default launch is unchanged")
    args = parser.parse_args()
    need(sys.platform == "linux", "Linux wait4/RSS accounting required")
    need(math.isfinite(args.timeout) and args.timeout > 0, "timeout must be finite and positive")
    for values in (args.payload_bytes, args.concurrency, args.modes):
        need(len(values) == len(set(values)), "duplicate case dimension refused")
    for payload in args.payload_bytes:
        check_fixture_budget(payload, args.payload_style)
    os.umask(0o077)
    output = args.out.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    samples = []
    for payload, mode, concurrency in itertools.product(args.payload_bytes, args.modes, args.concurrency):
        for arm in "ABBA":
            samples.append({"index": len(samples), "arm": arm, "mode": mode,
                            "payload_bytes": payload, "payload_style": args.payload_style,
                            "concurrency": concurrency,
                            "executed": False, "passed": False})
    report = {
        "schema": "hepta-inventory-read-abba/v1", "passed": False, "samples": samples,
        "order_per_case": "ABBA", "automatic_retries": 0, "runner_sha256": digest(Path(__file__)),
        "source_binding": "observed compiler inputs and supplied binary hashes; build provenance is separate",
        "scope": "local guarded inventory and wire response in isolated libtest builds; not SSH/full MCP throughput",
        "fixture_note": "one shared immutable 128-receipt fixture per payload, verified before/after every child",
        "payload_style": args.payload_style,
        "payload_note": "payload_bytes is decoded UTF-8 length; escaped uses repeated line=\"a\" plus backslash/newline",
        "fixture_source_byte_limit": MAX_FIXTURE_BYTES,
        "cache_note": "full fixture hash verification plus one inventory warmup; no cold-disk or disk-write speed claim",
        "cpu_note": "benchmark RUSAGE_SELF deltas exclude fixture/warmup; wait4 totals include the whole child",
        "rss_note": "wait4 maxrss is Linux KiB, one fresh process per case/arm; includes fixture checks/warmup",
        "latency_note": "raw admission-through-wire latencies; wall also includes exact public identity checks",
        "statistics_note": "one ABBA block, two processes per arm/case; descriptive results, no significance claim",
        "calls_per_worker": args.calls_per_worker, "timeout_seconds": args.timeout,
    }
    started = time.monotonic()
    try:
        run(args, output, report)
        report["passed"] = all(row["passed"] for row in samples)
    except (Exception, KeyboardInterrupt) as error:
        report.update(passed=False, error=f"{type(error).__name__}: {error}", statistics=None)
    report["elapsed_seconds"] = time.monotonic() - started
    checkpoint(output, report)
    print(json.dumps({"report": str(output / "report.json"), "passed": report["passed"]}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
