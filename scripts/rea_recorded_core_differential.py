#!/usr/bin/env python3
"""Capture unchanged REA recorded-core output, then compare a bound native worker.

The immutable corpus is produced by rea_recorded_core_corpus.py. This harness
preserves the complete Python helper reply, a separately executed unchanged
inspect_core payload, every native reply, process status, and actual limits.
Payload equality is a deliberately narrower claim than whole-helper equality.
No original file is edited, and no existing evidence directory is overwritten.
"""
from __future__ import annotations

import argparse
from collections import Counter
import concurrent.futures
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import resource
import signal
import struct
import subprocess
import sys
import time
import traceback

MAX_INPUT = 256 * 1024 * 1024
MAX_OUTPUT = 64 * 1024 * 1024
FRAME_SCHEMA = "hepta.rea.recorded-core-frame.v1"
REFERENCE_PROFILE = "pwntools@4.15.0;pyelftools@0.33;unicorn@2.1.2"
NATIVE_PROFILE = "hepta-native-recorded-core-v1"
SOURCE_PINS = {
    "recorded_crash_impl.py": "8dd89f64d7fa1a218b7def48c02a1e3bddfe8d2a47a2816e2e06441b9d394bb8",
    "recorded_crash.py": "1ff9358501ffd02af6e33d1ec759d2018171c33c749049bf3599335eca7a41bb",
    "decoder_runtime.py": "46a066d55314f0a3fa72b2ac14ddcd18bca2c21f975115347cefd2286741e410",
}
PACKAGE_PINS = {"pwntools": "4.15.0", "pyelftools": "0.33", "unicorn": "2.1.2"}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def identity(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": digest(data)}


def encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode()


def equal(left, right) -> bool:
    # JSON booleans and numbers are distinct, unlike Python's True == 1.
    return encode(left) == encode(right)


def save(path: Path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, ensure_ascii=True, indent=2, allow_nan=False)
        stream.write("\n")


def load(path: Path):
    return json.loads(path.read_bytes())


def pins(root: Path):
    found = {name: identity(root / name) for name in SOURCE_PINS}
    for name, expected in SOURCE_PINS.items():
        if found[name]["sha256"] != expected:
            raise RuntimeError("frozen reference source mismatch: " + name)
    return found


def corpus_rows(root: Path):
    manifest = load(root / "manifest.json")
    if manifest["schema"] != "hepta.rea.recorded-core-corpus.v1":
        raise RuntimeError("wrong corpus schema")
    names = set()
    for row in manifest["cases"]:
        if row["id"] in names:
            raise RuntimeError("duplicate corpus id")
        names.add(row["id"])
        path = root / row["path"]
        actual = identity(path)
        if actual["sha256"] != row["sha256"] or actual["bytes"] != row["bytes"]:
            raise RuntimeError("fixture identity mismatch: " + row["id"])
        if row["bytes"] > MAX_INPUT:
            raise RuntimeError("regular corpus fixture exceeds input cap")
    return manifest["cases"]


def execute(argv, directory: Path, *, data=None, timeout=45, env=None):
    started = time.monotonic()
    child_env = dict(os.environ)
    child_env.update({"PYTHONDONTWRITEBYTECODE": "1", "PWNLIB_NOTERM": "1",
                      "LC_ALL": "C.UTF-8"})
    if env:
        child_env.update(env)
    process = subprocess.Popen([str(x) for x in argv], cwd=directory, env=child_env,
        stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(data, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
    (directory / "stdout.bin").write_bytes(stdout)
    (directory / "stderr.bin").write_bytes(stderr)
    result = {"argv": [str(x) for x in argv], "cwd": str(directory),
        "pid": process.pid, "owned_process_group": process.pid,
        "exit_code": process.returncode, "timed_out": timed_out,
        "wall_seconds": time.monotonic() - started,
        "reaped": process.poll() is not None,
        "stdout": {"bytes": len(stdout), "sha256": digest(stdout)},
        "stderr": {"bytes": len(stderr), "sha256": digest(stderr)}}
    save(directory / "process.json", result)
    return result


def environment_receipt():
    installed = []
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name", "unknown")
        receipt = {"name": name, "version": distribution.version}
        for metadata_name in ("METADATA", "RECORD", "WHEEL", "direct_url.json"):
            text = distribution.read_text(metadata_name)
            if text is not None:
                receipt[metadata_name + "_sha256"] = digest(text.encode())
        installed.append(receipt)
    installed.sort(key=lambda item: (item["name"].lower(), item["version"]))
    found = {name: importlib.metadata.version(name) for name in PACKAGE_PINS}
    if found != PACKAGE_PINS:
        raise RuntimeError("pinned reference package mismatch: " + repr(found))
    return {"python": identity(Path(sys.executable)), "python_version": sys.version,
        "platform": platform.platform(), "machine": platform.machine(),
        "pointer_bytes": struct.calcsize("P"), "byteorder": sys.byteorder,
        "pinned_packages": found, "installed_distributions": installed}


def lower_soft_limits():
    actual = {}
    for name, kind, maximum in (("address_space_bytes", resource.RLIMIT_AS, 3 * 1024**3),
            ("cpu_seconds", resource.RLIMIT_CPU, 30),
            ("file_size_bytes", resource.RLIMIT_FSIZE, MAX_OUTPUT)):
        soft, hard = resource.getrlimit(kind)
        effective = min([maximum] + [v for v in (soft, hard) if v != resource.RLIM_INFINITY])
        resource.setrlimit(kind, (effective, hard))
        actual[name] = effective
    return actual


def internal_inspect(args):
    """This instrumentation calls the original compiled source without edits."""
    rows = corpus_rows(args.corpus)
    source_before = pins(args.reference_root)
    environment = environment_receipt()
    actual_limits = lower_soft_limits()
    os.environ["PWNLIB_NOTERM"] = "1"
    os.environ["PWNLIB_CACHE_DIR"] = str(args.output / "cache")
    source_path = args.reference_root / "recorded_crash_impl.py"
    namespace = {"__file__": str(source_path), "__name__": "frozen_rea_recorded_crash"}
    source = source_path.read_bytes()
    exec(compile(source, str(source_path), "exec"), namespace)
    failures = Counter()
    with (args.output / "api-rows.jsonl").open("x", encoding="utf-8") as stream:
        for row in rows:
            start = time.monotonic()
            try:
                value = namespace["inspect_core"](args.corpus / row["path"], args.output / "cache")
                outcome = {"ok": True, "value": value}
                failures["success"] += 1
            except namespace["CoreFailure"] as error:
                outcome = {"ok": False, "reason": error.reason, "message": str(error)}
                failures["typed:" + error.reason] += 1
            except Exception as error:
                outcome = {"unhandled_exception": {"type": type(error).__name__,
                    "message": str(error), "traceback": traceback.format_exc()}}
                failures["unhandled:" + type(error).__name__] += 1
            record = {"id": row["id"], "index": row["index"],
                      "fixture_sha256": row["sha256"], "outcome": outcome,
                      "wall_seconds": time.monotonic() - start}
            stream.write(json.dumps(record, ensure_ascii=True, allow_nan=False) + "\n")
            stream.flush()
    save(args.output / "api-receipt.json", {"schema": "hepta.rea.recorded-core-api-oracle.v1",
        "source_before": source_before, "source_after": pins(args.reference_root),
        "source_unchanged": source_before == pins(args.reference_root),
        "environment": environment, "actual_soft_limits": actual_limits,
        "counts": dict(failures), "case_count": len(rows),
        "instrumentation": "exec compile of byte-exact pinned source; direct inspect_core call; no source rewrite"})


def reference(args):
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "harness-source.py").write_bytes(Path(__file__).read_bytes())
    cases = corpus_rows(args.corpus)
    source_before = pins(args.reference_root)
    start_receipt = {"schema": "hepta.rea.recorded-core-reference-capture.v1",
        "corpus": identity(args.corpus / "manifest.json"), "source_before": source_before,
        "harness": identity(Path(__file__)), "python": identity(args.python),
        "reference_profile": REFERENCE_PROFILE}
    if args.pip_report:
        report_data = args.pip_report.read_bytes()
        (args.output / "pip-report.json").write_bytes(report_data)
        start_receipt["pip_report"] = identity(args.pip_report)
        installs = json.loads(report_data).get("install", [])
        save(args.output / "resolved-package-archives.json", [{
            "name": item["metadata"]["name"], "version": item["metadata"]["version"],
            "download_info": item.get("download_info"),
            "requested": item.get("requested")} for item in installs])
    save(args.output / "start.json", start_receipt)
    api_dir = args.output / "direct-api"
    api_dir.mkdir()
    api_result = execute([args.python, "-I", "-B", Path(__file__).resolve(), "internal-inspect",
        "--reference-root", args.reference_root, "--corpus", args.corpus,
        "--output", api_dir], api_dir, timeout=120)
    if api_result["exit_code"] or api_result["timed_out"]:
        raise RuntimeError("unchanged direct API capture did not complete; retained raw logs")
    api_rows = {row["id"]: row for row in map(json.loads,
               (api_dir / "api-rows.jsonl").read_text().splitlines())}
    helper_dir = args.output / "whole-helper"
    helper_dir.mkdir()

    def one(row):
        directory = helper_dir / row["id"]
        directory.mkdir()
        request = {"snapshot_path": str((args.corpus / row["path"]).resolve()),
                   "reply_path": str(directory / "reply.json")}
        save(directory / "request.json", request)
        result = execute([args.python, "-I", "-B", args.reference_root / "recorded_crash.py",
            directory / "failure-marker", directory / "request.json"], directory, timeout=args.timeout)
        helper, error = None, None
        reply = directory / "reply.json"
        if reply.exists():
            try:
                helper = load(reply)
            except Exception as exc:
                error = type(exc).__name__ + ": " + str(exc)
        limits = load(directory / "limits.json") if (directory / "limits.json").exists() else None
        api = api_rows[row["id"]]["outcome"]
        consistency = False
        if helper is not None:
            if api.get("ok") is True and limits is not None:
                expected = json.loads(json.dumps(api["value"]))
                expected["limitations"].append("Effective owned Python resource soft limits: "
                    + json.dumps(limits, sort_keys=True) + ". Inherited tighter limits are retained.")
                consistency = equal(helper, {"ok": True, "profile": REFERENCE_PROFILE, "value": expected})
            elif api.get("ok") is False:
                consistency = equal(helper, api)
            elif "unhandled_exception" in api:
                exception = api["unhandled_exception"]
                consistency = equal(helper, {"ok": False, "reason": "decoder",
                    "message": exception["type"] + ": " + exception["message"]})
        return {"id": row["id"], "index": row["index"], "category": row["category"],
            "fixture_sha256": row["sha256"], "api": api, "helper": helper,
            "helper_reply_identity": identity(reply) if reply.exists() else None,
            "actual_helper_limits": limits, "process": result,
            "reply_decode_error": error, "api_helper_boundary_consistent": consistency,
            "raw_directory": str(directory)}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        for count, row in enumerate(executor.map(one, cases), 1):
            results.append(row)
            if count % 50 == 0 or count == len(cases):
                print(json.dumps({"stage": "reference", "done": count, "total": len(cases)}), flush=True)
    with (args.output / "reference-rows.jsonl").open("x") as stream:
        for row in results:
            stream.write(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n")
    source_after = pins(args.reference_root)
    counts = Counter("success" if r["helper"] and r["helper"].get("ok") else
                     "failure:" + str((r["helper"] or {}).get("reason", "missing")) for r in results)
    summary = {"schema": "hepta.rea.recorded-core-reference-summary.v1", "case_count": len(results),
        "counts": dict(counts), "api_helper_consistent": sum(r["api_helper_boundary_consistent"] for r in results),
        "inconsistent_cases": [r["id"] for r in results if not r["api_helper_boundary_consistent"]],
        "process_failures": [r["id"] for r in results if r["process"]["exit_code"] or r["process"]["timed_out"]],
        "source_after": source_after, "source_unchanged": source_before == source_after,
        "reference_rows": identity(args.output / "reference-rows.jsonl"),
        "scope": "Byte-exact unchanged inspect_core and unchanged whole helper separately captured; no native claim."}
    save(args.output / "summary.json", summary)
    print(json.dumps(summary), flush=True)
    return 0 if summary["api_helper_consistent"] == len(cases) and summary["source_unchanged"] else 1


def first_difference(expected, actual, path="$"):
    if type(expected) is not type(actual):
        return {"path": path, "expected": expected, "actual": actual, "kind": "type"}
    if isinstance(expected, dict):
        if expected.keys() != actual.keys():
            return {"path": path, "expected_keys": sorted(expected), "actual_keys": sorted(actual), "kind": "keys"}
        for key in expected:
            difference = first_difference(expected[key], actual[key], path + "." + key)
            if difference:
                return difference
    elif isinstance(expected, list):
        if len(expected) != len(actual):
            return {"path": path, "expected_length": len(expected), "actual_length": len(actual), "kind": "length"}
        for index, (left, right) in enumerate(zip(expected, actual)):
            difference = first_difference(left, right, f"{path}[{index}]")
            if difference:
                return difference
    elif expected != actual:
        return {"path": path, "expected": expected, "actual": actual, "kind": "value"}
    return None


def frame(content, *, max_file_bytes=MAX_INPUT, max_output_bytes=MAX_OUTPUT,
          replacement=None):
    header = {"schema": FRAME_SCHEMA, "sha256": digest(content), "bytes": len(content),
              "max_file_bytes": max_file_bytes, "max_output_bytes": max_output_bytes}
    if replacement:
        header.update(replacement)
    wire_header = encode(header)
    return struct.pack("<I", len(wire_header)) + wire_header + content


def native_run(runtime: Path, directory: Path, wire: bytes, *, timeout=45, launcher=None):
    directory.mkdir()
    (directory / "stdin.bin").write_bytes(wire)
    process = execute(launcher or [runtime, "rea-recorded-core-worker"], directory, data=wire, timeout=timeout)
    stdout = (directory / "stdout.bin").read_bytes()
    stderr = (directory / "stderr.bin").read_bytes()
    reply, decode_error, diagnostic = None, None, None
    try:
        if stdout:
            reply = json.loads(stdout)
    except Exception as exc:
        decode_error = type(exc).__name__ + ": " + str(exc)
    if stderr:
        try:
            diagnostic = json.loads(stderr)
        except Exception:
            pass
    return {"process": process, "reply": reply, "reply_decode_error": decode_error,
            "stderr_diagnostic": diagnostic, "raw_directory": str(directory),
            "stdout_bytes": len(stdout), "stdout_ends_newline": stdout.endswith(b"\n")}


def genuine_native_limits(value):
    maxima = {"address_space_bytes": 3 * 1024**3, "cpu_seconds": 30,
              "file_size_bytes": MAX_OUTPUT, "open_files": 64, "core_file_bytes": 0}
    if not isinstance(value, dict) or set(value) != set(maxima):
        return False
    return all(type(value[key]) is int and 0 <= value[key] <= maximum
               for key, maximum in maxima.items())


def owned_open_input(runtime: Path, directory: Path, wire: bytes, deadline: float):
    directory.mkdir()
    (directory / "stdin-prefix.bin").write_bytes(wire)
    start = time.monotonic()
    process = subprocess.Popen([str(runtime), "rea-recorded-core-worker"], cwd=directory,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    process.stdin.write(wire)
    process.stdin.flush()
    timed_out = False
    try:
        process.wait(timeout=deadline)
    except subprocess.TimeoutExpired:
        timed_out = True
        # This PID is the process-group leader created by this exact Popen.
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
    stdout, stderr = process.communicate(timeout=10)
    (directory / "stdout.bin").write_bytes(stdout)
    (directory / "stderr.bin").write_bytes(stderr)
    result = {"pid": process.pid, "owned_process_group": process.pid,
        "external_wall_deadline_seconds": deadline, "timed_out": timed_out,
        "exit_code": process.returncode, "wall_seconds": time.monotonic() - start,
        "reaped": process.poll() is not None, "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
        "stdin_kept_open_until_deadline": True,
        "scope": "External harness owns deadline, group kill, reap and drain; not native public-provider cancellation proof."}
    save(directory / "process.json", result)
    return result


def protocol_cases(runtime, output, success_content, timeout):
    output.mkdir()
    valid = frame(success_content)
    header_size = struct.unpack("<I", valid[:4])[0]
    header = json.loads(valid[4:4 + header_size])

    def literal_header(value, content=success_content):
        encoded = value if isinstance(value, bytes) else encode(value)
        return struct.pack("<I", len(encoded)) + encoded + content

    specifications = [
        ("empty-input", b""), ("short-length", b"\x01\0"),
        ("zero-header", struct.pack("<I", 0)),
        ("header-over-cap", struct.pack("<I", 16385)),
        ("short-header", valid[:4 + header_size - 1]),
        ("invalid-json", literal_header(b"{")),
        ("unknown-field", literal_header(dict(header, injected=1))),
        ("duplicate-field", literal_header(encode(header)[:-1] + b',"bytes":0}')),
        ("short-payload", valid[:-1]), ("trailing-payload", valid + b"\0"),
        ("wrong-digest", frame(success_content, replacement={"sha256": "0" * 64})),
        ("uppercase-digest", frame(success_content, replacement={"sha256": digest(success_content).upper()})),
        ("wrong-schema", frame(success_content, replacement={"schema": "different"})),
        ("negative-bytes", frame(success_content, replacement={"bytes": -1})),
        ("zero-file-budget", frame(success_content, max_file_bytes=0)),
        ("file-budget-over-cap", frame(success_content, max_file_bytes=MAX_INPUT + 1)),
        ("zero-output-budget", frame(success_content, max_output_bytes=0)),
        ("output-budget-over-cap", frame(success_content, max_output_bytes=MAX_OUTPUT + 1)),
        ("declared-over-file-budget", frame(success_content, max_file_bytes=len(success_content) - 1)),
        ("declared-over-hard-cap", frame(success_content, replacement={"bytes": MAX_INPUT + 1})),
    ]
    rows = []
    expected_reasons = {"wrong-digest": "integrity", "zero-file-budget": "input-limit",
        "file-budget-over-cap": "input-limit", "declared-over-file-budget": "input-limit",
        "declared-over-hard-cap": "input-limit", "zero-output-budget": "output-limit"}
    for name, wire in specifications:
        result = native_run(runtime, output / name, wire, timeout=timeout)
        reply = result["reply"] or result["stderr_diagnostic"]
        result.update({"id": name, "native_typed_rejection": bool(reply and reply.get("ok") is False
            and isinstance(reply.get("reason"), str) and isinstance(reply.get("message"), str)),
            "comparison_scope": "Native strict captured-frame boundary; original Python file protocol has no identical frame."})
        result["expected_reason"] = expected_reasons.get(name, "protocol")
        result["contract_matches"] = bool(reply and reply.get("ok") is False
            and reply.get("reason") == result["expected_reason"]
            and "value" not in reply and "snapshot" not in reply
            and not result["process"]["timed_out"] and result["process"]["reaped"]
            and ((result["stdout_bytes"] > 0 and result["stdout_ends_newline"]
                  and result["process"]["exit_code"] == 0)
                 or (result["stdout_bytes"] == 0 and result["process"]["exit_code"] == 76
                     and result["process"]["stderr"]["bytes"] <= 4096)))
        rows.append(result)
    baseline = native_run(runtime, output / "complete-envelope-baseline", valid, timeout=timeout)
    rows.append(dict(baseline, id="complete-envelope-baseline", comparison_scope="Native output budget measurement"))
    # Apply real inherited limits in a fresh owned child, then exec the same
    # bound native image. This is deliberately not subprocess.preexec_fn in a
    # threaded harness, and the original Python reference is never modified.
    launcher_source = '''import json,os,resource,sys
limits = {}
for name,kind,maximum in (
    ("address_space_bytes",resource.RLIMIT_AS,1536*1024*1024),
    ("cpu_seconds",resource.RLIMIT_CPU,10),
    ("file_size_bytes",resource.RLIMIT_FSIZE,32*1024*1024),
    ("open_files",resource.RLIMIT_NOFILE,32),
    ("core_file_bytes",resource.RLIMIT_CORE,0)):
    soft,hard=resource.getrlimit(kind)
    effective=min([maximum]+[v for v in (soft,hard) if v != resource.RLIM_INFINITY])
    resource.setrlimit(kind,(effective,hard))
    limits[name]={"inherited_soft":soft,"inherited_hard":hard,"requested_soft":maximum,
                  "applied_soft":resource.getrlimit(kind)[0],"preserved_hard":resource.getrlimit(kind)[1]}
with open("inherited-limits-before-exec.json","x") as stream:
    json.dump(limits,stream,sort_keys=True)
os.execv(sys.argv[1],[sys.argv[1],"rea-recorded-core-worker"])
'''
    (output / "inherited-limit-launcher.py").write_text(launcher_source)
    inherited = native_run(runtime, output / "inherited-tighter-limits", valid, timeout=timeout,
        launcher=[sys.executable, "-I", "-B", "-c", launcher_source, runtime])
    receipt_path = output / "inherited-tighter-limits/inherited-limits-before-exec.json"
    inherited_receipt = load(receipt_path) if receipt_path.exists() else None
    inherited_actual = (inherited["reply"] or {}).get("reported_limits")
    inherited_expected = ({key: value["applied_soft"] for key, value in inherited_receipt.items()}
                          if inherited_receipt else None)
    inherited.update({"id": "inherited-tighter-limits", "exec_receipt": inherited_receipt,
        "expected_actual_soft_limits": inherited_expected,
        "contract_matches": bool(inherited_receipt and inherited["reply"]
            and inherited["reply"].get("ok") is True and inherited["process"]["exit_code"] == 0
            and inherited["stdout_ends_newline"] and equal(inherited_expected, inherited_actual)
            and equal(inherited["reply"].get("value"), (baseline["reply"] or {}).get("value"))
            and all(value["inherited_hard"] == value["preserved_hard"] for value in inherited_receipt.values())),
        "comparison_scope": "Actually inherited tighter soft limits remain exact after native setup; not Python-helper resource-boundary equivalence."})
    rows.append(inherited)
    size = baseline["stdout_bytes"]
    # Each candidate is measured with its real reported limit field; no payload-only size estimate.
    candidates = sorted(set([1, 64, 128, 256] + list(range(max(1, size - 12), size + 3))))
    for budget in candidates:
        result = native_run(runtime, output / f"output-budget-{budget}",
            frame(success_content, max_output_bytes=budget), timeout=timeout)
        result.update({"id": f"output-budget-{budget}", "budget": budget,
            "stdout_within_budget": result["stdout_bytes"] <= budget,
            "comparison_scope": "Native complete envelope budget; explicit cap outside unchanged inspect_core payload equality."})
        reply = result["reply"] or result["stderr_diagnostic"]
        result["contract_matches"] = bool(reply and result["stdout_within_budget"]
            and not result["process"]["timed_out"] and result["process"]["reaped"]
            and ((reply.get("ok") is True and baseline["reply"] is not None
                  and equal(reply, baseline["reply"]))
                 or (reply.get("ok") is False and reply.get("reason") == "output-limit"))
            and ((result["stdout_bytes"] > 0 and result["stdout_ends_newline"]
                  and result["process"]["exit_code"] == 0)
                 or (result["stdout_bytes"] == 0 and result["process"]["exit_code"] == 76
                     and result["process"]["stderr"]["bytes"] <= 4096)))
        rows.append(result)
    lifecycle = []
    for name, prefix in (("partial-header-kept-open", valid[:6]), ("full-frame-without-eof", valid)):
        result = owned_open_input(runtime, output / name, prefix, min(timeout, 1.0))
        lifecycle.append(dict(result, id=name))
    save(output / "rows.json", rows)
    save(output / "lifecycle.json", lifecycle)
    successes = [r["budget"] for r in rows if "budget" in r and r["reply"] and r["reply"].get("ok") is True]
    return {"rows": rows, "lifecycle": lifecycle,
        "contract_failures": [r["id"] for r in rows if r.get("contract_matches") is False],
        "baseline_success": bool(baseline["reply"] and baseline["reply"].get("ok") is True),
        "baseline_complete_reply_bytes_including_newline": size,
        "smallest_observed_success_budget": min(successes) if successes else None,
        "lifecycle_contract_matches": all(r["timed_out"] and r["reaped"] and r["exit_code"] == -9
                                          and r["stdout_bytes"] == 0 for r in lifecycle)}


def native(args):
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "harness-source.py").write_bytes(Path(__file__).read_bytes())
    runtime_before = identity(args.runtime)
    if runtime_before["sha256"] != args.runtime_sha256:
        raise RuntimeError("native runtime identity mismatch")
    cases = corpus_rows(args.corpus)
    reference = {r["id"]: r for r in map(json.loads,
                 (args.reference / "reference-rows.jsonl").read_text().splitlines())}
    reference_summary = load(args.reference / "summary.json")
    if reference_summary["api_helper_consistent"] != len(cases) or not reference_summary["source_unchanged"]:
        raise RuntimeError("reference capture did not establish unchanged, complete oracle rows")
    if set(reference) != {r["id"] for r in cases}:
        raise RuntimeError("reference/corpus case set differs")
    save(args.output / "start.json", {"schema": "hepta.rea.recorded-core-native-start.v1",
        "runtime": runtime_before, "harness": identity(Path(__file__)),
        "corpus": identity(args.corpus / "manifest.json"),
        "reference_rows": identity(args.reference / "reference-rows.jsonl"),
        "source_binding": identity(args.source_binding) if args.source_binding else None})
    parser_directory = args.output / "parser"
    parser_directory.mkdir()

    def one(row):
        original = reference[row["id"]]
        if original["fixture_sha256"] != row["sha256"]:
            raise RuntimeError("reference fixture digest mismatch")
        content = (args.corpus / row["path"]).read_bytes()
        result = native_run(args.runtime, parser_directory / row["id"], frame(content), timeout=args.timeout)
        actual = result["reply"]
        api = original["api"]
        expected = api if "unhandled_exception" not in api else original["helper"]
        difference = None
        if actual is None:
            difference = {"path": "$", "kind": "missing-native-reply", "expected": expected}
        elif expected.get("ok") is True:
            if actual.get("ok") is not True:
                difference = first_difference(expected, actual)
            else:
                difference = first_difference(expected["value"], actual.get("value"), "$.value")
        else:
            expected_failure = {key: expected.get(key) for key in ("ok", "reason", "message")}
            actual_failure = {key: actual.get(key) for key in ("ok", "reason", "message")}
            difference = first_difference(expected_failure, actual_failure)
        snapshot_correct = (actual is not None and equal(actual.get("snapshot"),
                            {"sha256": row["sha256"], "bytes": row["bytes"]}))
        process_complete = (not result["process"]["timed_out"] and result["process"]["reaped"]
                            and result["process"]["exit_code"] == 0 and result["stdout_ends_newline"])
        parser_equal = difference is None and process_complete
        result.update({"id": row["id"], "index": row["index"], "category": row["category"],
            "fixture_sha256": row["sha256"], "reference_api": api,
            "reference_whole_helper": original["helper"],
            "parser_payload_or_typed_failure_equal": parser_equal,
            "difference": difference, "snapshot_correct": snapshot_correct,
            "whole_helper_envelope_equal": equal(original["helper"], actual),
            "native_success_profile_correct": (actual.get("profile") == NATIVE_PROFILE
                if actual and actual.get("ok") is True else None),
            "reported_limits": actual.get("reported_limits") if actual else None,
            "native_limits_shape_and_caps_correct": genuine_native_limits(actual.get("reported_limits") if actual else None),
            "comparison_scope": "Exact unchanged inspect_core payload or stable reason/message; complete outer envelopes are retained separately."})
        return result

    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        for count, result in enumerate(executor.map(one, cases), 1):
            rows.append(result)
            if count % 100 == 0 or count == len(cases):
                print(json.dumps({"stage": "native", "done": count, "total": len(cases)}), flush=True)
    with (args.output / "comparison-rows.jsonl").open("x") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n")
    successful_case = next(row for row in cases if reference[row["id"]]["api"].get("ok") is True)
    boundary = protocol_cases(args.runtime, args.output / "native-boundary",
                             (args.corpus / successful_case["path"]).read_bytes(), args.timeout)
    runtime_after = identity(args.runtime)
    mismatches = [{"id": row["id"], "category": row["category"], "difference": row["difference"]}
                  for row in rows if not row["parser_payload_or_typed_failure_equal"]]
    summary = {"schema": "hepta.rea.recorded-core-differential-summary.v1",
        "case_count": len(rows), "payload_or_typed_failure_equal": len(rows) - len(mismatches),
        "mismatch_count": len(mismatches), "mismatches": mismatches,
        "whole_helper_envelopes_equal": sum(r["whole_helper_envelope_equal"] for r in rows),
        "native_snapshot_correct": sum(r["snapshot_correct"] for r in rows),
        "native_success_profile_correct": sum(r["native_success_profile_correct"] is True for r in rows),
        "native_success_profile_failures": [r["id"] for r in rows if r["native_success_profile_correct"] is False],
        "native_limits_shape_and_caps_correct": sum(r["native_limits_shape_and_caps_correct"] for r in rows),
        "runtime_before": runtime_before, "runtime_after": runtime_after,
        "runtime_unchanged": runtime_before == runtime_after,
        "category_counts": dict(Counter(r["category"] for r in rows)),
        "boundary_cases": len(boundary["rows"]), "lifecycle_cases": boundary["lifecycle"],
        "boundary_contract_failures": boundary["contract_failures"],
        "complete_reply_budget": {key: boundary[key] for key in
            ("baseline_success", "baseline_complete_reply_bytes_including_newline", "smallest_observed_success_budget")},
        "lifecycle_contract_matches": boundary["lifecycle_contract_matches"],
        "comparison_rows": identity(args.output / "comparison-rows.jsonl"),
        "claim": "Parser payload and stable typed failures only, with all raw whole-helper/native envelopes retained. This does not qualify the complete Python helper, P09 decoder runtime, public Provider, or MCP lifecycle as replaced."}
    save(args.output / "summary.json", summary)
    print(json.dumps(summary), flush=True)
    return 0 if (not mismatches and summary["runtime_unchanged"]
        and not summary["boundary_contract_failures"] and summary["lifecycle_contract_matches"]
        and summary["native_snapshot_correct"] == len(rows)
        and summary["native_limits_shape_and_caps_correct"] == len(rows)
        and not summary["native_success_profile_failures"]) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    ref = commands.add_parser("reference")
    ref.add_argument("--corpus", type=Path, required=True)
    ref.add_argument("--reference-root", type=Path, required=True)
    ref.add_argument("--python", type=Path, required=True)
    ref.add_argument("--output", type=Path, required=True)
    ref.add_argument("--pip-report", type=Path)
    ref.add_argument("--jobs", type=int, default=2)
    ref.add_argument("--timeout", type=float, default=45)
    internal = commands.add_parser("internal-inspect")
    internal.add_argument("--corpus", type=Path, required=True)
    internal.add_argument("--reference-root", type=Path, required=True)
    internal.add_argument("--output", type=Path, required=True)
    worker = commands.add_parser("native")
    worker.add_argument("--corpus", type=Path, required=True)
    worker.add_argument("--reference", type=Path, required=True)
    worker.add_argument("--runtime", type=Path, required=True)
    worker.add_argument("--runtime-sha256", required=True)
    worker.add_argument("--source-binding", type=Path)
    worker.add_argument("--output", type=Path, required=True)
    worker.add_argument("--jobs", type=int, default=2)
    worker.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    for name in ("corpus", "reference_root", "python", "output", "reference", "runtime", "source_binding", "pip_report"):
        value = getattr(args, name, None)
        if value is not None:
            setattr(args, name, value.resolve())
    if getattr(args, "jobs", 1) < 1 or getattr(args, "jobs", 1) > 8:
        parser.error("jobs must be in 1..8")
    if args.command == "internal-inspect":
        internal_inspect(args)
        return 0
    return reference(args) if args.command == "reference" else native(args)


if __name__ == "__main__":
    raise SystemExit(main())
