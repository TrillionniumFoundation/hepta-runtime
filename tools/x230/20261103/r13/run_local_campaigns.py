#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Gate three serial local campaigns on one completed qualification.

No compilation, remote operation, production-service mutation, or automatic
retry. Telemetry collects process command names, never process command lines.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

ROOT = Path("/home/qian/hepta-runtime-optimization-20261103-r13")
SOURCE, QUAL, HERE = ROOT / "source", ROOT / "qualification-02", ROOT / "measurement-tools"
OUT = ROOT / "local-campaigns-01"
R12 = Path("/home/qian/hepta-runtime-optimization-20261103-r12")
R11 = Path("/home/qian/hepta-runtime-optimization-20261103-r11")
OLD_TOOLS = R12 / "source/tools/x230/20261103/r12"
WAIT_SECONDS, CAMPAIGN_TIMEOUT, ANALYZER_TIMEOUT = 3600, 1800, 180
STAGES = ("format", "fmt-check", "harness-tests", "clippy", "test-build",
          "isolated-tests", "audit-isolated-tests", "release")
RELEASE_NAMES = {"hepta-runtime", "hepta-runtime-jobctl", "native_process_driver"}
BASELINES = {
    "r12": (R12 / "qualification-02",
            "e7f1f8275c6735a6823f35b6367baf9fc9f943ea7e62a1114fe1187e82cd1c1f"),
    "r11": (R11 / "qualification-01",
            "660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c"),
}
CAMPAIGNS = {"projection": ROOT / "operation-projection-abba-01",
             "cancel_r12_r13": ROOT / "cancel-r12-r13-01",
             "cancel_r11_r13": ROOT / "cancel-r11-r13-01"}
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
       "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
BUILD_NAMES = {"cargo", "rustc", "rustdoc", "cc", "cc1", "cc1plus", "c++", "g++",
               "gcc", "clang", "clang++", "ld", "ld.lld", "lld", "collect2"}
REPORT, BOUND = {}, {}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def identity(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and path.resolve() == path,
            "bound input is not a direct regular file: " + str(path))
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def bind(path, expected=None):
    path = Path(path)
    before, digest = identity(path), sha(path)
    require(before == identity(path), "input changed while hashing: " + str(path))
    require(expected is None or digest == expected, "bound SHA256 differs: " + str(path))
    row = {"path": str(path), "sha256": digest, "identity": before}
    require(str(path) not in BOUND or BOUND[str(path)] == row,
            "bound input identity changed: " + str(path))
    BOUND[str(path)] = row
    return row


def source_map():
    files = [SOURCE / name for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
    for name in ("src", "examples"):
        files.extend(p for p in (SOURCE / name).rglob("*") if p.is_file())
    result = {}
    for path in sorted(files):
        if path.is_file():
            identity(path)
            result[str(path.relative_to(SOURCE))] = sha(path)
    return result


def save():
    temporary = OUT / "report.next"
    temporary.write_bytes(encoded(REPORT))
    os.replace(temporary, OUT / "report.json")


def event(state, **fields):
    print(json.dumps({"utc": utc(), "state": state, **fields}), flush=True)


def snapshot_json(path, name):
    raw = Path(path).read_bytes()
    value = json.loads(raw)
    with (OUT / "bindings" / name).open("xb") as stream:
        stream.write(raw)
    bind(path, hashlib.sha256(raw).hexdigest())
    return value


def proc_info(pid):
    try:
        data = Path(f"/proc/{pid}/stat").read_text()
        last = data.rfind(")")
        fields = data[last + 2:].split()
        return {"pid": int(pid), "ppid": int(fields[1]), "start_ticks": int(fields[19]),
                "comm": data[data.find("(") + 1:last], "state": fields[0]}
    except (OSError, ValueError, IndexError):
        return None


def processes():
    rows = {}
    for path in Path("/proc").iterdir():
        if path.name.isdigit():
            row = proc_info(int(path.name))
            if row is not None:
                rows[row["pid"]] = row
    return rows


def prohibit_compile():
    rows = [row for row in processes().values()
            if row["state"] not in {"Z", "X"} and (row["comm"] in BUILD_NAMES
                or row["comm"].startswith(("rustc", "cargo")))]
    require(not rows, "concurrent compiler process observed: " + json.dumps(rows))


def telemetry():
    result = {"utc": utc(), "scope": "host snapshots, not per-campaign causal attribution"}
    for name in ("uptime", "meminfo", "loadavg"):
        try:
            result[name] = Path("/proc", name).read_text()
        except OSError as error:
            result[name + "_error"] = type(error).__name__
    result["thermal"] = []
    directories = (list(Path("/sys/class/thermal").glob("thermal_zone*"))
                   + list(Path("/sys/class/hwmon").glob("hwmon*")))
    for directory in sorted(directories):
        row = {"path": str(directory)}
        names = (["type", "temp"] if directory.name.startswith("thermal_zone") else
                 ["name"] + sorted(p.name for p in directory.glob("temp*_input")))
        for name in names:
            try:
                row[name] = (directory / name).read_text().strip()
            except OSError as error:
                row[name + "_error"] = type(error).__name__
        result["thermal"].append(row)
    result["cpu_frequency"] = []
    for directory in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq")):
        row = {"cpu": directory.parent.name}
        for name in ("scaling_cur_freq", "scaling_min_freq", "scaling_max_freq",
                     "scaling_governor", "cpuinfo_cur_freq"):
            try:
                row[name] = (directory / name).read_text().strip()
            except OSError as error:
                row[name + "_error"] = type(error).__name__
        result["cpu_frequency"].append(row)
    try:
        result["cpu_top_scope"] = "ps lifetime %CPU, command names only; not interval CPU"
        output = subprocess.run(
            ["/bin/ps", "-eo", "pid=,ppid=,pcpu=,pmem=,comm=", "--sort=-pcpu"],
            capture_output=True, timeout=10, check=True, text=True, env=ENV).stdout
        result["cpu_top_comm"] = []
        for line in output.splitlines()[:15]:
            fields = line.split(None, 4)
            if len(fields) == 5:
                result["cpu_top_comm"].append({
                    "pid": int(fields[0]), "ppid": int(fields[1]), "cpu_percent": float(fields[2]),
                    "memory_percent": float(fields[3]), "comm": fields[4]})
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result["cpu_top_error"] = type(error).__name__
    return result


def same_process(row):
    now = proc_info(row["pid"])
    return now is not None and now["start_ticks"] == row["start_ticks"]


def stop_owned_tree(process, original):
    """Stop only the new local driver's observed PID generations after failure."""
    result = {"reason": "bounded local stage interrupted", "observed": [], "signals": []}
    if original is None or not same_process(original):
        return result
    try:
        os.kill(original["pid"], signal.SIGSTOP)
    except ProcessLookupError:
        return result
    owned = {original["pid"]: original}
    for unused in range(2):
        table, changed = processes(), True
        while changed:
            changed = False
            for pid, row in table.items():
                if row["ppid"] in owned and pid not in owned:
                    owned[pid], changed = row, True
        for row in owned.values():
            if same_process(row):
                try:
                    os.kill(row["pid"], signal.SIGSTOP)
                except ProcessLookupError:
                    pass
    result["observed"] = list(owned.values())
    for row in reversed(list(owned.values())):
        if same_process(row):
            try:
                os.kill(row["pid"], signal.SIGKILL)
                result["signals"].append({"pid": row["pid"], "start_ticks": row["start_ticks"],
                                          "signal": "SIGKILL"})
            except ProcessLookupError:
                pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        result["driver_wait_timed_out"] = True
    return result


def wait_for_qualification(started):
    deadline, previous = started + WAIT_SECONDS, None
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "qualification gate timed out after 3600 seconds; no campaign started")
        try:
            qualification = json.loads((QUAL / "report.json").read_bytes())
        except FileNotFoundError:
            qualification = {}
        except json.JSONDecodeError as error:
            raise RuntimeError("qualification report is not complete valid JSON") from error
        require(not qualification.get("error"), "qualification failed; original report retained")
        require(not any(row.get("returncode") not in (None, 0)
                        for row in qualification.get("stages", [])),
                "qualification stage failed; no campaign started")
        observed = (qualification.get("current_stage"), qualification.get("finished_utc"),
                    qualification.get("qualified"))
        REPORT["qualification_wait"] = {
            "elapsed_seconds": time.monotonic() - started, "limit_seconds": WAIT_SECONDS,
            "current_stage": observed[0], "finished_utc": observed[1], "qualified": observed[2],
            "last_observed_utc": utc()}
        save()
        if observed != previous:
            event("waiting_for_qualification", stage=observed[0], qualified=observed[2])
            previous = observed
        if qualification.get("finished_utc"):
            require(qualification.get("qualified") is True,
                    "qualification finished unsuccessfully; no campaign started")
            return
        time.sleep(min(10, remaining))


def establish_binding():
    q = snapshot_json(QUAL / "report.json", "qualification.json")
    require(q["schema"] == "hepta-x230-composed-qualification/v1"
            and q.get("qualified") is True and q.get("finished_utc")
            and q.get("source") == str(SOURCE), "qualification terminal identity differs")
    require(not q.get("error") and q.get("automatic_test_retries") == 0
            and q.get("service_changes") is False, "qualification policy result differs")
    require([row["name"] for row in q["stages"]] == list(STAGES)
            and all(row.get("returncode") == 0 for row in q["stages"]),
            "qualification did not pass every required stage")
    tested = q["source_tested"]
    require(isinstance(tested, dict) and tested and tested == q["source_after"],
            "tested and post-qualification source maps differ")
    current = source_map()
    require(current == tested, "current complete compiler-input map differs")
    (OUT / "bindings/source-map-current.json").write_bytes(encoded(current))
    require(set(q["binaries"]) == RELEASE_NAMES, "three release artifacts are required")
    for name, row in q["binaries"].items():
        require(row["path"] == str(QUAL / name)
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
                "release artifact location or digest differs")
        bind(row["path"], row["sha256"])
    path = QUAL / "retained-artifacts.jsonl"
    raw = path.read_bytes()
    with (OUT / "bindings/retained-artifacts.jsonl").open("xb") as stream:
        stream.write(raw)
    bind(path, hashlib.sha256(raw).hexdigest())
    selected = []
    for line in raw.splitlines():
        item = json.loads(line)
        target = item.get("target", {})
        if (item.get("reason") == "compiler-artifact" and item.get("profile", {}).get("test")
                and target.get("name") == "hepta_runtime" and "lib" in target.get("kind", [])
                and target.get("src_path") == str(SOURCE / "src/lib.rs")):
            selected.append(item)
    require(len(selected) == 1 and selected[0].get("executable"),
            "retained Cargo events do not identify one qualified library test binary")
    libtest = Path(selected[0]["executable"])
    require(libtest.parent == QUAL / "test-binaries" and libtest.resolve() == libtest,
            "libtest is not the preserved qualification copy")
    isolated = snapshot_json(QUAL / "isolated-tests/summary.json", "isolated-summary.json")
    require(isolated.get("passed", 0) > 0 and isolated.get("failed") == 0
            and isolated.get("retries") == 0 and not isolated.get("enumeration_errors"),
            "isolated qualification summary is not successful with zero retries")
    entries = [row for row in isolated["binaries"] if row.get("path") == str(libtest)]
    require(len(entries) == 1 and re.fullmatch(r"[0-9a-f]{64}", entries[0]["sha256"]),
            "isolated qualification does not bind one libtest digest")
    lib = bind(libtest, entries[0]["sha256"])
    baselines = {}
    for name, (directory, digest) in BASELINES.items():
        baseline = snapshot_json(directory / "report.json", name + "-qualification.json")
        require(baseline.get("qualified") is True and baseline.get("finished_utc"),
                "baseline qualification is not terminal and qualified")
        row = baseline["binaries"]["hepta-runtime"]
        require(row["path"] == str(directory / "hepta-runtime") and row["sha256"] == digest,
                "baseline differs from the retained R11/R12 identity")
        baselines[name] = bind(row["path"], digest)
    bind(Path(__file__).resolve(), REPORT["driver_sha256"])
    for directory in (HERE, OLD_TOOLS, R12 / "source/tools/x230/20261028"):
        for path in sorted(directory.glob("*.py")):
            bind(path)
    fixtures = snapshot_json(HERE / "fixtures/manifest.json", "projection-fixtures.json")
    require(fixtures["schema"] == "hepta-operation-projection-fixtures/v1"
            and [row["payload"] for row in fixtures["fixtures"]] == ["plain", "escaped"],
            "prepared fixture manifest differs")
    for row in fixtures["fixtures"]:
        path = HERE / "fixtures" / row["relative_path"]
        require(path.resolve().is_relative_to(HERE / "fixtures") and row["bytes"] == 4194272,
                "fixture location or size differs")
        bind(path, row["sha256"])
    prohibit_compile()
    REPORT["gate"] = {
        "passed": True, "utc": utc(), "source_files": len(current),
        "source_map_sha256": hashlib.sha256(encoded(current)).hexdigest(),
        "source_tested_after_current_equal": True, "release_binaries": q["binaries"],
        "libtest": lib, "libtest_cargo_target": selected[0]["target"],
        "libtest_hash_source": str(QUAL / "isolated-tests/summary.json"),
        "isolated_passed": isolated["passed"], "isolated_failed": isolated["failed"],
        "isolated_ignored": isolated["ignored"], "baselines": baselines}
    REPORT["bound_inputs"] = list(BOUND.values())
    save()
    event("qualification_gate_passed", source_files=len(current), libtest_sha256=lib["sha256"])
    return q, lib


def check_binding(tested):
    require(source_map() == tested, "compiler inputs changed after qualification gate")
    for row in list(BOUND.values()):
        require(identity(row["path"]) == row["identity"] and sha(row["path"]) == row["sha256"],
                "bound input changed after qualification gate: " + row["path"])
    prohibit_compile()


def run_stage(name, argv, timeout):
    row = {"name": name, "command": argv, "timeout_seconds": timeout,
           "started_utc": utc(), "returncode": None, "automatic_retries": 0,
           "environment_before": telemetry()}
    REPORT["stages"].append(row)
    REPORT["current_stage"] = name
    save()
    event("stage_started", stage=name)
    start, process, original = time.monotonic(), None, None
    stdout_path, stderr_path = OUT / "logs" / (name + ".stdout"), OUT / "logs" / (name + ".stderr")
    try:
        prohibit_compile()
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(argv, cwd=ROOT, env=ENV, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            original = proc_info(process.pid)
            row["original_process"] = original
            save()
            row["returncode"] = process.wait(timeout=timeout)
        require(row["returncode"] == 0, name + " failed; original logs retained")
    except BaseException as error:
        row["error"] = {"type": type(error).__name__, "reason": str(error)[:2000]}
        if process is not None and process.poll() is None:
            row["owned_cleanup"] = stop_owned_tree(process, original)
            row["returncode"] = process.poll()
        raise
    finally:
        row["seconds"], row["finished_utc"] = time.monotonic() - start, utc()
        for field, path in (("stdout", stdout_path), ("stderr", stderr_path)):
            if path.exists():
                row[field] = {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}
        row["environment_after"] = telemetry()
        save()
        event("stage_finished", stage=name, returncode=row["returncode"])


def validate_projection(path):
    summary = json.loads(path.read_bytes())
    require(summary.get("verified") is True and summary.get("measurement_processes") == 16
            and summary.get("successful_calls") == 640, "projection independent summary differs")


def validate_cancel(path):
    summary = json.loads(path.read_bytes())
    require(summary.get("rpc_responses_and_statistical_fields_validated") is True
            and summary.get("controller_generations") == 16
            and summary["counts"]["measured"] == 3456 and summary["counts"]["warmup"] == 288
            and {(row["workers"], row["receipt_bytes"]) for row in summary["cases"]}
            == {(1, 1024), (1, 4194272), (2, 1024), (2, 4194272)},
            "cancel independent summary differs")


def main():
    os.umask(0o077)
    started = time.monotonic()
    OUT.mkdir(mode=0o700)
    (OUT / "logs").mkdir(mode=0o700)
    (OUT / "bindings").mkdir(mode=0o700)
    REPORT.update({
        "schema": "hepta-r13-local-campaigns/v1", "success": False, "state": "waiting",
        "started_utc": utc(), "driver_sha256": sha(Path(__file__).resolve()),
        "qualification_wait_limit_seconds": WAIT_SECONDS,
        "campaign_timeout_seconds": CAMPAIGN_TIMEOUT, "analyzer_timeout_seconds": ANALYZER_TIMEOUT,
        "automatic_retries": 0, "remote_operations": 0, "production_service_changes": False,
        "compilation_started": False, "qualification": str(QUAL / "report.json"),
        "campaign_directories": {name: str(path) for name, path in CAMPAIGNS.items()},
        "stages": [], "environment_before": telemetry(),
        "resource_observation_limit": "before/after host snapshots; command names only; no causal attribution"})
    save()
    try:
        require(all(not path.exists() for path in CAMPAIGNS.values()),
                "campaign output already exists; no reuse or retry permitted")
        wait_for_qualification(started)
        qualification, libtest = establish_binding()
        REPORT["state"] = "running"
        save()
        projection = CAMPAIGNS["projection"]
        check_binding(qualification["source_tested"])
        run_stage("projection-campaign", [
            "/usr/bin/python3", "-B", str(HERE / "run_operation_projection_abba.py"),
            "--fixtures", str(HERE / "fixtures"), "--binary", libtest["path"],
            "--binary-sha256", libtest["sha256"], "--out", str(projection),
            "--pins", "8", "32", "--rounds", "2"], CAMPAIGN_TIMEOUT)
        run_stage("projection-analysis", [
            "/usr/bin/python3", "-B", str(HERE / "analyze_operation_projection.py"),
            "--report", str(projection / "report.json"),
            "--output", str(projection / "independent-summary.json")], ANALYZER_TIMEOUT)
        validate_projection(projection / "independent-summary.json")
        check_binding(qualification["source_tested"])
        for baseline in ("r12", "r11"):
            name = "cancel_" + baseline + "_r13"
            directory = CAMPAIGNS[name]
            check_binding(qualification["source_tested"])
            run_stage(name + "-campaign", [
                "/usr/bin/python3", "-B", str(OLD_TOOLS / "run_cancel_responsiveness.py"),
                "--baseline", str(BASELINES[baseline][0] / "hepta-runtime"),
                "--candidate", str(QUAL / "hepta-runtime"), "--out", str(directory),
                "--workers", "1", "2", "--receipt-bytes", "1024", "4194272",
                "--payload", "escaped", "--concurrency", "8", "--waves", "24"], CAMPAIGN_TIMEOUT)
            run_stage(name + "-analysis", [
                "/usr/bin/python3", "-B", str(OLD_TOOLS / "analyze_cancel_responsiveness.py"),
                str(directory / "report.json"), "--summary",
                str(directory / "independent-summary.json"), "--markdown",
                str(directory / "independent-summary.md")], ANALYZER_TIMEOUT)
            validate_cancel(directory / "independent-summary.json")
            check_binding(qualification["source_tested"])
        REPORT["success"], REPORT["state"] = True, "passed"
    except BaseException as error:
        REPORT["success"], REPORT["state"] = False, "failed"
        REPORT["error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
        event("pipeline_stopped", error_type=type(error).__name__, reason=str(error)[:3000])
    finally:
        REPORT["environment_after"] = telemetry()
        REPORT["finished_utc"], REPORT["seconds"] = utc(), time.monotonic() - started
        REPORT["retained_result_files"] = []
        for directory in CAMPAIGNS.values():
            if directory.exists():
                for name in ("report.json", "independent-summary.json", "independent-summary.md"):
                    path = directory / name
                    if path.is_file():
                        REPORT["retained_result_files"].append(
                            {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)})
        save()
        event("pipeline_finished", success=REPORT["success"], report=str(OUT / "report.json"))
    return 0 if REPORT["success"] else 1


def interrupted(signum, unused_frame):
    raise InterruptedError("local pipeline received signal " + str(signum))


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    sys.exit(main())
