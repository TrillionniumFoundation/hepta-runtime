#!/usr/bin/env python3
"""One original, source-bound external Rust CI attempt after qualification01."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r31")
OUT = ROOT / "rust-ci-01"
ACTIVE_CLEANUP = False
INTERRUPTS = []


def need(value, message):
    if not value:
        raise RuntimeError(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_module(name, filename, expected):
    path = Path(__file__).absolute().with_name(filename)
    need(path.resolve(strict=True) == path and digest(path) == expected, "reviewed executor dependency differs")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, {"path": str(path), "bytes": path.stat().st_size, "sha256": expected}


def process_identity(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    end = raw.rfind(") ")
    fields = raw[end + 2:].split()
    need(end > 0 and len(fields) >= 20 and int(raw.split("(", 1)[0]) == pid, "malformed original child identity")
    return {"pid": pid, "start_ticks": int(fields[19]), "process_group": int(fields[2])}


def group_present(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def interrupted(number, frame):
    INTERRUPTS.append({"signal": signal.Signals(number).name, "utc": utc()})
    if not ACTIVE_CLEANUP:
        raise InterruptedError("original Rust CI parent interrupted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--materializer-sha256", required=True)
    parser.add_argument("--auditor-sha256", required=True)
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0, "native nonroot Linux executor required")
    need(process_identity(os.getpid()) is not None, "native /proc identity required")
    materializer, materializer_identity = load_module("bound_rust_ci_materializer", "materialize_rust_ci_plan_01.py", args.materializer_sha256)
    materializer.require_frozen_qualification()
    auditor, auditor_identity = load_module("bound_nextest_auditor", "audit_nextest_0137.py", args.auditor_sha256)
    plan_identity, raw = materializer.read_file(args.plan, retain=True)
    need(plan_identity["sha256"] == args.plan_sha256 and args.plan.is_relative_to(ROOT), "materialized plan identity differs")
    plan = json.loads(raw)
    need(plan["schema"] == "hepta-r31-materialized-exact-rust-ci-plan/v1" and plan["attempt"] == "01"
         and plan["executed"] is False and plan["qualification_job_id"] == materializer.JOB_ID,
         "plan does not bind the original qualification01")
    need(plan["source"] == str(materializer.SOURCE)
         and [{k: row[k] for k in ("workflow_step", "argv")} for row in plan["commands"]] == materializer.COMMANDS
         and all(row["cwd"] == str(materializer.SOURCE) for row in plan["commands"])
         and plan["inventory_command"]["argv"] == materializer.INVENTORY_COMMAND
         and plan["inventory_command"]["cwd"] == str(materializer.SOURCE), "workflow or inventory argv/cwd differ")
    need(plan["execution_contract"]["fresh_evidence_directory"] == str(OUT), "fresh output contract differs")
    need(plan["nextest_binary"] == materializer.NEXTEST_BINARY, "nextest pin differs")
    need(OUT.parent.resolve(strict=True) == ROOT and not os.path.lexists(OUT), "existing Rust CI attempt must not be replayed")
    os.umask(0o077)
    OUT.mkdir(mode=0o700)
    (OUT / "plan.json").write_bytes(raw)
    report_path = OUT / "report.json"
    report = {"schema": "hepta-r31-external-rust-ci/v1", "attempt": "01", "passed": False,
        "started_utc": utc(), "finished_utc": None, "original_qualification_job_id": materializer.JOB_ID,
        "plan": plan_identity, "materializer": materializer_identity, "auditor": auditor_identity,
        "launcher": materializer.read_file(Path(__file__).absolute())[0], "stages": [],
        "automatic_retries": 0, "production_services_modified": False, "hosted_actions_passed": False,
        "source_inputs_unchanged": False, "owned_children_closed": False, "interrupts": INTERRUPTS}
    deadline = time.monotonic() + 6600
    binaries_from_listing = []
    env = dict(os.environ)
    removed_names = []
    for key in list(env):
        if key.startswith(tuple(plan["remove_environment_prefixes"])) or key in plan["remove_environment_keys"]:
            removed_names.append(key)
            del env[key]
    env.update(plan["environment"])
    report["explicit_environment"] = plan["environment"]
    report["removed_environment_names"] = sorted(removed_names)
    report["home_unchanged"] = env.get("HOME") == os.environ.get("HOME")
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)

    def checkpoint():
        temporary = OUT / "report.next"
        with temporary.open("w") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, report_path)

    def unchanged():
        need(materializer.read_file(args.plan)[0] == plan_identity, "plan changed")
        for expected in plan["input_bindings"] + [materializer_identity, auditor_identity, report["launcher"]] + binaries_from_listing:
            need(materializer.read_file(Path(expected["path"]))[0] == expected, "bound input changed: " + expected["path"])
        files = [materializer.SOURCE / name for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
        for directory in ("src", "examples"):
            files.extend(path for path in (materializer.SOURCE / directory).rglob("*") if path.is_file())
        actual = {path.relative_to(materializer.SOURCE).as_posix(): digest(path) for path in sorted(files)}
        need(actual == plan["source_files"], "compiler source tree changed or gained a file")
        harness = {path.name: digest(path) for path in sorted((materializer.SOURCE / "tools/x230/20261028").glob("*.py"))}
        need(harness == plan["qualification_harness"], "qualification harness inventory changed")
        for row in plan["tool_configuration_inventory"]:
            need(os.path.lexists(row["path"]) is row["exists"], "tool configuration presence changed")
        report["last_inputs_verified_utc"] = utc()

    def run_stage(name, argv, timeout):
        global ACTIVE_CLEANUP
        unchanged()
        remaining = deadline - time.monotonic() - 160
        need(remaining > 0, "original Rust CI budget exhausted")
        row = {"name": name, "argv": argv, "cwd": str(materializer.SOURCE), "timeout_seconds": timeout,
            "effective_timeout_seconds": min(timeout, remaining), "started_utc": utc(),
            "returncode": None, "passed": False, "timed_out": False,
            "waited_and_reaped": False, "cleanup_signals": [], "cleanup_scope": "original owned process group only"}
        report["stages"].append(row)
        checkpoint()
        stdout_path, stderr_path = OUT / (name + ".stdout"), OUT / (name + ".stderr")
        child, birth, primary = None, None, None
        started = time.monotonic()
        print(json.dumps({"stage": name, "state": "started"}), flush=True)
        try:
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                child = subprocess.Popen(argv, cwd=materializer.SOURCE, env=env, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, start_new_session=True, umask=0o022)
                row["pid"] = child.pid
                birth = process_identity(child.pid)
                need(birth is not None and birth["process_group"] == child.pid, "original child identity unavailable")
                row["identity"] = birth
                checkpoint()
                row["returncode"] = child.wait(timeout=row["effective_timeout_seconds"])
                row["waited_and_reaped"] = True
                need(row["returncode"] == 0, name + " returned nonzero; original output retained")
        except BaseException as error:
            primary = error
            row["error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
            row["timed_out"] = isinstance(error, subprocess.TimeoutExpired)
        finally:
            ACTIVE_CLEANUP = True
            if child is not None:
                try:
                    if child.poll() is None:
                        for sig, seconds in ((signal.SIGINT, 120), (signal.SIGTERM, 10), (signal.SIGKILL, 10)):
                            need(birth is not None and process_identity(child.pid) == birth, "original child identity changed before cleanup")
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
                    need(row["owned_process_absent"] and row["owned_process_group_absent"], "owned process/group remains; no next stage")
                except BaseException as error:
                    row["cleanup_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
                    primary = primary or error
            row["finished_utc"] = utc()
            row["elapsed_seconds"] = time.monotonic() - started
            for key, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                if path.exists():
                    row[key] = materializer.read_file(path)[0]
            row["passed"] = primary is None and child is not None
            checkpoint()
            ACTIVE_CLEANUP = False
            print(json.dumps({"stage": name, "passed": row["passed"], "returncode": row["returncode"]}), flush=True)
        if primary is not None:
            raise primary
        unchanged()
        return row

    try:
        checkpoint()
        unchanged()
        _, terminal_raw = materializer.read_file(Path(plan["qualification_terminal_status"]["path"]), retain=True)
        materializer.verify_terminal(json.loads(terminal_raw))
        _, qualification_raw = materializer.read_file(Path(plan["qualification"]["path"]), retain=True)
        qualification = json.loads(qualification_raw)
        materializer.verify_qualification(qualification)
        _, preparation_raw = materializer.read_file(Path(plan["preparation"]["path"]), retain=True)
        materializer.verify_preparation(json.loads(preparation_raw), qualification, plan["qualification"], json.loads(terminal_raw))
        compiler_names = {"cargo", "rustc", "rust-lld", "ld.lld", "cc", "gcc", "clang", "clang++"}
        active = []
        for path in Path("/proc").glob("[0-9]*/comm"):
            try:
                if path.stat().st_uid == os.geteuid() and path.read_text().strip() in compiler_names:
                    active.append({"pid": int(path.parent.name), "name": path.read_text().strip()})
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        report["compiler_activity_before"] = active
        need(not active, "another compiler is active; no CI command was submitted")
        need(shutil.which("cargo-nextest", path=env["PATH"]) == materializer.NEXTEST_BINARY["path"], "cargo-nextest PATH differs")
        need(shutil.which("cargo", path=env["PATH"]) == "/home/qian/.cargo/bin/cargo", "cargo PATH differs")
        for name, argv, prefix in (
            ("cargo-version", ["cargo", "--version"], "cargo 1.95.0 "),
            ("rustc-version", ["rustc", "--version"], "rustc 1.95.0 "),
            ("nextest-version", ["cargo", "nextest", "--version"], "cargo-nextest 0.9.137 (75ddba7e9 2026-05-26)"),
        ):
            row = run_stage(name, argv, 30)
            need(Path(row["stdout"]["path"]).read_text().startswith(prefix), "actual tool version differs")
        run_stage("cargo-check", materializer.COMMANDS[0]["argv"], 1800)
        listing = run_stage("nextest-list", materializer.INVENTORY_COMMAND, 900)
        raw = Path(listing["stdout"]["path"]).read_bytes()
        listed = auditor.inventory(json.loads(raw), plan["expected_nextest"], materializer.SOURCE, ROOT / "target-build")
        for binary in listed["binary_paths"].values():
            actual, _ = materializer.read_file(Path(binary["path"]))
            need(all(actual[key] == binary["qualified"][key] for key in ("bytes", "sha256")), "nextest test executable differs from retained qualified binary")
            binaries_from_listing.append(actual)
        report["structured_inventory"] = {key: value for key, value in listed.items() if key != "runtime_cases"}
        report["structured_inventory"]["original_stdout"] = listing["stdout"]
        checkpoint()
        run = run_stage("nextest-run", materializer.COMMANDS[1]["argv"], 3600)
        raw = Path(run["stderr"]["path"]).read_bytes()
        result = auditor.run_output(raw, listed, plan["expected_nextest"])
        report["nextest_output_audit"] = result
        with (OUT / "nextest-output-audit.json").open("x") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
        unchanged()
        report["source_inputs_unchanged"] = True
        report["owned_children_closed"] = all(row["passed"] and row["waited_and_reaped"] and row["owned_process_absent"] and row["owned_process_group_absent"] for row in report["stages"])
        need(report["owned_children_closed"] and not INTERRUPTS, "original child ownership or interruption did not close")
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:4000]}
        report["traceback"] = traceback.format_exc()
    finally:
        report["finished_utc"] = utc()
        checkpoint()
        print(json.dumps({"passed": report["passed"], "report": materializer.read_file(report_path)[0],
                          "automatic_retries": 0, "hosted_actions_passed": False}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
