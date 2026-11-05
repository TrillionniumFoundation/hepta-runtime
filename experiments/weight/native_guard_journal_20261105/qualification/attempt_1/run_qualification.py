#!/usr/bin/env python3
"""Record one isolated journal compilation/test attempt; preserve failure."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile
import time

SOURCE_FILES = [
    "src/mcp/mod.rs", "src/mcp/server.rs", "src/mcp/weight_guard.rs",
    "src/mcp/weight_guard_journal.rs", "src/mcp/weight_guard_journal_tests.rs",
    "src/mcp/weight_norm.rs", "src/mcp/weight_forward.rs", "src/mcp/weight_tensor.rs",
    "src/mcp/weight_artifact.rs", "src/mcp/weight_config.rs", "src/mcp/rea_files.rs",
    "src/mcp/rea_model.rs", "src/mcp/rea_evidence.rs", "Cargo.toml", "Cargo.lock",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ["root", "target", "output", "protocol"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    temporary = tempfile.TemporaryDirectory(prefix="wgj-", dir="/tmp")
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(args.target.resolve()), CARGO_BUILD_JOBS="2",
               TMPDIR=temporary.name, RUST_BACKTRACE="1")
    cargo = str(Path.home() / ".cargo/bin/cargo")
    commands = [
        [cargo, "fmt", "--all"],
        [cargo, "test", "--locked", "--offline", "--all-features", "--lib", "weight_guard_journal", "--", "--test-threads=1", "--nocapture"],
        [cargo, "clippy", "--locked", "--offline", "--all-features", "--all-targets", "--", "-D", "warnings"],
        [cargo, "fmt", "--all", "--", "--check"],
    ]

    def sources():
        return [{"path":name, "bytes":(root/name).stat().st_size, "sha256":sha(root/name)} for name in SOURCE_FILES]

    receipt = {
        "schema":"hepta.native-guard-journal-local-qualification.v1", "attempt":args.attempt,
        "started_utc":datetime.now(timezone.utc).isoformat(), "source_before_format":sources(),
        "protocol_sha256":sha(args.protocol), "driver_sha256":sha(Path(__file__)),
        "base_tree":subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"],cwd=root,text=True).strip(),
        "rustc":subprocess.check_output([str(Path.home()/".cargo/bin/rustc"),"--version"],text=True).strip(),
        "cargo":subprocess.check_output([cargo,"--version"],text=True).strip(),
        "commands":[], "complete":False, "passed":False, "cargo_jobs":2, "test_threads":1,
        "per_command_timeout_seconds":1200, "address_space_limit_bytes":8*1024**3,
        "nofile_limit":1024, "gpu_used":False,
        "scope":"Focused journal software/process-crash qualification, not full repository suite, power loss, model quality, or production activation",
    }

    def save():
        (output/"qualification.json").write_text(json.dumps(receipt,indent=2,sort_keys=True,allow_nan=False)+"\n")

    def limits():
        for kind,cap in [(resource.RLIMIT_AS,8*1024**3),(resource.RLIMIT_NOFILE,1024)]:
            _, hard = resource.getrlimit(kind)
            value = cap if hard == resource.RLIM_INFINITY else min(cap,hard)
            resource.setrlimit(kind,(value,value))

    total_start, supervisor_cpu = time.perf_counter(), time.process_time()
    save()
    for index, command in enumerate(commands):
        log = output / f"command-{index+1}.log"
        before, start = resource.getrusage(resource.RUSAGE_CHILDREN), time.perf_counter()
        timed_out = False
        with log.open("xb") as stream:
            process = subprocess.Popen(command, cwd=root,env=env,stdout=stream,stderr=subprocess.STDOUT,
                                       start_new_session=True,preexec_fn=limits)
            try:
                code = process.wait(timeout=1200)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid,signal.SIGTERM)
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL)
                    code = process.wait()
        after=resource.getrusage(resource.RUSAGE_CHILDREN)
        receipt["commands"].append({"command":["cargo"]+command[1:],"exit_code":code,"timed_out":timed_out,
            "wall_seconds":time.perf_counter()-start,"child_user_cpu_seconds":after.ru_utime-before.ru_utime,
            "child_system_cpu_seconds":after.ru_stime-before.ru_stime,
            "cumulative_child_max_rss_kib_not_additive":after.ru_maxrss,
            "log_bytes":log.stat().st_size,"log_sha256":sha(log)})
        receipt["source_after_last_command"]=sources()
        if index == 0 and code == 0:
            receipt["source_after_format"] = receipt["source_after_last_command"]
        save()
        print(json.dumps({"command_index":index+1,"exit_code":code,"wall_seconds":receipt["commands"][-1]["wall_seconds"]}),flush=True)
        if code != 0: break
    receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
    receipt["total_wall_seconds"] = time.perf_counter()-total_start
    receipt["supervisor_cpu_seconds"] = time.process_time()-supervisor_cpu
    receipt["child_cpu_seconds"] = sum(c["child_user_cpu_seconds"]+c["child_system_cpu_seconds"] for c in receipt["commands"])
    receipt["complete"] = len(receipt["commands"])==len(commands)
    receipt["passed"] = receipt["complete"] and all(c["exit_code"]==0 for c in receipt["commands"])
    receipt["source_stable_after_format"] = receipt["source_after_last_command"] == receipt.get("source_after_format")
    save()
    print(json.dumps({"status":"PASS" if receipt["passed"] else "FAILED_PRESERVED", "attempt":args.attempt,
        "receipt_sha256":sha(output/"qualification.json"),"total_wall_seconds":receipt["total_wall_seconds"],
        "child_cpu_seconds":receipt["child_cpu_seconds"],"supervisor_cpu_seconds":receipt["supervisor_cpu_seconds"]}),flush=True)
    temporary.cleanup()
    return 0 if receipt["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
