#!/usr/bin/env python3
"""Run explicit commands once against frozen source/test inputs; retain every result."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()

def digest_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def inventory(root):
    raw = subprocess.check_output(["/usr/bin/git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root)
    rows = {"source": [], "verification": []}
    for path in sorted(set(raw.decode().split("\0")) - {""}):
        group = None
        if path.startswith(("src/", "examples/", ".cargo/")) or path in ("Cargo.toml", "Cargo.lock", "build.rs", "rustfmt.toml"):
            group = "source"
        elif path.startswith(("tests/", "scripts/", ".github/")) or (path.endswith(".py") and path.startswith(("deploy/", "tools/x230/", "workers/"))):
            group = "verification"
        if group:
            p = root / path
            if p.is_symlink() or not p.is_file():
                raise RuntimeError("non-regular build/verification input: " + path)
            rows[group].append({"path": path, "bytes": p.stat().st_size, "sha256": digest_file(p)})
    return {name: {"files": files, "count": len(files), "sha256": digest_json(files)} for name, files in rows.items()}

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)

plan = json.load(sys.stdin)
root = Path(plan["root"])
evidence = Path(plan["evidence"])
assert root.is_absolute() and evidence.is_absolute()
evidence.mkdir(mode=0o700)
os.umask(0o022)
env = os.environ.copy()
env.update(plan.get("env", {}))
write_json(evidence / "plan.json", plan)
before = inventory(root)
write_json(evidence / "inputs-before.json", before)
summary = {
    "schema": "hepta.rea.frozen-command-qualification.v1",
    "root": str(root),
    "baseline_commit": subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
    "runner_sha256": digest_file(Path(__file__)),
    "started_unix_ms": int(time.time() * 1000),
    "retry_count": 0,
    "child_umask": "0022",
    "commands": [],
    "qualified": False,
}
error = None
try:
    for index, command in enumerate(plan["commands"]):
        name = command["name"]
        argv = command["argv"]
        log = evidence / (f"{index:02d}-" + name + ".log")
        print(json.dumps({"event": "command_started", "name": name, "argv": argv, "log": str(log)}), flush=True)
        started = time.monotonic()
        with log.open("xb") as output:
            result = subprocess.run(argv, cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT, check=False)
        log.chmod(0o600)
        record = {"name": name, "argv": argv, "exit_code": result.returncode,
                  "expected_exit_code": command.get("expected_exit_code", 0),
                  "elapsed_seconds": round(time.monotonic() - started, 3),
                  "log": str(log), "log_sha256": digest_file(log),
                  "log_bytes": log.stat().st_size}
        summary["commands"].append(record)
        write_json(evidence / "progress.json", summary)
        print(json.dumps({"event": "command_finished", **record}), flush=True)
        if result.returncode != record["expected_exit_code"]:
            raise RuntimeError("command failed: " + name)
    if plan.get("freeze_binary"):
        original = Path(plan["freeze_binary"])
        frozen = evidence / "hepta-runtime-qualified"
        with original.open("rb") as src, frozen.open("xb") as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        frozen.chmod(0o700)
        summary["binary"] = {"build_path": str(original), "frozen_path": str(frozen),
                             "bytes": frozen.stat().st_size, "sha256": digest_file(frozen)}
        if summary["binary"]["sha256"] != digest_file(original):
            raise RuntimeError("binary changed while freezing")
except BaseException as caught:
    error = str(caught)
finally:
    after = inventory(root)
    write_json(evidence / "inputs-after.json", after)
    summary["inputs"] = {name: {"count": before[name]["count"], "sha256": before[name]["sha256"],
                               "after_sha256": after[name]["sha256"],
                               "unchanged": before[name] == after[name]}
                         for name in before}
    summary["source_and_verification_unchanged"] = before == after
    summary["finished_unix_ms"] = int(time.time() * 1000)
    summary["error"] = error
    summary["qualified"] = error is None and before == after and len(summary["commands"]) == len(plan["commands"])
    write_json(evidence / "qualification.json", summary)
    print(json.dumps({"event": "qualification_finished", "qualified": summary["qualified"],
                      "inputs": summary["inputs"], "binary": summary.get("binary"), "error": error}), flush=True)
sys.exit(0 if summary["qualified"] else 1)
