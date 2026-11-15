#!/usr/bin/env python3
"""Fail-closed local qualification receipts for Hepta source trees.

No fetch/checkout/merge/deploy, no source edits, and no authority delegation.
The tool reports test observations; it does not grant production GO.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
from typing import Any


RUST_RUNTIME_VERSION = re.compile(r"^rustc 1\.95\.0(?:\s|$)")
MAX_LOG_TAIL_BYTES = 8192


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def run_limited(argv: list[str], cwd: Path, timeout: int, log: Path) -> dict[str, Any]:
    log.parent.mkdir(parents=True, exist_ok=True)
    begun = utc_now()
    start = time.monotonic()
    result: dict[str, Any] = {"command": argv, "start_utc": begun}
    try:
        with log.open("wb") as output:
            completed = subprocess.run(
                argv,
                cwd=str(cwd),
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
                env=dict(os.environ, CARGO_TERM_COLOR="never"),
            )
        result["status"] = "PASS" if completed.returncode == 0 else "FAIL"
        result["returncode"] = completed.returncode
    except FileNotFoundError:
        log.write_text("Executable not installed or not in PATH.\n", encoding="utf-8")
        result["status"] = "BLOCKED"
        result["reason"] = "executable_missing"
    except subprocess.TimeoutExpired:
        result["status"] = "TIMEOUT"
        result["reason"] = "time_limit_exceeded"
        result["timeout_seconds"] = timeout
    except OSError as exc:
        log.write_text(f"OS error: {type(exc).__name__}: {exc}\n", encoding="utf-8")
        result["status"] = "BLOCKED"
        result["reason"] = "os_error"
    result["duration_seconds"] = round(time.monotonic() - start, 3)
    result["end_utc"] = utc_now()
    result["log"] = str(log)
    result["log_bytes"] = log.stat().st_size
    result["log_sha256"] = sha256_file(log)
    with log.open("rb") as stream:
        stream.seek(max(0, result["log_bytes"] - MAX_LOG_TAIL_BYTES))
        result["log_tail"] = stream.read().decode("utf-8", errors="replace")
    return result


def read_short(argv: list[str], cwd: Path, timeout: int = 20) -> tuple[bool, str]:
    try:
        p = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode == 0, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False, ""


def trustworthy_path(repo_paths: list[Path]) -> tuple[bool, str]:
    """Deny relative/source-controlled executable search directories before any spawn."""
    value = os.environ.get("PATH", "")
    if not value:
        return False, "missing_PATH"
    roots = [root.expanduser().resolve() for root in repo_paths]
    for item in value.split(os.pathsep):
        directory = Path(item)
        if not directory.is_absolute():
            return False, "relative_or_empty_PATH_component"
        resolved = directory.resolve()
        if not directory.is_dir() or any(resolved == root or root in resolved.parents for root in roots):
            return False, "untrusted_or_missing_PATH_directory"
    return True, "trusted_absolute_PATH"


def git_info(repo: Path, expect: str | None = None) -> dict[str, Any]:
    info: dict[str, Any] = {"path": str(repo.resolve()), "status": "BLOCKED"}
    if not repo.is_dir():
        info["reason"] = "repository_directory_missing"
        return info
    git = shutil.which("git")
    if not git:
        info["reason"] = "git_missing"
        return info
    safe_git = [git, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
    ok_root, root = read_short(safe_git + ["rev-parse", "--show-toplevel"], repo)
    if not ok_root or Path(root).resolve() != repo.resolve():
        info["reason"] = "not_exact_git_root"
        return info
    ok_sha, head = read_short(safe_git + ["rev-parse", "--verify", "HEAD^{commit}"], repo)
    ok_state, changed = read_short(safe_git + ["status", "--porcelain=v1", "--untracked-files=normal"], repo)
    if not ok_sha or not ok_state:
        info["reason"] = "git_revision_or_status_unavailable"
        return info
    info.update({"head_sha": head, "clean": not bool(changed),
                 "dirty_paths_count": len(changed.splitlines()) if changed else 0,
                 "status": "PASS"})
    lock = repo / "Cargo.lock"
    if lock.is_file():
        info["cargo_lock_sha256"] = sha256_file(lock)
    if expect and head != expect:
        info.update({"status": "BLOCKED", "reason": "unexpected_head_sha", "expected_sha": expect})
    if changed:
        info.update({"status": "BLOCKED", "reason": "dirty_worktree"})
    return info


def tool_versions(repo: Path) -> dict[str, Any]:
    versions = {}
    for name, argv in {
        "rustc": ["rustc", "--version"],
        "cargo": ["cargo", "--version"],
        "just": ["just", "--version"],
        "bazel": ["bazel", "--version"],
        "python3": ["python3", "--version"],
    }.items():
        present, version = read_short(argv, repo)
        versions[name] = {"present": present, "version": version or None}
    return versions


def commands_for(project: str, full: bool, include_bazel: bool) -> list[tuple[str, list[str], int]]:
    if project == "runtime":
        return [
            ("rust-format", ["cargo", "fmt", "--all", "--", "--check"], 300),
            ("rust-check", ["cargo", "check", "--locked", "--all-targets"], 3600),
            ("rust-clippy", ["cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings"], 3600),
            ("rust-tests", ["cargo", "test", "--locked", "--all-targets"], 5400),
            ("rust-release", ["cargo", "build", "--locked", "--release"], 5400),
        ]
    if full:
        cmds = [
            ("fmt-check", ["just", "fmt-check"], 1200),
            ("rust-workspace-check", ["cargo", "check", "--locked", "--workspace", "--all-targets"], 7200),
            ("rust-workspace-clippy", ["cargo", "clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"], 7200),
            ("rust-workspace-tests", ["just", "test"], 10800),
            ("rust-workspace-release", ["cargo", "build", "--locked", "--release", "--workspace"], 10800),
        ]
        if include_bazel:
            cmds.append(("bazel-repo-tests", ["bazel", "test", "//..."], 14400))
        return cmds
    return [
        ("fmt-check", ["just", "fmt-check"], 1200),
        ("neuron-tests", ["cargo", "test", "--locked", "-p", "codex-hepta-neuron"], 3600),
        ("plasticity-tests", ["cargo", "test", "--locked", "-p", "codex-hepta-plasticity"], 3600),
        ("codex-adapter-tests", ["cargo", "test", "--locked", "-p", "codex-hepta-codex-adapter"], 3600),
    ]


def qualify_project(project: str, path: Path, report_dir: Path, *, full: bool,
                    include_bazel: bool, check_only: bool, expected_sha: str | None) -> dict[str, Any]:
    info = git_info(path, expected_sha)
    outcome: dict[str, Any] = {"project": project, "source": info, "checks": []}
    if info["status"] != "PASS":
        outcome.update({"qualification": "BLOCKED", "reason": info.get("reason")})
        return outcome
    workdir = path if project == "runtime" else path / "codex-rs"
    if not workdir.is_dir():
        outcome.update({"qualification": "BLOCKED", "reason": "missing_rust_workspace"})
        return outcome
    versions = tool_versions(workdir)
    outcome["tool_versions"] = versions
    if not RUST_RUNTIME_VERSION.search(versions["rustc"]["version"] or ""):
        outcome.update({"qualification": "BLOCKED", "reason": "requires_rustc_1_95_0"})
        return outcome
    for name, argv, timeout in commands_for(project, full, include_bazel):
        cmd = {"name": name, "command": argv}
        if not shutil.which(argv[0]):
            cmd.update({"status": "BLOCKED", "reason": f"missing_{argv[0]}"})
        elif check_only:
            cmd.update({"status": "NOT_RUN", "reason": "check_only"})
        else:
            cmd.update(run_limited(argv, workdir, timeout, report_dir / f"{project}-{name}.log"))
        outcome["checks"].append(cmd)
    # A test that changed a tracked/untracked source tree or advanced HEAD did not
    # validate the originally recorded immutable bytes.
    outcome["final_source"] = git_info(path, info["head_sha"])
    if check_only:
        outcome["qualification"] = "NOT_RUN"
    elif any(item["status"] != "PASS" for item in outcome["checks"]):
        outcome["qualification"] = "BLOCKED"
    elif outcome["final_source"]["status"] != "PASS":
        outcome["qualification"] = "BLOCKED"
        outcome["reason"] = "source_changed_during_qualification"
    else:
        # Passing build/test checks alone is NEVER a release/FinalUse decision.
        outcome["qualification"] = "LOCAL_TESTS_PASS_ONLY"
    return outcome


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, help="Existing hepta-private-ci Git checkout root")
    parser.add_argument("--runtime", type=Path, help="Existing hepta-runtime Git checkout root")
    parser.add_argument("--scope", choices=("focused", "full"), default="full")
    parser.add_argument("--bazel", action="store_true", help="Also run entire Hepta Bazel test graph (very expensive)")
    parser.add_argument("--check-only", action="store_true", help="Only inspect source identity/toolchains; do not build or test")
    parser.add_argument("--expect-hepta-sha", help="Fail closed unless local Hepta HEAD equals this SHA")
    parser.add_argument("--expect-runtime-sha", help="Fail closed unless local Runtime HEAD equals this SHA")
    parser.add_argument("--output", type=Path, help="Directory for logs and machine-readable report")
    args = parser.parse_args(argv)
    if args.hepta is None and args.runtime is None:
        parser.error("At least one of --hepta or --runtime is required")
    if args.bazel and args.scope != "full":
        parser.error("--bazel requires --scope full")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = (args.output or Path.home() / "hepta-local-qualification" / timestamp).expanduser().resolve()
    repo_paths = [p for p in (args.hepta, args.runtime) if p is not None]
    for p in repo_paths:
        root = p.expanduser().resolve()
        if out == root or root in out.parents:
            parser.error("--output must be outside every source repository")
    out.mkdir(parents=True, exist_ok=False)
    trusted, path_reason = trustworthy_path(repo_paths)
    report: dict[str, Any] = {
        "schema": "hepta.local_qualification.v1",
        "created_utc": utc_now(),
        "host_os": platform.system(),
        "architecture": platform.machine(),
        "scope": args.scope,
        "authority": "EVIDENCE_ONLY; NO_PRODUCTION_GO; NO_FINAL_USE; NO_MERGE",
        "projects": [],
        "PATH_guard": {"passed": trusted, "reason": path_reason},
    }
    if not trusted:
        for name, p in (("hepta", args.hepta), ("runtime", args.runtime)):
            if p is not None:
                report["projects"].append({"project": name, "qualification": "BLOCKED", "reason": path_reason})
    if trusted and args.hepta is not None:
        report["projects"].append(qualify_project("hepta", args.hepta, out, full=args.scope == "full",
                                                 include_bazel=args.bazel, check_only=args.check_only,
                                                 expected_sha=args.expect_hepta_sha))
    if trusted and args.runtime is not None:
        report["projects"].append(qualify_project("runtime", args.runtime, out, full=args.scope == "full",
                                                 include_bazel=False, check_only=args.check_only,
                                                 expected_sha=args.expect_runtime_sha))
    ok = all(item["qualification"] == "LOCAL_TESTS_PASS_ONLY" for item in report["projects"])
    report["summary"] = "LOCAL_TESTS_PASS_ONLY" if ok else "BLOCKED_OR_UNVERIFIED"
    report["completed_utc"] = utc_now()
    report_path = out / "qualification.json"
    # Atomic publication of a non-authorizing diagnostic receipt.
    tmp = out / ".qualification.json.tmp"
    with tmp.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, report_path)
    print(f"Report: {report_path}")
    for item in report["projects"]:
        print(f"{item['project']}: {item['qualification']} ({item.get('reason', 'see checks')})")
        for step in item.get("checks", []):
            print(f"  {step['name']}: {step['status']}")
    print(f"Verdict: {report['summary']} — never a production authorization")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
