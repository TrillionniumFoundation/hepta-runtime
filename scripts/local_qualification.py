#!/usr/bin/env python3
"""Fail-closed local Rust evidence for an exact GitHub PR head AND merge.

This creates isolated detached worktrees and captures bounded execution logs.
A successful result is *local source/test evidence*, never FinalUse or a
production/host authorization. The two exact GitHub SHAs must be supplied by
the operator and both objects must already be present in the local repo.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

RUST_VERSION = "1.95.0"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
CHECKS = (
    ("source_contract", (sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_runtime_ci_contract.py", "-v")),
    ("local_receipt_regressions", (sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_local_qualification.py", "-v")),
    ("format", ("cargo", "fmt", "--all", "--", "--check")),
    ("check", ("cargo", "check", "--locked", "--all-targets")),
    ("clippy", ("cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings")),
    ("test", ("cargo", "test", "--locked", "--all-targets")),
    ("release", ("cargo", "build", "--locked", "--release")),
)


class QualificationError(Exception):
    pass


def git(repo: Path, *args: str) -> bytes:
    # Bypass Git object replacement and executable hooks for all own queries.
    p = subprocess.run(
        ("git", "-c", "core.hooksPath=/dev/null", *args),
        cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=safe_env(), check=False,
    )
    if p.returncode:
        raise QualificationError(f"git {args[0]} failed: {p.stderr.decode('utf-8', 'replace')[:500]}")
    return p.stdout


# The source SHA does not attest ambient hooks which alter *how* Cargo, Git,
# Python, the linker or the dynamic loader execute. Refuse their inherited names
# before launching Git or a build. Values must never appear in denial receipts.
_ALLOWED_EXECUTION_ENV = frozenset((
    "RUST_BACKTRACE", "RUST_LOG", "CARGO_TERM_COLOR", "PYTHONDONTWRITEBYTECODE",
    "PYTHONUNBUFFERED", "PYTHON_VERSION",
))
_BLOCKED_EXECUTION_ENV_EXACT = frozenset((
    "CC", "CXX", "LD", "AR", "RANLIB", "STRIP", "OBJCOPY", "OBJDUMP",
    "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "MAKEFLAGS",
    "CMAKE_PREFIX_PATH", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR",
    "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH",
    "NODE_OPTIONS",
))
_BLOCKED_EXECUTION_ENV_PREFIXES = (
    "GIT_", "RUST", "CARGO_", "LD_", "DYLD_", "PYTHON",
    "PKG_CONFIG_", "CMAKE_", "OPENSSL_", "LIBCLANG_",
    "BINDGEN_", "CC_", "CXX_",
)


def _blocked_execution_env_names() -> list[str]:
    return sorted(
        name for name in os.environ
        if name not in _ALLOWED_EXECUTION_ENV
        and (name in _BLOCKED_EXECUTION_ENV_EXACT
             or name.startswith(_BLOCKED_EXECUTION_ENV_PREFIXES))
    )


def safe_env() -> dict[str, str]:
    blocked = _blocked_execution_env_names()
    if blocked:
        names = ", ".join(name[:96] for name in blocked[:12])
        suffix = f" (+{len(blocked) - 12} more)" if len(blocked) > 12 else ""
        raise QualificationError("unreviewed execution environment keys: " + names + suffix)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and k not in (
        "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR", "RUSTUP_TOOLCHAIN",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_TARGET",
    )}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    # Global/system Git config can add unreviewed checkout filters.
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["RUSTUP_TOOLCHAIN"] = RUST_VERSION
    env["CARGO_INCREMENTAL"] = "0"
    return env


def blob_hash(data: bytes, algo: str) -> str:
    h = hashlib.new(algo)
    h.update(b"blob " + str(len(data)).encode() + b"\x00")
    h.update(data)
    return h.hexdigest()


def assert_github_merge_parentage(repo: Path, source_sha: str, merge_sha: str) -> None:
    """Reject unrelated/linear 'merge' evidence by checking raw commit parents.

    Read the content-addressed commit object, not rev-list: local graft and
    shallow metadata can alter displayed ancestry without changing the object.
    The caller must still obtain the genuine merge SHA from GitHub PR refs.
    """
    raw = git(repo, "cat-file", "commit", merge_sha)
    header, sep, _message = raw.partition(b"\n\n")
    if not sep:
        raise QualificationError("malformed GitHub merge commit object")
    parents = []
    for line in header.splitlines():
        if line.startswith(b"parent "):
            value = line[7:]
            if not re.fullmatch(rb"[0-9a-f]{40}", value):
                raise QualificationError("invalid parent in GitHub merge commit")
            parents.append(value.decode("ascii"))
    if len(parents) != 2 or parents[0] == source_sha or parents[1] != source_sha:
        raise QualificationError(
            "GitHub PR merge must have exactly two parents, with source HEAD as second parent"
        )


def check_source_bytes(worktree: Path) -> tuple[str, int]:
    """Require exact checked-out bytes for every Git index entry.

    Ignore/assume flags are rejected instead of trusting a clean porcelain
    status. Unlike git status, this does not invoke user-defined clean filters.
    """
    fmt = git(worktree, "rev-parse", "--show-object-format").decode().strip()
    if fmt not in ("sha1", "sha256"):
        raise QualificationError(f"unsupported Git object format: {fmt}")
    flags = git(worktree, "ls-files", "-v", "-z").split(b"\x00")
    for item in flags:
        if item and (item[:2] != b"H " or b"\n" in item[:2]):
            raise QualificationError("source index contains skip-worktree/assume-unchanged/unmerged flags")
    names = set()
    for item in git(worktree, "ls-files", "--stage", "-z").split(b"\x00"):
        if not item:
            continue
        try:
            metadata, relative = item.split(b"\t", 1)
            mode, expected, stage = metadata.decode("ascii").split(" ")
            path = worktree / os.fsdecode(relative)
            if stage != "0" or mode not in ("100644", "100755", "120000"):
                raise QualificationError(f"unexpected index stage or mode for {os.fsdecode(relative)}")
            if mode == "120000":
                if not path.is_symlink():
                    raise QualificationError(f"expected symlink: {os.fsdecode(relative)}")
                raw = os.fsencode(os.readlink(path))
            else:
                if not path.is_file() or path.is_symlink():
                    raise QualificationError(f"missing/nonregular checked-out source: {os.fsdecode(relative)}")
                raw = path.read_bytes()
                executable = bool(path.stat().st_mode & 0o111)
                if executable != (mode == "100755"):
                    raise QualificationError(f"source executable bit differs: {os.fsdecode(relative)}")
            if blob_hash(raw, fmt) != expected:
                raise QualificationError(f"source bytes differ from Git index: {os.fsdecode(relative)}")
            names.add(relative)
        except (OSError, ValueError) as exc:
            raise QualificationError(f"cannot attest index entry: {exc}") from exc
    if not names:
        raise QualificationError("source index is empty")
    # Unlike normal status, exclude-standard deliberately ignores generated
    # build products. No ignored file may substitute for a tracked source.
    untracked = git(worktree, "ls-files", "--others", "--exclude-standard", "-z")
    if untracked:
        raise QualificationError("untracked source files in qualification worktree")
    return fmt, len(names)



def assert_no_executable_checkout_config(repo: Path) -> None:
    """Reject executable checkout config before starting any Git worktree.

    Disabling Git hooks does not disable smudge/process filters or fsmonitor.
    Conditional includes can apply to a new linked worktree but not the root.
    """
    settings = git(repo, "config", "--list", "-z")
    for entry in settings.split(b"\0"):
        if not entry:
            continue
        raw_key, separator, value = entry.partition(b"\n")
        if not separator:
            raise QualificationError("malformed Git config entry")
        try:
            key = raw_key.decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise QualificationError("noncanonical Git config key") from exc
        if key == "core.hookspath":
            if value != b"/dev/null":
                raise QualificationError("unreviewed Git hooksPath config")
        elif key == "core.fsmonitor":
            if value.strip().lower() not in (b"false", b"0", b""):
                raise QualificationError("unreviewed Git fsmonitor command")
        elif (key.startswith("filter.")
              and (key.endswith(".smudge") or key.endswith(".process"))
              and value.strip()):
            raise QualificationError("unreviewed Git checkout filter command")
        elif key == "include.path" or (key.startswith("includeif.") and key.endswith(".path")):
            raise QualificationError("unreviewed Git included/conditional config")

def kill_tree(proc: subprocess.Popen) -> None:
    # The session leader may have exited while descendants still retain its
    # stdout/stderr pipe. Kill its process group even after leader exit.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def execute_bounded(args: tuple[str, ...], worktree: Path, env: dict[str, str],
                    log_path: Path, deadline: int, max_log: int) -> dict:
    """Bound log bytes, deadline and (POSIX) child process trees.

    Reads the pipe independently from the child: a full stdout pipe cannot
    deadlock a tool that is also waiting on input or a process exit.
    """
    start = time.monotonic()
    digest = hashlib.sha256()
    too_large = threading.Event()
    failures: list[str] = []
    written = [0]
    proc = None
    try:
        proc = subprocess.Popen(
            args, cwd=worktree, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
        )
        assert proc.stdout is not None
        with log_path.open("wb") as output:
            def reader() -> None:
                try:
                    while True:
                        chunk = proc.stdout.read(8192)
                        if not chunk:
                            return
                        available = max_log - written[0]
                        if len(chunk) > available:
                            if available:
                                output.write(chunk[:available]); digest.update(chunk[:available]); written[0] += available
                            too_large.set()
                            return
                        output.write(chunk); digest.update(chunk); written[0] += len(chunk)
                except OSError as exc:
                    failures.append(str(exc))

            t = threading.Thread(target=reader, name="bounded-capture", daemon=True)
            t.start()
            expired = False
            while proc.poll() is None:
                if too_large.is_set() or failures:
                    kill_tree(proc)
                    break
                if time.monotonic() - start > deadline:
                    expired = True
                    kill_tree(proc)
                    break
                time.sleep(0.025)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                kill_tree(proc)
                proc.wait(timeout=3)
            t.join(timeout=3)
            if t.is_alive():
                # A child may outlive its session leader and hold the pipe open.
                # Without group cleanup that process survives failed evidence.
                kill_tree(proc)
                t.join(timeout=3)
                failures.append(
                    "descendant held capture pipe" if not t.is_alive()
                    else "reader thread did not settle"
                )
            # A parent can return 0 and close stdout while a descendant
            # continues work with redirected stdio. EOF != group termination.
            # The launch's start_new_session=True isolates its process group.
            if not t.is_alive() and not too_large.is_set() and not expired and not failures:
                try:
                    os.killpg(proc.pid, 0)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    failures.append("cannot attest command process-group termination")
                else:
                    kill_tree(proc)
                    failures.append("process-group descendants remain after command exit")
            reason = "log_limit" if too_large.is_set() else "timeout" if expired else "io_error" if failures else "nonzero" if proc.returncode else "pass"
            return {"command": list(args), "outcome": reason, "exit_code": proc.returncode,
                    "duration_seconds": round(time.monotonic() - start, 3),
                    "log_bytes": written[0], "log_sha256": digest.hexdigest(),
                    "log": log_path.name}
    except OSError as exc:
        if proc is not None:
            kill_tree(proc)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        return {"command": list(args), "outcome": "not_started", "error": str(exc),
                "duration_seconds": round(time.monotonic() - start, 3), "log_bytes": written[0],
                "log_sha256": digest.hexdigest(), "log": log_path.name}
    finally:
        if proc is not None and proc.stdout is not None:
            proc.stdout.close()


def qualify(repo: Path, source_sha: str, merge_sha: str, output_dir: Path,
            timeout: int = 1800, max_log: int = 8 * 1024 * 1024) -> dict:
    receipt = {"schema": "HeptaLocalRuntimeQualificationV1", "status": "BLOCKED",
               "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
               "repo": str(repo.resolve()), "head_sha": source_sha, "github_merge_sha": merge_sha,
               "rust_toolchain": RUST_VERSION, "production_authority": False, "lanes": []}
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        if os.name != "posix":
            raise QualificationError("POSIX process-group isolation required; unsupported host")
        for sha in (source_sha, merge_sha):
            if not SHA_RE.fullmatch(sha):
                raise QualificationError("expected both exact 40-character lowercase Git SHAs")
        if source_sha == merge_sha:
            raise QualificationError("source and GitHub merge SHA must be independently identified")
        # A checkout smudge filter could execute before byte attestation.
        assert_no_executable_checkout_config(repo)
        # Reject replacement refs before reading either source commit object.
        if git(repo, "for-each-ref", "--format=%(refname)", "refs/replace").strip():
            raise QualificationError("repository contains Git replacement objects")
        for sha in (source_sha, merge_sha):
            if git(repo, "rev-parse", "--verify", f"{sha}^{{commit}}").decode().strip() != sha:
                raise QualificationError(f"not an available exact commit: {sha}")
        assert_github_merge_parentage(repo, source_sha, merge_sha)

        with tempfile.TemporaryDirectory(prefix="hepta-runtime-proof-") as work:
            workdir = Path(work)
            for name, sha in (("head", source_sha), ("merge", merge_sha)):
                p = workdir / name
                lane = {"name": name, "sha": sha, "status": "BLOCKED", "checks": []}
                receipt["lanes"].append(lane)
                git(repo, "worktree", "add", "--detach", str(p), sha)
                try:
                    actual = git(p, "rev-parse", "HEAD").decode().strip()
                    if actual != sha:
                        raise QualificationError(f"worktree HEAD mismatch on {name}")
                    lane["tree_sha"] = git(p, "rev-parse", "HEAD^{tree}").decode().strip()
                    lane["object_format"], lane["tracked_files"] = check_source_bytes(p)
                    e = safe_env()
                    target = workdir / f"target-{name}"
                    e["CARGO_TARGET_DIR"] = str(target)
                    versions = ("rustc", "cargo")
                    for binary in versions:
                        result = execute_bounded((binary, "--version"), p, e, output_dir / f"{name}-{binary}-version.log", 30, max_log)
                        lane["checks"].append(result)
                        if result["outcome"] != "pass":
                            raise QualificationError(f"{name}: {binary} is unavailable (Rust {RUST_VERSION} required)")
                        version_text = (output_dir / result["log"]).read_text(encoding="utf-8", errors="replace")
                        if not version_text.startswith(f"{binary} {RUST_VERSION} "):
                            raise QualificationError(f"{name}: {binary} version differs from {RUST_VERSION}")
                    for check_name, command in CHECKS:
                        result = execute_bounded(command, p, e, output_dir / f"{name}-{check_name}.log", timeout, max_log)
                        lane["checks"].append({"name": check_name, **result})
                        if result["outcome"] != "pass":
                            raise QualificationError(f"{name}: {check_name} failed ({result['outcome']})")
                        check_source_bytes(p)
                        if git(p, "rev-parse", "HEAD").decode().strip() != sha:
                            raise QualificationError(f"{name}: commit moved during qualification")
                    lane["status"] = "LOCAL_CHECKS_PASS"
                finally:
                    git(repo, "worktree", "remove", "--force", str(p))
        if all(l["status"] == "LOCAL_CHECKS_PASS" for l in receipt["lanes"]) and len(receipt["lanes"]) == 2:
            receipt["status"] = "LOCAL_CHECKS_PASS_NOT_PRODUCTION"
    except (QualificationError, OSError) as exc:
        receipt["error"] = str(exc)
    finally:
        tmp = output_dir / "qualification.json.tmp"
        tmp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(output_dir / "qualification.json")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--merge-sha", required=True)
    parser.add_argument("--output", type=Path, required=True, help="directory OUTSIDE repo for evidence/logs")
    parser.add_argument("--timeout", type=int, default=1800, help="per-command wallclock seconds")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    repo = args.repo.resolve()
    output = args.output.resolve()
    if output == repo or repo in output.parents:
        parser.error("--output must be outside the repository")
    result = qualify(repo, args.source_sha, args.merge_sha, output, timeout=args.timeout)
    print(json.dumps({"status": result["status"], "error": result.get("error"),
                      "report": str(output / "qualification.json")}, ensure_ascii=False))
    return 0 if result["status"] == "LOCAL_CHECKS_PASS_NOT_PRODUCTION" else 1


if __name__ == "__main__":
    sys.exit(main())
