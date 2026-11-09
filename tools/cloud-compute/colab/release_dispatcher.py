#!/usr/bin/env python3
"""Route Colab jobs to an explicitly retained, hash-verified adapter release.

The CLI is the account launcher's CLI; it has no configuration/path override.
The effective user's fixed ~/.config/hepta-colab directory contains accounts.json
and release-map.json. The latter is an operator-maintained allowlist, not a cache:

  {"schema": 1, "current": "v5", "releases": {"v5": {
    "directory": "/absolute/retained/release",
    "python": "/absolute/sdk-venv/bin/python",
    "python_sha256": "<resolved interpreter SHA256>",
    "runner_sha256": "<remote_runner.py SHA256>",
    "files": {"account_launcher.py": "<SHA256>", "...": "<SHA256>"}
  }}}

Every Python source in a selected release must be in files, including all six
required adapter modules. Interpreter symlinks may resolve into the trusted SDK
installation; release/config/ledger paths may not contain symlinks. The SDK venv
and its dependencies remain part of the operator's existing trusted installation.
Retain an entry for every runner hash present in the historical jobs ledger.

Only an existing, valid ledger proves a new submit key is absent. Missing state,
ambiguous identity, unknown runners and changed releases fail closed. No ledger,
payload, profile or runner is rewritten. The selected original account launcher
is exec'd in a fresh isolated Python process and keeps its own identity guards.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import sqlite3
import stat
import sys
import time


REQUIRED_MODULES = frozenset({"account_launcher.py", "hepta_colab.py",
    "remote_runner.py", "manage_colab.py", "authorize_colab.py",
    "launch_authorization.py"})
HEX = re.compile(r"[0-9a-f]{64}\Z")
FORBIDDEN = frozenset({"--expected-account", "--expected-email", "--state-dir",
    "--quota-project", "--profile", "--status-file", "--jobs-state-dir", "--name"})


class DispatchError(Exception):
    """A fixed, public error code; never include config or SQLite contents."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise DispatchError("DISPATCH_ARGUMENTS_INVALID")


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        seen = getattr(namespace, "_seen", set())
        if self.dest in seen:
            raise DispatchError("DISPATCH_IDENTITY_AMBIGUOUS")
        setattr(namespace, "_seen", seen | {self.dest})
        setattr(namespace, self.dest, values)


def _absolute(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or len(value) > 4096 or "\x00" in value
            or any(p in ("", ".", "..") for p in value.split("/")[1:])):
        raise DispatchError("DISPATCH_PATH_UNSAFE")
    return Path(value)


@contextmanager
def _parent(path, *, private=False):
    """Walk without symlinks or group/other-writable ancestors."""
    path = _absolute(str(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    uid = os.geteuid()
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in (0, uid) or info.st_mode & 0o022:
                raise DispatchError("DISPATCH_PATH_UNSAFE")
        if private and os.fstat(fd).st_uid != uid:
            raise DispatchError("DISPATCH_PATH_UNSAFE")
        yield fd, path.name
    finally:
        os.close(fd)


def _regular(info, *, private=False):
    uid = os.geteuid()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in ((uid,) if private else (0, uid))
            or info.st_mode & (0o077 if private else 0o022)):
        raise DispatchError("DISPATCH_FILE_UNSAFE")


def _read_file(path, *, private=False, limit=2 * 1024 * 1024):
    with _parent(path, private=private) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            _regular(before, private=private)
            if before.st_size > limit:
                raise DispatchError("DISPATCH_FILE_TOO_LARGE")
            chunks, size = [], 0
            while True:
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > limit:
                    raise DispatchError("DISPATCH_FILE_TOO_LARGE")
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(before) != identity(after) or identity(after) != identity(current):
                raise DispatchError("DISPATCH_FILE_CHANGED")
            return b"".join(chunks)
        finally:
            os.close(fd)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DispatchError("DISPATCH_CONFIG_AMBIGUOUS")
        result[key] = value
    return result


def _json_file(path):
    try:
        result = json.loads(_read_file(path, private=True, limit=262144),
                            object_pairs_hook=_unique_object)
        if not isinstance(result, dict):
            raise DispatchError("DISPATCH_CONFIG_INVALID")
        return result
    except (ValueError, UnicodeError):
        raise DispatchError("DISPATCH_CONFIG_INVALID") from None


def _parse(argv):
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("account")
    parser.add_argument("--provision-key", action=_Once)
    parser.add_argument("action", choices=("authorize", "manage", "run"))
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.provision_key is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", args.provision_key):
        raise DispatchError("INVALID_PROVISION_KEY")
    if any(token.startswith("--") and token != "--"
           and any(flag.startswith(token.split("=", 1)[0]) for flag in FORBIDDEN)
           for token in args.args):
        raise DispatchError("ACCOUNT_IDENTITY_OVERRIDE_DENIED")
    if args.action != "run" or any(token in ("--help", "-h") for token in args.args):
        return args, None, None
    commands = {"submit", "inspect-key", "run", "status", "cancel", "read", "fetch"}
    if not args.args or args.args[0] not in commands:
        raise DispatchError("DISPATCH_COMMAND_UNSUPPORTED")
    verb = args.args[0]
    command = _Parser(add_help=False, allow_abbrev=False)
    field = "idempotency_key" if verb in ("submit", "inspect-key") else "job_id"
    command.add_argument("--key" if field == "idempotency_key" else "--job-id",
                         dest="identity", required=True, action=_Once)
    if verb == "submit":
        command.add_argument("--code-file", required=True, action=_Once)
        command.add_argument("--artifact", action="append")
        command.add_argument("--wall-seconds", type=int, action=_Once)
    elif verb == "status":
        command.add_argument("--local", action="store_true")
    elif verb == "read":
        command.add_argument("--stream", choices=("stdout", "stderr"), action=_Once)
        command.add_argument("--offset", type=int, action=_Once)
        command.add_argument("--limit", type=int, action=_Once)
    elif verb == "fetch":
        command.add_argument("--artifact", required=True, action=_Once)
        command.add_argument("--destination", required=True, action=_Once)
    selected = command.parse_args(args.args[1:]).identity
    if not 1 <= len(selected.encode("utf-8")) <= 128 or "\x00" in selected:
        raise DispatchError("DISPATCH_IDENTITY_INVALID")
    return args, field, selected


def _account(config, alias):
    accounts = config.get("accounts")
    if not isinstance(accounts, dict) or alias not in accounts:
        raise DispatchError("DISPATCH_ACCOUNT_UNKNOWN")
    roots = []
    for entry in accounts.values():
        if not isinstance(entry, dict):
            raise DispatchError("DISPATCH_CONFIG_INVALID")
        roots.append(str(_absolute(entry.get("state_dir"))))
    if len(roots) != len(set(roots)):
        raise DispatchError("DISPATCH_ACCOUNT_STATE_AMBIGUOUS")
    entry = accounts[alias]
    _absolute(entry.get("profile"))
    if any(not isinstance(entry.get(k), str) or not entry[k]
           for k in ("email", "keyring_service", "chrome_profile")):
        raise DispatchError("DISPATCH_CONFIG_INVALID")
    return Path(entry["state_dir"]) / "jobs"


def _auxiliaries(parent, name):
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            info = os.stat(name + suffix, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            continue
        _regular(info, private=True)


def _ledger_runner(state, field, identity):
    """Read only routing metadata, never historical code or job arguments."""
    path = state / "jobs.sqlite3"
    try:
        with _parent(path, private=True) as (parent, name):
            source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                info = os.fstat(source)
                _regular(info, private=True)
                _auxiliaries(parent, name)
                db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True,
                                     isolation_level=None, timeout=2)
                try:
                    deadline = time.monotonic() + 3
                    db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                    db.execute("PRAGMA query_only=ON")
                    db.execute("PRAGMA trusted_schema=OFF")
                    db.execute("BEGIN")
                    tables = dict(db.execute("SELECT name,type FROM sqlite_master WHERE name IN ('jobs','events')"))
                    if tables != {"jobs": "table", "events": "table"}:
                        raise DispatchError("DISPATCH_LEDGER_INVALID")
                    db.execute("SELECT job_id,idempotency_key,runner_sha256,profile_hash,submit_attempts,state,endpoint,dispatched_at,worker_pid,worker_start_ticks,receipt_json,manifest_json FROM jobs LIMIT 0")
                    db.execute("SELECT job_id,event FROM events LIMIT 0")
                    if db.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
                        raise DispatchError("DISPATCH_LEDGER_INVALID")
                    # Both identities must still have their original uniqueness guarantees.
                    unique = set()
                    for index in db.execute("PRAGMA index_list(jobs)"):
                        if index[2] and not index[4]:
                            quoted = '"' + index[1].replace('"', '""') + '"'
                            unique.add(tuple(row[2] for row in db.execute("PRAGMA index_info(" + quoted + ")")))
                    if not {("job_id",), ("idempotency_key",)} <= unique:
                        raise DispatchError("DISPATCH_LEDGER_AMBIGUOUS")
                    # A malformed key in another row must not turn an old key
                    # into apparent absence (SQLite TEXT columns can hold BLOBs).
                    invalid = db.execute("""SELECT 1 FROM jobs WHERE
                        typeof(job_id)!='text' OR typeof(idempotency_key)!='text'
                        OR length(CAST(job_id AS BLOB)) NOT BETWEEN 1 AND 128
                        OR length(CAST(idempotency_key AS BLOB)) NOT BETWEEN 1 AND 128
                        OR instr(job_id,char(0))>0 OR instr(idempotency_key,char(0))>0
                        OR typeof(runner_sha256)!='text' OR length(runner_sha256)!=64
                        OR runner_sha256 GLOB '*[^0-9a-f]*'
                        OR typeof(profile_hash)!='text' OR length(profile_hash)!=64
                        OR profile_hash GLOB '*[^0-9a-f]*' LIMIT 1""").fetchone()
                    if invalid is not None:
                        raise DispatchError("DISPATCH_LEDGER_INVALID")
                    # field is chosen internally by _parse, never taken from a CLI SQL expression.
                    if field not in ("job_id", "idempotency_key"):
                        raise DispatchError("DISPATCH_IDENTITY_INVALID")
                    rows = db.execute("SELECT job_id,idempotency_key,runner_sha256,profile_hash FROM jobs WHERE "
                                      + field + "=? LIMIT 2", (identity,)).fetchall()
                    if len(rows) > 1:
                        raise DispatchError("DISPATCH_LEDGER_AMBIGUOUS")
                    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                        raise DispatchError("DISPATCH_LEDGER_CHANGED")
                    _auxiliaries(parent, name)
                    if not rows:
                        return None
                    job, key, runner, profile = rows[0]
                    if (job if field == "job_id" else key) != identity:
                        raise DispatchError("DISPATCH_IDENTITY_AMBIGUOUS")
                    if (any(not isinstance(x, str) or not 1 <= len(x.encode()) <= 128 or "\x00" in x
                            for x in (job, key))
                            or not isinstance(runner, str) or not HEX.fullmatch(runner)
                            or not isinstance(profile, str) or not HEX.fullmatch(profile)):
                        raise DispatchError("DISPATCH_LEDGER_INVALID")
                    return runner
                finally:
                    db.close()
            finally:
                os.close(source)
    except FileNotFoundError:
        raise DispatchError("DISPATCH_LEDGER_MISSING") from None
    except sqlite3.Error:
        raise DispatchError("DISPATCH_LEDGER_INVALID") from None


def _release_map(config):
    if config.get("schema") != 1 or type(config.get("schema")) is not int:
        raise DispatchError("DISPATCH_RELEASE_MAP_INVALID")
    releases, current = config.get("releases"), config.get("current")
    if (not isinstance(releases, dict) or not 1 <= len(releases) <= 16
            or not isinstance(current, str) or current not in releases):
        raise DispatchError("DISPATCH_RELEASE_MAP_INVALID")
    runners, directories = {}, set()
    for label, release in releases.items():
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", label)
                or not isinstance(release, dict)):
            raise DispatchError("DISPATCH_RELEASE_MAP_INVALID")
        directory = str(_absolute(release.get("directory")))
        _absolute(release.get("python"))
        files = release.get("files")
        if (not isinstance(files, dict) or not REQUIRED_MODULES <= files.keys()
                or not 6 <= len(files) <= 128):
            raise DispatchError("DISPATCH_RELEASE_MAP_INVALID")
        for name, digest in files.items():
            relative = PurePosixPath(name)
            if (relative.is_absolute() or str(relative) != name or "\\" in name
                    or any(p in ("", ".", "..", "__pycache__") for p in relative.parts)
                    or relative.suffix != ".py" or not isinstance(digest, str)
                    or not HEX.fullmatch(digest)):
                raise DispatchError("DISPATCH_RELEASE_MAP_INVALID")
        runner = release.get("runner_sha256")
        if (runner != files["remote_runner.py"] or runner in runners
                or directory in directories or not isinstance(release.get("python_sha256"), str)
                or not HEX.fullmatch(release["python_sha256"])):
            raise DispatchError("DISPATCH_RELEASE_MAP_AMBIGUOUS")
        runners[runner] = label
        directories.add(directory)
    return releases, current, runners


def _interpreter_target(python):
    """Validate every symlink hop, while retaining the venv path for exec."""
    current = python
    for _ in range(40):
        with _parent(current) as (parent, name):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                if info.st_uid not in (0, os.geteuid()) or info.st_nlink != 1:
                    raise DispatchError("DISPATCH_INTERPRETER_UNSAFE")
                target = os.readlink(name, dir_fd=parent)
                current = _absolute(os.path.normpath(os.path.join(current.parent, target)))
            else:
                _regular(info)
                if not info.st_mode & 0o111:
                    raise DispatchError("DISPATCH_INTERPRETER_UNSAFE")
                return current
    raise DispatchError("DISPATCH_INTERPRETER_UNSAFE")


def _verify_release(release):
    root = Path(release["directory"])
    # Opening a dummy leaf validates the entire release directory chain.
    with _parent(root / ".validate"):
        pass
    found, entries = set(), 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name != "__pycache__"]
        entries += len(dirs) + len(names)
        if entries > 1024:
            raise DispatchError("DISPATCH_RELEASE_INVALID")
        for name in dirs:
            with _parent(Path(directory) / name / ".validate"):
                pass
        for name in names:
            path = Path(directory) / name
            if path.suffix == ".py":
                found.add(path.relative_to(root).as_posix())
            elif path.suffix in (".pyc", ".pyo", ".so", ".pyd", ".dylib"):
                raise DispatchError("DISPATCH_RELEASE_UNMANIFESTED_CODE")
    if found != set(release["files"]):
        raise DispatchError("DISPATCH_RELEASE_UNMANIFESTED_CODE")
    for name, expected in release["files"].items():
        actual = hashlib.sha256(_read_file(root / name)).hexdigest()
        if actual != expected:
            raise DispatchError("DISPATCH_RELEASE_HASH_MISMATCH")
    # Keep the configured venv path in argv: resolving argv[0] would lose its SDK.
    python = Path(release["python"])
    resolved = _interpreter_target(python)
    actual = hashlib.sha256(_read_file(resolved, limit=128 * 1024 * 1024)).hexdigest()
    if actual != release["python_sha256"] or not os.access(python, os.X_OK):
        raise DispatchError("DISPATCH_INTERPRETER_HASH_MISMATCH")


@dataclass(frozen=True)
class DispatchPlan:
    release: str
    reason: str
    command: tuple[str, ...]
    home: str

    def environment(self):
        # -I also disables Python environment flags and user-site imports.
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("PYTHON", "DYLD_"))
               and k not in {"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "__PYVENV_LAUNCHER__"}}
        env["HOME"] = self.home
        return env


def make_plan(argv, *, home=None):
    """Build and verify a plan; the optional home argument is for offline tests."""
    argv = tuple(argv)
    args, field, identity = _parse(argv)
    home = _absolute(str(home if home is not None else pwd.getpwuid(os.geteuid()).pw_dir))
    config_dir = home / ".config" / "hepta-colab"
    state = _account(_json_file(config_dir / "accounts.json"), args.account)
    releases, selected, runners = _release_map(_json_file(config_dir / "release-map.json"))
    reason = "current_non_job_command"
    if field is not None:
        runner = _ledger_runner(state, field, identity)
        if runner is None:
            if field == "job_id":
                raise DispatchError("DISPATCH_JOB_NOT_FOUND")
            reason = "verified_key_absent"
        else:
            if runner not in runners:
                raise DispatchError("DISPATCH_RUNNER_UNKNOWN")
            selected, reason = runners[runner], "original_runner"
    release = releases[selected]
    _verify_release(release)
    # A non-directory pycache prefix prevents reading pre-existing __pycache__
    # bytecode. -B prevents writes; unmanifested sourceless modules are rejected.
    command = (release["python"], "-I", "-B", "-X", "pycache_prefix=/dev/null",
               str(Path(release["directory"]) / "account_launcher.py"), *argv)
    return DispatchPlan(selected, reason, tuple(command), str(home))


def main(argv=None):
    os.umask(0o077)
    try:
        plan = make_plan(sys.argv[1:] if argv is None else argv)
        os.execve(plan.command[0], plan.command, plan.environment())
    except DispatchError as exc:
        code = str(exc)
    except (OSError, ValueError, TypeError, KeyError):
        code = "DISPATCH_LOCAL_EVIDENCE_UNAVAILABLE"
    print(json.dumps({"status": "blocked", "error_code": code}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
