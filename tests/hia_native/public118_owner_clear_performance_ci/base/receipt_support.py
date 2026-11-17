"""Complete regular-file evidence and owned-process capture for this fixture."""
from pathlib import Path
import hashlib
import json
import math
import os
import signal
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parent
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PIN = lambda raw: {"bytes": len(raw), "sha256": SHA(raw)}


def require(ok, message):
    if not ok:
        raise ValueError("rebuilt Batch evidence: " + message)


def regular(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            "expected an unaliased regular file: " + str(path))
    require(path.resolve(strict=True) == path.absolute(), "symlink in evidence path: " + str(path))
    return path.read_bytes()


def put(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON evidence key")
            result[key] = value
        return result
    return json.loads(regular(path), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def exact(stream, count):
    require(type(count) is int and count >= 0, "invalid complete span")
    raw = stream.read(count)
    require(len(raw) == count, "truncated complete evidence stream")
    return raw


def process(folder, name, argv, *, cwd, stdin=b"", env=None, timeout=180):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    require(name.replace("-", "").isalnum(), "process label")
    destination = folder / (name + ".json")
    require(not destination.exists(), "process receipt already exists")
    selected = {"PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"}
    if env:
        selected.update(env)
    environment = dict(os.environ, **selected)
    before = time.monotonic()
    row = {"schema": "hepta.runtime.rebuilt-batch-process.v1", "name": name,
        "argv": [str(x) for x in argv], "cwd": str(Path(cwd).absolute()),
        "controlled_env": selected, "timeout_seconds": timeout, "stdin": PIN(stdin),
        "status": "STARTING", "timed_out": False, "reaped": False}
    put(destination, row)
    child = None
    out = err = b""
    try:
        child = subprocess.Popen(row["argv"], cwd=cwd, env=environment, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        row.update(status="RUNNING", pid=child.pid, process_group=os.getpgid(child.pid))
        require(row["pid"] == row["process_group"], "owned process group was not created")
        put(destination, row)
        try:
            out, err = child.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            row["timed_out"] = True
            os.killpg(child.pid, signal.SIGKILL)
            out, err = child.communicate()
        row.update(returncode=child.returncode, reaped=True,
                   status="PASS" if child.returncode == 0 and not row["timed_out"] else "FAIL")
    except BaseException as error:
        row.update(status="FAIL", failure=repr(error))
        raise
    finally:
        try:
            if child is not None and child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                finally:
                    out, err = child.communicate()
                    row.update(returncode=child.returncode, reaped=True)
        finally:
            row["elapsed_seconds"] = time.monotonic() - before
            for kind, raw in (("stdin", stdin), ("stdout", out), ("stderr", err)):
                path = folder / (name + "." + kind)
                path.write_bytes(raw)
                row[kind] = dict(path=path.name, **PIN(raw))
            put(destination, row)
    require(row["status"] == "PASS", "actual process failed: " + name)
    return row, out, err


def check_process(folder, name, *, timeout=180):
    folder = Path(folder)
    row = read_json(folder / (name + ".json"))
    require(row["schema"] == "hepta.runtime.rebuilt-batch-process.v1" and row["name"] == name,
            "process identity")
    require(row["status"] == "PASS" and type(row["returncode"]) is int and row["returncode"] == 0
            and row["timed_out"] is False and row["reaped"] is True, "process did not complete")
    require(type(row["pid"]) is int and row["pid"] > 0 and row["process_group"] == row["pid"],
            "process group custody")
    elapsed = row["elapsed_seconds"]
    require(row["timeout_seconds"] == timeout and type(elapsed) in (int, float)
            and math.isfinite(elapsed) and 0 <= elapsed < timeout, "process deadline")
    require(isinstance(row["argv"], list) and row["argv"] and all(type(x) is str for x in row["argv"])
            and Path(row["cwd"]).is_absolute(), "process command/cwd")
    streams = {}
    for kind in ("stdin", "stdout", "stderr"):
        raw = regular(folder / (name + "." + kind))
        require(row[kind] == dict(path=name + "." + kind, **PIN(raw)), "complete process " + kind)
        streams[kind] = raw
    return row, streams
