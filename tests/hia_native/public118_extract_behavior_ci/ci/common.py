"""Complete source pins and orchestration without a new outer process timer."""
from pathlib import Path
import hashlib
import json
import stat
import subprocess
import time

def require(ok, text):
    if not ok:
        raise ValueError(text)

def pin(path):
    path = Path(path)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": path.stat().st_size, "sha256": digest}

def put(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")

def files(root):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        require(not stat.S_ISLNK(mode), "symlink: " + str(path))
        if stat.S_ISDIR(mode):
            continue
        require(stat.S_ISREG(mode), "non-regular file: " + str(path))
        result[path.relative_to(root).as_posix()] = pin(path)
    return result

def verify(root, expected):
    actual = files(root)
    require(set(actual) == set(expected), "source file set differs")
    for name, row in expected.items():
        require(actual[name] == {"bytes": row["bytes"], "sha256": row["sha256"]},
                "source bytes differ: " + name)
    return actual

def command(root, label, argv, env=None):
    """The frozen inner tools and workflow retain their own deadlines."""
    root = Path(root)
    logs = root / "processes"
    logs.mkdir(parents=True, exist_ok=True)
    row = {"label": label, "command": [str(x) for x in argv], "cwd": str(root),
           "new_outer_timeout": False, "workflow_job_limit_minutes": 15,
           "started": False, "pid": None, "exit_code": None}
    started, process, failure = time.monotonic_ns(), None, None
    try:
        with (logs/(label+".stdout")).open("xb") as out, (logs/(label+".stderr")).open("xb") as err:
            process = subprocess.Popen(argv, cwd=root, env=env,
                stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            row.update(started=True, pid=process.pid)
            row["exit_code"] = process.wait()
        require(row["exit_code"] == 0, label + " failed; full streams retained")
    except BaseException as error:
        failure = error
        row["failure"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        row["elapsed_ns"] = time.monotonic_ns() - started
        row["process_still_running"] = process is not None and process.poll() is None
        for name in ("stdout", "stderr"):
            path = logs/(label+"."+name)
            if path.is_file():
                row[name] = pin(path)
        put(logs/(label+".json"), row)
    if failure is not None:
        raise failure
    return row
