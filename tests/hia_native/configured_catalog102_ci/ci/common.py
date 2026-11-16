"""Exact-source, complete-stream and owned-process contracts for this CI recipe."""
from pathlib import Path
import hashlib, importlib.util, json, math, os, signal, stat, subprocess, sys, time
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
TARGET = "d3d75c30719db966b004756f610007a7c723729e"
TREE = "612e145513961556ac8844b5cc978f9b5175e4d4"
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
TRUSTED_PACKAGE = (ROOT / "PACKAGE.json").read_bytes() if (ROOT / "PACKAGE.json").exists() else None
FALSE_FLAGS = ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified",
    "all_136_tools_qualified", "public_tool_bodies_qualified", "full_http_dispatcher_replaced")

def need(value, label):
    if not value:
        raise ValueError("configured catalog: " + label)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()

def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda text: (_ for _ in ()).throw(ValueError(text)))

def regular(path):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode),
        "physical regular file: " + str(path))
    return path.read_bytes()

def read_json(path):
    return parse(regular(path))

def put(path, value):
    raw = value if type(value) is bytes else encoded(value)
    path = Path(path)
    with path.open("xb") as stream:
        need(stream.write(raw) == len(raw), "complete exclusive write")
    return pin(raw)

def source_module(name, path):
    path = Path(path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(regular(path), str(path), "exec", dont_inherit=True), module.__dict__)
    return module

def source_check(package=ROOT):
    package = Path(package).absolute()
    raw = regular(package / "PACKAGE.json")
    need(raw == TRUSTED_PACKAGE, "frozen source package bytes")
    data = parse(raw)
    need(data["schema"] == "hepta.runtime.configured-catalog-ci-source.v1"
        and data["target_commit"] == TARGET and data["compiler_commit"] == COMPILER,
        "exact target and compiler")
    actual = {p.relative_to(package).as_posix() for p in package.rglob("*") if p.is_file()}
    need(actual == set(data["files"]) | {"PACKAGE.json"}, "complete recipe source domain")
    for name, expected in data["files"].items():
        p = Path(name)
        need(not p.is_absolute() and ".." not in p.parts and p.as_posix() == name, "source path")
        body = regular(package / p)
        need(pin(body) == {k: expected[k] for k in ("bytes", "sha256")}, "source bytes: " + name)
        if "git_blob" in expected:
            need(hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                == expected["git_blob"], "source Git object: " + name)
    return data

class Reader:
    def __init__(self, root):
        self.root = Path(root).absolute()
        need(self.root.resolve(strict=True) == self.root, "physical reader root")
        self.files = {}
    def raw(self, name, expected=None):
        relative = Path(name)
        need(not relative.is_absolute() and ".." not in relative.parts, "relative evidence path")
        raw = regular(self.root / relative)
        identity = pin(raw)
        if expected is not None:
            need(identity == expected, "complete bytes: " + name)
        self.files[relative.as_posix()] = identity
        return raw
    def document(self, name):
        return parse(self.raw(name))
    def complete(self):
        actual = {p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file()}
        need(actual == set(self.files), "unread/missing evidence: " + repr(sorted(actual ^ set(self.files))))

def original_environment(target_dir):
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith(("RUST", "CARGO_")):
            env.pop(name, None)
    env.update(RUSTUP_TOOLCHAIN="1.95.0", CARGO_TARGET_DIR=str(target_dir),
        CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0",
        CARGO_ENCODED_RUSTFLAGS="", LC_ALL="C", PYTHONDONTWRITEBYTECODE="1")
    return env

ENV_FIELDS = ("RUSTUP_TOOLCHAIN", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
    "CARGO_PROFILE_DEV_DEBUG", "CARGO_ENCODED_RUSTFLAGS", "LC_ALL", "PYTHONDONTWRITEBYTECODE")

def record_process(folder, name, command, cwd, timeout, *, env=None, stdin=None):
    folder = Path(folder); folder.mkdir(parents=True, exist_ok=True)
    command = [str(value) for value in command]
    env = os.environ.copy() if env is None else dict(env)
    process = None; streams = []
    start = time.monotonic_ns()
    row = {"name": name, "command": command, "cwd": str(cwd), "timeout_seconds": timeout,
        "parent_pid": os.getpid(), "parent_pgid": os.getpgrp(), "pid": None, "pgid": None,
        "controlled_environment": {name: env.get(name) for name in ENV_FIELDS},
        "stdin": pin(regular(stdin)) if stdin is not None else None,
        "timed_out": False, "exit_code": None, "start_error": None, "reaped": False}
    failure = None
    try:
        out = (folder / (name + ".stdout")).open("xb"); streams.append(out)
        err = (folder / (name + ".stderr")).open("xb"); streams.append(err)
        inp = open(stdin, "rb") if stdin is not None else None
        if inp is not None: streams.append(inp)
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=inp or subprocess.DEVNULL,
            stdout=out, stderr=err, start_new_session=True)
        row["pid"] = process.pid; row["pgid"] = os.getpgid(process.pid)
        try:
            row["exit_code"] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            row["timed_out"] = True
            raise
    except BaseException as error:
        failure = error
        row["start_error"] = repr(error) if process is None else None
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                row["exit_code"] = process.wait()
                row["reaped"] = True
        finally:
            try:
                for stream in reversed(streams):
                    try: stream.close()
                    except BaseException as error:
                        if failure is None: failure = error
            finally:
                row["elapsed_ns"] = time.monotonic_ns() - start
                for field in ("stdout", "stderr"):
                    path = folder / (name + "." + field)
                    row[field] = pin(path.read_bytes()) if path.exists() else None
                put(folder / (name + ".process.json"), row)
    if failure is not None: raise failure
    need(row["exit_code"] == 0 and not row["timed_out"] and row["reaped"], "actual process failed: " + name)
    return row

def process(reader, name, *, command, cwd, timeout, parent, stdin=None, empty_stderr=False):
    row = reader.document("processes/" + name + ".process.json")
    need(row["name"] == name and row["command"] == list(command) and row["cwd"] == str(cwd),
        "actual command/cwd: " + name)
    need(type(row["timeout_seconds"]) is int and row["timeout_seconds"] == timeout,
        "exact process deadline")
    need(type(row["elapsed_ns"]) is int and 0 < row["elapsed_ns"] <= timeout * 1_000_000_000,
        "actual elapsed deadline")
    for key in ("pid", "pgid", "parent_pid", "parent_pgid"):
        need(type(row[key]) is int and row[key] > 0, "actual PID: " + key)
    need(row["pid"] == row["pgid"] and row["parent_pid"] == parent["pid"]
        and row["parent_pgid"] == parent["pgid"], "actual owned process group")
    need(type(row["exit_code"]) is int and row["exit_code"] == 0 and row["timed_out"] is False
        and row["start_error"] is None and row["reaped"] is True, "actual successful reaping")
    need(row["stdin"] == (pin(stdin) if stdin is not None else None), "complete process stdin")
    streams = {key: reader.raw("processes/" + name + "." + key, row[key]) for key in ("stdout", "stderr")}
    if empty_stderr: need(streams["stderr"] == b"", "actual process stderr")
    return row, streams
