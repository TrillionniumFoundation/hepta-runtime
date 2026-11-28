"""Full child-process custody; definitions only on import."""
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import time
SHA=lambda raw:hashlib.sha256(raw).hexdigest()

def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+"\n")


def environment(inherited, rust_bin=None, target=None):
    env = dict(inherited)
    removed = []
    forbidden = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
                 "RUSTC", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP",
                 "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_INCREMENTAL", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}
    for name in list(env):
        if name in forbidden or (name.startswith("CARGO_") and any(part in name for part in ("RUSTFLAGS", "RUSTC", "RUSTDOC", "PROFILE_", "LINKER"))):
            removed.append(name); env.pop(name)
    env.update(PYTHONDONTWRITEBYTECODE="1")
    if rust_bin is not None:
        rust_bin = Path(rust_bin).resolve(strict=True)
        env.update(PATH=str(rust_bin)+os.pathsep+env.get("PATH", ""), RUSTC=str(rust_bin/"rustc"),
            RUSTDOC=str(rust_bin/"rustdoc"), RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="",
            CARGO_BUILD_RUSTC=str(rust_bin/"rustc"), CARGO_BUILD_RUSTC_WRAPPER="", CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER="",
            CARGO_ENCODED_RUSTFLAGS="", CARGO_ENCODED_RUSTDOCFLAGS="", CARGO_BUILD_RUSTFLAGS="",
            CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu")
        if target is not None:
            env["CARGO_TARGET_DIR"] = str(Path(target).absolute())
    controlled = {"RUSTC", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC",
                  "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_ENCODED_RUSTFLAGS",
                  "CARGO_ENCODED_RUSTDOCFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"}
    binding = {name: env[name] for name in sorted(controlled) if name in env}
    return env, dict(removed_keys=sorted(removed), explicit_reference_environment=binding,
        cargo_encoded_rustflags_override=env.get("CARGO_ENCODED_RUSTFLAGS"),
        inherited_environment_values_not_logged=True)


class Recorder:
    def __init__(self, root, directory, env=None):
        self.root = Path(root).resolve(strict=True)
        self.directory = Path(directory).absolute()
        self.directory.mkdir(parents=True, exist_ok=False)
        self.env = dict(os.environ) if env is None else dict(env)
        self.records = []

    def run(self, name, argv, *, cwd=None, stdin=None, timeout=180):
        assert name.replace("-", "").isalnum() and name not in {r["name"] for r in self.records}
        argv = [str(x) for x in argv]
        cwd = self.root if cwd is None else Path(cwd).resolve(strict=True)
        started = time.monotonic()
        process = None
        out, error, code, timed_out, completed = b"", b"", None, False, False
        exception = None
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=self.env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            pgid = os.getpgid(process.pid)
            out, error = process.communicate(input=stdin, timeout=timeout)
            code = process.returncode
            completed = True
        except subprocess.TimeoutExpired as failure:
            timed_out = True
            exception = failure
        except BaseException as failure:
            exception = failure
        finally:
            # Reaping is independent of all evidence writes, including ENOSPC.
            if process is not None and not completed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finally:
                    out, error = process.communicate()
                    code = process.returncode
            if process is not None:
                process.wait()
            row = dict(name=name, argv=argv, cwd=str(cwd), pid=process.pid if process else None,
                parent_pid=os.getpid(), pgid=pgid if process is not None and "pgid" in locals() else None,
                exit_code=code, timed_out=timed_out, completed=completed, timeout_seconds=timeout,
                elapsed_seconds=time.monotonic()-started,
                stdin=None if stdin is None else dict(file=name+".stdin", bytes=len(stdin), sha256=SHA(stdin)),
                stdout=dict(file=name+".stdout", bytes=len(out), sha256=SHA(out)),
                stderr=dict(file=name+".stderr", bytes=len(error), sha256=SHA(error)))
            for suffix, raw in (("stdout",out),("stderr",error)):
                (self.directory/(name+"."+suffix)).write_bytes(raw)
            if stdin is not None:
                (self.directory/(name+".stdin")).write_bytes(stdin)
            self.records.append(row)
            put(self.directory/"processes.json",self.records)
        if exception is not None:
            raise exception
        if code != 0:
            raise RuntimeError("recorded command failed: "+name)
        return out, row
