"""Executed by the official SDK inside the selected cloud kernel.

The adapter prepends an immutable _HEPTA_PAYLOAD dictionary. This file alone
has no entry point and never authenticates or allocates a Colab runtime.
"""


def _hepta_main(payload):
    import hashlib
    import json
    import os
    from pathlib import Path, PurePosixPath
    import signal
    import stat
    import subprocess
    import sys
    import time
    import traceback

    identity = {k: payload[k] for k in (
        "job_id", "payload_sha256", "endpoint", "kernel_id", "session_id"
    )}
    root = Path(payload["remote_dir"])
    # Refuse every symlink ancestor before and after creating the owned root.
    for candidate in (root, *root.parents):
        if candidate.is_symlink():
            raise RuntimeError("receipt_path_is_symlink")
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for candidate in (root, *root.parents):
        if candidate.is_symlink():
            raise RuntimeError("receipt_path_is_symlink")
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        # A duplicate dispatch can only inspect the original receipt. Even if
        # it crashed before request.json appeared, it must never run again.
        existing = root / "request.json"
        if not existing.is_file():
            raise RuntimeError("claim_exists_without_request")
        observed = json.loads(existing.read_text())
        if any(observed.get(k) != v for k, v in identity.items()):
            raise RuntimeError("remote_claim_identity_mismatch")
        print(json.dumps({**identity, "duplicate_claim": True}))
        return

    def atomic_json(name, value):
        target = root / name
        tmp = root / (name + ".tmp")
        with open(tmp, "x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, target)

    def group_live(pgid):
        # Signal 0 is resolved in this process's PID namespace, unlike a
        # potentially inherited /proc mount. A missing group is decisive.
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        try:
            if int(Path("/proc/self").resolve().name) != os.getpid():
                return True  # Cannot safely interpret a foreign /proc mount.
        except (OSError, ValueError):
            return True
        # In the matching namespace, zombies cannot do further computation.
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            try:
                fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
                if int(fields[2]) == pgid and fields[0] != "Z":
                    return True
            except (FileNotFoundError, ProcessLookupError, PermissionError,
                    ValueError, IndexError):
                continue
        return False

    def stop_group(proc):
        for sig, grace in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 3.0)):
            if proc.poll() is None or group_live(proc.pid):
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                proc.poll()
                if proc.returncode is not None and not group_live(proc.pid):
                    return True
                time.sleep(0.05)
        proc.poll()
        return proc.returncode is not None and not group_live(proc.pid)

    def digest_file(path):
        h = hashlib.sha256()
        size = 0
        with open(path, "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest(), size

    atomic_json("request.json", {**identity,
        "code_sha256": payload["code_sha256"], "created_at": time.time()})
    work = root / "work"
    work.mkdir(mode=0o700)
    script = root / "code.py"
    encoded = payload["code"].encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != payload["code_sha256"]:
        raise RuntimeError("code_hash_mismatch")
    with open(script, "xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    initial = {**identity, "state": "starting", "started_at": time.time(),
        "cloud_execution_stopped": False, "execution_started": False}
    atomic_json("status.json", initial)
    proc = None
    reason = None
    state = "failed"
    stopped = True
    exit_code = None
    with open(root / "stdout.bin", "xb", buffering=0) as stdout, \
         open(root / "stderr.bin", "xb", buffering=0) as stderr:
        try:
            bootstrap = ("import resource,runpy,sys; "
                f"resource.setrlimit(resource.RLIMIT_FSIZE, ({payload['max_artifact_bytes']}, "
                f"{payload['max_artifact_bytes']})); "
                "runpy.run_path(sys.argv[1], run_name='__main__')")
            proc = subprocess.Popen([sys.executable, "-u", "-c", bootstrap, str(script)],
                cwd=work, stdout=stdout, stderr=stderr, start_new_session=True)
            initial.update(state="running", execution_started=True,
                           cloud_pid=proc.pid, cloud_process_group=proc.pid)
            atomic_json("status.json", initial)
            print(json.dumps({**identity, "state": "running"}), flush=True)
            deadline = time.monotonic() + payload["wall_seconds"]
            while proc.poll() is None:
                cancel_path = root / "cancel.request.json"
                if cancel_path.is_file():
                    try:
                        cancellation = json.loads(cancel_path.read_text())
                    except (OSError, ValueError):
                        cancellation = None
                    if cancellation and all(cancellation.get(k) == v
                                            for k, v in identity.items()):
                        reason = "cancel_requested"
                        break
                if time.monotonic() >= deadline:
                    reason = "wall_time_limit"
                    break
                if max(os.fstat(stdout.fileno()).st_size,
                       os.fstat(stderr.fileno()).st_size) > payload["max_output_bytes"]:
                    reason = "output_size_limit"
                    break
                time.sleep(0.1)
            if reason or group_live(proc.pid):
                stopped = stop_group(proc)
            else:
                proc.wait()
                stopped = not group_live(proc.pid)
            exit_code = proc.returncode
            # A short-lived child can exit between polls, and descendants can
            # write while their group is stopping. Validate the final sizes
            # before a zero exit code is allowed to become success.
            if reason is None and max(os.fstat(stdout.fileno()).st_size,
                                      os.fstat(stderr.fileno()).st_size) > payload["max_output_bytes"]:
                reason = "output_size_limit"
            if not stopped:
                state = "unknown"
                reason = "process_group_still_live"
            elif reason == "cancel_requested":
                state = "cancelled"
            elif reason == "wall_time_limit":
                state = "timed_out"
            elif reason == "output_size_limit":
                state = "failed"
            else:
                state = "succeeded" if exit_code == 0 else "failed"
        except KeyboardInterrupt:
            reason = "kernel_interrupt"
            stopped = stop_group(proc) if proc is not None else True
            exit_code = proc.returncode if proc is not None else None
            state = "cancelled" if stopped else "unknown"
        except BaseException as exc:
            # Details belong to the user's raw stderr, not local transport logs.
            stderr.write(traceback.format_exc().encode("utf-8"))
            stopped = stop_group(proc) if proc is not None else True
            exit_code = proc.returncode if proc is not None else None
            reason = type(exc).__name__
            state = "failed" if stopped else "unknown"
        finally:
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())

    entries = {}
    artifact_errors = []
    for name, file_path in (("stdout", root / "stdout.bin"),
                            ("stderr", root / "stderr.bin")):
        sha, size = digest_file(file_path)
        entries[name] = {"remote_path": str(file_path), "sha256": sha, "size": size}
    for name in payload["artifacts"]:
        relative = PurePosixPath(name)
        path = work.joinpath(*relative.parts)
        try:
            if relative.is_absolute() or any(p in ("", ".", "..") for p in relative.parts):
                raise ValueError("invalid_artifact_path")
            cursor = work
            for part in relative.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise ValueError("artifact_symlink")
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("artifact_not_regular")
            if info.st_size > payload["max_artifact_bytes"]:
                raise ValueError("artifact_too_large")
            sha, size = digest_file(path)
            entries[name] = {"remote_path": str(path), "sha256": sha, "size": size}
        except (OSError, ValueError) as exc:
            artifact_errors.append({"artifact": name, "error": type(exc).__name__})
    if artifact_errors and state == "succeeded":
        state, reason = "failed", "artifact_contract_failed"
    manifest = {**identity, "entries": entries, "errors": artifact_errors}
    atomic_json("artifacts.json", manifest)
    manifest_sha, manifest_size = digest_file(root / "artifacts.json")
    final = {**initial, "state": state, "reason": reason,
        "finished_at": time.time(), "exit_code": exit_code,
        "cloud_execution_stopped": bool(stopped),
        "cloud_process_group_alive": not bool(stopped),
        "artifact_manifest_sha256": manifest_sha,
        "artifact_manifest_size": manifest_size}
    atomic_json("status.json", final)
    print(json.dumps({**identity, "state": state,
                      "cloud_execution_stopped": bool(stopped)}), flush=True)


if "_HEPTA_PAYLOAD" in globals():
    _hepta_main(_HEPTA_PAYLOAD)

