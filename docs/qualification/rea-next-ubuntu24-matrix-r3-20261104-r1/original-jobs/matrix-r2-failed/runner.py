
import os, pathlib, stat, sys
_hepta_directory_pins = []
def private_job_directory(raw, create=False):
    if not isinstance(raw, str) or not raw.startswith("/") or any(p in (".", "..") for p in raw.split("/")):
        raise SystemExit("unsafe remote job path")
    parts = [p for p in raw.split("/") if p]
    if len(parts) < 3 or parts[-2] != "jobs":
        raise SystemExit("remote job path must name a dedicated state/jobs/job directory")
    shared_access = getattr(os, "O_PATH", os.O_RDONLY) if sys.platform == "linux" else os.O_RDONLY
    path_only_shared = shared_access != os.O_RDONLY
    directory_flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", shared_access | directory_flags)
    _hepta_directory_pins.append(fd)
    for offset, part in enumerate(parts):
        private = offset >= len(parts) - 3
        if create and private and not path_only_shared:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
                os.fsync(fd)
            except FileExistsError:
                pass
        access = os.O_RDONLY if private else shared_access
        try:
            child = os.open(part, access | directory_flags, dir_fd=fd)
        except FileNotFoundError:
            if not (create and private and path_only_shared):
                raise
            # O_PATH traverses an existing searchable ancestor without reading it.
            # A new child still needs its parent's original durability barrier:
            # acquire a readable handle before mkdir, or refuse without creating.
            sync_parent = os.open(".", os.O_RDONLY | directory_flags, dir_fd=fd)
            _hepta_directory_pins.append(sync_parent)
            pinned = os.fstat(fd)
            readable = os.fstat(sync_parent)
            if (pinned.st_dev, pinned.st_ino) != (readable.st_dev, readable.st_ino):
                raise SystemExit("remote parent directory identity changed; no directory created")
            try:
                os.mkdir(part, mode=0o700, dir_fd=sync_parent)
            except FileExistsError:
                pass
            else:
                os.fsync(sync_parent)
            child = os.open(part, os.O_RDONLY | directory_flags, dir_fd=sync_parent)
        _hepta_directory_pins.append(child)
        info = os.fstat(child)
        if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise SystemExit("unsafe remote state/jobs/job directory; existing permissions are never repaired")
        fd = child
    os.fchdir(fd)
    return pathlib.Path(".")

def private_bound_job_directory(raw, expected):
    job = private_job_directory(raw)
    info = os.fstat(_hepta_directory_pins[-1])
    if (info.st_dev, info.st_ino) != (expected["device"], expected["inode"]):
        raise SystemExit("remote job directory identity changed; no workload submitted")
    return job

def private_open_job_file(name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=_hepta_directory_pins[-1])
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SystemExit("unsafe remote job file " + name) from error
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(fd)
        raise SystemExit("unsafe remote job file " + name + ": non-regular or linked inode")
    return fd

def private_read_json(name):
    import json
    fd = private_open_job_file(name)
    if fd is None: return None
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > 4 * 1024 * 1024:
            raise SystemExit("unsafe remote job file " + name + ": linked or oversized inode")
        encoded = stream.read(4 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
        current = os.stat(name, dir_fd=_hepta_directory_pins[-1], follow_symlinks=False)
    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if len(encoded) > 4 * 1024 * 1024 or stamp(before) != stamp(after) or stamp(after) != stamp(current):
        raise SystemExit("unsafe remote job file " + name + ": changed while reading")
    try:
        value = json.loads(encoded)
        if not isinstance(value, dict): raise ValueError("not an object")
        return value
    except (ValueError, UnicodeError) as error:
        raise SystemExit("corrupt remote job file " + name) from error


#!/usr/bin/env python3
import errno, fcntl, hashlib, json, os, pathlib, select, shutil, signal, stat, subprocess, sys, threading, time
# Only the trusted launcher chooses this argv marker, never request metadata.
# A legacy unmarked runner retains the original detached nice adjustment.
if len(sys.argv) not in (3, 4):
    raise SystemExit("invalid supervisor launch backend; no workload submitted")
launch_backend = sys.argv[3] if len(sys.argv) == 4 else "detached"
if launch_backend not in ("systemd", "detached"):
    raise SystemExit("invalid supervisor launch backend; no workload submitted")
binding = json.loads(sys.argv[2])
job = private_bound_job_directory(sys.argv[1], binding)
req = private_read_json("request.json")
if (req.get("job_id"), req.get("launch_nonce"), req.get("request_fingerprint")) != (binding["job_id"], binding["launch_nonce"], binding["request_fingerprint"]):
    raise SystemExit("remote launch identity changed; no workload submitted")

def atomic(name, value):
    target = job / name
    tmp = job / (name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, target)
    os.fsync(_hepta_directory_pins[-1])
    return encoded

def publish_terminal(value):
    value = {**value, "terminal_publication_protocol": 1,
             "job_id": req["job_id"], "launch_nonce": req["launch_nonce"]}
    encoded = atomic("exit.json", value)
    # A visible witness proves that the preceding exit file and directory
    # barriers returned. Losing the witness only makes status unconfirmed;
    # its presence does not claim its own final directory fsync survived loss.
    atomic("exit.witness.json", {
        "terminal_publication_protocol": 1,
        "job_id": req["job_id"],
        "launch_nonce": req["launch_nonce"],
        "exit_sha256": hashlib.sha256(encoded).hexdigest(),
    })

def reap_original_child(child, timeout):
    # Finish every original-group signal before entering this bounded wait.
    # Popen.wait maps ECHILD to a successful-looking zero; only an actual
    # waitpid return for this original child can prove a reap and exit code.
    wait_deadline = time.monotonic() + timeout
    while True:
        waited_pid, status = os.waitpid(child.pid, os.WNOHANG)
        if waited_pid == child.pid:
            child.returncode = os.waitstatus_to_exitcode(status)
            return child.returncode
        if waited_pid != 0:
            raise RuntimeError("wait returned an unexpected child identity")
        remaining = wait_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("original child wait deadline exceeded")
        time.sleep(min(0.01, remaining))

def process_identity(pid):
    if sys.platform == "linux":
        try:
            ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
            boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            return {"kind": "proc_start_ticks", "value": boot + ":" + str(ticks)} if boot else None
        except Exception:
            return None
    try:
        value = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True, timeout=3).strip()
        return {"kind": "ps_lstart", "value": value} if value else None
    except Exception:
        return None

os.umask(0o077)
owner_fd = os.open(job / "owner.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
owner_stat = os.fstat(owner_fd)
if not stat.S_ISREG(owner_stat.st_mode) or owner_stat.st_uid != os.geteuid() or owner_stat.st_nlink != 1 or owner_stat.st_mode & 0o077:
    raise SystemExit("unsafe supervisor lifetime lock")
fcntl.flock(owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
if any(os.path.lexists(job / name) for name in ("owner-intent.json","started.json","exit.json","exit.witness.json","exit.witness.json.tmp")):
    raise SystemExit("prior supervisor intent or binding exists; workload must not be replayed")
if sys.platform == "linux":
    if not hasattr(os, "waitid") or not hasattr(os, "WNOWAIT"):
        raise SystemExit("non-reaping child identity observation unavailable; no workload submitted")
elif not all(hasattr(select, name) for name in ("kqueue","kevent","KQ_FILTER_PROC","KQ_NOTE_EXIT")):
    raise SystemExit("non-reaping child exit observation unavailable; no workload submitted")
owner_identity = process_identity(os.getpid())
if not owner_identity:
    raise SystemExit("supervisor start identity unavailable; no workload submitted")
owner_binding = {"at_unix_ms":int(time.time()*1000),"job_id":req["job_id"],
    "launch_nonce":req["launch_nonce"],"supervisor_pid":os.getpid(),
    "supervisor_uid":os.geteuid(),"supervisor_identity":owner_identity,
    "invocation_id":os.environ.get("INVOCATION_ID")}
def stage_owner(name):
    fd = os.open(job / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(owner_binding, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
# Both files must be synced and closed before one barrier publishes their names.
# Surviving partial creates remain tombstones; no workload precedes this barrier.
stage_owner("owner-intent.json")
stage_owner("started.json")
os.fsync(_hepta_directory_pins[-1])
child = None
cancel_requested = False

def stop_handler(signum, _frame):
    global cancel_requested
    cancel_requested = True

signal.signal(signal.SIGTERM, stop_handler)
signal.signal(signal.SIGINT, stop_handler)
# systemd has already applied Nice=; only the detached path needs an adjustment.
if launch_backend == "detached" and req.get("nice"):
    try:
        os.nice(int(req["nice"]))
    except OSError:
        pass
out = open(job / "stdout.log", "ab", buffering=0)
err = open(job / "stderr.log", "ab", buffering=0)
stdin_handle = subprocess.DEVNULL
if req.get("stdin_path"):
    stdin_handle = open(job / "stdin.bin", "rb", buffering=0)
env = os.environ.copy()
env.update(req.get("env", {}))
env["HEPTA_RUNTIME_JOB_ID"] = req["job_id"]
try:
    child = subprocess.Popen(
        [req["executable"], *req.get("args", [])],
        cwd=req.get("cwd") or req.get("default_cwd"),
        env=env,
        stdin=stdin_handle,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    atomic("child.json", {
        "pid": child.pid,
        "identity": process_identity(child.pid),
    })
except Exception as exc:
    if child is not None:
        # Popen crossed the effect boundary. Keep the original child unreaped
        # until every group signal is sent, and never report a prelaunch error.
        group_signal = "submitted"
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            group_signal = "already_absent"
        except OSError:
            group_signal = "failed"
        child_reaped = False
        try:
            reap_original_child(child, 2)
            child_reaped = True
        except Exception:
            pass
        publish_terminal({
            "at_unix_ms": int(time.time() * 1000),
            "exit_code": 125,
            "supervisor_error": "child receipt publication failed after spawn",
            "effect_outcome": "unknown",
            "status_authoritative": False,
            "automatic_retry": False,
            "child_spawned": True,
            "child_pid": child.pid,
            "child_group_signal": group_signal,
            "child_reaped": child_reaped,
            "child_exit_code": child.returncode if child_reaped else None,
            "output_complete": False,
            "output_durable": False,
            "cancelled": False,
            "timed_out": False,
        })
        raise SystemExit(125)
    publish_terminal({
        "at_unix_ms": int(time.time() * 1000),
        "exit_code": 127,
        "launch_error": str(exc),
        "cancelled": False,
        "timed_out": False,
    })
    print(str(exc), file=err, flush=True)
    raise SystemExit(127)

# Operator archives retain every byte; isolated compatibility remains bounded.
# Disk failures are explicit capture errors, never silent tail eviction.
log_truncated = {"stdout": False, "stderr": False}
log_errors = {"stdout": None, "stderr": None}
log_eof = {"stdout": False, "stderr": False}
log_drain_finished = {"stdout": None, "stderr": None}
log_bytes = {"stdout": {"seen": 0, "stored": 0}, "stderr": {"seen": 0, "stored": 0}}
def drain(stream, sink, label):
    stored = 0
    try:
        while True:
            chunk = stream.read1(65536)
            if not chunk:
                log_eof[label] = True
                break
            log_bytes[label]["seen"] += len(chunk)
            keep = chunk if req.get("execution_mode") == "operator" else chunk[:max(0, 16 * 1024 * 1024 - stored)]
            if len(keep) != len(chunk):
                log_truncated[label] = True
            if log_errors[label] is None:
                try:
                    pending = memoryview(keep)
                    while pending:
                        written = sink.write(pending)
                        if written is None or written <= 0 or written > len(pending):
                            raise OSError("log write made invalid progress")
                        stored += written
                        log_bytes[label]["stored"] = stored
                        pending = pending[written:]
                except Exception as exc:
                    # Continue draining after storage failure; never deadlock the
                    # producer or publish silent success for lost output.
                    log_errors[label] = "write: " + str(exc)
    except Exception as exc:
        log_errors[label] = "read: " + str(exc)
    finally:
        try:
            stream.close()
        except Exception as exc:
            if log_errors[label] is None:
                log_errors[label] = "close: " + str(exc)
        log_drain_finished[label] = time.monotonic()

readers = None
try:
    readers = [threading.Thread(target=drain, args=(child.stdout, out, "stdout"), daemon=True),
               threading.Thread(target=drain, args=(child.stderr, err, "stderr"), daemon=True)]
    for reader in readers:
        reader.start()
except Exception as exc:
    # Reader startup is after Popen and the durable child receipt. Keep the
    # original child unreaped until the last group signal, just as for a
    # post-spawn receipt failure; this must never become a prelaunch error.
    primary_error = type(exc).__name__ + ": " + str(exc)
    cleanup_errors = []
    group_signal = "submitted"
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        group_signal = "already_absent"
    except Exception as cleanup:
        group_signal = "failed"
        cleanup_errors.append("signal: " + str(cleanup))
    child_reaped = False
    try:
        reap_original_child(child, 2)
        child_reaped = True
    except Exception as cleanup:
        cleanup_errors.append("wait: " + str(cleanup))
    for index, (label, stream) in enumerate((("stdout", child.stdout), ("stderr", child.stderr))):
        reader = readers[index] if readers is not None else None
        # ident remains set after a thread exits. Join every reader whose
        # startup is observable; do not join one without an observed ident.
        try:
            if reader is not None and reader.ident is not None:
                reader.join(timeout=2)
                if reader.is_alive():
                    cleanup_errors.append(label + ": output reader did not stop")
            else:
                stream.close()
        except Exception as cleanup:
            cleanup_errors.append(label + ": " + str(cleanup))
    try:
        publish_terminal({
            "at_unix_ms": int(time.time() * 1000),
            "exit_code": 125,
            "supervisor_error": "output reader startup failed after spawn: " + primary_error,
            "supervisor_cleanup_errors": cleanup_errors,
            "effect_outcome": "unknown",
            "status_authoritative": False,
            "automatic_retry": False,
            "child_spawned": True,
            "child_pid": child.pid,
            "child_group_signal": group_signal,
            "child_reaped": child_reaped,
            "child_exit_code": child.returncode if child_reaped else None,
            "output_complete": False,
            "output_durable": False,
            "cancelled": False,
            "timed_out": False,
        })
    except Exception as publication_error:
        # A failed error receipt must not replace the original startup error.
        raise exc from publication_error
    raise SystemExit(125)
timed_out = False
timeout = req.get("timeout_seconds")
deadline = time.monotonic() + float(timeout) if timeout else None
stop_deadline, kill_submitted = None, False
# Preserve both original join budgets while the leader remains unreaped:
# stdout gets two seconds, then stderr gets two seconds after stdout finishes.
# The absolute four-second cap also bounds any cleanup after a failed join.
leader_drain_until, leader_reader_deadline = None, None
leader_reader_index, leader_reader_expired = 0, False
leader_drain_error, leader_group_signal = None, "not_submitted"
leader_group_signal_number = None
leader_kill_submitted, leader_cancel_signalled = False, False
leader_cleanup_errors = []
exit_queue, exit_seen = None, False
def exit_observation_failed(exc):
    # A failed observer does not establish that the submitted child stopped.
    # Except for ECHILD, this owner has never reaped its original child: finish
    # every group signal before its bounded wait. ECHILD expressly removes
    # that custody; neither a saved PID nor Popen's ECHILD compatibility result
    # may then authorize signalling or be presented as a known child exit.
    primary_error = type(exc).__name__ + ": " + str(exc)
    cleanup_errors = []
    custody_retained = not isinstance(exc, ChildProcessError) and getattr(exc, "errno", None) != errno.ECHILD
    group_signal, group_signal_number, child_reaped = "not_submitted", None, False
    if custody_retained:
        group_signal, group_signal_number = "submitted", int(signal.SIGKILL)
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            group_signal = "already_absent"
        except Exception as cleanup:
            group_signal = "failed"
            cleanup_errors.append("signal: " + str(cleanup))
        try:
            reap_original_child(child, 2)
            child_reaped = True
        except Exception as cleanup:
            if isinstance(cleanup, ChildProcessError) or getattr(cleanup, "errno", None) == errno.ECHILD:
                custody_retained = False
            cleanup_errors.append("wait: " + str(cleanup))
    else:
        cleanup_errors.append("wait: original child custody unavailable; no signal or wait submitted")
    # This is a separate failure cleanup budget, never a new workload timeout
    # or a retry. One absolute join budget covers both already-started readers.
    join_deadline = time.monotonic() + 2
    for label, reader in zip(("stdout", "stderr"), readers):
        try:
            reader.join(timeout=max(0, join_deadline - time.monotonic()))
            if reader.is_alive():
                cleanup_errors.append(label + ": output reader did not stop")
        except Exception as cleanup:
            cleanup_errors.append(label + ": " + str(cleanup))
    if exit_queue is not None:
        try:
            exit_queue.close()
        except Exception as cleanup:
            cleanup_errors.append("observer close: " + str(cleanup))
    try:
        publish_terminal({
            "at_unix_ms": int(time.time() * 1000),
            "exit_code": 125,
            "supervisor_error": "child exit observation failed after spawn: " + primary_error,
            "supervisor_cleanup_errors": cleanup_errors,
            "effect_outcome": "unknown",
            "status_authoritative": False,
            "automatic_retry": False,
            "child_spawned": True,
            "child_pid": child.pid,
            "child_custody_retained": custody_retained,
            "child_group_signal": group_signal,
            "child_group_signal_number": group_signal_number,
            "child_reaped": child_reaped,
            "child_exit_code": child.returncode if child_reaped else None,
            "output_complete": False,
            "output_durable": False,
            "cancelled": bool(cancel_requested),
            "timed_out": bool(timed_out),
        })
    except Exception as publication_error:
        raise exc from publication_error
    raise SystemExit(125)

if sys.platform != "linux":
    try:
        exit_queue = select.kqueue()
        try:
            exit_queue.control([select.kevent(child.pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0, 0)
        except ProcessLookupError:
            exit_seen = True
    except Exception as exc:
        exit_observation_failed(exc)
while True:
    # waitid(WNOWAIT) / kqueue observes exit without reaping. The original
    # leader holds its PID/PGID until this one path completes all group signals.
    try:
        if sys.platform == "linux":
            exited = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        else:
            exit_seen = exit_seen or bool(exit_queue.control([], 1, 0))
            exited = True if exit_seen else None
    except Exception as exc:
        exit_observation_failed(exc)
    now = time.monotonic()
    if exited is None and deadline is not None and now >= deadline:
        timed_out = True
    stopping = timed_out or cancel_requested
    if exited is not None and not stopping and leader_drain_until is None:
        leader_reader_deadline, leader_drain_until = now + 2, now + 4
    if leader_drain_until is not None:
        if not leader_kill_submitted:
            while leader_reader_index < len(readers):
                label = ("stdout", "stderr")[leader_reader_index]
                finished = log_drain_finished[label]
                # Natural completion requires EOF and an ended thread: a read
                # failure also ends drain without releasing inherited writers.
                # A completion timestamp later than this reader's deadline
                # cannot turn an expired join into success.
                if (log_eof[label] and not readers[leader_reader_index].is_alive() and finished is not None
                        and finished <= leader_reader_deadline):
                    leader_reader_index += 1
                    if leader_reader_index < len(readers):
                        leader_reader_deadline = min(leader_drain_until, now + 2)
                    continue
                if now >= leader_reader_deadline:
                    leader_reader_expired = True
                break
            if leader_reader_index == len(readers):
                break
        elif not any(reader.is_alive() for reader in readers):
            break
        # Cancellation during this existing drain window must not renew it
        # with a fresh eight-second cancellation grace period.
        if cancel_requested and not leader_cancel_signalled and not leader_kill_submitted:
            leader_cancel_signalled = True
            # SIGTERM can close the inherited pipes immediately. Record the
            # interrupted capture before signalling, not only on escalation.
            leader_drain_error = "output drain cancelled after leader exit"
            for label in log_errors:
                if not log_eof[label]:
                    log_errors[label] = log_errors[label] or leader_drain_error
            leader_group_signal, leader_group_signal_number = "submitted", int(signal.SIGTERM)
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                leader_group_signal = "already_absent"
            except Exception as cleanup:
                leader_group_signal = "failed"
                leader_cleanup_errors.append("signal: " + str(cleanup))
        if leader_reader_expired and not leader_kill_submitted:
            leader_kill_submitted = True
            leader_drain_error = leader_drain_error or "output drain deadline exceeded after leader exit"
            expired_label = ("stdout", "stderr")[leader_reader_index]
            log_errors[expired_label] = log_errors[expired_label] or leader_drain_error
            for label in log_errors:
                if not log_eof[label]:
                    log_errors[label] = log_errors[label] or leader_drain_error
            leader_group_signal, leader_group_signal_number = "submitted", int(signal.SIGKILL)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                leader_group_signal = "already_absent"
            except Exception as cleanup:
                leader_group_signal = "failed"
                leader_cleanup_errors.append("signal: " + str(cleanup))
        if now >= leader_drain_until:
            # A late stderr timeout may leave no join time. Signal while the
            # original leader is still held, then report any undrained reader;
            # never grant another interval or claim cleanup completed.
            break
    elif stopping:
        if stop_deadline is None:
            stop_deadline = now + 8
            try: os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError: pass
        elif now >= stop_deadline and not kill_submitted:
            kill_submitted = True
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        if exited is not None and (all(log_eof.values()) or now >= stop_deadline):
            break
    time.sleep(.05)
try:
    # Every loop exit already observed the original leader's exit. Consume its
    # actual status once, without creating another child-wait interval.
    reap_original_child(child, 0)
except Exception as exc:
    # This is after the final reap boundary, unlike observer failures above.
    # A failed final wait grants no further signal or wait authority: ECHILD
    # may mean the original identity is already gone. Never rescue by old PGID.
    cleanup_errors = list(leader_cleanup_errors)
    # An existing leader drain deadline also bounds this error path, including
    # the zero remaining time after expiry; do not grant another two seconds.
    join_deadline = leader_drain_until if leader_drain_until is not None else time.monotonic() + 2
    for label, reader in zip(("stdout", "stderr"), readers):
        try:
            reader.join(timeout=max(0, join_deadline - time.monotonic()))
            if reader.is_alive():
                cleanup_errors.append(label + ": output reader did not stop")
        except Exception as cleanup:
            cleanup_errors.append(label + ": " + str(cleanup))
    if exit_queue is not None:
        try:
            exit_queue.close()
        except Exception as cleanup:
            cleanup_errors.append("observer close: " + str(cleanup))
    terminal = {
        "at_unix_ms": int(time.time() * 1000),
        "exit_code": 125,
        "supervisor_error": "final child wait failed after exit observation: " + type(exc).__name__ + ": " + str(exc),
        "supervisor_cleanup_errors": cleanup_errors,
        "effect_outcome": "unknown",
        "status_authoritative": False,
        "automatic_retry": False,
        "child_spawned": True,
        "child_pid": child.pid,
        "child_reaped": False,
        "child_exit_code": None,
        "output_complete": False,
        "output_durable": False,
        "log_truncated": log_truncated,
        "log_errors": log_errors,
        "log_bytes": log_bytes,
        "log_synced": {"stdout": False, "stderr": False},
        "cancelled": bool(cancel_requested),
        "timed_out": bool(timed_out),
    }
    if leader_drain_error is not None:
        terminal.update({
            "prior_output_drain_error": leader_drain_error,
            "child_group_signal": leader_group_signal,
            "child_group_signal_number": leader_group_signal_number,
        })
    try:
        publish_terminal(terminal)
    except Exception as publication_error:
        raise exc from publication_error
    raise SystemExit(125)
if exit_queue is not None: exit_queue.close()
rc = 124 if timed_out else child.returncode
log_synced = {"stdout": False, "stderr": False}
for label, reader, sink in zip(("stdout", "stderr"), readers, (out, err)):
    remaining = max(0, leader_drain_until - time.monotonic()) if leader_drain_until is not None else 2
    reader.join(timeout=remaining)
    if reader.is_alive():
        log_errors[label] = log_errors[label] or "output drain deadline exceeded"
        if leader_drain_error is not None:
            leader_cleanup_errors.append(label + ": output reader did not stop")
        continue
    try:
        # One barrier per completed stream, never per chunk. A durable exit
        # receipt must not precede the output bytes whose completion it claims.
        sink.flush()
        os.fsync(sink.fileno())
        log_synced[label] = True
    except Exception as exc:
        log_errors[label] = log_errors[label] or "sync: " + str(exc)
output_complete = leader_drain_error is None and all(log_eof.values()) and not any(log_errors.values()) and not any(log_truncated.values())
output_durable = output_complete and all(log_synced.values())
terminal = {
    "at_unix_ms": int(time.time() * 1000),
    "exit_code": int(rc),
    "cancelled": bool(cancel_requested),
    "timed_out": bool(timed_out),
    "log_truncated": log_truncated,
    "log_errors": log_errors,
    "log_bytes": log_bytes,
    "output_complete": output_complete,
    "output_durable": output_durable,
    "log_synced": log_synced,
}
if leader_drain_error is not None:
    # EOF after terminating an inherited writer cannot restore successful
    # capture or establish which external effects that writer performed.
    terminal.update({
        "exit_code": 125,
        "supervisor_error": leader_drain_error,
        "supervisor_cleanup_errors": leader_cleanup_errors,
        "effect_outcome": "unknown",
        "status_authoritative": False,
        "automatic_retry": False,
        "child_spawned": True,
        "child_pid": child.pid,
        "child_group_signal": leader_group_signal,
        "child_group_signal_number": leader_group_signal_number,
        "child_reaped": True,
        "child_exit_code": child.returncode,
    })
publish_terminal(terminal)
supervisor_rc = 125 if leader_drain_error is not None else rc if output_durable or rc != 0 else 74
raise SystemExit(int(supervisor_rc) if 0 <= int(supervisor_rc) <= 255 else 1)
