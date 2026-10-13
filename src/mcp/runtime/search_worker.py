# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Private bounded native searches; no shell, executable or arbitrary target input."""
import contextlib
import fcntl
import json
import os
import resource
import signal
import stat
import sys
import time
import unicodedata

TERMINAL = {"completed", "limited", "cancelled", "failed", "interrupted"}
CAPS = {"entries": 10000, "results": 1000, "bytes": 64 * 1024 * 1024,
        "seconds": 30, "depth": 64, "file_bytes": 4 * 1024 * 1024,
        "result_bytes": 2 * 1024 * 1024, "jobs": 1024, "active": 8}
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


class StopSearch(Exception):
    def __init__(self, state, reason):
        self.state, self.reason = state, reason


def absolute(path):
    if not isinstance(path, str) or not path.startswith("/") or len(path.encode()) > 4096:
        raise ValueError("absolute path of at most 4096 bytes required")
    if any(x in path for x in ("\x00", "\n", "\r")) or any(x in (".", "..") for x in path.split("/")):
        raise ValueError("unsafe path component")
    return path.rstrip("/") or "/"


def private(fd):
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("search state must be owned private mode 0700")


def open_dir(path, create=False):
    path = absolute(path)
    fd = os.open("/", FLAGS | os.O_DIRECTORY)
    try:
        for name in path.split("/"):
            if not name:
                continue
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            next_fd = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_json(fd, name, value):
    temporary = "." + name + "." + os.urandom(8).hex()
    output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=fd)
    try:
        data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
        with os.fdopen(output, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=fd)


def read_json(fd, name):
    file_fd = os.open(name, FLAGS, dir_fd=fd)
    with os.fdopen(file_fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("ordinary search state file required")
        data = handle.read(16385)
        if len(data) > 16384:
            raise ValueError("oversize search state")
        return json.loads(data)


def job_id(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("invalid search identity")
    return value


def authorized_root(request):
    root = absolute(request["root"])
    roots = [absolute(p) for p in request["allowed_roots"]]
    if not any(root == p or p == "/" or root.startswith(p + "/") for p in roots):
        raise ValueError("search root not authorized")
    return root


def protected_path(target, prefixes):
    # macOS volumes may alias names by case and canonical Unicode normalization.
    # Conservatively deny such aliases even when a particular volume is case-sensitive.
    if sys.platform == "darwin":
        target = unicodedata.normalize("NFD", target).casefold()
        prefixes = [unicodedata.normalize("NFD", prefix).casefold() for prefix in prefixes]
    return any(target == prefix or prefix == "/" or target.startswith(prefix + "/") for prefix in prefixes)


def reconcile(fd, record):
    # Never reattach or signal a PID whose identity cannot be proved after restart.
    if record["state"] not in TERMINAL and time.time() > record["deadline"] + 5:
        record.update(state="interrupted", reason="worker_deadline_without_terminal_receipt", snapshot_ready=False)
        write_json(fd, "record.json", record)
    return record


def snapshot(fd, record, cursor, limit):
    if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor < 0 or cursor > CAPS["results"]:
        raise ValueError("invalid search cursor")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 32:
        raise ValueError("search page limit must be 1..32")
    response = {"state": record["state"], "reason": record.get("reason"),
                "snapshot_ready": record.get("snapshot_ready", False),
                "statistics": record.get("statistics", {}), "results": [], "next_cursor": None}
    if not response["snapshot_ready"]:
        return response
    count = record["statistics"]["results"]
    if cursor > count:
        raise ValueError("cursor exceeds terminal snapshot")
    result_fd = os.open("results.ndjson", FLAGS, dir_fd=fd)
    page_bytes = 0
    with os.fdopen(result_fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > CAPS["result_bytes"]:
            raise ValueError("invalid terminal snapshot")
        for index, line in enumerate(handle):
            if len(line) > 8192:
                raise ValueError("invalid snapshot row size")
            if cursor <= index < cursor + limit:
                if page_bytes + len(line) > 65536:
                    break
                response["results"].append(json.loads(line))
                page_bytes += len(line)
            if index + 1 >= cursor + limit:
                break
    next_cursor = cursor + len(response["results"])
    if next_cursor < count:
        response["next_cursor"] = next_cursor
    return response


def search(fd, request, record):
    stats = {"entries": 0, "files": 0, "bytes": 0, "results": 0,
             "skipped_symlinks": 0, "skipped_special": 0, "skipped_large": 0,
             "skipped_binary_or_non_utf8": 0, "skipped_hardlinks": 0, "skipped_protected": 0, "unreadable": 0}
    budget = request["limits"]
    encoded = request["query"].encode("utf-8")
    if not encoded or len(encoded) > 512 or b"\n" in encoded or b"\r" in encoded or b"\0" in encoded:
        raise ValueError("query must contain 1..512 UTF-8 bytes and no NUL/newlines")
    for key, cap in (("entries", CAPS["entries"]), ("results", CAPS["results"]),
                     ("bytes", CAPS["bytes"]), ("seconds", CAPS["seconds"])):
        if not isinstance(budget[key], int) or isinstance(budget[key], bool) or not 1 <= budget[key] <= cap:
            raise ValueError("invalid resource budget")
    if request["kind"] not in ("files", "content"):
        raise ValueError("unknown search kind")
    root = authorized_root(request)
    protected = [absolute(path) for path in request.get("protected_roots", [])]
    root_fd = open_dir(root)
    result_fd = os.open("results.ndjson", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=fd)
    result_bytes = 0
    start = time.monotonic()

    def checkpoint():
        if time.monotonic() - start >= budget["seconds"]:
            raise StopSearch("limited", "time_limit")
        try:
            os.stat("cancel", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise StopSearch("cancelled", "owner_requested_stop")

    def alarm(_number, _frame):
        raise StopSearch("limited", "time_limit")

    def append(value):
        nonlocal result_bytes
        checkpoint()
        data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        if len(data) > 8192 or result_bytes + len(data) > CAPS["result_bytes"]:
            raise StopSearch("limited", "result_bytes_limit")
        output.write(data)
        result_bytes += len(data)
        stats["results"] += 1
        if stats["results"] >= budget["results"]:
            raise StopSearch("limited", "result_limit")

    def read_content(directory_fd, name, relative):
        checkpoint()
        try:
            file_fd = os.open(name, FLAGS | os.O_NONBLOCK, dir_fd=directory_fd)
        except OSError:
            stats["unreadable"] += 1
            return
        with os.fdopen(file_fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                stats["skipped_special"] += 1
                return
            if info.st_nlink != 1:
                stats["skipped_hardlinks"] += 1
                return
            if info.st_size > CAPS["file_bytes"]:
                stats["skipped_large"] += 1
                return
            stats["files"] += 1
            remaining = min(CAPS["file_bytes"] + 1, budget["bytes"] - stats["bytes"])
            if remaining <= 0:
                raise StopSearch("limited", "read_bytes_limit")
            chunks = []
            while remaining > 0:
                checkpoint()
                piece = source.read(min(65536, remaining))
                if not piece:
                    break
                chunks.append(piece)
                remaining -= len(piece)
                stats["bytes"] += len(piece)
            if stats["bytes"] >= budget["bytes"]:
                raise StopSearch("limited", "read_bytes_limit")
            data = b"".join(chunks)
            if len(data) > CAPS["file_bytes"]:
                stats["skipped_large"] += 1
                return
            after = os.fstat(source.fileno())
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                stats["unreadable"] += 1
                return
            try:
                if b"\0" in data:
                    raise UnicodeError()
                content = data.decode("utf-8")
            except UnicodeError:
                stats["skipped_binary_or_non_utf8"] += 1
                return
            # Line-at-a-time scanning avoids a huge list for files containing millions of short lines.
            import io
            for number, line in enumerate(io.StringIO(content), 1):
                checkpoint()
                if request["query"] in line:
                    preview = line.rstrip("\r\n").encode("utf-8")[:512].decode("utf-8", "ignore")
                    append({"path": relative, "line": number, "preview": preview,
                            "preview_truncated": len(line.rstrip("\r\n").encode("utf-8")) > 512})

    def walk(directory_fd, relative, depth):
        checkpoint()
        if depth > CAPS["depth"]:
            raise StopSearch("limited", "depth_limit")
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                checkpoint()
                if stats["entries"] >= budget["entries"]:
                    raise StopSearch("limited", "entry_limit")
                stats["entries"] += 1
                name = entry.name
                if not request.get("include_hidden", False) and name.startswith("."):
                    continue
                if len(os.fsencode(name)) > 255:
                    stats["unreadable"] += 1
                    continue
                try:
                    name.encode("utf-8")
                except UnicodeError:
                    stats["unreadable"] += 1
                    continue
                path = name if not relative else relative + "/" + name
                target = root.rstrip("/") + "/" + path
                if protected_path(target, protected):
                    stats["skipped_protected"] += 1
                    continue
                if len(path.encode("utf-8", "surrogateescape")) > 1024:
                    raise StopSearch("limited", "relative_path_limit")
                try:
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        stats["skipped_symlinks"] += 1
                    elif stat.S_ISDIR(info.st_mode):
                        child = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=directory_fd)
                        try:
                            walk(child, path, depth + 1)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        # Opening descriptor-bound paths prevents symlink exchange from escaping the root.
                        if request["kind"] == "files":
                            file_fd = os.open(name, FLAGS | os.O_NONBLOCK, dir_fd=directory_fd)
                            try:
                                opened = os.fstat(file_fd)
                                if opened.st_nlink != 1:
                                    stats["skipped_hardlinks"] += 1
                                elif stat.S_ISREG(opened.st_mode) and request["query"] in path:
                                    append({"path": path})
                            finally:
                                os.close(file_fd)
                        else:
                            read_content(directory_fd, name, path)
                    else:
                        stats["skipped_special"] += 1
                except OSError:
                    stats["unreadable"] += 1

    signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, budget["seconds"])
    state, reason = "completed", None
    try:
        with os.fdopen(result_fd, "wb") as output:
            try:
                walk(root_fd, "", 0)
            except StopSearch as stopped:
                state, reason = stopped.state, stopped.reason
            except BaseException:
                state, reason = "failed", "native_worker_error"
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                output.flush()
                os.fsync(output.fileno())
    finally:
        os.close(root_fd)
    record.update(state=state, reason=reason, snapshot_ready=True, statistics=stats,
                  finished_unix_ms=int(time.time() * 1000), result_bytes=result_bytes)
    write_json(fd, "record.json", record)


def main(request):
    identity = job_id(request["search_id"])
    owner = job_id(request["owner"])
    state_path = absolute(request["state_dir"]) + "/search"
    base = open_dir(state_path, create=True)
    private(base)
    lock_fd = os.open(".lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=base)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        if request["action"] == "start":
            authorized_root(request)
            # Limit both permanent state growth and concurrent detached workers.
            total = active = owned = 0
            with os.scandir(base) as entries:
                for entry in entries:
                    if entry.name.startswith("."):
                        continue
                    total += 1
                    if total >= CAPS["jobs"]:
                        raise ValueError("search receipt quota reached")
                    other_fd = os.open(entry.name, FLAGS | os.O_DIRECTORY, dir_fd=base)
                    try:
                        other = reconcile(other_fd, read_json(other_fd, "record.json"))
                    finally:
                        os.close(other_fd)
                    if other["state"] not in TERMINAL:
                        active += 1
                        owned += other["owner"] == owner
            if active >= CAPS["active"] or owned >= 4:
                raise ValueError("active search quota reached")
            os.mkdir(identity, 0o700, dir_fd=base)
        fd = os.open(identity, FLAGS | os.O_DIRECTORY, dir_fd=base)
        private(fd)
        try:
            if request["action"] == "start":
                record = {"owner": owner, "state": "running", "snapshot_ready": False,
                          "deadline": time.time() + request["limits"]["seconds"], "statistics": {}}
                write_json(fd, "record.json", record)
                child = os.fork()
                if child == 0:
                    os.close(lock_fd)
                    os.setsid()
                    if os.fork() != 0:
                        os._exit(0)
                    devnull = os.open("/dev/null", os.O_RDWR)
                    for stream in (0, 1, 2):
                        os.dup2(devnull, stream)
                    if devnull > 2:
                        os.close(devnull)
                    try:
                        # Darwin refuses RLIMIT_AS; its buffers remain structurally bounded by the same file/read/result caps.
                        if sys.platform == "linux":
                            resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
                        resource.setrlimit(resource.RLIMIT_CPU, (10, 12))
                        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
                        search(fd, request, record)
                    except BaseException:
                        record.update(state="failed", reason="native_worker_setup_error", snapshot_ready=False)
                        with contextlib.suppress(BaseException):
                            write_json(fd, "record.json", record)
                    os._exit(0)
                os.waitpid(child, 0)
                return {"state": "running", "snapshot_ready": False}
            record = reconcile(fd, read_json(fd, "record.json"))
            if record["owner"] != owner:
                raise ValueError("search unavailable to this session")
            if request["action"] == "stop":
                if record["state"] not in TERMINAL:
                    cancel = os.open("cancel", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=fd)
                    os.fsync(cancel)
                    os.close(cancel)
                    os.fsync(fd)
                return {"state": record["state"], "stop_requested": record["state"] not in TERMINAL}
            if request["action"] == "results":
                return snapshot(fd, record, request.get("cursor", 0), request.get("limit", 32))
            if request["action"] == "status":
                return {"state": record["state"], "reason": record.get("reason"),
                        "snapshot_ready": record.get("snapshot_ready", False),
                        "statistics": record.get("statistics", {})}
            raise ValueError("unknown search action")
        finally:
            os.close(fd)
    finally:
        os.close(lock_fd)
        os.close(base)


if __name__ == "__main__":
    try:
        print(json.dumps(main(json.load(sys.stdin)), ensure_ascii=True, separators=(",", ":")))
    except Exception:
        # Paths and filesystem exceptions must not leak through denied references.
        print(json.dumps({"error": "native search request refused"}), file=sys.stderr)
        sys.exit(1)
