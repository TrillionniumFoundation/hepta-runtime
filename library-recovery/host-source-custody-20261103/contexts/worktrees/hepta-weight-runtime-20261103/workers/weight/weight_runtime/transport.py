"""JSONL transports, owner-bounded lifetime and durable request idempotency."""
import argparse
import ctypes
from contextlib import contextmanager, redirect_stdout
import gc
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import threading
import time

from . import PROTOCOL_VERSION
from .artifacts import PathPolicy, atomic_create, file_sha256
from .errors import canonical, digest, identifier, integer, loads, need, WeightError
from .session import Session

MAX_MESSAGE_BYTES = 1048576


@contextmanager
def model_logs_to_stderr():
    """Redirect Python and native-library stdout without corrupting the JSONL channel."""
    sys.stdout.flush()
    libc = ctypes.CDLL(None)
    fflush = libc.fflush
    fflush.argtypes = [ctypes.c_void_p]
    fflush.restype = ctypes.c_int
    fflush(None)
    saved_fd = os.dup(1)
    try:
        os.dup2(2, 1)
        with redirect_stdout(sys.stderr):
            yield
    finally:
        sys.stderr.flush()
        fflush(None)
        os.dup2(saved_fd, 1)
        os.close(saved_fd)


def failure(request_id, code, message, details=None):
    return {"id": request_id, "ok": False, "error": {"code": code, "message": message, "details": details or {}}}


def read_line(stream):
    data = stream.readline(MAX_MESSAGE_BYTES + 1)
    need(data and len(data) <= MAX_MESSAGE_BYTES and data.endswith(b"\n"),
         "MESSAGE_LIMIT", "Expected one newline-terminated JSON message up to 1 MiB")
    value = loads(data)
    need(isinstance(value, dict), "INVALID_REQUEST", "Request must be an object")
    return value


def response_bytes(value):
    encoded = canonical(value) + b"\n"
    need(len(encoded) <= MAX_MESSAGE_BYTES, "MESSAGE_LIMIT", "Response too large; use retained views")
    return encoded


def hard_exit(code, reason):
    os.write(2, canonical({"event": reason, "exit_code": code}) + b"\n")
    os._exit(code)


class Deadline:
    def __init__(self, milliseconds):
        self.timer = threading.Timer(milliseconds / 1000, hard_exit, (124, "request_deadline_exceeded"))
        self.timer.daemon = True

    def __enter__(self):
        self.timer.start()
        return self

    def __exit__(self, *_):
        self.timer.cancel()


class Dispatcher:
    def __init__(self, session_id):
        self.session = Session(session_id)
        self.ledger = None
        self.unknown_pending = []

    def _prepare_ledger(self, request):
        if self.ledger is None:
            need(request["op"] == "open", "SESSION_STATE", "First operation must be open")
            params = request["params"]
            policy = PathPolicy(params["input_roots"], params["output_root"])
            self.ledger = policy.output / "requests"
            self.ledger.mkdir(exist_ok=True, mode=0o700)

    def _abort_open(self):
        """Failed admission cannot leave a callable model, even if cleanup also fails."""
        try:
            with model_logs_to_stderr():
                self.session.close({})
        except Exception as exc:
            # Keep the original admission error, but retain cleanup failure in worker logs.
            try:
                os.write(2, canonical({"event": "failed_open_cleanup_error",
                                       "exception_type": type(exc).__name__,
                                       "message": str(exc)[:2048]}) + b"\n")
            except OSError:
                pass
        finally:
            self.session.closed = True
            self.session.provider = self.session.store = self.session.policy = None
            self.session.open_spec_id = None

    def _restore_counts(self):
        # Restore consumed budgets before loading a model; a failed reload cannot reset them.
        for path in self.ledger.glob("*.done.json"):
            entry = loads(path.read_bytes())
            counts = entry.get("counts", {})
            need(isinstance(counts, dict), "INVALID_LEDGER", "Invalid retained operation counters")
            for name in ("forward_examples", "patch_candidates"):
                value = integer(counts.get(name, 0), "retained " + name)
                setattr(self.session, name, max(getattr(self.session, name), value))
        self.unknown_pending = [p.name for p in self.ledger.glob("*.pending.json")
                                if not p.with_name(p.name.replace(".pending.json", ".done.json")).exists()]

    def handle(self, request):
        request_id = request.get("id")
        if not isinstance(request_id, str) or len(request_id) > 128:
            request_id = None
        opening = opened = False
        try:
            identifier(request_id, "request id")
            need(set(request) <= {"id", "op", "session_id", "params"}, "INVALID_REQUEST", "Unknown request fields")
            need(request.get("session_id", self.session.session_id) == self.session.session_id,
                 "SESSION_IDENTITY", "Request session_id differs")
            need(isinstance(request.get("op"), str) and isinstance(request.get("params", {}), dict), "INVALID_REQUEST", "Invalid op/params")
            request = {**request, "params": request.get("params", {})}
            self._prepare_ledger(request)
            key, request_hash = digest(request_id), digest(request)
            pending, done = self.ledger / (key + ".pending.json"), self.ledger / (key + ".done.json")
            if done.exists():
                saved = loads(done.read_bytes())
                need(saved["request_sha256"] == request_hash, "IDEMPOTENCY_CONFLICT", "Request id was used with different content")
                if request["op"] == "open" and self.session.provider is None and not self.session.closed:
                    opening = True
                    self._restore_counts()
                    if saved["response"]["ok"]:
                        with model_logs_to_stderr():
                            result = self.session.open(request["params"])
                        for field in ("model_id", "backend_id", "open_spec_id"):
                            need(result[field] == saved["response"]["result"][field],
                                 "IDENTITY_MISMATCH", "Restored session identity differs", field=field)
                        opened = True
                return saved["response"]
            if pending.exists():
                saved = loads(pending.read_bytes())
                need(saved["request_sha256"] == request_hash, "IDEMPOTENCY_CONFLICT", "Pending request id has different content")
                raise WeightError("UNKNOWN_OPERATION_STATE", "An earlier attempt has no completion receipt; it will not be rerun", {"request_id": request_id})
            need(not self.unknown_pending or request["op"] in ("inspect", "query", "close"),
                 "UNKNOWN_OPERATION_STATE", "Recovered session has unresolved operations; use a new experiment for computation")
            atomic_create(pending, canonical({"request_sha256": request_hash, "request": request,
                                             "started_at_ms": int(time.time() * 1000)}) + b"\n")
            started, cpu_started = time.monotonic(), time.process_time()
            opening = request["op"] == "open"
            try:
                with model_logs_to_stderr():
                    result = self.session.dispatch(request["op"], request["params"])
                result["cost"] = {"worker_wall_seconds": time.monotonic() - started,
                                  "worker_cpu_seconds": time.process_time() - cpu_started,
                                  "forward_examples_total": self.session.forward_examples,
                                  "patch_candidates_total": self.session.patch_candidates}
                result["session_id"] = self.session.session_id
                response = {"id": request_id, "ok": True, "result": result}
                response_bytes(response)
            except WeightError as exc:
                response = {"id": request_id, "ok": False, "error": exc.as_dict()}
            except (KeyError, ValueError, TypeError, IndexError, AttributeError) as exc:
                response = failure(request_id, "INVALID_ARGUMENT", str(exc)[:2048])
            except Exception as exc:
                response = failure(request_id, "MODEL_EXECUTION_ERROR", str(exc)[:2048], {"exception_type": type(exc).__name__})
            atomic_create(done, canonical({"request_sha256": request_hash, "response": response,
                                          "counts": {"forward_examples": self.session.forward_examples,
                                                     "patch_candidates": self.session.patch_candidates},
                                          "completed_at_ms": int(time.time() * 1000)}) + b"\n")
            opened = opening and response["ok"]
            return response
        except WeightError as exc:
            return {"id": request_id, "ok": False, "error": exc.as_dict()}
        except (KeyError, ValueError, TypeError, OSError) as exc:
            return failure(request_id, "INVALID_REQUEST", str(exc)[:2048])
        except Exception as exc:
            return failure(request_id, "MODEL_EXECUTION_ERROR", str(exc)[:2048],
                           {"exception_type": type(exc).__name__})
        finally:
            if opening and not opened:
                self._abort_open()


def request_timeout(request, maximum):
    params = request.get("params", {})
    need(isinstance(params, dict), "INVALID_REQUEST", "params must be an object")
    return integer(params.get("timeout_ms", min(120000, maximum)), "timeout_ms", 1, maximum)


def memory_watch(limit, stop):
    while not stop.wait(0.25):
        try:
            resident = int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
            if resident > limit:
                hard_exit(125, "resident_memory_budget_exceeded")
        except (OSError, ValueError, IndexError):
            return


def serve(args):
    first = read_line(sys.stdin.buffer)
    need(first.get("op") == "open", "SESSION_STATE", "Daemon startup requires one open request")
    identifier(args.session_id, "session_id")
    params = first["params"]
    policy = PathPolicy(params["input_roots"], params["output_root"])
    path = Path(args.socket)
    need(path.is_absolute() and path.parent.resolve() == policy.output.parent,
         "PATH_DENIED", "Socket must be a sibling of the owner-injected artifact directory")
    need(len(os.fsencode(path)) < 104, "SOCKET_PATH_LIMIT", "Unix socket path is too long")
    if path.exists() or path.is_symlink():
        need(not path.is_symlink() and stat.S_ISSOCK(path.stat().st_mode), "INVALID_PATH", "Existing socket path has wrong type")
        test = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            test.settimeout(0.2)
            test.connect(str(path))
        except (ConnectionRefusedError, FileNotFoundError):
            path.unlink(missing_ok=True)
        else:
            raise WeightError("SESSION_ACTIVE", "An active worker already owns this socket")
        finally:
            test.close()
    idle = integer(params.get("idle_timeout_s", 900), "idle_timeout_s", 1, 3600)
    memory = integer(params.get("max_memory_bytes", 4294967296), "max_memory_bytes", 134217728, 137438953472)
    dispatcher = Dispatcher(args.session_id)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    os.chmod(path, 0o600)
    server.listen(8)
    stop = threading.Event()
    threading.Thread(target=memory_watch, args=(memory, stop), daemon=True).start()
    lifetime = threading.Timer(args.lifetime_s, hard_exit, (124, "worker_lifetime_exceeded"))
    lifetime.daemon = True
    lifetime.start()
    try:
        with Deadline(request_timeout(first, args.max_request_ms)):
            response = dispatcher.handle(first)
        sys.stdout.buffer.write(response_bytes(response))
        sys.stdout.buffer.flush()
        if not response["ok"]:
            return 1
        last_activity = time.monotonic()
        while not dispatcher.session.closed:
            remaining = idle - (time.monotonic() - last_activity)
            if remaining <= 0:
                os.write(2, canonical({"event": "idle_timeout", "session_id": args.session_id}) + b"\n")
                break
            server.settimeout(min(remaining, 1))
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            with connection:
                if hasattr(socket, "SO_PEERCRED"):
                    _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid != os.getuid():
                        connection.sendall(response_bytes(failure(None, "PEER_DENIED", "Socket peer UID differs")))
                        continue
                connection.settimeout(5)
                try:
                    with connection.makefile("rb") as incoming:
                        request = read_line(incoming)
                    with Deadline(request_timeout(request, args.max_request_ms)):
                        response = dispatcher.handle(request)
                except WeightError as exc:
                    response = {"id": None, "ok": False, "error": exc.as_dict()}
                except (OSError, ValueError) as exc:
                    response = failure(None, "TRANSPORT_ERROR", str(exc))
                try:
                    connection.sendall(response_bytes(response))
                except (BrokenPipeError, ConnectionResetError):
                    pass  # Completion is durable even if the requesting client disconnected.
                last_activity = time.monotonic()
        dispatcher.session.close({})
        gc.collect()
        return 0
    finally:
        lifetime.cancel()
        stop.set()
        server.close()
        path.unlink(missing_ok=True)


def client(args):
    request = read_line(sys.stdin.buffer)
    deadline = time.monotonic() + args.connect_timeout_ms / 1000
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        while True:
            try:
                connection.settimeout(min(1.0, args.timeout_ms / 1000))
                connection.connect(args.socket)
                break
            except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
                if time.monotonic() >= deadline:
                    raise WeightError("CONNECT_TIMEOUT", "Worker socket did not become available")
                time.sleep(0.05)
        connection.settimeout(args.timeout_ms / 1000)
        connection.sendall(response_bytes(request))
        with connection.makefile("rb") as incoming:
            response = read_line(incoming)
        need(response.get("id") in (None, request.get("id")), "PROTOCOL_ERROR", "Response id differs")
    except socket.timeout:
        response = failure(request.get("id"), "REQUEST_TIMEOUT_UNKNOWN", "Client timed out; inspect durable operation before retrying")
    except WeightError as exc:
        response = {"id": request.get("id"), "ok": False, "error": exc.as_dict()}
    except OSError as exc:
        response = failure(request.get("id"), "TRANSPORT_UNKNOWN", str(exc))
    finally:
        connection.close()
    sys.stdout.buffer.write(response_bytes(response))
    sys.stdout.buffer.flush()
    return 0 if response.get("ok") else 1


def stdio(args):
    dispatcher = Dispatcher(args.session_id)
    while True:
        data = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 1)
        if not data:
            return 0
        try:
            need(len(data) <= MAX_MESSAGE_BYTES and data.endswith(b"\n"), "MESSAGE_LIMIT", "Invalid JSONL frame")
            request = loads(data)
            need(isinstance(request, dict), "INVALID_REQUEST", "Expected object")
            with Deadline(request_timeout(request, args.max_request_ms)):
                response = dispatcher.handle(request)
        except WeightError as exc:
            response = {"id": None, "ok": False, "error": exc.as_dict()}
        sys.stdout.buffer.write(response_bytes(response))
        sys.stdout.buffer.flush()
        if dispatcher.session.closed:
            return 0


def package_identity(entry):
    entry = Path(entry).resolve()
    sources = [entry] + sorted((entry.parent / "weight_runtime").glob("*.py"))
    return {"worker_sha256": file_sha256(entry),
            "package_sha256": digest({p.relative_to(entry.parent).as_posix(): file_sha256(p) for p in sources}),
            "protocol": PROTOCOL_VERSION}


def main(entry):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--serve", action="store_true")
    mode.add_argument("--client", action="store_true")
    mode.add_argument("--stdio", action="store_true")
    mode.add_argument("--print-identity", action="store_true")
    parser.add_argument("--socket")
    parser.add_argument("--session-id", default="local")
    parser.add_argument("--timeout-ms", type=int, default=120000)
    parser.add_argument("--connect-timeout-ms", type=int, default=30000)
    parser.add_argument("--max-request-ms", type=int, default=600000)
    parser.add_argument("--lifetime-s", type=int, default=1800)
    parser.add_argument("--expected-worker-sha256")
    parser.add_argument("--expected-package-sha256")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        identity = package_identity(entry)
        for field in ("worker_sha256", "package_sha256"):
            expected = getattr(args, "expected_" + field)
            need(expected is None or expected == identity[field], "IDENTITY_MISMATCH", "Worker code identity differs", field=field)
        integer(args.timeout_ms, "timeout_ms", 1, 600000)
        integer(args.connect_timeout_ms, "connect_timeout_ms", 1, 600000)
        integer(args.max_request_ms, "max_request_ms", 1, 600000)
        integer(args.lifetime_s, "lifetime_s", 1, 7200)
        if args.print_identity:
            sys.stdout.buffer.write(canonical(identity) + b"\n")
            return 0
        if args.client or args.serve:
            need(isinstance(args.socket, str), "INVALID_ARGUMENT", "--socket is required")
        return client(args) if args.client else serve(args) if args.serve else stdio(args)
    except WeightError as exc:
        sys.stdout.buffer.write(response_bytes({"id": None, "ok": False, "error": exc.as_dict()}))
        return 1
    except OSError as exc:
        sys.stdout.buffer.write(response_bytes(failure(None, "TRANSPORT_UNAVAILABLE", str(exc))))
        return 1
    except (KeyError, TypeError, ValueError) as exc:
        sys.stdout.buffer.write(response_bytes(failure(None, "INVALID_REQUEST", str(exc))))
        return 1
