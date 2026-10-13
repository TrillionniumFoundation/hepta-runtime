// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Durable host-bound job identities, recovery and log pagination.
use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;

use super::config::{check_environment, check_execution, runtime_config, valid_name};
use super::config::{ExecutionMode, Platform};
use super::ssh::{run_jobctl, run_python_json};

static JOB_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static START_LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
static AUDIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const MAX_STDIN_BYTES: usize = 1024 * 1024;
const MAX_LOG_READ_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartParams {
	/// Configured host name, never a raw SSH destination.
	pub host: String,
	/// Executable path or command name. Shell syntax is not accepted.
	pub executable: String,
	#[serde(default)]
	pub args: Vec<String>,
	#[serde(default)]
	pub cwd: Option<String>,
	#[serde(default)]
	pub env: BTreeMap<String, String>,
	/// Optional standard input written once at process start (max 1 MiB).
	#[serde(default)]
	pub stdin: Option<String>,
	/// Optional process timeout. The remote supervisor terminates the process group.
	#[serde(default)]
	pub timeout_seconds: Option<u64>,
	/// Reusing the same host+key returns the existing durable job instead of starting twice.
	#[serde(default)]
	pub idempotency_key: Option<String>,
	/// Non-negative Unix nice adjustment, 0..19.
	#[serde(default)]
	pub nice: Option<u8>,
	/// Optional transient systemd CPUQuota percentage, 1..1000.
	#[serde(default)]
	pub cpu_quota_percent: Option<u16>,
	/// Optional transient systemd MemoryMax in bytes.
	#[serde(default)]
	pub memory_max_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessRefParams {
	pub host: String,
	pub job_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessReadParams {
	pub host: String,
	pub job_id: String,
	#[serde(default)]
	pub stdout_offset: Option<u64>,
	#[serde(default)]
	pub stderr_offset: Option<u64>,
	/// Maximum bytes returned per stream, capped at 16 KiB with lossless byte cursors.
	#[serde(default)]
	pub limit: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessWaitParams {
	pub host: String,
	pub job_id: String,
	/// Maximum wait for this call, capped at 30 seconds.
	#[serde(default)]
	pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessCancelParams {
	pub host: String,
	pub job_id: String,
	/// Grace period before the fallback backend sends SIGKILL, capped at 30 seconds.
	#[serde(default)]
	pub grace_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessListParams {
	#[serde(default)]
	pub host: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct JobRecord {
	#[serde(default)]
	execution_mode: ExecutionMode,
	#[serde(default)]
	system_jobctl: bool,
	id: String,
	host: String,
	ssh_target: String,
	unit: String,
	remote_job_dir: String,
	executable: String,
	args: Vec<String>,
	cwd: Option<String>,
	env_keys: Vec<String>,
	created_unix_ms: u128,
	idempotency_key: Option<String>,
	request_fingerprint: u64,
	#[serde(default)]
	request_digest: Option<String>,
	#[serde(default = "default_launch_state")]
	launch_state: String,
	#[serde(default)]
	launch_error: Option<String>,
}

fn default_launch_state() -> String {
	"launched".to_string()
}

fn start_lock() -> &'static AsyncMutex<()> {
	START_LOCK.get_or_init(|| AsyncMutex::new(()))
}

fn now_ms() -> u128 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis()
}

fn next_job_id() -> String {
	let seq = JOB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
	format!("{:x}-{:x}-{:x}", now_ms(), std::process::id(), seq)
}

fn jobs_dir() -> Result<PathBuf> {
	let path = runtime_config()?.state_dir.join("jobs");
	std::fs::create_dir_all(&path)?;
	Ok(path)
}

fn record_path(id: &str) -> Result<PathBuf> {
	if !valid_name(id) {
		bail!("invalid job id `{id}`");
	}
	Ok(jobs_dir()?.join(format!("{id}.json")))
}

fn save_record(record: &JobRecord) -> Result<()> {
	let path = record_path(&record.id)?;
	let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
	let bytes = serde_json::to_vec_pretty(record)?;
	{
		let mut file = OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.open(&tmp)?;
		file.write_all(&bytes)?;
		file.sync_all()?;
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
	}
	std::fs::rename(tmp, &path)?;
	if let Some(parent) = path.parent() {
		std::fs::File::open(parent)?.sync_all()?;
	}
	Ok(())
}

fn load_record(id: &str) -> Result<JobRecord> {
	let path = record_path(id)?;
	let bytes = std::fs::read(&path).with_context(|| format!("unknown durable job `{id}`"))?;
	serde_json::from_slice(&bytes).context("corrupt durable job metadata")
}

fn all_records() -> Result<Vec<JobRecord>> {
	let mut records = Vec::new();
	for entry in std::fs::read_dir(jobs_dir()?)? {
		let entry = entry?;
		if entry.path().extension().and_then(|s| s.to_str()) != Some("json") {
			continue;
		}
		let bytes = std::fs::read(entry.path())?;
		let record = serde_json::from_slice::<JobRecord>(&bytes)
			.context("corrupt job record; refusing to lose idempotency binding")?;
		records.push(record);
	}
	records.sort_by_key(|record| record.created_unix_ms);
	Ok(records)
}

fn find_idempotent(host: &str, key: &str) -> Result<Option<JobRecord>> {
	Ok(all_records()?
		.into_iter()
		.find(|record| record.host == host && record.idempotency_key.as_deref() == Some(key)))
}

fn request_digest(params: &ProcessStartParams) -> Result<String> {
	let binding = json!({
		"host": params.host,
		"executable": params.executable,
		"args": params.args,
		"cwd": params.cwd,
		"env": params.env,
		"stdin": params.stdin,
		"timeout_seconds": params.timeout_seconds,
		"nice": params.nice,
		"cpu_quota_percent": params.cpu_quota_percent,
		"memory_max_bytes": params.memory_max_bytes,
	});
	let bytes = serde_json::to_vec(&binding)?;
	let digest = Sha256::digest(bytes);
	Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

// Retain the old prefix only for readable legacy metadata. New idempotent
// requests compare all 256 bits, and legacy bindings never silently relaunch.
fn fingerprint(params: &ProcessStartParams) -> u64 {
	request_digest(params)
		.ok()
		.and_then(|v| u64::from_str_radix(&v[..16], 16).ok())
		.unwrap_or(0)
}
fn matches_request(record: &JobRecord, params: &ProcessStartParams) -> Result<bool> {
	let expected = record.request_digest.as_ref().context(
		"legacy idempotency binding lacks a full digest; inspect existing job_id instead of relaunching",
	)?;
	Ok(*expected == request_digest(params)?)
}

fn check_ref(params: &ProcessRefParams) -> Result<JobRecord> {
	let record = load_record(&params.job_id)?;
	check_binding(&record)?;
	if record.host != params.host {
		bail!(
			"job `{}` belongs to host `{}`, not `{}`",
			params.job_id,
			record.host,
			params.host
		);
	}
	Ok(record)
}

pub(crate) fn audit(action: &str, host: &str, subject: &str, outcome: &Value) -> Result<()> {
	let path = runtime_config()?.state_dir.join("audit/events.jsonl");
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	let event = json!({
		"at_unix_ms": now_ms(),
		"action": action,
		"host": host,
		"subject": subject,
		"outcome": outcome,
	});
	let _guard = AUDIT_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow::anyhow!("audit lock poisoned"))?;
	let mut line = serde_json::to_vec(&event)?;
	line.push(b'\n');
	let mut file = OpenOptions::new().create(true).append(true).open(path)?;
	file.write_all(&line)?;
	file.sync_data()?;
	Ok(())
}

const START_CODE: &str = r#"
import fcntl, json, os, pathlib, shutil, subprocess, sys, time
req = json.load(sys.stdin)
job = pathlib.Path(req["job_dir"])
job.mkdir(parents=True, exist_ok=True)
os.chmod(job, 0o700)
launch_lock = open(job / "launch.lock", "a")
fcntl.flock(launch_lock.fileno(), fcntl.LOCK_EX)


def read_json(name):
    try:
        return json.loads((job / name).read_text(encoding="utf-8"))
    except Exception:
        return None

def atomic(name, value):
    target = job / name
    tmp = job / (name + ".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)

stdin_text = req.pop("stdin", None)
existing = read_json("request.json")
if existing is not None:
    if existing.get("job_id") != req.get("job_id") or existing.get("request_fingerprint") != req.get("request_fingerprint"):
        raise SystemExit("remote job directory is bound to a different request")
    launch = read_json("launch.json")
    exit_data = read_json("exit.json")
    started = read_json("started.json")
    if launch or exit_data:
        print(json.dumps({"ok": True, "reused_remote": True, **(launch or {"backend": "completed"})}, sort_keys=True))
        raise SystemExit(0)
    raise SystemExit("ambiguous prior launch: inspect this job; do not relaunch under another key")
else:
    if stdin_text is not None:
        stdin_path = job / "stdin.bin"
        stdin_path.write_bytes(stdin_text.encode("utf-8"))
        os.chmod(stdin_path, 0o600)
        req["stdin_path"] = str(stdin_path)
    atomic("request.json", req)
runner = r'''#!/usr/bin/env python3
import json, os, pathlib, shutil, signal, subprocess, sys, threading, time
job = pathlib.Path(__file__).resolve().parent
req = json.loads((job / "request.json").read_text(encoding="utf-8"))

def atomic(name, value):
    target = job / name
    tmp = job / (name + ".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)

def process_identity(pid):
    try:
        ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
        boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return {"kind": "proc_start_ticks", "value": boot + ":" + str(ticks)}
    except Exception:
        pass
    try:
        value = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True).strip()
        return {"kind": "ps_lstart", "value": value} if value else None
    except Exception:
        return None

os.umask(0o077)
child = None
cancel_requested = False

def stop_handler(signum, _frame):
    global cancel_requested
    cancel_requested = True
    if child is not None and child.poll() is None:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

signal.signal(signal.SIGTERM, stop_handler)
signal.signal(signal.SIGINT, stop_handler)
if req.get("nice"):
    try:
        os.nice(int(req["nice"]))
    except OSError:
        pass
atomic("started.json", {
    "at_unix_ms": int(time.time() * 1000),
    "supervisor_pid": os.getpid(),
    "supervisor_identity": process_identity(os.getpid()),
})
out = open(job / "stdout.log", "ab", buffering=0)
err = open(job / "stderr.log", "ab", buffering=0)
stdin_handle = subprocess.DEVNULL
if req.get("stdin_path"):
    stdin_handle = open(req["stdin_path"], "rb", buffering=0)
env = os.environ.copy()
env.update(req.get("env", {}))
env["HEPTA_RUNTIME_JOB_ID"] = req["job_id"]
try:
    child = subprocess.Popen(
        [req["executable"], *req.get("args", [])],
        cwd=req.get("cwd") or None,
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
    atomic("exit.json", {
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

readers = [threading.Thread(target=drain, args=(child.stdout, out, "stdout"), daemon=True),
           threading.Thread(target=drain, args=(child.stderr, err, "stderr"), daemon=True)]
for reader in readers:
    reader.start()
timed_out = False
timeout = req.get("timeout_seconds")
deadline = time.monotonic() + float(timeout) if timeout else None
stop_deadline = None
while child.poll() is None:
    now = time.monotonic()
    if deadline is not None and now >= deadline:
        timed_out = True
    if timed_out or cancel_requested:
        if stop_deadline is None:
            stop_deadline = now + 8
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        elif now >= stop_deadline:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    time.sleep(.05)
rc = 124 if timed_out else child.returncode
for label, reader in zip(("stdout", "stderr"), readers):
    reader.join(timeout=2)
    if reader.is_alive():
        log_errors[label] = log_errors[label] or "output drain deadline exceeded"
output_complete = all(log_eof.values()) and not any(log_errors.values()) and not any(log_truncated.values())
atomic("exit.json", {
    "at_unix_ms": int(time.time() * 1000),
    "exit_code": int(rc),
    "cancelled": bool(cancel_requested),
    "timed_out": bool(timed_out),
    "log_truncated": log_truncated,
    "log_errors": log_errors,
    "log_bytes": log_bytes,
    "output_complete": output_complete,
})
raise SystemExit(int(rc) if 0 <= int(rc) <= 255 else 1)
'''
runner_path = job / "runner.py"
runner_path.write_text(runner, encoding="utf-8")
os.chmod(runner_path, 0o700)
uid = os.getuid()
env = os.environ.copy()
env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus")
cmd = [
    "systemd-run", "--user", "--quiet", "--collect",
    "--unit", req["unit"],
    "--property", "KillMode=control-group",
    "--property", "TimeoutStopSec=10s",
    "--property", f"Description=Hepta Runtime job {req['job_id']}",
]
if req.get("cpu_quota_percent"):
    cmd += ["--property", f"CPUQuota={int(req['cpu_quota_percent'])}%"]
if req.get("memory_max_bytes"):
    cmd += ["--property", f"MemoryMax={int(req['memory_max_bytes'])}"]
if req.get("nice"):
    cmd += ["--property", f"Nice={int(req['nice'])}"]
if req.get("execution_mode", "isolated") != "operator":
    cmd += ["--property", "NoNewPrivileges=yes", "--property", "RestrictSUIDSGID=yes"]
if not req.get("allow_job_network", False):
    cmd += ["--property", "PrivateNetwork=yes", "--property", "RestrictAddressFamilies=AF_UNIX AF_NETLINK"]
cmd += ["--", sys.executable, str(runner_path)]
if req.get("platform", "linux") == "linux" and shutil.which("systemd-run"):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
else:
    result = subprocess.CompletedProcess(cmd, 127, "", "systemd user units unavailable on this platform")
if result.returncode == 0:
    launch = {"backend": "systemd", "unit": req["unit"], "launcher_pid": None}
else:
    if not req.get("allow_detached_fallback", False):
        atomic("launch.json", {
            "backend": "launch_failed",
            "unit": req["unit"],
            "systemd_error": result.stderr.strip(),
        })
        print(result.stderr.strip(), file=sys.stderr)
        raise SystemExit(result.returncode or 1)
    if req.get("cpu_quota_percent") or req.get("memory_max_bytes"):
        raise SystemExit("detached backend cannot enforce requested CPU/memory limits")
    process = subprocess.Popen(
        [sys.executable, str(runner_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
        env=env,
    )
    launch = {
        "backend": "detached",
        "unit": req["unit"],
        "launcher_pid": process.pid,
        "systemd_error": result.stderr.strip(),
    }
atomic("launch.json", launch)
print(json.dumps({"ok": True, **launch}, sort_keys=True))
"#;

const STATUS_CODE: &str = r#"
import json, os, pathlib, subprocess, sys, time
q = json.load(sys.stdin)
job = pathlib.Path(q["job_dir"])

def read_json(name):
    try:
        return json.loads((job / name).read_text(encoding="utf-8"))
    except Exception:
        return None

def process_identity(pid):
    try:
        ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
        boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return {"kind": "proc_start_ticks", "value": boot + ":" + str(ticks)}
    except Exception:
        pass
    try:
        value = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True).strip()
        return {"kind": "ps_lstart", "value": value} if value else None
    except Exception:
        return None

def final_status(exit_data):
    if exit_data.get("timed_out"):
        state = "timed_out"
    elif exit_data.get("cancelled"):
        state = "cancelled"
    elif int(exit_data.get("exit_code", -1)) == 0:
        state = "succeeded"
    else:
        state = "failed"
    return {"state": state, **exit_data}

def one_status():
    request = read_json("request.json")
    if not request or request.get("job_id") != q["job_id"]:
        return {"state": "unknown", "reason": "remote job metadata missing or mismatched"}
    exit_data = read_json("exit.json")
    if exit_data:
        return final_status(exit_data)
    launch = read_json("launch.json") or {}
    if launch.get("backend") == "systemd":
        uid = os.getuid()
        env = os.environ.copy()
        env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
        env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus")
        p = subprocess.run(
            ["systemctl", "--user", "show", q["unit"], "--no-pager",
             "--property=LoadState,ActiveState,SubState,Result,ExecMainPID,ExecMainCode,ExecMainStatus"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        props = {}
        for line in p.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1); props[k] = v
        # A --collect unit can disappear immediately after the runner exits.
        # Re-read the atomic exit record after querying systemd to close that race.
        exit_data = read_json("exit.json")
        if exit_data:
            return final_status(exit_data)
        active = props.get("ActiveState")
        sub = props.get("SubState")
        if active in ("active", "activating") and sub not in ("exited", "dead"):
            state = "running"
        elif active == "failed":
            state = "failed"
        elif active == "active" and sub == "exited":
            # RemainAfterExit can become visible a few microseconds before the
            # supervisor's atomic exit.json rename. systemd already has the
            # authoritative process result, so use it rather than returning a
            # false completed_unknown race.
            try:
                exit_code = int(props.get("ExecMainStatus", "-1"))
            except ValueError:
                exit_code = -1
            if props.get("ExecMainCode") == "1":
                state = "succeeded" if exit_code == 0 else "failed"
                return {"state": state, "backend": "systemd", "exit_code": exit_code, "systemd": props}
            state = "completed_unknown"
        elif props.get("LoadState") == "not-found":
            state = "finalizing"
        else:
            state = active or "unknown"
        return {"state": state, "backend": "systemd", "systemd": props}
    started = read_json("started.json") or {}
    pid = int(started.get("supervisor_pid") or launch.get("launcher_pid") or 0)
    expected = started.get("supervisor_identity")
    actual = process_identity(pid) if pid else None
    running = bool(pid and actual is not None and (expected is not None and expected == actual))
    return {"state": "running" if running else "lost", "backend": launch.get("backend", "detached"), "pid": pid, "identity": actual}

deadline = time.monotonic() + min(float(q.get("wait_seconds", 0)), 30.0)
while True:
    status = one_status()
    state = status.get("state")
    transient = state in ("running", "activating", "finalizing", "completed_unknown")
    now = time.monotonic()
    if not transient or now >= deadline:
        if now >= deadline and state in ("finalizing", "completed_unknown"):
            status["state"] = "lost"
            status["reason"] = "no exit record appeared before the wait deadline"
        status["job_id"] = q["job_id"]
        print(json.dumps(status, sort_keys=True))
        break
    time.sleep(0.1)
"#;

const READ_CODE: &str = r#"
import json, pathlib, sys
q = json.load(sys.stdin)
job = pathlib.Path(q["job_dir"])
try:
    request = json.loads((job / "request.json").read_text(encoding="utf-8"))
except Exception:
    raise SystemExit("remote job metadata missing")
if request.get("job_id") != q["job_id"]:
    raise SystemExit("remote job metadata mismatch")
limit = max(1, min(int(q.get("limit", 16384)), 16384))

def read_part(name, offset):
    path = job / name
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        size = 0
    offset = max(0, int(offset or 0))
    if offset > size: raise SystemExit("cursor exceeds log length; refusing silent rewind")
    data = b""
    if size:
        with path.open("rb") as f:
            f.seek(offset)
            data = f.read(min(limit, size - offset))
    return {
        "offset": offset,
        "next_offset": offset + len(data),
        "size": size,
        "eof": offset + len(data) >= size,
        "text": data.decode("utf-8", errors="replace"),
        "bytes_hex": data.hex(),
    }

print(json.dumps({
    "job_id": q["job_id"],
    "stdout": read_part("stdout.log", q.get("stdout_offset", 0)),
    "stderr": read_part("stderr.log", q.get("stderr_offset", 0)),
}, sort_keys=True))
"#;

const CANCEL_CODE: &str = r#"
import json, os, pathlib, signal, subprocess, sys, time
q = json.load(sys.stdin)
job = pathlib.Path(q["job_dir"])

def read_json(name):
    try:
        return json.loads((job / name).read_text(encoding="utf-8"))
    except Exception:
        return None

def atomic(name, value):
    target = job / name
    tmp = job / (name + ".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)

def process_identity(pid):
    try:
        ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
        boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return {"kind": "proc_start_ticks", "value": boot + ":" + str(ticks)}
    except Exception:
        pass
    try:
        value = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True).strip()
        return {"kind": "ps_lstart", "value": value} if value else None
    except Exception:
        return None

def command_line(pid):
    try:
        return pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    except Exception:
        try:
            return subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True).strip()
        except Exception:
            return ""

request = read_json("request.json")
if not request or request.get("job_id") != q["job_id"]:
    raise SystemExit("remote job metadata missing or mismatched")
if read_json("exit.json"):
    print(json.dumps({"job_id": q["job_id"], "result": "already_exited"}))
    raise SystemExit(0)
launch = read_json("launch.json") or {}
atomic("cancel-request.json", {"at_unix_ms": int(time.time() * 1000)})
grace = max(0.0, min(float(q.get("grace_seconds", 10)), 30.0))
result = "not_running"
if launch.get("backend") == "systemd":
    uid = os.getuid()
    env = os.environ.copy()
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus")
    p = subprocess.run(["systemctl", "--user", "stop", q["unit"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    result = "stop_requested" if p.returncode == 0 else "stop_failed"
    if p.returncode != 0:
        print(json.dumps({"job_id": q["job_id"], "result": result, "stderr": p.stderr.strip()}))
        raise SystemExit(1)
else:
    started = read_json("started.json") or {}
    pid = int(started.get("supervisor_pid") or launch.get("launcher_pid") or 0)
    expected = started.get("supervisor_identity")
    actual = process_identity(pid) if pid else None
    cmdline = command_line(pid) if pid else ""
    valid = bool(pid and actual is not None and str(job / "runner.py") in cmdline)
    valid = valid and expected is not None and expected == actual
    if not valid:
        raise SystemExit("refusing to signal PID: ownership verification failed")
    try:
        os.killpg(pid, signal.SIGTERM)
        result = "term_sent"
    except ProcessLookupError:
        result = "not_running"
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if read_json("exit.json") or not command_line(pid):
            break
        time.sleep(0.2)
    if command_line(pid) and not read_json("exit.json"):
        if process_identity(pid) != expected or str(job / "runner.py") not in command_line(pid):
            raise SystemExit("refusing SIGKILL: process identity changed")
        # The workload has its own process group. Kill it only after verifying
        # the stored child identity, before terminating the supervisor itself.
        child_record = read_json("child.json") or {}
        child_pid = int(child_record.get("pid") or 0)
        if child_pid and child_record.get("identity") == process_identity(child_pid):
            try:
                if os.getpgid(child_pid) == child_pid:
                    os.killpg(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            os.killpg(pid, signal.SIGKILL)
            result = "kill_sent"
        except ProcessLookupError:
            pass
print(json.dumps({"job_id": q["job_id"], "result": result}, sort_keys=True))
"#;

fn validate_start(params: &ProcessStartParams) -> Result<()> {
	check_execution(
		&params.host,
		&params.executable,
		&params.args,
		params.cwd.as_deref(),
		false,
	)?;
	check_environment(&params.host, &params.env)?;
	if params.args.len() > 256 {
		bail!("at most 256 arguments are allowed");
	}
	if params.env.len() > 128 {
		bail!("at most 128 environment variables are allowed");
	}
	for key in params.env.keys() {
		let valid = !key.is_empty()
			&& !key.as_bytes()[0].is_ascii_digit()
			&& key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
		if !valid {
			bail!("invalid environment variable name `{key}`");
		}
	}
	if params
		.stdin
		.as_ref()
		.is_some_and(|value| value.len() > MAX_STDIN_BYTES)
	{
		bail!("stdin exceeds the 1 MiB limit");
	}
	if params
		.timeout_seconds
		.is_some_and(|value| value == 0 || value > 604_800)
	{
		bail!("timeout_seconds must be between 1 and 604800");
	}
	if params.nice.is_some_and(|value| value > 19) {
		bail!("nice must be between 0 and 19");
	}
	if params
		.cpu_quota_percent
		.is_some_and(|value| value == 0 || value > 1000)
	{
		bail!("cpu_quota_percent must be between 1 and 1000");
	}
	if params
		.memory_max_bytes
		.is_some_and(|value| value < 16 * 1024 * 1024)
	{
		bail!("memory_max_bytes must be at least 16 MiB");
	}
	if params
		.idempotency_key
		.as_ref()
		.is_some_and(|value| value.is_empty() || value.len() > 256)
	{
		bail!("idempotency_key must contain 1..256 bytes");
	}
	Ok(())
}

fn check_binding(record: &JobRecord) -> Result<()> {
	let host = runtime_config()?.host(&record.host)?;
	if host.ssh_target != record.ssh_target || host.execution_mode != record.execution_mode {
		bail!("host binding changed; refusing to operate an old job");
	}
	Ok(())
}

async fn status_record(record: &JobRecord, wait_seconds: u64) -> Result<Value> {
	let config = runtime_config()?;
	let host = config.host(&record.host)?;
	check_binding(record)?;
	if record.system_jobctl {
		let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_seconds.min(30));
		loop {
			let value = run_jobctl(host, &json!({"op":"status","job_id":record.id})).await?;
			if value.get("state").and_then(Value::as_str) != Some("running")
				|| tokio::time::Instant::now() >= deadline
			{
				return Ok(value);
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
	let request = json!({
		"job_id": record.id,
		"job_dir": record.remote_job_dir,
		"unit": record.unit,
		"wait_seconds": wait_seconds.min(30),
	});
	run_python_json(
		host,
		STATUS_CODE,
		&request,
		Duration::from_secs(wait_seconds.min(30) + 10),
	)
	.await
}

fn require_operation_intent(outcome: Result<()>) -> Result<()> {
	outcome.map_err(|_| {
		anyhow::anyhow!("Operation intent audit unavailable; no remote operation submitted")
	})
}

fn operation_intent(action: &str, host: &str, job_id: &str) -> Result<()> {
	require_operation_intent(audit(
		action,
		host,
		job_id,
		&json!({"phase":"intent","remote_operation_submitted":false}),
	))
}

fn retain_result_after_audit(mut result: Value, outcome: Result<()>) -> Value {
	result["audit_recorded"] = json!(outcome.is_ok());
	if outcome.is_err() {
		result["audit_warning"] = json!(
			"Operation result retained; completion audit unavailable. Reconcile using the existing job_id."
		);
	}
	result
}

#[derive(Debug)]
struct LaunchOutcome {
	value: Value,
	local_record_pending: bool,
}

fn trusted_launch_ack(record: &JobRecord, value: &Value) -> bool {
	if value["ok"] != true {
		return false;
	}
	if record.system_jobctl && record.execution_mode == ExecutionMode::Isolated {
		return value["backend"] == "systemd_system"
			&& value
				.pointer("/status/job_id")
				.is_none_or(|id| id.as_str() == Some(&record.id));
	}
	match value["backend"].as_str() {
		Some("systemd") => value["unit"].as_str() == Some(&record.unit),
		Some("detached") => value["launcher_pid"]
			.as_u64()
			.is_some_and(|pid| pid > 0 && pid <= i32::MAX as u64),
		Some("completed" | "launch_failed") => value["reused_remote"] == true,
		_ => false,
	}
}

fn preserve_launch_outcome<F>(
	record: &mut JobRecord,
	outcome: Result<Value>,
	persist: F,
) -> LaunchOutcome
where
	F: FnOnce(&JobRecord) -> Result<()>,
{
	let value = match outcome {
		Ok(value) if trusted_launch_ack(record, &value) => {
			let remote_state = if record.system_jobctl
				&& record.execution_mode == ExecutionMode::Isolated
				&& value.get("reused_remote").and_then(Value::as_bool) == Some(true)
			{
				value
					.pointer("/status/launch_state")
					.and_then(Value::as_str)
					.filter(|state| {
						matches!(
							*state,
							"pending" | "launch_failed" | "launched" | "cancelled"
						)
					})
					.unwrap_or("launch_unknown")
			} else if value["backend"] == "launch_failed" {
				"launch_failed"
			} else {
				"launched"
			};
			record.launch_state = remote_state.to_string();
			record.launch_error = (remote_state == "launch_unknown")
				.then(|| "Remote launch state unavailable".to_string());
			value
		}
		Ok(_) | Err(_) => {
			// Invalid ACKs and transport failures cannot prove the supervisor did not launch.
			record.launch_state = "launch_unknown".to_string();
			record.launch_error = Some("Remote launch outcome unavailable".to_string());
			json!({
				"job_id":record.id,
				"state":"launch_unknown",
				"outcome":"unknown",
				"status_authoritative":false,
				"automatic_retry":false,
				"reconcile_via":"process_status"
			})
		}
	};
	LaunchOutcome {
		value,
		local_record_pending: persist(record).is_err(),
	}
}

fn attach_launch_record_warning(result: &mut Value, outcome: &LaunchOutcome) {
	result["local_record_pending"] = json!(outcome.local_record_pending);
	if outcome.local_record_pending {
		result["reconcile_warning"] = json!(
			"Remote launch outcome retained; local launch record update is pending. Use process_status with the existing job_id; do not create a new key."
		);
	}
}

fn reconcile_retry_allowed(record: &JobRecord) -> bool {
	// The administrator-pinned jobctl first checks the same job ID and full
	// request digest. Operator helpers never relaunch an uncertain old record.
	record.system_jobctl
		&& record.execution_mode == ExecutionMode::Isolated
		&& matches!(record.launch_state.as_str(), "pending" | "launch_failed")
}

fn unavailable_status(job_id: &str) -> Value {
	json!({"job_id":job_id,"state":"status_unavailable","outcome":"unknown",
        "status_authoritative":false,"automatic_retry":false})
}

fn retain_cancel_outcome(job_id: &str, outcome: Result<Value>) -> Value {
	if let Ok(value) = outcome {
		if value["job_id"].as_str() == Some(job_id)
			&& value["result"].as_str().is_some_and(|result| {
				matches!(
					result,
					"already_exited" | "stop_requested" | "term_sent" | "kill_sent" | "not_running"
				)
			}) {
			// An acknowledgement requests or sends a signal; it is not terminal proof.
			return json!({"job_id":job_id,"result":value["result"],"automatic_retry":false,
				"termination_confirmed":false,"reconcile_via":"process_status"});
		}
	}
	json!({"job_id":job_id,"result":"cancel_unknown","outcome":"unknown",
		"status_authoritative":false,"automatic_retry":false,"termination_confirmed":false,
		"reconcile_via":"process_status"})
}

async fn launch_record(
	record: &mut JobRecord,
	params: &ProcessStartParams,
) -> Result<LaunchOutcome> {
	let config = runtime_config()?;
	let host = config.host(&record.host)?;
	let request = json!({
		"job_id": record.id,
		"job_dir": record.remote_job_dir,
		"unit": record.unit,
		"request_fingerprint": record.request_digest.clone().unwrap_or_else(|| format!("{:016x}", record.request_fingerprint)),
		"platform": host.platform,
		"execution_mode": record.execution_mode,
		"executable": params.executable,
		"args": params.args,
		"cwd": params.cwd,
		"env": params.env,
		"stdin": params.stdin,
		"timeout_seconds": params.timeout_seconds,
		"nice": params.nice.unwrap_or(0),
		"cpu_quota_percent": params.cpu_quota_percent,
		"memory_max_bytes": params.memory_max_bytes,
		"allow_job_network": host.allow_job_network,
		"allow_detached_fallback": host.allow_detached_fallback,
	});
	let launch_result = if record.system_jobctl {
		run_jobctl(
			host,
			&json!({
				"op":"start", "job_id":record.id, "executable":params.executable,
				"args":params.args, "cwd":params.cwd, "env":params.env, "stdin":params.stdin,
				"timeout_seconds":params.timeout_seconds, "nice":params.nice,
				"cpu_quota_percent":params.cpu_quota_percent, "memory_max_bytes":params.memory_max_bytes
			}),
		)
		.await
	} else {
		run_python_json(host, START_CODE, &request, Duration::from_secs(20)).await
	};
	Ok(preserve_launch_outcome(record, launch_result, save_record))
}

pub async fn start_job(params: ProcessStartParams) -> Result<String> {
	validate_start(&params)?;
	let _start_guard = start_lock().lock().await;
	let request_fingerprint = fingerprint(&params);
	if let Some(key) = params.idempotency_key.as_deref() {
		if let Some(mut existing) = find_idempotent(&params.host, key)? {
			if !matches_request(&existing, &params)? {
				bail!("idempotency key `{key}` is already bound to a different request");
			}
			check_binding(&existing)?;
			let retry = reconcile_retry_allowed(&existing);
			let launch = if retry {
				operation_intent("process_start_reconcile_intent", &params.host, &existing.id)?;
				Some(launch_record(&mut existing, &params).await?)
			} else {
				None
			};
			let status = status_record(&existing, 0)
				.await
				.unwrap_or_else(|_| unavailable_status(&existing.id));
			let mut result = json!({
				"reused": true,
				"retried_launch": retry,
				"job": existing,
				"launch": launch.as_ref().map(|outcome| &outcome.value),
				"status": status,
			});
			if let Some(outcome) = &launch {
				attach_launch_record_warning(&mut result, outcome);
			}
			let completion = audit(
				"process_start_reused",
				&params.host,
				&existing.id,
				&json!({"phase":"result","reused":true,"retried_launch":retry}),
			);
			let result = retain_result_after_audit(result, completion);
			return Ok(serde_json::to_string_pretty(&result)?);
		}
	}

	let config = runtime_config()?;
	let host = config.host(&params.host)?;
	let id = next_job_id();
	let unit = format!("hepta-runtime-job-{id}");
	let remote_job_dir = format!("{}/jobs/{id}", host.remote_state_dir.trim_end_matches('/'));
	let mut record = JobRecord {
		system_jobctl: host.platform == Platform::Linux
			&& host.execution_mode == ExecutionMode::Isolated,
		execution_mode: host.execution_mode,
		id: id.clone(),
		host: params.host.clone(),
		ssh_target: host.ssh_target.clone(),
		unit,
		remote_job_dir,
		executable: params.executable.clone(),
		args: params.args.clone(),
		cwd: params.cwd.clone(),
		env_keys: params.env.keys().cloned().collect(),
		created_unix_ms: now_ms(),
		idempotency_key: params.idempotency_key.clone(),
		request_fingerprint,
		request_digest: Some(request_digest(&params)?),
		launch_state: "pending".to_string(),
		launch_error: None,
	};
	// Persist identity before remote launch. Later calls reconcile this same
	// host, job ID and request binding; never invent a second remote job.
	operation_intent("process_start_intent", &params.host, &id)?;
	save_record(&record).map_err(|_| {
		anyhow::anyhow!("Durable job identity could not be saved; no remote launch submitted")
	})?;
	let launch = launch_record(&mut record, &params).await?;
	let mut result = json!({"reused": false, "job": record, "launch": launch.value});
	attach_launch_record_warning(&mut result, &launch);
	let completion = audit(
		"process_start",
		&params.host,
		&id,
		&json!({"phase":"result","launch_state":record.launch_state}),
	);
	let result = retain_result_after_audit(result, completion);
	Ok(serde_json::to_string_pretty(&result)?)
}

pub async fn status_job(params: ProcessRefParams) -> Result<String> {
	let record = check_ref(&params)?;
	let status = status_record(&record, 0).await?;
	let completion = audit(
		"process_status",
		&params.host,
		&params.job_id,
		&json!({"phase":"observation","ok":true}),
	);
	Ok(serde_json::to_string_pretty(
		&retain_observation_after_audit(status, completion, &record.host, &record.id),
	)?)
}

pub async fn wait_job(params: ProcessWaitParams) -> Result<String> {
	let reference = ProcessRefParams {
		host: params.host.clone(),
		job_id: params.job_id.clone(),
	};
	let record = check_ref(&reference)?;
	let wait = params.timeout_seconds.unwrap_or(10).min(30);
	let status = status_record(&record, wait).await?;
	let completion = audit(
		"process_wait",
		&params.host,
		&params.job_id,
		&json!({"phase":"observation","ok":true}),
	);
	Ok(serde_json::to_string_pretty(
		&retain_observation_after_audit(status, completion, &record.host, &record.id),
	)?)
}

pub async fn read_job(params: ProcessReadParams) -> Result<String> {
	let reference = ProcessRefParams {
		host: params.host.clone(),
		job_id: params.job_id.clone(),
	};
	let record = check_ref(&reference)?;
	let host = runtime_config()?.host(&record.host)?;
	let request = json!({
		"job_id": record.id,
		"job_dir": record.remote_job_dir,
		"stdout_offset": params.stdout_offset.unwrap_or(0),
		"stderr_offset": params.stderr_offset.unwrap_or(0),
		"limit": params.limit.unwrap_or(65_536).min(MAX_LOG_READ_BYTES),
	});
	let output: Value = if record.system_jobctl {
		run_jobctl(host, &json!({"op":"read","job_id":record.id,
            "stdout_offset":params.stdout_offset.unwrap_or(0),"stderr_offset":params.stderr_offset.unwrap_or(0),"limit":params.limit.unwrap_or(16384)})).await?
	} else {
		run_python_json(host, READ_CODE, &request, Duration::from_secs(15)).await?
	};
	let completion = audit(
		"process_read",
		&params.host,
		&params.job_id,
		&json!({"phase":"observation","ok": true}),
	);
	Ok(serde_json::to_string_pretty(
		&retain_observation_after_audit(output, completion, &record.host, &record.id),
	)?)
}

fn retain_observation_after_audit(
	mut result: Value,
	outcome: Result<()>,
	host: &str,
	job_id: &str,
) -> Value {
	if !result.is_object() {
		return json!({"host":host,"job_id":job_id,"result":"invalid_remote_observation","outcome":"unknown","automatic_retry":false,"audit_recorded":outcome.is_ok(),"reconcile_warning":"Existing job observation was not a trusted object. No new job was launched."});
	}
	result["audit_recorded"] = json!(outcome.is_ok());
	if outcome.is_err() {
		result["audit_warning"] =
			json!("Existing job observation retained; audit unavailable. No new job was launched.");
	}
	result
}

pub async fn cancel_job(params: ProcessCancelParams) -> Result<String> {
	let reference = ProcessRefParams {
		host: params.host.clone(),
		job_id: params.job_id.clone(),
	};
	let record = check_ref(&reference)?;
	let host = runtime_config()?.host(&record.host)?;
	let request = json!({
		"job_id": record.id,
		"job_dir": record.remote_job_dir,
		"unit": record.unit,
		"grace_seconds": params.grace_seconds.unwrap_or(10).min(30),
	});
	operation_intent("process_cancel_intent", &params.host, &params.job_id)?;
	let remote = if record.system_jobctl {
		run_jobctl(host, &json!({"op":"cancel","job_id":record.id})).await
	} else {
		run_python_json(host, CANCEL_CODE, &request, Duration::from_secs(45)).await
	};
	let output = retain_cancel_outcome(&params.job_id, remote);
	let completion = audit(
		"process_cancel",
		&params.host,
		&params.job_id,
		&json!({"phase":"result","outcome_unknown":output["outcome"]=="unknown"}),
	);
	let output = retain_result_after_audit(output, completion);
	Ok(serde_json::to_string_pretty(&output)?)
}

pub fn list_jobs(params: ProcessListParams) -> Result<String> {
	if let Some(host) = params.host.as_deref() {
		runtime_config()?.host(host)?;
	}
	let records: Vec<_> = all_records()?
		.into_iter()
		.filter(|record| params.host.as_ref().is_none_or(|host| &record.host == host))
		.collect();
	Ok(serde_json::to_string_pretty(&json!({"jobs": records}))?)
}

#[cfg(test)]
#[path = "jobs_tests.rs"]
mod tests;
