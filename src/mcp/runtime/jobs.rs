use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;

use super::config::{check_environment, check_execution, runtime_config, valid_name};
use super::ssh::run_python_json;

static JOB_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const START_LOCK_SHARDS: usize = 256;
static START_LOCKS: OnceLock<Vec<AsyncMutex<()>>> = OnceLock::new();
static AUDIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const MAX_STDIN_BYTES: usize = 1024 * 1024;
const MAX_LOG_READ_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
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
	/// Mandatory stable operation key; retries of one exact host+request never launch twice.
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
pub struct ProcessRefParams {
	pub host: String,
	pub job_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProcessReadParams {
	pub host: String,
	pub job_id: String,
	#[serde(default)]
	pub stdout_offset: Option<u64>,
	#[serde(default)]
	pub stderr_offset: Option<u64>,
	/// Maximum bytes returned per stream, capped at 1 MiB.
	#[serde(default)]
	pub limit: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProcessWaitParams {
	pub host: String,
	pub job_id: String,
	/// Maximum wait for this call, capped at 30 seconds.
	#[serde(default)]
	pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProcessCancelParams {
	pub host: String,
	pub job_id: String,
	/// Grace period before the fallback backend sends SIGKILL, capped at 30 seconds.
	#[serde(default)]
	pub grace_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProcessListParams {
	#[serde(default)]
	pub host: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct JobRecord {
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
	/// Full, canonical SHA-256 request binding for collision-resistant idempotency.
	/// Old records remain readable but cannot be automatically re-dispatched.
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

fn start_lock(host: &str, key: Option<&str>) -> &'static AsyncMutex<()> {
	// Only requests sharing the same host and idempotency key must be serialized.
	// Fixed sharding bounds lock memory and avoids global remote-launch head-of-line blocking.
	let locks = START_LOCKS.get_or_init(|| {
		(0..START_LOCK_SHARDS).map(|_| AsyncMutex::new(())).collect()
	});
	let mut hasher = std::collections::hash_map::DefaultHasher::new();
	host.hash(&mut hasher);
	key.hash(&mut hasher);
	&locks[(hasher.finish() as usize) % START_LOCK_SHARDS]
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

fn save_record_at(path: &Path, record: &JobRecord) -> Result<()> {
	let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
	let bytes = serde_json::to_vec_pretty(record)?;
	#[cfg(unix)]
	let mut file = {
		use std::os::unix::fs::OpenOptionsExt;
		OpenOptions::new()
			.create(true)
			.write(true)
			.truncate(true)
			.mode(0o600)
			.open(&tmp)?
	};
	#[cfg(not(unix))]
	let mut file = File::create(&tmp)?;
	file.write_all(&bytes)?;
	// The identity must be durable before an external process can be launched.
	file.sync_all()?;
	drop(file);
	std::fs::rename(&tmp, path)?;
	#[cfg(unix)]
	if let Some(parent) = path.parent() {
		File::open(parent)?.sync_all()?;
	}
	Ok(())
}

fn save_record(record: &JobRecord) -> Result<()> {
	save_record_at(&record_path(&record.id)?, record)
}

fn load_record(id: &str) -> Result<JobRecord> {
	let path = record_path(id)?;
	let bytes = std::fs::read(&path).with_context(|| format!("unknown durable job `{id}`"))?;
	serde_json::from_slice(&bytes).context("corrupt durable job metadata")
}

fn scan_records_dir(dir: &Path) -> Result<Vec<JobRecord>> {
	let mut records = Vec::new();
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let path = entry.path();
		if path.extension().and_then(|s| s.to_str()) != Some("json") {
			continue;
		}
		// A corrupt/unreadable record might be the owner of an idempotency key.
		// Skipping it would allow a second physical launch after a restart.
		let bytes = std::fs::read(&path)
			.with_context(|| format!("cannot read durable job record {}", path.display()))?;
		let record: JobRecord = serde_json::from_slice(&bytes)
			.with_context(|| format!("corrupt durable job record {}", path.display()))?;
		if path.file_stem().and_then(|stem| stem.to_str()) != Some(record.id.as_str()) {
			bail!("durable job filename/identity mismatch: {}", path.display());
		}
		records.push(record);
	}
	records.sort_by_key(|record| record.created_unix_ms);
	Ok(records)
}

fn all_records() -> Result<Vec<JobRecord>> {
	scan_records_dir(&jobs_dir()?)
}

fn find_idempotent(host: &str, key: &str) -> Result<Option<JobRecord>> {
	Ok(all_records()?
		.into_iter()
		.find(|record| record.host == host && record.idempotency_key.as_deref() == Some(key)))
}

fn request_digest(params: &ProcessStartParams) -> (u64, String) {
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
	let bytes = serde_json::to_vec(&binding).expect("process binding serializes");
	let digest = Sha256::digest(bytes);
	let legacy = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
	(legacy, format!("{digest:x}"))
}

#[cfg(test)]
fn fingerprint(params: &ProcessStartParams) -> u64 {
	request_digest(params).0
}

fn verify_reuse_binding(
	existing: &JobRecord,
	key: &str,
	legacy_fingerprint: u64,
	full_digest: &str,
) -> Result<()> {
	// Old 64-bit-only records remain inspectable, but do not establish a
	// collision-resistant authorization to restart a physical process.
	if existing.request_digest.is_none() {
		bail!("legacy idempotency record lacks full request binding; reconcile without replay");
	}
	if existing.request_fingerprint != legacy_fingerprint
		|| existing.request_digest.as_deref() != Some(full_digest)
	{
		bail!("idempotency key `{key}` is already bound to a different request");
	}
	Ok(())
}

fn check_ref(params: &ProcessRefParams) -> Result<JobRecord> {
	let record = load_record(&params.job_id)?;
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
import json, os, pathlib, shutil, subprocess, sys, time
req = json.load(sys.stdin)
job = pathlib.Path(req["job_dir"])
job.mkdir(parents=True, exist_ok=True)
os.chmod(job, 0o700)

def read_json(name):
    target = job / name
    if target.is_symlink():
        raise SystemExit(f"unsafe remote job state symlink: {name}")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception as exc:
        raise SystemExit(f"corrupt remote job state {name}: {exc}")
    if not isinstance(value, dict):
        raise SystemExit(f"invalid remote job state object: {name}")
    return value

def atomic(name, value):
    target = job / name
    tmp = job / (name + ".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)

stdin_text = req.pop("stdin", None)
existing = read_json("request.json")
if existing is not None:
    if (existing.get("job_id") != req.get("job_id")
            or existing.get("request_fingerprint") != req.get("request_fingerprint")
            or not req.get("request_digest")
            or existing.get("request_digest") != req.get("request_digest")):
        raise SystemExit("remote job directory is bound to a different request")
    launch = read_json("launch.json")
    exit_data = read_json("exit.json")
    started = read_json("started.json")
    if exit_data is not None:
        print(json.dumps({"ok": True, "reused_remote": True, "backend": "completed"}, sort_keys=True))
        raise SystemExit(0)
    if launch is not None:
        if launch.get("backend") not in ("systemd", "detached"):
            raise SystemExit("prior remote launch failed or has unknown backend; reconcile before retry")
        print(json.dumps({"ok": True, "reused_remote": True, **launch}, sort_keys=True))
        raise SystemExit(0)
    if started is not None:
        raise SystemExit("ambiguous prior launch: supervisor started without launch record")
    # A request may have crossed the remote dispatch boundary before the
    # controller lost its acknowledgement. Never infer 'not started' from
    # missing launch metadata; a later launch would risk a duplicate effect.
    raise SystemExit("ambiguous prior launch: request exists without terminal evidence")
else:
    # Missing request.json does not establish non-execution: a prior controller
    # may have lost its durable request or encountered remote state corruption.
    # Never overwrite evidence of a prior effect under the same job identity.
    for name in ("launch.json", "started.json", "exit.json", "child.json", "runner.py", "stdin.bin"):
        path = job / name
        if path.exists() or path.is_symlink():
            raise SystemExit("orphaned remote job state without request.json; reconcile before launch")
    if stdin_text is not None:
        stdin_path = job / "stdin.bin"
        stdin_path.write_bytes(stdin_text.encode("utf-8"))
        os.chmod(stdin_path, 0o600)
        req["stdin_path"] = str(stdin_path)
    atomic("request.json", req)
runner = r'''#!/usr/bin/env python3
import json, os, pathlib, shutil, signal, subprocess, sys, time
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
        ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().split()[21])
        return {"kind": "proc_start_ticks", "value": str(ticks)}
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
        stdout=out,
        stderr=err,
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

timed_out = False
try:
    timeout = req.get("timeout_seconds")
    rc = child.wait(timeout=float(timeout) if timeout else None)
except subprocess.TimeoutExpired:
    timed_out = True
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        rc = child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        rc = child.wait()
    rc = 124
atomic("exit.json", {
    "at_unix_ms": int(time.time() * 1000),
    "exit_code": int(rc),
    "cancelled": bool(cancel_requested),
    "timed_out": bool(timed_out),
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
        ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().split()[21])
        return {"kind": "proc_start_ticks", "value": str(ticks)}
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
    running = bool(pid and actual is not None and (expected is None or expected == actual))
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
limit = max(1, min(int(q.get("limit", 65536)), 1048576))

def read_part(name, offset):
    path = job / name
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        size = 0
    offset = min(max(0, int(offset or 0)), size)
    data = b""
    if size:
        with path.open("rb") as f:
            f.seek(offset)
            data = f.read(limit)
    return {
        "offset": offset,
        "next_offset": offset + len(data),
        "size": size,
        "eof": offset + len(data) >= size,
        "text": data.decode("utf-8", errors="replace"),
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
        ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().split()[21])
        return {"kind": "proc_start_ticks", "value": str(ticks)}
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
    if expected is not None:
        valid = valid and expected == actual
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
        try:
            os.killpg(pid, signal.SIGKILL)
            result = "kill_sent"
        except ProcessLookupError:
            pass
print(json.dumps({"job_id": q["job_id"], "result": result}, sort_keys=True))
"#;

fn validate_start(params: &ProcessStartParams) -> Result<()> {
	// Without a caller-stable key an ambiguous transport retry is a new launch.
	// Reject before reaching any host or execution-policy lookup.
	if params
		.idempotency_key
		.as_ref()
		.is_none_or(|value| value.trim().is_empty() || value.len() > 256)
	{
		bail!("idempotency_key is required and must contain 1..256 non-blank bytes");
	}
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
	Ok(())
}

async fn status_record(record: &JobRecord, wait_seconds: u64) -> Result<Value> {
	let config = runtime_config()?;
	let host = config.host(&record.host)?;
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

async fn launch_record(record: &mut JobRecord, params: &ProcessStartParams) -> Result<Value> {
	let config = runtime_config()?;
	let host = config.host(&record.host)?;
	let request = json!({
		"job_id": record.id,
		"job_dir": record.remote_job_dir,
		"unit": record.unit,
		"request_fingerprint": format!("{:016x}", record.request_fingerprint),
		"request_digest": record.request_digest,
		"platform": host.platform,
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
	match run_python_json(host, START_CODE, &request, Duration::from_secs(20)).await {
		Ok(launch) => {
			record.launch_state = "launched".to_string();
			record.launch_error = None;
			save_record(record)?;
			Ok(launch)
		}
		Err(error) => {
			record.launch_state = "launch_failed".to_string();
			record.launch_error = Some(error.to_string());
			save_record(record)?;
			let outcome = json!({"error": error.to_string(), "job": record});
			audit("process_start_failed", &record.host, &record.id, &outcome)?;
			Err(error)
		}
	}
}

pub async fn start_job(params: ProcessStartParams) -> Result<String> {
	validate_start(&params)?;
	let _start_guard = start_lock(&params.host, params.idempotency_key.as_deref())
		.lock()
		.await;
	let (request_fingerprint, request_digest) = request_digest(&params);
	if let Some(key) = params.idempotency_key.as_deref() {
		if let Some(mut existing) = find_idempotent(&params.host, key)? {
			verify_reuse_binding(&existing, key, request_fingerprint, &request_digest)?;
			let retry = matches!(existing.launch_state.as_str(), "pending" | "launch_failed");
			let launch = if retry {
				Some(launch_record(&mut existing, &params).await?)
			} else {
				None
			};
			let status = status_record(&existing, 0).await.unwrap_or_else(
				|error| json!({"state": "status_error", "error": error.to_string()}),
			);
			let result = json!({
				"reused": true,
				"retried_launch": retry,
				"job": existing,
				"launch": launch,
				"status": status,
			});
			audit("process_start_reused", &params.host, &existing.id, &result)?;
			return Ok(serde_json::to_string_pretty(&result)?);
		}
	}

	let config = runtime_config()?;
	let host = config.host(&params.host)?;
	let id = next_job_id();
	let unit = format!("hepta-runtime-job-{id}");
	let remote_job_dir = format!("{}/jobs/{id}", host.remote_state_dir.trim_end_matches('/'));
	let mut record = JobRecord {
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
		request_digest: Some(request_digest),
		launch_state: "pending".to_string(),
		launch_error: None,
	};
	// Persist identity before remote launch. A crash can be retried with the same
	// idempotency key and request, never by inventing a second remote job.
	save_record(&record)?;
	let launch = launch_record(&mut record, &params).await?;
	let result = json!({"reused": false, "job": record, "launch": launch});
	audit("process_start", &params.host, &id, &result)?;
	Ok(serde_json::to_string_pretty(&result)?)
}

pub async fn status_job(params: ProcessRefParams) -> Result<String> {
	let record = check_ref(&params)?;
	let status = status_record(&record, 0).await?;
	audit("process_status", &params.host, &params.job_id, &status)?;
	Ok(serde_json::to_string_pretty(&status)?)
}

pub async fn wait_job(params: ProcessWaitParams) -> Result<String> {
	let reference = ProcessRefParams {
		host: params.host.clone(),
		job_id: params.job_id.clone(),
	};
	let record = check_ref(&reference)?;
	let wait = params.timeout_seconds.unwrap_or(10).min(30);
	let status = status_record(&record, wait).await?;
	audit("process_wait", &params.host, &params.job_id, &status)?;
	Ok(serde_json::to_string_pretty(&status)?)
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
	let output: Value = run_python_json(host, READ_CODE, &request, Duration::from_secs(15)).await?;
	audit(
		"process_read",
		&params.host,
		&params.job_id,
		&json!({"ok": true}),
	)?;
	Ok(serde_json::to_string_pretty(&output)?)
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
	let output: Value =
		run_python_json(host, CANCEL_CODE, &request, Duration::from_secs(45)).await?;
	audit("process_cancel", &params.host, &params.job_id, &output)?;
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
