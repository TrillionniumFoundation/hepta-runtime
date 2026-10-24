// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Closed systemd job capability: only setup is privileged; workloads use DynamicUser.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
const ROOT: &str = "/var/lib/hepta-runtime-jobctl";
const POLICY: &str = "/etc/hepta-runtime/job-policy.json";
const HELPER: &str = "/usr/local/libexec/hepta-runtime-jobctl";
const INPUT_MAX: u64 = 1_048_576;
const LOG_MAX: u64 = 16 * 1024 * 1024;
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) {
	STOP.store(true, Ordering::SeqCst);
}
fn signals() {
	unsafe {
		for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
			libc::signal(sig, on_signal as *const () as libc::sighandler_t);
		}
	}
}
fn now() -> u128 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis()
}
fn boot() -> Result<String> {
	Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
		.trim()
		.to_owned())
}
fn safe_id(id: &str) -> bool {
	!id.is_empty() && id.len() <= 96 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn digest(v: &impl Serialize) -> Result<String> {
	Ok(Sha256::digest(serde_json::to_vec(v)?)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect())
}
fn atomic(path: &Path, value: &impl Serialize) -> Result<()> {
	let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
	let mut f = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&tmp)?;
	let result = (|| -> Result<()> {
		serde_json::to_writer(&mut f, value)?;
		f.write_all(b"\n")?;
		f.sync_all()?;
		fs::rename(&tmp, path)?;
		if let Some(parent) = path.parent() {
			File::open(parent)?.sync_all()?;
		}
		Ok(())
	})();
	if result.is_err() {
		let _ = fs::remove_file(tmp);
	}
	result
}
fn json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
	let f = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
		.open(path)?;
	let metadata = f.metadata()?;
	if !metadata.is_file() || metadata.len() > INPUT_MAX {
		bail!("not a bounded regular JSON file");
	}
	Ok(serde_json::from_reader(f.take(INPUT_MAX + 1))?)
}
struct Lock(File);
impl Lock {
	fn acquire() -> Result<Self> {
		fs::create_dir_all(ROOT)?;
		fs::set_permissions(ROOT, fs::Permissions::from_mode(0o700))?;
		let f = OpenOptions::new()
			.create(true)
			.truncate(false)
			.read(true)
			.write(true)
			.mode(0o600)
			.open(format!("{ROOT}/lock"))?;
		use std::os::fd::AsRawFd;
		if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(Self(f))
	}
}
impl Drop for Lock {
	fn drop(&mut self) {
		use std::os::fd::AsRawFd;
		unsafe {
			libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
		}
	}
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
	workspace: PathBuf,
	#[serde(default)]
	allow_network: bool,
	#[serde(default = "default_timeout")]
	max_timeout_seconds: u64,
	#[serde(default = "default_cpu")]
	max_cpu_percent: u16,
	#[serde(default = "default_memory")]
	max_memory_bytes: u64,
}
fn default_timeout() -> u64 {
	3600
}
fn default_cpu() -> u16 {
	100
}
fn default_memory() -> u64 {
	1024 * 1024 * 1024
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
	op: String,
	job_id: String,
	#[serde(default)]
	executable: String,
	#[serde(default)]
	args: Vec<String>,
	#[serde(default)]
	cwd: Option<String>,
	#[serde(default)]
	env: BTreeMap<String, String>,
	#[serde(default)]
	stdin: Option<String>,
	#[serde(default)]
	timeout_seconds: Option<u64>,
	#[serde(default)]
	nice: Option<u8>,
	#[serde(default)]
	cpu_quota_percent: Option<u16>,
	#[serde(default)]
	memory_max_bytes: Option<u64>,
	#[serde(default)]
	stdout_offset: u64,
	#[serde(default)]
	stderr_offset: u64,
	#[serde(default)]
	limit: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
	job_id: String,
	unit: String,
	request_digest: String,
	boot_id: String,
	nonce: String,
	invocation_id: Option<String>,
	launch_state: String,
	created_unix_ms: u128,
}
#[derive(Serialize, Deserialize)]
struct Spec {
	request: Request,
	nonce: String,
	boot_id: String,
	workspace: String,
}
#[derive(Serialize, Deserialize)]
struct Exit {
	job_id: String,
	nonce: String,
	exit_code: i32,
	timed_out: bool,
	cancelled: bool,
	at_unix_ms: u128,
}
fn record_path(id: &str) -> PathBuf {
	Path::new(ROOT).join(id).join("record.json")
}
fn data_dir(id: &str) -> PathBuf {
	PathBuf::from(format!("/var/lib/hepta-job-{id}"))
}
fn load_record(id: &str) -> Result<Record> {
	if !safe_id(id) {
		bail!("invalid owned job ID");
	}
	let r: Record = json_file(&record_path(id)).context("unknown owned job")?;
	if r.job_id != id || r.unit != format!("hepta-job-{id}.service") {
		bail!("job identity mismatch");
	}
	Ok(r)
}
fn policy() -> Result<Policy> {
	let m = fs::symlink_metadata(POLICY)?;
	if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
		bail!("policy must be root-owned and not group/other writable");
	}
	let mut p: Policy = json_file(Path::new(POLICY))?;
	p.workspace = fs::canonicalize(&p.workspace)?;
	if !p.workspace.starts_with("/var/lib/hepta-runtime/workspaces")
		|| p.max_timeout_seconds == 0
		|| p.max_timeout_seconds > 604800
		|| p.max_cpu_percent == 0
		|| p.max_cpu_percent > 1000
		|| p.max_memory_bytes < 67108864
	{
		bail!("invalid administrator job policy");
	}
	Ok(p)
}
fn validate(q: &mut Request, p: &Policy) -> Result<()> {
	if !safe_id(&q.job_id) {
		bail!("invalid job ID");
	}
	if !Path::new(&q.executable).is_absolute()
		|| q.executable.contains('\0')
		|| q.args.len() > 256
		|| q.args.iter().any(|a| a.len() > 65536 || a.contains('\0'))
		|| q.env.len() > 64
	{
		bail!("invalid executable/arguments");
	}
	let cwd = fs::canonicalize(q.cwd.as_deref().map(Path::new).unwrap_or(&p.workspace))?;
	if !cwd.starts_with(&p.workspace) {
		bail!("cwd escapes administrator workspace");
	}
	q.cwd = Some(cwd.to_string_lossy().into_owned());
	for (k, v) in &q.env {
		if k.is_empty()
			|| k.as_bytes()[0].is_ascii_digit()
			|| !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
			|| v.len() > 65536
			|| v.contains('\0')
			|| [
				"CREDENTIALS_DIRECTORY",
				"STATE_DIRECTORY",
				"INVOCATION_ID",
				"NOTIFY_SOCKET",
			]
			.contains(&k.as_str())
		{
			bail!("invalid environment");
		}
	}
	if q.timeout_seconds
		.is_some_and(|v| v == 0 || v > p.max_timeout_seconds)
		|| q.cpu_quota_percent
			.is_some_and(|v| v == 0 || v > p.max_cpu_percent)
		|| q.memory_max_bytes
			.is_some_and(|v| v < 67108864 || v > p.max_memory_bytes)
		|| q.nice.is_some_and(|v| v > 19)
	{
		bail!("requested resources exceed administrator caps");
	}
	q.timeout_seconds = Some(q.timeout_seconds.unwrap_or(p.max_timeout_seconds));
	Ok(())
}
fn properties(r: &Record) -> Result<BTreeMap<String, String>> {
	let out=Command::new("/usr/bin/systemctl").args(["show","--no-pager","--property=LoadState,ActiveState,SubState,Result,InvocationID,Description,ExecMainStatus,ExecMainCode","--",&r.unit]).output()?;
	Ok(String::from_utf8_lossy(&out.stdout)
		.lines()
		.filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
		.collect())
}
fn bind_invocation(r: &mut Record, p: &BTreeMap<String, String>) -> Result<bool> {
	if p.get("LoadState").map(String::as_str) == Some("not-found") {
		return Ok(false);
	}
	if p.get("Description") != Some(&format!("Hepta Runtime {} {}", r.job_id, r.nonce)) {
		bail!("unit ownership mismatch: refusing operation");
	}
	let inv = p
		.get("InvocationID")
		.filter(|s| !s.is_empty())
		.context("unit has no invocation identity")?;
	if let Some(expected) = &r.invocation_id {
		if expected != inv {
			bail!("unit incarnation changed: refusing operation");
		}
	} else {
		r.invocation_id = Some(inv.clone());
		atomic(&record_path(&r.job_id), r)?;
	}
	Ok(true)
}
fn completed_result(r: &Record, e: &Exit) -> Result<Value> {
	let id = &r.job_id;
	if e.job_id != *id || e.nonce != r.nonce {
		bail!("exit identity mismatch");
	}
	let state = if e.timed_out {
		"timed_out"
	} else if e.cancelled || r.launch_state == "cancelled" {
		"cancelled"
	} else if e.exit_code == 0 {
		"succeeded"
	} else {
		"failed"
	};
	Ok(json!({"job_id":id,"state":state,"exit_code":e.exit_code,
		"timed_out":e.timed_out,"cancelled":state=="cancelled","backend":"systemd_system"}))
}

fn status(id: &str) -> Result<Value> {
	let mut r = load_record(id)?;
	// Completed results remain valid across a target reboot. Only in-flight
	// processes are lost; never replay a completed job to reconstruct its state.
	let exit_path = data_dir(id).join("exit.json");
	if exit_path.try_exists()? {
		let e: Exit = json_file(&exit_path).context("invalid completion record")?;
		return completed_result(&r, &e);
	}
	if r.boot_id != boot()? {
		return Ok(
			json!({"job_id":id,"state":"lost","reason":"target_reboot","backend":"systemd_system"}),
		);
	}
	let p = properties(&r)?;
	let present = bind_invocation(&mut r, &p)?;
	let state = if r.launch_state == "cancelled" {
		"cancelled"
	} else if present
		&& ["active", "activating", "deactivating"]
			.contains(&p.get("ActiveState").map(String::as_str).unwrap_or(""))
	{
		"running"
	} else if present && p.get("ActiveState").map(String::as_str) == Some("failed") {
		"failed"
	} else {
		"lost"
	};
	Ok(
		json!({"job_id":id,"state":state,"backend":"systemd_system","systemd":p,"launch_state":r.launch_state}),
	)
}
fn read_part(id: &str, name: &str, offset: u64, limit: u64) -> Result<Value> {
	let mut f = match OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
		.open(data_dir(id).join(name))
	{
		Ok(f) => f,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
			if offset != 0 {
				bail!("cursor exceeds absent log");
			}
			return Ok(
				json!({"offset":0,"next_offset":0,"size":0,"eof":true,"text":"","bytes_hex":""}),
			);
		}
		Err(e) => return Err(e.into()),
	};
	let m = f.metadata()?;
	if !m.is_file() {
		bail!("refusing non-regular log");
	}
	let size = m.len();
	if offset > size {
		bail!("cursor exceeds log length; refusing silent rewind");
	}
	f.seek(SeekFrom::Start(offset))?;
	let mut bytes = Vec::new();
	f.take(limit.clamp(1, 16384)).read_to_end(&mut bytes)?;
	let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
	Ok(
		json!({"offset":offset,"next_offset":offset+bytes.len()as u64,"size":size,"eof":offset+bytes.len()as u64>=size,"text":String::from_utf8_lossy(&bytes),"bytes_hex":hex,"log_limit_bytes":LOG_MAX}),
	)
}
fn cancel(id: &str) -> Result<Value> {
	let _lock = Lock::acquire()?;
	let mut r = load_record(id)?;
	if r.boot_id != boot()? {
		bail!("target rebooted: refusing to cancel old job");
	}
	let p = properties(&r)?;
	if !bind_invocation(&mut r, &p)?
		|| !["active", "activating", "deactivating"]
			.contains(&p.get("ActiveState").map(String::as_str).unwrap_or(""))
	{
		return Ok(json!({"job_id":id,"result":"already_exited"}));
	}
	let out = Command::new("/usr/bin/systemctl")
		.args(["stop", "--", &r.unit])
		.output()?;
	if !out.status.success() {
		bail!(
			"owned unit stop failed: {}",
			String::from_utf8_lossy(&out.stderr)
		);
	}
	r.launch_state = "cancelled".to_owned();
	atomic(&record_path(id), &r)?;
	Ok(json!({"job_id":id,"result":"stop_requested","invocation_id":r.invocation_id}))
}
fn start(mut q: Request, interactive: bool) -> Result<Value> {
	let p = policy()?;
	validate(&mut q, &p)?;
	let lock = Lock::acquire()?;
	let path = record_path(&q.job_id);
	let hash = digest(&q)?;
	if path.exists() {
		let r = load_record(&q.job_id)?;
		if hash != r.request_digest {
			bail!("job ID already bound to a different request");
		}
		return Ok(
			json!({"ok":true,"reused_remote":true,"backend":"systemd_system","status":status(&q.job_id)?}),
		);
	}
	if fs::read_dir(ROOT)?
		.filter_map(|e| e.ok())
		.filter(|e| e.path().is_dir())
		.count()
		>= 128
	{
		bail!("retained job limit reached; administrator must archive completed jobs");
	}
	let dir = path.parent().context("record directory")?;
	fs::create_dir_all(dir)?;
	fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
	let nonce = fs::read_to_string("/proc/sys/kernel/random/uuid")?
		.trim()
		.to_owned();
	let mut r = Record {
		job_id: q.job_id.clone(),
		unit: format!("hepta-job-{}.service", q.job_id),
		request_digest: hash,
		boot_id: boot()?,
		nonce: nonce.clone(),
		invocation_id: None,
		launch_state: "pending".to_owned(),
		created_unix_ms: now(),
	};
	let spec_path = dir.join("spec.json");
	atomic(
		&spec_path,
		&Spec {
			request: q.clone(),
			nonce,
			boot_id: r.boot_id.clone(),
			workspace: p.workspace.to_string_lossy().into_owned(),
		},
	)?;
	atomic(&path, &r)?;
	let mut cmd = Command::new("/usr/bin/systemd-run");
	cmd.args(["--quiet", "--collect", "--unit", &r.unit]);
	if interactive {
		cmd.args(["--pty", "--wait"]);
	}
	let props=vec![
 format!("Description=Hepta Runtime {} {}",r.job_id,r.nonce),"DynamicUser=yes".to_owned(),
        "Slice=hepta-runtime-jobs.slice".to_owned(),"SupplementaryGroups=hepta-workspace".to_owned(),
 format!("StateDirectory=hepta-job-{}",q.job_id),"StateDirectoryMode=0700".to_owned(),format!("LoadCredential=spec:{}",spec_path.display()),
 format!("BindPaths={}:/workspace",p.workspace.display()),"WorkingDirectory=/workspace".to_owned(),
 "InaccessiblePaths=-/var/lib/hepta-runtime -/etc/hepta-runtime -/run/user -/run/dbus -/run/systemd/private -/run/docker.sock -/run/libvirt".to_owned(),
 "ProtectHome=yes".to_owned(),"ProtectSystem=strict".to_owned(),"PrivateTmp=yes".to_owned(),"PrivateDevices=yes".to_owned(),"NoNewPrivileges=yes".to_owned(),"CapabilityBoundingSet=".to_owned(),"RestrictSUIDSGID=yes".to_owned(),"ProtectKernelTunables=yes".to_owned(),"ProtectKernelModules=yes".to_owned(),"ProtectControlGroups=yes".to_owned(),"RestrictRealtime=yes".to_owned(),"LockPersonality=yes".to_owned(),"ProtectProc=invisible".to_owned(),"KillMode=control-group".to_owned(),"TimeoutStopSec=3s".to_owned(),"TasksMax=64".to_owned(),"UMask=0007".to_owned(),"MemorySwapMax=0".to_owned(),
 format!("CPUQuota={}%",q.cpu_quota_percent.unwrap_or(p.max_cpu_percent)),format!("MemoryMax={}",q.memory_max_bytes.unwrap_or(p.max_memory_bytes)),format!("Nice={}",q.nice.unwrap_or(10)),format!("RuntimeMaxSec={}s",q.timeout_seconds.unwrap_or(p.max_timeout_seconds)+10)];
	for prop in props {
		cmd.args(["--property", &prop]);
	}
	if !p.allow_network {
		cmd.args([
			"--property",
			"PrivateNetwork=yes",
			"--property",
			"RestrictAddressFamilies=AF_UNIX AF_NETLINK",
		]);
	}
	cmd.args([
		"--",
		HELPER,
		if interactive {
			"supervise-pty"
		} else {
			"supervise"
		},
		&q.job_id,
	]);
	let mut pty_child: Option<Child> = None;
	if interactive {
		signals();
		pty_child = Some(cmd.spawn()?);
		for _ in 0..100 {
			if properties(&r)?
				.get("InvocationID")
				.is_some_and(|v| !v.is_empty())
			{
				break;
			}
			std::thread::sleep(Duration::from_millis(10));
		}
	} else {
		let out = cmd.output()?;
		if !out.status.success() {
			r.launch_state = "launch_failed".to_owned();
			atomic(&path, &r)?;
			bail!(
				"systemd launch failed: {}",
				String::from_utf8_lossy(&out.stderr)
			);
		}
	}
	r.launch_state = "launched".to_owned();
	let props = properties(&r)?;
	let _ = bind_invocation(&mut r, &props)?;
	atomic(&path, &r)?;
	drop(lock);
	if let Some(mut child) = pty_child {
		loop {
			if let Some(e) = child.try_wait()? {
				return Ok(json!({"pty_exit_code":e.code()}));
			}
			if STOP.load(Ordering::SeqCst) {
				let _ = cancel(&q.job_id);
				let _ = child.kill();
				let _ = child.wait();
				break;
			}
			std::thread::sleep(Duration::from_millis(25));
		}
	}
	Ok(
		json!({"ok":true,"backend":"systemd_system","unit":r.unit,"invocation_id":r.invocation_id,"workspace":"/workspace"}),
	)
}
fn log_copy(mut reader: impl Read, mut writer: File) -> std::io::Result<()> {
	let mut buf = [0u8; 8192];
	let mut saved = 0;
	loop {
		let n = reader.read(&mut buf)?;
		if n == 0 {
			break;
		}
		let keep = (LOG_MAX - saved).min(n as u64) as usize;
		if keep > 0 {
			writer.write_all(&buf[..keep])?;
			saved += keep as u64;
		}
	}
	writer.sync_all()
}
fn supervise(id: &str, interactive: bool) -> Result<()> {
	if unsafe { libc::geteuid() } == 0 {
		bail!("supervisor must never execute as root");
	}
	signals();
	let spec: Spec =
		json_file(&PathBuf::from(std::env::var("CREDENTIALS_DIRECTORY")?).join("spec"))?;
	if spec.request.job_id != id || spec.boot_id != boot()? {
		bail!("supervisor identity mismatch");
	}
	let state = PathBuf::from(std::env::var("STATE_DIRECTORY")?);
	let q = spec.request;
	let cwd =
		Path::new(q.cwd.as_deref().unwrap_or(&spec.workspace)).strip_prefix(&spec.workspace)?;
	let exe = if Path::new(&q.executable).starts_with(&spec.workspace) {
		Path::new("/workspace").join(Path::new(&q.executable).strip_prefix(&spec.workspace)?)
	} else {
		PathBuf::from(&q.executable)
	};
	let mut cmd = Command::new(exe);
	cmd.args(&q.args)
		.current_dir(Path::new("/workspace").join(cwd))
		.env_clear()
		.env("PATH", "/usr/bin:/bin")
		.env("HOME", "/tmp")
		.env("LANG", "C.UTF-8")
		.env("TERM", "xterm-256color")
		.envs(&q.env)
		.env("HEPTA_RUNTIME_JOB_ID", id);
	if interactive {
		cmd.stdin(Stdio::inherit())
			.stdout(Stdio::inherit())
			.stderr(Stdio::inherit());
	} else {
		let input = state.join("stdin.bin");
		if let Some(text) = &q.stdin {
			fs::write(&input, text)?;
			cmd.stdin(File::open(&input)?);
		} else {
			cmd.stdin(Stdio::null());
		}
		cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	}
	let mut child = match cmd.spawn() {
		Ok(c) => c,
		Err(e) => {
			atomic(
				&state.join("exit.json"),
				&Exit {
					job_id: id.to_owned(),
					nonce: spec.nonce,
					exit_code: 127,
					timed_out: false,
					cancelled: false,
					at_unix_ms: now(),
				},
			)?;
			return Err(e.into());
		}
	};
	let mut readers = Vec::new();
	if let Some(out) = child.stdout.take() {
		let f = File::create(state.join("stdout.log"))?;
		readers.push(std::thread::spawn(move || log_copy(out, f)));
	}
	if let Some(err) = child.stderr.take() {
		let f = File::create(state.join("stderr.log"))?;
		readers.push(std::thread::spawn(move || log_copy(err, f)));
	}
	let begin = Instant::now();
	let mut timed_out = false;
	let mut cancelled = false;
	let exit = loop {
		if let Some(e) = child.try_wait()? {
			break e;
		}
		cancelled = STOP.load(Ordering::SeqCst);
		timed_out = begin.elapsed().as_secs() >= q.timeout_seconds.unwrap_or(3600);
		if cancelled || timed_out {
			child.kill()?;
			break child.wait()?;
		}
		std::thread::sleep(Duration::from_millis(20));
	};
	// Bound pipe draining: escaped descendants cannot keep completion blocked.
	for _ in 0..20 {
		if readers.iter().all(|r| r.is_finished()) {
			break;
		}
		std::thread::sleep(Duration::from_millis(10));
	}
	for reader in readers {
		if reader.is_finished() {
			let _ = reader.join();
		}
	}
	let code = if timed_out {
		124
	} else {
		exit.code().unwrap_or(128 + exit.signal().unwrap_or(0))
	};
	atomic(
		&state.join("exit.json"),
		&Exit {
			job_id: id.to_owned(),
			nonce: spec.nonce,
			exit_code: code,
			timed_out,
			cancelled: cancelled || STOP.load(Ordering::SeqCst),
			at_unix_ms: now(),
		},
	)?;
	Ok(())
}
fn run() -> Result<()> {
	let args: Vec<String> = std::env::args().collect();
	if args.len() == 3 && ["supervise", "supervise-pty"].contains(&args[1].as_str()) {
		return supervise(&args[2], args[1] == "supervise-pty");
	}
	if args.len() != 1 || unsafe { libc::geteuid() } != 0 {
		bail!("control requires exact no-argument sudo capability");
	}
	let mut input = Vec::new();
	let mut byte = [0u8; 1];
	let mut stdin = std::io::stdin();
	loop {
		if stdin.read(&mut byte)? == 0 || byte[0] == b'\n' {
			break;
		}
		input.push(byte[0]);
		if input.len() as u64 > INPUT_MAX {
			bail!("request too large");
		}
	}
	let q: Request = serde_json::from_slice(&input)?;
	if !safe_id(&q.job_id) {
		bail!("invalid owned job ID");
	}
	let v = match q.op.as_str() {
		"start" => start(q, false)?,
		"pty" => start(q, true)?,
		"status" => {
			let _lock = Lock::acquire()?;
			status(&q.job_id)?
		}
		"read" => {
			let _r = load_record(&q.job_id)?;
			json!({"job_id":q.job_id,"stdout":read_part(&q.job_id,"stdout.log",q.stdout_offset,q.limit.unwrap_or(16384))?,"stderr":read_part(&q.job_id,"stderr.log",q.stderr_offset,q.limit.unwrap_or(16384))?})
		}
		"cancel" => cancel(&q.job_id)?,
		_ => bail!("unknown closed capability"),
	};
	println!("{}", serde_json::to_string(&v)?);
	Ok(())
}
fn main() {
	if let Err(e) = run() {
		eprintln!("jobctl: {e:#}");
		std::process::exit(1);
	}
}
#[cfg(test)]
#[path = "../jobctl_tests.rs"]
mod tests;
