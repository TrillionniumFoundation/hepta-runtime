use anyhow::{anyhow, bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStdin, Command};
use tokio::sync::Mutex as AsyncMutex;

use super::config::{check_environment, check_execution, runtime_config, valid_name};
use super::ssh::build_exec_command;

const MAX_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_WRITE_BYTES: usize = 64 * 1024;
static PTY_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static PTYS: OnceLock<Mutex<HashMap<String, PtySession>>> = OnceLock::new();

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PtyStartParams {
	pub host: String,
	pub executable: String,
	#[serde(default)]
	pub args: Vec<String>,
	#[serde(default)]
	pub cwd: Option<String>,
	#[serde(default)]
	pub env: BTreeMap<String, String>,
	#[serde(default)]
	pub rows: Option<u16>,
	#[serde(default)]
	pub cols: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PtyRefParams {
	pub host: String,
	pub session_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PtyReadParams {
	pub host: String,
	pub session_id: String,
	#[serde(default)]
	pub offset: Option<u64>,
	#[serde(default)]
	pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PtyWriteParams {
	pub host: String,
	pub session_id: String,
	/// UTF-8 data sent exactly as provided; control characters such as \u0003 are allowed.
	pub data: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PtyListParams {
	#[serde(default)]
	pub host: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum PtyState {
	Running,
	Exited,
	Signalled,
	WaitError,
}

#[derive(Debug, Clone, Serialize)]
struct PtyStatus {
	state: PtyState,
	exit_code: Option<i32>,
	detail: Option<String>,
}

#[derive(Debug)]
struct RingBuffer {
	base_offset: u64,
	data: Vec<u8>,
}

impl RingBuffer {
	fn new() -> Self {
		Self {
			base_offset: 0,
			data: Vec::new(),
		}
	}

	fn append(&mut self, bytes: &[u8]) {
		self.data.extend_from_slice(bytes);
		if self.data.len() > MAX_BUFFER_BYTES {
			let remove = self.data.len() - MAX_BUFFER_BYTES;
			self.data.drain(..remove);
			self.base_offset += remove as u64;
		}
	}

	fn read(&self, requested: u64, limit: usize) -> (u64, u64, bool, String) {
		let truncated = requested < self.base_offset;
		let offset = requested.max(self.base_offset);
		let start = (offset - self.base_offset) as usize;
		if start >= self.data.len() {
			return (offset, offset, truncated, String::new());
		}
		let end = (start + limit).min(self.data.len());
		let text = String::from_utf8_lossy(&self.data[start..end]).into_owned();
		(offset, self.base_offset + end as u64, truncated, text)
	}
}

#[derive(Clone)]
struct PtySession {
	id: String,
	host: String,
	pid: u32,
	created_unix_ms: u128,
	stdin: Arc<AsyncMutex<Option<ChildStdin>>>,
	output: Arc<Mutex<RingBuffer>>,
	status: Arc<Mutex<PtyStatus>>,
}

fn registry() -> &'static Mutex<HashMap<String, PtySession>> {
	PTYS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_ms() -> u128 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis()
}

fn next_id() -> String {
	let seq = PTY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
	format!("pty-{:x}-{:x}-{:x}", now_ms(), std::process::id(), seq)
}

fn lookup(host: &str, id: &str) -> Result<PtySession> {
	if !valid_name(id) {
		bail!("invalid PTY session id");
	}
	let session = registry()
		.lock()
		.map_err(|_| anyhow!("PTY registry lock poisoned"))?
		.get(id)
		.cloned()
		.ok_or_else(|| anyhow!("unknown PTY session `{id}`"))?;
	if session.host != host {
		bail!(
			"PTY session `{id}` belongs to `{}`, not `{host}`",
			session.host
		);
	}
	Ok(session)
}

async fn copy_reader<R>(mut reader: R, output: Arc<Mutex<RingBuffer>>)
where
	R: AsyncRead + Unpin,
{
	let mut buf = vec![0_u8; 8192];
	loop {
		match reader.read(&mut buf).await {
			Ok(0) => break,
			Ok(n) => {
				if let Ok(mut guard) = output.lock() {
					guard.append(&buf[..n]);
				}
			}
			Err(_) => break,
		}
	}
}

pub async fn start_pty(params: PtyStartParams) -> Result<String> {
	let host = check_execution(
		&params.host,
		&params.executable,
		&params.args,
		params.cwd.as_deref(),
		true,
	)?;
	check_environment(&params.host, &params.env)?;
	let rows = params.rows.unwrap_or(24).clamp(1, 500);
	let cols = params.cols.unwrap_or(120).clamp(1, 1000);
	let remote = build_exec_command(
		&params.executable,
		&params.args,
		params.cwd.as_deref(),
		&params.env,
		rows,
		cols,
	)?;
	let mut command = Command::new("ssh");
	command
		.arg("-tt")
		.arg("-o")
		.arg("BatchMode=yes")
		.arg("-o")
		.arg("ConnectTimeout=8")
		.arg("-o")
		.arg("StrictHostKeyChecking=yes")
		.arg(&host.ssh_target)
		.arg(remote)
		.env("TERM", "xterm-256color")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(false);
	let mut child = command.spawn()?;
	let pid = child.id().ok_or_else(|| anyhow!("ssh child has no PID"))?;
	let stdin = Arc::new(AsyncMutex::new(child.stdin.take()));
	let output = Arc::new(Mutex::new(RingBuffer::new()));
	if let Some(stdout) = child.stdout.take() {
		tokio::spawn(copy_reader(stdout, output.clone()));
	}
	if let Some(stderr) = child.stderr.take() {
		tokio::spawn(copy_reader(stderr, output.clone()));
	}
	let status = Arc::new(Mutex::new(PtyStatus {
		state: PtyState::Running,
		exit_code: None,
		detail: None,
	}));
	let waiter_status = status.clone();
	tokio::spawn(async move {
		let next = match child.wait().await {
			Ok(exit) if exit.code().is_some() => PtyStatus {
				state: PtyState::Exited,
				exit_code: exit.code(),
				detail: None,
			},
			Ok(_) => PtyStatus {
				state: PtyState::Signalled,
				exit_code: None,
				detail: None,
			},
			Err(error) => PtyStatus {
				state: PtyState::WaitError,
				exit_code: None,
				detail: Some(error.to_string()),
			},
		};
		if let Ok(mut guard) = waiter_status.lock() {
			*guard = next;
		}
	});
	let id = next_id();
	let session = PtySession {
		id: id.clone(),
		host: params.host.clone(),
		pid,
		created_unix_ms: now_ms(),
		stdin,
		output,
		status,
	};
	registry()
		.lock()
		.map_err(|_| anyhow!("PTY registry lock poisoned"))?
		.insert(id.clone(), session);
	Ok(serde_json::to_string_pretty(&json!({
		"session_id": id,
		"host": params.host,
		"pid": pid,
		"persistent_across_runtime_restart": false,
	}))?)
}

pub fn read_pty(params: PtyReadParams) -> Result<String> {
	let session = lookup(&params.host, &params.session_id)?;
	let status = session
		.status
		.lock()
		.map_err(|_| anyhow!("PTY status lock poisoned"))?
		.clone();
	let output = session
		.output
		.lock()
		.map_err(|_| anyhow!("PTY output lock poisoned"))?;
	let requested = params.offset.unwrap_or(output.base_offset);
	let limit = params.limit.unwrap_or(65_536).clamp(1, MAX_READ_BYTES);
	let (offset, next_offset, truncated, text) = output.read(requested, limit);
	Ok(serde_json::to_string_pretty(&json!({
		"session_id": session.id,
		"host": session.host,
		"offset": offset,
		"next_offset": next_offset,
		"truncated_before_offset": truncated,
		"text": text,
		"status": status,
	}))?)
}

pub async fn write_pty(params: PtyWriteParams) -> Result<String> {
	if params.data.len() > MAX_WRITE_BYTES {
		bail!("PTY write exceeds 64 KiB");
	}
	let session = lookup(&params.host, &params.session_id)?;
	let mut guard = session.stdin.lock().await;
	let stdin = guard
		.as_mut()
		.ok_or_else(|| anyhow!("PTY stdin is already closed"))?;
	stdin.write_all(params.data.as_bytes()).await?;
	stdin.flush().await?;
	Ok(serde_json::to_string_pretty(&json!({
		"session_id": params.session_id,
		"bytes_written": params.data.len(),
	}))?)
}

pub async fn close_pty(params: PtyRefParams) -> Result<String> {
	let session = lookup(&params.host, &params.session_id)?;
	session.stdin.lock().await.take();
	#[cfg(unix)]
	unsafe {
		libc::kill(session.pid as i32, libc::SIGTERM);
	}
	Ok(serde_json::to_string_pretty(&json!({
		"session_id": params.session_id,
		"signal": "SIGTERM",
	}))?)
}

pub fn close_all_ptys() {
	if let Ok(mut sessions) = registry().lock() {
		#[cfg(unix)]
		for session in sessions.values() {
			unsafe {
				libc::kill(session.pid as i32, libc::SIGTERM);
			}
		}
		sessions.clear();
	}
}

pub fn list_ptys(params: PtyListParams) -> Result<String> {
	if let Some(host) = params.host.as_deref() {
		runtime_config()?.host(host)?;
	}
	let sessions: Vec<Value> = registry()
		.lock()
		.map_err(|_| anyhow!("PTY registry lock poisoned"))?
		.values()
		.filter(|session| {
			params
				.host
				.as_ref()
				.is_none_or(|host| &session.host == host)
		})
		.map(|session| {
			let status = session.status.lock().ok().map(|value| value.clone());
			json!({
				"session_id": session.id,
				"host": session.host,
				"pid": session.pid,
				"created_unix_ms": session.created_unix_ms,
				"status": status,
			})
		})
		.collect();
	Ok(serde_json::to_string_pretty(
		&json!({"sessions": sessions}),
	)?)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ring_tracks_dropped_prefix() {
		let mut ring = RingBuffer::new();
		ring.append(&vec![b'x'; MAX_BUFFER_BYTES + 7]);
		assert_eq!(ring.base_offset, 7);
		let (_, _, truncated, _) = ring.read(0, 32);
		assert!(truncated);
	}
}
