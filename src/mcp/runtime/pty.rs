// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Controller-scoped interactive SSH sessions with owned cancellation.
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
use super::config::{ExecutionMode, Platform};
use super::jobs::audit;
use super::ssh::{build_exec_command, run_jobctl};
use tokio_util::sync::CancellationToken;

const MAX_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const MAX_READ_BYTES: usize = 16 * 1024;
const MAX_WRITE_BYTES: usize = 64 * 1024;
static PTY_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static PTYS: OnceLock<Mutex<HashMap<String, PtySession>>> = OnceLock::new();

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct PtyRefParams {
	pub host: String,
	pub session_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PtyReadParams {
	pub host: String,
	pub session_id: String,
	#[serde(default)]
	pub offset: Option<u64>,
	#[serde(default)]
	pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PtyWriteParams {
	pub host: String,
	pub session_id: String,
	/// UTF-8 data sent exactly as provided; control characters such as \u0003 are allowed.
	pub data: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
	stop: CancellationToken,
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
	if registry()
		.lock()
		.map_err(|_| anyhow!("PTY registry lock poisoned"))?
		.len() >= 128
	{
		bail!("PTY session limit reached");
	}
	let id = next_id();
	let rows = params.rows.unwrap_or(24).clamp(1, 500);
	let cols = params.cols.unwrap_or(120).clamp(1, 1000);
	let mut remote = build_exec_command(
		&params.executable,
		&params.args,
		params.cwd.as_deref(),
		&params.env,
		rows,
		cols,
	)?;
	let system_jobctl =
		host.platform == Platform::Linux && host.execution_mode == ExecutionMode::Isolated;
	if system_jobctl {
		remote = format!("stty -echo rows {rows} cols {cols}; exec sudo -n /usr/local/libexec/hepta-runtime-jobctl");
	}
	let mut command = Command::new("ssh");
	command
		.arg("-tt")
		.arg("-o")
		.arg("BatchMode=yes")
		.arg("-o")
		.arg("ConnectTimeout=8")
		.arg("-o")
		.arg("StrictHostKeyChecking=yes")
		.arg("-o")
		.arg("ForwardAgent=no")
		.arg(&host.ssh_target)
		.arg(remote)
		.env("TERM", "xterm-256color")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(false);
	let mut child = command.spawn()?;
	let pid = child.id().ok_or_else(|| anyhow!("ssh child has no PID"))?;
	let mut input = child.stdin.take();
	if system_jobctl {
		let mut payload = serde_json::to_vec(
			&json!({"op":"pty","job_id":id,"executable":params.executable,"args":params.args,"cwd":params.cwd,"env":params.env,"timeout_seconds":3600}),
		)?;
		payload.push(b'\n');
		if let Some(pipe) = input.as_mut() {
			pipe.write_all(&payload).await?;
			pipe.flush().await?;
		}
	}
	let stdin = Arc::new(AsyncMutex::new(input));
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
	let stop = CancellationToken::new();
	let cancelled = stop.clone();
	let remote_job_id = id.clone();
	tokio::spawn(async move {
		let waited = tokio::select! {
			result = child.wait() => result,
			_ = cancelled.cancelled() => {
				if system_jobctl { let _ = run_jobctl(host, &json!({"op":"cancel","job_id":remote_job_id})).await; }
				// Only the task owning the Child can terminate it. No stored PID signal.
				let _ = child.start_kill();
				child.wait().await
			}
		};
		let next = match waited {
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
	let session = PtySession {
		stop,
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
	audit(
		"pty_start",
		&params.host,
		&id,
		&json!({"rows":rows,"cols":cols,"restart_persistent":false}),
	)?;
	Ok(serde_json::to_string_pretty(&json!({
		"session_id": id,
		"host": params.host,
		"pid": pid,
		"pid_scope": "controller_ssh",
		"execution_mode": host.execution_mode,
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
	if requested > output.base_offset + output.data.len() as u64 {
		bail!("PTY cursor exceeds available output; refusing silent forward seek");
	}
	let limit = params.limit.unwrap_or(65_536).clamp(1, MAX_READ_BYTES);
	let (offset, next_offset, truncated, text) = output.read(requested, limit);
	let begin = (offset - output.base_offset) as usize;
	let end = (next_offset - output.base_offset) as usize;
	let bytes_hex: String = output.data[begin..end]
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect();
	Ok(serde_json::to_string_pretty(&json!({
		"session_id": session.id,
		"host": session.host,
		"offset": offset,
		"next_offset": next_offset,
		"available_end": output.base_offset + output.data.len() as u64,
		"truncated_before_offset": truncated,
		"text": text,
		"bytes_hex": bytes_hex,
		"status": status,
	}))?)
}

pub async fn write_pty(params: PtyWriteParams) -> Result<String> {
	if params.data.len() > MAX_WRITE_BYTES {
		bail!("PTY write exceeds 64 KiB");
	}
	let session = lookup(&params.host, &params.session_id)?;
	if !matches!(
		session
			.status
			.lock()
			.map_err(|_| anyhow!("PTY status lock poisoned"))?
			.state,
		PtyState::Running
	) {
		bail!("PTY process has exited; input is not accepted");
	}
	let mut guard = session.stdin.lock().await;
	let stdin = guard
		.as_mut()
		.ok_or_else(|| anyhow!("PTY stdin is already closed"))?;
	tokio::time::timeout(std::time::Duration::from_secs(5), async {
		stdin.write_all(params.data.as_bytes()).await?;
		stdin.flush().await
	})
	.await
	.map_err(|_| anyhow!("PTY input timeout"))??;
	audit(
		"pty_write",
		&params.host,
		&params.session_id,
		&json!({"bytes_written":params.data.len()}),
	)?;
	Ok(serde_json::to_string_pretty(&json!({
		"session_id": params.session_id,
		"bytes_written": params.data.len(),
	}))?)
}

pub async fn close_pty(params: PtyRefParams) -> Result<String> {
	let session = lookup(&params.host, &params.session_id)?;
	session.stdin.lock().await.take();
	session.stop.cancel();
	audit(
		"pty_close",
		&params.host,
		&params.session_id,
		&json!({"close_requested":true}),
	)?;
	Ok(serde_json::to_string_pretty(&json!({
		"session_id": params.session_id,
		"result": "close_requested",
	}))?)
}

pub async fn close_all_ptys() {
	let sessions = match registry().lock() {
		Ok(mut sessions) => sessions.drain().map(|(_, s)| s).collect::<Vec<_>>(),
		Err(_) => return,
	};
	for session in &sessions {
		session.stop.cancel();
	}
	for _ in 0..240 {
		let running = sessions.iter().any(|s| {
			s.status
				.lock()
				.is_ok_and(|v| matches!(v.state, PtyState::Running))
		});
		if !running {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
#[path = "pty_tests.rs"]
mod tests;
