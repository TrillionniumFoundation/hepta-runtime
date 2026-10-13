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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

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
static PTY_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
const MAX_ACTIVE_SESSIONS: usize = 128;
const MAX_TRACKED_SESSIONS: usize = 256;

fn reserve_pty_slot() -> Result<OwnedSemaphorePermit> {
	PTY_SLOTS
		.get_or_init(|| Arc::new(Semaphore::new(MAX_ACTIVE_SESSIONS)))
		.clone()
		.try_acquire_owned()
		.map_err(|_| anyhow!("active PTY session limit reached"))
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PtyStartParams {
	/// Operator terminals reuse the same key after an uncertain launch acknowledgement.
	#[serde(default)]
	pub idempotency_key: Option<String>,
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
	/// Preferred page bytes; text pages may extend up to 3 bytes to fit one character.
	pub limit: Option<usize>,
	/// Keep exact byte page boundaries instead of UTF-8-safe text boundaries.
	/// Use bytes_hex for binary data; text_is_lossy labels invalid UTF-8 views.
	#[serde(default)]
	pub raw_bytes: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PtyWriteParams {
	/// Optional deduplication key for input sent to a persistent operator terminal.
	#[serde(default)]
	pub request_id: Option<String>,
	pub host: String,
	pub session_id: String,
	/// UTF-8 data sent exactly as provided; control characters such as \u0003 are allowed.
	pub data: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PtyListParams {
	#[serde(default)]
	pub after_session_id: Option<String>,
	#[serde(default)]
	pub limit: Option<usize>,
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

// Invalid bytes are retained; only an incomplete trailing character waits for
// more input. Callers can explicitly select raw byte pages without waiting.
fn complete_prefix(bytes: &[u8]) -> usize {
	let mut offset = 0;
	while offset < bytes.len() {
		match std::str::from_utf8(&bytes[offset..]) {
			Ok(_) => return bytes.len(),
			Err(error) => {
				offset += error.valid_up_to();
				match error.error_len() {
					Some(n) => offset += n,
					None => return offset,
				}
			}
		}
	}
	offset
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

	fn read(
		&self,
		requested: u64,
		limit: usize,
		finished: bool,
		raw_bytes: bool,
	) -> (u64, u64, bool, String) {
		let truncated = requested < self.base_offset;
		let offset = requested.max(self.base_offset);
		let start = (offset - self.base_offset) as usize;
		if start >= self.data.len() {
			return (offset, offset, truncated, String::new());
		}
		let mut end = (start + limit.clamp(1, MAX_READ_BYTES)).min(self.data.len());
		if !(raw_bytes || finished && end == self.data.len()) {
			end = start + complete_prefix(&self.data[start..end]);
			if end == start {
				let expanded = (start + 4).min(self.data.len());
				end = if finished && expanded == self.data.len() {
					expanded
				} else {
					start + complete_prefix(&self.data[start..expanded])
				};
			}
		}
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

async fn copy_reader<R>(mut reader: R, output: Arc<Mutex<RingBuffer>>) -> std::io::Result<()>
where
	R: AsyncRead + Unpin,
{
	let mut buf = vec![0_u8; 8192];
	loop {
		match reader.read(&mut buf).await {
			Ok(0) => return Ok(()),
			Ok(n) => {
				output
					.lock()
					.map_err(|_| std::io::Error::other("PTY output lock poisoned"))?
					.append(&buf[..n]);
			}
			Err(error) => return Err(error),
		}
	}
}

async fn drain_readers(
	readers: Vec<tokio::task::JoinHandle<std::io::Result<()>>>,
	deadline: std::time::Duration,
) -> Option<String> {
	let mut failures = Vec::new();
	for mut reader in readers {
		match tokio::time::timeout(deadline, &mut reader).await {
			Ok(Ok(Ok(()))) => {}
			Ok(Ok(Err(error))) => failures.push(format!("output read failed: {error}")),
			Ok(Err(error)) => failures.push(format!("output reader task failed: {error}")),
			Err(_) => {
				reader.abort();
				let _ = reader.await;
				failures.push("output drain deadline exceeded".into());
			}
		}
	}
	if failures.is_empty() {
		None
	} else {
		Some(failures.join("; "))
	}
}

pub(super) fn require_pty_intent(outcome: Result<()>) -> Result<()> {
	outcome.map_err(|_| anyhow!("PTY intent audit unavailable; no terminal operation dispatched"))
}

pub(super) fn unknown_pty_outcome(
	host: &str,
	id: &str,
	operation: &str,
	persistent: bool,
) -> Value {
	let mut value = json!({"host":host,"session_id":id,"operation":operation,"result":"pty_outcome_unknown",
		"outcome":"unknown","automatic_retry":false,"effect_confirmed":false,
		"persistent_across_runtime_restart":persistent,
		"reconcile_warning":"Terminal operation outcome is not confirmed. Inspect this existing session identity; do not repeat input or create a new terminal automatically."});
	if operation == "close" {
		value["termination_confirmed"] = json!(false);
	}
	value
}

pub(super) fn retain_pty_after_audit(mut result: Value, completion: Result<()>) -> Value {
	result["automatic_retry"] = json!(false);
	result["audit_recorded"] = json!(completion.is_ok());
	if completion.is_err() {
		result["audit_warning"] = json!("Terminal result retained; completion audit unavailable. Do not repeat the operation automatically.");
	}
	result
}

async fn write_input<W: AsyncWrite + Unpin>(
	input: &mut W,
	data: &[u8],
	deadline: std::time::Duration,
) -> Result<()> {
	tokio::time::timeout(deadline, async {
		input.write_all(data).await?;
		input.flush().await
	})
	.await
	.map_err(|_| anyhow!("PTY input acknowledgement timeout"))??;
	Ok(())
}

async fn dispatch_input<W: AsyncWrite + Unpin>(
	input: &mut W,
	host: &str,
	id: &str,
	data: &[u8],
	intent: Result<()>,
	deadline: std::time::Duration,
) -> Result<Value> {
	require_pty_intent(intent)?;
	let sent = write_input(input, data, deadline).await;
	Ok(if sent.is_ok() {
		json!({"session_id":id,"host":host,"bytes_written":data.len()})
	} else {
		unknown_pty_outcome(host, id, "write", false)
	})
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
	if host.execution_mode == ExecutionMode::Operator {
		return super::terminal::start(&params).await;
	}
	if params.idempotency_key.is_some() {
		bail!("PTY keys require an operator host");
	}
	// Reserve before any asynchronous launch, so concurrent starts cannot
	// overrun the cap. Closed sessions must not permanently consume capacity.
	let permit = reserve_pty_slot()?;
	{
		let mut sessions = registry()
			.lock()
			.map_err(|_| anyhow!("PTY registry lock poisoned"))?;
		if sessions.len() >= MAX_TRACKED_SESSIONS {
			sessions.retain(|_, session| {
				session
					.status
					.lock()
					.map(|status| matches!(status.state, PtyState::Running))
					.unwrap_or(true)
			});
		}
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
	let payload = if system_jobctl {
		let mut bytes = serde_json::to_vec(
			&json!({"op":"pty","job_id":id,"executable":params.executable,"args":params.args,"cwd":params.cwd,"env":params.env,"timeout_seconds":3600}),
		)?;
		bytes.push(b'\n');
		Some(bytes)
	} else {
		None
	};
	require_pty_intent(audit(
		"pty_start_intent",
		&params.host,
		&id,
		&json!({"phase":"intent","remote_operation_submitted":false}),
	))?;
	let mut child = command.spawn()?;
	let pid = child.id().unwrap_or(0);
	let stdin = Arc::new(AsyncMutex::new(child.stdin.take()));
	let output = Arc::new(Mutex::new(RingBuffer::new()));
	let mut reader_tasks = Vec::new();
	if let Some(stdout) = child.stdout.take() {
		reader_tasks.push(tokio::spawn(copy_reader(stdout, output.clone())));
	}
	if let Some(stderr) = child.stderr.take() {
		reader_tasks.push(tokio::spawn(copy_reader(stderr, output.clone())));
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
		let _permit = permit;
		let waited = tokio::select! {
			result = child.wait() => result,
			_ = cancelled.cancelled() => {
				if system_jobctl { let _ = run_jobctl(host, &json!({"op":"cancel","job_id":remote_job_id})).await; }
				// Only the task owning the Child can terminate it. No stored PID signal.
				let _ = child.start_kill();
				child.wait().await
			}
		};
		// Publish a terminal state only after final output has been drained.
		let capture_error = drain_readers(reader_tasks, std::time::Duration::from_secs(2)).await;
		let mut next = match waited {
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
		if let Some(error) = capture_error {
			next.detail = Some(match next.detail {
				Some(previous) => format!("{previous}; {error}"),
				None => error,
			});
		}
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
	// Register the owned child before sending its launch handshake. Partial input
	// or a lost flush acknowledgement must leave a discoverable close/read identity.
	let registered = match registry().lock() {
		Ok(mut sessions) => {
			sessions.insert(id.clone(), session.clone());
			true
		}
		Err(_) => {
			session.stop.cancel();
			false
		}
	};
	let handshake = if registered {
		if let Some(payload) = payload {
			let mut input = session.stdin.lock().await;
			match input.as_mut() {
				Some(pipe) => write_input(pipe, &payload, std::time::Duration::from_secs(5)).await,
				None => Err(anyhow!("PTY launch input unavailable")),
			}
		} else {
			Ok(())
		}
	} else {
		Err(anyhow!("PTY identity registration unavailable"))
	};
	let result = if handshake.is_ok() && pid != 0 {
		json!({"session_id":id,"host":params.host,"pid":pid,
			"pid_scope":"controller_ssh","execution_mode":host.execution_mode,
			"persistent_across_runtime_restart":false})
	} else {
		let mut unknown = unknown_pty_outcome(&params.host, &id, "start", false);
		unknown["pid"] = json!(pid);
		unknown["pid_scope"] = json!("controller_ssh");
		unknown["session_registered"] = json!(registered);
		unknown
	};
	let completion = audit(
		"pty_start",
		&params.host,
		&id,
		&json!({"phase":"result","rows":rows,"cols":cols,"restart_persistent":false,
			"outcome_unknown":result["outcome"]=="unknown"}),
	);
	Ok(serde_json::to_string_pretty(&retain_pty_after_audit(
		result, completion,
	))?)
}

pub async fn read_pty_async(params: PtyReadParams) -> Result<String> {
	if params.session_id.starts_with("dpty-") {
		super::terminal::read(&params).await
	} else {
		read_pty(params)
	}
}

pub async fn list_ptys_async(params: PtyListParams) -> Result<String> {
	let limit = params.limit.unwrap_or(128).clamp(1, 128);
	let (mut persisted, more) = super::terminal::list(
		params.host.as_deref(),
		params.after_session_id.as_deref(),
		limit,
	)
	.await?;
	let legacy: Value = serde_json::from_str(&list_ptys(params)?)?;
	let mut next = persisted.last().and_then(|v| v.get("session_id")).cloned();
	if let Some(values) = legacy.get("sessions").and_then(Value::as_array) {
		persisted.extend(values.iter().cloned());
	}
	if !more {
		next = None;
	}
	Ok(serde_json::to_string(
		&json!({"sessions":persisted,"has_more":more,"next_after_session_id":next}),
	)?)
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
	let finished = !matches!(status.state, PtyState::Running);
	let (offset, next_offset, truncated, text) =
		output.read(requested, limit, finished, params.raw_bytes);
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
		"text_is_lossy": std::str::from_utf8(&output.data[begin..end]).is_err(),
		"utf8_pending": !params.raw_bytes && !finished && begin == end && end < output.data.len(),
		"output_complete": !matches!(status.state, PtyState::Running) && status.detail.is_none(),
		"status": status,
	}))?)
}

pub async fn write_pty(params: PtyWriteParams) -> Result<String> {
	if params.session_id.starts_with("dpty-") {
		return super::terminal::write(&params).await;
	}
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
	let intent = audit(
		"pty_write_intent",
		&params.host,
		&params.session_id,
		&json!({"phase":"intent","bytes":params.data.len(),"remote_operation_submitted":false}),
	);
	let result = dispatch_input(
		stdin,
		&params.host,
		&params.session_id,
		params.data.as_bytes(),
		intent,
		std::time::Duration::from_secs(5),
	)
	.await?;
	let completion = audit(
		"pty_write",
		&params.host,
		&params.session_id,
		&json!({"phase":"result","bytes_written":result["bytes_written"],"outcome_unknown":result["outcome"]=="unknown"}),
	);
	Ok(serde_json::to_string_pretty(&retain_pty_after_audit(
		result, completion,
	))?)
}

pub async fn close_pty(params: PtyRefParams) -> Result<String> {
	if params.session_id.starts_with("dpty-") {
		return super::terminal::close(&params).await;
	}
	let session = lookup(&params.host, &params.session_id)?;
	require_pty_intent(audit(
		"pty_close_intent",
		&params.host,
		&params.session_id,
		&json!({"phase":"intent","remote_operation_submitted":false}),
	))?;
	session.stdin.lock().await.take();
	session.stop.cancel();
	let completion = audit(
		"pty_close",
		&params.host,
		&params.session_id,
		&json!({"phase":"result","close_requested":true}),
	);
	Ok(serde_json::to_string_pretty(&retain_pty_after_audit(
		json!({"session_id":params.session_id,"host":params.host,"result":"close_requested",
			"termination_confirmed":false}),
		completion,
	))?)
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

#[cfg(test)]
#[path = "pty_operator_tests.rs"]
mod operator_tests;
