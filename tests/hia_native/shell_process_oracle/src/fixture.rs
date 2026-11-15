// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Read-only capture observer and JSONL control for the original owner.
//!
//! A controller-provided command gate holds execution until this observer has
//! opened both original capture files. The controller releases that same gate
//! for both implementations. Open FDs preserve the original foreground bytes
//! after the unchanged owner unlinks its files.
//!
//! stdin belongs to a detached std::thread, never Tokio's blocking stdin pool:
//! a completed case can exit naturally while its controller still holds stdin.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::BufRead;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

use crate::mcp::fs::{background, shell};
use crate::mcp::McpToolCall;

const EVENT_SCHEMA: &str = "hepta.runtime.shell-process-fixture-event.v1";

enum Input {
	Line(std::result::Result<String, String>),
	Eof,
}

#[derive(Clone)]
struct Emitter {
	sender: mpsc::UnboundedSender<Value>,
	serial: Arc<Mutex<u64>>,
	start: Instant,
}

impl Emitter {
	fn emit(&self, mut value: Value) {
		if let (Ok(mut seq), Some(object)) = (self.serial.lock(), value.as_object_mut()) {
			*seq += 1;
			object.insert("schema".to_string(), json!(EVENT_SCHEMA));
			object.insert("seq".to_string(), json!(*seq));
			object.insert("oracle_pid".to_string(), json!(std::process::id()));
			object.insert(
				"elapsed_ns".to_string(),
				json!(u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX)),
			);
			object.insert(
				"unix_ns".to_string(),
				json!(u64::try_from(
					SystemTime::now()
						.duration_since(UNIX_EPOCH)
						.unwrap_or_default()
						.as_nanos()
				)
				.unwrap_or(u64::MAX)),
			);
			let _ = self.sender.send(value);
		}
	}
}

fn hex(bytes: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut value = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		value.push(DIGITS[(byte >> 4) as usize] as char);
		value.push(DIGITS[(byte & 15) as usize] as char);
	}
	value
}

fn unhex(value: &str) -> Result<Vec<u8>> {
	if value.len() % 2 != 0 || !value.is_ascii() {
		bail!("fixture hex must contain an even number of ASCII digits");
	}
	let mut bytes = Vec::with_capacity(value.len() / 2);
	for pair in value.as_bytes().chunks_exact(2) {
		fn digit(c: u8) -> Result<u8> {
			match c {
				b'0'..=b'9' => Ok(c - b'0'),
				b'a'..=b'f' => Ok(c - b'a' + 10),
				_ => bail!("fixture hex must be canonical lowercase"),
			}
		}
		bytes.push(digit(pair[0])? * 16 + digit(pair[1])?);
	}
	Ok(bytes)
}

fn job_value(job: &background::Job) -> Value {
	let (state, code) = match job.status() {
		background::JobStatus::Running => ("running", None),
		background::JobStatus::Exited(code) => ("exited", Some(code)),
	};
	json!({
		"id":job.id, "pid":job.pid, "command":job.command,
		"working_dir_hex":hex(job.working_dir.as_os_str().as_bytes()),
		"stdout_path":job.stdout_path.to_string_lossy(),
		"stderr_path":job.stderr_path.to_string_lossy(),
		"stdout_path_hex":hex(job.stdout_path.as_os_str().as_bytes()),
		"stderr_path_hex":hex(job.stderr_path.as_os_str().as_bytes()),
		"started_unix":job.started_unix, "status":state, "exit_code":code
	})
}

fn snapshot() -> Value {
	let mut jobs = background::list();
	jobs.sort_by(|a, b| a.id.cmp(&b.id));
	json!({
		"tracker_pids":shell::fixture_tracked_pids(),
		"background_jobs":jobs.iter().map(job_value).collect::<Vec<_>>()
	})
}

fn job_for_uri(uri: &str) -> Option<background::Job> {
	let id = background::job_id_from_uri(uri)?;
	background::list().into_iter().find(|job| job.id == id)
}

fn proc_start(raw: &str) -> Option<&str> {
	raw.rsplit_once(") ")?.1.split_whitespace().nth(19)
}

async fn proc_stat(pid: u32) -> Option<String> {
	tokio::fs::read_to_string(format!("/proc/{pid}/stat"))
		.await
		.ok()
}

async fn reaped(pid: u32, original_stat: Option<&str>) -> Option<bool> {
	match proc_stat(pid).await {
		None => Some(true),
		Some(now) => match original_stat.and_then(proc_start) {
			Some(before) => Some(proc_start(&now).is_some_and(|after| after != before)),
			None => Some(false),
		},
	}
}

struct Capture {
	stdout: tokio::fs::File,
	stderr: tokio::fs::File,
	stdout_source: PathBuf,
	stderr_source: PathBuf,
	pid: Option<u32>,
	initial_proc_stat: Option<String>,
}

async fn observe_capture(
	emitter: Emitter,
	finished: watch::Receiver<bool>,
	destination: PathBuf,
) -> Result<Option<Capture>> {
	// Only observation duplicates this path construction. Original prepare,
	// next_id, file creation, spawning, waiting and discard are not replaced.
	let owner = std::process::id();
	let directory = std::env::temp_dir().join(format!("octofs-jobs-{owner}"));
	let stdout_source = directory.join(format!("{owner}-1.stdout.log"));
	let stderr_source = directory.join(format!("{owner}-1.stderr.log"));
	let mut stdout = None;
	let mut stderr = None;
	loop {
		if stdout.is_none() {
			stdout = tokio::fs::File::open(&stdout_source).await.ok();
		}
		if stderr.is_none() {
			stderr = tokio::fs::File::open(&stderr_source).await.ok();
		}
		let pids = shell::fixture_tracked_pids();
		let done = *finished.borrow();
		if stdout.is_some() && stderr.is_some() && (!pids.is_empty() || done) {
			let pid = pids.first().copied();
			let initial_proc_stat = match pid {
				Some(pid) => proc_stat(pid).await,
				None => None,
			};
			if let Some(pid) = pid {
				let stdin_link = tokio::fs::read_link(format!("/proc/{pid}/fd/0")).await.ok();
				let status = tokio::fs::read_to_string(format!("/proc/{pid}/status"))
					.await
					.ok();
				emitter.emit(json!({
					"event":"capture_ready", "pid":pid,
					"stdout_source_path":stdout_source.to_string_lossy(),
					"stderr_source_path":stderr_source.to_string_lossy(),
					"stdout_capture_path":destination.join("stdout.bin").to_string_lossy(),
					"stderr_capture_path":destination.join("stderr.bin").to_string_lossy(),
					"tracker_pids":pids, "initial_proc_stat":initial_proc_stat,
					"initial_proc_status":status,
					"stdin_link_hex":stdin_link.as_ref().map(|p| hex(p.as_os_str().as_bytes())),
					"observer":"read-only original log FDs; controller releases shared fixture gate"
				}));
			}
			if let (Some(stdout), Some(stderr)) = (stdout.take(), stderr.take()) {
				return Ok(Some(Capture {
					stdout,
					stderr,
					stdout_source,
					stderr_source,
					pid,
					initial_proc_stat,
				}));
			}
		}
		if done {
			return Ok(None);
		}
		tokio::time::sleep(Duration::from_millis(1)).await;
	}
}

async fn retain_capture(
	capture: Option<Capture>,
	destination: &Path,
) -> Result<(Value, Option<u32>, Option<String>)> {
	let Some(mut capture) = capture else {
		return Ok((
			json!({
				"observed":false, "stdout_path":null, "stderr_path":null,
				"stdout_bytes":null, "stderr_bytes":null,
				"source_paths_exist":null,
				"reason":"original files were not both opened before owner completed"
			}),
			None,
			None,
		));
	};
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	capture
		.stdout
		.read_to_end(&mut stdout)
		.await
		.context("read original stdout FD")?;
	capture
		.stderr
		.read_to_end(&mut stderr)
		.await
		.context("read original stderr FD")?;
	let stdout_path = destination.join("stdout.bin");
	let stderr_path = destination.join("stderr.bin");
	let mut out = tokio::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&stdout_path)
		.await
		.context("create retained stdout")?;
	out.write_all(&stdout).await?;
	out.flush().await?;
	let mut err = tokio::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&stderr_path)
		.await
		.context("create retained stderr")?;
	err.write_all(&stderr).await?;
	err.flush().await?;
	let stdout_exists = tokio::fs::try_exists(&capture.stdout_source).await?;
	let stderr_exists = tokio::fs::try_exists(&capture.stderr_source).await?;
	Ok((
		json!({
			"observed":true,
			"stdout_path":stdout_path.to_string_lossy(),
			"stderr_path":stderr_path.to_string_lossy(),
			"stdout_bytes":stdout.len(), "stderr_bytes":stderr.len(),
			"stdout_source_path":capture.stdout_source.to_string_lossy(),
			"stderr_source_path":capture.stderr_source.to_string_lossy(),
			"source_paths_exist":{"stdout":stdout_exists,"stderr":stderr_exists},
			"complete_read_from_original_file_descriptors":true,
			"original_paths_mutated_by_observer":false
		}),
		capture.pid,
		capture.initial_proc_stat,
	))
}

fn errno_from_message(message: &str) -> Option<i32> {
	message
		.rsplit_once("(os error ")?
		.1
		.strip_suffix(')')?
		.parse()
		.ok()
}

fn exit_from_message(message: &str) -> Option<i32> {
	let suffix = message
		.strip_prefix("Command failed with exit code ")
		.or_else(|| message.strip_prefix("Command exited with code "))?;
	suffix
		.split(|c: char| !(c.is_ascii_digit() || c == '-'))
		.next()?
		.parse()
		.ok()
}

async fn output(writer: &mut tokio::io::Stdout, value: &Value) -> Result<()> {
	let mut bytes = serde_json::to_vec(value)?;
	bytes.push(b'\n');
	writer.write_all(&bytes).await?;
	writer.flush().await?;
	Ok(())
}

fn shutdown(emitter: &Emitter, reason: &str) {
	let before = shell::fixture_tracked_pids();
	shell::kill_all_shell_children();
	emitter.emit(json!({
		"event":"shutdown","reason":reason,
		"tracker_before":before,"tracker_after":shell::fixture_tracked_pids(),
		"owner_function":"kill_all_shell_children"
	}));
}

pub async fn run() -> Result<()> {
	let (input_tx, mut inputs) = mpsc::unbounded_channel();
	// The JoinHandle is deliberately detached; main never waits on an open
	// controller stdin after the original owner and capture observer finish.
	std::thread::Builder::new()
		.name("shell-original-fixture-stdin".to_string())
		.spawn(move || {
			let stdin = std::io::stdin();
			for line in stdin.lock().lines() {
				if input_tx
					.send(Input::Line(line.map_err(|e| e.to_string())))
					.is_err()
				{
					return;
				}
			}
			let _ = input_tx.send(Input::Eof);
		})
		.context("start fixture stdin reader")?;
	let first = match inputs.recv().await {
		Some(Input::Line(Ok(line))) => serde_json::from_str::<Value>(&line)?,
		Some(Input::Line(Err(error))) => bail!("fixture stdin: {error}"),
		Some(Input::Eof) | None => return Ok(()),
	};
	if first.get("op").and_then(Value::as_str) != Some("execute") {
		bail!("first fixture request must be execute");
	}
	let command = match (first.get("command"), first.get("command_hex")) {
		(Some(Value::String(text)), None) => text.clone(),
		(None, Some(Value::String(encoded))) => String::from_utf8(unhex(encoded)?)?,
		_ => bail!("provide exactly one UTF8 command or command_hex"),
	};
	let cwd = unhex(
		first
			.get("cwd_hex")
			.and_then(Value::as_str)
			.ok_or_else(|| anyhow!("fixture cwd_hex is required"))?,
	)?;
	let timeout_ms = first
		.get("timeout_ms")
		.and_then(Value::as_u64)
		.ok_or_else(|| anyhow!("fixture timeout_ms must be an unsigned integer"))?;
	let capture_dir = PathBuf::from(
		first
			.get("capture_dir")
			.and_then(Value::as_str)
			.ok_or_else(|| anyhow!("fixture capture_dir is required"))?,
	);
	if !capture_dir.is_absolute() {
		bail!("fixture capture_dir must be absolute");
	}
	tokio::fs::create_dir_all(&capture_dir).await?;
	if tokio::fs::read_dir(&capture_dir)
		.await?
		.next_entry()
		.await?
		.is_some()
	{
		bail!("fixture capture_dir must be empty");
	}
	let call = McpToolCall {
		tool_name: "shell".to_string(),
		tool_id: "source-bound-process-fixture".to_string(),
		parameters: json!({"command":command}),
		workdir: PathBuf::from(std::ffi::OsString::from_vec(cwd.clone())),
	};
	let (event_tx, mut events) = mpsc::unbounded_channel();
	let emitter = Emitter {
		sender: event_tx,
		serial: Arc::new(Mutex::new(0)),
		start: Instant::now(),
	};
	emitter.emit(json!({
		"event":"started","command_hex":hex(command.as_bytes()),"cwd_hex":hex(&cwd),
		"timeout_ms":timeout_ms,"capture_dir":capture_dir.to_string_lossy(),
		"owner_entry":"unchanged execute_with_timeout",
		"request_context":"complete original request_ctx; original ViewCache type only",
		"stdin_reader":"detached std::thread; no Tokio blocking stdin"
	}));
	let (finish_tx, finish_rx) = watch::channel(false);
	let observer = tokio::spawn(observe_capture(
		emitter.clone(),
		finish_rx,
		capture_dir.clone(),
	));
	let completion_count = Arc::new(AtomicU64::new(0));
	let count_for_notify = completion_count.clone();
	let notify_emitter = emitter.clone();
	let on_background: shell::BackgroundNotify = Box::new(move |uri| {
		let count = count_for_notify.fetch_add(1, Ordering::SeqCst) + 1;
		let job = job_for_uri(&uri);
		let code = job.as_ref().and_then(|job| match job.status() {
			background::JobStatus::Running => None,
			background::JobStatus::Exited(code) => Some(code),
		});
		notify_emitter.emit(json!({
			"event":"completion","resource_uri":uri,
			"job_id":job.as_ref().map(|job| job.id.clone()),
			"pid":job.as_ref().map(|job| job.pid),
			"exit_code":code,"callback_count":count,
			"tracker_pids":shell::fixture_tracked_pids(),
			"raw_wait_status":null,"raw_wait_status_observable":false,
			"snapshot":snapshot()
		}));
	});
	let mut caller = tokio::spawn(async move {
		let cache = Arc::new(crate::mcp::fs::delta::ViewCache::default());
		crate::mcp::request_ctx::with_request_context(cache, async move {
			let result = shell::fixture_execute(
				&call,
				Duration::from_millis(timeout_ms),
				Some(on_background),
			)
			.await;
			(result, crate::mcp::request_ctx::drain_hints())
		})
		.await
	});
	let mut writer = tokio::io::stdout();
	let mut caller_done = false;
	let mut completion_seen = false;
	let mut stdin_closed = false;
	let mut cancel_requested = false;
	let mut cancelled_at: Option<Instant> = None;
	let mut outcome = "running";
	let mut resource_uri: Option<String> = None;
	let mut child_pid: Option<u32> = None;
	let mut child_initial_stat: Option<String> = None;
	let mut tick = tokio::time::interval(Duration::from_millis(2));
	loop {
		tokio::select! {
			joined = &mut caller, if !caller_done => {
				caller_done = true;
				match joined {
					Ok((Ok(value),hints)) => {
						if let Some(uri) = value.resource_uri {
							outcome = "background";
							resource_uri = Some(uri.clone());
							let job = job_for_uri(&uri);
							emitter.emit(json!({
								"event":"promoted","text":value.text,"resource_uri":uri,
								"job_id":job.as_ref().map(|job|job.id.clone()),
								"pid":job.as_ref().map(|job|job.pid),
								"hints":hints,"tracker_pids":shell::fixture_tracked_pids(),
								"job":job.as_ref().map(job_value),"snapshot":snapshot()
							}));
							if cancel_requested {
								emitter.emit(json!({
									"event":"cancelled","phase":"background",
									"caller_aborted":false,"background_waiter_aborted":false,
									"tracker_pids":shell::fixture_tracked_pids()
								}));
							}
						} else {
							outcome = "foreground";
							emitter.emit(json!({
								"event":"foreground","ok":true,"text":value.text,"error":null,
								"error_chain":[],"os_error_from_message":null,
								"error_io_kind_from_chain":null,"exit_code_from_owner_result":0,
								"hints":hints,"tracker_pids":shell::fixture_tracked_pids(),
								"raw_wait_status":null,"raw_wait_status_observable":false,
								"snapshot":snapshot()
							}));
						}
					}
					Ok((Err(error),hints)) => {
						outcome = "error";
						let text = error.to_string();
						let io_kind = error.downcast_ref::<std::io::Error>()
							.map(|io|format!("{:?}",io.kind()));
						emitter.emit(json!({
							"event":"foreground","ok":false,"text":null,"error":text,
							"error_chain":error.chain().map(|cause|cause.to_string()).collect::<Vec<_>>(),
							"os_error_from_message":errno_from_message(&text),
							"error_io_kind_from_chain":io_kind,
							"exit_code_from_owner_result":exit_from_message(&text),
							"hints":hints,"tracker_pids":shell::fixture_tracked_pids(),
							"raw_wait_status":null,"raw_wait_status_observable":false,
							"snapshot":snapshot()
						}));
					}
					Err(error) if error.is_cancelled() => {
						outcome = "cancelled";
						cancelled_at = Some(Instant::now());
						emitter.emit(json!({
							"event":"cancelled","phase":"foreground",
							"caller_aborted":true,"caller_join_observed":true,
							"background_waiter_aborted":false,
							"tracker_pids":shell::fixture_tracked_pids(),
							"owner_cleanup":"original Child kill_on_drop only; no implicit kill_all/discard/unregister"
						}));
					}
					Err(error) => return Err(anyhow!("original caller task: {error}")),
				}
			}
			event = events.recv() => {
				if let Some(event) = event {
					match event.get("event").and_then(Value::as_str) {
						Some("capture_ready") => {
							child_pid = event.get("pid").and_then(Value::as_u64).and_then(|v|u32::try_from(v).ok());
							child_initial_stat = event.get("initial_proc_stat").and_then(Value::as_str).map(str::to_owned);
						}
						Some("completion") => completion_seen = true,
						_ => {}
					}
					output(&mut writer,&event).await?;
				}
			}
			input = inputs.recv(), if !stdin_closed => {
				match input {
					Some(Input::Line(Ok(line))) => {
						let value: Value = serde_json::from_str(&line)?;
						match value.get("op").and_then(Value::as_str) {
							Some("cancel") => {
								if !caller_done {
									cancel_requested = true;
									caller.abort();
								} else {
									emitter.emit(json!({
										"event":"cancelled","phase":if outcome=="background" {"background"} else {"completed"},
										"caller_aborted":false,"background_waiter_aborted":false,
										"tracker_pids":shell::fixture_tracked_pids()
									}));
								}
							}
							Some("shutdown") => shutdown(&emitter,"explicit"),
							_ => bail!("fixture accepts cancel/shutdown after execute"),
						}
					}
					Some(Input::Line(Err(error))) => bail!("fixture stdin: {error}"),
					Some(Input::Eof) | None => {
						stdin_closed = true;
						shutdown(&emitter,"stdin_eof");
					}
				}
			}
			_ = tick.tick() => {}
		}
		let done = match outcome {
			"foreground" | "error" => caller_done,
			"background" => caller_done && completion_seen,
			"cancelled" => {
				// This observation window gives a controller time to send an
				// explicit same-owner shutdown. It never kills/reaps a child.
				let elapsed = cancelled_at
					.map(|start| start.elapsed())
					.unwrap_or_default();
				let gone = match child_pid {
					Some(pid) => reaped(pid, child_initial_stat.as_deref())
						.await
						.unwrap_or(false),
					None => shell::fixture_tracked_pids().is_empty(),
				};
				elapsed >= Duration::from_millis(50) && gone || elapsed >= Duration::from_secs(5)
			}
			_ => false,
		};
		if done {
			break;
		}
	}
	let _ = finish_tx.send(true);
	let capture = observer.await.context("capture observer task")??;
	// Flush capture_ready/completion queued at the finish boundary before final.
	while let Ok(event) = events.try_recv() {
		if event.get("event").and_then(Value::as_str) == Some("capture_ready") {
			child_pid = event
				.get("pid")
				.and_then(Value::as_u64)
				.and_then(|v| u32::try_from(v).ok());
			child_initial_stat = event
				.get("initial_proc_stat")
				.and_then(Value::as_str)
				.map(str::to_owned);
		}
		output(&mut writer, &event).await?;
	}
	let (raw_capture, captured_pid, captured_stat) = retain_capture(capture, &capture_dir).await?;
	child_pid = child_pid.or(captured_pid);
	if child_initial_stat.is_none() {
		child_initial_stat = captured_stat;
	}
	let child_reaped = match child_pid {
		Some(pid) => reaped(pid, child_initial_stat.as_deref()).await,
		None => None,
	};
	let resource_text = resource_uri
		.as_ref()
		.and_then(|uri| background::job_id_from_uri(uri))
		.and_then(background::resource_text);
	emitter.emit(json!({
		"event":"final","outcome":outcome,"raw_capture":raw_capture,
		"pid":child_pid,"tracker_pids":shell::fixture_tracked_pids(),
		"callback_count":completion_count.load(Ordering::SeqCst),
		"child_reaped_observed":child_reaped,"resource_uri":resource_uri,
		"resource_text":resource_text,"snapshot":snapshot(),
		"raw_wait_status":null,"raw_wait_status_observable":false,
		"implicit_shutdown_performed":false,
		"original_owner_bodies_changed":false
	}));
	while let Ok(event) = events.try_recv() {
		output(&mut writer, &event).await?;
	}
	writer.flush().await?;
	Ok(())
}
