// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded SSH transport using preconfigured hosts and verified keys.
use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Component, Path};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use super::config::HostConfig;

const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_OBSERVATION_BYTES: usize = 64 * 1024;
// Published only after successful startup, before accepting MCP requests.
// Shutdown never clears intent: a failed/stopped pool must not select direct SSH.
static FILE_OBSERVATIONS_REQUESTED: AtomicBool = AtomicBool::new(false);

fn validate_observation_bytes(command: &str, input: &[u8]) -> Result<()> {
	if command
		.len()
		.checked_add(input.len())
		.is_none_or(|bytes| bytes > MAX_OBSERVATION_BYTES)
	{
		bail!("observation_pool_payload_unsupported: queued command and stdin exceed64KiB; no fallback");
	}
	Ok(())
}

#[cfg(target_os = "linux")]
#[path = "ssh_observation_pool.rs"]
mod observation_pool;
#[cfg(target_os = "linux")]
pub use observation_pool::PoolGuard as ObservationPoolGuard;

#[cfg(not(target_os = "linux"))]
pub struct ObservationPoolGuard;
#[cfg(not(target_os = "linux"))]
impl ObservationPoolGuard {
	pub async fn shutdown(self) -> Result<()> {
		Ok(())
	}
}

pub async fn start_observation_pool(
	profile: Option<&Path>,
	file_observations: bool,
) -> Result<Option<ObservationPoolGuard>> {
	let Some(profile) = profile else {
		if file_observations {
			bail!("file observation pooling requires an explicit observation pool profile");
		}
		return Ok(None);
	};
	#[cfg(target_os = "linux")]
	{
		let guard = observation_pool::start(profile).await?;
		if file_observations {
			FILE_OBSERVATIONS_REQUESTED.store(true, Ordering::Release);
		}
		Ok(Some(guard))
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = profile;
		bail!("observation SSH pooling requires Linux");
	}
}

pub(super) fn file_observation_pool_requested() -> bool {
	FILE_OBSERVATIONS_REQUESTED.load(Ordering::Acquire)
}

pub fn freeze_observation_pool() {
	#[cfg(target_os = "linux")]
	observation_pool::freeze();
}

pub(super) fn observation_pool_requested() -> bool {
	#[cfg(target_os = "linux")]
	{
		observation_pool::requested()
	}
	#[cfg(not(target_os = "linux"))]
	{
		false
	}
}

pub(super) enum ObservationScript {
	Status,
	Read,
}

/// Only these existing process observations can enter the new transport.
/// There is no raw command, executable, address or caller-selected `op`.
pub(super) enum JobObservation<'a> {
	PythonStatus {
		job_id: &'a str,
		job_dir: &'a str,
		unit: &'a str,
		wait_seconds: u64,
	},
	PythonRead {
		job_id: &'a str,
		job_dir: &'a str,
		stdout_offset: u64,
		stderr_offset: u64,
		limit: u64,
	},
	SystemStatus {
		job_id: &'a str,
	},
	SystemRead {
		job_id: &'a str,
		stdout_offset: u64,
		stderr_offset: u64,
		limit: u64,
	},
}

/// File policy has already selected the configured read root. No caller can
/// choose an operation, script, executable, address, or extra JSON fields here.
pub(super) enum FileObservation<'a> {
	Info {
		root: &'a str,
		path: &'a str,
	},
	Read {
		root: &'a str,
		path: &'a str,
		offset: Option<u64>,
		limit: u64,
		expected_version: Option<&'a str>,
	},
}

fn prepare_file_observation(value: FileObservation<'_>) -> Result<(String, Vec<u8>)> {
	use serde_json::json;
	let fields: &[&str] = match &value {
		FileObservation::Info { root, path } => &[root, path],
		FileObservation::Read {
			root,
			path,
			expected_version,
			..
		} => &[root, path, expected_version.unwrap_or("")],
	};
	// Check borrowed originals before JSON clones or escaping can expand them.
	if fields
		.iter()
		.try_fold(0usize, |total, field| total.checked_add(field.len()))
		.is_none_or(|bytes| bytes > MAX_OBSERVATION_BYTES)
	{
		bail!(
			"observation_pool_payload_unsupported: original file fields exceed64KiB; no fallback"
		);
	}
	let input = match value {
		FileObservation::Info { root, path } => json!({"op":"info","root":root,"path":path}),
		FileObservation::Read {
			root,
			path,
			offset,
			limit,
			expected_version,
		} => {
			json!({"op":"read","root":root,"path":path,"offset":offset,"limit":limit,"expected_version":expected_version})
		}
	};
	let command = python_json_command("python3", super::binary::observation_source())?;
	let bytes = serde_json::to_vec(&input)?;
	validate_observation_bytes(&command, &bytes)?;
	Ok((command, bytes))
}

pub(super) async fn run_file_observation(
	host_name: &str,
	value: FileObservation<'_>,
) -> Result<serde_json::Value> {
	if !file_observation_pool_requested() {
		bail!("file observation pool was not requested");
	}
	let host = super::config::runtime_config()?.host(host_name)?;
	let (command, bytes) = prepare_file_observation(value)?;
	// This single capture establishes the original absolute budget before queueing.
	let output = capture_observation(host_name, command, bytes, Duration::from_secs(30)).await?;
	parse_file_observation(host, &output)
}

fn parse_file_observation(
	host: &HostConfig,
	output: &CapturedObservation,
) -> Result<serde_json::Value> {
	// Borrow the wrapper through status and JSON parsing. Global/admission leases
	// remain held here; the host lease already ended at the original SSH reap.
	if !output.status.success() {
		bail!(
			"remote helper on {} failed with {}\nstdout:\n{}\nstderr:\n{}",
			host.ssh_target,
			output.status.code().unwrap_or(-1),
			String::from_utf8_lossy(&output.stdout).trim(),
			String::from_utf8_lossy(&output.stderr).trim()
		);
	}
	serde_json::from_slice(&output.stdout).map_err(|error| {
		anyhow!(
			"remote helper on {} returned invalid JSON: {error}; output={}",
			host.ssh_target,
			String::from_utf8_lossy(&output.stdout)
		)
	})
}

fn prepare_observation(value: JobObservation<'_>) -> Result<(String, Vec<u8>, Duration, bool)> {
	use serde_json::json;
	let fields: &[&str] = match &value {
		JobObservation::PythonStatus {
			job_id,
			job_dir,
			unit,
			..
		} => &[job_id, job_dir, unit],
		JobObservation::PythonRead {
			job_id, job_dir, ..
		} => &[job_id, job_dir],
		JobObservation::SystemStatus { job_id } | JobObservation::SystemRead { job_id, .. } => {
			&[job_id]
		}
	};
	// Reject before json! clones or expands an oversized original string.
	if fields
		.iter()
		.try_fold(0usize, |total, field| total.checked_add(field.len()))
		.is_none_or(|bytes| bytes > MAX_OBSERVATION_BYTES)
	{
		bail!("observation_pool_payload_unsupported: original observation fields exceed64KiB; no fallback");
	}
	let (script, input, timeout, system) = match value {
		JobObservation::PythonStatus {
			job_id,
			job_dir,
			unit,
			wait_seconds,
		} => (
			Some(ObservationScript::Status),
			json!({"job_id":job_id,"job_dir":job_dir,"unit":unit,"wait_seconds":wait_seconds.min(30)}),
			Duration::from_secs(wait_seconds.min(30) + 10),
			false,
		),
		JobObservation::PythonRead {
			job_id,
			job_dir,
			stdout_offset,
			stderr_offset,
			limit,
		} => (
			Some(ObservationScript::Read),
			json!({"job_id":job_id,"job_dir":job_dir,"stdout_offset":stdout_offset,"stderr_offset":stderr_offset,"limit":limit}),
			Duration::from_secs(15),
			false,
		),
		JobObservation::SystemStatus { job_id } => (
			None,
			json!({"op":"status","job_id":job_id}),
			Duration::from_secs(20),
			true,
		),
		JobObservation::SystemRead {
			job_id,
			stdout_offset,
			stderr_offset,
			limit,
		} => (
			None,
			json!({"op":"read","job_id":job_id,"stdout_offset":stdout_offset,"stderr_offset":stderr_offset,"limit":limit}),
			Duration::from_secs(20),
			true,
		),
	};
	let command = match script {
		Some(script) => python_json_command("python3", &super::jobs::observation_script(script)?)?,
		None => "sudo -n /usr/local/libexec/hepta-runtime-jobctl".to_owned(),
	};
	let mut bytes = serde_json::to_vec(&input)?;
	if system {
		bytes.push(b'\n');
	}
	validate_observation_bytes(&command, &bytes)?;
	Ok((command, bytes, timeout, system))
}

pub(super) async fn run_job_observation(
	host_name: &str,
	value: JobObservation<'_>,
) -> Result<serde_json::Value> {
	let host = super::config::runtime_config()?.host(host_name)?;
	let (command, bytes, duration, system) = prepare_observation(value)?;
	let output = capture_observation(host_name, command, bytes, duration).await?;
	if !output.status.success() {
		if system {
			bail!(
				"job capability failed: {}",
				String::from_utf8_lossy(&output.stderr)
			);
		}
		bail!(
			"remote helper on {} failed with {}\nstdout:\n{}\nstderr:\n{}",
			host.ssh_target,
			output.status.code().unwrap_or(-1),
			String::from_utf8_lossy(&output.stdout).trim(),
			String::from_utf8_lossy(&output.stderr).trim()
		);
	}
	serde_json::from_slice(&output.stdout).map_err(|error| {
		anyhow!(
			"remote helper on {} returned invalid JSON: {error}; output={}",
			host.ssh_target,
			String::from_utf8_lossy(&output.stdout)
		)
	})
}

async fn capture_observation(
	host: &str,
	command: String,
	bytes: Vec<u8>,
	duration: Duration,
) -> Result<CapturedObservation> {
	#[cfg(target_os = "linux")]
	{
		observation_pool::capture(host, command, bytes, duration).await
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (host, command, bytes, duration);
		bail!("observation SSH pooling requires Linux");
	}
}

#[cfg(target_os = "linux")]
type CapturedObservation = observation_pool::Captured;
#[cfg(not(target_os = "linux"))]
type CapturedObservation = std::process::Output;

pub fn shell_quote(value: &str) -> String {
	if value.is_empty() {
		return "''".to_string();
	}
	let mut out = String::with_capacity(value.len() + 2);
	out.push('\'');
	for ch in value.chars() {
		if ch == '\'' {
			out.push_str("'\"'\"'");
		} else {
			out.push(ch);
		}
	}
	out.push('\'');
	out
}

pub fn ssh_base(host: &HostConfig) -> Command {
	let mut command = Command::new("ssh");
	command
		.arg("-T")
		.arg("-o")
		.arg("BatchMode=yes")
		.arg("-o")
		.arg("ConnectTimeout=8")
		.arg("-o")
		.arg("StrictHostKeyChecking=yes")
		.arg("-o")
		.arg("ForwardAgent=no")
		.arg(&host.ssh_target);
	command
}

async fn read_bounded(mut reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
	let mut result = Vec::new();
	let mut buf = [0u8; 8192];
	loop {
		let n = reader.read(&mut buf).await?;
		if n == 0 {
			break;
		}
		if result.len() + n > MAX_CAPTURE_BYTES {
			bail!("remote response exceeds 8 MiB capture limit");
		}
		result.extend_from_slice(&buf[..n]);
	}
	Ok(result)
}

pub async fn run_capture(
	host: &HostConfig,
	remote_command: &str,
	stdin_data: &[u8],
	timeout: Duration,
) -> Result<std::process::Output> {
	let mut command = ssh_base(host);
	command
		.arg(remote_command)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	let mut child = command
		.spawn()
		.with_context(|| format!("failed to start ssh for {}", host.ssh_target))?;
	let mut stdin = child
		.stdin
		.take()
		.ok_or_else(|| anyhow!("missing SSH stdin"))?;
	let stdout = child
		.stdout
		.take()
		.ok_or_else(|| anyhow!("missing SSH stdout"))?;
	let stderr = child
		.stderr
		.take()
		.ok_or_else(|| anyhow!("missing SSH stderr"))?;
	let result = tokio::time::timeout(timeout, async {
		let input = async {
			stdin.write_all(stdin_data).await?;
			stdin.shutdown().await?;
			drop(stdin);
			Ok::<(), anyhow::Error>(())
		};
		let wait = async { Ok::<_, anyhow::Error>(child.wait().await?) };
		let (_, stdout, stderr, status) =
			tokio::try_join!(input, read_bounded(stdout), read_bounded(stderr), wait)?;
		Ok::<_, anyhow::Error>(std::process::Output {
			status,
			stdout,
			stderr,
		})
	})
	.await;
	let output = match result {
		Ok(Ok(output)) => output,
		other => {
			let _ = child.start_kill();
			let _ = child.wait().await;
			return match other {
				Ok(Err(error)) => Err(error),
				_ => Err(anyhow!(
					"ssh to {} timed out after {}s",
					host.ssh_target,
					timeout.as_secs()
				)),
			};
		}
	};
	Ok(output)
}

pub async fn run_python_json<I, O>(
	host: &HostConfig,
	code: &str,
	input: &I,
	timeout: Duration,
) -> Result<O>
where
	I: Serialize + ?Sized,
	O: DeserializeOwned,
{
	run_python_json_with_interpreter(host, "python3", code, input, timeout).await
}

pub(crate) fn validate_python_interpreter(interpreter: &str) -> Result<()> {
	if interpreter != "python3"
		&& (!Path::new(interpreter).is_absolute()
			|| Path::new(interpreter)
				.components()
				.any(|component| matches!(component, Component::ParentDir | Component::CurDir)))
	{
		bail!("configured Python interpreter must be absolute or the fixed python3 default");
	}
	if interpreter.len() > 4096 || interpreter.chars().any(char::is_control) {
		bail!("configured Python interpreter contains invalid characters or exceeds 4096 bytes");
	}
	Ok(())
}

fn python_json_command(interpreter: &str, code: &str) -> Result<String> {
	validate_python_interpreter(interpreter)?;
	Ok(format!(
		"{} -c {}",
		shell_quote(interpreter),
		shell_quote(code)
	))
}

/// Administrator-selected interpreter; tool requests must never choose this executable.
pub async fn run_python_json_with_interpreter<I, O>(
	host: &HostConfig,
	interpreter: &str,
	code: &str,
	input: &I,
	timeout: Duration,
) -> Result<O>
where
	I: Serialize + ?Sized,
	O: DeserializeOwned,
{
	let remote_command = python_json_command(interpreter, code)?;
	let payload = serde_json::to_vec(input)?;
	let output = run_capture(host, &remote_command, &payload, timeout).await?;
	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		let stdout = String::from_utf8_lossy(&output.stdout);
		bail!(
			"remote helper on {} failed with {}\nstdout:\n{}\nstderr:\n{}",
			host.ssh_target,
			output.status.code().unwrap_or(-1),
			stdout.trim(),
			stderr.trim()
		);
	}
	serde_json::from_slice(&output.stdout).map_err(|error| {
		anyhow!(
			"remote helper on {} returned invalid JSON: {error}; output={}",
			host.ssh_target,
			String::from_utf8_lossy(&output.stdout)
		)
	})
}

pub fn build_exec_command(
	executable: &str,
	args: &[String],
	cwd: Option<&str>,
	env: &std::collections::BTreeMap<String, String>,
	rows: u16,
	cols: u16,
) -> Result<String> {
	for key in env.keys() {
		if key.is_empty()
			|| !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
			|| key.as_bytes()[0].is_ascii_digit()
		{
			bail!("invalid environment variable name `{key}`");
		}
	}
	let mut command = String::new();
	if rows > 0 && cols > 0 {
		command.push_str(&format!(
			"stty rows {rows} cols {cols} 2>/dev/null || true; "
		));
	}
	if let Some(cwd) = cwd {
		command.push_str("cd ");
		command.push_str(&shell_quote(cwd));
		command.push_str(" && ");
	}
	command.push_str("exec env");
	for (key, value) in env {
		command.push(' ');
		command.push_str(key);
		command.push('=');
		command.push_str(&shell_quote(value));
	}
	command.push(' ');
	command.push_str(&shell_quote(executable));
	for arg in args {
		command.push(' ');
		command.push_str(&shell_quote(arg));
	}
	Ok(command)
}

/// Fixed no-argument capability; the administrator policy, not the caller, owns
/// systemd properties, DynamicUser selection and protected paths.
pub async fn run_jobctl(host: &HostConfig, input: &serde_json::Value) -> Result<serde_json::Value> {
	let mut data = serde_json::to_vec(input)?;
	data.push(b'\n');
	let output = run_capture(
		host,
		"sudo -n /usr/local/libexec/hepta-runtime-jobctl",
		&data,
		Duration::from_secs(20),
	)
	.await?;
	if !output.status.success() {
		bail!(
			"job capability failed: {}",
			String::from_utf8_lossy(&output.stderr)
		);
	}
	Ok(serde_json::from_slice(&output.stdout)?)
}

#[cfg(test)]
#[path = "ssh_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ssh_observation_transport_tests.rs"]
mod observation_tests;

#[cfg(test)]
#[path = "ssh_file_observation_tests.rs"]
mod file_observation_tests;
