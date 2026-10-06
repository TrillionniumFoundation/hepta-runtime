// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit operator tools. The configured SSH login and OS are the authority.
use anyhow::{bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

use super::config::{runtime_config, ExecutionMode, HostConfig};
use super::jobs::{audit, start_job, ProcessStartParams};
use super::pty::{start_pty, PtyStartParams};
use super::ssh::{run_capture, shell_quote};

fn operator_host(name: &str) -> Result<&'static HostConfig> {
	let host = runtime_config()?.host(name)?;
	if host.execution_mode != ExecutionMode::Operator {
		bail!(
			"host `{name}` is isolated; operator authority must be configured by its administrator"
		);
	}
	Ok(host)
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellStartParams {
	pub host: String,
	/// Shell source, including pipelines, redirects and compound commands.
	pub command: String,
	/// Absolute shell executable; defaults to /bin/sh.
	#[serde(default)]
	pub shell: Option<String>,
	#[serde(default)]
	pub cwd: Option<String>,
	#[serde(default)]
	pub env: BTreeMap<String, String>,
	#[serde(default)]
	pub timeout_seconds: Option<u64>,
	#[serde(default)]
	pub idempotency_key: Option<String>,
}

pub async fn shell_start(params: ShellStartParams) -> Result<String> {
	operator_host(&params.host)?;
	if params.command.len() > 65536 || params.command.contains('\0') {
		bail!("shell source must not contain NUL and is limited to 64 KiB");
	}
	start_job(ProcessStartParams {
		host: params.host,
		executable: params.shell.unwrap_or_else(|| "/bin/sh".into()),
		args: vec!["-c".into(), params.command],
		cwd: params.cwd,
		env: params.env,
		stdin: None,
		timeout_seconds: params.timeout_seconds,
		idempotency_key: params.idempotency_key,
		nice: None,
		cpu_quota_percent: None,
		memory_max_bytes: None,
	})
	.await
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostProcessesParams {
	pub host: String,
	#[serde(default)]
	pub after_pid: Option<u32>,
	/// At most 128 process records per response.
	#[serde(default)]
	pub limit: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostSignalParams {
	pub host: String,
	/// A single positive host PID, never a process group or -1 wildcard.
	pub pid: u32,
	/// Signal number; default SIGTERM (15). Zero probes permissions/existence.
	#[serde(default)]
	pub signal: Option<i32>,
	/// Identity from host_processes; rejects PID reuse when supplied.
	#[serde(default)]
	pub expected_identity: Option<String>,
	/// Use existing noninteractive sudo permission; never grants privileges.
	#[serde(default)]
	pub sudo: bool,
}

fn validate_signal(params: &HostSignalParams) -> Result<i32> {
	if params.pid == 0 || params.pid > i32::MAX as u32 {
		bail!("pid must identify exactly one positive host process");
	}
	let number = params.signal.unwrap_or(15);
	if !(0..=64).contains(&number) {
		bail!("signal must be in 0..64 and supported by the target OS");
	}
	if params
		.expected_identity
		.as_ref()
		.is_some_and(|v| v.is_empty() || v.len() > 256)
	{
		bail!("expected_identity must contain 1..256 bytes");
	}
	Ok(number)
}

async fn process_rpc(host: &HostConfig, input: &Value, sudo: bool) -> Result<String> {
	let code = include_str!("process_ops.py");
	let prefix = if sudo { "sudo -n -- " } else { "" };
	let command = format!("{prefix}/usr/bin/python3 -c {}", shell_quote(code));
	let output = run_capture(
		host,
		&command,
		&serde_json::to_vec(input)?,
		Duration::from_secs(20),
	)
	.await?;
	if !output.status.success() {
		bail!(
			"operator process request failed (do not blindly retry a signal): {}",
			String::from_utf8_lossy(&output.stderr)
		);
	}
	let value: Value = serde_json::from_slice(&output.stdout)?;
	Ok(serde_json::to_string_pretty(&value)?)
}

pub async fn host_processes(params: HostProcessesParams) -> Result<String> {
	let host = operator_host(&params.host)?;
	if !host.allow_execute {
		bail!("operator process inspection is disabled");
	}
	process_rpc(host, &json!({"op":"list", "after_pid":params.after_pid.unwrap_or(0), "limit":params.limit.unwrap_or(64).clamp(1,128)}), false).await
}

pub async fn host_signal(params: HostSignalParams) -> Result<String> {
	let host = operator_host(&params.host)?;
	if !host.allow_execute {
		bail!("operator signalling is disabled");
	}
	let number = validate_signal(&params)?;
	let request = json!({"op":"signal", "pid":params.pid, "signal":number, "expected_identity":params.expected_identity, "sudo":params.sudo});
	// Record intent before side effects. If the transport fails, outcome is unknown.
	audit(
		"host_signal_requested",
		&params.host,
		&params.pid.to_string(),
		&request,
	)?;
	let result = process_rpc(host, &request, params.sudo).await?;
	audit(
		"host_signal_result",
		&params.host,
		&params.pid.to_string(),
		&serde_json::from_str::<Value>(&result)?,
	)?;
	Ok(result)
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SudoStartParams {
	pub host: String,
	pub executable: String,
	#[serde(default)]
	pub args: Vec<String>,
	#[serde(default)]
	pub cwd: Option<String>,
	/// Environment before sudo; sudo itself may filter it according to sudoers.
	#[serde(default)]
	pub env: BTreeMap<String, String>,
	#[serde(default)]
	pub run_as: Option<String>,
	/// Use -n to fail instead of requesting a password.
	#[serde(default)]
	pub non_interactive: bool,
	/// Default true: use sudo -k so an existing cached credential is not relied on.
	#[serde(default = "default_true")]
	pub fresh_auth: bool,
	#[serde(default)]
	pub rows: Option<u16>,
	#[serde(default)]
	pub cols: Option<u16>,
}

fn default_true() -> bool {
	true
}

fn sudo_argv(params: &SudoStartParams) -> Result<Vec<String>> {
	if !params.executable.starts_with('/') || params.executable.contains('\0') {
		bail!("sudo executable must be an absolute path without NUL");
	}
	let user = params.run_as.as_deref().unwrap_or("root");
	if user.is_empty()
		|| user.len() > 128
		|| !user
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b"_-.#".contains(&b))
		|| user.starts_with('-')
	{
		bail!("invalid sudo run_as user");
	}
	let mut args = Vec::new();
	if params.fresh_auth {
		args.push("-k".into());
	}
	if params.non_interactive {
		args.push("-n".into());
	}
	args.extend([
		"-u".into(),
		user.into(),
		"--".into(),
		params.executable.clone(),
	]);
	args.extend(params.args.clone());
	Ok(args)
}

pub async fn sudo_start(params: SudoStartParams) -> Result<String> {
	operator_host(&params.host)?;
	let args = sudo_argv(&params)?;
	audit(
		"sudo_start_requested",
		&params.host,
		"pty",
		&json!({"executable":params.executable,"run_as":params.run_as,"fresh_auth":params.fresh_auth,"non_interactive":params.non_interactive}),
	)?;
	start_pty(PtyStartParams {
		idempotency_key: None,
		host: params.host,
		executable: "/usr/bin/sudo".into(),
		args,
		cwd: params.cwd,
		env: params.env,
		rows: params.rows,
		cols: params.cols,
	})
	.await
}

#[cfg(test)]
#[path = "operator_tests.rs"]
mod tests;
