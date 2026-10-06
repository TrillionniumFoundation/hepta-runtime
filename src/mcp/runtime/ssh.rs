// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded SSH transport using preconfigured hosts and verified keys.
use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use super::config::HostConfig;

const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;

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
	let payload = serde_json::to_vec(input)?;
	let remote_command = format!("python3 -c {}", shell_quote(code));
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
