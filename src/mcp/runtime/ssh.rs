use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
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
		.arg(&host.ssh_target);
	command
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
	if let Some(mut stdin) = child.stdin.take() {
		stdin.write_all(stdin_data).await?;
		stdin.shutdown().await?;
	}
	let output = tokio::time::timeout(timeout, child.wait_with_output())
		.await
		.map_err(|_| {
			anyhow!(
				"ssh to {} timed out after {}s",
				host.ssh_target,
				timeout.as_secs()
			)
		})??;
	if output.stdout.len() > MAX_CAPTURE_BYTES || output.stderr.len() > MAX_CAPTURE_BYTES {
		bail!("remote response exceeded the 8 MiB safety limit");
	}
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

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::BTreeMap;

	#[test]
	fn quotes_shell_data() {
		assert_eq!(shell_quote("a b"), "'a b'");
		assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
	}

	#[test]
	fn builds_argv_without_model_side_quoting() {
		let cmd = build_exec_command(
			"/bin/printf",
			&["%s".into(), "a b'c".into()],
			Some("/tmp/a b"),
			&BTreeMap::new(),
			24,
			80,
		)
		.unwrap();
		assert!(cmd.contains("'/tmp/a b'"));
		assert!(cmd.contains("'a b'\"'\"'c'"));
	}
}
