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
		.arg(&host.ssh_target);
	command
}

// Enforce the limit while draining: wait_with_output() buffers without a cap
// and could exhaust controller memory before any length check ran.
async fn read_limited<R: AsyncRead + Unpin>(mut reader: R, limit: usize) -> Result<Vec<u8>> {
	let mut output = Vec::new();
	let mut buffer = [0u8; 8192];
	loop {
		let read = reader.read(&mut buffer).await?;
		if read == 0 {
			break;
		}
		if read > limit.saturating_sub(output.len()) {
			bail!("remote response exceeded the 8 MiB safety limit");
		}
		output.extend_from_slice(&buffer[..read]);
	}
	Ok(output)
}

// Drive stdin, stdout and stderr concurrently. A remote program can write
// before it reads stdin, so sequential write-then-capture can deadlock.
// An over-limit stream or timeout cancels all readers and reaps the process.
async fn capture_command(
	mut command: Command,
	stdin_data: &[u8],
	timeout: Duration,
	target: &str,
) -> Result<std::process::Output> {
	command
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	let mut child = command
		.spawn()
		.with_context(|| format!("failed to start ssh for {}", target))?;
	let mut stdin = child
		.stdin
		.take()
		.ok_or_else(|| anyhow!("ssh stdin pipe was not created"))?;
	let stdout = child
		.stdout
		.take()
		.ok_or_else(|| anyhow!("ssh stdout pipe was not created"))?;
	let stderr = child
		.stderr
		.take()
		.ok_or_else(|| anyhow!("ssh stderr pipe was not created"))?;

	let capture = async {
		let ((), stdout, stderr, status) = tokio::try_join!(
			async {
				stdin.write_all(stdin_data).await?;
				stdin.shutdown().await?;
				Ok::<(), anyhow::Error>(())
			},
			read_limited(stdout, MAX_CAPTURE_BYTES),
			read_limited(stderr, MAX_CAPTURE_BYTES),
			async { Ok::<std::process::ExitStatus, anyhow::Error>(child.wait().await?) },
		)?;
		Ok::<std::process::Output, anyhow::Error>(std::process::Output {
			status,
			stdout,
			stderr,
		})
	};

	match tokio::time::timeout(timeout, capture).await {
		Ok(Ok(output)) => Ok(output),
		Ok(Err(error)) => {
			let _ = child.kill().await;
			Err(error)
		}
		Err(_) => {
			let _ = child.kill().await;
			Err(anyhow!(
				"ssh to {} timed out after {}s",
				target,
				timeout.as_secs()
			))
		}
	}
}

pub async fn run_capture(
	host: &HostConfig,
	remote_command: &str,
	stdin_data: &[u8],
	timeout: Duration,
) -> Result<std::process::Output> {
	let mut command = ssh_base(host);
	command.arg(remote_command);
	capture_command(command, stdin_data, timeout, &host.ssh_target).await
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
	allowed_cwd_prefixes: &[String],
) -> Result<String> {
	for key in env.keys() {
		if key.is_empty()
			|| !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
			|| key.as_bytes()[0].is_ascii_digit()
		{
			bail!("invalid environment variable name `{key}`");
		}
	}
	if !allowed_cwd_prefixes.is_empty() && cwd.is_none() {
		bail!("cwd is required for guarded remote execution");
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
		if !allowed_cwd_prefixes.is_empty() {
			// Resolve roots on the target host. The eventual exec inherits the
			// already-verified physical cwd instead of following the path twice.
			command.push_str("cwd_physical=$(pwd -P) || exit 125; cwd_guard=0; ");
			for prefix in allowed_cwd_prefixes {
				command.push_str("root_physical=$(cd ");
				command.push_str(&shell_quote(prefix));
				command.push_str(" && pwd -P) || exit 125; ");
				command.push_str("if [ \"$root_physical\" = / ]; then cwd_guard=1; else ");
				command.push_str("case \"$cwd_physical\" in \"$root_physical\"|\"$root_physical\"/*) cwd_guard=1;; esac; fi; ");
			}
			command.push_str("[ \"$cwd_guard\" = 1 ] || exit 126; ");
		}
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
			&[],
		)
		.unwrap();
		assert!(cmd.contains("'/tmp/a b'"));
		assert!(cmd.contains("'a b'\"'\"'c'"));
	}

	#[cfg(unix)]
	#[test]
	fn remote_cwd_guard_rejects_symlink_escape_before_exec() {
		use std::os::unix::fs::symlink;

		let dir = tempfile::tempdir().unwrap();
		let allowed = dir.path().join("allowed");
		let outside = dir.path().join("outside");
		std::fs::create_dir(&allowed).unwrap();
		std::fs::create_dir(&outside).unwrap();
		let link = allowed.join("escape");
		symlink(&outside, &link).unwrap();
		let roots = vec![allowed.to_string_lossy().into_owned()];
		let env = BTreeMap::new();

		assert!(build_exec_command("/bin/pwd", &[], None, &env, 0, 0, &roots).is_err());
		let denied = build_exec_command(
			"/bin/pwd", &[], Some(link.to_str().unwrap()), &env, 0, 0, &roots,
		)
		.unwrap();
		let output = std::process::Command::new("sh")
			.arg("-c")
			.arg(denied)
			.output()
			.unwrap();
		assert_eq!(output.status.code(), Some(126));

		let admitted = build_exec_command(
			"/bin/pwd", &[], Some(allowed.to_str().unwrap()), &env, 0, 0, &roots,
		)
		.unwrap();
		let output = std::process::Command::new("sh")
			.arg("-c")
			.arg(admitted)
			.output()
			.unwrap();
		assert!(output.status.success());
		assert_eq!(
			String::from_utf8_lossy(&output.stdout).trim(),
			allowed.canonicalize().unwrap().to_str().unwrap()
		);
	}
}

#[cfg(test)]
#[path = "ssh_bounded_tests.rs"]
mod bounded_tests;
