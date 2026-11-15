// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
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

//! Bounded ASAR worker over an inherited read-only descriptor. The controller
//! retains and reaps the original child on cancellation, deadline or output refusal.

use anyhow::{bail, Context, Result};
use std::io::Write;

use super::{parser, MAX_WORKER_RESPONSE_BYTES};

#[cfg(unix)]
fn apply_limits() -> Result<()> {
	for (kind, allowed) in [
		(libc::RLIMIT_AS, 768 * 1024 * 1024),
		(libc::RLIMIT_CPU, 12),
		(libc::RLIMIT_NOFILE, 64),
		(libc::RLIMIT_CORE, 0),
		(
			libc::RLIMIT_FSIZE,
			MAX_WORKER_RESPONSE_BYTES as libc::rlim_t,
		),
	] {
		let limit = libc::rlimit {
			rlim_cur: allowed,
			rlim_max: allowed,
		};
		if unsafe { libc::setrlimit(kind, &limit) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot establish ASAR worker resource limits");
		}
	}
	#[cfg(target_os = "linux")]
	{
		let parent = unsafe { libc::getppid() };
		if parent == 1 || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
			bail!("cannot bind ASAR worker to controller lifetime");
		}
		if unsafe { libc::getppid() } != parent {
			bail!("ASAR controller exited during worker startup");
		}
	}
	Ok(())
}

#[cfg(unix)]
fn inherited_source() -> Result<std::fs::File> {
	use std::os::fd::FromRawFd;
	let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
	if fd < 0 {
		return Err(std::io::Error::last_os_error())
			.context("ASAR worker requires an inherited regular-file descriptor");
	}
	let file = unsafe { std::fs::File::from_raw_fd(fd) };
	let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
	if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY || !file.metadata()?.is_file() {
		bail!("ASAR worker stdin must be a read-only regular-file descriptor");
	}
	Ok(file)
}

pub(super) fn serve_once(request_json: &str) -> Result<()> {
	#[cfg(not(unix))]
	{
		let _ = request_json;
		bail!("ASAR worker is not qualified on non-Unix hosts")
	}
	#[cfg(unix)]
	{
		apply_limits()?;
		if request_json.len() > 32 * 1024 {
			bail!("ASAR worker request exceeds 32 KiB");
		}
		let request: parser::Request =
			serde_json::from_str(request_json).context("invalid ASAR worker request")?;
		let mut file = inherited_source()?;
		super::super::rea_seccomp::tighten_after_read()?;
		let result = parser::inspect_file(&mut file, &request)?;
		let encoded = serde_json::to_vec(&result)?;
		if encoded.len() > MAX_WORKER_RESPONSE_BYTES {
			bail!("ASAR worker output exceeds 4 MiB; reduce index page");
		}
		let mut stdout = std::io::stdout().lock();
		stdout.write_all(&encoded)?;
		stdout.write_all(b"\n")?;
		stdout.flush()?;
		Ok(())
	}
}

#[cfg(not(test))]
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(reader: R, limit: usize) -> Result<Vec<u8>> {
	use tokio::io::AsyncReadExt;
	let mut bytes = Vec::new();
	reader
		.take(limit as u64 + 1)
		.read_to_end(&mut bytes)
		.await?;
	if bytes.len() > limit {
		bail!("ASAR worker output exceeds its byte budget");
	}
	Ok(bytes)
}

#[cfg(not(test))]
pub(super) async fn inspect_isolated(
	file: std::fs::File,
	request: &parser::Request,
	cancellation: &tokio_util::sync::CancellationToken,
) -> Result<serde_json::Value> {
	use anyhow::anyhow;
	use std::process::Stdio;
	use std::time::Duration;
	use tokio::process::Command;
	super::ensure_not_cancelled(cancellation)?;
	let encoded = serde_json::to_string(request)?;
	if encoded.len() > 32 * 1024 {
		bail!("ASAR worker request exceeds 32 KiB");
	}
	let binary = std::env::current_exe().context("cannot locate ASAR worker binary")?;
	let mut child = Command::new(binary)
		.arg("rea-asar-worker")
		.arg("--request")
		.arg(encoded)
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::from(file))
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true)
		.spawn()
		.context("cannot spawn bounded ASAR worker")?;
	let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
		let _ = child.kill().await;
		child
			.wait()
			.await
			.context("cannot reap ASAR worker after missing pipe")?;
		bail!("ASAR worker pipes unavailable");
	};
	let collected = tokio::select! {
		biased;
		_ = cancellation.cancelled() => Err(anyhow!("ASAR inspection cancelled")),
		collected = tokio::time::timeout(Duration::from_secs(20), async {
			tokio::try_join!(read_capped(stdout, MAX_WORKER_RESPONSE_BYTES + 1),
				read_capped(stderr, 64 * 1024), async { child.wait().await.map_err(anyhow::Error::from) })
		}) => match collected {
			Ok(result) => result,
			Err(_) => Err(anyhow!("ASAR worker exceeded 20 second wall-clock deadline")),
		},
	};
	let (stdout, stderr, status) = match collected {
		Ok(result) => result,
		Err(error) => {
			let _ = child.kill().await;
			child.wait().await.with_context(|| {
				format!("cannot reap ASAR worker after inspection failure: {error:#}")
			})?;
			return Err(error);
		}
	};
	if !status.success() {
		bail!(
			"ASAR worker failed ({status}): {}",
			String::from_utf8_lossy(&stderr).trim()
		);
	}
	serde_json::from_slice(&stdout).context("ASAR worker returned invalid JSON")
}
