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

//! One-shot archive parser using a controller-admitted read-only descriptor as
//! stdin. No archive pathname, credentials or payload-sized IPC buffer is passed.

use anyhow::{bail, Context, Result};
use std::io::Write;

use super::{parser, MAX_RESPONSE_BYTES};

#[cfg(unix)]
fn apply_limits() -> Result<()> {
	for (kind, allowed) in [
		(libc::RLIMIT_AS, 768 * 1024 * 1024),
		(libc::RLIMIT_CPU, 25),
		(libc::RLIMIT_NOFILE, 64),
		(libc::RLIMIT_CORE, 0),
		(libc::RLIMIT_FSIZE, MAX_RESPONSE_BYTES as libc::rlim_t),
	] {
		let limits = libc::rlimit {
			rlim_cur: allowed,
			rlim_max: allowed,
		};
		if unsafe { libc::setrlimit(kind, &limits) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot establish archive parser resource limits");
		}
	}
	#[cfg(target_os = "linux")]
	{
		let parent = unsafe { libc::getppid() };
		if parent == 1 || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
			bail!("cannot bind archive parser to its controller lifetime");
		}
		if unsafe { libc::getppid() } != parent {
			bail!("archive parser controller exited during startup");
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
			.context("archive parser requires an inherited regular-file descriptor on stdin");
	}
	let file = unsafe { std::fs::File::from_raw_fd(fd) };
	let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
	if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY || !file.metadata()?.is_file() {
		bail!("archive parser stdin must be a read-only regular-file descriptor");
	}
	Ok(file)
}

pub(super) fn serve_once(request_json: &str) -> Result<()> {
	#[cfg(not(unix))]
	{
		let _ = request_json;
		bail!("archive parser worker is not qualified on non-Unix hosts")
	}
	#[cfg(unix)]
	{
		apply_limits()?;
		if request_json.len() > 16 * 1024 {
			bail!("archive worker request exceeds 16 KiB");
		}
		let request: parser::Request =
			serde_json::from_str(request_json).context("invalid archive parser request")?;
		let mut file = inherited_source()?;
		super::super::rea_seccomp::tighten_after_read()?;
		let result = parser::inspect_file(&mut file, &request)?;
		let encoded = serde_json::to_vec(&result)?;
		if encoded.len() > MAX_RESPONSE_BYTES {
			bail!("archive parser response exceeds 1 MiB; reduce page size");
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
		bail!("archive worker output exceeds its {limit} byte budget");
	}
	Ok(bytes)
}

#[cfg(not(test))]
pub(super) async fn inspect_isolated(
	file: std::fs::File,
	request: &parser::Request,
) -> Result<serde_json::Value> {
	use anyhow::anyhow;
	use std::process::Stdio;
	use std::time::Duration;
	use tokio::process::Command;
	let binary = std::env::current_exe().context("cannot locate archive parser binary")?;
	let encoded_request = serde_json::to_string(request)?;
	if encoded_request.len() > 16 * 1024 {
		bail!("archive worker request exceeds 16 KiB");
	}
	let mut child = Command::new(binary)
		.arg("rea-archive-worker")
		.arg("--request")
		.arg(encoded_request)
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::from(file))
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true)
		.spawn()
		.context("cannot spawn bounded archive parser")?;
	let stdout = child
		.stdout
		.take()
		.ok_or_else(|| anyhow!("archive worker stdout unavailable"))?;
	let stderr = child
		.stderr
		.take()
		.ok_or_else(|| anyhow!("archive worker stderr unavailable"))?;
	let collected = tokio::time::timeout(Duration::from_secs(30), async {
		tokio::try_join!(
			read_capped(stdout, MAX_RESPONSE_BYTES + 1),
			read_capped(stderr, 64 * 1024),
			async { child.wait().await.map_err(anyhow::Error::from) }
		)
	})
	.await;
	let (stdout, stderr, status) = match collected {
		Ok(Ok(result)) => result,
		Ok(Err(error)) => {
			let _ = child.kill().await;
			let _ = child.wait().await;
			return Err(error);
		}
		Err(_) => {
			let _ = child.kill().await;
			let _ = child.wait().await;
			bail!("archive parser exceeded 30 second wall-clock deadline");
		}
	};
	if !status.success() {
		bail!(
			"archive parser failed ({status}): {}",
			String::from_utf8_lossy(&stderr).trim()
		);
	}
	serde_json::from_slice(&stdout).context("archive parser returned invalid JSON")
}
