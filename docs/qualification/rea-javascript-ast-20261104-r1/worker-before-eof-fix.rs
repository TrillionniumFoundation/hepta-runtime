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

//! One-shot AST worker using the shipped runtime. No original file path or
//! credential reaches the parser; resource refusal never becomes graph success.

use anyhow::{bail, Context, Result};

use super::{graph, WorkerRequest, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};

#[cfg(unix)]
fn apply_limits() -> Result<()> {
	for (kind, allowed) in [
		(libc::RLIMIT_AS, 768 * 1024 * 1024),
		(libc::RLIMIT_CPU, 12),
		(libc::RLIMIT_NOFILE, 64),
		(libc::RLIMIT_CORE, 0),
		(libc::RLIMIT_FSIZE, MAX_RESPONSE_BYTES as libc::rlim_t),
	] {
		let limit = libc::rlimit {
			rlim_cur: allowed,
			rlim_max: allowed,
		};
		if unsafe { libc::setrlimit(kind, &limit) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot establish AST worker resource limits");
		}
	}
	#[cfg(target_os = "linux")]
	{
		let parent = unsafe { libc::getppid() };
		if parent == 1 || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
			bail!("cannot bind AST worker to controller lifetime");
		}
		if unsafe { libc::getppid() } != parent {
			bail!("AST worker controller exited during startup");
		}
	}
	Ok(())
}

pub(super) fn serve_once() -> Result<()> {
	#[cfg(not(unix))]
	bail!("JavaScript AST worker is not qualified on non-Unix hosts");
	#[cfg(unix)]
	{
		use std::io::{Read, Write};
		apply_limits()?;
		let mut bytes = Vec::new();
		std::io::stdin()
			.lock()
			.take(MAX_REQUEST_BYTES as u64 + 1)
			.read_to_end(&mut bytes)?;
		if bytes.len() > MAX_REQUEST_BYTES {
			bail!("JavaScript AST worker input exceeds 32 MiB");
		}
		super::super::rea_seccomp::tighten_after_read()?;
		let request: WorkerRequest =
			serde_json::from_slice(&bytes).context("invalid AST worker request")?;
		let result = graph::report(&request)?;
		let encoded = serde_json::to_vec(&result)?;
		if encoded.len() > MAX_RESPONSE_BYTES {
			bail!("JavaScript AST worker output exceeds 1 MiB");
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
		bail!("JavaScript AST worker output exceeds its byte budget");
	}
	Ok(bytes)
}

#[cfg(not(test))]
pub(super) async fn inspect_isolated(request: &WorkerRequest) -> Result<serde_json::Value> {
	use anyhow::anyhow;
	use std::process::Stdio;
	use std::time::Duration;
	use tokio::io::AsyncWriteExt;
	use tokio::process::Command;
	let encoded = serde_json::to_vec(request)?;
	if encoded.len() > MAX_REQUEST_BYTES {
		bail!("JavaScript AST worker request exceeds 32 MiB");
	}
	let binary = std::env::current_exe().context("cannot locate JavaScript AST worker binary")?;
	let mut child = Command::new(binary)
		.arg("rea-javascript-worker")
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true)
		.spawn()
		.context("cannot spawn bounded JavaScript AST worker")?;
	let mut stdin = child
		.stdin
		.take()
		.ok_or_else(|| anyhow!("AST worker stdin unavailable"))?;
	let stdout = child
		.stdout
		.take()
		.ok_or_else(|| anyhow!("AST worker stdout unavailable"))?;
	let stderr = child
		.stderr
		.take()
		.ok_or_else(|| anyhow!("AST worker stderr unavailable"))?;
	let collected = tokio::time::timeout(Duration::from_secs(20), async {
		tokio::try_join!(
			async {
				stdin.write_all(&encoded).await?;
				stdin.shutdown().await?;
				Ok::<_, anyhow::Error>(())
			},
			read_capped(stdout, MAX_RESPONSE_BYTES + 1),
			read_capped(stderr, 64 * 1024),
			async { child.wait().await.map_err(anyhow::Error::from) }
		)
	})
	.await;
	let ((), stdout, stderr, status) = match collected {
		Ok(Ok(result)) => result,
		Ok(Err(error)) => {
			let _ = child.kill().await;
			let _ = child.wait().await;
			return Err(error);
		}
		Err(_) => {
			let _ = child.kill().await;
			let _ = child.wait().await;
			bail!("JavaScript AST worker exceeded 20 second wall-clock deadline");
		}
	};
	if !status.success() {
		bail!(
			"JavaScript AST worker failed ({status}): {}",
			String::from_utf8_lossy(&stderr).trim()
		);
	}
	serde_json::from_slice(&stdout).context("JavaScript AST worker returned invalid JSON")
}
