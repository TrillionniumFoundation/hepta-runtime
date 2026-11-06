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

//! Stdin-only APK cryptographic parser with explicit cancellation and reaping.
//! The process has no source path, runtime credentials or network dependency.

use super::{parser, MAX_APK_BYTES, MAX_RESPONSE_BYTES};
use anyhow::{bail, Context, Result};

#[cfg(unix)]
fn apply_limits() -> Result<()> {
	for (kind, allowed) in [
		(libc::RLIMIT_AS, 1024 * 1024 * 1024),
		(libc::RLIMIT_CPU, 20),
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
				.context("cannot establish APK worker limits");
		}
	}
	#[cfg(target_os = "linux")]
	{
		let parent = unsafe { libc::getppid() };
		if parent == 1 || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
			bail!("cannot bind APK worker to controller lifetime");
		}
		if unsafe { libc::getppid() } != parent {
			bail!("APK controller exited during startup");
		}
	}
	Ok(())
}

pub(super) fn serve_once() -> Result<()> {
	#[cfg(not(unix))]
	bail!("APK signature worker is qualified only on Unix");
	#[cfg(unix)]
	{
		use std::io::{Read, Write};
		apply_limits()?;
		let mut bytes = Vec::new();
		std::io::stdin()
			.lock()
			.take(MAX_APK_BYTES as u64 + 1)
			.read_to_end(&mut bytes)?;
		if bytes.len() > MAX_APK_BYTES {
			bail!("APK worker input exceeds 128 MiB");
		}
		super::super::rea_seccomp::tighten_after_read()?;
		let encoded = serde_json::to_vec(&parser::inspect(&bytes)?)?;
		if encoded.len() > MAX_RESPONSE_BYTES {
			bail!("APK worker output exceeds 1 MiB");
		}
		let mut stdout = std::io::stdout().lock();
		stdout.write_all(&encoded)?;
		stdout.write_all(b"\n")?;
		stdout.flush()?;
		Ok(())
	}
}

#[cfg(not(test))]
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(reader: R, max: usize) -> Result<Vec<u8>> {
	use tokio::io::AsyncReadExt;
	let mut bytes = Vec::new();
	reader.take(max as u64 + 1).read_to_end(&mut bytes).await?;
	if bytes.len() > max {
		bail!("APK worker output exceeds its byte budget");
	}
	Ok(bytes)
}

#[cfg(not(test))]
pub(super) async fn inspect_isolated(
	input: Vec<u8>,
	cancellation: &tokio_util::sync::CancellationToken,
) -> Result<serde_json::Value> {
	use anyhow::anyhow;
	use std::process::Stdio;
	use std::time::Duration;
	use tokio::io::AsyncWriteExt;
	use tokio::process::Command;
	super::ensure_not_cancelled(cancellation)?;
	if input.len() > MAX_APK_BYTES {
		bail!("APK worker input exceeds 128 MiB");
	}
	let binary = std::env::current_exe().context("cannot locate APK worker binary")?;
	let mut child = Command::new(binary)
		.arg("rea-apk-signature-worker")
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true)
		.spawn()
		.context("cannot spawn APK worker")?;
	let (Some(mut stdin), Some(stdout), Some(stderr)) =
		(child.stdin.take(), child.stdout.take(), child.stderr.take())
	else {
		let _ = child.kill().await;
		child
			.wait()
			.await
			.context("cannot reap APK worker after missing pipe")?;
		bail!("APK worker pipes unavailable");
	};
	let collected = tokio::select! {
		biased;
		_ = cancellation.cancelled() => Err(anyhow!("APK signature inspection cancelled")),
		collected = tokio::time::timeout(Duration::from_secs(30), async {
			tokio::try_join!(
				async move {
					stdin.write_all(&input).await?;
					stdin.shutdown().await?;
					// Close the owned endpoint: Unix pipe shutdown alone does not deliver EOF.
					drop(stdin);
					Ok::<_, anyhow::Error>(())
				},
				read_capped(stdout, MAX_RESPONSE_BYTES + 1),
				read_capped(stderr, 64 * 1024),
				async { child.wait().await.map_err(anyhow::Error::from) }
			)
		}) => match collected {
			Ok(result) => result,
			Err(_) => Err(anyhow!("APK worker exceeded 30 second wall-clock deadline")),
		},
	};
	let ((), stdout, stderr, status) = match collected {
		Ok(result) => result,
		Err(error) => {
			let _ = child.kill().await;
			child
				.wait()
				.await
				.with_context(|| format!("cannot reap APK worker after failure: {error:#}"))?;
			return Err(error);
		}
	};
	if !status.success() {
		bail!(
			"APK worker failed ({status}): {}",
			String::from_utf8_lossy(&stderr).trim()
		);
	}
	serde_json::from_slice(&stdout).context("APK worker returned invalid JSON")
}
