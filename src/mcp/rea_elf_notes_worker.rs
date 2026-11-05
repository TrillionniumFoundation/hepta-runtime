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

//! The binary frame avoids expanding a 512 MiB snapshot into a JSON byte array.
//! A small JSON header precedes exact raw bytes. EOF is required after the frame.

#[cfg(not(test))]
use super::DEADLINE_MS;
use super::{parser, Failure, Input, MAX_BYTES, MAX_WORKER_REPLY, OP};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const MAX_HEADER: usize = 64 * 1024;
const MEMORY_BYTES: libc::rlim_t = 2 * 1024 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
	input: Input,
	sha256: String,
	bytes: u64,
}

#[cfg(unix)]
fn limits() -> Result<()> {
	for (kind, allowed) in [
		(libc::RLIMIT_AS, MEMORY_BYTES),
		(libc::RLIMIT_CPU, 20),
		(libc::RLIMIT_NOFILE, 64),
		(libc::RLIMIT_CORE, 0),
		(libc::RLIMIT_FSIZE, MAX_WORKER_REPLY as libc::rlim_t),
	] {
		let mut inherited = libc::rlimit {
			rlim_cur: 0,
			rlim_max: 0,
		};
		if unsafe { libc::getrlimit(kind, &mut inherited) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot inspect inherited ELF worker limits");
		}
		let hard = inherited.rlim_max.min(allowed);
		let bound = libc::rlimit {
			rlim_cur: inherited.rlim_cur.min(hard),
			rlim_max: hard,
		};
		if unsafe { libc::setrlimit(kind, &bound) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot establish ELF worker limits");
		}
	}
	#[cfg(target_os = "linux")]
	{
		let parent = unsafe { libc::getppid() };
		if parent == 1 || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
			bail!("cannot bind ELF worker to controller lifetime");
		}
		if unsafe { libc::getppid() } != parent {
			bail!("ELF worker controller exited during startup");
		}
	}
	Ok(())
}

fn parse(header: &Header, bytes: &[u8]) -> Result<Value> {
	let artifact = parser::ElfNotesArtifact {
		path: header.input.path.clone(),
		sha256: header.sha256.clone(),
		bytes: header.bytes,
	};
	Ok(
		match parser::parse_elf_notes(
			bytes,
			artifact,
			header.input.max_file_bytes,
			header.input.max_entries,
		) {
			Ok(report) => json!({"report":report}),
			Err(failure) => {
				let message = failure.to_string();
				let mut value = serde_json::to_value(failure)?;
				value["message"] = json!(message);
				json!({"failure":value})
			}
		},
	)
}

pub(super) fn serve_once() -> Result<()> {
	#[cfg(not(unix))]
	bail!("ELF isolation is not available on this platform");
	#[cfg(unix)]
	{
		use std::io::{Read, Write};
		limits()?;
		let mut stdin = std::io::stdin().lock();
		let mut length = [0_u8; 4];
		stdin.read_exact(&mut length)?;
		let length = u32::from_le_bytes(length) as usize;
		if length == 0 || length > MAX_HEADER {
			bail!("ELF worker header exceeds its bound");
		}
		let mut header = vec![0_u8; length];
		stdin.read_exact(&mut header)?;
		let header: Header = serde_json::from_slice(&header)?;
		if header.bytes > MAX_BYTES
			|| header.bytes > header.input.max_file_bytes
			|| !(64..=MAX_BYTES).contains(&header.input.max_file_bytes)
			|| !(1..=256).contains(&header.input.max_entries)
		{
			bail!("ELF worker frame exceeds admitted bounds");
		}
		let mut bytes = Vec::new();
		bytes
			.try_reserve_exact(header.bytes as usize)
			.context("ELF worker cannot reserve snapshot memory")?;
		bytes.resize(header.bytes as usize, 0);
		stdin.read_exact(&mut bytes)?;
		let mut extra = [0_u8; 1];
		if stdin.read(&mut extra)? != 0 {
			bail!("ELF worker received trailing frame bytes");
		}
		super::super::rea_seccomp::tighten_after_read()?;
		let result = parse(&header, &bytes)?;
		let encoded = serde_json::to_vec(&result)?;
		if encoded.len() > MAX_WORKER_REPLY {
			bail!("ELF worker complete report exceeds its 64 MiB reply allowance");
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
		bail!("ELF worker reply exceeds its allowance");
	}
	Ok(bytes)
}

#[cfg(not(test))]
pub(super) async fn inspect_isolated(
	input: &Input,
	digest: &str,
	bytes: &[u8],
	cancellation: &tokio_util::sync::CancellationToken,
) -> std::result::Result<Value, Failure> {
	use std::process::Stdio;
	use std::time::Duration;
	use tokio::io::AsyncWriteExt;
	use tokio::process::Command;

	super::active(cancellation)?;
	let header = serde_json::to_vec(&Header {
		input: input.clone(),
		sha256: digest.to_owned(),
		bytes: bytes.len() as u64,
	})
	.map_err(|error| Failure::output(OP, error.to_string()))?;
	if header.len() > MAX_HEADER {
		return Err(Failure::output(OP, "ELF worker header exceeds its bound."));
	}
	let binary = std::env::current_exe().map_err(|error| Failure::output(OP, error.to_string()))?;
	let mut child = Command::new(binary)
		.arg("rea-elf-notes-worker")
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true)
		.spawn()
		.map_err(|error| {
			Failure::output(OP, format!("Cannot spawn isolated ELF parser: {error}"))
		})?;
	let (Some(mut stdin), Some(stdout), Some(stderr)) =
		(child.stdin.take(), child.stdout.take(), child.stderr.take())
	else {
		let _ = child.kill().await;
		child
			.wait()
			.await
			.map_err(|error| Failure::output(OP, format!("ELF worker reaping failed: {error}")))?;
		return Err(Failure::output(OP, "ELF worker pipes are unavailable."));
	};
	let collected = tokio::select! {
		biased;
		_ = cancellation.cancelled() => Err(Failure::cancelled(OP)),
		collected = tokio::time::timeout(Duration::from_millis(DEADLINE_MS), async {
			tokio::try_join!(
				async {
					stdin.write_all(&(header.len() as u32).to_le_bytes()).await?;
					stdin.write_all(&header).await?;
					stdin.write_all(bytes).await?;
					drop(stdin);
					Ok::<_,anyhow::Error>(())
				},
				read_capped(stdout,MAX_WORKER_REPLY+1), read_capped(stderr,64*1024),
				async { child.wait().await.map_err(anyhow::Error::from) }
			)
		}) => match collected {
			Err(_) => Err(Failure::timeout(OP,DEADLINE_MS)),
			Ok(Err(error)) => Err(Failure::output(OP,format!("Isolated ELF parser failed: {error:#}"))),
			Ok(Ok(value)) => Ok(value),
		}
	};
	let ((), stdout, stderr, status) = match collected {
		Ok(value) => value,
		Err(failure) => {
			let _ = child.kill().await;
			if let Err(error) = child.wait().await {
				return Err(Failure::output(
					OP,
					format!("ELF worker could not be reaped after failure: {error}"),
				));
			}
			return Err(failure);
		}
	};
	if !status.success() {
		return Err(Failure::output(
			OP,
			format!(
				"Isolated ELF parser exited ({status}): {}",
				String::from_utf8_lossy(&stderr).trim()
			),
		));
	}
	serde_json::from_slice(&stdout)
		.map_err(|error| Failure::output(OP, format!("ELF worker returned invalid JSON: {error}")))
}

#[cfg(test)]
pub(super) async fn inspect_isolated(
	input: &Input,
	digest: &str,
	bytes: &[u8],
	cancellation: &tokio_util::sync::CancellationToken,
) -> std::result::Result<Value, Failure> {
	super::active(cancellation)?;
	parse(
		&Header {
			input: input.clone(),
			sha256: digest.to_owned(),
			bytes: bytes.len() as u64,
		},
		bytes,
	)
	.map_err(|error| Failure::output(OP, error.to_string()))
}
