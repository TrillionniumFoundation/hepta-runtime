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

//! Single-shot Rust parser worker. The controller admits file bytes through its
//! configured workspace descriptor, then sends those bytes over stdin to this
//! process. The child never receives the path to open or runtime credentials.
//!
//! Linux adds a process-thread-synchronized syscall denylist after stdin has
//! been read. This is NOT a complete sandbox: UID, namespaces and other
//! information-flow paths remain outside the current boundary.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::io::{Read, Write};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const INPUT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_STDOUT_BYTES: usize = 256 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const WORKER_DEADLINE: Duration = Duration::from_secs(20);

#[cfg(unix)]
fn apply_limits() -> Result<()> {
	const MAX_ADDRESS_SPACE: libc::rlim_t = 512 * 1024 * 1024;
	const MAX_CPU_SECONDS: libc::rlim_t = 12;
	const MAX_OPEN_FILES: libc::rlim_t = 64;
	let limits = [
		(libc::RLIMIT_AS, MAX_ADDRESS_SPACE),
		(libc::RLIMIT_CPU, MAX_CPU_SECONDS),
		(libc::RLIMIT_NOFILE, MAX_OPEN_FILES),
		(libc::RLIMIT_CORE, 0),
		(libc::RLIMIT_FSIZE, MAX_STDOUT_BYTES as libc::rlim_t),
	];
	for (kind, allowed) in limits {
		let rule = libc::rlimit {
			rlim_cur: allowed,
			rlim_max: allowed,
		};
		if unsafe { libc::setrlimit(kind, &rule) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("failed to establish Rust REA worker resource limits");
		}
	}
	Ok(())
}

#[cfg(not(unix))]
fn apply_limits() -> Result<()> {
	bail!("native Rust REA worker is not qualified on non-Unix systems");
}

/// The only worker entrypoint. It never performs filesystem or remote reads.
/// stdout is emitted only for a completed, successful analysis.
pub fn serve_once(selected_path: &str, sandbox_probe: bool) -> Result<()> {
	apply_limits()?;
	let mut input = Vec::new();
	std::io::stdin()
		.lock()
		.take(INPUT_BYTES + 1)
		.read_to_end(&mut input)
		.context("cannot read Rust REA worker input")?;
	if input.len() as u64 > INPUT_BYTES {
		bail!("REA worker input exceeds 32 MiB");
	}
	super::rea_seccomp::tighten_after_read()?;
	if sandbox_probe {
		super::rea_seccomp::verify_file_network_denial()?;
		let mut stdout = std::io::stdout().lock();
		stdout.write_all(b"{\"status\":\"file_and_network_syscalls_denied\"}\n")?;
		stdout.flush()?;
		return Ok(());
	}
	let report = super::rea::inspect_bytes(&input, selected_path)?;
	let encoded = serde_json::to_vec(&report)?;
	if encoded.len() > MAX_STDOUT_BYTES {
		bail!("REA worker response exceeds 256 KiB");
	}
	let mut stdout = std::io::stdout().lock();
	stdout.write_all(&encoded)?;
	stdout.write_all(b"\n")?;
	stdout.flush()?;
	Ok(())
}

/// Run the shipped worker as a child of the current binary. This boundary
/// contains parser aborts (the production profile uses panic = abort) and
/// applies a deadline as well as independent worker rlimits.
pub async fn inspect_isolated(input: Vec<u8>, selected_path: &str) -> Result<Value> {
	if input.len() as u64 > INPUT_BYTES {
		bail!("REA inspection file exceeds 32 MiB worker limit");
	}
	let binary = std::env::current_exe().context("cannot locate Rust REA worker binary")?;
	let mut command = Command::new(binary);
	command
		.arg("rea-worker")
		.arg(format!("--selected-path={selected_path}"))
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	let run = async move {
		let mut child = command
			.spawn()
			.context("failed to spawn bounded Rust REA worker")?;
		let mut stdin = child
			.stdin
			.take()
			.ok_or_else(|| anyhow!("REA worker stdin unavailable"))?;
		stdin
			.write_all(&input)
			.await
			.context("failed to supply REA worker bytes")?;
		stdin
			.shutdown()
			.await
			.context("failed to close REA worker stdin")?;
		drop(stdin);
		let output = child
			.wait_with_output()
			.await
			.context("failed to wait for REA worker")?;
		if !output.status.success() {
			let diagnostic_len = output.stderr.len().min(MAX_STDERR_BYTES);
			let diagnostic = String::from_utf8_lossy(&output.stderr[..diagnostic_len]);
			bail!(
				"Rust REA worker failed ({}): {}",
				output.status,
				diagnostic.trim()
			);
		}
		if output.stdout.len() > MAX_STDOUT_BYTES {
			bail!("REA worker exceeded bounded response size");
		}
		let record: Value =
			serde_json::from_slice(&output.stdout).context("Rust REA worker output is not JSON")?;
		if record["record_format"] != "hepta.rea.preview.v1"
			|| record["rea_evidence_compatible"] != false
		{
			bail!("Rust REA worker returned an unexpected evidence contract");
		}
		Ok::<_, anyhow::Error>(record)
	};
	tokio::time::timeout(WORKER_DEADLINE, run)
		.await
		.context("Rust REA worker exceeded 20-second wall-clock deadline")?
}
