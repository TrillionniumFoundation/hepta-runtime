// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One-shot fixed static backend worker with immutable Linux input snapshots.
//!
//! It is a child of the ordinary jobs owner, and its backend remains in the
//! same process group. Inputs are never executed. No persistent service, shell,
//! arbitrary flags, scripts or caller-selected backend is introduced. Java engine
//! temporary files live in private monitored scratch with explicit cleanup.

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{bail, Result};
#[cfg(target_os = "linux")]
use serde_json::{json, Value};
#[cfg(target_os = "linux")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(target_os = "linux")]
use super::rea_provider::{validate_worker_request, WorkerRequest, MAX_WORKER_REQUEST};

#[cfg(target_os = "linux")]
#[path = "rea_engine.rs"]
mod engine;

#[cfg(target_os = "linux")]
mod linux {
	use super::*;
	use crate::mcp::rea_provider::sha256;
	use anyhow::anyhow;
	use sha2::{Digest, Sha256};
	use std::ffi::CString;
	use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
	use std::os::unix::ffi::OsStrExt;
	use std::os::unix::fs::MetadataExt;
	use std::path::{Component, Path};
	use std::process::Stdio;
	use std::time::Duration;
	use tokio::io::{AsyncRead, AsyncSeekExt};
	use tokio::process::Command;
	use tokio::time::Instant;

	const MAX_BACKEND_BYTES: u64 = 64 * 1024 * 1024;
	// Debug-qualified binaries include symbols; hashing remains streaming.
	const MAX_RUNTIME_BYTES: u64 = 1024 * 1024 * 1024;

	pub(super) struct Snapshot {
		pub(super) file: std::fs::File,
		pub(super) sha256: String,
		pub(super) size: u64,
	}

	pub(super) fn unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
		before.dev() == after.dev()
			&& before.ino() == after.ino()
			&& before.len() == after.len()
			&& before.mode() == after.mode()
			&& before.uid() == after.uid()
			&& before.gid() == after.gid()
			&& before.nlink() == after.nlink()
			&& before.mtime() == after.mtime()
			&& before.mtime_nsec() == after.mtime_nsec()
			&& before.ctime() == after.ctime()
			&& before.ctime_nsec() == after.ctime_nsec()
	}

	/// Roots are administrator-owned; each user-selected descendant is opened
	/// while holding its parent directory descriptor, never re-resolved by name.
	pub(super) fn open_artifact(path: &Path, roots: &[String]) -> Result<std::fs::File> {
		for root in roots {
			let Ok(relative) = path.strip_prefix(root) else {
				continue;
			};
			let parts = relative
				.components()
				.map(|component| match component {
					Component::Normal(name) => {
						CString::new(name.as_bytes()).context("artifact path contains NUL")
					}
					_ => bail!("non-normal artifact path component"),
				})
				.collect::<Result<Vec<_>>>()?;
			let (leaf, parents) = parts
				.split_last()
				.context("artifact must be a file below its root")?;
			let root = CString::new(root.as_bytes())?;
			let fd = unsafe {
				libc::open(
					root.as_ptr(),
					libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
				)
			};
			if fd < 0 {
				return Err(std::io::Error::last_os_error())
					.context("cannot open static input root");
			}
			let mut parent = unsafe { OwnedFd::from_raw_fd(fd) };
			for part in parents {
				let fd = unsafe {
					libc::openat(
						parent.as_raw_fd(),
						part.as_ptr(),
						libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
					)
				};
				if fd < 0 {
					return Err(std::io::Error::last_os_error())
						.context("unsafe artifact directory component");
				}
				parent = unsafe { OwnedFd::from_raw_fd(fd) };
			}
			let fd = unsafe {
				libc::openat(
					parent.as_raw_fd(),
					leaf.as_ptr(),
					libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
				)
			};
			if fd < 0 {
				return Err(std::io::Error::last_os_error())
					.context("unsafe artifact file component");
			}
			return Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }));
		}
		bail!("artifact is outside configured static roots")
	}

	pub(super) fn memfile(name: &str) -> Result<std::fs::File> {
		let name = CString::new(name)?;
		let fd = unsafe {
			libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error())
				.context("Linux sealed memory snapshots unavailable");
		}
		Ok(unsafe { std::fs::File::from_raw_fd(fd) })
	}

	pub(super) async fn snapshot(
		mut source: tokio::fs::File,
		expected: &str,
		limit: u64,
		executable: bool,
		deadline: Instant,
	) -> Result<Snapshot> {
		let before = source.metadata().await?;
		if !before.is_file() || before.len() > limit {
			bail!("static source is not a bounded regular file");
		}
		let memory = memfile(if executable {
			"hepta-static-backend"
		} else {
			"hepta-static-artifact"
		})?;
		let mut memory = tokio::fs::File::from_std(memory);
		let mut hash = Sha256::new();
		let mut total = 0u64;
		let mut bytes = vec![0u8; 64 * 1024];
		loop {
			let size = tokio::time::timeout_at(deadline, source.read(&mut bytes))
				.await
				.context("static snapshot deadline exceeded")??;
			if size == 0 {
				break;
			}
			total = total
				.checked_add(size as u64)
				.context("static snapshot size overflow")?;
			if total > limit {
				bail!("static source grew beyond its byte limit");
			}
			hash.update(&bytes[..size]);
			tokio::time::timeout_at(deadline, memory.write_all(&bytes[..size]))
				.await
				.context("static snapshot deadline exceeded")??;
		}
		if !unchanged(&before, &source.metadata().await?) || total != before.len() {
			bail!("static source changed during snapshot admission");
		}
		let actual: String = hash
			.finalize()
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect();
		if actual != expected {
			bail!("static source SHA-256 does not match the admitted identity");
		}
		memory.flush().await?;
		memory.seek(std::io::SeekFrom::Start(0)).await?;
		let memory = memory.into_std().await;
		let mode = if executable { 0o500 } else { 0o400 };
		if unsafe { libc::fchmod(memory.as_raw_fd(), mode) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot set static snapshot permissions");
		}
		let seals =
			libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
		if unsafe { libc::fcntl(memory.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot make static snapshot immutable");
		}
		Ok(Snapshot {
			file: memory,
			sha256: actual,
			size: total,
		})
	}

	pub(super) async fn hash_runtime(expected: &str, deadline: Instant) -> Result<()> {
		// /proc/self/exe names the running image, even if its deployment pathname
		// was replaced. It is kernel-provided, not a caller-controlled file path.
		let mut file = tokio::fs::File::open("/proc/self/exe").await?;
		let before = file.metadata().await?;
		if !before.is_file() || before.len() > MAX_RUNTIME_BYTES {
			bail!("runtime image exceeds pinning limit");
		}
		let mut hash = Sha256::new();
		let mut total = 0u64;
		let mut buf = vec![0u8; 64 * 1024];
		loop {
			let n = tokio::time::timeout_at(deadline, file.read(&mut buf))
				.await
				.context("runtime hash deadline exceeded")??;
			if n == 0 {
				break;
			}
			total += n as u64;
			if total > MAX_RUNTIME_BYTES {
				bail!("runtime image grew past pinning limit");
			}
			hash.update(&buf[..n]);
		}
		let actual: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
		if actual != expected || !unchanged(&before, &file.metadata().await?) {
			bail!("running static worker image does not match its configured SHA-256");
		}
		Ok(())
	}

	pub(super) async fn read_capped(reader: impl AsyncRead + Unpin, max: usize) -> Result<Vec<u8>> {
		let mut out = Vec::new();
		reader.take(max as u64 + 1).read_to_end(&mut out).await?;
		if out.len() > max {
			bail!("static backend exceeded its output bound; partial output is not returned");
		}
		Ok(out)
	}

	/// Backend children inherit the jobs owner's process group; no setsid,
	/// process-group reparenting, detached process or separate supervisor exists.
	pub(super) async fn run_bounded(
		backend: &Snapshot,
		arguments: &[String],
		artifact_fd: Option<RawFd>,
		max_output: usize,
		deadline: Instant,
	) -> Result<(Vec<u8>, Vec<u8>, std::process::ExitStatus)> {
		let backend_fd = backend.file.as_raw_fd();
		let mut command = Command::new(format!("/proc/self/fd/{backend_fd}"));
		command
			.args(arguments)
			.env_clear()
			.env("LC_ALL", "C")
			.current_dir("/")
			.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped())
			.kill_on_drop(true);
		unsafe {
			command.pre_exec(move || {
				// These are the only descriptors intentionally carried into exec.
				for fd in [Some(backend_fd), artifact_fd].into_iter().flatten() {
					if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
						return Err(std::io::Error::last_os_error());
					}
				}
				if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
					return Err(std::io::Error::last_os_error());
				}
				Ok(())
			});
		}
		let mut child = command
			.spawn()
			.context("cannot launch pinned static backend snapshot")?;
		let stdout = child
			.stdout
			.take()
			.context("static backend stdout unavailable")?;
		let stderr = child
			.stderr
			.take()
			.context("static backend stderr unavailable")?;
		let result = tokio::time::timeout_at(deadline, async {
			tokio::try_join!(
				read_capped(stdout, max_output),
				read_capped(stderr, max_output),
				async { child.wait().await.map_err(Into::into) }
			)
		})
		.await;
		match result {
			Ok(Ok(result)) => Ok(result),
			other => {
				let _ = child.start_kill();
				let _ = child.wait().await;
				match other {
					Ok(Err(error)) => Err(error),
					Err(_) => bail!("static backend exceeded its total deadline"),
					Ok(Ok(_)) => Err(anyhow!("unreachable static backend completion")),
				}
			}
		}
	}

	pub(super) async fn analyze(input: WorkerRequest) -> Result<Value> {
		validate_worker_request(&input)?;
		if input.profile.provider == crate::mcp::rea_provider::StaticProvider::Jadx {
			return super::engine::analyze(input).await;
		}
		if input.profile.provider == crate::mcp::rea_provider::StaticProvider::Ghidra {
			return super::engine::analyze_ghidra(input).await;
		}
		let started = Instant::now();
		let deadline = started + Duration::from_secs(input.profile.timeout_seconds);
		hash_runtime(&input.profile.runtime_sha256, deadline).await?;
		let backend_file = tokio::fs::File::open(&input.profile.backend_executable)
			.await
			.context("cannot open configured static backend")?;
		let backend = snapshot(
			backend_file,
			&input.profile.backend_sha256,
			MAX_BACKEND_BYTES,
			true,
			deadline,
		)
		.await?;
		let (version_out, version_err, version_status) =
			run_bounded(&backend, &["--version".into()], None, 8192, deadline).await?;
		let version_text =
			std::str::from_utf8(&version_out).context("backend version is not UTF-8")?;
		let version = version_text
			.lines()
			.next()
			.context("backend version line absent")?;
		if !version_status.success()
			|| !version_err.is_empty()
			|| version != input.profile.backend_version
		{
			bail!("static backend version does not match its configured identity");
		}
		let selected = input.request.artifact_path.clone();
		let roots = input.profile.input_roots.clone();
		let source =
			tokio::task::spawn_blocking(move || open_artifact(Path::new(&selected), &roots))
				.await
				.context("static artifact admission task failed")??;
		let artifact = snapshot(
			tokio::fs::File::from_std(source),
			&input.request.artifact_sha256,
			input.profile.max_artifact_bytes,
			false,
			deadline,
		)
		.await?;
		let descriptor_path = format!("/proc/self/fd/{}", artifact.file.as_raw_fd());
		let arguments = input
			.profile
			.provider
			.arguments(input.request.operation, &descriptor_path)?;
		let (stdout, stderr, status) = run_bounded(
			&backend,
			&arguments,
			Some(artifact.file.as_raw_fd()),
			input.profile.max_output_bytes,
			deadline,
		)
		.await?;
		let stdout_text = std::str::from_utf8(&stdout).context("backend stdout is not UTF-8")?;
		let stderr_text = std::str::from_utf8(&stderr).context("backend stderr is not UTF-8")?;
		let mut report = json!({
			"schema":"hepta.rea.static-report.v1","request_sha256":sha256(&serde_json::to_vec(&input)?),
			"runtime_sha256":input.profile.runtime_sha256,
			"provider":input.profile.provider,"operation":input.request.operation,
			"backend":{"sha256":backend.sha256,"version":version,"size_bytes":backend.size},
			"subject":{"selected_path":input.request.artifact_path,"sha256":artifact.sha256,"size_bytes":artifact.size,"snapshot":"sealed_linux_memfd"},
			"backend_success":status.success(),"backend_exit_code":status.code(),
			"stdout":stdout_text,"stderr":stderr_text,"stdout_sha256":sha256(&stdout),"stderr_sha256":sha256(&stderr),
			"stdout_bytes":stdout.len(),"stderr_bytes":stderr.len(),"output_complete":true,
			"summary":crate::mcp::rea_provider::summary::selected_fields(input.profile.provider,input.request.operation,stdout_text,status.success()),
			"elapsed_ms":started.elapsed().as_millis(),"rea_evidence_compatible":false,
			"coverage":{"scope":"selected_static_backend_operation","status":"partial"},
			"limitations":["Raw backend text is retained; no full REA normalization or decompiler parity is claimed", "Pinned executable bytes and version do not attest the system dynamic-library closure", "Supported GPU objects depend on this exact installed GNU backend; unsupported objects remain explicit backend failures"]
		});
		let id = sha256(&serde_json::to_vec(&report)?);
		report["native_report_id"] = json!(format!("hepta_rea_static_v1_{id}"));
		Ok(report)
	}
}

/// CLI entry: one bounded policy-owned request on stdin, one completed report.
/// The same runtime binary is launched by the existing durable jobs owner.
#[cfg(target_os = "linux")]
pub async fn serve_once() -> Result<()> {
	let mut bytes = Vec::new();
	tokio::time::timeout(
		std::time::Duration::from_secs(5),
		tokio::io::stdin()
			.take(MAX_WORKER_REQUEST as u64 + 1)
			.read_to_end(&mut bytes),
	)
	.await
	.context("static worker request deadline exceeded")??;
	if bytes.len() > MAX_WORKER_REQUEST {
		bail!("static worker request exceeds 64 KiB");
	}
	let input: WorkerRequest =
		serde_json::from_slice(&bytes).context("invalid static worker request")?;
	validate_worker_request(&input)?;
	let report = linux::analyze(input).await?;
	let mut output = serde_json::to_vec(&report)?;
	if output.len() > super::rea_provider::MAX_RESULT_BYTES - 4096 {
		bail!("static report exceeds output envelope limit");
	}
	output.push(b'\n');
	let mut stdout = tokio::io::stdout();
	stdout.write_all(&output).await?;
	stdout.flush().await?;
	if report["backend_success"] != true {
		bail!("static backend reported failure; inspect its retained report");
	}
	Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn serve_once() -> Result<()> {
	bail!("static backend workers require Linux sealed memory snapshots")
}

#[cfg(all(test, target_os = "linux"))]
#[path = "rea_static_tests.rs"]
mod tests;
