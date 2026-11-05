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

//! Shared framed transport and lifetime ownership for native analysis workers.
//! A request can drop, while its private owner completes kill, reap and reader
//! joins before releasing the parser slot and runtime effect admission.

use super::rea_contract::Failure;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::io::{self, Read, Write};
use std::sync::Arc;
#[cfg(not(test))]
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

pub(super) const MAX_HEADER: usize = 64 * 1024;
const IO_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(super) struct WorkerSpec {
	pub(super) operation: &'static str,
	pub(super) reply_limit: usize,
	pub(super) deadline_ms: u64,
}

struct BoundedWriter<W> {
	inner: W,
	remaining: usize,
}

impl<W: Write> Write for BoundedWriter<W> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if bytes.len() > self.remaining {
			return Err(io::Error::other(
				"Native analysis worker complete report exceeds its reply bound",
			));
		}
		let written = self.inner.write(bytes)?;
		self.remaining -= written;
		Ok(written)
	}
	fn flush(&mut self) -> io::Result<()> {
		self.inner.flush()
	}
}

pub(super) fn write_json<W: Write, T: Serialize>(writer: W, value: &T, limit: usize) -> Result<()> {
	let mut writer = BoundedWriter {
		inner: io::BufWriter::with_capacity(IO_BUFFER_BYTES, writer),
		remaining: limit,
	};
	serde_json::to_writer(&mut writer, value)?;
	writer.write_all(b"\n")?;
	writer.flush()?;
	Ok(())
}

#[cfg(unix)]
pub(super) fn install_limits(
	reply_limit: usize,
	memory_bytes: libc::rlim_t,
	cpu_seconds: libc::rlim_t,
) -> Result<()> {
	for (kind, allowed) in [
		(libc::RLIMIT_AS, memory_bytes),
		(libc::RLIMIT_CPU, cpu_seconds),
		(libc::RLIMIT_NOFILE, 64),
		(libc::RLIMIT_CORE, 0),
		(libc::RLIMIT_FSIZE, reply_limit as libc::rlim_t),
	] {
		let mut inherited = libc::rlimit {
			rlim_cur: 0,
			rlim_max: 0,
		};
		if unsafe { libc::getrlimit(kind, &mut inherited) } != 0 {
			return Err(io::Error::last_os_error())
				.context("cannot inspect inherited native analysis worker limits");
		}
		let hard = inherited.rlim_max.min(allowed);
		let bound = libc::rlimit {
			rlim_cur: inherited.rlim_cur.min(hard),
			rlim_max: hard,
		};
		if unsafe { libc::setrlimit(kind, &bound) } != 0 {
			return Err(io::Error::last_os_error())
				.context("cannot establish native analysis worker limits");
		}
	}
	#[cfg(target_os = "linux")]
	{
		let parent = unsafe { libc::getppid() };
		if parent == 1 || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
			bail!("cannot bind native analysis worker to controller lifetime");
		}
		if unsafe { libc::getppid() } != parent {
			bail!("native analysis worker controller exited during startup");
		}
	}
	Ok(())
}

/// Count every transport byte, including trailing whitespace. An exact-bound EOF
/// is allowed; a one-byte probe distinguishes it from an oversized reply.
pub(super) struct BoundedReader<R> {
	pub(super) inner: R,
	pub(super) remaining: usize,
}

impl<R: Read> Read for BoundedReader<R> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		if buffer.is_empty() {
			return Ok(0);
		}
		if self.remaining == 0 {
			let mut extra = [0_u8; 1];
			return match self.inner.read(&mut extra)? {
				0 => Ok(0),
				_ => Err(io::Error::other(
					"Native analysis worker reply exceeds its allowance",
				)),
			};
		}
		let allowed = buffer.len().min(self.remaining);
		let count = self.inner.read(&mut buffer[..allowed])?;
		self.remaining -= count;
		Ok(count)
	}
}

#[cfg(unix)]
struct CancellablePipe {
	file: std::fs::File,
	cancellation: CancellationToken,
}

#[cfg(unix)]
impl Read for CancellablePipe {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		use std::os::fd::AsRawFd;
		if bytes.is_empty() {
			return Ok(0);
		}
		loop {
			if self.cancellation.is_cancelled() {
				return Err(io::Error::new(
					io::ErrorKind::ConnectionAborted,
					"Native analysis worker reply read cancelled",
				));
			}
			let mut pollfd = libc::pollfd {
				fd: self.file.as_raw_fd(),
				events: libc::POLLIN,
				revents: 0,
			};
			// The descriptor is owned by this single reader. Poll bounds cancellation
			// latency even if an unexpected writer keeps the pipe open after reaping.
			let ready = unsafe { libc::poll(&mut pollfd, 1, 50) };
			if ready < 0 {
				let error = io::Error::last_os_error();
				if error.kind() == io::ErrorKind::Interrupted {
					continue;
				}
				return Err(error);
			}
			if ready == 0 {
				continue;
			}
			if pollfd.revents & libc::POLLNVAL != 0 {
				return Err(io::Error::other(
					"Native analysis worker reply descriptor is invalid",
				));
			}
			match self.file.read(bytes) {
				Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
				result => return result,
			}
		}
	}
}

#[cfg(unix)]
fn blocking_stdout(stdout: tokio::process::ChildStdout) -> Result<std::fs::File> {
	use std::os::fd::AsRawFd;
	let fd = stdout
		.into_owned_fd()
		.context("cannot take ownership of Native analysis worker stdout")?;
	// No asynchronous reader retains this descriptor. Clear Tokio's nonblocking
	// flag before transferring sole ownership to the blocking JSON reader.
	let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
	if flags < 0
		|| unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0
	{
		return Err(io::Error::last_os_error())
			.context("cannot make Native analysis worker stdout blocking");
	}
	Ok(std::fs::File::from(fd))
}

#[cfg(unix)]
pub(super) fn read_reply(
	file: std::fs::File,
	limit: usize,
	cancellation: CancellationToken,
) -> Result<Value> {
	let pipe = CancellablePipe { file, cancellation };
	let reader = io::BufReader::with_capacity(
		IO_BUFFER_BYTES,
		BoundedReader {
			inner: pipe,
			remaining: limit,
		},
	);
	serde_json::from_reader(reader)
		.context("Native analysis worker returned invalid or oversized JSON")
}

#[cfg(unix)]
async fn read_stderr(reader: tokio::process::ChildStderr) -> Result<Vec<u8>> {
	use tokio::io::AsyncReadExt;
	let mut bytes = Vec::new();
	reader.take((64 * 1024) + 1).read_to_end(&mut bytes).await?;
	if bytes.len() > 64 * 1024 {
		bail!("Native analysis worker stderr exceeds its allowance");
	}
	Ok(bytes)
}

#[cfg(unix)]
async fn kill_and_reap(child: &mut tokio::process::Child) -> Result<()> {
	// start_kill may race a normal exit. Only wait's outcome decides whether this
	// owner has completed reaping; an already-exited child still must be waited.
	let kill = child.start_kill();
	match child.wait().await {
		Ok(_) => Ok(()),
		Err(error) => Err(error)
			.with_context(|| format!("Native analysis worker reaping failed (kill={kill:?})")),
	}
}

#[cfg(unix)]
pub(super) async fn supervise_child(
	mut child: tokio::process::Child,
	header: Vec<u8>,
	bytes: Arc<Vec<u8>>,
	cancellation: CancellationToken,
	spec: WorkerSpec,
) -> std::result::Result<Value, Failure> {
	use tokio::io::AsyncWriteExt;
	let deadline = std::time::Duration::from_millis(spec.deadline_ms);
	let operation = spec.operation;
	let (Some(mut stdin), Some(stdout), Some(stderr)) =
		(child.stdin.take(), child.stdout.take(), child.stderr.take())
	else {
		let cleanup = kill_and_reap(&mut child).await;
		return Err(Failure::output(
			operation,
			format!("Native analysis worker pipes are unavailable; cleanup={cleanup:?}"),
		));
	};
	let stdout = match blocking_stdout(stdout) {
		Ok(stdout) => stdout,
		Err(error) => {
			drop(stdin);
			drop(stderr);
			let cleanup = kill_and_reap(&mut child).await;
			return Err(Failure::output(
				operation,
				format!("Native analysis worker stdout admission failed: {error:#}; cleanup={cleanup:?}"),
			));
		}
	};
	let reader_cancel = CancellationToken::new();
	let reader_token = reader_cancel.clone();
	let (reply_sender, reply_receiver) = tokio::sync::oneshot::channel();
	// Keep the JoinHandle outside every cancellable/select/try_join future. The
	// channel transports the parsed Value; only the owner below joins the reader.
	let reader = tokio::task::spawn_blocking(move || {
		let reply = read_reply(stdout, spec.reply_limit, reader_token);
		let _ = reply_sender.send(reply);
	});
	// Preserve diagnostics even when another branch fails before EOF. This task
	// is also joined by the owner after the sole worker process has been reaped.
	let stderr_reader = tokio::spawn(read_stderr(stderr));
	let collected = tokio::select! {
		biased;
		_ = cancellation.cancelled() => Err(Failure::cancelled(operation)),
		collected = tokio::time::timeout(deadline, async {
			tokio::try_join!(
				async {
					stdin.write_all(&(header.len() as u32).to_le_bytes()).await?;
					stdin.write_all(&header).await?;
					stdin.write_all(bytes.as_slice()).await?;
					drop(stdin);
					Ok::<_, anyhow::Error>(())
				},
				async { reply_receiver.await.context("Native analysis worker JSON reader stopped without a result")? },
				async { child.wait().await.map_err(anyhow::Error::from) },
			)
		}) => match collected {
			Err(_) => Err(Failure::timeout(operation, deadline.as_millis().min(u128::from(u64::MAX)) as u64)),
			Ok(Err(error)) => Err(Failure::output(operation, format!("Isolated native analysis parser failed: {error:#}"))),
			Ok(Ok(value)) => Ok(value),
		}
	};
	match collected {
		Err(mut failure) => {
			// Do not detach a blocking reader when the request is cancelled or one
			// concurrent branch fails: first terminate/reap, then stop and join it.
			let reaped = kill_and_reap(&mut child).await;
			reader_cancel.cancel();
			let joined = reader.await;
			let stderr = stderr_reader.await;
			if reaped.is_err() || joined.is_err() {
				return Err(Failure::output(operation, format!("Native analysis worker cleanup failed: reap={reaped:?}; reader={joined:?}; stderr={stderr:?}; original={failure:?}")));
			}
			match stderr {
				Ok(Ok(stderr)) if !stderr.is_empty() => {
					failure.0["details"]["worker_stderr"] =
						Value::String(String::from_utf8_lossy(&stderr).into_owned());
				}
				Err(error) => {
					failure.0["details"]["worker_stderr_error"] = Value::String(error.to_string())
				}
				Ok(Err(error)) => {
					failure.0["details"]["worker_stderr_error"] =
						Value::String(format!("{error:#}"))
				}
				_ => {}
			}
			Err(failure)
		}
		Ok(((), reply, status)) => {
			// child.wait completed inside the join above. Join exactly once before
			// returning any successful Value or dropping the owner's admission guards.
			let joined = reader.await;
			let stderr = stderr_reader.await;
			joined.map_err(|error| {
				Failure::output(
					operation,
					format!("Native analysis worker JSON reader join failed: {error}"),
				)
			})?;
			let stderr = stderr
				.map_err(|error| {
					Failure::output(
						operation,
						format!("Native analysis worker stderr reader join failed: {error}"),
					)
				})?
				.map_err(|error| {
					Failure::output(
						operation,
						format!("Native analysis worker stderr read failed: {error:#}"),
					)
				})?;
			if !status.success() {
				return Err(Failure::output(
					operation,
					format!(
						"Isolated native analysis parser exited ({status}): {}",
						String::from_utf8_lossy(&stderr).trim()
					),
				));
			}
			Ok(reply)
		}
	}
}

#[cfg(all(not(test), unix))]
struct OwnerResources {
	_lease: Arc<OwnedSemaphorePermit>,
	_admission: Arc<super::runtime::effect_owner_fence::AdmissionPermit>,
}

/// The resource value remains owned until the complete supervision future ends.
/// Tests use a drop witness alongside a real semaphore lease; production passes
/// both real admission guards. No requester can abort this private owner task.
#[cfg(unix)]
async fn keep_resources<R: Send>(
	resources: R,
	work: impl std::future::Future<Output = std::result::Result<Value, Failure>>,
) -> std::result::Result<Value, Failure> {
	let result = work.await;
	drop(resources);
	result
}

#[cfg(unix)]
pub(super) async fn await_owned<R, F>(
	resources: R,
	cancellation: &CancellationToken,
	operation: &'static str,
	work: impl FnOnce(CancellationToken) -> F,
) -> std::result::Result<Value, Failure>
where
	R: Send + 'static,
	F: std::future::Future<Output = std::result::Result<Value, Failure>> + Send + 'static,
{
	let owner_cancel = cancellation.child_token();
	let _cancel_on_drop = owner_cancel.clone().drop_guard();
	let owner = tokio::spawn(keep_resources(resources, work(owner_cancel)));
	owner.await.map_err(|error| {
		Failure::output(
			operation,
			format!("Native analysis worker owner task failed: {error}"),
		)
	})?
}

#[cfg(not(test))]
pub(super) async fn inspect_frame(
	spec: WorkerSpec,
	command: &'static str,
	header: Vec<u8>,
	bytes: Arc<Vec<u8>>,
	cancellation: &CancellationToken,
	lease: Arc<OwnedSemaphorePermit>,
	admission: Arc<super::runtime::effect_owner_fence::AdmissionPermit>,
) -> std::result::Result<Value, Failure> {
	if cancellation.is_cancelled() {
		return Err(Failure::cancelled(spec.operation));
	}
	if header.is_empty() || header.len() > MAX_HEADER {
		return Err(Failure::output(
			spec.operation,
			"Native worker header exceeds its bound.",
		));
	}
	#[cfg(not(unix))]
	{
		let _ = (command, header, bytes, lease, admission);
		Err(Failure::output(
			spec.operation,
			"Native isolation is not available on this platform",
		))
	}
	#[cfg(unix)]
	{
		use std::process::Stdio;
		let binary = std::env::current_exe()
			.map_err(|error| Failure::output(spec.operation, error.to_string()))?;
		let resources = OwnerResources {
			_lease: lease,
			_admission: admission,
		};
		await_owned(
			resources,
			cancellation,
			spec.operation,
			move |owner_cancel| async move {
				if owner_cancel.is_cancelled() {
					return Err(Failure::cancelled(spec.operation));
				}
				let child = tokio::process::Command::new(binary)
					.arg(command)
					.env_clear()
					.current_dir("/")
					.stdin(Stdio::piped())
					.stdout(Stdio::piped())
					.stderr(Stdio::piped())
					.kill_on_drop(true)
					.spawn()
					.map_err(|error| {
						Failure::output(
							spec.operation,
							format!("Cannot spawn native analysis worker: {error}"),
						)
					})?;
				supervise_child(child, header, bytes, owner_cancel, spec).await
			},
		)
		.await
	}
}
