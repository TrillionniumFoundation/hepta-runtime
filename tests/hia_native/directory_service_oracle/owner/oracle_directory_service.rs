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
//! Private lifecycle driver for unchanged original directory and session owners.
//! The driver schedules actual Futures; it makes no policy or filesystem choice.
pub mod mcp;
pub mod utils;

use anyhow::{bail, ensure, Context};
use mcp::{fs, request_ctx, runtime, McpToolCall};
use rmcp::{
	handler::server::wrapper::Parameters,
	model::{ClientCapabilities, RequestId},
	service::{RequestContext, RunningService},
	RoleServer, ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
	collections::BTreeMap,
	future::Future,
	io::{Read, Write},
	os::fd::{FromRawFd, RawFd},
	path::{Path, PathBuf},
	pin::Pin,
	sync::{atomic::AtomicBool, Arc, RwLock},
	task::{Context as TaskContext, Poll, Wake, Waker},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tracing::debug;

struct OctofsServer {
	workdir: Arc<SessionWorkdir>,
	session_applied: Arc<AtomicBool>,
	view_cache: Arc<fs::delta::ViewCache>,
}
include!("generated_session_owner.rs");
include!("generated_directory_owner.rs");

#[derive(Clone)]
struct NullServer;
impl rmcp::ServerHandler for NullServer {}

async fn bootstrap(
	modern: bool,
) -> anyhow::Result<(RunningService<RoleServer, NullServer>, DuplexStream, Value)> {
	let (mut client, server) = tokio::io::duplex(16384);
	let task = tokio::spawn(async move { NullServer.serve(server).await });
	let request = if modern {
		json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
			"io.modelcontextprotocol/protocolVersion":"2026-07-28",
			"io.modelcontextprotocol/clientCapabilities":{}
		}}})
	} else {
		json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
			"protocolVersion":"2025-11-25","capabilities":{},
			"clientInfo":{"name":"hia-context-reference","version":"1"}
		}})
	};
	let mut wire = serde_json::to_vec(&request)?;
	wire.push(b'\n');
	client.write_all(&wire).await?;
	let mut response = Vec::new();
	loop {
		let byte = client.read_u8().await?;
		response.push(byte);
		ensure!(response.len() <= 16384, "bootstrap response capacity");
		if byte == b'\n' {
			break;
		}
	}
	let response: Value = serde_json::from_slice(&response)?;
	ensure!(response["id"] == 1, "bootstrap response id");
	let running = task.await??;
	if !modern {
		client
			.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
			.await?;
	}
	Ok((
		running,
		client,
		json!({"modern":modern,"request":request,"response":response}),
	))
}

fn word(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().expect("checked private frame"))
}

struct WakePipe(RawFd);
impl Wake for WakePipe {
	fn wake(self: Arc<Self>) {
		self.wake_by_ref();
	}
	fn wake_by_ref(self: &Arc<Self>) {
		// Wake coalescing only: the real Future retains its result independently.
		unsafe {
			libc::write(self.0, b"x".as_ptr().cast(), 1);
		}
	}
}
impl Drop for WakePipe {
	fn drop(&mut self) {
		unsafe {
			libc::close(self.0);
		}
	}
}

struct Task {
	future: Pin<Box<dyn Future<Output = Result<String, String>>>>,
	cancel: Box<dyn Fn()>,
	suppressed: bool,
}

fn event(kind: u64, id: u64, code: u64, payload: &[u8]) -> anyhow::Result<()> {
	let mut output = std::io::stdout().lock();
	output.write_all(&(40 + payload.len() as u64).to_le_bytes())?;
	output.write_all(b"HMDCTR01")?;
	for number in [kind, id, code, payload.len() as u64] {
		output.write_all(&number.to_le_bytes())?;
	}
	output.write_all(payload)?;
	output.flush()?;
	Ok(())
}

fn poll_tasks(tasks: &mut BTreeMap<u64, Task>, waker: &Waker) -> anyhow::Result<()> {
	let mut done = Vec::new();
	for (id, task) in tasks.iter_mut() {
		if let Poll::Ready(result) = task
			.future
			.as_mut()
			.poll(&mut TaskContext::from_waker(waker))
		{
			if task.suppressed {
				event(2, *id, 0, &[])?;
			} else {
				let (tag, text) = match result {
					Ok(text) => (0_u64, text),
					Err(text) => (1_u64, text),
				};
				let mut raw = b"HMDCRS01".to_vec();
				for number in [tag, 0, text.len() as u64] {
					raw.extend_from_slice(&number.to_le_bytes());
				}
				raw.extend_from_slice(text.as_bytes());
				event(2, *id, raw.len() as u64, &raw)?;
			}
			done.push(*id);
		}
	}
	for id in done {
		tasks.remove(&id);
	}
	Ok(())
}

fn driver(state: Arc<OctofsServer>, peer: rmcp::Peer<RoleServer>) -> anyhow::Result<()> {
	let mut pipes = [-1; 2];
	ensure!(
		unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == 0,
		"qualification wake pipe: {}",
		std::io::Error::last_os_error()
	);
	let wake_read = unsafe { std::fs::File::from_raw_fd(pipes[0]) };
	let waker = Waker::from(Arc::new(WakePipe(pipes[1])));
	let old = unsafe { libc::fcntl(0, libc::F_GETFL) };
	ensure!(old >= 0 && unsafe { libc::fcntl(0, libc::F_SETFL, old | libc::O_NONBLOCK) } == 0);
	let mut tasks = BTreeMap::<u64, Task>::new();
	let mut buffer = Vec::<u8>::new();
	let mut last = 0;
	let mut eof = false;
	let mut inputs = 0_u64;
	let mut drops = 0_u64;
	let mut cancels = 0_u64;
	while !eof {
		poll_tasks(&mut tasks, &waker)?;
		while buffer.len() >= 8 {
			let n = word(&buffer, 0) as usize;
			ensure!((32..=16777288).contains(&n), "private input bound");
			if buffer.len() < n + 8 {
				break;
			}
			let raw: Vec<u8> = buffer.drain(..n + 8).skip(8).collect();
			ensure!(&raw[..8] == b"HMDCTL01" && word(&raw, 24) as usize == n - 32);
			let command = word(&raw, 8);
			let id = word(&raw, 16);
			ensure!(id != 0);
			inputs += 1;
			match command {
				1 => {
					ensure!(id > last && n >= 72);
					last = id;
					let body = &raw[32..];
					ensure!(&body[..8] == b"HMDCRQ02" && word(body, 32) == 0);
					let path_len = word(body, 8) as usize;
					let present = word(body, 16);
					let meta_len = word(body, 24) as usize;
					ensure!(path_len <= 8 << 20 && meta_len <= 8 << 20 && present <= 1);
					ensure!(present == 1 || meta_len == 0);
					ensure!(40 + path_len + meta_len == body.len());
					let path = std::str::from_utf8(&body[40..40 + path_len])?.to_owned();
					let mut context =
						RequestContext::new(RequestId::Number(id as i64), peer.clone());
					let meta = if present == 1 {
						&body[40 + path_len..]
					} else {
						b"{}"
					};
					context.meta = serde_json::from_slice(meta)?;
					let cancellation = context.ct.clone();
					let state = state.clone();
					let future = Box::pin(async move {
						state
							.directory_create(context, Parameters(DirectoryCreateParams { path }))
							.await
					});
					tasks.insert(
						id,
						Task {
							future,
							cancel: Box::new(move || cancellation.cancel()),
							suppressed: false,
						},
					);
					event(1, id, 0, &[])?;
				}
				2 => {
					ensure!(n == 32);
					let code = if let Some(task) = tasks.get_mut(&id) {
						(task.cancel)();
						task.suppressed = true;
						cancels += 1;
						0
					} else {
						1
					};
					event(3, id, code, &[])?;
				}
				3 => {
					ensure!(n == 32);
					let code = if let Some(task) = tasks.remove(&id) {
						// Actual synchronous Future drop releases its AdmissionPermit;
						// Tokio's already submitted blocking closure remains running.
						drop(task);
						drops += 1;
						0
					} else {
						1
					};
					event(4, id, code, &[])?;
				}
				_ => bail!("private command"),
			}
			// Preserve the synchronous portion of a real Future::poll before
			// considering another cancellation or ordinary input frame.
			poll_tasks(&mut tasks, &waker)?;
		}
		let mut pollfd = [
			libc::pollfd {
				fd: 0,
				events: libc::POLLIN,
				revents: 0,
			},
			libc::pollfd {
				fd: pipes[0],
				events: libc::POLLIN,
				revents: 0,
			},
		];
		let count = unsafe { libc::poll(pollfd.as_mut_ptr(), 2, -1) };
		if count < 0 {
			if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
				continue;
			}
			bail!("private poll: {}", std::io::Error::last_os_error());
		}
		if pollfd[1].revents != 0 {
			let mut bytes = [0_u8; 4096];
			loop {
				let n = unsafe { libc::read(pipes[0], bytes.as_mut_ptr().cast(), bytes.len()) };
				if n > 0 {
					continue;
				}
				if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
					continue;
				}
				ensure!(
					n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN)
				);
				break;
			}
		}
		if pollfd[0].revents != 0 {
			let mut bytes = [0_u8; 65536];
			let n = unsafe { libc::read(0, bytes.as_mut_ptr().cast(), bytes.len()) };
			if n == 0 {
				eof = true;
			} else if n > 0 {
				buffer.extend_from_slice(&bytes[..n as usize]);
			} else {
				ensure!([Some(libc::EINTR), Some(libc::EAGAIN)]
					.contains(&std::io::Error::last_os_error().raw_os_error()));
			}
		}
	}
	ensure!(buffer.is_empty(), "truncated private frame");
	// Original runtime destruction waits for submitted spawn_blocking tasks.
	// No invented completion event is claimed for an explicitly dropped future.
	drop(tasks);
	drop(waker);
	drop(wake_read);
	eprintln!(
		"{}",
		json!({"schema":"hepta.directory.original-driver.v1","inputs":inputs,
        "outer_future_drops":drops,"context_cancellations":cancels,"business_owner_unchanged":true})
	);
	Ok(())
}

fn main() -> anyhow::Result<()> {
	let mut snapshot = Vec::new();
	unsafe { std::fs::File::from_raw_fd(4) }
		.take((8 << 20) + 33)
		.read_to_end(&mut snapshot)?;
	ensure!(snapshot.len() >= 32 && &snapshot[..8] == b"HMDINIT1");
	let mode = word(&snapshot, 8);
	let present = word(&snapshot, 16);
	let n = word(&snapshot, 24) as usize;
	ensure!(mode <= 1 && present <= 1 && n <= 8 << 20 && n + 32 == snapshot.len());
	ensure!(present == 1 || n == 0);
	let legacy: Option<ClientCapabilities> = if present == 1 {
		Some(serde_json::from_slice(&snapshot[32..])?)
	} else {
		None
	};
	let args: Vec<_> = std::env::args_os().collect();
	let root = match args.len() {
		3 => {
			ensure!(args[1] == "--session-root");
			PathBuf::from(&args[2])
		}
		5 => {
			ensure!(args[1] == "--runtime-config" && args[3] == "--session-root");
			if let Err(error) = runtime::config::RuntimeConfig::load(Path::new(&args[2]))
				.and_then(runtime::config::init_runtime)
			{
				eprintln!("{error}");
				std::process::exit(78);
			}
			PathBuf::from(&args[4])
		}
		_ => bail!("qualification startup arguments"),
	};
	let state = Arc::new(OctofsServer {
		workdir: Arc::new(SessionWorkdir::new(root)),
		session_applied: Arc::new(AtomicBool::new(false)),
		view_cache: Arc::new(fs::delta::ViewCache),
	});
	let rt = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?;
	let (mut running, _client, startup) = if mode == 0 && legacy.is_none() {
		let (server, client) = tokio::io::duplex(4096);
		let enter = rt.enter();
		let running =
			rmcp::service::serve_directly::<RoleServer, _, _, _, _>(NullServer, server, None);
		drop(enter);
		(
			running,
			client,
			json!({"legacy_absent":"actual serve_directly with None peer_info"}),
		)
	} else {
		rt.block_on(async {
			tokio::time::timeout(std::time::Duration::from_secs(5), bootstrap(mode == 1)).await?
		})?
	};
	if let Some(capabilities) = legacy {
		let info = serde_json::from_value(
			json!({"protocolVersion":"2025-11-25","capabilities":capabilities,
            "clientInfo":{"name":"hia-context-reference","version":"1"}}),
		)?;
		running.peer().set_peer_info(info);
	}
	eprintln!(
		"{}",
		json!({"schema":"hepta.directory.actual-sdk-bootstrap.v1","startup":startup,"mode":mode,"legacy_present":present})
	);
	let enter = rt.enter();
	let result = driver(state, running.peer().clone());
	drop(enter);
	rt.block_on(running.close())?;
	drop(rt);
	result.context("private lifecycle driver")
}
