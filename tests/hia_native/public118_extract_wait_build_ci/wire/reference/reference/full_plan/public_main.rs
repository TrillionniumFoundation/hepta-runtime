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
//! Test-owned byte transport around the unchanged Bellman method and rmcp 3.9.
//! The complete target audit/router and concurrent cancellation registry are
//! outside this serial reference; their qualification cannot be inferred here.
#![allow(deprecated)]

use anyhow::{anyhow, bail, Result};
use rmcp::handler::server::tool::{AsyncMethodAdapter, ToolCallContext};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
	CallToolRequestParams, CallToolResponse, ExperimentalCapabilities, Implementation, JsonObject,
	ProtocolVersion, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{
	AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf,
};

#[path = "../weight_bellman.rs"]
mod weight_bellman;

const CLAUDE_CHANNEL_CAPABILITY: &str = "claude/channel";

#[derive(Default)]
struct Counts {
	dispatch: AtomicU64,
	started: AtomicU64,
	completed: AtomicU64,
}

#[derive(Clone)]
struct OctofsServer {
	counts: Arc<Counts>,
}

include!("original_methods.inc");
include!("original_get_info.inc");

impl OctofsServer {
	fn sdk_bellman(
		&self,
		params: Parameters<weight_bellman::BellmanPlanParams>,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
		self.counts.started.fetch_add(1, Ordering::SeqCst);
		Box::pin(async move {
			let value = self.weight_bellman_plan(params).await;
			self.counts.completed.fetch_add(1, Ordering::SeqCst);
			value
		})
	}
}

impl ServerHandler for OctofsServer {
	fn get_info(&self) -> ServerConfig {
		OriginalInfo::get_info(self)
	}

	async fn call_tool(
		&self,
		request: CallToolRequestParams,
		context: RequestContext<RoleServer>,
	) -> Result<CallToolResponse, ErrorData> {
		self.counts.dispatch.fetch_add(1, Ordering::SeqCst);
		if request.name.as_ref() != "weight_bellman_plan" {
			return Err(ErrorData::invalid_params("tool outside the declared fixture domain", None));
		}
		ToolCallContext::new(self, request, context)
			.invoke::<
				_,
				AsyncMethodAdapter<(Parameters<weight_bellman::BellmanPlanParams>,), Result<String, String>>,
			>(Self::sdk_bellman)
			.await
	}
}

fn clock_ns() -> Result<u64> {
	let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
	let code = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
	if code != 0 || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
		bail!("invalid actual monotonic clock");
	}
	u64::try_from(value.tv_sec)?
		.checked_mul(1_000_000_000)
		.and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
		.ok_or_else(|| anyhow!("monotonic clock overflow"))
}

fn word(raw: &[u8], offset: usize) -> Result<u64> {
	let bytes = raw.get(offset..offset + 8).ok_or_else(|| anyhow!("short fixture word"))?;
	Ok(u64::from_le_bytes(bytes.try_into()?))
}

struct WireSession {
	reader: BufReader<ReadHalf<DuplexStream>>,
	writer: WriteHalf<DuplexStream>,
	task: tokio::task::JoinHandle<Result<(), String>>,
}

impl WireSession {
	fn start(server: OctofsServer) -> Self {
		let (client, transport) = tokio::io::duplex(65_536);
		let task = tokio::spawn(async move {
			let running = server.serve(transport).await.map_err(|error| error.to_string())?;
			running.waiting().await.map(|_| ()).map_err(|error| format!("{error:?}"))
		});
		let (input, writer) = tokio::io::split(client);
		Self { reader: BufReader::new(input), writer, task }
	}

	async fn exchange(&mut self, wire: &[u8], frames: u64) -> Result<Vec<u8>> {
		self.writer.write_all(wire).await?;
		let mut output = Vec::new();
		for _ in 0..frames {
			let mut line = Vec::new();
			let count = self.reader.read_until(b'\n', &mut line).await?;
			if count == 0 || line.last() != Some(&b'\n') {
				bail!("SDK response ended before its complete line");
			}
			output.extend_from_slice(&line);
		}
		tokio::task::yield_now().await;
		Ok(output)
	}

	async fn close(mut self) -> Result<Vec<u8>> {
		self.writer.shutdown().await?;
		drop(self.writer);
		let mut remaining = Vec::new();
		self.reader.read_to_end(&mut remaining).await?;
		drop(self.reader);
		self.task.await?.map_err(anyhow::Error::msg)?;
		Ok(remaining)
	}
}

fn main() -> Result<()> {
	let executor = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
	let servers: [OctofsServer; 2] = std::array::from_fn(|_| OctofsServer { counts: Arc::default() });
	let mut sessions = executor.block_on(async {
		servers.iter().cloned().map(|server| Some(WireSession::start(server))).collect::<Vec<_>>()
	});
	let mut input = std::io::BufReader::new(std::io::stdin().lock());
	let mut output = std::io::BufWriter::new(std::io::stdout().lock());
	let mut sequence = 0_u64;
	loop {
		let mut header = [0_u8; 64];
		if input.read(&mut header[..1])? == 0 { break; }
		input.read_exact(&mut header[1..])?;
		let opcode = word(&header, 16)?;
		let session = usize::try_from(word(&header, 24)?)?;
		let length = usize::try_from(word(&header, 32)?)?;
		let frames = word(&header, 40)?;
		if &header[..8] != b"HBPOREQ1" || word(&header, 8)? != sequence || session > 1
			|| word(&header, 48)? != 0 || word(&header, 56)? != 0 || length > 64 * 1024 * 1024
			|| frames > 2 {
			bail!("fixture input outside its fixed envelope");
		}
		let mut wire = vec![0_u8; length];
		input.read_exact(&mut wire)?;
		let before = clock_ns()?;
		let bytes = match opcode {
			1 => {
				let active = sessions[session].as_mut().ok_or_else(|| anyhow!("wire after close"))?;
				executor.block_on(async {
					tokio::time::timeout(Duration::from_secs(60), active.exchange(&wire, frames)).await?
				})?
			}
			2 => {
				if length != 0 || frames != 0 { bail!("close fixture has a payload"); }
				let active = sessions[session].take().ok_or_else(|| anyhow!("duplicate close"))?;
				executor.block_on(async {
					tokio::time::timeout(Duration::from_secs(60), active.close()).await?
				})?
			}
			_ => bail!("unknown fixture opcode"),
		};
		let after = clock_ns()?;
		let counts = &servers[session].counts;
		output.write_all(b"HBPORES1")?;
		for value in [sequence, opcode, session as u64, length as u64, bytes.len() as u64,
			before, after, counts.dispatch.load(Ordering::SeqCst),
			counts.started.load(Ordering::SeqCst), counts.completed.load(Ordering::SeqCst), 0] {
			output.write_all(&value.to_le_bytes())?;
		}
		output.write_all(&bytes)?;
		output.flush()?;
		sequence += 1;
	}
	if sessions.iter().any(Option::is_some) { bail!("fixture ended before both normal closes"); }
	Ok(())
}
