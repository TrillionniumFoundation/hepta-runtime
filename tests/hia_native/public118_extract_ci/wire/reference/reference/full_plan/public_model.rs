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
//! Independent actual SDK model boundary followed by the unchanged plan.
//! Root arguments are the SDK's JsonObject, preserving its distinction from
//! directly parsing a generic serde_json::Value with the RawValue feature.

use anyhow::{anyhow, bail, Result};
use rmcp::handler::server::tool::parse_json_object;
use rmcp::model::{ClientJsonRpcMessage, ClientRequest};
use std::io::{Read, Write};

#[path = "../weight_bellman.rs"]
mod original;

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

fn main() -> Result<()> {
	let executor = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
	let mut input = std::io::BufReader::new(std::io::stdin().lock());
	let mut output = std::io::BufWriter::new(std::io::stdout().lock());
	let mut sequence = 0_u64;
	loop {
		let mut header = [0_u8; 64];
		if input.read(&mut header[..1])? == 0 { break; }
		input.read_exact(&mut header[1..])?;
		let opcode = word(&header, 16)?;
		let session = word(&header, 24)?;
		let length = usize::try_from(word(&header, 32)?)?;
		if &header[..8] != b"HBPOREQ1" || word(&header, 8)? != sequence || session > 1
			|| word(&header, 48)? != 0 || word(&header, 56)? != 0 || length > 64 * 1024 * 1024
			|| word(&header, 40)? > 2 || !matches!(opcode, 1 | 2) {
			bail!("fixture input outside its fixed envelope");
		}
		let mut wire = vec![0_u8; length];
		input.read_exact(&mut wire)?;
		let before = clock_ns()?;
		let mut canonical = Vec::new();
		let mut kind = 0_u64;
		let mut status = 3_u64;
		let mut text = String::new();
		if let Ok(ClientJsonRpcMessage::Request(request)) =
			serde_json::from_slice::<ClientJsonRpcMessage>(&wire)
		{
			match request.request {
				ClientRequest::CallToolRequest(call) if call.params.name.as_ref() == "weight_bellman_plan" => {
					kind = 1;
					let arguments = call.params.arguments.unwrap_or_default();
					canonical = serde_json::to_vec(&arguments)?;
					(status, text) = match parse_json_object::<original::BellmanPlanParams>(arguments) {
						Ok(params) => match executor.block_on(original::plan(params)) {
							Ok(value) => (0, value),
							Err(error) => (2, error.to_string()),
						},
						Err(error) => (1, error.message.to_string()),
					};
				}
				ClientRequest::CustomRequest(request) if request.method == "tools/call" => {
					kind = 2;
					text = request.method;
				}
				_ => {}
			}
		}
		let after = clock_ns()?;
		output.write_all(b"HBPMOR01")?;
		for value in [sequence, opcode, session, kind, status, canonical.len() as u64,
			text.len() as u64, before, after, 0, 0] {
			output.write_all(&value.to_le_bytes())?;
		}
		output.write_all(&canonical)?;
		output.write_all(text.as_bytes())?;
		output.flush()?;
		sequence += 1;
	}
	Ok(())
}
