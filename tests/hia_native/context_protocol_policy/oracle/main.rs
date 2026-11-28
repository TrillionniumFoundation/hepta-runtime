// Copyright 2026 Muvon Un Limited
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

//! Only the resolved Option<ProtocolVersion> boundary is qualified here.
#![allow(deprecated)]
use rmcp::{
	model::{ProtocolVersion, RequestId},
	service::RequestContext,
	RoleServer,
};
use std::io::{Read, Write};

#[derive(Clone)]
struct NullServer;
impl rmcp::ServerHandler for NullServer {}

// Both definitions are exact byte slices of the pinned current target server.
include!("original_policy.rs");

fn word(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

async fn replay() -> anyhow::Result<()> {
	let (transport, peer_transport) = tokio::io::duplex(4096);
	let mut running = rmcp::service::serve_directly::<RoleServer, _, _, _, _>(NullServer, transport, None);
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	let mut observations = std::io::stderr().lock();
	let mut count = 0u64;
	loop {
		let mut header = [0u8; 8];
		if input.read(&mut header[..1])? == 0 { break; }
		input.read_exact(&mut header[1..])?;
		let size: usize = u64::from_le_bytes(header).try_into()?;
		anyhow::ensure!((32..=(16 << 20)).contains(&size), "frame capacity");
		let mut raw = vec![0u8; size];
		input.read_exact(&mut raw)?;
		anyhow::ensure!(&raw[..8] == b"HCPOLQ01" && word(&raw, 8) == 1);
		let present = word(&raw, 16);
		anyhow::ensure!(present <= 1 && word(&raw, 24) == (size - 32) as u64);
		anyhow::ensure!(present == 1 || size == 32);
		let version = std::str::from_utf8(&raw[32..])?;
		let resolved: Option<ProtocolVersion> = if present == 1 {
			Some(serde_json::from_value(serde_json::Value::String(version.to_owned()))?)
		} else { None };
		let mut context = RequestContext::new(RequestId::Number(count as i64), running.peer().clone());
		if let Some(value) = resolved.clone() { context.meta.set_protocol_version(value); }
		let actual = context.protocol_version();
		anyhow::ensure!(actual == resolved, "actual RequestContext resolution differs from the admitted input at {count}");
		let actual_json = actual.as_ref().map(serde_json::to_value).transpose()?;
		let actual_bytes = match actual_json.as_ref() {
			Some(serde_json::Value::String(value)) => value.as_bytes(),
			None => b"",
			_ => anyhow::bail!("ProtocolVersion serialization is not a string"),
		};
		observations.write_all(b"HCPCTX01")?;
		for value in [count, actual.is_some() as u64, actual_bytes.len() as u64] {
			observations.write_all(&value.to_le_bytes())?;
		}
		observations.write_all(actual_bytes)?;
		// Do not substitute a host comparison for either unchanged target call.
		let cache = supports_cache_hints(&context);
		let unsolicited = allows_unsolicited_notifications(&context);
		let mut result = b"HCPOLS01".to_vec();
		for value in [actual.is_some() as u64, cache as u64, unsolicited as u64] {
			result.extend_from_slice(&value.to_le_bytes());
		}
		output.write_all(&(result.len() as u64).to_le_bytes())?;
		output.write_all(&result)?;
		count += 1;
	}
	output.flush()?;
	running.close().await?;
	drop(peer_transport);
	observations.write_all(b"HCPCEND1")?;
	for value in [count, std::process::id() as u64, 1u64] {
		observations.write_all(&value.to_le_bytes())?;
	}
	observations.flush()?;
	Ok(())
}

fn main() -> anyhow::Result<()> {
	tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(replay())
}
