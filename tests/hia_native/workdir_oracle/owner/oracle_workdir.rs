// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Actual SDK and unchanged public workdir method qualification driver.
pub mod mcp;
pub mod utils;

use mcp::{fs, runtime, McpToolCall};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{
	model::{ClientCapabilities, RequestId},
	service::{RequestContext, RunningService},
	RoleServer, ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tracing::debug;

struct OctofsServer {
	workdir: Arc<SessionWorkdir>,
	session_applied: Arc<AtomicBool>,
}

include!("generated_session_owner.rs");
include!("generated_workdir_owner.rs");

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
		anyhow::ensure!(response.len() <= 16384, "bootstrap response capacity");
		if byte == b'\n' {
			break;
		}
	}
	let response: Value = serde_json::from_slice(&response)?;
	anyhow::ensure!(response["id"] == 1, "bootstrap response id");
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
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

async fn compare_session_frames(state: OctofsServer) -> anyhow::Result<()> {
	let (mut legacy, _legacy_client, legacy_bootstrap) =
		tokio::time::timeout(std::time::Duration::from_secs(5), bootstrap(false)).await??;
	let (mut modern_absent, _modern_absent_client, modern_absent_bootstrap) =
		tokio::time::timeout(std::time::Duration::from_secs(5), bootstrap(true)).await??;
	let (mut modern_present, _modern_present_client, modern_present_bootstrap) =
		tokio::time::timeout(std::time::Duration::from_secs(5), bootstrap(true)).await??;
	let (direct, _direct_client) = tokio::io::duplex(4096);
	let mut legacy_absent =
		rmcp::service::serve_directly::<RoleServer, _, _, _, _>(NullServer, direct, None);
	let info = serde_json::from_value(json!({
		"protocolVersion":"2025-11-25","capabilities":{},
		"clientInfo":{"name":"hia-context-reference","version":"1"}
	}))?;
	modern_present.peer().set_peer_info(info);
	anyhow::ensure!(
		RequestContext::new(RequestId::Number(0), legacy.peer().clone())
			.client_capabilities()
			.is_some()
	);
	for peer in [
		modern_absent.peer(),
		modern_present.peer(),
		legacy_absent.peer(),
	] {
		anyhow::ensure!(RequestContext::new(RequestId::Number(0), peer.clone())
			.client_capabilities()
			.is_none());
	}
	eprintln!(
		"{}",
		json!({
			"schema":"hepta.client-context.actual-sdk-bootstrap.v1",
			"bootstraps":[legacy_bootstrap,modern_absent_bootstrap,modern_present_bootstrap],
			"legacy_absent":"actual serve_directly with None peer_info",
			"modern_peer_info_does_not_enable_fallback":true
		})
	);
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	loop {
		let mut header = [0; 8];
		if input.read(&mut header[..1])? == 0 {
			break;
		}
		input.read_exact(&mut header[1..])?;
		let size = u64::from_le_bytes(header) as usize;
		anyhow::ensure!((64..=(24 << 20) + 64).contains(&size));
		let mut raw = vec![0; size];
		input.read_exact(&mut raw)?;
		anyhow::ensure!(&raw[..8] == b"HMWDRQ01");
		let command = word(&raw, 8);
		let mode = word(&raw, 16);
		let present = word(&raw, 24);
		let meta_len = word(&raw, 32) as usize;
		let legacy_len = word(&raw, 40) as usize;
		let params_len = word(&raw, 48) as usize;
		anyhow::ensure!(command <= 3 && mode <= 1 && present <= 1 && word(&raw, 56) == 0);
		anyhow::ensure!(meta_len <= 8 << 20 && legacy_len <= 8 << 20 && params_len <= 8 << 20);
		anyhow::ensure!(64 + meta_len + legacy_len + params_len == size);
		anyhow::ensure!(present == 1 || legacy_len == 0);
		let params_at = 64 + meta_len + legacy_len;
		let value: Value = serde_json::from_slice(&raw[params_at..])?;
		let mut normalized = Vec::new();
		let (tag, result) = if command == 0 {
			match serde_json::from_value::<WorkdirParams>(value) {
				Ok(params) => {
					normalized = serde_json::to_vec(&params)?;
					(0_u64, String::new())
				}
				Err(error) => (2_u64, error.to_string()),
			}
		} else if command == 3 {
			(0_u64, String::new())
		} else if command == 2 {
			let call = McpToolCall {
				tool_name: "workdir".to_owned(),
				parameters: value,
				tool_id: String::new(),
				workdir: state.workdir.get_current(),
			};
			match fs::execute_workdir_command(&call).await {
				Ok(value) => (0_u64, value.to_json_string()),
				Err(error) => (1_u64, error.to_string()),
			}
		} else {
			match serde_json::from_value::<WorkdirParams>(value) {
				Err(error) => (2_u64, error.to_string()),
				Ok(params) => {
					normalized = serde_json::to_vec(&params)?;
					let peer = match (mode, present) {
						(0, 0) => legacy_absent.peer(),
						(0, 1) => legacy.peer(),
						(1, 0) => modern_absent.peer(),
						(1, 1) => modern_present.peer(),
						_ => unreachable!(),
					};
					if present == 1 {
						let value: Value = serde_json::from_slice(&raw[64 + meta_len..params_at])?;
						let capabilities: ClientCapabilities = serde_json::from_value(value)?;
						let info = serde_json::from_value(json!({
							"protocolVersion":"2025-11-25", "capabilities":capabilities,
							"clientInfo":{"name":"hia-context-reference","version":"1"}
						}))?;
						peer.set_peer_info(info);
					}
					let mut context = RequestContext::new(RequestId::Number(0), peer.clone());
					context.meta = serde_json::from_slice(&raw[64..64 + meta_len])?;
					match state.workdir(context, Parameters(params)).await {
						Ok(text) => (0_u64, text),
						Err(text) => (1_u64, text),
					}
				}
			}
		};
		let current = state.workdir.get_current();
		let bytes = current.as_os_str().as_bytes();
		let mut response = b"HMWDRS01".to_vec();
		for number in [
			tag,
			state
				.session_applied
				.load(std::sync::atomic::Ordering::SeqCst) as u64,
			bytes.len() as u64,
			result.len() as u64,
			normalized.len() as u64,
			0,
		] {
			response.extend_from_slice(&number.to_le_bytes());
		}
		response.extend_from_slice(bytes);
		response.extend_from_slice(result.as_bytes());
		response.extend_from_slice(&normalized);
		output.write_all(&(response.len() as u64).to_le_bytes())?;
		output.write_all(&response)?;
		output.flush()?;
	}

	legacy.close().await?;
	modern_absent.close().await?;
	modern_present.close().await?;
	legacy_absent.close().await?;
	Ok(())
}

fn main() -> anyhow::Result<()> {
	let args: Vec<_> = std::env::args_os().collect();
	let root = match args.len() {
		3 => {
			assert_eq!(args[1], "--session-root");
			PathBuf::from(&args[2])
		}
		5 => {
			assert_eq!(args[1], "--runtime-config");
			assert_eq!(args[3], "--session-root");
			let loaded = runtime::config::RuntimeConfig::load(Path::new(&args[2]))
				.and_then(runtime::config::init_runtime);
			if let Err(error) = loaded {
				eprintln!("{error}");
				std::process::exit(78);
			}
			PathBuf::from(&args[4])
		}
		_ => anyhow::bail!("qualification startup arguments"),
	};
	let state = OctofsServer {
		workdir: Arc::new(SessionWorkdir::new(root)),
		session_applied: Arc::new(AtomicBool::new(false)),
	};
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?
		.block_on(compare_session_frames(state))
}
