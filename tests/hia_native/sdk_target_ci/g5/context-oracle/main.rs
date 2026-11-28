// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Access-only fixture for actual SDK capability decoding and context selection.
#![allow(deprecated)]
use rmcp::{
	model::{ClientCapabilities, RequestId},
	service::{RequestContext, RunningService},
	RoleServer, ServiceExt,
};
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

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

fn type_probe() -> anyhow::Result<()> {
	let input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	for line in input.lines() {
		let raw = line?;
		let value: Value = serde_json::from_str(&raw)?;
		let result = match serde_json::from_value::<ClientCapabilities>(value) {
			Ok(capabilities) => json!({"ok":true,"supports_tasks":capabilities.supports_tasks(),"value":capabilities}),
			Err(error) => json!({"ok":false,"error":error.to_string()}),
		};
		serde_json::to_writer(&mut output, &result)?;
		output.write_all(b"\n")?;
	}
	Ok(())
}

async fn compare_frames() -> anyhow::Result<()> {
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
		anyhow::ensure!((40..=(16 << 20) + 40).contains(&size));
		let mut raw = vec![0; size];
		input.read_exact(&mut raw)?;
		anyhow::ensure!(&raw[..8] == b"HRCMCQ02");
		let mode = word(&raw, 8);
		let legacy_present = word(&raw, 16);
		let meta_len = word(&raw, 24) as usize;
		let legacy_len = word(&raw, 32) as usize;
		anyhow::ensure!(mode <= 1 && legacy_present <= 1);
		anyhow::ensure!(meta_len <= 8 << 20 && legacy_len <= 8 << 20);
		anyhow::ensure!(meta_len + legacy_len + 40 == size);
		anyhow::ensure!(legacy_present == 1 || legacy_len == 0);
		let peer = match (mode, legacy_present) {
			(0, 0) => legacy_absent.peer(),
			(0, 1) => legacy.peer(),
			(1, 0) => modern_absent.peer(),
			(1, 1) => modern_present.peer(),
			_ => unreachable!(),
		};
		if legacy_present == 1 {
			let value: Value = serde_json::from_slice(&raw[40 + meta_len..])?;
			let capabilities: ClientCapabilities = serde_json::from_value(value)?;
			let info = serde_json::from_value(json!({
				"protocolVersion":"2025-11-25","capabilities":capabilities,
				"clientInfo":{"name":"hia-context-reference","version":"1"}
			}))?;
			peer.set_peer_info(info);
		}
		let mut context = RequestContext::new(RequestId::Number(0), peer.clone());
		context.meta = serde_json::from_slice(&raw[40..40 + meta_len])?;
		let resolved = context.client_capabilities();
		let experimental = resolved
			.as_ref()
			.and_then(|value| value.experimental.as_ref());
		let payload = experimental.map(serde_json::to_vec).transpose()?;
		let mut response = b"HRCMPR02".to_vec();
		for value in [
			resolved.is_some() as u64,
			experimental.is_some() as u64,
			payload.as_ref().map_or(0, |bytes| bytes.len()) as u64,
		] {
			response.extend_from_slice(&value.to_le_bytes());
		}
		if let Some(bytes) = payload {
			response.extend_from_slice(&bytes);
		}
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
	if std::env::args().nth(1).as_deref() == Some("--types") {
		return type_probe();
	}
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?
		.block_on(compare_frames())
}
