// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Observe actual locked SDK byte transport parsing and ignore behavior.
#![allow(deprecated)]
use rmcp::{
	model::ClientJsonRpcMessage,
	transport::{async_rw::AsyncRwTransport, Transport},
	RoleServer,
};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn hex(raw: &str) -> anyhow::Result<Vec<u8>> {
	anyhow::ensure!(raw.len() % 2 == 0, "odd hex");
	raw.as_bytes()
		.chunks_exact(2)
		.map(|p| Ok(u8::from_str_radix(std::str::from_utf8(p)?, 16)?))
		.collect()
}
async fn observe(input: Value) -> anyhow::Result<Value> {
	let raw = hex(input["hex"].as_str().unwrap())?;
	let (server, client) = tokio::io::duplex(65536);
	let (server_r, server_w) = tokio::io::split(server);
	let (mut client_r, mut client_w) = tokio::io::split(client);
	let receiving = tokio::spawn(async move {
		let mut transport = AsyncRwTransport::<RoleServer, _, _>::new(server_r, server_w);
		let mut messages = Vec::new();
		while let Some(message) = transport.receive().await {
			let kind = match &message {
				ClientJsonRpcMessage::Request(_) => "request",
				ClientJsonRpcMessage::Response(_) => "response",
				ClientJsonRpcMessage::Notification(_) => "notification",
				ClientJsonRpcMessage::Error(_) => "error",
			};
			messages.push(
				json!({"kind":kind,"message":message,"wire":serde_json::to_string(&message)?}),
			);
		}
		transport.close().await?;
		Ok::<_, anyhow::Error>(messages)
	});
	let sending = tokio::spawn(async move {
		client_w.write_all(&raw).await?;
		client_w.shutdown().await?;
		Ok::<_, anyhow::Error>(())
	});
	let mut reply = Vec::new();
	tokio::time::timeout(
		std::time::Duration::from_secs(3),
		client_r.read_to_end(&mut reply),
	)
	.await??;
	sending.await??;
	let messages = receiving.await??;
	Ok(
		json!({"label":input["label"],"messages":messages,"response_hex":reply.iter().map(|b|format!("{b:02x}")).collect::<String>(),"response_raw":String::from_utf8(reply)?}),
	)
}
fn main() -> anyhow::Result<()> {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?;
	let mut out = std::io::stdout().lock();
	for line in std::io::stdin().lock().lines() {
		let input: Value = serde_json::from_str(&line?)?;
		let result = runtime.block_on(observe(input))?;
		serde_json::to_writer(&mut out, &result)?;
		out.write_all(b"\n")?;
		out.flush()?;
	}
	Ok(())
}
