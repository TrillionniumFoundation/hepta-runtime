// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Observe actual SDK transport/lifecycle and preflight with unchanged runtime get_info.
#![allow(deprecated)]
use anyhow::Context;
use rmcp::{
	model::{
		ClientNotification, ClientRequest, ExperimentalCapabilities, Implementation, JsonObject,
		ProtocolVersion, ServerCapabilities, ServerConfig, ServerResult,
	},
	service::{NotificationContext, RequestContext},
	ErrorData, RoleServer, ServerHandler, Service, ServiceExt,
};
use serde_json::{json, Value};
use std::{
	borrow::Cow,
	io::{BufRead, Write},
	sync::{Arc, Mutex},
	time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const CLAUDE_CHANNEL_CAPABILITY: &str = "claude/channel";
#[derive(Clone)]
struct ReferenceServer;
include!("generated_get_info.rs");

#[derive(Clone)]
struct Recorder {
	inner: ReferenceServer,
	trace: Arc<Mutex<Vec<Value>>>,
}
impl Service<RoleServer> for Recorder {
	async fn handle_request(
		&self,
		request: ClientRequest,
		context: RequestContext<RoleServer>,
	) -> Result<ServerResult, ErrorData> {
		let peer = context.peer.clone();
		let before = json!({"request":request,"request_id":context.id,
            "metadata":context.meta,"protocol_version":context.protocol_version(),
            "capabilities":context.client_capabilities(),"peer_info":peer.peer_info()});
		let reply =
			<ReferenceServer as Service<RoleServer>>::handle_request(&self.inner, request, context)
				.await;
		let result = match &reply {
			Ok(value) => json!({"ok":value}),
			Err(error) => json!({"error":error}),
		};
		self.trace
			.lock()
			.unwrap()
			.push(json!({"before":before,"result":result,"peer_info_after":peer.peer_info()}));
		reply
	}
	async fn handle_notification(
		&self,
		notification: ClientNotification,
		context: NotificationContext<RoleServer>,
	) -> Result<(), ErrorData> {
		self.trace.lock().unwrap().push(
			json!({"notification":notification,"meta":context.meta,"peer_info":context.peer.peer_info()}),
		);
		<ReferenceServer as Service<RoleServer>>::handle_notification(
			&self.inner,
			notification,
			context,
		)
		.await
	}
	fn get_info(&self) -> ServerConfig {
		ServerHandler::get_info(&self.inner)
	}
	fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
		ServerHandler::supported_protocol_versions(&self.inner)
	}
}

async fn response_line(client: &mut DuplexStream) -> anyhow::Result<Option<Vec<u8>>> {
	let mut raw = Vec::new();
	loop {
		let mut byte = [0];
		if client.read(&mut byte).await? == 0 {
			anyhow::ensure!(raw.is_empty(), "incomplete response line");
			return Ok(None);
		}
		raw.push(byte[0]);
		anyhow::ensure!(raw.len() <= 16 << 20, "response line capacity");
		if byte[0] == b'\n' {
			return Ok(Some(raw));
		}
	}
}

async fn observe(case: Value) -> anyhow::Result<Value> {
	let trace = Arc::new(Mutex::new(Vec::new()));
	let recorder = Recorder {
		inner: ReferenceServer,
		trace: trace.clone(),
	};
	let (mut client, server) = tokio::io::duplex(65536);
	let mut task = tokio::spawn(async move {
		match recorder.serve(server).await {
			Ok(running) => match running.waiting().await {
				Ok(reason) => json!({"phase":"running","quit":format!("{reason:?}")}),
				Err(error) => json!({"phase":"running","join_error":error.to_string()}),
			},
			Err(error) => json!({"phase":"startup","error":error.to_string()}),
		}
	});
	let mut events = Vec::new();
	for event in case["events"].as_array().context("events array")? {
		let wire = event.get("wire").and_then(Value::as_str).unwrap_or("");
		let mut bytes = if let Some(hex) = event.get("wire_hex").and_then(Value::as_str) {
			anyhow::ensure!(hex.len() % 2 == 0, "odd raw hex");
			hex.as_bytes()
				.chunks_exact(2)
				.map(|p| {
					u8::from_str_radix(std::str::from_utf8(p)?, 16).map_err(anyhow::Error::from)
				})
				.collect::<anyhow::Result<Vec<u8>>>()?
		} else {
			wire.as_bytes().to_vec()
		};
		anyhow::ensure!(!bytes.contains(&b'\n'), "one transport line per event");
		if event
			.get("append_lf")
			.and_then(Value::as_bool)
			.unwrap_or(true)
		{
			bytes.push(b'\n');
		}
		if let Err(error) = client.write_all(&bytes).await {
			events.push(
				json!({"wire":wire,"wire_hex":event.get("wire_hex"),"write_error":error.to_string()}),
			);
			break;
		}
		if event["response"].as_bool().context("response marker")? {
			let received =
				tokio::time::timeout(Duration::from_secs(3), response_line(&mut client)).await??;
			match received {
                Some(raw) => events.push(json!({"wire":wire,"wire_hex":event.get("wire_hex"),"response_raw":String::from_utf8(raw.clone())?,"response":serde_json::from_slice::<Value>(&raw)?})),
                None => {events.push(json!({"wire":wire,"wire_hex":event.get("wire_hex"),"eof":true}));break;}
            }
		} else {
			events.push(
				json!({"wire":wire,"wire_hex":event.get("wire_hex"),"response_expected":false}),
			);
		}
	}
	client.shutdown().await?;
	drop(client);
	let terminal = tokio::time::timeout(Duration::from_secs(3), &mut task).await??;
	let observed = trace.lock().unwrap().clone();
	Ok(json!({"label":case["label"],"events":events,"trace":observed,"terminal":terminal}))
}

fn main() -> anyhow::Result<()> {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?;
	let input = std::io::stdin();
	let mut output = std::io::stdout().lock();
	for line in input.lock().lines() {
		let case: Value = serde_json::from_str(&line?)?;
		let result = runtime.block_on(observe(case))?;
		serde_json::to_writer(&mut output, &result)?;
		output.write_all(b"\n")?;
		output.flush()?;
	}
	Ok(())
}
