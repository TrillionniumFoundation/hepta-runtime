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

//! Observe the unchanged current get_info through the actual RMCP serve lifecycle.
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

#[derive(Clone)]
struct ReferenceServer;
include!("generated_get_info.rs");

fn record(trace: &Arc<Mutex<Vec<Value>>>, event: Value) -> Result<(), ErrorData> {
	trace
		.lock()
		.map_err(|_| ErrorData::internal_error("fixture trace lock poisoned", None))?
		.push(event);
	Ok(())
}

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
			"capabilities":context.client_capabilities(),"client_info":context.client_info(),
			"peer_info":peer.peer_info(),"supports_cache_hints":supports_cache_hints(&context),
			"allows_unsolicited_notifications":allows_unsolicited_notifications(&context)});
		let reply = <ReferenceServer as Service<RoleServer>>::handle_request(
			&self.inner, request, context,
		).await;
		let result = match &reply {
			Ok(value) => json!({"ok":value}),
			Err(error) => json!({"error":error}),
		};
		record(&self.trace, json!({"before":before,"result":result,
			"peer_info_after":peer.peer_info()}))?;
		reply
	}

	async fn handle_notification(
		&self,
		notification: ClientNotification,
		context: NotificationContext<RoleServer>,
	) -> Result<(), ErrorData> {
		record(&self.trace, json!({"notification":notification,"meta":context.meta,
			"peer_info":context.peer.peer_info()}))?;
		<ReferenceServer as Service<RoleServer>>::handle_notification(
			&self.inner, notification, context,
		).await
	}

	fn get_info(&self) -> ServerConfig {
		ServerHandler::get_info(&self.inner)
	}

	fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
		ServerHandler::supported_protocol_versions(&self.inner)
	}
}

async fn response_line(client: &mut DuplexStream) -> anyhow::Result<Vec<u8>> {
	let mut raw = Vec::new();
	loop {
		let mut byte = [0];
		anyhow::ensure!(client.read(&mut byte).await? == 1, "expected normal response line");
		raw.push(byte[0]);
		anyhow::ensure!(raw.len() <= 65536, "normal response capacity");
		if byte[0] == b'\n' {
			return Ok(raw);
		}
	}
}

async fn observe(case: Value) -> anyhow::Result<Value> {
	let trace = Arc::new(Mutex::new(Vec::new()));
	let peer_after_handshake = Arc::new(Mutex::new(None::<Value>));
	let peer_observed = peer_after_handshake.clone();
	let fixed_info_wire = serde_json::to_string(&ServerHandler::get_info(&ReferenceServer))?;
	let supported_versions = ServerHandler::supported_protocol_versions(&ReferenceServer);
	let recorder = Recorder { inner: ReferenceServer, trace: trace.clone() };
	let (mut client, server) = tokio::io::duplex(65536);
	let mut task = tokio::spawn(async move {
		let terminal = match recorder.serve(server).await {
			Ok(running) => {
				let actual_peer = serde_json::to_value(running.peer().peer_info())?;
				*peer_observed.lock().map_err(|_| anyhow::anyhow!("fixture peer lock poisoned"))? =
					Some(actual_peer);
				match running.waiting().await {
					Ok(reason) => json!({"phase":"running","quit":format!("{reason:?}")}),
					Err(error) => json!({"phase":"running","join_error":error.to_string()}),
				}
			}
			Err(error) => json!({"phase":"startup","error":error.to_string()}),
		};
		Ok::<Value, anyhow::Error>(terminal)
	});
	let mut events = Vec::new();
	for event in case["events"].as_array().context("events array")? {
		let wire = event["wire"].as_str().context("normal wire string")?;
		anyhow::ensure!(!wire.as_bytes().contains(&b'\n'), "one transport line per event");
		let request: Value = serde_json::from_str(wire)?;
		anyhow::ensure!(request["jsonrpc"] == "2.0", "normal JSON-RPC version");
		let mut bytes = wire.as_bytes().to_vec();
		bytes.push(b'\n');
		client.write_all(&bytes).await?;
		if event["response"].as_bool().context("response marker")? {
			let raw = tokio::time::timeout(Duration::from_secs(3), response_line(&mut client)).await??;
			events.push(json!({"wire":wire,"response_raw":String::from_utf8(raw.clone())?,
				"response":serde_json::from_slice::<Value>(&raw)?}));
		} else {
			events.push(json!({"wire":wire,"response_expected":false}));
		}
	}
	client.shutdown().await?;
	drop(client);
	let joined = tokio::time::timeout(Duration::from_secs(3), &mut task).await?;
	let terminal = joined??;
	let observed = trace.lock().map_err(|_| anyhow::anyhow!("fixture trace lock poisoned"))?.clone();
	let negotiated_peer = peer_after_handshake
		.lock().map_err(|_| anyhow::anyhow!("fixture peer lock poisoned"))?.clone();
	Ok(json!({"label":case["label"],"events":events,"trace":observed,"terminal":terminal,
		"negotiated_peer_info":negotiated_peer,"fixed_get_info_wire":fixed_info_wire,
		"supported_protocol_versions":supported_versions}))
}

fn main() -> anyhow::Result<()> {
	let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
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
