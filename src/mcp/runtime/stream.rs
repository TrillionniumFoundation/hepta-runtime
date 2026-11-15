// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Controller-local cooperative stream adoption owned independently of MCP lifetime.
use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::config::runtime_config;

const SOURCE: &str = include_str!("stream_broker.py");
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_RESULT_BYTES: usize = 256 * 1024;
const MAX_INPUT_B64: usize = 90 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamPrepareParams {
	/// Reuse exactly this key after an uncertain prepare acknowledgement.
	pub idempotency_key: String,
	/// First PID is the application leader. Additional entries must be its descendants.
	pub application_pids: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamRefParams {
	pub session_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StreamName {
	Stdout,
	Stderr,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamReadParams {
	pub session_id: String,
	#[serde(default = "default_stdout")]
	pub stream: StreamName,
	#[serde(default)]
	pub offset: Option<u64>,
	/// Preferred byte count, bounded to 16 KiB.
	#[serde(default)]
	pub limit: Option<usize>,
}

fn default_stdout() -> StreamName {
	StreamName::Stdout
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamWriteParams {
	pub session_id: String,
	/// Mandatory retry identity. Reuse only with the identical byte payload.
	pub request_id: String,
	/// Exact bytes encoded as base64, at most 64 KiB decoded.
	pub data_base64: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamListParams {
	#[serde(default)]
	pub limit: Option<usize>,
}

fn session_id(key: &str) -> Result<String> {
	if key.is_empty() || key.len() > 256 {
		bail!("stream idempotency key must contain 1..256 bytes");
	}
	Ok(format!(
		"stream-{}",
		Sha256::digest(key.as_bytes())
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect::<String>()
	))
}

fn valid_session(id: &str) -> bool {
	id.len() == 71
		&& id.starts_with("stream-")
		&& id[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn invoke(mut input: Value) -> Result<Value> {
	let config = runtime_config()?;
	input["state_dir"] = json!(config.state_dir);
	let body = serde_json::to_vec(&input)?;
	if body.len() > MAX_REQUEST_BYTES {
		bail!("stream request exceeds 128 KiB");
	}
	let source = serde_json::to_string(SOURCE)?;
	let code = format!(
        "HEPTA_HELPER_SOURCE = {source}\nexec(compile(HEPTA_HELPER_SOURCE,'stream_broker.py','exec'))"
    );
	let mut command = Command::new("/usr/bin/python3");
	command
		.args(["-I", "-c", &code])
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	let mut child = command.spawn()?;
	let mut stdin = child
		.stdin
		.take()
		.ok_or_else(|| anyhow!("missing stream helper stdin"))?;
	stdin.write_all(&body).await?;
	stdin.shutdown().await?;
	drop(stdin);
	let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
		.await
		.context("stream helper timed out")??;
	if !output.status.success() {
		let detail = String::from_utf8_lossy(&output.stderr);
		bail!(
			"stream helper failed: {}",
			detail.chars().take(2000).collect::<String>()
		);
	}
	if output.stdout.len() > MAX_RESULT_BYTES {
		bail!("stream helper result exceeds 256 KiB");
	}
	Ok(serde_json::from_slice(&output.stdout)?)
}

pub async fn prepare(params: StreamPrepareParams) -> Result<String> {
	if params.application_pids.is_empty()
		|| params.application_pids.len() > 64
		|| params.application_pids.iter().any(|pid| *pid <= 1)
	{
		bail!("stream prepare requires 1..64 positive non-system application PIDs");
	}
	let id = session_id(&params.idempotency_key)?;
	super::jobs::audit(
		"stream_handoff_prepare",
		"controller",
		&id,
		&json!({"application_pid_count": params.application_pids.len()}),
	)?;
	let value = invoke(json!({
		"op": "prepare",
		"session_id": id,
		"application_pids": params.application_pids
	}))
	.await?;
	Ok(serde_json::to_string(&value)?)
}

pub async fn status(params: StreamRefParams) -> Result<String> {
	if !valid_session(&params.session_id) {
		bail!("invalid stream session identity");
	}
	let value = invoke(json!({"op":"status","session_id":params.session_id})).await?;
	Ok(serde_json::to_string(&value)?)
}

pub async fn read(params: StreamReadParams) -> Result<String> {
	if !valid_session(&params.session_id) {
		bail!("invalid stream session identity");
	}
	let stream = match params.stream {
		StreamName::Stdout => "stdout",
		StreamName::Stderr => "stderr",
	};
	let value = invoke(json!({
		"op":"read",
		"session_id":params.session_id,
		"stream":stream,
		"offset":params.offset,
		"limit":params.limit.unwrap_or(16 * 1024).clamp(1, 16 * 1024)
	}))
	.await?;
	Ok(serde_json::to_string(&value)?)
}

pub async fn write(params: StreamWriteParams) -> Result<String> {
	if !valid_session(&params.session_id)
		|| params.request_id.len() < 8
		|| params.request_id.len() > 128
		|| !params
			.request_id
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
	{
		bail!("invalid stream or request identity");
	}
	if params.data_base64.len() > MAX_INPUT_B64 {
		bail!("stream input exceeds bounded base64 request size");
	}
	super::jobs::audit(
		"stream_handoff_write",
		"controller",
		&params.session_id,
		&json!({"base64_chars":params.data_base64.len(),"request_id_present":true}),
	)?;
	let value = invoke(json!({
		"op":"write",
		"session_id":params.session_id,
		"request_id":params.request_id,
		"data_base64":params.data_base64
	}))
	.await?;
	Ok(serde_json::to_string(&value)?)
}

pub async fn close(params: StreamRefParams) -> Result<String> {
	if !valid_session(&params.session_id) {
		bail!("invalid stream session identity");
	}
	super::jobs::audit(
		"stream_handoff_close",
		"controller",
		&params.session_id,
		&json!({"input_close_only":true}),
	)?;
	let value = invoke(json!({"op":"close","session_id":params.session_id})).await?;
	Ok(serde_json::to_string(&value)?)
}

pub async fn list(params: StreamListParams) -> Result<String> {
	let value =
		invoke(json!({"op":"list","limit":params.limit.unwrap_or(64).clamp(1,128)})).await?;
	Ok(serde_json::to_string(&value)?)
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
