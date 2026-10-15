// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Target-owned operator PTYs with durable controller references and full archives.
use super::config::{runtime_config, ExecutionMode};
use super::pty::{
	require_pty_intent, retain_pty_after_audit, unknown_pty_outcome, PtyReadParams, PtyRefParams,
	PtyStartParams, PtyWriteParams,
};
use super::ssh::run_python_json;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

static SERIAL: AtomicU64 = AtomicU64::new(1);
static START_LOCK: Mutex<()> = Mutex::const_new(());
const SOURCE: &str = include_str!("terminal_host.py");

#[derive(Debug, Serialize, Deserialize)]
struct TerminalRecord {
	session_id: String,
	host: String,
	ssh_target: String,
	remote_state_dir: String,
	job_dir: String,
	request: Value,
}

fn directory() -> Result<PathBuf> {
	Ok(runtime_config()?.state_dir.join("terminals"))
}

fn record_path(id: &str) -> Result<PathBuf> {
	if !id.starts_with("dpty-")
		|| id.len() > 96
		|| !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
	{
		bail!("invalid persistent terminal identity");
	}
	Ok(directory()?.join(format!("{id}.json")))
}

async fn load(host_name: &str, id: &str) -> Result<TerminalRecord> {
	let record: TerminalRecord = serde_json::from_slice(
		&tokio::fs::read(record_path(id)?)
			.await
			.context("unknown persistent terminal")?,
	)?;
	let host = runtime_config()?.host(host_name)?;
	if record.host != host_name
		|| record.ssh_target != host.ssh_target
		|| record.remote_state_dir != host.remote_state_dir
		|| host.execution_mode != ExecutionMode::Operator
	{
		bail!("terminal authority binding changed or wrong host");
	}
	Ok(record)
}

async fn rpc(record: &TerminalRecord, mut input: Value) -> Result<Value> {
	let host = runtime_config()?.host(&record.host)?;
	input["job_dir"] = json!(record.job_dir);
	input["session_id"] = json!(record.session_id);
	let code = format!(
		"HEPTA_HELPER_SOURCE = {}\nexec(HEPTA_HELPER_SOURCE)",
		serde_json::to_string(SOURCE)?
	);
	let mut output: Value = run_python_json(host, &code, &input, Duration::from_secs(25)).await?;
	if !output.is_object() {
		bail!("invalid terminal acknowledgement");
	}
	output["session_id"] = json!(record.session_id);
	output["host"] = json!(record.host);
	output["persistent_across_runtime_restart"] = json!(true);
	Ok(output)
}

fn retain_terminal_outcome(
	record: &TerminalRecord,
	operation: &str,
	remote: Result<Value>,
	requested_bytes: Option<usize>,
) -> Value {
	let mut value = match remote {
		Ok(value) if value.is_object() => value,
		_ => return unknown_pty_outcome(&record.host, &record.session_id, operation, true),
	};
	let valid = match operation {
		"start" => {
			value["reused"].is_boolean()
				&& matches!(
					value["status"]["state"].as_str(),
					Some("running" | "exited" | "lost" | "launch_unknown")
				) && value["status"]["output_complete"].is_boolean()
		}
		"write" => {
			value["bytes_written"]
				.as_u64()
				.zip(requested_bytes)
				.is_some_and(|(written, requested)| {
					written <= requested as u64
						&& value["complete"].as_bool() == Some(written == requested as u64)
				}) && value["reused"].is_boolean()
		}
		"close" => matches!(
			value["result"].as_str(),
			Some("close_requested" | "already_exited")
		),
		_ => false,
	};
	if !valid || value.get("error").is_some() {
		return unknown_pty_outcome(&record.host, &record.session_id, operation, true);
	}
	// These bindings come from the locally authorized record, never a remote ACK.
	value["host"] = json!(record.host);
	value["session_id"] = json!(record.session_id);
	value["persistent_across_runtime_restart"] = json!(true);
	value["automatic_retry"] = json!(false);
	if operation == "start"
		&& matches!(
			value["status"]["state"].as_str(),
			Some("lost" | "launch_unknown")
		) {
		value["result"] = json!("pty_outcome_unknown");
		value["outcome"] = json!("unknown");
		value["reconcile_warning"] = json!("Terminal launch acknowledgement is unavailable. Inspect this same session identity; do not create another terminal automatically.");
	}
	if operation == "close" {
		value["termination_confirmed"] = json!(false);
		if value["result"] == "already_exited" {
			// The current helper also uses this ACK for lost/launch_unknown state.
			// It is not proof that the target child actually exited.
			value["outcome"] = json!("unknown");
			value["reconcile_warning"] = json!("Terminal owner is not accepting close. Inspect this session's exit status; this acknowledgement does not confirm termination.");
		}
	}
	value
}

async fn dispatch_operation(
	record: &TerminalRecord,
	operation: &str,
	input: Value,
	requested_bytes: Option<usize>,
) -> Result<String> {
	require_pty_intent(super::jobs::audit(
		&format!("persistent_pty_{operation}_intent"),
		&record.host,
		&record.session_id,
		&json!({"phase":"intent","bytes":requested_bytes,"remote_operation_submitted":false}),
	))?;
	let result =
		retain_terminal_outcome(record, operation, rpc(record, input).await, requested_bytes);
	let completion = super::jobs::audit(
		&format!("persistent_pty_{operation}"),
		&record.host,
		&record.session_id,
		&json!({"phase":"result","outcome_unknown":result["outcome"]=="unknown",
			"bytes_written":result["bytes_written"],"close_requested":result["result"]=="close_requested"}),
	);
	Ok(serde_json::to_string(&retain_pty_after_audit(
		result, completion,
	))?)
}

pub async fn start(params: &PtyStartParams) -> Result<String> {
	let _guard = START_LOCK.lock().await;
	let host = runtime_config()?.host(&params.host)?;
	if host.execution_mode != ExecutionMode::Operator {
		bail!("persistent terminal requires an operator host");
	}
	let request = json!({"allow_detached_fallback":host.allow_detached_fallback,"executable":params.executable,"args":params.args,"cwd":params.cwd,"env":params.env,
        "rows":params.rows.unwrap_or(24).clamp(1,500), "cols":params.cols.unwrap_or(120).clamp(1,1000)});
	let id = if let Some(key) = &params.idempotency_key {
		if key.is_empty() || key.len() > 256 {
			bail!("PTY idempotency key must contain 1..256 bytes");
		}
		format!(
			"dpty-{}",
			Sha256::digest(format!("{}\0{key}", params.host).as_bytes())
				.iter()
				.map(|b| format!("{b:02x}"))
				.collect::<String>()
		)
	} else {
		let t = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
		format!(
			"dpty-{t:x}-{:x}-{:x}",
			std::process::id(),
			SERIAL.fetch_add(1, Ordering::Relaxed)
		)
	};
	let path = record_path(&id)?;
	if tokio::fs::try_exists(&path).await? {
		let record = load(&params.host, &id).await?;
		let mut compare = request.clone();
		compare["session_id"] = json!(id);
		if compare != record.request {
			bail!("terminal key is already bound to a different request");
		}
		return dispatch_operation(
			&record,
			"start",
			json!({"op":"start","request":record.request}),
			None,
		)
		.await;
	}
	tokio::fs::create_dir_all(directory()?).await?;
	let mut req = request;
	req["session_id"] = json!(id);
	let record = TerminalRecord {
		session_id: id.clone(),
		host: params.host.clone(),
		ssh_target: host.ssh_target.clone(),
		remote_state_dir: host.remote_state_dir.clone(),
		job_dir: format!("{}/terminals/{id}", host.remote_state_dir),
		request: req,
	};
	// Durable intent precedes remote effects. A transport failure can be reconciled
	// using the same key rather than creating a second terminal.
	use tokio::io::AsyncWriteExt;
	let mut file = tokio::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&path)
		.await?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		file.set_permissions(std::fs::Permissions::from_mode(0o600))
			.await?;
	}
	file.write_all(&serde_json::to_vec(&record)?).await?;
	file.sync_all().await?;
	dispatch_operation(
		&record,
		"start",
		json!({"op":"start","request":record.request}),
		None,
	)
	.await
}

pub async fn read(params: &PtyReadParams) -> Result<String> {
	let record = load(&params.host, &params.session_id).await?;
	Ok(serde_json::to_string(
		&rpc(
			&record,
			json!({"op":"read","offset":params.offset,"limit":params.limit,"raw_bytes":params.raw_bytes}),
		)
		.await?,
	)?)
}

pub async fn write(params: &PtyWriteParams) -> Result<String> {
	if params.data.len() > 65536 {
		bail!("PTY input exceeds 64 KiB");
	}
	if params
		.request_id
		.as_ref()
		.is_some_and(|key| key.is_empty() || key.chars().count() > 128)
	{
		bail!("invalid PTY input request identity");
	}
	let record = load(&params.host, &params.session_id).await?;
	dispatch_operation(
		&record,
		"write",
		json!({"op":"write","data":params.data,"request_id":params.request_id}),
		Some(params.data.len()),
	)
	.await
}

pub async fn close(params: &PtyRefParams) -> Result<String> {
	let record = load(&params.host, &params.session_id).await?;
	dispatch_operation(&record, "close", json!({"op":"close"}), None).await
}

pub async fn list(
	host_name: Option<&str>,
	after: Option<&str>,
	limit: usize,
) -> Result<(Vec<Value>, bool)> {
	if !tokio::fs::try_exists(directory()?).await? {
		return Ok((Vec::new(), false));
	}
	let mut entries = tokio::fs::read_dir(directory()?).await?;
	let mut ids = Vec::new();
	while let Some(entry) = entries.next_entry().await? {
		let name = entry.file_name().to_string_lossy().into_owned();
		if let Some(id) = name.strip_suffix(".json") {
			if after.is_none_or(|a| id > a) {
				ids.push(id.to_owned());
			}
		}
	}
	ids.sort();
	let mut values = Vec::new();
	for id in ids {
		let record: TerminalRecord =
			serde_json::from_slice(&tokio::fs::read(record_path(&id)?).await?)?;
		if host_name.is_some_and(|h| h != record.host) {
			continue;
		}
		if values.len() == limit {
			return Ok((values, true));
		}
		// Discovery is local and bounded: disconnected hosts cannot stall listing.
		values.push(
			json!({"session_id":id,"host":record.host,"persistent_across_runtime_restart":true,
            "status":{"state":"inspect_with_pty_read"}}),
		);
	}
	Ok((values, false))
}

#[cfg(test)]
#[path = "terminal_tests.rs"]
mod tests;
