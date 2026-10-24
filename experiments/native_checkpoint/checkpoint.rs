// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Native CRIU snapshot calls on explicitly pinned Linux operator hosts.
use super::config::{runtime_config, ExecutionMode, Platform};
use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointAction {
	Inspect,
	Dump,
	Restore,
	Status,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointIdentity {
	pub pid: u32,
	pub uid: u32,
	pub boot_id: String,
	pub start_ticks: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointParams {
	pub host: String,
	pub action: CheckpointAction,
	#[serde(default)]
	pub pid: Option<u32>,
	#[serde(default)]
	pub expected_identity: Option<CheckpointIdentity>,
	#[serde(default)]
	pub checkpoint_id: Option<String>,
	#[serde(default)]
	pub acknowledge_process_stop: bool,
}

pub async fn execute(p: CheckpointParams) -> Result<String> {
	let host = runtime_config()?.host(&p.host)?;
	if host.execution_mode != ExecutionMode::Operator
		|| host.platform != Platform::Linux
		|| !host.allow_execute
	{
		bail!("checkpoint API requires an explicitly configured Linux operator host");
	}
	let binary = host
		.checkpoint_binary
		.as_ref()
		.context("administrator has not pinned a CRIU binary for this host")?;
	let sha = host
		.checkpoint_binary_sha256
		.as_ref()
		.context("administrator has not pinned a CRIU SHA256 for this host")?;
	if matches!(p.action, CheckpointAction::Inspect | CheckpointAction::Dump)
		&& p.pid.is_none_or(|pid| pid <= 1)
	{
		bail!("inspect/dump requires one positive non-system PID");
	}
	if matches!(p.action, CheckpointAction::Dump)
		&& p.expected_identity
			.as_ref()
			.is_none_or(|i| Some(i.pid) != p.pid)
	{
		bail!("dump requires the exact identity returned by inspect");
	}
	if !matches!(p.action, CheckpointAction::Inspect)
		&& (!p.acknowledge_process_stop
			|| p.checkpoint_id.as_ref().is_none_or(|id| {
				id.len() < 8
					|| id.len() > 80
					|| !id
						.bytes()
						.all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
			})) {
		bail!(
			"checkpoint lifecycle requires a strict checkpoint ID and process-stop acknowledgement"
		);
	}
	super::jobs::audit(
		"native_process_checkpoint",
		&p.host,
		p.checkpoint_id.as_deref().unwrap_or("inspect"),
		&json!({"action":p.action,"pid":p.pid}),
	)?;
	let mut q = serde_json::to_value(&p)?;
	q["configured_binary"] = json!(binary);
	q["configured_sha256"] = json!(sha);
	let command = format!(
		"sudo -n /usr/bin/python3 -I -c {}",
		super::ssh::shell_quote(include_str!("checkpoint_host.py"))
	);
	let output = super::ssh::run_capture(
		host,
		&command,
		&serde_json::to_vec(&q)?,
		Duration::from_secs(75),
	)
	.await?;
	if !output.status.success() {
		bail!(
			"checkpoint operation failed: {}",
			String::from_utf8_lossy(&output.stderr)
		);
	}
	let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
	Ok(serde_json::to_string(&value)?)
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
