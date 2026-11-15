// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Opaque terminal output from the existing jobs owner, never a new registry.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use super::{jobs, ProcessCancelParams, ProcessReadParams, ProcessStartParams};
use crate::mcp::runtime::runtime_config;

#[path = "native_observation_wire.rs"]
mod wire;
use wire::{
	decode_page, require_job_id, terminal_proof, validate_job, validate_observation_envelope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeJobOutcome {
	Succeeded,
	Failed,
	Cancelled,
	TimedOut,
}

/// Only observation of the original durable job can construct this witness.
/// Host authority and model-facing receipt binding remain with the agent owner.
pub struct NativeTerminalOutput {
	host: String,
	key: String,
	request_digest: String,
	job_id: String,
	exit_code: i32,
	outcome: NativeJobOutcome,
	stdout: Vec<u8>,
	stderr: Vec<u8>,
}

impl NativeTerminalOutput {
	pub fn matches_request(&self, original: &ProcessStartParams) -> Result<bool> {
		Ok(self.host == original.host
			&& original.idempotency_key.as_deref() == Some(self.key.as_str())
			&& jobs::request_digest(original)? == self.request_digest)
	}

	pub fn job_id(&self) -> &str {
		&self.job_id
	}
	pub fn exit_code(&self) -> i32 {
		self.exit_code
	}
	pub fn outcome(&self) -> NativeJobOutcome {
		self.outcome
	}
	pub fn into_streams(self) -> (Vec<u8>, Vec<u8>) {
		(self.stdout, self.stderr)
	}
}

/// Observe and retain bounded complete output from the same request. No path
/// here calls start_job, allocates a job, repairs or relaunches an unknown job.
pub async fn observe_terminal_output(
	original: &ProcessStartParams,
	max_output_bytes: usize,
) -> Result<Option<NativeTerminalOutput>> {
	super::require_key(original)?;
	if max_output_bytes == 0 {
		bail!("native observation requires a nonzero output budget");
	}
	let Some(raw) = super::observe_request(original.clone()).await? else {
		return Ok(None);
	};
	let envelope: Value = serde_json::from_str(&raw)?;
	validate_observation_envelope(&envelope)?;
	let configured = runtime_config()?.host(&original.host)?;
	let job_id = validate_job(&envelope, original, configured)?;
	let Some(proof) = terminal_proof(&envelope["status"], &job_id)? else {
		return Ok(None);
	};
	let total = proof
		.stdout_bytes
		.checked_add(proof.stderr_bytes)
		.context("runtime output length overflow")?;
	if u128::from(total) > max_output_bytes as u128 {
		bail!("original runtime output exceeds the admitted retention budget");
	}
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	let mut stdout_offset = 0;
	let mut stderr_offset = 0;
	let page_limit = (16 * 1024).min(u64::try_from(max_output_bytes)?);
	loop {
		let page: Value = serde_json::from_str(
			&super::read(ProcessReadParams {
				host: original.host.clone(),
				job_id: job_id.clone(),
				stdout_offset: Some(stdout_offset),
				stderr_offset: Some(stderr_offset),
				limit: Some(page_limit),
			})
			.await?,
		)?;
		require_job_id(&page, &job_id)?;
		let out = decode_page(
			&page["stdout"],
			stdout_offset,
			proof.stdout_bytes,
			page_limit,
		)?;
		let err = decode_page(
			&page["stderr"],
			stderr_offset,
			proof.stderr_bytes,
			page_limit,
		)?;
		let next_size = stdout
			.len()
			.checked_add(stderr.len())
			.and_then(|n| n.checked_add(out.bytes.len()))
			.and_then(|n| n.checked_add(err.bytes.len()))
			.context("runtime output accumulation overflow")?;
		if next_size > max_output_bytes {
			bail!("runtime output exceeds the admitted retention budget");
		}
		stdout.extend_from_slice(&out.bytes);
		stderr.extend_from_slice(&err.bytes);
		stdout_offset = out.next_offset;
		stderr_offset = err.next_offset;
		if out.eof && err.eof {
			break;
		}
	}
	let final_raw = super::observe_request(original.clone())
		.await?
		.context("original runtime binding unavailable after output read; reconcile only")?;
	let final_envelope: Value = serde_json::from_str(&final_raw)?;
	validate_observation_envelope(&final_envelope)?;
	if validate_job(&final_envelope, original, configured)? != job_id
		|| terminal_proof(&final_envelope["status"], &job_id)?.as_ref() != Some(&proof)
	{
		bail!("original runtime terminal publication changed while reading output");
	}
	let outcome = match proof.state.as_str() {
		"succeeded" => NativeJobOutcome::Succeeded,
		"failed" => NativeJobOutcome::Failed,
		"cancelled" => NativeJobOutcome::Cancelled,
		"timed_out" => NativeJobOutcome::TimedOut,
		_ => bail!("runtime terminal outcome changed"),
	};
	Ok(Some(NativeTerminalOutput {
		host: original.host.clone(),
		key: original
			.idempotency_key
			.clone()
			.context("original key missing")?,
		request_digest: jobs::request_digest(original)?,
		job_id,
		exit_code: proof.exit_code,
		outcome,
		stdout,
		stderr,
	}))
}

/// Cancel only the job resolved from this exact original request. This returns
/// an acknowledgement; terminality still requires observe_terminal_output.
pub async fn cancel_request(original: &ProcessStartParams, grace_seconds: u64) -> Result<()> {
	super::require_key(original)?;
	let raw = super::observe_request(original.clone())
		.await?
		.context("original runtime binding not found; cancellation remains unconfirmed")?;
	let envelope: Value = serde_json::from_str(&raw)?;
	validate_observation_envelope(&envelope)?;
	let job_id = validate_job(&envelope, original, runtime_config()?.host(&original.host)?)?;
	let result: Value = serde_json::from_str(
		&super::cancel(ProcessCancelParams {
			host: original.host.clone(),
			job_id: job_id.clone(),
			grace_seconds: Some(grace_seconds.min(30)),
		})
		.await?,
	)?;
	require_job_id(&result, &job_id)?;
	if !matches!(
		result["result"].as_str(),
		Some("already_exited" | "stop_requested" | "term_sent" | "kill_sent" | "not_running")
	) {
		bail!("original runtime cancellation outcome is unknown; observe the same request");
	}
	Ok(())
}
