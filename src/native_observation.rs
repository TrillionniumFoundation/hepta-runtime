// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Opaque terminal output from the existing jobs owner, never a new registry.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::time::{Duration, Instant};

use super::{jobs, ProcessCancelParams, ProcessReadParams, ProcessStartParams};
use crate::mcp::runtime::runtime_config;

#[path = "native_observation_wire.rs"]
mod wire;
use wire::{require_job_id, terminal_proof, validate_job, validate_observation_envelope};

#[path = "native_observation_pages.rs"]
mod pages;

/// Monotonic durations for one successful observation of the original output.
/// These are diagnostics, not authority or remote execution timings.
#[derive(Clone, Debug)]
pub struct NativeOutputObservationTiming {
	pub initial_observation: Duration,
	pub page_reads: usize,
	pub read_windows: usize,
	pub output_read: Duration,
	pub final_observation: Duration,
}

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
	timing: NativeOutputObservationTiming,
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
	pub fn observation_timing(&self) -> &NativeOutputObservationTiming {
		&self.timing
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
	let initial_started = Instant::now();
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
	let initial_observation = initial_started.elapsed();
	let read_started = Instant::now();
	let streams = pages::collect(
		&original.host,
		&job_id,
		proof.stdout_bytes,
		proof.stderr_bytes,
		max_output_bytes,
		super::read,
	)
	.await?;
	let output_read = read_started.elapsed();
	let final_started = Instant::now();
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
		stdout: streams.stdout,
		stderr: streams.stderr,
		timing: NativeOutputObservationTiming {
			initial_observation,
			page_reads: streams.page_reads,
			read_windows: streams.read_windows,
			output_read,
			final_observation: final_started.elapsed(),
		},
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
