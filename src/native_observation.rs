// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Opaque terminal output from the existing jobs owner, never a new registry.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::future::Future;
use std::time::{Duration, Instant};

use super::{jobs, ProcessCancelParams, ProcessReadParams, ProcessStartParams};
use crate::mcp::runtime::{runtime_config, HostConfig};

#[path = "native_observation_error.rs"]
mod diagnostic;
use diagnostic::{Cause, Failure, Stage};

pub(crate) fn observation_failure_diagnostic(error: &anyhow::Error) -> String {
	diagnostic::public_diagnostic(error)
}

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
	scratch_cleanup: Option<Value>,
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
	/// Original owner's witnessed engine-directory cleanup; absent for legacy
	/// jobs and jobs which did not reserve an engine scratch namespace.
	pub fn scratch_cleanup(&self) -> Option<&Value> {
		self.scratch_cleanup.as_ref()
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
	observe_terminal_output_with(
		original,
		max_output_bytes,
		|| runtime_config()?.host(&original.host),
		super::observe_request,
		super::read,
	)
	.await
}

// This seam accepts only original-request lookup and page reads. Tests cannot
// supply a launch callback, and the production path keeps the same owner APIs.
async fn observe_terminal_output_with<'host, H, O, OF, R, RF>(
	original: &ProcessStartParams,
	max_output_bytes: usize,
	configured: H,
	observe: O,
	read: R,
) -> Result<Option<NativeTerminalOutput>>
where
	H: FnOnce() -> Result<&'host HostConfig> + Send,
	O: Fn(ProcessStartParams) -> OF + Sync,
	OF: Future<Output = Result<Option<String>>> + Send,
	R: Fn(ProcessReadParams) -> RF + Sync,
	RF: Future<Output = Result<String>> + Send,
{
	let initial_started = Instant::now();
	let initial_fault = |stage, cause, source| {
		let mut failure = Failure::new(stage, cause, source);
		failure.elapsed = initial_started.elapsed();
		failure.initial_observation = failure.elapsed;
		anyhow::Error::new(failure)
	};
	super::require_key(original)
		.map_err(|error| initial_fault(Stage::Admission, Cause::InvalidRequest, error))?;
	if max_output_bytes == 0 {
		return Err(initial_fault(
			Stage::OutputBudget,
			Cause::RetentionBudget,
			anyhow!("native observation requires a nonzero output budget"),
		));
	}
	let Some(raw) = observe(original.clone())
		.await
		.map_err(|error| initial_fault(Stage::InitialLookup, Cause::transport(&error), error))?
	else {
		return Ok(None);
	};
	let envelope: Value = serde_json::from_str(&raw)
		.map_err(|error| initial_fault(Stage::InitialEnvelope, Cause::InvalidJson, error.into()))?;
	validate_observation_envelope(&envelope)
		.map_err(|error| initial_fault(Stage::InitialEnvelope, Cause::BindingMismatch, error))?;
	let configured = configured()
		.map_err(|error| initial_fault(Stage::InitialBinding, Cause::Unavailable, error))?;
	let job_id = validate_job(&envelope, original, configured)
		.map_err(|error| initial_fault(Stage::InitialBinding, Cause::BindingMismatch, error))?;
	let Some(proof) = terminal_proof(&envelope["status"], &job_id).map_err(|error| {
		initial_fault(Stage::InitialPublication, Cause::PublicationInvalid, error)
	})?
	else {
		return Ok(None);
	};
	let total = proof
		.stdout_bytes
		.checked_add(proof.stderr_bytes)
		.ok_or_else(|| {
			initial_fault(
				Stage::OutputBudget,
				Cause::RetentionBudget,
				anyhow!("runtime output length overflow"),
			)
		})?;
	if u128::from(total) > max_output_bytes as u128 {
		return Err(initial_fault(
			Stage::OutputBudget,
			Cause::RetentionBudget,
			anyhow!("original runtime output exceeds the admitted retention budget"),
		));
	}
	let initial_observation = initial_started.elapsed();
	let read_started = Instant::now();
	let streams = pages::collect(
		&original.host,
		&job_id,
		proof.stdout_bytes,
		proof.stderr_bytes,
		max_output_bytes,
		read,
	)
	.await
	.map_err(|mut error| {
		if let Some(failure) = error.downcast_mut::<Failure>() {
			failure.initial_observation = initial_observation;
			failure.output_read = read_started.elapsed();
			failure.elapsed = initial_started.elapsed();
		}
		error
	})?;
	let output_read = read_started.elapsed();
	let final_started = Instant::now();
	let final_fault = |stage, cause, source| {
		let mut failure = Failure::new(stage, cause, source);
		failure.initial_observation = initial_observation;
		failure.output_read = output_read;
		failure.final_observation = final_started.elapsed();
		failure.elapsed = initial_started.elapsed();
		failure.page_reads_attempted = streams.page_reads;
		failure.validated_page_reads = streams.page_reads;
		failure.read_windows = streams.read_windows;
		failure.retained_stdout_bytes = streams.stdout.len();
		failure.retained_stderr_bytes = streams.stderr.len();
		anyhow::Error::new(failure)
	};
	let final_raw = observe(original.clone())
		.await
		.map_err(|error| final_fault(Stage::FinalLookup, Cause::transport(&error), error))?
		.ok_or_else(|| {
			final_fault(
				Stage::FinalLookup,
				Cause::Unavailable,
				anyhow!("original runtime binding unavailable after output read; reconcile only"),
			)
		})?;
	let final_envelope: Value = serde_json::from_str(&final_raw)
		.map_err(|error| final_fault(Stage::FinalEnvelope, Cause::InvalidJson, error.into()))?;
	validate_observation_envelope(&final_envelope)
		.map_err(|error| final_fault(Stage::FinalEnvelope, Cause::BindingMismatch, error))?;
	let final_job_id = validate_job(&final_envelope, original, configured)
		.map_err(|error| final_fault(Stage::FinalBinding, Cause::BindingMismatch, error))?;
	if final_job_id != job_id {
		return Err(final_fault(
			Stage::FinalBinding,
			Cause::BindingMismatch,
			anyhow!("original runtime job changed while reading output"),
		));
	}
	let final_proof = terminal_proof(&final_envelope["status"], &job_id)
		.map_err(|error| final_fault(Stage::FinalPublication, Cause::PublicationInvalid, error))?;
	if final_proof.as_ref() != Some(&proof) {
		return Err(final_fault(
			Stage::FinalPublication,
			Cause::PublicationChanged,
			anyhow!("original runtime terminal publication changed while reading output"),
		));
	}
	let outcome = match proof.state.as_str() {
		"succeeded" => NativeJobOutcome::Succeeded,
		"failed" => NativeJobOutcome::Failed,
		"cancelled" => NativeJobOutcome::Cancelled,
		"timed_out" => NativeJobOutcome::TimedOut,
		_ => {
			return Err(final_fault(
				Stage::FinalPublication,
				Cause::PublicationChanged,
				anyhow!("runtime terminal outcome changed"),
			))
		}
	};
	let key = original.idempotency_key.clone().ok_or_else(|| {
		final_fault(
			Stage::FinalBinding,
			Cause::BindingMismatch,
			anyhow!("original key missing"),
		)
	})?;
	let request_digest = jobs::request_digest(original)
		.map_err(|error| final_fault(Stage::FinalBinding, Cause::BindingMismatch, error))?;
	Ok(Some(NativeTerminalOutput {
		host: original.host.clone(),
		key,
		request_digest,
		job_id,
		exit_code: proof.exit_code,
		outcome,
		scratch_cleanup: proof.scratch_cleanup,
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

#[cfg(test)]
#[path = "native_observation_tests.rs"]
mod tests;

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
