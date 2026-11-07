// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original five-page observation, failure attribution and no-launch injection seam.

use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const ORIGINAL_BYTES: usize = 73_616;
const JOB: &str = "1a1b5bcfe89-12894-d3";
const PRIVATE_ERROR: &str = "fixture-private-token-and-SSH-stderr";

#[derive(Clone, Copy)]
enum Case {
	Complete,
	PageTimeout,
	PageCorruption,
	MultiplePageFailures,
	FinalLookupMissing,
	FinalLookupError,
	FinalNonceChanged,
	FinalPublicationInvalid,
	FinalStatusUnavailable,
	FinalJobChanged,
}

#[derive(Default)]
struct Calls {
	lookups: AtomicUsize,
	pages: Mutex<Vec<(u64, u64, u64)>>,
}

fn page(params: &ProcessReadParams, stdout: &[u8]) -> Value {
	let part = |bytes: &[u8], offset: u64| {
		let offset = offset as usize;
		let end = (offset + params.limit.unwrap() as usize).min(bytes.len());
		let encoded: String = bytes[offset..end]
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect();
		json!({"offset":offset,"next_offset":end,"size":bytes.len(),
			"eof":end == bytes.len(),"bytes_hex":encoded})
	};
	json!({"job_id":JOB,
		"stdout":part(stdout, params.stdout_offset.unwrap()),
		"stderr":part(&[], params.stderr_offset.unwrap())})
}

async fn fixture(
	case: Case,
) -> (
	Result<Option<NativeTerminalOutput>>,
	Arc<Calls>,
	ProcessStartParams,
) {
	let original: ProcessStartParams = serde_json::from_value(json!({
		"host":"x230","executable":"/usr/bin/python3", "args":["original-read"],
		"idempotency_key":"original-read-key", "stdin":"same-original-request\n"
	}))
	.unwrap();
	let host: HostConfig = serde_json::from_value(json!({
		"ssh_target":"configured-original-host", "remote_state_dir":"/srv/original-state",
		"platform":"linux", "execution_mode":"isolated"
	}))
	.unwrap();
	let envelope = json!({
		"observation_only":true,"reused":true,"retried_launch":false,"launch":null,
		"job":{"id":JOB,"host":original.host,"idempotency_key":original.idempotency_key,
			"request_digest":jobs::request_digest(&original).unwrap(),"ssh_target":host.ssh_target,
			"remote_job_dir":format!("/srv/original-state/jobs/{JOB}"),
			"execution_mode":host.execution_mode,"executable":original.executable,
			"args":original.args,"cwd":original.cwd,"env_keys":[]},
		"status":{"job_id":JOB,"state":"succeeded","exit_code":0,
			"launch_nonce":"ac50f92801e2dac54c9bd528ce2a8ee1","at_unix_ms":1794050434735_u64,
			"cancelled":false,"timed_out":false,"terminal_publication_protocol":1,
			"terminal_publication_confirmed":true,"output_complete":true,"output_durable":true,
			"log_bytes":{"stdout":{"seen":ORIGINAL_BYTES,"stored":ORIGINAL_BYTES},
				"stderr":{"seen":0,"stored":0}},
			"log_errors":{"stdout":null,"stderr":null},
			"log_synced":{"stdout":true,"stderr":true},
			"log_truncated":{"stdout":false,"stderr":false}}
	});
	let exact = serde_json::to_vec(&original).unwrap();
	let calls = Arc::new(Calls::default());
	let stdout: Arc<Vec<u8>> = Arc::new((0..ORIGINAL_BYTES).map(|i| (i % 251) as u8).collect());
	let observe = |params: ProcessStartParams| {
		assert_eq!(serde_json::to_vec(&params).unwrap(), exact);
		let index = calls.lookups.fetch_add(1, Ordering::SeqCst);
		assert!(index < 2, "original lookup was retried");
		let mut envelope = envelope.clone();
		async move {
			if index == 1 {
				match case {
					Case::FinalLookupMissing => return Ok(None),
					Case::FinalLookupError => bail!(PRIVATE_ERROR),
					Case::FinalNonceChanged => {
						envelope["status"]["launch_nonce"] = json!("b".repeat(32))
					}
					Case::FinalPublicationInvalid => {
						envelope["status"]["output_durable"] = json!(false)
					}
					Case::FinalStatusUnavailable => {
						envelope["status"]["state"] = json!("status_unavailable")
					}
					Case::FinalJobChanged => {
						envelope["job"]["id"] = json!("replacement");
						envelope["job"]["remote_job_dir"] =
							json!("/srv/original-state/jobs/replacement");
					}
					_ => {}
				}
			}
			Ok(Some(envelope.to_string()))
		}
	};
	let read = |params: ProcessReadParams| {
		assert_eq!(params.host, original.host);
		assert_eq!(params.job_id, JOB);
		let offset = params.stdout_offset.unwrap();
		calls.pages.lock().unwrap().push((
			offset,
			params.stderr_offset.unwrap(),
			params.limit.unwrap(),
		));
		let stdout = stdout.clone();
		async move {
			if (matches!(case, Case::PageTimeout) && offset == 65_536)
				|| (matches!(case, Case::MultiplePageFailures) && offset == 32_768)
			{
				tokio::time::timeout(Duration::from_millis(2), std::future::pending::<()>())
					.await
					.context(PRIVATE_ERROR)?;
			}
			let mut value = page(&params, &stdout);
			if (matches!(case, Case::PageCorruption) && offset == 16_384)
				|| (matches!(case, Case::MultiplePageFailures) && offset == 0)
			{
				value["stdout"]["next_offset"] = json!(offset + 1);
			}
			Ok(value.to_string())
		}
	};
	// No global runtime initialization and no execute/start callback exist in
	// this fixture. The unchanged production entry test also counts SSH launches.
	let result =
		observe_terminal_output_with(&original, 512 * 1024, || Ok(&host), observe, read).await;
	(result, calls, original)
}

#[tokio::test]
async fn original_73616_byte_output_has_five_reads_and_two_bound_observations() {
	let (result, calls, original) = fixture(Case::Complete).await;
	let output = result.unwrap().unwrap();
	assert_eq!(calls.lookups.load(Ordering::SeqCst), 2);
	let mut pages = calls.pages.lock().unwrap().clone();
	pages.sort_unstable();
	assert_eq!(
		pages,
		vec![
			(0, 0, 16384),
			(16384, 0, 16384),
			(32768, 0, 16384),
			(49152, 0, 16384),
			(65536, 0, 16384)
		]
	);
	assert!(output.matches_request(&original).unwrap());
	assert_eq!(output.job_id(), JOB);
	assert_eq!(output.outcome(), NativeJobOutcome::Succeeded);
	assert_eq!(output.observation_timing().page_reads, 5);
	assert_eq!(output.observation_timing().read_windows, 2);
	let (stdout, stderr) = output.into_streams();
	assert_eq!(
		stdout,
		(0..ORIGINAL_BYTES)
			.map(|i| (i % 251) as u8)
			.collect::<Vec<_>>()
	);
	assert!(stderr.is_empty());
}

#[tokio::test]
async fn last_page_timeout_retains_completed_window_cost_and_safe_cause() {
	let (result, calls, _) = fixture(Case::PageTimeout).await;
	let error = result.err().unwrap();
	let failure = error.downcast_ref::<Failure>().unwrap();
	assert_eq!(
		(failure.stage, failure.cause),
		(Stage::PageTransport, Cause::Deadline)
	);
	assert_eq!(
		(
			failure.page_reads_attempted,
			failure.validated_page_reads,
			failure.read_windows
		),
		(5, 4, 2)
	);
	assert_eq!(failure.retained_stdout_bytes, 65_536);
	assert_eq!(failure.pages.len(), 1);
	assert_eq!(
		(
			failure.pages[0].window,
			failure.pages[0].index,
			failure.pages[0].stdout_offset
		),
		(2, 4, 65_536)
	);
	assert!(failure.output_read >= failure.pages[0].elapsed);
	assert!(failure.elapsed >= failure.initial_observation + failure.output_read);
	assert!(!failure.pages[0].elapsed.is_zero());
	assert_eq!(calls.lookups.load(Ordering::SeqCst), 1);
	assert_eq!(calls.pages.lock().unwrap().len(), 5);
	assert!(error
		.chain()
		.any(|cause| cause.to_string().contains(PRIVATE_ERROR)));
	let public = observation_failure_diagnostic(&error);
	assert!(public.contains("cause=deadline") && public.contains("window=2 page=4"));
	assert!(!public.contains(PRIVATE_ERROR));
}

#[tokio::test]
async fn corrupted_page_never_admits_bytes_or_skips_the_failed_range() {
	let (result, calls, _) = fixture(Case::PageCorruption).await;
	let error = result.err().unwrap();
	let failure = error.downcast_ref::<Failure>().unwrap();
	assert_eq!(
		(failure.stage, failure.cause),
		(Stage::PageIntegrity, Cause::InvalidPage)
	);
	assert_eq!(
		(
			failure.page_reads_attempted,
			failure.validated_page_reads,
			failure.read_windows
		),
		(4, 3, 1)
	);
	assert_eq!(failure.retained_stdout_bytes, 16_384);
	assert_eq!((failure.pages[0].window, failure.pages[0].index), (1, 1));
	assert_eq!(calls.lookups.load(Ordering::SeqCst), 1);
	assert_eq!(calls.pages.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn failed_window_retains_every_failed_slot_without_starting_a_new_window() {
	let (result, calls, _) = fixture(Case::MultiplePageFailures).await;
	let error = result.err().unwrap();
	let failure = error.downcast_ref::<Failure>().unwrap();
	assert_eq!(failure.pages.len(), 2);
	assert_eq!(
		(failure.pages[0].index, failure.pages[0].cause),
		(0, Cause::InvalidPage)
	);
	assert_eq!(
		(failure.pages[1].index, failure.pages[1].cause),
		(2, Cause::Deadline)
	);
	assert_eq!(
		(failure.page_reads_attempted, failure.validated_page_reads),
		(4, 2)
	);
	assert_eq!(calls.pages.lock().unwrap().len(), 4);
	assert_eq!(calls.lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn final_lookup_failure_preserves_full_read_cost_without_authorizing_output() {
	for case in [Case::FinalLookupMissing, Case::FinalLookupError] {
		let (result, calls, _) = fixture(case).await;
		let error = result.err().unwrap();
		let failure = error.downcast_ref::<Failure>().unwrap();
		assert_eq!(
			(failure.stage, failure.cause),
			(Stage::FinalLookup, Cause::Unavailable)
		);
		assert_eq!(
			(
				failure.page_reads_attempted,
				failure.validated_page_reads,
				failure.read_windows
			),
			(5, 5, 2)
		);
		assert_eq!(failure.retained_stdout_bytes, ORIGINAL_BYTES);
		assert!(
			failure.elapsed
				>= failure.initial_observation + failure.output_read + failure.final_observation
		);
		assert_eq!(calls.lookups.load(Ordering::SeqCst), 2);
		assert_eq!(calls.pages.lock().unwrap().len(), 5);
		assert!(!observation_failure_diagnostic(&error).contains(PRIVATE_ERROR));
	}
}

#[tokio::test]
async fn final_publication_and_job_changes_are_distinguished_and_still_rejected() {
	for (case, stage, cause) in [
		(
			Case::FinalNonceChanged,
			Stage::FinalPublication,
			Cause::PublicationChanged,
		),
		(
			Case::FinalStatusUnavailable,
			Stage::FinalPublication,
			Cause::PublicationChanged,
		),
		(
			Case::FinalPublicationInvalid,
			Stage::FinalPublication,
			Cause::PublicationInvalid,
		),
		(
			Case::FinalJobChanged,
			Stage::FinalBinding,
			Cause::BindingMismatch,
		),
	] {
		let (result, calls, _) = fixture(case).await;
		let error = result.err().unwrap();
		let failure = error.downcast_ref::<Failure>().unwrap();
		assert_eq!((failure.stage, failure.cause), (stage, cause));
		assert_eq!(failure.retained_stdout_bytes, ORIGINAL_BYTES);
		assert_eq!(calls.lookups.load(Ordering::SeqCst), 2);
		assert_eq!(calls.pages.lock().unwrap().len(), 5);
	}
}

#[test]
fn diagnostic_is_bounded_even_for_four_failures_and_never_formats_the_source() {
	let mut failure = Failure::new(
		Stage::InitialPublication,
		Cause::PublicationChanged,
		anyhow!(PRIVATE_ERROR),
	);
	failure.elapsed = Duration::MAX;
	failure.initial_observation = Duration::MAX;
	failure.output_read = Duration::MAX;
	failure.final_observation = Duration::MAX;
	failure.page_reads_attempted = usize::MAX;
	failure.validated_page_reads = usize::MAX;
	failure.read_windows = usize::MAX;
	failure.retained_stdout_bytes = usize::MAX;
	failure.retained_stderr_bytes = usize::MAX;
	failure.pages = (0..4)
		.map(|_| diagnostic::PageFailure {
			stage: Stage::InitialPublication,
			cause: Cause::PublicationChanged,
			window: usize::MAX,
			index: usize::MAX,
			stdout_offset: u64::MAX,
			stderr_offset: u64::MAX,
			limit: u64::MAX,
			elapsed: Duration::MAX,
		})
		.collect();
	assert!(!format!("{failure:?}").contains(PRIVATE_ERROR));
	let public = observation_failure_diagnostic(&failure.into());
	assert!(public.is_ascii());
	// Leaves room for the unchanged HIA guidance inside its 2048-character
	// message limit, without truncating any failure in the four-page window.
	assert!(public.len() <= 1800, "{}", public.len());
	assert!(!public.contains(PRIVATE_ERROR));
	let forged_text = anyhow!("deadline timeout expired {PRIVATE_ERROR}");
	assert_eq!(Cause::transport(&forged_text), Cause::Unavailable);
}
