// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pinned adapter to HIA Worker envelope and durable job identities.

use std::{
	fs::File,
	io::{Seek, SeekFrom},
	os::fd::AsRawFd,
	path::{Path, PathBuf},
	process::{ExitStatus, Stdio},
	sync::OnceLock,
	time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use super::hia_contract::MAX_WORKER_BYTES;
use super::hia_wire_candidate::{admit_executable, image_selected, sealed};

const PATH: &str = "HIA_LOCAL_MCP_PREPARE_IMAGE";
const SHA: &str = "HIA_LOCAL_MCP_PREPARE_SHA256";
const PREFIX_BYTES: usize = 8 + 4 * 64;
const JOB_PATH: &str = "HIA_LOCAL_MCP_JOB_IDENTITY_IMAGE";
const JOB_SHA: &str = "HIA_LOCAL_MCP_JOB_IDENTITY_SHA256";
const JOB_FRAME_MAX: usize = 8 << 20;
const JOB_FRAME_OUT: usize = 72;
const REUSE_FRAME_OUT: usize = 16;
const SCOPE_PATH: &str = "HIA_LOCAL_MCP_SESSION_SCOPE_IMAGE";
const SCOPE_SHA: &str = "HIA_LOCAL_MCP_SESSION_SCOPE_SHA256";
const SCOPE_FRAME_OUT: usize = 16;
const HTTP_AUTH_PATH: &str = "HIA_LOCAL_MCP_HTTP_AUTH_IMAGE";
const HTTP_AUTH_SHA: &str = "HIA_LOCAL_MCP_HTTP_AUTH_SHA256";
const TRANSITION_PATH: &str = "HIA_LOCAL_MCP_JOB_TRANSITION_IMAGE";
const TRANSITION_SHA: &str = "HIA_LOCAL_MCP_JOB_TRANSITION_SHA256";
const LAUNCH_ACK_PATH: &str = "HIA_LOCAL_MCP_JOB_LAUNCH_ACK_IMAGE";
const LAUNCH_ACK_SHA: &str = "HIA_LOCAL_MCP_JOB_LAUNCH_ACK_SHA256";
const JOB_POLL_PATH: &str = "HIA_LOCAL_MCP_JOB_POLL_IMAGE";
const JOB_POLL_SHA: &str = "HIA_LOCAL_MCP_JOB_POLL_SHA256";
const JOB_TERMINAL_PATH: &str = "HIA_LOCAL_MCP_JOB_TERMINAL_IMAGE";
const JOB_TERMINAL_RECEIPT_PATH: &str = "HIA_LOCAL_MCP_JOB_TERMINAL_RECEIPT_IMAGE";
const JOB_TERMINAL_SHA: &str = "HIA_LOCAL_MCP_JOB_TERMINAL_SHA256";
const JOB_WITNESS_PATH: &str = "HIA_LOCAL_MCP_JOB_WITNESS_IMAGE";
const JOB_WITNESS_SHA: &str = "HIA_LOCAL_MCP_JOB_WITNESS_SHA256";
const CAPTURE_PATH: &str = "HIA_LOCAL_MCP_CAPTURE_POLICY_IMAGE";
const CAPTURE_SHA: &str = "HIA_LOCAL_MCP_CAPTURE_POLICY_SHA256";
const JOB_LIFECYCLE_PATH: &str = "HIA_LOCAL_MCP_JOB_LIFECYCLE_IMAGE";
const JOB_LIFECYCLE_SHA: &str = "HIA_LOCAL_MCP_JOB_LIFECYCLE_SHA256";
const JOB_OPERATION_PATH: &str = "HIA_LOCAL_MCP_JOB_OPERATION_IMAGE";
const JOB_OPERATION_SHA: &str = "HIA_LOCAL_MCP_JOB_OPERATION_SHA256";
const JOB_PENDING_PATH: &str = "HIA_LOCAL_MCP_JOB_PENDING_IMAGE";
const JOB_PENDING_SHA: &str = "HIA_LOCAL_MCP_JOB_PENDING_SHA256";

pub(super) struct EncodedRequest {
	pub(super) transport_arguments_sha256: String,
	pub(super) profile_sha256: String,
	pub(super) request_sha256: String,
	pub(super) idempotency_digest: String,
	pub(super) stdin: String,
}

pub(super) fn selected() -> bool {
	image_selected(PATH, SHA)
}

pub(super) fn capture_policy_selected() -> bool {
	image_selected(CAPTURE_PATH, CAPTURE_SHA)
}

pub(super) fn job_operation_selected() -> bool {
	image_selected(JOB_OPERATION_PATH, JOB_OPERATION_SHA)
}

pub(super) fn job_operation_image() -> Result<&'static File> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	IMAGE
		.get_or_init(|| {
			admit_executable(JOB_OPERATION_PATH, JOB_OPERATION_SHA)
				.map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA job operation admission failed: {error}"))
}

pub(super) async fn job_operation(
	names: [&str; 5],
	digests: [&str; 3],
) -> Result<serde_json::Value> {
	let image = job_operation_image()?;
	let frame = job_operation_frame(names, digests)?;
	let (status, output) = run_filter(image, &frame, 512).await?;
	ensure!(
		status.success(),
		"native owner record differs from the admitted HIA job"
	);
	let operation =
		serde_json::from_slice(&output).context("HIA omitted the bound job operation")?;
	tracing::info!("Native HIA bound and rendered the original job operation");
	Ok(operation)
}

pub(super) fn job_operation_frame(names: [&str; 5], digests: [&str; 3]) -> Result<Vec<u8>> {
	ensure!(
		names.iter().all(|name| name.len() <= 256) && digests.iter().all(|value| value.len() == 64),
		"native owner record exceeds its operation frame bounds"
	);
	let mut frame = Vec::with_capacity(240 + names.iter().map(|value| value.len()).sum::<usize>());
	frame.extend_from_slice(b"HIAJOP01");
	for name in names {
		frame.extend_from_slice(&(name.len() as u64).to_le_bytes());
	}
	for hash in digests {
		frame.extend_from_slice(hash.as_bytes());
	}
	for name in names {
		frame.extend_from_slice(name.as_bytes());
	}
	Ok(frame)
}

pub(super) fn job_pending_selected() -> bool {
	image_selected(JOB_PENDING_PATH, JOB_PENDING_SHA)
}

pub(super) fn job_pending_image() -> Result<&'static File> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	IMAGE
		.get_or_init(|| {
			admit_executable(JOB_PENDING_PATH, JOB_PENDING_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA job observation admission failed: {error}"))
}

pub(super) async fn job_pending(
	reason: u64,
	unknown: u64,
	operation: &serde_json::Value,
	request: &str,
	diagnostic: &str,
) -> Result<serde_json::Value> {
	let id = operation["job_id"].as_str().context("missing HIA job ID")?;
	let host = operation["host"].as_str().context("missing HIA job host")?;
	ensure!(
		operation["request_sha256"] == request,
		"job observation lost its original HIA request"
	);
	let frame = job_pending_frame(reason, unknown, request, id, host, diagnostic)?;
	let (status, output) = run_filter(job_pending_image()?, &frame, 4096).await?;
	ensure!(status.success(), "HIA refused the job observation");
	let response: serde_json::Value =
		serde_json::from_slice(&output).context("HIA omitted its job observation")?;
	ensure!(
		response["operation"] == *operation
			&& response["request_id"] == format!("hia_{request}")
			&& matches!(response["status"].as_str(), Some("accepted" | "unknown")),
		"job observation changed its original HIA request or terminal authority"
	);
	tracing::info!("Native HIA rendered its nonterminal job observation");
	Ok(response)
}

pub(super) fn job_pending_frame(
	reason: u64,
	unknown: u64,
	request: &str,
	id: &str,
	host: &str,
	diagnostic: &str,
) -> Result<Vec<u8>> {
	ensure!(
		request.len() == 64 && id.len() <= 128 && host.len() <= 128 && diagnostic.len() <= 3072,
		"job observation exceeds its HIA frame bounds"
	);
	let mut frame = Vec::with_capacity(112 + id.len() + host.len() + diagnostic.len());
	frame.extend_from_slice(b"HIAJPN01");
	for field in [
		reason,
		unknown,
		id.len() as u64,
		host.len() as u64,
		diagnostic.len() as u64,
	] {
		frame.extend_from_slice(&field.to_le_bytes());
	}
	for field in [request, id, host, diagnostic] {
		frame.extend_from_slice(field.as_bytes());
	}
	Ok(frame)
}

pub(super) async fn admit_capture_path(
	path: &str,
	same_host: bool,
	explicit_identity: bool,
	roots: [&[String]; 3],
) -> Result<bool> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| {
			admit_executable(CAPTURE_PATH, CAPTURE_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA capture policy admission failed: {error}"))?;
	let frame = capture_policy_frame(path, same_host, explicit_identity, roots)?;
	let (status, output) = run_filter(image, &frame, 16).await?;
	ensure!(
		status.success() && output.len() == 16 && output.starts_with(b"HIACPV01"),
		"HIA capture policy refused its input"
	);
	let decision = u64::from_le_bytes(output[8..].try_into()?);
	ensure!(decision <= 1, "invalid HIA capture policy decision");
	tracing::info!(
		allowed = decision == 1,
		"Native HIA evaluated the Worker artifact capture policy"
	);
	Ok(decision == 1)
}

fn capture_policy_frame(
	path: &str,
	same_host: bool,
	explicit_identity: bool,
	roots: [&[String]; 3],
) -> Result<Vec<u8>> {
	ensure!(
		path.len() <= JOB_FRAME_MAX - 40,
		"HIA capture path exceeds the policy observation bound"
	);
	let mut frame = Vec::new();
	frame.extend_from_slice(b"HIACPQ01");
	for field in [
		u64::from(same_host),
		u64::from(explicit_identity),
		path.len() as u64,
		roots.iter().map(|group| group.len() as u64).sum(),
	] {
		frame.extend_from_slice(&field.to_le_bytes());
	}
	frame.extend_from_slice(path.as_bytes());
	for (role, group) in (1_u64..=3).zip(roots) {
		for root in group {
			// Match Path::starts_with's Linux component normalization without
			// treating a relative root or a noninitial `..` as authority.
			let root: PathBuf = Path::new(root).components().collect();
			let bytes = root.as_os_str().as_encoded_bytes();
			ensure!(
				JOB_FRAME_MAX - frame.len() >= 16
					&& bytes.len() <= JOB_FRAME_MAX - frame.len() - 16,
				"HIA capture roots exceed the policy observation bound"
			);
			frame.extend_from_slice(&role.to_le_bytes());
			frame.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
			frame.extend_from_slice(bytes);
		}
	}
	Ok(frame)
}

pub(super) async fn encode(catalog: &str, fragments: [&[u8]; 5]) -> Result<EncodedRequest> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| admit_executable(PATH, SHA).map_err(|error| error.to_string()))
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA Worker encoder admission failed: {error}"))?;
	encode_with(image, catalog, fragments).await
}

async fn encode_with(image: &File, catalog: &str, fragments: [&[u8]; 5]) -> Result<EncodedRequest> {
	ensure!(
		valid_digest(catalog.as_bytes()),
		"invalid HIA Worker catalog pin"
	);
	let mut frame =
		Vec::with_capacity(112 + fragments.iter().map(|part| part.len()).sum::<usize>());
	frame.extend_from_slice(b"HIAWPR01");
	for part in fragments {
		frame.extend_from_slice(&(part.len() as u64).to_le_bytes());
	}
	frame.extend_from_slice(catalog.as_bytes());
	for part in fragments {
		frame.extend_from_slice(part);
	}
	let (status, output) = run_filter(image, &frame, MAX_WORKER_BYTES + PREFIX_BYTES).await?;
	if status.code() == Some(3) {
		bail!("HIA worker request exceeds 512 KiB");
	}
	ensure!(status.success(), "HIA Worker encoder refused the request");
	frame_result(&output)
}

pub(super) fn job_identity_selected(key: Option<&str>) -> bool {
	image_selected(JOB_PATH, JOB_SHA) && key.is_some_and(hia_job_key)
}

pub(super) fn hia_job_key(key: &str) -> bool {
	key.strip_prefix("hia-agent-")
		.is_some_and(|suffix| valid_digest(suffix.as_bytes()))
}

pub(super) fn job_transition_selected(key: &str) -> bool {
	image_selected(TRANSITION_PATH, TRANSITION_SHA) && hia_job_key(key)
}

pub(super) fn launch_ack_selected(key: Option<&str>) -> bool {
	image_selected(LAUNCH_ACK_PATH, LAUNCH_ACK_SHA) && key.is_some_and(hia_job_key)
}

pub(super) fn job_poll_selected(key: Option<&str>) -> bool {
	image_selected(JOB_POLL_PATH, JOB_POLL_SHA) && key.is_some_and(hia_job_key)
}

pub(super) fn job_terminal_selected(key: Option<&str>) -> bool {
	image_selected(JOB_TERMINAL_PATH, JOB_TERMINAL_SHA) && key.is_some_and(hia_job_key)
}

pub(super) fn job_witness_selected(key: Option<&str>) -> bool {
	image_selected(JOB_WITNESS_PATH, JOB_WITNESS_SHA) && key.is_some_and(hia_job_key)
}

pub(super) fn job_terminal_receipt_selected() -> bool {
	super::hia_controller_release::selected(JOB_TERMINAL_RECEIPT_PATH)
}

pub(super) fn job_witness_image() -> Result<&'static File> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	IMAGE
		.get_or_init(|| {
			admit_executable(JOB_WITNESS_PATH, JOB_WITNESS_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|_| JobStatusUnavailable::Terminal.into())
}

pub(super) async fn job_terminal_witness(protocols: [u64; 3], fields: [&[u8]; 8]) -> Result<u64> {
	use JobStatusUnavailable::Terminal;

	ensure!(
		fields[..7].iter().all(|field| field.len() <= 128) && fields[7].len() <= 1 << 20,
		Terminal
	);
	let mut frame = Vec::with_capacity(96 + fields.iter().map(|field| field.len()).sum::<usize>());
	frame.extend_from_slice(b"HIAJWC01");
	for protocol in protocols {
		frame.extend_from_slice(&protocol.to_le_bytes());
	}
	for field in fields {
		frame.extend_from_slice(&(field.len() as u64).to_le_bytes());
	}
	for field in fields {
		frame.extend_from_slice(field);
	}
	let (status, output) = run_filter(job_witness_image()?, &frame, 16)
		.await
		.context(Terminal)?;
	ensure!(
		status.success() && output.len() == 16 && output.starts_with(b"HIAJWR01"),
		Terminal
	);
	let decision = u64::from_le_bytes(output[8..16].try_into()?);
	ensure!(decision <= 4, Terminal);
	tracing::info!(
		decision,
		"Native HIA decided the exact remote terminal receipt witness"
	);
	Ok(decision)
}

pub(super) fn job_lifecycle_selected(key: Option<&str>) -> bool {
	image_selected(JOB_LIFECYCLE_PATH, JOB_LIFECYCLE_SHA) && key.is_some_and(hia_job_key)
}

#[derive(Debug)]
pub(super) enum JobStatusUnavailable {
	Poll,
	Terminal,
	Lifecycle,
}

impl std::fmt::Display for JobStatusUnavailable {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(match self {
			Self::Poll => "HIA job observation unavailable",
			Self::Terminal => "HIA terminal job state unavailable",
			Self::Lifecycle => "HIA systemd lifecycle state unavailable",
		})
	}
}

impl std::error::Error for JobStatusUnavailable {}

pub(super) enum JobLifecycle {
	OwnerUnavailable,
	IncarnationChanged,
	ProcessChanged,
	Running,
	AwaitingExitWitness,
	Failed,
	Exited(bool),
	CompletedUnknown,
	AwaitingMissingWitness,
	Finalizing,
	AwaitingWitness,
	Other,
}

pub(super) fn job_lifecycle_image() -> Result<&'static File> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	IMAGE
		.get_or_init(|| {
			admit_executable(JOB_LIFECYCLE_PATH, JOB_LIFECYCLE_SHA)
				.map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|_| JobStatusUnavailable::Lifecycle.into())
}

pub(super) async fn job_lifecycle_owner(numbers: [u64; 4], fields: [&str; 13]) -> Result<[u64; 3]> {
	use JobStatusUnavailable::Lifecycle;
	ensure!(fields.iter().all(|field| field.len() <= 256), Lifecycle);
	let image = job_lifecycle_image()?;
	let mut frame = Vec::with_capacity(144 + fields.iter().map(|field| field.len()).sum::<usize>());
	frame.extend_from_slice(b"HIAJOQ01");
	for field in numbers
		.into_iter()
		.chain(fields.map(|field| field.len() as u64))
	{
		frame.extend_from_slice(&field.to_le_bytes());
	}
	for field in fields {
		frame.extend_from_slice(field.as_bytes());
	}
	let (status, output) = run_filter(image, &frame, 32).await.context(Lifecycle)?;
	ensure!(
		status.success() && output.len() == 32 && output.starts_with(b"HIAJOR01"),
		Lifecycle
	);
	let mut facts = [0; 3];
	for (fact, bytes) in facts.iter_mut().zip(output[8..].chunks_exact(8)) {
		*fact = u64::from_le_bytes(bytes.try_into().context(Lifecycle)?);
	}
	ensure!(
		facts[0] <= 1 && facts[1] <= 1 && matches!(facts[2], 1 | 2),
		Lifecycle
	);
	tracing::info!("Native HIA admitted raw systemd supervisor observations");
	Ok(facts)
}

pub(super) async fn job_lifecycle(facts: [u64; 6], properties: [&str; 3]) -> Result<JobLifecycle> {
	use JobLifecycle::*;
	use JobStatusUnavailable::Lifecycle;
	let image = job_lifecycle_image()?;
	ensure!(properties.iter().all(|value| value.len() <= 128), Lifecycle);
	let mut frame =
		Vec::with_capacity(80 + properties.iter().map(|value| value.len()).sum::<usize>());
	frame.extend_from_slice(b"HIAJSS01");
	for value in facts
		.into_iter()
		.chain(properties.map(|value| value.len() as u64))
	{
		frame.extend_from_slice(&value.to_le_bytes());
	}
	for value in properties {
		frame.extend_from_slice(value.as_bytes());
	}
	let (status, output) = run_filter(image, &frame, 16).await.context(Lifecycle)?;
	ensure!(
		status.success() && output.len() == 16 && output.starts_with(b"HIAJSV01"),
		Lifecycle
	);
	let state = match u64::from_le_bytes(output[8..16].try_into()?) {
		1 => OwnerUnavailable,
		2 => IncarnationChanged,
		3 => ProcessChanged,
		4 => Running,
		5 => AwaitingExitWitness,
		6 => Failed,
		7 => Exited(true),
		8 => Exited(false),
		9 => CompletedUnknown,
		10 => AwaitingMissingWitness,
		11 => Finalizing,
		12 => AwaitingWitness,
		13 => Other,
		_ => return Err(Lifecycle.into()),
	};
	tracing::info!("Native HIA classified a live systemd lifecycle snapshot");
	Ok(state)
}

pub(super) fn job_terminal_image() -> Result<&'static File> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	IMAGE
		.get_or_init(|| {
			admit_executable(JOB_TERMINAL_PATH, JOB_TERMINAL_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|_| JobStatusUnavailable::Terminal.into())
}

pub(super) async fn job_terminal_state(facts: [u64; 6]) -> Result<Option<&'static str>> {
	let image = job_terminal_image()?;
	let mut frame = [0_u8; 56];
	frame[..8].copy_from_slice(b"HIAJTS01");
	for (field, value) in frame[8..].chunks_exact_mut(8).zip(facts) {
		field.copy_from_slice(&value.to_le_bytes());
	}
	let (status, output) = run_filter(image, &frame, 16)
		.await
		.context(JobStatusUnavailable::Terminal)?;
	ensure!(status.success(), JobStatusUnavailable::Terminal);
	let state = decode_job_terminal_state(&output)?;
	tracing::info!("Native HIA classified a terminal job receipt");
	Ok(state)
}

pub(super) async fn job_terminal_state_from_receipt(raw: &[u8]) -> Result<Option<&'static str>> {
	use JobStatusUnavailable::Terminal;
	ensure!((2..=(1 << 20)).contains(&raw.len()), Terminal);
	let image = super::hia_controller_release::image(JOB_TERMINAL_RECEIPT_PATH)
		.ok_or(Terminal)?
		.context(Terminal)?;
	let (status, output) = run_filter(&image, raw, 24).await.context(Terminal)?;
	ensure!(status.success() && output.len() >= 8, Terminal);
	let extent = u64::from_le_bytes(output[..8].try_into()?);
	if output.len() == 8 && matches!(extent, 0xfffffff0 | 0xfffffffc..=0xffffffff) {
		return Ok(None);
	}
	ensure!(extent == 16, Terminal);
	let state = decode_job_terminal_state(&output[8..])?;
	tracing::info!("Native HIA classified an exact witnessed terminal receipt");
	Ok(state)
}

fn decode_job_terminal_state(data: &[u8]) -> Result<Option<&'static str>> {
	use JobStatusUnavailable::Terminal;
	ensure!(data.len() == 16 && data.starts_with(b"HIAJTV01"), Terminal);
	let state = match u64::from_le_bytes(data[8..16].try_into()?) {
		0 => None,
		1 => Some("effect_unknown"),
		2 => Some("timed_out"),
		3 => Some("cancelled"),
		4 => Some("failed"),
		5 => Some("succeeded"),
		_ => return Err(Terminal.into()),
	};
	Ok(state)
}

pub(super) async fn job_poll_window(wait_seconds: u64) -> Result<Duration> {
	let decision = job_poll(0, wait_seconds, 0, None, false)
		.await
		.context(JobStatusUnavailable::Poll)?;
	ensure!(decision <= 30, JobStatusUnavailable::Poll);
	Ok(Duration::from_secs(decision))
}

pub(super) enum JobPollDecision {
	Finish,
	PollAfter(Duration),
	MarkLost,
}

pub(super) async fn job_poll_decision(
	window: Duration,
	elapsed: Duration,
	state: Option<&str>,
	operator_status: bool,
	unconfirmed: bool,
) -> Result<JobPollDecision> {
	let nanoseconds = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
	let stage = if operator_status { 2 } else { 1 };
	let raw = job_poll(stage, window.as_secs(), nanoseconds, state, unconfirmed)
		.await
		.context(JobStatusUnavailable::Poll)?;
	let decision = match raw {
		0 => JobPollDecision::Finish,
		100 => JobPollDecision::PollAfter(Duration::from_millis(raw)),
		101 if operator_status => JobPollDecision::MarkLost,
		_ => return Err(JobStatusUnavailable::Poll.into()),
	};
	tracing::info!("Native HIA decided a systemd job observation");
	Ok(decision)
}

async fn job_poll(
	stage: u64,
	wait_seconds: u64,
	age_ns: u64,
	state: Option<&str>,
	unconfirmed: bool,
) -> Result<u64> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| {
			admit_executable(JOB_POLL_PATH, JOB_POLL_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA job observation admission failed: {error}"))?;
	// Copy an opaque bounded prefix; HIA owns the exact state comparison.
	let bytes = state.unwrap_or_default().as_bytes();
	let count = bytes.len().min(24);
	let mut frame = [0_u8; 72];
	frame[..8].copy_from_slice(b"HIAJPL01");
	frame[8..16].copy_from_slice(&stage.to_le_bytes());
	frame[16..24].copy_from_slice(&wait_seconds.to_le_bytes());
	frame[24..32].copy_from_slice(&age_ns.to_le_bytes());
	frame[32..40].copy_from_slice(&(count as u64).to_le_bytes());
	frame[40..48].copy_from_slice(&u64::from(unconfirmed).to_le_bytes());
	frame[48..48 + count].copy_from_slice(&bytes[..count]);
	let (status, output) = run_filter(image, &frame, 24).await?;
	ensure!(
		status.success()
			&& output.len() == 24
			&& output.starts_with(b"HIAJPO01")
			&& output[8..16] == stage.to_le_bytes(),
		"invalid HIA job observation response"
	);
	Ok(u64::from_le_bytes(output[16..24].try_into()?))
}

pub(super) fn launch_ack_image() -> Result<&'static File> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	IMAGE
		.get_or_init(|| {
			admit_executable(LAUNCH_ACK_PATH, LAUNCH_ACK_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA launch acknowledgement admission failed: {error}"))
}

/// Transport JSON typing is preserved. This adapter does not compare or
/// normalize backend names, state names, or the received job/unit identity.
pub(super) async fn launch_ack(
	isolated_jobctl: bool,
	job_id: &str,
	unit: &str,
	ack: &serde_json::Value,
) -> Result<Option<&'static str>> {
	const SLOT: usize = 256;
	const FIELD_COUNT: usize = 6;
	ensure!(
		job_id.len() <= SLOT && unit.len() <= SLOT,
		"HIA launch identity exceeds acknowledgement bounds"
	);
	let image = launch_ack_image()?;
	let reported_job = ack.pointer("/status/job_id");
	let flags = u64::from(ack["ok"] == true)
		| (u64::from(isolated_jobctl) << 1)
		| (u64::from(ack["reused_remote"] == true) << 2)
		| (u64::from(reported_job.is_some()) << 3);
	let fields: [Option<&str>; FIELD_COUNT] = [
		ack["backend"].as_str(),
		reported_job.and_then(serde_json::Value::as_str),
		Some(job_id),
		ack["unit"].as_str(),
		Some(unit),
		ack.pointer("/status/launch_state")
			.and_then(serde_json::Value::as_str),
	];
	let mut frame = [0_u8; 24 + FIELD_COUNT * (8 + SLOT)];
	frame[..8].copy_from_slice(b"HIAJAK01");
	frame[8..16].copy_from_slice(&flags.to_le_bytes());
	let pid = ack["launcher_pid"].as_u64().unwrap_or(0);
	frame[16..24].copy_from_slice(&pid.to_le_bytes());
	for (field, slot) in fields
		.into_iter()
		.zip(frame[24..].chunks_exact_mut(8 + SLOT))
	{
		// Oversized remote strings cannot match any admissible reference
		// or recognized state. Keep presence independent of string length.
		if let Some(field) = field.filter(|value| value.len() <= SLOT) {
			slot[..8].copy_from_slice(&(field.len() as u64).to_le_bytes());
			slot[8..8 + field.len()].copy_from_slice(field.as_bytes());
		}
	}
	let (status, output) = run_filter(image, &frame, 16).await?;
	ensure!(
		status.success()
			&& output.len() == 16
			&& output.starts_with(b"HIAJAO01")
			&& output[9..].iter().all(|&byte| byte == 0),
		"invalid HIA launch acknowledgement response"
	);
	let state = match output[8] {
		0 => None,
		1 => Some("launched"),
		2 => Some("launch_failed"),
		3 => Some("pending"),
		4 => Some("cancelled"),
		5 => Some("launch_unknown"),
		_ => bail!("invalid HIA launch acknowledgement decision"),
	};
	tracing::info!("Native HIA classified a durable launch acknowledgement");
	Ok(state)
}

fn job_image() -> Result<&'static File> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	IMAGE
		.get_or_init(|| admit_executable(JOB_PATH, JOB_SHA).map_err(|error| error.to_string()))
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA job identity admission failed: {error}"))
}

pub(super) async fn job_identity(binding: &[u8]) -> Result<String> {
	let image = job_image()?;
	ensure!(
		binding.len() <= JOB_FRAME_MAX - 8,
		"HIA job binding exceeds native limit"
	);
	let mut frame = Vec::with_capacity(8 + binding.len());
	frame.extend_from_slice(b"HIAJID01");
	frame.extend_from_slice(binding);
	let (status, output) = run_filter(image, &frame, JOB_FRAME_OUT).await?;
	ensure!(
		status.success()
			&& output.len() == JOB_FRAME_OUT
			&& output.starts_with(b"HIAJDO01")
			&& valid_digest(&output[8..]),
		"HIA native job identity refused the binding"
	);
	Ok(std::str::from_utf8(&output[8..])?.to_owned())
}

pub(super) enum JobReuse {
	Matching,
	Different,
	LegacyDigestMissing,
}

pub(super) async fn job_reuse(
	fingerprint: u64,
	expected: &str,
	stored: Option<&str>,
) -> Result<JobReuse> {
	ensure!(
		valid_digest(expected.as_bytes()),
		"invalid prepared HIA job digest"
	);
	let mut frame = Vec::with_capacity(152);
	frame.extend_from_slice(b"HIAJRE01");
	frame.extend_from_slice(&fingerprint.to_le_bytes());
	frame.extend_from_slice(&u64::from(stored.is_some()).to_le_bytes());
	frame.extend_from_slice(expected.as_bytes());
	if let Some(value) = stored.filter(|value| value.len() == 64) {
		frame.extend_from_slice(value.as_bytes());
	}
	let (status, output) = run_filter(job_image()?, &frame, REUSE_FRAME_OUT).await?;
	ensure!(
		status.success()
			&& output.len() == REUSE_FRAME_OUT
			&& output.starts_with(b"HIAJRO01")
			&& output[9..].iter().all(|&byte| byte == 0),
		"HIA native job reuse refused the binding"
	);
	match output[8] {
		0 => Ok(JobReuse::Matching),
		1 => Ok(JobReuse::Different),
		2 => Ok(JobReuse::LegacyDigestMissing),
		_ => bail!("invalid HIA native job reuse decision"),
	}
}

pub(super) fn http_auth_selected() -> bool {
	image_selected(HTTP_AUTH_PATH, HTTP_AUTH_SHA)
}

pub(super) async fn http_auth(expected: &[u8; 32], candidate: &[u8]) -> Result<bool> {
	if !(32..=4096).contains(&candidate.len()) {
		return Ok(false);
	}
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| {
			admit_executable(HTTP_AUTH_PATH, HTTP_AUTH_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|_| anyhow::anyhow!("HIA HTTP credential verifier unavailable"))?;
	const HEX: &[u8; 16] = b"0123456789abcdef";
	let mut frame = Vec::with_capacity(72 + candidate.len());
	frame.extend_from_slice(b"HIAHAT01");
	for byte in expected {
		frame.push(HEX[(byte >> 4) as usize]);
		frame.push(HEX[(byte & 15) as usize]);
	}
	frame.extend_from_slice(candidate);
	let (status, output) = run_filter(image, &frame, 16).await?;
	ensure!(
		status.success()
			&& output.len() == 16
			&& output.starts_with(b"HIAHAO01")
			&& output[9..].iter().all(|&byte| byte == 0),
		"invalid HIA HTTP credential-verification response"
	);
	match output[8] {
		0 => Ok(false),
		1 => Ok(true),
		_ => bail!("invalid HIA HTTP credential verdict"),
	}
}

pub(super) fn session_scope_selected() -> bool {
	image_selected(SCOPE_PATH, SCOPE_SHA)
}

pub(super) async fn session_scope(
	http: bool,
	candidate: Option<&str>,
	previous: Option<(bool, &str)>,
) -> Result<()> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| admit_executable(SCOPE_PATH, SCOPE_SHA).map_err(|error| error.to_string()))
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA session authority admission failed: {error}"))?;
	let mut frame = [0_u8; 160];
	frame[..8].copy_from_slice(b"HIASCO01");
	frame[8..16].copy_from_slice(&u64::from(http).to_le_bytes());
	let candidate = candidate.unwrap_or_default().as_bytes();
	frame[16..24].copy_from_slice(&(candidate.len() as u64).to_le_bytes());
	if candidate.len() == 64 {
		frame[32..96].copy_from_slice(candidate);
	}
	if let Some((authenticated, owner)) = previous {
		ensure!(owner.len() == 64, "invalid bound HIA session owner");
		frame[24..32].copy_from_slice(&(1 + u64::from(authenticated)).to_le_bytes());
		frame[96..160].copy_from_slice(owner.as_bytes());
	}
	let (status, output) = run_filter(image, &frame, SCOPE_FRAME_OUT).await?;
	ensure!(
		status.success()
			&& output.len() == SCOPE_FRAME_OUT
			&& output.starts_with(b"HIASCR01")
			&& output[9..].iter().all(|&byte| byte == 0),
		"HIA native session authority returned an invalid decision"
	);
	match output[8] {
		0 => Ok(()),
		1 => bail!("authenticated operator scope unavailable; dispatch refused"),
		2 => bail!("native session entropy unavailable"),
		3 => bail!("session credential authority changed; dispatch refused"),
		_ => bail!("unknown HIA native session authority decision"),
	}
}

#[derive(Debug)]
pub(super) enum JobTransition {
	ObserveLocked,
	ObserveUnlocked,
	ReconcileKnownJob,
}

pub(super) async fn job_transition(
	allow_reconcile: bool,
	system_jobctl: bool,
	isolated: bool,
	state: &str,
) -> Result<JobTransition> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| {
			admit_executable(TRANSITION_PATH, TRANSITION_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA job transition admission failed: {error}"))?;
	let flags =
		u64::from(allow_reconcile) | (u64::from(system_jobctl) << 1) | (u64::from(isolated) << 2);
	let mut frame = [0_u8; 80];
	frame[..8].copy_from_slice(b"HIAJTR01");
	frame[8..16].copy_from_slice(&flags.to_le_bytes());
	if state.len() <= 56 {
		frame[16..24].copy_from_slice(&(state.len() as u64).to_le_bytes());
		frame[24..24 + state.len()].copy_from_slice(state.as_bytes());
	}
	let (status, output) = run_filter(image, &frame, 16).await?;
	ensure!(
		status.success()
			&& output.len() == 16
			&& output.starts_with(b"HIAJTO01")
			&& output[9..].iter().all(|&byte| byte == 0),
		"HIA native job transition returned an invalid decision"
	);
	match output[8] {
		0 => Ok(JobTransition::ObserveLocked),
		1 => Ok(JobTransition::ObserveUnlocked),
		2 if flags == 7 => Ok(JobTransition::ReconcileKnownJob),
		_ => bail!("HIA native job transition exceeds admitted authority"),
	}
}

async fn run_filter(image: &File, frame: &[u8], cap: usize) -> Result<(ExitStatus, Vec<u8>)> {
	let mut input = sealed(c"hia-worker-identity-frame", frame, false)?;
	input.seek(SeekFrom::Start(0))?;
	let mut child = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()))
		.env_clear()
		.kill_on_drop(true)
		.stdin(Stdio::from(input))
		.stdout(Stdio::piped())
		.stderr(Stdio::null())
		.spawn()?;
	let stdout = child
		.stdout
		.take()
		.context("missing native HIA identity output")?;
	timeout(Duration::from_secs(5), async {
		let mut bytes = Vec::new();
		stdout
			.take((cap + 1) as u64)
			.read_to_end(&mut bytes)
			.await?;
		ensure!(
			bytes.len() <= cap,
			"native HIA identity output exceeds its bound"
		);
		Ok((child.wait().await?, bytes))
	})
	.await
	.context("native HIA identity filter timed out")?
}

fn valid_digest(value: &[u8]) -> bool {
	value.len() == 64
		&& value
			.iter()
			.all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn frame_result(output: &[u8]) -> Result<EncodedRequest> {
	ensure!(
		output.len() > PREFIX_BYTES + 2 && output.starts_with(b"HIAWPO01"),
		"invalid HIA Worker encoder frame"
	);
	let digest = |start| -> Result<String> {
		let value = &output[start..start + 64];
		ensure!(valid_digest(value), "invalid HIA Worker encoder digest");
		Ok(std::str::from_utf8(value)?.to_owned())
	};
	let stdin = &output[PREFIX_BYTES..];
	ensure!(
		stdin.starts_with(b"{")
			&& stdin.ends_with(b"}\n")
			&& !stdin[..stdin.len() - 1].contains(&b'\n'),
		"invalid HIA Worker encoder request"
	);
	Ok(EncodedRequest {
		transport_arguments_sha256: digest(8)?,
		profile_sha256: digest(72)?,
		request_sha256: digest(136)?,
		idempotency_digest: digest(200)?,
		stdin: std::str::from_utf8(stdin)?.into(),
	})
}
