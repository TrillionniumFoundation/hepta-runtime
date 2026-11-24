// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Mechanical transport for the complete administrator-bound native job bundle.
//! HIA retains submission, observation, cancellation and launcher semantics.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::config::{HostConfig, NativeJobEntries, Platform};

pub(super) enum NativeJobOperation<'a> {
	Submit(&'a Value),
	Read(&'a Value),
	Status(&'a Value),
	Cancel(&'a Value),
}

pub(super) struct PreparedNativeJob {
	pub command: String,
	pub input: NativeJobInput,
}

/// The immutable Store image is shared across queued requests. The original
/// 64 KiB observation command/control budget is not enlarged by the image.
pub(super) struct NativeJobInput {
	header: [u8; 96],
	image: Arc<[u8]>,
	payload: Vec<u8>,
}

impl NativeJobInput {
	pub(super) fn validate_observation(&self, command: &str) -> Result<()> {
		ensure!(
			self.header[8..16] == 2u64.to_le_bytes(),
			"only typed native observations enter the observation pool"
		);
		ensure!(
			command
				.len()
				.checked_add(self.header.len())
				.and_then(|size| size.checked_add(self.payload.len()))
				.is_some_and(|size| size <= 65_536),
			"observation_pool_payload_unsupported: native command and control exceed64KiB; no fallback"
		);
		ensure!(
			(64..=4_194_304).contains(&self.image.len()),
			"invalid shared native observation image extent"
		);
		Ok(())
	}

	pub(super) fn wire(&self) -> Result<Vec<u8>> {
		let size = self
			.header
			.len()
			.checked_add(self.image.len())
			.and_then(|size| size.checked_add(self.payload.len()))
			.context("native job frame extent overflow")?;
		let mut wire = Vec::with_capacity(size);
		wire.extend_from_slice(&self.header);
		wire.extend_from_slice(&self.image);
		wire.extend_from_slice(&self.payload);
		Ok(wire)
	}

	pub(super) async fn write_to<W: AsyncWrite + Unpin>(
		&self,
		writer: &mut W,
	) -> std::io::Result<()> {
		writer.write_all(&self.header).await?;
		writer.write_all(&self.image).await?;
		writer.write_all(&self.payload).await
	}
}

#[cfg(target_os = "linux")]
fn artifact(name: &str, expected: &str) -> Result<Arc<[u8]>> {
	crate::mcp::hia_controller_release::native_job_artifact(name, expected)
}
#[cfg(not(target_os = "linux"))]
fn artifact(_name: &str, _expected: &str) -> Result<Arc<[u8]>> {
	bail!("native job transport requires Linux; no Python fallback")
}

#[cfg(target_os = "linux")]
fn artifact_pin(name: &str) -> Result<String> {
	crate::mcp::hia_controller_release::native_job_artifact_sha256(name)
}
#[cfg(not(target_os = "linux"))]
fn artifact_pin(_name: &str) -> Result<String> {
	bail!("native job transport requires Linux; no Python fallback")
}

fn helper(name: &str) -> Result<(String, Arc<[u8]>)> {
	let pin = artifact_pin(name)?;
	let image = artifact(name, &pin)?;
	ensure!(
		(64..=1_048_576).contains(&image.len()),
		"native helper {name} exceeds its existing image bound"
	);
	Ok((pin, image))
}

pub(super) fn prepare(
	host: &HostConfig,
	operation: NativeJobOperation<'_>,
) -> Result<PreparedNativeJob> {
	ensure!(
		host.platform == Platform::Linux,
		"native job transport requires Linux; no fallback"
	);
	let entries = host
		.native_jobs
		.as_ref()
		.context("native job profile was not configured")?;
	entries.validate()?;
	ensure!(
		crate::mcp::hia_controller_release::has_native_job_transport(),
		"native job transport requires an admitted v26 controller; no fallback"
	);
	// Admission covers the whole selected bundle. A broken unused role must not
	// silently turn a supposedly complete native-only profile into a partial one.
	for (role, pin) in entries.roles() {
		artifact(role, &pin.sha256)?;
	}
	let (kind, role, pin, payload) = match operation {
		NativeJobOperation::Submit(request) => (
			1,
			"hia-job-submit",
			&entries.submit.sha256,
			submit_payload(request, entries)?,
		),
		NativeJobOperation::Read(request) => (
			2,
			"hia-job-observation",
			&entries.observation.sha256,
			observation_payload(request, false)?,
		),
		NativeJobOperation::Status(request) => (
			2,
			"hia-job-observation",
			&entries.observation.sha256,
			observation_payload(request, true)?,
		),
		NativeJobOperation::Cancel(request) => (
			3,
			"hia-job-cancel",
			&entries.cancel.sha256,
			cancel_payload(request)?,
		),
	};
	let image = artifact(role, pin)?;
	ensure!(
		(64..=4_194_304).contains(&image.len()),
		"native target image exceeds entry bound"
	);
	let mut header = [0u8; 96];
	header[..8].copy_from_slice(b"HIAJEX01");
	header[8..16].copy_from_slice(&u64::to_le_bytes(kind));
	header[16..24].copy_from_slice(&(image.len() as u64).to_le_bytes());
	header[24..32].copy_from_slice(&(payload.len() as u64).to_le_bytes());
	header[32..96].copy_from_slice(pin.as_bytes());
	Ok(PreparedNativeJob {
		command: super::ssh::shell_quote(&entries.entry.executable),
		input: NativeJobInput {
			header,
			image,
			payload,
		},
	})
}

fn string<'a>(request: &'a Value, name: &str) -> Result<&'a str> {
	request.get(name).and_then(Value::as_str).with_context(|| {
		format!("native-only job profile requires a complete {name} binding; no legacy fallback")
	})
}

fn integer(request: &Value, name: &str) -> Result<u64> {
	request
		.get(name)
		.and_then(Value::as_u64)
		.with_context(|| format!("native job {name} must be an unsigned integer"))
}

fn binding(request: &Value) -> Result<[&[u8]; 4]> {
	let fields = [
		string(request, "job_dir")?,
		string(request, "job_id")?,
		string(request, "unit")?,
		string(request, "request_digest")?,
	];
	ensure!(
		fields
			.iter()
			.all(|value| !value.is_empty() && !value.as_bytes().contains(&0)),
		"native job binding contains an empty or NUL field"
	);
	ensure!(
		fields
			.iter()
			.try_fold(0usize, |total, field| total.checked_add(field.len()))
			.is_some_and(|total| total <= 65_536 - 80),
		"native job binding exceeds control bound"
	);
	Ok(fields.map(str::as_bytes))
}

fn words(output: &mut Vec<u8>, values: &[u64]) {
	for value in values {
		output.extend_from_slice(&value.to_le_bytes());
	}
}

fn observation_payload(request: &Value, status: bool) -> Result<Vec<u8>> {
	let fields = binding(request)?;
	let (mode, stdout, stderr, limit, flags) = if status {
		ensure!(
			integer(request, "wait_seconds")? == 0,
			"native status is an immediate snapshot; the existing HIA poller must own waiting"
		);
		for flag in [
			"hia_status_snapshot",
			"hia_status_terminal_facts",
			"hia_status_terminal_witness",
			"hia_status_native_receipt",
			"hia_status_lifecycle_facts",
			"hia_status_lifecycle_owner",
		] {
			ensure!(
				request.get(flag) == Some(&Value::Bool(true)),
				"native status requires all six HIA facts; unsupported legacy profile, no fallback"
			);
		}
		(1, 0, 0, 16_384, 63)
	} else {
		(
			0,
			integer(request, "stdout_offset")?,
			integer(request, "stderr_offset")?,
			integer(request, "limit")?,
			0,
		)
	};
	let mut payload = b"HIAJOBQ1".to_vec();
	words(
		&mut payload,
		&[
			mode,
			stdout,
			stderr,
			limit,
			fields[0].len() as u64,
			fields[1].len() as u64,
			fields[2].len() as u64,
			fields[3].len() as u64,
			flags,
		],
	);
	for field in fields {
		payload.extend_from_slice(field);
	}
	Ok(payload)
}

fn raw_sha(pin: &str) -> Result<[u8; 32]> {
	ensure!(
		pin.len() == 64
			&& pin
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
		"invalid native image digest"
	);
	let mut result = [0u8; 32];
	for (index, pair) in pin.as_bytes().chunks_exact(2).enumerate() {
		let digit = |byte: u8| {
			if byte <= b'9' {
				byte - b'0'
			} else {
				byte - b'a' + 10
			}
		};
		result[index] = (digit(pair[0]) << 4) | digit(pair[1]);
	}
	Ok(result)
}

fn cancel_payload(request: &Value) -> Result<Vec<u8>> {
	let fields = binding(request)?;
	let grace = integer(request, "grace_seconds")?
		.checked_mul(1_000_000_000)
		.context("native cancellation grace extent overflow")?;
	let (authority_pin, authority) = helper("hia-worker-prepare")?;
	let (writer_pin, writer) = helper("hia-job-receipt")?;
	let mut payload = b"HIAJCQ02".to_vec();
	words(
		&mut payload,
		&[
			grace,
			authority.len() as u64,
			writer.len() as u64,
			0,
			fields[0].len() as u64,
			fields[1].len() as u64,
			fields[2].len() as u64,
			fields[3].len() as u64,
			0,
		],
	);
	for field in fields {
		payload.extend_from_slice(field);
	}
	payload.extend_from_slice(&raw_sha(&authority_pin)?);
	payload.extend_from_slice(&raw_sha(&writer_pin)?);
	payload.extend_from_slice(&authority);
	payload.extend_from_slice(&writer);
	ensure!(
		payload.len() <= 2_162_688,
		"native cancellation payload exceeds entry bound"
	);
	Ok(payload)
}

const NATIVE_SUBMIT_FLAGS: [&str; 16] = [
	"hia_terminal_supervisor",
	"hia_owner_publication",
	"hia_workdir_authority",
	"hia_loop_authority",
	"hia_group_authority",
	"hia_child_publication",
	"hia_original_child_wait",
	"hia_native_output_capture",
	"hia_workload_spawn",
	"hia_supervisor_identity",
	"hia_owner_lock_admission",
	"hia_owner_record_encoding",
	"hia_owner_file_lock",
	"hia_owner_marker_observation",
	"hia_owner_custody",
	"hia_native_job_owner",
];

fn submit_payload(request: &Value, entries: &NativeJobEntries) -> Result<Vec<u8>> {
	for flag in NATIVE_SUBMIT_FLAGS {
		ensure!(
			request.get(flag) == Some(&Value::Bool(true)),
			"native-only submission requires the complete HIA authority profile ({flag}); no legacy fallback"
		);
	}
	let stdin = match request.get("stdin") {
		None | Some(Value::Null) => None,
		Some(Value::String(value)) => Some(value.as_bytes()),
		_ => bail!("native job stdin must be an optional string"),
	};
	ensure!(
		stdin.is_none_or(|value| value.len() <= 536_870_912),
		"native job stdin exceeds its existing 512 MiB bound"
	);
	let (encoder_pin, encoder) = helper("hia-worker-prepare")?;
	let (writer_pin, writer) = helper("hia-job-receipt")?;
	let (supervisor_pin, supervisor) = helper("hia-job-supervisor")?;
	let launcher = artifact("hia-job-launch", &entries.launcher.sha256)?;
	ensure!(
		(64..=1_048_576).contains(&launcher.len()),
		"native launcher exceeds its existing image bound"
	);
	let mut metadata = request
		.as_object()
		.context("native submission request must be an object")?
		.clone();
	metadata.remove("stdin");
	metadata.remove("hia_terminal_publication_artifacts");
	metadata.insert(
		"hia_terminal_publisher".into(),
		json!({"encoder":encoder_pin,"writer":writer_pin,"supervisor":supervisor_pin}),
	);
	metadata.insert(
		"hia_job_launcher_sha256".into(),
		json!(entries.launcher.sha256),
	);
	metadata.insert("hia_job_entry_path".into(), json!(entries.entry.executable));
	let metadata = serde_json::to_vec(&metadata)?;
	ensure!(
		metadata.len() <= 4_194_304,
		"native job metadata exceeds its existing 4 MiB bound"
	);
	let mut payload = b"HIAJSB01".to_vec();
	words(
		&mut payload,
		&[
			metadata.len() as u64,
			stdin.map_or(u64::MAX, |value| value.len() as u64),
			encoder.len() as u64,
			writer.len() as u64,
			supervisor.len() as u64,
			launcher.len() as u64,
			0,
		],
	);
	payload.extend_from_slice(&metadata);
	for image in [&encoder, &writer, &supervisor, &launcher] {
		payload.extend_from_slice(image);
	}
	if let Some(stdin) = stdin {
		payload.extend_from_slice(stdin);
	}
	ensure!(
		payload.len() <= 545_259_584,
		"native job submission exceeds entry bound"
	);
	Ok(payload)
}

#[cfg(test)]
#[path = "native_jobs_tests.rs"]
mod native_jobs_tests;
