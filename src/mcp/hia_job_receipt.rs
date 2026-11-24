// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pass a sealed record to the pinned HIA publisher without transferring path authority.

use std::{
	fs::OpenOptions,
	os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
	path::Path,
	process::{Command, Stdio},
	sync::OnceLock,
};

use anyhow::{Context, Result, ensure};

use super::{
	hia_request_prepare::hia_job_key,
	hia_wire_candidate::{admit_executable, image_selected, sealed},
};

pub(super) const PATH: &str = "HIA_LOCAL_MCP_JOB_RECEIPT_IMAGE";
const PIN: &str = "HIA_LOCAL_MCP_JOB_RECEIPT_SHA256";

pub(super) fn selected(key: Option<&str>) -> bool {
	key.is_some_and(hia_job_key) && image_selected(PATH, PIN)
}

pub(super) fn publish(path: &Path, id: &str, record: &[u8]) -> Result<()> {
	static IMAGE: OnceLock<Result<std::fs::File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| admit_executable(PATH, PIN).map_err(|error| error.to_string()))
		.as_ref()
		.map_err(|error| anyhow::anyhow!("HIA job receipt publisher admission failed: {error}"))?;
	let directory = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
		.open(
			path.parent()
				.context("durable job path has no registry directory")?,
		)?;
	let mut frame = Vec::with_capacity(32 + id.len() + record.len());
	frame.extend_from_slice(b"HIAJRQ01");
	frame.extend_from_slice(&(record.len() as u64).to_le_bytes());
	frame.extend_from_slice(&u64::from(std::process::id()).to_le_bytes());
	frame.extend_from_slice(&(id.len() as u64).to_le_bytes());
	frame.extend_from_slice(id.as_bytes());
	frame.extend_from_slice(record);
	let input = sealed(c"hia-job-receipt-frame", &frame, false)?;
	let result = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()))
		.env_clear()
		.stdin(Stdio::from(input))
		.stdout(Stdio::from(directory))
		.stderr(Stdio::piped())
		.output()
		.context("could not invoke the admitted HIA job receipt publisher")?;
	// A lost acknowledgement may follow a rename. Never re-invoke the publisher
	// or fall back to the Rust writer after entering this boundary.
	ensure!(
		result.status.success()
			&& result.stderr.len() == 24
			&& result.stderr.starts_with(b"HIAJRW01"),
		"HIA job receipt publication did not return a complete acknowledgement"
	);
	let phase = u64::from_le_bytes(result.stderr[8..16].try_into()?);
	let status = i64::from_le_bytes(result.stderr[16..24].try_into()?);
	if (1..=6).contains(&phase) && (-4095..=-1).contains(&status) {
		return Err(std::io::Error::from_raw_os_error((-status) as i32).into());
	}
	ensure!(
		phase == 6 && status == 0,
		"invalid HIA job receipt acknowledgement"
	);
	tracing::info!("Native HIA durably published a local job record");
	Ok(())
}
