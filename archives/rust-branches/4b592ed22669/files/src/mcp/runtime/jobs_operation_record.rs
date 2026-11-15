// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Keep only validated routing data while an observation or cancellation awaits its host.
use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct OperationRecord {
	pub(super) execution_mode: ExecutionMode,
	pub(super) system_jobctl: bool,
	pub(super) id: String,
	pub(super) host: String,
	pub(super) ssh_target: String,
	pub(super) unit: String,
	pub(super) remote_job_dir: String,
	pub(super) request_digest: Option<String>,
}

/// The existing start/reuse paths borrow the same fields without changing their owned receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OperationRecordRef<'a> {
	pub(super) execution_mode: ExecutionMode,
	pub(super) system_jobctl: bool,
	pub(super) id: &'a str,
	pub(super) host: &'a str,
	pub(super) ssh_target: &'a str,
	pub(super) unit: &'a str,
	pub(super) remote_job_dir: &'a str,
	pub(super) request_digest: Option<&'a str>,
}

impl<'a> From<&'a JobRecord> for OperationRecordRef<'a> {
	fn from(record: &'a JobRecord) -> Self {
		Self {
			execution_mode: record.execution_mode,
			system_jobctl: record.system_jobctl,
			id: &record.id,
			host: &record.host,
			ssh_target: &record.ssh_target,
			unit: &record.unit,
			remote_job_dir: &record.remote_job_dir,
			request_digest: record.request_digest.as_deref(),
		}
	}
}

impl<'a> From<&'a OperationRecord> for OperationRecordRef<'a> {
	fn from(record: &'a OperationRecord) -> Self {
		Self {
			execution_mode: record.execution_mode,
			system_jobctl: record.system_jobctl,
			id: &record.id,
			host: &record.host,
			ssh_target: &record.ssh_target,
			unit: &record.unit,
			remote_job_dir: &record.remote_job_dir,
			request_digest: record.request_digest.as_deref(),
		}
	}
}

pub(super) fn read_operation_record_at(path: &Path, expected_id: &str) -> Result<OperationRecord> {
	with_record_read_buffer(&mut Vec::new(), |bytes| {
		// The shared decoder validates every field and descriptor before this projection.
		// No input buffer or discarded payload survives into a remote await.
		let record = read_operation_record_at_into(path, expected_id, bytes)?;
		Ok(OperationRecord {
			execution_mode: record.execution_mode,
			system_jobctl: record.system_jobctl,
			id: record.id,
			host: record.host,
			ssh_target: record.ssh_target.into_owned(),
			unit: record.unit.into_owned(),
			remote_job_dir: record.remote_job_dir.into_owned(),
			request_digest: record.request_digest.map(BorrowedJobString::into_owned),
		})
	})
}

pub(super) fn check_operation_ref(params: &ProcessRefParams) -> Result<OperationRecord> {
	let record = read_operation_record_at(&record_path(&params.job_id)?, &params.job_id)
		.with_context(|| format!("unknown or invalid durable job `{}`", params.job_id))?;
	check_binding(&record)?;
	if record.host != params.host {
		bail!(
			"job `{}` belongs to host `{}`, not `{}`",
			params.job_id,
			record.host,
			params.host
		);
	}
	Ok(record)
}
