// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
const MAX_GLOBAL: usize = 512;
const MAX_OWNER: usize = 128;
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DurableState {
	Unknown,
	Completed,
	Failed,
}
mod record_schema {
	use super::DurableState;
	use serde::{Deserialize, Serialize};

	// Serde derives its default Visitor diagnostic from the Rust identifier,
	// not serde(rename). Keep the original name for both string specializations.
	#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
	#[serde(deny_unknown_fields)]
	pub(super) struct Record<S> {
		pub(super) request_id: S,
		pub(super) owner: S,
		pub(super) tool_name: S,
		pub(super) state: DurableState,
		pub(super) accepted_unix_ms: u128,
		pub(super) elapsed_ms: Option<u64>,
	}
}
type RecordFields<S> = record_schema::Record<S>;
type Record = record_schema::Record<String>;
fn retained_record(hot: &File, archive: &Archive, id: &str) -> Result<Option<Record>> {
	fn optional(directory: &File, id: &str) -> Result<Option<Record>> {
		match read_record(directory, &format!("{id}.json")) {
			Ok(record) => Ok(Some(record)),
			Err(error)
				if error
					.downcast_ref::<std::io::Error>()
					.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
			{
				Ok(None)
			}
			Err(error) => Err(error),
		}
	}
	let hot = optional(hot, id)?;
	let archived = match archive.read_record(&format!("{id}.json")) {
		Ok(record) => Some(record),
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
		{
			None
		}
		Err(error) => return Err(error),
	};
	if let (Some(hot), Some(archived)) = (&hot, &archived) {
		if hot.owner != archived.owner
			|| hot.tool_name != archived.tool_name
			|| hot.accepted_unix_ms != archived.accepted_unix_ms
			|| (hot.state != DurableState::Unknown && hot.state != archived.state)
			|| (hot.elapsed_ms.is_some() && hot.elapsed_ms != archived.elapsed_ms)
		{
			bail!("request archive identity or outcome changed");
		}
	}
	// Completion is published to the archive first. A failed hot-cache update
	// can leave an older unknown receipt, but cannot undo the archived completion.
	Ok(archived.or(hot))
}
fn archived_copy_matches(archive: &Archive, record: &Record) -> bool {
	let Ok(archived) = archive.read_record(&format!("{}.json", record.request_id)) else {
		return false;
	};
	archived.owner == record.owner
		&& archived.tool_name == record.tool_name
		&& archived.accepted_unix_ms == record.accepted_unix_ms
		&& (record.state == DurableState::Unknown || record.state == archived.state)
		&& (record.elapsed_ms.is_none() || record.elapsed_ms == archived.elapsed_ms)
}
fn archive_replacement(archive: &Archive, record: &Record) -> Result<Option<bool>> {
	let replacing = match archive.read_record(&format!("{}.json", record.request_id)) {
		Ok(existing) => {
			if existing.owner != record.owner
				|| existing.tool_name != record.tool_name
				|| existing.accepted_unix_ms != record.accepted_unix_ms
			{
				bail!("request archive identity changed");
			}
			if record.state == DurableState::Unknown && existing.state != DurableState::Unknown {
				return Ok(None);
			}
			if existing.state != DurableState::Unknown && existing.state != record.state {
				bail!("request archive terminal outcome changed");
			}
			if existing.state != DurableState::Unknown && existing.elapsed_ms != record.elapsed_ms {
				bail!("request archive terminal outcome changed");
			}
			if existing.state == record.state && existing.elapsed_ms == record.elapsed_ms {
				return Ok(None);
			}
			true
		}
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
		{
			false
		}
		Err(error) => return Err(error),
	};
	Ok(Some(replacing))
}
fn retain_for_batch(
	directory: &File,
	archive: &Archive,
	owner: &str,
	records: &mut Vec<Record>,
	pending: &HashSet<String>,
	sync_directory: bool,
) -> Result<bool> {
	while records
		.iter()
		.filter(|record| record.owner == owner)
		.count()
		>= MAX_OWNER
	{
		let mut victim = None;
		for (index, record) in records.iter().enumerate() {
			if record.owner == owner
				&& !pending.contains(&record.request_id)
				&& !is_active(&record.request_id)?
				&& archived_copy_matches(archive, record)
			{
				victim = Some(index);
				break;
			}
		}
		let Some(index) = victim else {
			return Ok(false);
		};
		remove_record(directory, &records[index], sync_directory)?;
		records.remove(index);
	}
	while records.len() >= MAX_GLOBAL {
		let mut victim = None;
		for (index, record) in records.iter().enumerate() {
			if !pending.contains(&record.request_id)
				&& !is_active(&record.request_id)?
				&& archived_copy_matches(archive, record)
			{
				victim = Some(index);
				break;
			}
		}
		let Some(index) = victim else {
			return Ok(false);
		};
		remove_record(directory, &records[index], sync_directory)?;
		records.remove(index);
	}
	Ok(true)
}
