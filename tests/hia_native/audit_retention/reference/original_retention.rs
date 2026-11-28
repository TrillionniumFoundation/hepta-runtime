// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact target retention function bodies for boundary-isolated comparison.
#[cfg(unix)]
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

#[cfg(unix)]
fn retain_before_begin(
	directory: &File,
	archive: &Archive,
	owner: &str,
	records: &mut Vec<Record>,
) -> Result<bool> {
	retain_for_batch(directory, archive, owner, records, &HashSet::new(), true)
}

#[cfg(unix)]
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
