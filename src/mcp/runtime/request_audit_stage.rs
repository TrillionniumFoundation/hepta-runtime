// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded persistent file barriers before serial, ownership-fenced publication.
use super::*;
use std::os::fd::AsRawFd;

#[path = "request_audit_sync.rs"]
mod file_sync;

const MAX_FILES: usize = 32;

pub(super) fn is_ready() -> bool {
	file_sync::is_ready()
}

struct Prepared<'a> {
	directory: &'a File,
	file: Arc<File>,
	temporary: std::ffi::CString,
	target: std::ffi::CString,
	replacing: bool,
	published: bool,
}

impl Drop for Prepared<'_> {
	fn drop(&mut self) {
		if !self.published {
			unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.temporary.as_ptr(), 0) };
		}
	}
}

fn prepare<'a>(
	directory: &'a File,
	record: &Record,
	replacing: bool,
	cohort: usize,
	slot: usize,
) -> Result<Prepared<'a>> {
	trace::measure("stage_private_directory", cohort, Some(slot), || {
		private_directory(directory)
	})?;
	let filename = format!("{}.json", record.request_id);
	if replacing {
		let existing = trace::measure("stage_read_existing", cohort, Some(slot), || {
			read_record(directory, &filename)
		})?;
		if existing.owner != record.owner
			|| existing.tool_name != record.tool_name
			|| existing.accepted_unix_ms != record.accepted_unix_ms
		{
			bail!("request audit receipt binding changed");
		}
	}
	let bytes = serde_json::to_vec(record)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("request audit record size refused");
	}
	let temporary = format!(".{}-{}.tmp", record.request_id, record.request_id);
	let file = trace::measure("stage_open_temporary", cohort, Some(slot), || {
		open_at(
			directory,
			&temporary,
			libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
			0o600,
		)
	})?;
	// Construct cleanup ownership before validating or writing can fail. The
	// temporary remains caller-owned while workers borrow only its existing FD.
	let mut prepared = Prepared {
		directory,
		file: Arc::new(file),
		temporary: name(&temporary)?,
		target: name(&filename)?,
		replacing,
		published: false,
	};
	trace::measure("stage_validate_temporary", cohort, Some(slot), || {
		validate_file(&prepared.file)
	})?;
	let file = Arc::get_mut(&mut prepared.file)
		.ok_or_else(|| anyhow!("audit staging file unexpectedly shared"))?;
	trace::measure("stage_write_temporary", cohort, Some(slot), || {
		file.write_all(&bytes)?;
		Ok(())
	})?;
	Ok(prepared)
}

fn publish(prepared: &mut Prepared<'_>, cohort: usize, slot: usize) -> Result<()> {
	let directory = prepared.directory.as_raw_fd();
	let stage = if prepared.replacing {
		"stage_rename"
	} else {
		"stage_link"
	};
	trace::measure(stage, cohort, Some(slot), || {
		let status = unsafe {
			if prepared.replacing {
				libc::renameat(
					directory,
					prepared.temporary.as_ptr(),
					directory,
					prepared.target.as_ptr(),
				)
			} else {
				libc::linkat(
					directory,
					prepared.temporary.as_ptr(),
					directory,
					prepared.target.as_ptr(),
					0,
				)
			}
		};
		if status < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(())
	})?;
	if !prepared.replacing {
		trace::measure("stage_unlink_temporary", cohort, Some(slot), || {
			if unsafe { libc::unlinkat(directory, prepared.temporary.as_ptr(), 0) } < 0 {
				return Err(std::io::Error::last_os_error().into());
			}
			Ok(())
		})?;
	}
	prepared.published = true;
	Ok(())
}

fn synchronize(
	prepared: &[Result<Prepared<'_>>],
	operation: file_sync::Operation,
	barrier: &impl Fn(&[Arc<File>], file_sync::Operation) -> Vec<Result<()>>,
) -> Vec<Result<()>> {
	let mut files = Vec::with_capacity(prepared.len());
	let mut indices = Vec::with_capacity(prepared.len());
	for (index, value) in prepared.iter().enumerate() {
		if let Ok(value) = value {
			files.push(value.file.clone());
			indices.push(index);
		}
	}
	// The barrier drains all submitted jobs even while unwinding. These local
	// Arc references disappear before any Prepared may publish, close or unlink.
	let span = trace::Span::new("stage_file_barriers", prepared.len(), None);
	let synchronized = barrier(&files, operation);
	span.record(synchronized.iter().find_map(|result| result.as_ref().err()));
	let mut results: Vec<_> = (0..prepared.len())
		.map(|_| Err(anyhow!("audit cohort staging unavailable")))
		.collect();
	if synchronized.len() != indices.len() {
		return results;
	}
	for (index, result) in indices.into_iter().zip(synchronized) {
		results[index] = result;
	}
	results
}

#[cfg(test)]
pub(super) fn save(directory: &File, records: &[(&Record, bool)]) -> Vec<Result<()>> {
	save_with(
		directory,
		records,
		Arc::new(|file: &File| {
			file.sync_all()?;
			Ok(())
		}),
	)
}

#[cfg(test)]
fn save_with(
	directory: &File,
	records: &[(&Record, bool)],
	operation: file_sync::Operation,
) -> Vec<Result<()>> {
	save_with_barrier(directory, records, operation, &file_sync::synchronize)
}

#[cfg(test)]
pub(super) fn save_with_barrier(
	directory: &File,
	records: &[(&Record, bool)],
	operation: file_sync::Operation,
	barrier: &impl Fn(&[Arc<File>], file_sync::Operation) -> Vec<Result<()>>,
) -> Vec<Result<()>> {
	let writes: Vec<_> = records
		.iter()
		.map(|(record, replacing)| (directory, *record, *replacing))
		.collect();
	save_many_with_barrier(&writes, operation, barrier)
}

/// One file-barrier cohort may span several immutable archive directories.
/// Publication still waits for every submitted file job and retains FIFO slots.
pub(super) fn save_many(records: &[(&File, &Record, bool)]) -> Vec<Result<()>> {
	save_many_with_barrier(
		records,
		Arc::new(|file: &File| {
			file.sync_all()?;
			Ok(())
		}),
		&file_sync::synchronize,
	)
}

pub(super) fn save_many_with_barrier(
	records: &[(&File, &Record, bool)],
	operation: file_sync::Operation,
	barrier: &impl Fn(&[Arc<File>], file_sync::Operation) -> Vec<Result<()>>,
) -> Vec<Result<()>> {
	if records.len() > MAX_FILES {
		return (0..records.len())
			.map(|_| Err(anyhow!("audit file barrier cohort exceeded")))
			.collect();
	}
	let mut ids = HashSet::new();
	if records
		.iter()
		.any(|(_, record, _)| !ids.insert(&record.request_id))
	{
		return records
			.iter()
			.map(|(directory, record, replacing)| {
				save_many_with_barrier(
					&[(*directory, *record, *replacing)],
					operation.clone(),
					barrier,
				)
				.into_iter()
				.next()
				.unwrap_or_else(|| Err(anyhow!("audit file barrier unavailable")))
			})
			.collect();
	}
	let cohort = records.len();
	let prepared: Vec<_> = records
		.iter()
		.enumerate()
		.map(|(slot, (directory, record, replacing))| {
			trace::measure("stage_prepare", cohort, Some(slot), || {
				prepare(directory, record, *replacing, cohort, slot)
			})
		})
		.collect();
	let synchronized = synchronize(&prepared, operation, barrier);
	prepared
		.into_iter()
		.zip(synchronized)
		.enumerate()
		.map(|(slot, (prepared, result))| {
			let mut prepared = prepared?;
			trace::Span::new("stage_file_sync_result", cohort, Some(slot)).finish(result)?;
			publish(&mut prepared, cohort, slot)
		})
		.collect()
}

#[cfg(test)]
#[path = "request_audit_stage_tests.rs"]
mod tests;
