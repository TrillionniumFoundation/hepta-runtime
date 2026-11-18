// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// The registry is real and never initialized in this explicit qualification domain.
// The active-slot branch is an asserted unreachable dependency, not a port claim.
use super::*;
use std::collections::VecDeque;
use std::os::unix::fs::MetadataExt;
struct Slot { identity: (u64, u64) }
static INDEXES: OnceLock<Mutex<VecDeque<Arc<Slot>>>> = OnceLock::new();
pub(super) fn observer_absent() -> bool { INDEXES.get().is_none() }
fn publication_before(_: &Slot, _: &Archive) { panic!("outside absent-index qualification domain") }
fn publication_after(_: &Slot, _: &Archive, _: &[&Record], _: bool) { panic!("outside absent-index qualification domain") }
fn identity(file: &File) -> Result<(u64, u64)> {
	let metadata = file.metadata()?;
	Ok((metadata.dev(), metadata.ino()))
}
fn publication_slot(archive: &Archive) -> Option<Arc<Slot>> {
	let registry = INDEXES.get()?;
	let archive_id = identity(archive.legacy()).ok()?;
	match registry.lock() {
		Ok(registry) => registry
			.iter()
			.find(|slot| slot.identity == archive_id)
			.cloned(),
		Err(_) => None,
	}
}
pub(super) fn publication<T>(
	archive: &Archive,
	record: &Record,
	write: impl FnOnce() -> Result<T>,
) -> Result<T> {
	let Some(slot) = publication_slot(archive) else {
		return write();
	};
	publication_before(&slot, archive);
	let result = write();
	publication_after(&slot, archive, &[record], result.is_ok());
	result
}
