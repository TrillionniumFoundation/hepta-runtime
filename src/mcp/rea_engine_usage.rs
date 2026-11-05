// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Sample live Java scratch through its owned descriptors, tolerating only disappearance.

use super::directory::{mount_id, open_at, Directory};
use anyhow::{bail, Context, Result};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirEntryExt, MetadataExt};
use std::time::{Duration, Instant};

struct Budget {
	bytes: u64,
	entries: usize,
	max_bytes: u64,
	max_entries: usize,
	deadline: Instant,
}

fn stat_at(parent: &File, name: &OsStr) -> std::io::Result<libc::stat> {
	let name = CString::new(name.as_bytes())?;
	let mut info = unsafe { std::mem::zeroed() };
	if unsafe {
		libc::fstatat(
			parent.as_raw_fd(),
			name.as_ptr(),
			&mut info,
			libc::AT_SYMLINK_NOFOLLOW,
		)
	} != 0
	{
		return Err(std::io::Error::last_os_error());
	}
	Ok(info)
}

fn absent(error: &anyhow::Error) -> bool {
	error
		.downcast_ref::<std::io::Error>()
		.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn scan(
	directory: &File,
	budget: &mut Budget,
	depth: usize,
	enumerated: &mut impl FnMut(&File, &OsStr) -> Result<()>,
) -> Result<()> {
	if depth > 32 {
		bail!("Java scratch sample depth exceeded");
	}
	// /proc resolves this already-owned descriptor, never an engine-supplied path.
	for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
		.context("read owned Java scratch directory")?
	{
		budget.entries += 1;
		if budget.entries > budget.max_entries || Instant::now() >= budget.deadline {
			bail!("Java scratch sample entry or time budget exceeded");
		}
		let entry = entry.context("enumerate owned Java scratch")?;
		let name = entry.file_name();
		enumerated(directory, &name)?;
		let before = match stat_at(directory, &name) {
			Ok(info) => info,
			// A live JVM may unlink a temporary entry after readdir. The root
			// and every traversed parent retain their independently checked FDs.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(error) => {
				return Err(error)
					.with_context(|| format!("stat owned Java scratch entry {name:?}"))
			}
		};
		if before.st_ino != entry.ino() {
			bail!("Java scratch entry was replaced during sampling: {name:?}");
		}
		match before.st_mode & libc::S_IFMT {
			libc::S_IFREG => {
				budget.bytes = budget
					.bytes
					.checked_add(u64::try_from(before.st_size)?)
					.context("Java scratch sample size overflow")?;
				if budget.bytes > budget.max_bytes {
					bail!("Java scratch sample byte budget exceeded");
				}
			}
			libc::S_IFDIR => {
				let child = match open_at(directory, &name) {
					Ok(child) => child,
					Err(error) if absent(&error) => match stat_at(directory, &name) {
						Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
						Err(error) => {
							return Err(error)
								.context("recheck disappearing Java scratch directory")
						}
						Ok(_) => bail!("Java scratch directory changed while opening: {name:?}"),
					},
					Err(error) => return Err(error).context("open owned Java scratch child"),
				};
				let held = child.metadata()?;
				if held.dev() != before.st_dev || held.ino() != before.st_ino || !held.is_dir() {
					bail!("Java scratch directory identity changed before traversal: {name:?}");
				}
				if mount_id(directory)? != mount_id(&child)? {
					bail!("Java scratch sampling refuses a mounted descendant");
				}
				scan(&child, budget, depth + 1, enumerated)?;
				match stat_at(directory, &name) {
					Ok(after)
						if after.st_dev == held.dev()
							&& after.st_ino == held.ino()
							&& after.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
					// A removed directory has zero links. A renamed live directory
					// does not: its movement cannot be treated as a missing sample.
					Err(error)
						if error.kind() == std::io::ErrorKind::NotFound
							&& child.metadata()?.nlink() == 0 => {}
					Err(error) => {
						return Err(error).context("verify owned Java scratch child after sampling")
					}
					Ok(_) => bail!("Java scratch directory was replaced during sampling: {name:?}"),
				}
			}
			_ => bail!("Java scratch sample contains a symlink or unsupported file type: {name:?}"),
		}
	}
	Ok(())
}

fn sample_with(
	directory: &Directory,
	max_bytes: u64,
	max_entries: usize,
	mut enumerated: impl FnMut(&File, &OsStr) -> Result<()>,
) -> Result<u64> {
	directory
		.verify()
		.context("verify original Java scratch before sampling")?;
	let mut budget = Budget {
		bytes: 0,
		entries: 0,
		max_bytes,
		max_entries,
		deadline: Instant::now() + Duration::from_secs(3),
	};
	scan(&directory.file, &mut budget, 0, &mut enumerated)?;
	directory
		.verify()
		.context("verify original Java scratch after sampling")?;
	Ok(budget.bytes)
}

pub(super) fn sample(directory: &Directory, max_bytes: u64, max_entries: usize) -> Result<u64> {
	sample_with(directory, max_bytes, max_entries, |_, _| Ok(()))
}

#[cfg(test)]
#[path = "rea_engine_usage_tests.rs"]
mod tests;
