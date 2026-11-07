// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Descriptor-bound private directories shared by a static worker and its job owner.

use anyhow::{bail, Context, Result};
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub(crate) fn require_supported_platform() -> Result<()> {
	// Mount identity, descendant observation and cleanup use the Linux /proc
	// contracts. Refuse before creating or adopting a namespace on other OSes.
	if !cfg!(target_os = "linux") {
		bail!("Static engine scratch lifecycle requires Linux");
	}
	Ok(())
}

pub(crate) fn open_at(parent: &File, name: &OsStr) -> Result<File> {
	let name = CString::new(name.as_bytes())?;
	// The parent descriptor, not a re-resolved pathname, selects each child.
	let fd = unsafe {
		libc::openat(
			parent.as_raw_fd(),
			name.as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if fd < 0 {
		return Err(std::io::Error::last_os_error()).context("engine directory unavailable");
	}
	Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_path(path: &Path) -> Result<File> {
	if !path.is_absolute() {
		bail!("engine directory must be absolute");
	}
	let mut parent = File::open("/")?;
	for component in path.components() {
		match component {
			Component::RootDir => {}
			Component::Normal(name) => parent = open_at(&parent, name)?,
			_ => bail!("engine directory path is not normalized"),
		}
	}
	Ok(parent)
}

fn same_directory(left: &Metadata, right: &Metadata) -> bool {
	left.is_dir()
		&& right.is_dir()
		&& left.dev() == right.dev()
		&& left.ino() == right.ino()
		&& left.uid() == right.uid()
}

/// Only `create` authorizes a new owned directory. `open` also requires the
/// owner-supplied inode identity; a caller-selected cleanup pathname is absent.
pub(crate) struct Directory {
	pub(crate) path: PathBuf,
	pub(crate) file: File,
	parent: File,
	before: Metadata,
}

impl Directory {
	pub(crate) fn create(parent: &Path, name: &str) -> Result<Self> {
		require_supported_platform()?;
		if name.is_empty() || name == "." || name == ".." || name.contains('/') {
			bail!("invalid private engine directory name");
		}
		let parent_file = open_path(parent)?;
		let name_c = CString::new(name)?;
		if unsafe { libc::mkdirat(parent_file.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot exclusively create private engine directory");
		}
		let file = open_at(&parent_file, OsStr::new(name))?;
		let before = file.metadata()?;
		let value = Self {
			path: parent.join(name),
			file,
			parent: parent_file,
			before,
		};
		value.verify()?;
		value.file.sync_all()?;
		value.parent.sync_all()?;
		Ok(value)
	}

	pub(crate) fn open(path: &Path, device: u64, inode: u64) -> Result<Self> {
		require_supported_platform()?;
		let parent_path = path.parent().context("engine directory parent absent")?;
		let parent = open_path(parent_path)?;
		let file = open_at(
			&parent,
			path.file_name().context("engine directory name absent")?,
		)?;
		let before = file.metadata()?;
		if before.dev() != device || before.ino() != inode {
			bail!("engine directory differs from its original owner inode");
		}
		let value = Self {
			path: path.to_owned(),
			file,
			parent,
			before,
		};
		value.verify()?;
		Ok(value)
	}

	pub(crate) fn identity(&self) -> (u64, u64) {
		(self.before.dev(), self.before.ino())
	}

	pub(crate) fn verify(&self) -> Result<()> {
		require_supported_platform()?;
		let parent_path = self
			.path
			.parent()
			.context("engine directory parent absent")?;
		let current_parent = open_path(parent_path)?.metadata()?;
		let held_parent = self.parent.metadata()?;
		let named_leaf = open_at(
			&self.parent,
			self.path.file_name().context("engine name absent")?,
		)?
		.metadata()?;
		let current = open_path(&self.path)?.metadata()?;
		let held = self.file.metadata()?;
		if !same_directory(&held_parent, &current_parent)
			|| !same_directory(&named_leaf, &held)
			|| !same_directory(&self.before, &held)
			|| self.identity() != (current.dev(), current.ino())
			|| !same_directory(&held, &current)
			|| held.uid() != unsafe { libc::geteuid() }
			|| held.mode() & 0o777 != 0o700
		{
			bail!("private engine directory identity or permissions changed; retained");
		}
		Ok(())
	}

	pub(crate) fn remove(&self) -> Result<()> {
		self.verify()?;
		clear(
			&self.file,
			&mut 0,
			0,
			Instant::now() + Duration::from_secs(3),
		)?;
		self.verify()?;
		let name = CString::new(
			self.path
				.file_name()
				.context("engine name absent")?
				.as_bytes(),
		)?;
		if unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
			!= 0
		{
			return Err(std::io::Error::last_os_error())
				.context("engine directory removal unconfirmed");
		}
		self.parent
			.sync_all()
			.context("engine directory removal durability unconfirmed")
	}
}

fn clear(directory: &File, count: &mut usize, depth: usize, deadline: Instant) -> Result<()> {
	if depth > 32 {
		bail!("engine cleanup directory depth exceeded; retained");
	}
	for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
		*count += 1;
		if *count > 100_000 || Instant::now() >= deadline {
			bail!("engine cleanup budget exceeded; retained");
		}
		let entry = entry?;
		let name = entry.file_name();
		let name_c = CString::new(name.as_bytes())?;
		let mut flags = 0;
		if entry.file_type()?.is_dir() {
			let child = open_at(directory, &name)?;
			if mount_id(directory)? != mount_id(&child)? {
				bail!("engine cleanup refuses a mounted descendant; retained");
			}
			clear(&child, count, depth + 1, deadline)?;
			if !same_directory(&child.metadata()?, &open_at(directory, &name)?.metadata()?) {
				bail!("engine cleanup descendant identity changed; retained");
			}
			flags = libc::AT_REMOVEDIR;
		}
		// Symlinks are unlinked as leaves; neither their targets nor other mounts
		// reached through a substituted pathname grant cleanup authority.
		if unsafe { libc::unlinkat(directory.as_raw_fd(), name_c.as_ptr(), flags) } != 0 {
			return Err(std::io::Error::last_os_error()).context("engine cleanup incomplete");
		}
	}
	Ok(())
}

pub(crate) fn mount_id(directory: &File) -> Result<u64> {
	let mut bytes = Vec::new();
	File::open(format!("/proc/self/fdinfo/{}", directory.as_raw_fd()))?
		.take(16_385)
		.read_to_end(&mut bytes)?;
	if bytes.len() > 16_384 {
		bail!("engine mount identity exceeds its bound");
	}
	std::str::from_utf8(&bytes)?
		.lines()
		.find_map(|line| line.strip_prefix("mnt_id:"))
		.context("engine mount identity unavailable")?
		.trim()
		.parse()
		.context("invalid engine mount identity")
}
