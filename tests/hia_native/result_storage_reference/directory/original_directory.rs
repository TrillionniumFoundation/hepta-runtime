// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Unmodified original directory bodies; serialization derives are outside this include fragment.
use anyhow::{anyhow, bail, Result};
use std::fs::File;
use std::path::Path;
const STORE_NAME: &str = "request-results";
const ARCHIVE_ANCHOR: &str = ".request-results-v2-anchor.json";
struct DirectoryIdentity {
	device: u64,
	inode: u64,
}
fn name(value: &str) -> Result<std::ffi::CString> {
	std::ffi::CString::new(value).map_err(|_| anyhow!("invalid private metadata component"))
}
fn open_at(directory: &File, component: &str, flags: i32, mode: u32) -> Result<File> {
	use std::os::fd::{AsRawFd, FromRawFd};
	let component = name(component)?;
	let descriptor = unsafe {
		libc::openat(
			directory.as_raw_fd(),
			component.as_ptr(),
			flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			mode,
		)
	};
	if descriptor < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok(unsafe { File::from_raw_fd(descriptor) })
}
fn private_directory(directory: &File) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	let metadata = directory.metadata()?;
	if !metadata.is_dir()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o700
	{
		bail!("private request audit directory refused");
	}
	Ok(())
}
fn open_root(root: &Path) -> Result<File> {
	use std::os::fd::FromRawFd;
	let raw = root
		.to_str()
		.ok_or_else(|| anyhow!("request audit root is not UTF-8"))?;
	if !root.is_absolute() || raw.split('/').any(|part| part == "." || part == "..") {
		bail!("invalid request audit root");
	}
	let slash = name("/")?;
	let descriptor = unsafe {
		libc::open(
			slash.as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if descriptor < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let mut base = unsafe { File::from_raw_fd(descriptor) };
	for component in raw.split('/').filter(|part| !part.is_empty()) {
		base = open_at(&base, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	}
	Ok(base)
}
fn open_store(root: &Path) -> Result<File> {
	use std::os::fd::AsRawFd;
	let base = open_root(root)?;
	// Once the archive is anchored, a missing legacy directory is lost history.
	if !is_absent(&base, ARCHIVE_ANCHOR)? {
		let directory = open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
		private_directory(&directory)?;
		return Ok(directory);
	}
	let folder = name(STORE_NAME)?;
	let made = unsafe { libc::mkdirat(base.as_raw_fd(), folder.as_ptr(), 0o700) };
	if made < 0 {
		let error = std::io::Error::last_os_error();
		if error.kind() != std::io::ErrorKind::AlreadyExists {
			return Err(error.into());
		}
	} else {
		base.sync_all()?;
	}
	let directory = open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_directory(&directory)?;
	Ok(directory)
}
fn is_not_found(error: &anyhow::Error) -> bool {
	error
		.downcast_ref::<std::io::Error>()
		.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}
fn is_absent(directory: &File, component: &str) -> Result<bool> {
	match open_at(directory, component, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
		Ok(_) => Ok(false),
		Err(error) if is_not_found(&error) => Ok(true),
		Err(error) => Err(error),
	}
}
fn directory_identity(directory: &File, require_private: bool) -> Result<DirectoryIdentity> {
	use std::os::unix::fs::MetadataExt;
	if require_private {
		private_directory(directory)?;
	}
	let metadata = directory.metadata()?;
	Ok(DirectoryIdentity {
		device: metadata.dev(),
		inode: metadata.ino(),
	})
}
