// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Unchanged original audit acquisition functions plus exact test observation helpers.
use anyhow::{anyhow, bail, Result};
use std::fs::File;
use std::path::Path;
const STORE_NAME: &str = "request-audit";
fn name(value: &str) -> Result<std::ffi::CString> {
	std::ffi::CString::new(value).map_err(|_| anyhow!("invalid private metadata component"))
}
fn open_at(directory: &File, component: &str, flags: i32, mode: u32) -> Result<File> {
	let component = name(component)?;
	open_at_component(directory, &component, flags, mode)
}
fn open_at_component(
	directory: &File,
	component: &std::ffi::CStr,
	flags: i32,
	mode: u32,
) -> Result<File> {
	use std::os::fd::{AsRawFd, FromRawFd};
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
	private_directory_metadata(directory).map(|_| ())
}
fn private_directory_metadata(directory: &File) -> Result<std::fs::Metadata> {
	use std::os::unix::fs::MetadataExt;
	let metadata = directory.metadata()?;
	if !metadata.is_dir()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o700
	{
		bail!("private request audit directory refused");
	}
	Ok(metadata)
}
fn audit_root(root: &Path) -> Result<File> {
	use std::os::fd::FromRawFd;
	use std::os::unix::fs::MetadataExt;
	let raw = root
		.to_str()
		.ok_or_else(|| anyhow!("request audit root is not UTF-8"))?;
	if !root.is_absolute() || raw.split('/').any(|part| part == "." || part == "..") {
		bail!("invalid request audit root");
	}
	let components: Vec<_> = raw.split('/').filter(|part| !part.is_empty()).collect();
	#[cfg(target_os = "linux")]
	let ancestor_access = libc::O_PATH;
	#[cfg(not(target_os = "linux"))]
	let ancestor_access = libc::O_RDONLY;
	let slash = name("/")?;
	let descriptor = unsafe {
		libc::open(
			slash.as_ptr(),
			ancestor_access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if descriptor < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let mut base = unsafe { File::from_raw_fd(descriptor) };
	for (index, component) in components.iter().enumerate() {
		// Linux O_PATH needs search permission, not directory-listing permission.
		// Keep explicit denial of non-searchable ancestors even for privileged
		// callers, and open the private final directory as a normal fsync-able FD.
		if base.metadata()?.mode() & 0o111 == 0 {
			bail!("request audit ancestor is not searchable");
		}
		let access = if index + 1 == components.len() {
			libc::O_RDONLY
		} else {
			ancestor_access
		};
		base = open_at(&base, component, access | libc::O_DIRECTORY, 0)?;
	}
	private_directory(&base)?;
	Ok(base)
}
fn open_store(root: &Path) -> Result<File> {
	open_named_store(root, STORE_NAME)
}
fn open_named_store(root: &Path, store_name: &str) -> Result<File> {
	let base = audit_root(root)?;
	open_named_store_at(&base, store_name)
}
fn open_named_store_at(base: &File, store_name: &str) -> Result<File> {
	use std::os::fd::AsRawFd;
	let folder = name(store_name)?;
	let made = unsafe { libc::mkdirat(base.as_raw_fd(), folder.as_ptr(), 0o700) };
	if made < 0 {
		let error = std::io::Error::last_os_error();
		if error.kind() != std::io::ErrorKind::AlreadyExists {
			return Err(error.into());
		}
	} else {
		base.sync_all()?;
	}
	let directory = open_at(base, store_name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_directory(&directory)?;
	Ok(directory)
}
struct DirectoryIdentity {
	device: u64,
	inode: u64,
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
