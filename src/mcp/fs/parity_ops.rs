// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! Explicit controller-local filesystem primitives for DC capability parity.
//!
//! These perform only their documented actions. They are not alternate names
//! for shell or process execution, and cannot bypass runtime workspace roots.
//! Linux fd-relative operations avoid following symlinks during directory
//! traversal. We intentionally have no overwrite, cross-device or remote SSH
//! fallback and never try to acquire additional OS permissions.

use super::remote::{resolve_path_source, PathSource};
use crate::mcp::McpToolCall;
use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

fn scoped_local(path: &str, workdir: &Path) -> Result<PathBuf> {
	if crate::mcp::runtime::config::maybe_runtime_config().is_none() {
		bail!("Explicit workspace-scoped file operations require a runtime configuration");
	}
	match resolve_path_source(path, workdir) {
		PathSource::Local(p) => {
			crate::mcp::runtime::config::check_local_path(&p)?;
			Ok(p)
		}
		PathSource::Remote { .. } => {
			bail!("This operation is controller-local; remote path operations are not supported")
		}
	}
}

/// mkdir -p semantics, but only on controller-local authorized paths and without
/// following symlinks. An existing directory is a success, an existing regular
/// file or symlink is never accepted.
pub async fn execute_directory_create(call: &McpToolCall) -> Result<String> {
	let name = call
		.parameters
		.get("path")
		.and_then(|v| v.as_str())
		.ok_or_else(|| anyhow!("path must be a string"))?;
	let path = scoped_local(name, &call.workdir)?;
	let (display, created) = tokio::task::spawn_blocking(move || {
		#[cfg(target_os = "linux")]
		{
			let created = local_linux::make_directories(&path)?;
			Ok::<_, anyhow::Error>((path.display().to_string(), created))
		}
		#[cfg(not(target_os = "linux"))]
		{
			let _ = path;
			bail!("Scoped directory creation currently requires Linux")
		}
	})
	.await
	.context("directory creation task failed")??;
	Ok(
		serde_json::json!({"path": display, "created": created, "exists_as_directory": true})
			.to_string(),
	)
}

/// Rename an existing ordinary file without replacing anything at the destination.
/// Both endpoints must be authorized controller-local paths, and must be on
/// a filesystem supporting atomic RENAME_NOREPLACE. No copy/delete fallback.
pub async fn execute_file_move(call: &McpToolCall) -> Result<String> {
	let from = call
		.parameters
		.get("source")
		.and_then(|v| v.as_str())
		.ok_or_else(|| anyhow!("source must be a string"))?;
	let to = call
		.parameters
		.get("destination")
		.and_then(|v| v.as_str())
		.ok_or_else(|| anyhow!("destination must be a string"))?;
	let source = scoped_local(from, &call.workdir)?;
	let destination = scoped_local(to, &call.workdir)?;
	let source_copy = source.clone();
	let destination_copy = destination.clone();
	tokio::task::spawn_blocking(move || {
		#[cfg(target_os = "linux")]
		{
			local_linux::move_noreplace(&source_copy, &destination_copy)
		}
		#[cfg(not(target_os = "linux"))]
		{
			let _ = (&source_copy, &destination_copy);
			bail!("Scoped no-replace file move currently requires Linux")
		}
	})
	.await
	.context("file move task failed")??;
	super::delta::forget(&PathSource::Local(source.clone()));
	super::delta::forget(&PathSource::Local(destination.clone()));
	Ok(serde_json::json!({
		"source": source.display().to_string(),
		"destination": destination.display().to_string(),
		"moved": true, "destination_was_absent": true,
		"same_filesystem_atomic_noreplace": true
	})
	.to_string())
}

/// Rename a controller-local directory into an absent destination, preserving
/// the complete existing tree without copying, traversing entries or shell use.
/// Source and destination must both remain inside configured workspace roots.
pub async fn execute_directory_move(call: &McpToolCall) -> Result<String> {
	let from = call
		.parameters
		.get("source")
		.and_then(|v| v.as_str())
		.ok_or_else(|| anyhow!("source must be a string"))?;
	let to = call
		.parameters
		.get("destination")
		.and_then(|v| v.as_str())
		.ok_or_else(|| anyhow!("destination must be a string"))?;
	let source = scoped_local(from, &call.workdir)?;
	let destination = scoped_local(to, &call.workdir)?;
	let old = source.clone();
	let new = destination.clone();
	tokio::task::spawn_blocking(move || {
		#[cfg(target_os = "linux")]
		{
			local_linux::move_directory_noreplace(&old, &new)
		}
		#[cfg(not(target_os = "linux"))]
		{
			let _ = (&old, &new);
			bail!("Scoped no-replace directory move currently requires Linux")
		}
	})
	.await
	.context("directory move task failed")??;
	// Relocating a directory invalidates EVERY cached descendant. Forgetting
	// only its own path would leave stale whole-file delta snapshots behind.
	super::delta::forget_subtree(&PathSource::Local(source.clone()));
	super::delta::forget_subtree(&PathSource::Local(destination.clone()));
	Ok(serde_json::json!({
		"source": source.display().to_string(),
		"destination": destination.display().to_string(),
		"moved": true,
		"destination_was_absent": true,
		"same_filesystem_atomic_noreplace": true,
		"directory_tree_was_not_traversed": true,
		"external_writers_transactionally_excluded": false
	})
	.to_string())
}

#[cfg(target_os = "linux")]
mod local_linux {
	use anyhow::{anyhow, bail, Context, Result};
	use std::ffi::CString;
	use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
	use std::os::unix::ffi::OsStrExt;
	use std::path::{Component, Path};

	fn components(path: &Path) -> Result<Vec<CString>> {
		if !path.is_absolute() {
			bail!("A fully resolved local path is required");
		}
		let mut items = Vec::new();
		for c in path.components() {
			match c {
				Component::RootDir => {}
				Component::Normal(name) => items.push(
					CString::new(name.as_bytes())
						.map_err(|_| anyhow!("NUL is forbidden in paths"))?,
				),
				_ => bail!("Relative or dot path components are not accepted"),
			}
		}
		if items.is_empty() {
			bail!("Filesystem root cannot be modified");
		}
		Ok(items)
	}

	fn root() -> Result<OwnedFd> {
		// SAFETY: constant null-terminated path and documented libc open flags.
		let fd = unsafe {
			libc::open(
				c"/".as_ptr(),
				libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		// SAFETY: successful open hands a unique owned descriptor to OwnedFd.
		Ok(unsafe { OwnedFd::from_raw_fd(fd) })
	}

	fn open_dir(parent: &OwnedFd, name: &CString) -> Result<OwnedFd> {
		// SAFETY: CString is NUL terminated; fd is valid while parent lives.
		let fd = unsafe {
			libc::openat(
				parent.as_raw_fd(),
				name.as_ptr(),
				libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		// SAFETY: successful open owns exactly this descriptor.
		Ok(unsafe { OwnedFd::from_raw_fd(fd) })
	}

	fn existing_parent(parts: &[CString]) -> Result<(OwnedFd, &CString)> {
		let (last, parents) = parts
			.split_last()
			.ok_or_else(|| anyhow!("empty filename"))?;
		let mut current = root()?;
		for part in parents {
			current = open_dir(&current, part).context("non-directory or symlink parent")?;
		}
		Ok((current, last))
	}

	pub fn make_directories(path: &Path) -> Result<bool> {
		let parts = components(path)?;
		let mut current = root()?;
		let mut created = false;
		for part in &parts {
			match open_dir(&current, part) {
				Ok(next) => current = next,
				Err(error) => {
					if !matches!(error.downcast_ref::<std::io::Error>(), Some(e) if e.kind() == std::io::ErrorKind::NotFound)
					{
						return Err(error).context("directory component is not a safe directory");
					}
					// SAFETY: parent remains a valid directory descriptor, leaf is a CString.
					let rc = unsafe { libc::mkdirat(current.as_raw_fd(), part.as_ptr(), 0o700) };
					if rc < 0 {
						let why = std::io::Error::last_os_error();
						if why.kind() != std::io::ErrorKind::AlreadyExists {
							return Err(why).context("mkdirat failed");
						}
					} else {
						created = true;
					}
					current = open_dir(&current, part)
						.context("directory became a non-directory or symlink")?;
				}
			}
		}
		Ok(created)
	}

	pub fn move_directory_noreplace(source: &Path, destination: &Path) -> Result<()> {
		if source == destination {
			bail!("Source and destination must differ");
		}
		let a = components(source)?;
		let b = components(destination)?;
		let (src_parent, src_name) = existing_parent(&a)?;
		let (dst_parent, dst_name) = existing_parent(&b)?;
		let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
		// SAFETY: fd-held source parent, CString and initialized stat buffer.
		let rc = unsafe {
			libc::fstatat(
				src_parent.as_raw_fd(),
				src_name.as_ptr(),
				st.as_mut_ptr(),
				libc::AT_SYMLINK_NOFOLLOW,
			)
		};
		if rc < 0 {
			return Err(std::io::Error::last_os_error()).context("Directory source missing");
		}
		// SAFETY: successful fstatat initialized the provided storage.
		let source_stat = unsafe { st.assume_init() };
		if (source_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
			bail!("Source must be a directory, not a file or symlink");
		}
		// Kernel-enforced RENAME_NOREPLACE is the complete move operation.
		// We never recursively copy contents, follow child links or execute a
		// fallback on EXDEV, EEXIST or unsupported filesystem semantics.
		// SAFETY: live dir FDs and two bounded NUL-terminated names.
		let rc = unsafe {
			libc::renameat2(
				src_parent.as_raw_fd(),
				src_name.as_ptr(),
				dst_parent.as_raw_fd(),
				dst_name.as_ptr(),
				libc::RENAME_NOREPLACE,
			)
		};
		if rc < 0 {
			return Err(std::io::Error::last_os_error())
				.context("Atomic no-replace directory move refused");
		}
		Ok(())
	}

	pub fn move_noreplace(source: &Path, destination: &Path) -> Result<()> {
		if source == destination {
			bail!("Source and destination must differ");
		}
		let a = components(source)?;
		let b = components(destination)?;
		let (src_parent, src_name) = existing_parent(&a)?;
		let (dst_parent, dst_name) = existing_parent(&b)?;
		let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
		// SAFETY: valid descriptors, CString and stat destination.
		let rc = unsafe {
			libc::fstatat(
				src_parent.as_raw_fd(),
				src_name.as_ptr(),
				st.as_mut_ptr(),
				libc::AT_SYMLINK_NOFOLLOW,
			)
		};
		if rc < 0 {
			return Err(std::io::Error::last_os_error()).context("source missing");
		}
		// SAFETY: fstatat returned success and initialized the struct.
		let st = unsafe { st.assume_init() };
		if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
			bail!("Source must be a regular file, not a symlink or directory");
		}
		// SAFETY: both parents are fd-held directories; kernel renameat2 with
		// RENAME_NOREPLACE is the only move mechanism. No unsafe copy/delete fallback.
		let rc = unsafe {
			libc::renameat2(
				src_parent.as_raw_fd(),
				src_name.as_ptr(),
				dst_parent.as_raw_fd(),
				dst_name.as_ptr(),
				libc::RENAME_NOREPLACE,
			)
		};
		if rc < 0 {
			return Err(std::io::Error::last_os_error())
                .context("No-replace file move refused (destination exists, cross-device or unsupported filesystem)");
		}
		Ok(())
	}
}

#[cfg(test)]
#[path = "parity_ops_tests.rs"]
mod tests;
