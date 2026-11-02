// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Restricted local artifact access. File descriptors are opened relative to
//! a configured workspace root, not by resolving a path and then reopening it.
//! Symlink traversal (including symlinks inside the workspace) is denied.
//! This is only file admission: there is no isolated parser process yet.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

#[cfg(unix)]
fn open_beneath_root(path: &Path, roots: &[PathBuf]) -> Result<std::fs::File> {
	use std::ffi::CString;
	use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
	use std::os::unix::ffi::OsStrExt;
	use std::path::Component;

	let mut matched = false;
	for root in roots {
		if !root.is_absolute() {
			bail!("REA inspection denied: configured workspace root must be absolute");
		}
		let Ok(relative) = path.strip_prefix(root) else {
			continue;
		};
		matched = true;
		let components = relative
			.components()
			.map(|component| match component {
				Component::Normal(segment) => CString::new(segment.as_bytes())
					.context("REA inspection path contains NUL"),
				_ => bail!("REA inspection denied: parent or non-normal path component"),
			})
			.collect::<Result<Vec<_>>>()?;
		if components.is_empty() {
			bail!("REA inspection requires a regular file, not a workspace root");
		}

		// The policy root is administrator-controlled. No user-supplied path is
		// reopened after validation; every child lookup holds the parent fd.
		let root_path = CString::new(root.as_os_str().as_bytes())
			.context("REA configured root contains NUL")?;
		let root_fd = unsafe {
			libc::open(
				root_path.as_ptr(),
				libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
			)
		};
		if root_fd < 0 {
			return Err(std::io::Error::last_os_error())
				.with_context(|| format!("cannot open configured workspace {}", root.display()));
		}
		let mut parent = unsafe { OwnedFd::from_raw_fd(root_fd) };
		let (final_name, directories) = components.split_last()
			.ok_or_else(|| anyhow!("REA inspection requires a file component"))?;
		for name in directories {
			let fd = unsafe {
				libc::openat(
					parent.as_raw_fd(),
					name.as_ptr(),
					libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
				)
			};
			if fd < 0 {
				return Err(std::io::Error::last_os_error())
					.context("REA inspection denied: unsafe or missing directory component");
			}
			parent = unsafe { OwnedFd::from_raw_fd(fd) };
		}
		let fd = unsafe {
			libc::openat(
				parent.as_raw_fd(),
				final_name.as_ptr(),
				libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
			)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error())
				.context("REA inspection denied: unsafe or missing file component");
		}
		let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
		let metadata = file.metadata().context("cannot stat admitted artifact")?;
		if !metadata.is_file() {
			bail!("REA inspection requires a regular file");
		}
		return Ok(file);
	}
	if !matched {
		bail!("REA inspection denied: path is outside controller workspace roots");
	}
	bail!("REA inspection denied: no allowed file");
}

#[cfg(not(unix))]
fn open_beneath_root(_path: &Path, _roots: &[PathBuf]) -> Result<std::fs::File> {
	bail!("REA native inspection requires Unix file-descriptor admission on this build");
}

/// Read one chosen fd, limiting bytes even when the underlying file grows.
/// Race-resistance applies to path traversal, not to a hostile writer mutating
/// the *contents* of an already opened inode. The returned hash binds bytes read.
pub async fn read_bounded(path: &Path, roots: &[PathBuf], max_bytes: u64) -> Result<Vec<u8>> {
	if !path.is_absolute() {
		bail!("REA native inspection requires an absolute local path");
	}
	if roots.is_empty() {
		bail!("REA inspection denied: no controller workspace roots configured");
	}
	let chosen = path.to_path_buf();
	let configured = roots.to_vec();
	let file = tokio::task::spawn_blocking(move || {
		let file = open_beneath_root(&chosen, &configured)?;
		let metadata = file.metadata()?;
		if metadata.len() > max_bytes {
			bail!("REA inspection file exceeds {max_bytes} byte limit");
		}
		Ok::<_, anyhow::Error>(file)
	})
	.await
	.context("REA bounded open task failed")??;

	let mut data = Vec::new();
	tokio::fs::File::from_std(file)
		.take(max_bytes + 1)
		.read_to_end(&mut data)
		.await?;
	if data.len() as u64 > max_bytes {
		bail!("REA inspection file exceeds {max_bytes} byte limit");
	}
	Ok(data)
}

#[cfg(test)]
#[path = "rea_files_tests.rs"]
mod rea_files_tests;
