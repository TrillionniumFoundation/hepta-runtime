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

/// Compare two snapshots of the *same open descriptor*, not path lookups.
/// This detects ordinary concurrent truncation, append, in-place writes and
/// metadata substitution. A malicious same-UID writer with enough control to
/// restore metadata or race both snapshots remains outside this guarantee.
#[cfg(unix)]
fn ensure_unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	if before.dev() != after.dev()
		|| before.ino() != after.ino()
		|| before.len() != after.len()
		|| before.mode() != after.mode()
		|| before.uid() != after.uid()
		|| before.gid() != after.gid()
		|| before.nlink() != after.nlink()
		|| before.mtime() != after.mtime()
		|| before.mtime_nsec() != after.mtime_nsec()
		|| before.ctime() != after.ctime()
		|| before.ctime_nsec() != after.ctime_nsec()
	{
		bail!("REA inspection denied: admitted artifact changed during read");
	}
	Ok(())
}

/// A retained local preview must be read from a private, single-linked file.
/// This is checked against the opened fd, not a mutable pathname before open.
#[cfg(unix)]
fn require_private_inode(meta: &std::fs::Metadata) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	if !meta.is_file()
		|| meta.nlink() != 1
		|| meta.uid() != unsafe { libc::geteuid() }
		|| meta.mode() & 0o777 != 0o600
	{
		bail!("REA private preview inode must be owned, single-linked and mode 0600");
	}
	Ok(())
}

#[cfg(unix)]
fn open_beneath_root(path: &Path, roots: &[PathBuf]) -> Result<std::fs::File> {
	use std::ffi::CString;
	use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
	use std::os::unix::ffi::OsStrExt;
	use std::path::Component;

	for root in roots {
		if !root.is_absolute() {
			bail!("REA inspection denied: configured workspace root must be absolute");
		}
		let Ok(relative) = path.strip_prefix(root) else {
			continue;
		};
		let components = relative
			.components()
			.map(|component| match component {
				Component::Normal(segment) => {
					CString::new(segment.as_bytes()).context("REA inspection path contains NUL")
				}
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
		let (final_name, directories) = components
			.split_last()
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
	bail!("REA inspection denied: path is outside controller workspace roots");
}

#[cfg(not(unix))]
fn open_beneath_root(_path: &Path, _roots: &[PathBuf]) -> Result<std::fs::File> {
	bail!("REA native inspection requires Unix file-descriptor admission on this build");
}

/// Read one chosen fd, limiting bytes even when the underlying file grows.
/// A same-descriptor metadata snapshot also rejects ordinary concurrent writes.
/// A privileged writer restoring metadata or racing the snapshots remains an
/// explicit open limitation; the returned hash binds only the captured bytes.
pub async fn read_bounded(path: &Path, roots: &[PathBuf], max_bytes: u64) -> Result<Vec<u8>> {
	read_bounded_impl(path, roots, max_bytes, false).await
}

/// Read an exclusively owned private local preview from a single descriptor.
/// A pre-open path check is insufficient: an attacker could swap in a
/// hard-linked replacement before open. This does not prevent same-UID
/// in-place tampering or provide cryptographic authentication.
pub(super) async fn read_private_bounded(
	path: &Path,
	roots: &[PathBuf],
	max_bytes: u64,
) -> Result<Vec<u8>> {
	read_bounded_impl(path, roots, max_bytes, true).await
}

async fn read_bounded_impl(
	path: &Path,
	roots: &[PathBuf],
	max_bytes: u64,
	private: bool,
) -> Result<Vec<u8>> {
	if !path.is_absolute() {
		bail!("REA native inspection requires an absolute local path");
	}
	if roots.is_empty() {
		bail!("REA inspection denied: no controller workspace roots configured");
	}
	let chosen = path.to_path_buf();
	let configured = roots.to_vec();
	let (file, before) = tokio::task::spawn_blocking(move || {
		let file = open_beneath_root(&chosen, &configured)?;
		let metadata = file.metadata()?;
		if metadata.len() > max_bytes {
			bail!("REA inspection file exceeds {max_bytes} byte limit");
		}
		#[cfg(unix)]
		if private {
			require_private_inode(&metadata)?;
		}
		#[cfg(not(unix))]
		if private {
			bail!("REA private preview reads require Unix fd ownership validation");
		}
		Ok::<_, anyhow::Error>((file, metadata))
	})
	.await
	.context("REA bounded open task failed")??;

	let mut file = tokio::fs::File::from_std(file);
	let mut data = Vec::new();
	(&mut file)
		.take(max_bytes + 1)
		.read_to_end(&mut data)
		.await?;
	if data.len() as u64 > max_bytes {
		bail!("REA inspection file exceeds {max_bytes} byte limit");
	}
	#[cfg(unix)]
	{
		let after = file.metadata().await?;
		ensure_unchanged(&before, &after)?;
		if private {
			require_private_inode(&after)?;
		}
	}
	Ok(data)
}

#[cfg(test)]
#[path = "rea_files_tests.rs"]
mod rea_files_tests;
