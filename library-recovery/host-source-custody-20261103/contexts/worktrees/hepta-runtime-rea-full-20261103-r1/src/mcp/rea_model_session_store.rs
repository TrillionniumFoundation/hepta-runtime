// Copyright 2026 Muvon Un Limited
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

//! Private bounded storage for model snapshots. Publication is create-only;
//! incomplete staging counts toward the budget and is never a usable session.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;

use super::{MAX_SESSION_COUNT, MAX_STORE_BYTES};

pub(super) fn require_file(metadata: &std::fs::Metadata) -> Result<()> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if !metadata.is_file()
			|| metadata.uid() != unsafe { libc::geteuid() }
			|| metadata.mode() & 0o777 != 0o600
			|| metadata.nlink() != 1
		{
			bail!("model session file must be owned, private, regular and single-linked");
		}
		Ok(())
	}
	#[cfg(not(unix))]
	{
		let _ = metadata;
		bail!("model session storage requires Unix descriptor ownership");
	}
}

pub(super) async fn require_directory(path: &Path) -> Result<()> {
	let metadata = tokio::fs::symlink_metadata(path).await?;
	if !metadata.is_dir() || metadata.file_type().is_symlink() {
		bail!("model session directory must not be a symlink");
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
			bail!("model session directory must be private and owned");
		}
	}
	Ok(())
}

async fn create_directory(path: &Path) -> Result<()> {
	let mut options = tokio::fs::DirBuilder::new();
	#[cfg(unix)]
	options.mode(0o700);
	options.create(path).await?;
	require_directory(path).await
}

pub(super) fn root_path(state: &Path) -> Result<PathBuf> {
	if !state.is_absolute() {
		bail!("model session state must be an absolute administrator-configured directory");
	}
	Ok(state.join("rea-model-sessions-v1"))
}

pub(super) async fn root(state: &Path, create: bool) -> Result<PathBuf> {
	let root = root_path(state)?;
	if create {
		tokio::fs::create_dir_all(state).await?;
		match create_directory(&root).await {
			Ok(()) => {}
			Err(error)
				if error
					.downcast_ref::<std::io::Error>()
					.is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) => {}
			Err(error) => return Err(error),
		}
	}
	require_directory(&root).await?;
	Ok(root)
}

pub(super) async fn lock(root: &Path) -> Result<std::fs::File> {
	let mut options = tokio::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
	let file = options.open(root).await?.into_std().await;
	#[cfg(unix)]
	{
		use std::os::fd::AsRawFd;
		let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
		loop {
			if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
				break;
			}
			let error = std::io::Error::last_os_error();
			if error.kind() != std::io::ErrorKind::WouldBlock {
				return Err(error.into());
			}
			if tokio::time::Instant::now() >= deadline {
				bail!("model session publisher is busy; retry the same open request");
			}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}
	Ok(file)
}

pub(super) async fn admit_quota(root: &Path, incoming: u64) -> Result<()> {
	let mut directories = tokio::fs::read_dir(root).await?;
	let mut count = 0usize;
	let mut bytes = 0u64;
	while let Some(directory) = directories.next_entry().await? {
		count += 1;
		if count >= MAX_SESSION_COUNT {
			bail!("model session count budget exhausted");
		}
		require_directory(&directory.path()).await?;
		let mut members = tokio::fs::read_dir(directory.path()).await?;
		let mut member_count = 0usize;
		while let Some(member) = members.next_entry().await? {
			member_count += 1;
			if member_count > 4096 {
				bail!("model session contains too many store members");
			}
			let metadata = tokio::fs::symlink_metadata(member.path()).await?;
			require_file(&metadata)?;
			bytes = bytes
				.checked_add(metadata.len())
				.ok_or_else(|| anyhow!("model session storage accounting overflow"))?;
			if bytes > MAX_STORE_BYTES {
				bail!("model session store exceeds its total byte budget");
			}
		}
	}
	if bytes
		.checked_add(incoming)
		.is_none_or(|sum| sum > MAX_STORE_BYTES)
	{
		bail!("model session snapshot reservation exceeds the total store budget");
	}
	Ok(())
}

pub(super) async fn staging(root: &Path) -> Result<PathBuf> {
	static SEQUENCE: AtomicU64 = AtomicU64::new(0);
	let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
	let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
	let path = root.join(format!(
		".stage-{}-{stamp:x}-{sequence:x}",
		std::process::id()
	));
	create_directory(&path).await?;
	Ok(path)
}

pub(super) async fn create_private(path: &Path) -> Result<tokio::fs::File> {
	let mut options = tokio::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
	Ok(options.open(path).await?)
}

pub(super) async fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
	let mut file = create_private(path).await?;
	file.write_all(bytes).await?;
	file.sync_all().await?;
	Ok(())
}

pub(super) async fn read_private(path: &Path, root: &Path, limit: u64) -> Result<Vec<u8>> {
	crate::mcp::rea_files::read_private_bounded(path, &[root.to_owned()], limit).await
}

pub(super) async fn publish(from: &Path, to: &Path) -> Result<bool> {
	#[cfg(target_os = "linux")]
	{
		let from = from.to_owned();
		let to = to.to_owned();
		tokio::task::spawn_blocking(move || -> Result<bool> {
			use std::ffi::CString;
			use std::os::unix::ffi::OsStrExt;
			let source = CString::new(from.as_os_str().as_bytes())?;
			let destination = CString::new(to.as_os_str().as_bytes())?;
			let result = unsafe {
				libc::renameat2(
					libc::AT_FDCWD,
					source.as_ptr(),
					libc::AT_FDCWD,
					destination.as_ptr(),
					libc::RENAME_NOREPLACE,
				)
			};
			if result == 0 {
				Ok(false)
			} else {
				let error = std::io::Error::last_os_error();
				if error.kind() == std::io::ErrorKind::AlreadyExists {
					Ok(true)
				} else {
					Err(error.into())
				}
			}
		})
		.await
		.context("model session publication task failed")?
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (from, to);
		bail!("atomic model session publication is currently qualified on Linux only");
	}
}

pub(super) async fn remove_staging(path: &Path) -> Result<()> {
	match tokio::fs::remove_dir_all(path).await {
		Ok(()) => Ok(()),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(error).context("cannot remove this request's model staging directory"),
	}
}
