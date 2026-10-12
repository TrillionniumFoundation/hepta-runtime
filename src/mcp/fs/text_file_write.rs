// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! Bounded plain-text file publication with explicit create/replace/append semantics.
//!
//! This fills an actual Desktop Commander file-editing gap, not a renamed shell
//! or an alternative route around client permission checks. Requires the already
//! configured controller-local workspace and ordinary user filesystem rights.
//! Every operation changes file state; the tool is accurately annotated as such.

use super::remote::{resolve_path_source, PathSource};
use crate::mcp::McpToolCall;
use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

const MAX_TEXT_INPUT: usize = 64 * 1024;

fn local_workspace_path(path: &str, workdir: &Path) -> Result<PathBuf> {
	if crate::mcp::runtime::config::maybe_runtime_config().is_none() {
		bail!("Plain-text publishing requires an explicit configured controller workspace");
	}
	match resolve_path_source(path, workdir) {
		PathSource::Local(local) => {
			crate::mcp::runtime::config::check_local_path(&local)?;
			Ok(local)
		}
		PathSource::Remote { .. } => {
			bail!("Plain-text publication supports only controller-local workspace files")
		}
	}
}

/// Publish bounded UTF-8 content with a caller-pinned source digest.
/// For an existing file, append/rewrite publish a new inode atomically; this
/// is not an in-place editor or an atomic transaction with external writers.
pub async fn execute_text_file_write(call: &McpToolCall) -> Result<String> {
	let path = call
		.parameters
		.get("path")
		.and_then(serde_json::Value::as_str)
		.ok_or_else(|| anyhow!("path is required"))?;
	let mode = call
		.parameters
		.get("mode")
		.and_then(serde_json::Value::as_str)
		.ok_or_else(|| anyhow!("mode is required"))?;
	if !matches!(mode, "create" | "replace" | "append") {
		bail!("Unsupported text publication mode");
	}
	let expected = call
		.parameters
		.get("expected_sha256")
		.and_then(serde_json::Value::as_str)
		.ok_or_else(|| anyhow!("expected_sha256 is mandatory"))?;
	if !valid_expectation(mode, expected) {
		bail!("create needs 'absent'; existing-file modes need exact lowercase SHA256");
	}
	let content = call
		.parameters
		.get("content")
		.and_then(serde_json::Value::as_str)
		.ok_or_else(|| anyhow!("content must be UTF-8 text"))?;
	if content.len() > MAX_TEXT_INPUT {
		bail!("Text input exceeds 64 KiB; use explicit chunked binary tools");
	}
	let target = local_workspace_path(path, &call.workdir)?;
	let mode = mode.to_owned();
	let mode_for_response = mode.clone();
	let expected = expected.to_owned();
	let content = content.to_owned();
	let target_name = target.display().to_string();
	let result = tokio::task::spawn_blocking(move || {
		#[cfg(target_os = "linux")]
		{
			linux::publish(&target, &mode, &expected, &content)
		}
		#[cfg(not(target_os = "linux"))]
		{
			let _ = (target, mode, expected, content);
			bail!("This constrained text publisher currently requires Linux")
		}
	})
	.await
	.context("Text publisher task failed")??;
	super::delta::forget(&PathSource::Local(PathBuf::from(&target_name)));
	Ok(serde_json::json!({
		"path": target_name,
		"mode": mode_for_response,
		"published": true,
		"bytes": result.bytes,
		"sha256": result.sha256,
		"version": result.version,
		"was_new_file": result.was_new_file,
		"same_path_atomic_publication": true,
		"external_writers_transactionally_excluded": false,
	})
	.to_string())
}

fn valid_expectation(mode: &str, expected: &str) -> bool {
	if mode == "create" {
		return expected == "absent";
	}
	expected.len() == 64
		&& expected
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(target_os = "linux")]
mod linux {
	use anyhow::{anyhow, bail, Context, Result};
	use sha2::{Digest, Sha256};
	use std::ffi::CString;
	use std::io::{Read, Write};
	use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
	use std::os::unix::ffi::OsStrExt;
	use std::path::{Component, Path};

	const MAX_EXISTING_BYTES: u64 = 4 * 1024 * 1024;
	const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024 + super::MAX_TEXT_INPUT;

	pub struct Published {
		pub bytes: usize,
		pub sha256: String,
		pub version: String,
		pub was_new_file: bool,
	}

	fn split_path(path: &Path) -> Result<(OwnedFd, CString)> {
		if !path.is_absolute() {
			bail!("Expected an absolute controller path");
		}
		let components = path.components().collect::<Vec<_>>();
		let mut parent = open_dir_root()?;
		let mut tail = None;
		for (index, component) in components.iter().enumerate() {
			match component {
				Component::RootDir => {}
				Component::Normal(name) => {
					let c = CString::new(name.as_bytes()).context("Path contains NUL")?;
					if index == components.len() - 1 {
						tail = Some(c);
					} else {
						parent = open_dir_at(&parent, &c)
							.context("Parent directory absent or symlinked")?;
					}
				}
				_ => bail!("Path contains a relative or traversal component"),
			}
		}
		Ok((
			parent,
			tail.ok_or_else(|| anyhow!("Filesystem root cannot be a file"))?,
		))
	}

	fn open_dir_root() -> Result<OwnedFd> {
		// SAFETY: c string literal and libc open flags meet open() contracts.
		let raw = unsafe {
			libc::open(
				c"/".as_ptr(),
				libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			)
		};
		own(raw)
	}

	fn own(raw: i32) -> Result<OwnedFd> {
		if raw < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		// SAFETY: libc returned a newly owned valid file descriptor.
		Ok(unsafe { OwnedFd::from_raw_fd(raw) })
	}

	fn open_dir_at(parent: &OwnedFd, name: &CString) -> Result<OwnedFd> {
		// SAFETY: parent FD is live and name NUL-terminated.
		let raw = unsafe {
			libc::openat(
				parent.as_raw_fd(),
				name.as_ptr(),
				libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			)
		};
		own(raw)
	}

	fn open_existing(parent: &OwnedFd, name: &CString) -> Result<std::fs::File> {
		// SAFETY: parent FD is valid and CString has a terminating NUL.
		let raw = unsafe {
			libc::openat(
				parent.as_raw_fd(),
				name.as_ptr(),
				libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
			)
		};
		Ok(std::fs::File::from(own(raw)?))
	}

	fn stat_fd(fd: i32) -> Result<libc::stat> {
		let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
		// SAFETY: valid fd and writable stat storage.
		if unsafe { libc::fstat(fd, st.as_mut_ptr()) } < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		// SAFETY: fstat returned success.
		Ok(unsafe { st.assume_init() })
	}

	fn same_identity(a: &libc::stat, b: &libc::stat) -> bool {
		a.st_dev == b.st_dev
			&& a.st_ino == b.st_ino
			&& a.st_size == b.st_size
			&& a.st_mtime == b.st_mtime
			&& a.st_mtime_nsec == b.st_mtime_nsec
			&& a.st_ctime == b.st_ctime
			&& a.st_ctime_nsec == b.st_ctime_nsec
	}

	fn path_stat(parent: &OwnedFd, name: &CString) -> Result<libc::stat> {
		let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
		// SAFETY: parent FD and CString remain valid for this call.
		let rc = unsafe {
			libc::fstatat(
				parent.as_raw_fd(),
				name.as_ptr(),
				st.as_mut_ptr(),
				libc::AT_SYMLINK_NOFOLLOW,
			)
		};
		if rc < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		// SAFETY: successful fstatat initialized st.
		Ok(unsafe { st.assume_init() })
	}

	fn ordinary_file(st: &libc::stat, fd: i32) -> Result<()> {
		if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
			|| st.st_uid != unsafe { libc::geteuid() }
			|| st.st_nlink != 1
			|| (st.st_mode & 0o7111) != 0
			|| (st.st_mode & 0o200) == 0
		{
			bail!("Existing text target must be a single-linked, account-owned, owner-writable non-executable regular file");
		}
		// Do not silently erase ACLs, capabilities or other extended metadata
		// when publishing a new inode.
		// SAFETY: valid opened ordinary-file fd and null buffer when size==0.
		let n = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
		if n < 0 {
			return Err(std::io::Error::last_os_error()).context("Cannot verify source xattrs");
		}
		if n != 0 {
			bail!("Existing text file has xattrs/ACLs; this publisher refuses metadata loss");
		}
		Ok(())
	}

	fn hex_digest(raw: &[u8]) -> String {
		Sha256::digest(raw)
			.iter()
			.map(|b| format!("{b:02x}"))
			.collect::<String>()
	}

	fn lock_dir(fd: i32) -> Result<()> {
		// Advisory coordination only for calls to this publisher; independent
		// processes are NOT excluded, and the response states this explicitly.
		// SAFETY: directory descriptor and flock flags documented by libc.
		if unsafe { libc::flock(fd, libc::LOCK_EX) } < 0 {
			return Err(std::io::Error::last_os_error())
				.context("Cannot acquire directory writer lock");
		}
		Ok(())
	}

	fn temp_name() -> Result<CString> {
		let mut entropy = [0u8; 16];
		// SAFETY: writable byte array and its size are supplied.
		let got = unsafe { libc::getrandom(entropy.as_mut_ptr().cast(), entropy.len(), 0) };
		if got != entropy.len() as isize {
			bail!("Failed to obtain full random temporary-file identity");
		}
		let suffix = entropy
			.iter()
			.map(|b| format!("{b:02x}"))
			.collect::<String>();
		CString::new(format!(".hepta-text-{suffix}")).map_err(Into::into)
	}

	fn staging_file(parent: &OwnedFd, temp: &CString) -> Result<std::fs::File> {
		// SAFETY: fd-held parent and checked CString; O_EXCL prevents collisions.
		let raw = unsafe {
			libc::openat(
				parent.as_raw_fd(),
				temp.as_ptr(),
				libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
				0o600,
			)
		};
		Ok(std::fs::File::from(own(raw)?))
	}

	fn version(st: &libc::stat) -> String {
		format!(
			"{}:{}:{}:{}:{}:{}:{}",
			st.st_dev,
			st.st_ino,
			st.st_size,
			st.st_mtime,
			st.st_mtime_nsec,
			st.st_ctime,
			st.st_ctime_nsec
		)
	}

	pub fn publish(path: &Path, mode: &str, expected: &str, text: &str) -> Result<Published> {
		let (parent, name) = split_path(path)?;
		lock_dir(parent.as_raw_fd())?;
		let mut original = None;
		let mut output = Vec::new();
		let mut file_mode = 0o600u32;
		if mode == "create" {
			match path_stat(&parent, &name) {
				Ok(_) => bail!("Destination already exists; create-only operation refused"),
				Err(error) => {
					if !matches!(error.downcast_ref::<std::io::Error>(),
                        Some(e) if e.kind() == std::io::ErrorKind::NotFound)
					{
						return Err(error);
					}
				}
			}
		} else {
			let mut source = open_existing(&parent, &name)
				.context("Existing file cannot be opened without following symlinks")?;
			let st = stat_fd(source.as_raw_fd())?;
			ordinary_file(&st, source.as_raw_fd())?;
			if st.st_size < 0 || st.st_size as u64 > MAX_EXISTING_BYTES {
				bail!("Existing plain-text file exceeds 4 MiB reader limit");
			}
			(&mut source)
				.take(MAX_EXISTING_BYTES + 1)
				.read_to_end(&mut output)
				.context("Read bounded previous text bytes")?;
			if output.len() > MAX_EXISTING_BYTES as usize {
				bail!("Existing file grew beyond the limit");
			}
			let after = stat_fd(source.as_raw_fd())?;
			if !same_identity(&st, &after) {
				bail!("Existing file changed during text read");
			}
			if std::str::from_utf8(&output).is_err() {
				bail!("Existing file is not valid UTF-8");
			}
			if hex_digest(&output) != expected {
				bail!("Source SHA256 mismatch; no write performed");
			}
			file_mode = st.st_mode & 0o777;
			original = Some(st);
		}
		match mode {
			"create" | "replace" => output = text.as_bytes().to_vec(),
			"append" => output.extend_from_slice(text.as_bytes()),
			_ => bail!("Unsupported text write mode"),
		}
		if output.len() > MAX_RESULT_BYTES {
			bail!("Published text exceeds bounded output limit");
		}
		let digest = hex_digest(&output);
		let temp = temp_name()?;
		let mut staged_identity = None;
		let result = (|| -> Result<()> {
			let mut stage = staging_file(&parent, &temp)?;
			// SAFETY: the new staging FD remains valid through metadata setup.
			if unsafe { libc::fchmod(stage.as_raw_fd(), file_mode) } < 0 {
				return Err(std::io::Error::last_os_error()).context("Cannot set file permissions");
			}
			stage
				.write_all(&output)
				.context("Cannot write entire staging file")?;
			stage.sync_all().context("Cannot fsync staged text data")?;
			let staged = stat_fd(stage.as_raw_fd())?;
			staged_identity = Some((staged.st_dev, staged.st_ino, staged.st_size));
			drop(stage);
			if let Some(old) = original {
				let now = path_stat(&parent, &name)?;
				if !same_identity(&old, &now) {
					bail!("Target path changed before publication");
				}
			}
			// SAFETY: fd-held parent and CString names; no shell or arbitrary
			// external path resolver is used. The create path cannot overwrite.
			let rc = unsafe {
				libc::renameat2(
					parent.as_raw_fd(),
					temp.as_ptr(),
					parent.as_raw_fd(),
					name.as_ptr(),
					if original.is_none() {
						libc::RENAME_NOREPLACE
					} else {
						0
					},
				)
			};
			if rc < 0 {
				return Err(std::io::Error::last_os_error())
					.context("Atomic text publication refused");
			}
			// SAFETY: the held parent is still a valid directory descriptor.
			if unsafe { libc::fsync(parent.as_raw_fd()) } < 0 {
				return Err(std::io::Error::last_os_error())
					.context("Text published but directory durability uncertain");
			}
			Ok(())
		})();
		// SAFETY: the temp name is always a generated CString; cleanup is
		// safe even when rename succeeded (then it no longer exists).
		unsafe {
			libc::unlinkat(parent.as_raw_fd(), temp.as_ptr(), 0);
		}
		result?;
		let published = path_stat(&parent, &name)?;
		if staged_identity != Some((published.st_dev, published.st_ino, published.st_size)) {
			bail!("Published pathname identity changed before result verification");
		}
		Ok(Published {
			bytes: output.len(),
			sha256: digest,
			version: version(&published),
			was_new_file: original.is_none(),
		})
	}
}

#[cfg(test)]
#[path = "text_file_write_tests.rs"]
mod tests;
