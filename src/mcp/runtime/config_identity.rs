// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Opt-in private provenance for the bytes parsed and successfully installed.

use super::{ControllerLocks, InstalledRuntimeConfig, RuntimeConfig};
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// File-origin evidence cannot be constructed or edited by a library caller.
/// The only config accessor is immutable; installation consumes this value.
pub struct LoadedRuntimeConfig {
	config: RuntimeConfig,
	provenance: LoadProvenance,
}

#[derive(Clone, Serialize)]
pub(super) struct LoadProvenance {
	byte_len: usize,
	sha256: String,
}

impl LoadedRuntimeConfig {
	pub fn load(path: &Path) -> Result<Self> {
		let bytes = std::fs::read(path)
			.with_context(|| format!("failed to read runtime config {}", path.display()))?;
		let config: RuntimeConfig = serde_json::from_slice(&bytes)
			.with_context(|| format!("invalid runtime config JSON {}", path.display()))?;
		config.validate()?;
		// Hash the parsed buffer, never a later reopen of the pathname.
		Ok(Self {
			config,
			provenance: LoadProvenance {
				byte_len: bytes.len(),
				sha256: sha256_hex(&bytes),
			},
		})
	}

	pub fn config(&self) -> &RuntimeConfig {
		&self.config
	}

	pub(super) fn into_parts(self) -> (RuntimeConfig, LoadProvenance) {
		(self.config, self.provenance)
	}
}

fn sha256_hex(bytes: &[u8]) -> String {
	ring::digest::digest(&ring::digest::SHA256, bytes)
		.as_ref()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

pub(super) fn require_supported_platform() -> Result<()> {
	#[cfg(unix)]
	{
		Ok(())
	}
	#[cfg(not(unix))]
	{
		bail!("private configuration startup receipts require Unix ownership semantics")
	}
}

pub(super) fn publish_private_receipt(
	installed: &InstalledRuntimeConfig,
	owner: &ControllerLocks,
) -> Result<PathBuf> {
	#[cfg(unix)]
	{
		unix::publish(installed, owner)
	}
	#[cfg(not(unix))]
	{
		let _ = (installed, owner);
		bail!("private configuration startup receipts require Unix ownership semantics")
	}
}

#[cfg(unix)]
mod unix {
	use super::*;
	use ring::rand::SecureRandom;
	use std::ffi::{CStr, CString};
	use std::fs::{File, OpenOptions};
	use std::io::Write;
	use std::os::fd::{AsRawFd, FromRawFd};
	use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
	use std::time::{SystemTime, UNIX_EPOCH};

	const RECEIPT_LIMIT: usize = 4096;

	#[derive(Serialize)]
	struct FileIdentity {
		device: u64,
		inode: u64,
	}

	impl FileIdentity {
		fn of(file: &File) -> Result<Self> {
			let metadata = file.metadata()?;
			Ok(Self {
				device: metadata.dev(),
				inode: metadata.ino(),
			})
		}
	}

	#[derive(Serialize)]
	struct ProcessInstance {
		pid: u32,
		euid: u32,
		instance_id: String,
		receipt_created_unix_ns: u64,
	}

	#[derive(Serialize)]
	struct Receipt<'a> {
		schema: &'static str,
		stage: &'static str,
		raw_input: &'a LoadProvenance,
		installed_config_encoding: &'static str,
		installed_config_sha256: String,
		process: ProcessInstance,
		controller_owner_file: FileIdentity,
		controller_legacy_owner_file: FileIdentity,
	}

	pub(super) fn publish(
		installed: &InstalledRuntimeConfig,
		owner: &ControllerLocks,
	) -> Result<PathBuf> {
		let mut nonce = [0_u8; 16];
		ring::rand::SystemRandom::new()
			.fill(&mut nonce)
			.map_err(|_| anyhow!("cannot create private startup receipt instance identity"))?;
		let instance_id = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
		publish_instance(installed, owner, instance_id)
	}

	pub(super) fn publish_instance(
		installed: &InstalledRuntimeConfig,
		owner: &ControllerLocks,
		instance_id: String,
	) -> Result<PathBuf> {
		let provenance = installed
			.load_provenance
			.as_ref()
			.context("private startup receipt requires same-read file provenance")?;
		if instance_id.len() != 32
			|| !instance_id
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
		{
			bail!("invalid private startup receipt instance identity");
		}
		let uid = unsafe { libc::geteuid() };
		let receipt = Receipt {
			schema: "hepta.runtime.private-config-startup.v1",
			stage: "configuration_initialized",
			raw_input: provenance,
			installed_config_encoding: "serde_json::to_vec(RuntimeConfig)",
			installed_config_sha256: sha256_hex(&serde_json::to_vec(&installed.config)?),
			process: ProcessInstance {
				pid: std::process::id(),
				euid: uid,
				instance_id: instance_id.clone(),
				receipt_created_unix_ns: u64::try_from(
					SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
				)?,
			},
			controller_owner_file: FileIdentity::of(&owner._owner)?,
			controller_legacy_owner_file: FileIdentity::of(&owner._legacy)?,
		};
		let mut bytes = serde_json::to_vec(&receipt)?;
		bytes.push(b'\n');
		if bytes.len() > RECEIPT_LIMIT {
			bail!("private startup receipt exceeds its byte limit");
		}
		let state = OpenOptions::new()
			.read(true)
			.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
			.open(&installed.config.state_dir)
			.context("cannot open private startup receipt state root")?;
		super::super::validate_controller_state_root(&state.metadata()?, uid)?;
		let directory_name = c"startup-receipts";
		if unsafe { libc::mkdirat(state.as_raw_fd(), directory_name.as_ptr(), 0o700) } != 0 {
			let error = std::io::Error::last_os_error();
			if error.kind() != std::io::ErrorKind::AlreadyExists {
				return Err(error).context("cannot create private startup receipt directory");
			}
		}
		let directory = open_relative(
			&state,
			directory_name,
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			0,
		)?;
		super::super::validate_controller_state_root(&directory.metadata()?, uid)?;
		let stem = format!("config-{}-{instance_id}", std::process::id());
		let pending_name = CString::new(format!("{stem}.pending"))?;
		let final_name = CString::new(format!("{stem}.json"))?;
		let mut pending = open_relative(
			&directory,
			&pending_name,
			libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			0o600,
		)?;
		validate_private_file(&pending.metadata()?, uid)?;
		// Only a complete, synced file receives the public-in-this-private-dir
		// .json name. Failures retain .pending bytes for operator inspection.
		pending.write_all(&bytes)?;
		pending.sync_all()?;
		validate_private_file(&pending.metadata()?, uid)?;
		if unsafe {
			libc::linkat(
				directory.as_raw_fd(),
				pending_name.as_ptr(),
				directory.as_raw_fd(),
				final_name.as_ptr(),
				0,
			)
		} != 0
		{
			return Err(std::io::Error::last_os_error())
				.context("private startup receipt publication failed without replacement");
		}
		// After the link succeeds, an I/O error may leave a complete final
		// name. Report failure; never retry, overwrite, or claim readiness.
		if unsafe { libc::unlinkat(directory.as_raw_fd(), pending_name.as_ptr(), 0) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("private startup receipt cleanup failed; publication may exist");
		}
		validate_private_file(&pending.metadata()?, uid)?;
		directory
			.sync_all()
			.context("private startup receipt sync failed; publication may exist")?;
		state
			.sync_all()
			.context("private startup receipt state sync failed; publication may exist")?;
		Ok(installed
			.config
			.state_dir
			.join("startup-receipts")
			.join(format!("{stem}.json")))
	}

	fn open_relative(parent: &File, name: &CStr, flags: i32, mode: u32) -> Result<File> {
		let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) };
		if fd < 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot open private startup receipt entry");
		}
		// openat returned a new owned descriptor, consumed exactly once here.
		Ok(unsafe { File::from_raw_fd(fd) })
	}

	pub(super) fn validate_private_file(metadata: &std::fs::Metadata, uid: u32) -> Result<()> {
		if !metadata.is_file()
			|| metadata.uid() != uid
			|| metadata.nlink() != 1
			|| metadata.mode() & 0o7777 != 0o600
		{
			bail!("private startup receipt must be an owned mode-0600 single-link regular file");
		}
		Ok(())
	}
}

#[cfg(all(test, unix))]
#[path = "config_identity_tests.rs"]
mod tests;
