// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Worker adoption of the original durable job owner's private engine directory.

use anyhow::{anyhow, bail, Context, Result};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::ops::Deref;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::engine_directory as directory;
use directory::Directory;

#[path = "rea_engine_usage.rs"]
mod usage;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerBinding {
	schema: String,
	job_id: String,
	launch_nonce: String,
	path: PathBuf,
	device: u64,
	inode: u64,
}

pub(super) struct Scratch {
	directory: Arc<Directory>,
	owner_managed: bool,
}

impl Deref for Scratch {
	type Target = Path;
	fn deref(&self) -> &Self::Target {
		&self.directory.path
	}
}

impl Scratch {
	pub(super) async fn sampled_bytes(&self, max_bytes: u64, max_entries: usize) -> Result<u64> {
		let directory = Arc::clone(&self.directory);
		tokio::task::spawn_blocking(move || usage::sample(&directory, max_bytes, max_entries))
			.await?
	}

	pub(super) fn cleanup_owner(&self) -> &'static str {
		if self.owner_managed {
			"durable_job"
		} else {
			"standalone_worker"
		}
	}

	pub(super) async fn finish(self) -> Result<bool> {
		tokio::task::spawn_blocking(move || {
			if self.owner_managed {
				// The worker cannot prove that every engine descendant has stopped.
				// Only its original durable owner may remove this namespace.
				self.directory.verify()?;
				Ok(false)
			} else {
				self.directory.remove()?;
				Ok(true)
			}
		})
		.await?
	}
}

fn adopt(raw: &str, engine: &str, job_id: Option<&str>) -> Result<Directory> {
	if raw.len() > 8192 {
		bail!("engine scratch owner binding exceeds its bound");
	}
	let binding: OwnerBinding = serde_json::from_str(raw)?;
	if binding.schema != "hepta.rea.engine-scratch-owner.v1"
		|| binding.job_id.is_empty()
		|| binding.job_id.len() > 96
		|| !binding
			.job_id
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b == b'-')
		|| binding.launch_nonce.len() != 32
		|| !binding
			.launch_nonce
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
		|| job_id != Some(binding.job_id.as_str())
		|| binding.path.file_name().and_then(|s| s.to_str()) != Some("engine-scratch")
	{
		bail!("engine scratch does not identify its original durable owner");
	}
	let root = Directory::open(&binding.path, binding.device, binding.inode)?;
	// The claim survives normal per-operation cleanup. An older worker that
	// ignores the owner directory cannot produce a positive adoption receipt.
	let fd = unsafe {
		libc::openat(
			root.file.as_raw_fd(),
			c"claim.json".as_ptr(),
			libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			0o600,
		)
	};
	if fd < 0 {
		return Err(std::io::Error::last_os_error()).context("engine owner adoption unavailable");
	}
	let mut claim = unsafe { File::from_raw_fd(fd) };
	serde_json::to_writer(
		&mut claim,
		&json!({
			"schema":"hepta.rea.engine-scratch-claim.v1", "owner":binding,
			"worker_pid":std::process::id(), "engine":engine
		}),
	)?;
	claim.write_all(b"\n")?;
	claim.sync_all()?;
	root.file.sync_all()?;
	root.verify()?;
	Ok(root)
}

pub(super) fn create(
	profile_root: &Path,
	engine: &str,
	owner: Option<String>,
	job_id: Option<String>,
) -> Result<Scratch> {
	directory::require_supported_platform()?;
	if !matches!(engine, "jadx" | "ghidra") {
		bail!("unknown fixed engine scratch kind");
	}
	let root = owner
		.as_deref()
		.map(|raw| adopt(raw, engine, job_id.as_deref()))
		.transpose()?;
	let parent = root.as_ref().map_or(profile_root, |root| &root.path);
	let mut random = [0u8; 16];
	ring::rand::SystemRandom::new()
		.fill(&mut random)
		.map_err(|_| anyhow!("engine scratch identity unavailable"))?;
	let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
	let directory = Directory::create(parent, &format!(".hepta-rea-{engine}-{suffix}"))?;
	if let Some(root) = &root {
		root.verify()?;
	}
	eprintln!("hepta_{engine}_owned_scratch={}", directory.path.display());
	Ok(Scratch {
		directory: Arc::new(directory),
		owner_managed: root.is_some(),
	})
}

pub(super) async fn scratch(profile_root: &str, engine: &str) -> Result<Scratch> {
	let profile_root = PathBuf::from(profile_root);
	let engine = engine.to_owned();
	let owner = std::env::var("HEPTA_RUNTIME_ENGINE_SCRATCH").ok();
	let job_id = std::env::var("HEPTA_RUNTIME_JOB_ID").ok();
	tokio::task::spawn_blocking(move || create(&profile_root, &engine, owner, job_id)).await?
}

#[cfg(test)]
#[path = "rea_engine_scratch_tests.rs"]
mod tests;
