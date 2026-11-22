// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded explicit input capabilities and create-only durable research files.

use anyhow::{anyhow, bail, Context, Result};
use hepta_continuation_runtime_study::task::Public;
use hepta_semantic_source_adapter_study::{digest, unique_json, SourcePin};
use hepta_weight_program_study::snapshot::{valid_digest, EditDomain};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

pub const MAX_INPUT: usize = 32 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
	pub path: String,
	pub sha256: String,
	pub bytes: usize,
}

impl Pin {
	pub fn verify(&self, bytes: &[u8]) -> Result<()> {
		if self.bytes > MAX_INPUT
			|| self.bytes != bytes.len()
			|| !valid_digest(&self.sha256)
			|| digest(bytes) != self.sha256
		{
			bail!("pinned input byte identity differs");
		}
		Ok(())
	}
	pub fn read(&self) -> Result<Vec<u8>> {
		absolute(Path::new(&self.path))?;
		let bytes = read(Path::new(&self.path), MAX_INPUT)?;
		self.verify(&bytes)?;
		Ok(bytes)
	}
	pub fn source_pin(&self, original_source_id: &str) -> SourcePin {
		SourcePin {
			source_id: original_source_id.into(),
			sha256: self.sha256.clone(),
			size_bytes: self.bytes as u64,
		}
	}
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
	pub primary: Public,
	pub preservation: Vec<Public>,
	pub next_task: Public,
	pub minimum_gain: f64,
	pub maximum_preservation_loss: f64,
}

impl Policy {
	pub fn validate(&self) -> Result<()> {
		if !self.minimum_gain.is_finite()
			|| !(0.0..=2.0).contains(&self.minimum_gain)
			|| !self.maximum_preservation_loss.is_finite()
			|| !(0.0..=0.1).contains(&self.maximum_preservation_loss)
			|| self.preservation.len() > 8
		{
			bail!("bounded predeclared evaluation policy required");
		}
		self.primary.validate()?;
		self.next_task.validate()?;
		for task in &self.preservation {
			task.validate()?;
		}
		Ok(())
	}
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
	pub schema: String,
	pub role: String,
	pub source_bridge: Pin,
	pub source_gzip: Pin,
	pub decoded_source: SourcePin,
	pub semantic_contract: Pin,
	pub program: Pin,
	pub domain: EditDomain,
	pub policy: Policy,
}

impl Request {
	pub fn parse(bytes: &[u8]) -> Result<Self> {
		let value: Self = serde_json::from_value(unique_json(bytes)?)?;
		if value.schema != "hepta.weight-lifecycle-request.v1"
			|| value.role != "exposed_research_execution"
			|| value.decoded_source.size_bytes > MAX_INPUT as u64
			|| !valid_digest(&value.decoded_source.sha256)
		{
			bail!("explicit bounded research lifecycle request required");
		}
		value.policy.validate()?;
		Ok(value)
	}
}

pub fn absolute(path: &Path) -> Result<()> {
	if !path.is_absolute()
		|| path
			.components()
			.any(|c| matches!(c, Component::CurDir | Component::ParentDir))
	{
		bail!("absolute normalized path required");
	}
	Ok(())
}

pub fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
	let mut file = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
		.open(path)
		.with_context(|| format!("read {}", path.display()))?;
	let before = file.metadata()?;
	if !before.is_file() || before.len() > cap as u64 {
		bail!("bounded regular file required");
	}
	let mut bytes = Vec::new();
	(&mut file).take(cap as u64 + 1).read_to_end(&mut bytes)?;
	let after = file.metadata()?;
	if bytes.len() > cap
		|| before.len() != bytes.len() as u64
		|| before.dev() != after.dev()
		|| before.ino() != after.ino()
		|| before.mtime() != after.mtime()
		|| before.mtime_nsec() != after.mtime_nsec()
		|| before.ctime() != after.ctime()
		|| before.ctime_nsec() != after.ctime_nsec()
	{
		bail!("input changed while reading");
	}
	Ok(bytes)
}

pub fn new_dir(path: &Path) -> Result<()> {
	absolute(path)?;
	let parent = path
		.parent()
		.ok_or_else(|| anyhow!("directory parent missing"))?;
	if parent.canonicalize()? != parent {
		bail!("symlinked research parent refused");
	}
	std::fs::DirBuilder::new().mode(0o700).create(path)?;
	File::open(parent)?.sync_all()?;
	Ok(())
}

pub fn private_dir(path: &Path) -> Result<()> {
	absolute(path)?;
	if path.canonicalize()? != path {
		bail!("symlinked research directory refused");
	}
	let m = path.symlink_metadata()?;
	if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
		bail!("research directory must be private and owned by this uid");
	}
	Ok(())
}

pub fn save(path: &Path, bytes: &[u8]) -> Result<()> {
	let mut file = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW)
		.open(path)?;
	file.write_all(bytes)?;
	file.sync_all()?;
	File::open(
		path.parent()
			.ok_or_else(|| anyhow!("output parent missing"))?,
	)?
	.sync_all()?;
	Ok(())
}

pub fn save_json(path: &Path, value: &Value) -> Result<()> {
	save(path, &serde_json::to_vec_pretty(value)?)
}

pub fn result_name(name: &str) -> Result<()> {
	if !name.ends_with(".json")
		|| name.len() > 80
		|| name.starts_with('.')
		|| !name
			.bytes()
			.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
	{
		bail!("simple create-only JSON result filename required");
	}
	Ok(())
}
