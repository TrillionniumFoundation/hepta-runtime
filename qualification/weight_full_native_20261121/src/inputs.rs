// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact bounded offline inputs, inherited from the existing intent qualification route.

use anyhow::{anyhow, bail, Result};
use hepta_semantic_source_adapter_study::{SourcePin, MAX_JSON_BYTES};
use serde::Deserialize;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
	pub path: String,
	pub pin: SourcePin,
}

pub fn bounded(path: &Path) -> Result<Vec<u8>> {
	let file = std::fs::File::open(path)?;
	let meta = file.metadata()?;
	if !meta.is_file() || meta.len() > MAX_JSON_BYTES as u64 {
		bail!("bounded regular input required");
	}
	let mut bytes = Vec::new();
	file.take((MAX_JSON_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_JSON_BYTES {
		bail!("input grew beyond bound");
	}
	Ok(bytes)
}

pub fn input(pin: &Input) -> Result<Vec<u8>> {
	let bytes = bounded(Path::new(&pin.path))?;
	pin.pin.verify(&bytes, MAX_JSON_BYTES)?;
	Ok(bytes)
}

pub fn relative(root: &Path, path: &str) -> Result<PathBuf> {
	if Path::new(path)
		.components()
		.any(|p| !matches!(p, Component::Normal(_)))
	{
		bail!("nonrelative fixture source");
	}
	let path = root.join(path).canonicalize()?;
	if !path.starts_with(root) {
		bail!("fixture escapes original root");
	}
	Ok(path)
}

pub fn decoded_gzip(bytes: &[u8]) -> Result<Vec<u8>> {
	let mut decoded = Vec::new();
	flate2::read::GzDecoder::new(bytes)
		.take((MAX_JSON_BYTES + 1) as u64)
		.read_to_end(&mut decoded)?;
	if decoded.len() > MAX_JSON_BYTES {
		bail!("decoded JSON bound");
	}
	Ok(decoded)
}

pub fn write_new(path: &Path, value: &serde_json::Value) -> Result<()> {
	use std::io::Write;
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(path)?;
	file.write_all(&serde_json::to_vec_pretty(value)?)?;
	file.write_all(b"\n")?;
	file.sync_all()?;
	std::fs::File::open(
		path.parent()
			.ok_or_else(|| anyhow!("output parent missing"))?,
	)?
	.sync_all()?;
	Ok(())
}
