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

//! Committed row pages and tensor-name buckets. A query decodes only selected
//! pages, and a named read resolves one bucket instead of scanning the directory.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

use super::{hash, store, Manifest, PagePin, MAX_INDEX_BYTES, PAGE_ROWS};

const MAX_PAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_NAME_BUCKET_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NameRow {
	name: String,
	row: usize,
}

pub(super) struct BuiltIndex {
	pub summary: Value,
	pub tensor_count: usize,
	pub metadata_count: usize,
	pub tensor_pages: Vec<PagePin>,
	pub metadata_pages: Vec<PagePin>,
	pub tensor_names: Vec<Option<PagePin>>,
	pub stored_bytes: usize,
}

fn bucket(name: &str) -> usize {
	use sha2::{Digest, Sha256};
	usize::from(Sha256::digest(name.as_bytes())[0])
}

fn page_name(collection: &str, page: usize) -> String {
	format!("{collection}-{page:04x}.json")
}

fn bucket_name(number: usize) -> String {
	format!("names-{number:02x}.json")
}

async fn write_pin(
	path: &Path,
	bytes: Vec<u8>,
	rows: usize,
	max: usize,
	used: &mut usize,
) -> Result<PagePin> {
	if bytes.len() > max {
		bail!("model index page exceeds its byte budget; snapshot was not published");
	}
	*used = used
		.checked_add(bytes.len())
		.ok_or_else(|| anyhow!("model index accounting overflow"))?;
	if *used > MAX_INDEX_BYTES {
		bail!("model index exceeds the complete retained-index budget");
	}
	let pin = PagePin {
		sha256: hash(&bytes),
		byte_length: bytes.len(),
		rows,
	};
	store::write_private(path, &bytes).await?;
	Ok(pin)
}

async fn write_pages(
	stage: &Path,
	collection: &str,
	rows: &[Value],
	used: &mut usize,
) -> Result<Vec<PagePin>> {
	let mut pins = Vec::new();
	for (number, page) in rows.chunks(PAGE_ROWS).enumerate() {
		pins.push(
			write_pin(
				&stage.join(page_name(collection, number)),
				serde_json::to_vec(page)?,
				page.len(),
				MAX_PAGE_BYTES,
				used,
			)
			.await?,
		);
	}
	Ok(pins)
}

pub(super) async fn build(
	stage: &Path,
	mut report: Value,
	source_hash: &str,
) -> Result<BuiltIndex> {
	let result = report
		.get_mut("result")
		.and_then(Value::as_object_mut)
		.ok_or_else(|| anyhow!("snapshot index omitted its collections"))?;
	let tensors = result
		.remove("tensors")
		.and_then(|v| v.as_array().cloned())
		.ok_or_else(|| anyhow!("snapshot index omitted tensor rows"))?;
	let metadata = result
		.remove("metadata")
		.and_then(|v| v.as_array().cloned())
		.ok_or_else(|| anyhow!("snapshot index omitted metadata rows"))?;
	if tensors.len() > 100_000 || metadata.len() > 100_000 {
		bail!("snapshot directory exceeds its row budget");
	}
	let mut used = 0usize;
	let tensor_pages = write_pages(stage, "tensors", &tensors, &mut used).await?;
	let metadata_pages = write_pages(stage, "metadata", &metadata, &mut used).await?;
	let mut names: Vec<Vec<NameRow>> = (0..256).map(|_| Vec::new()).collect();
	for (row, tensor) in tensors.iter().enumerate() {
		let name = tensor["name"]
			.as_str()
			.ok_or_else(|| anyhow!("snapshot tensor row omitted its name"))?;
		names[bucket(name)].push(NameRow {
			name: name.to_owned(),
			row,
		});
	}
	let mut tensor_names = Vec::with_capacity(256);
	for (number, rows) in names.iter().enumerate() {
		tensor_names.push(if rows.is_empty() {
			None
		} else {
			Some(
				write_pin(
					&stage.join(bucket_name(number)),
					serde_json::to_vec(rows)?,
					rows.len(),
					MAX_NAME_BUCKET_BYTES,
					&mut used,
				)
				.await?,
			)
		});
	}
	let source = report["source"]
		.as_object_mut()
		.ok_or_else(|| anyhow!("snapshot index omitted source identity"))?;
	source.remove("observed_version");
	source.insert("full_sha256".into(), json!(source_hash));
	source.insert(
		"identity_scope".into(),
		json!("captured_snapshot_full_hash"),
	);
	report["operation"] = json!("retained_model_directory");
	report["result"] = json!({"tensor_count":tensors.len(),"metadata_count":metadata.len()});
	Ok(BuiltIndex {
		summary: report,
		tensor_count: tensors.len(),
		metadata_count: metadata.len(),
		tensor_pages,
		metadata_pages,
		tensor_names,
		stored_bytes: used,
	})
}

async fn read_pin(directory: &Path, filename: &str, pin: &PagePin, cap: usize) -> Result<Vec<u8>> {
	if pin.byte_length > cap {
		bail!("model session index pin exceeds its page budget");
	}
	let bytes = store::read_private(&directory.join(filename), directory, cap as u64).await?;
	if bytes.len() != pin.byte_length || hash(&bytes) != pin.sha256 {
		bail!("model session index page differs from its committed digest");
	}
	Ok(bytes)
}

async fn page(
	directory: &Path,
	collection: &str,
	number: usize,
	pin: &PagePin,
) -> Result<Vec<Value>> {
	let bytes = read_pin(
		directory,
		&page_name(collection, number),
		pin,
		MAX_PAGE_BYTES,
	)
	.await?;
	let value = crate::mcp::rea_evidence::parse_unique_json(&bytes)?;
	let rows: Vec<Value> = serde_json::from_value(value).context("invalid model index page")?;
	if rows.len() != pin.rows || rows.is_empty() || rows.len() > PAGE_ROWS {
		bail!("model session index page has an invalid row count");
	}
	Ok(rows)
}

pub(super) async fn query(
	directory: &Path,
	manifest: &Manifest,
	collection: super::super::Collection,
	offset: usize,
	limit: usize,
) -> Result<(Value, usize)> {
	let (name, total, pins) = match collection {
		super::super::Collection::Tensors => {
			("tensors", manifest.tensor_count, &manifest.tensor_pages)
		}
		super::super::Collection::Metadata => (
			"metadata",
			manifest.metadata_count,
			&manifest.metadata_pages,
		),
		super::super::Collection::Summary => {
			if offset != 0 {
				bail!("summary queries do not accept a row offset");
			}
			return Ok((manifest.summary.clone(), 0));
		}
	};
	if offset > total {
		bail!("model session query offset exceeds its collection");
	}
	let end = offset.saturating_add(limit).min(total);
	let mut result = Vec::with_capacity(end - offset);
	let mut pages_read = 0usize;
	if end > offset {
		for number in (offset / PAGE_ROWS)..=((end - 1) / PAGE_ROWS) {
			let pin = pins
				.get(number)
				.ok_or_else(|| anyhow!("model session page is missing"))?;
			let rows = page(directory, name, number, pin).await?;
			let base = number * PAGE_ROWS;
			let first = offset.saturating_sub(base);
			let last = (end - base).min(rows.len());
			if first > last || last > rows.len() {
				bail!("model session pagination is inconsistent");
			}
			result.extend_from_slice(&rows[first..last]);
			pages_read += 1;
		}
	}
	if result.len() != end - offset {
		bail!("model session pagination omitted committed rows");
	}
	Ok((
		json!({"collection":collection,"offset":offset,"limit":limit,"total":total,
		"next_offset":(end < total).then_some(end),"rows":result}),
		pages_read,
	))
}

pub(super) async fn tensor(directory: &Path, manifest: &Manifest, name: &str) -> Result<Value> {
	if name.is_empty() || name.len() > 4096 {
		bail!("tensor selection requires a nonempty name of at most 4096 bytes");
	}
	let number = bucket(name);
	let pin = manifest.tensor_names[number]
		.as_ref()
		.ok_or_else(|| anyhow!("selected tensor does not exist in this snapshot"))?;
	let bytes = read_pin(directory, &bucket_name(number), pin, MAX_NAME_BUCKET_BYTES).await?;
	let value = crate::mcp::rea_evidence::parse_unique_json(&bytes)?;
	let names: Vec<NameRow> = serde_json::from_value(value)?;
	if names.len() != pin.rows {
		bail!("model session name bucket count differs from its commitment");
	}
	let mut matches = names.iter().filter(|entry| entry.name == name);
	let selected = matches
		.next()
		.ok_or_else(|| anyhow!("selected tensor does not exist"))?;
	if matches.next().is_some() || selected.row >= manifest.tensor_count {
		bail!("model session tensor-name index is inconsistent");
	}
	let page_number = selected.row / PAGE_ROWS;
	let rows = page(
		directory,
		"tensors",
		page_number,
		&manifest.tensor_pages[page_number],
	)
	.await?;
	let tensor = rows
		.get(selected.row % PAGE_ROWS)
		.filter(|row| row["name"].as_str() == Some(name))
		.ok_or_else(|| anyhow!("model session name index does not match its tensor page"))?;
	Ok(tensor.clone())
}

pub(super) async fn verify_all(directory: &Path, manifest: &Manifest) -> Result<()> {
	for (collection, pins) in [
		("tensors", &manifest.tensor_pages),
		("metadata", &manifest.metadata_pages),
	] {
		for (number, pin) in pins.iter().enumerate() {
			let _ = page(directory, collection, number, pin).await?;
		}
	}
	for (number, pin) in manifest.tensor_names.iter().enumerate() {
		if let Some(pin) = pin {
			let _ = read_pin(directory, &bucket_name(number), pin, MAX_NAME_BUCKET_BYTES).await?;
		}
	}
	Ok(())
}
