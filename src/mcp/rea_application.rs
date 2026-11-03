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

//! Bounded declarations from the fixed APK/JAR manifest entry. Admission,
//! complete-file identity and compressed payload capture share one descriptor.
//! ZIP structure validation is reused from the native archive indexer.

use anyhow::{anyhow, bail, Context, Result};
use flate2::{Decompress, FlushDecompress, Status};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[path = "rea_application_parser.rs"]
mod parser;

const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationKind {
	Apk,
	Jar,
}

impl ApplicationKind {
	fn member(self) -> &'static str {
		match self {
			Self::Apk => "AndroidManifest.xml",
			Self::Jar => "META-INF/MANIFEST.MF",
		}
	}
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationCollection {
	#[default]
	Summary,
	Components,
	Permissions,
	Attributes,
}

fn default_limit() -> usize {
	64
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectApplicationParams {
	/// Absolute APK/JAR file inside configured controller workspace roots.
	pub path: String,
	/// Select the fixed manifest name; never inferred from the filename.
	pub kind: ApplicationKind,
	/// Exact complete-archive SHA-256; required for continuation pages.
	pub expected_sha256: Option<String>,
	#[serde(default)]
	pub collection: ApplicationCollection,
	#[serde(default)]
	pub offset: usize,
	/// 1..=256 rows. Summary returns declarations and counts without a row page.
	#[serde(default = "default_limit")]
	pub limit: usize,
}

fn validate(params: &InspectApplicationParams) -> Result<()> {
	if !(1..=256).contains(&params.limit) || params.offset > MAX_ROWS {
		bail!("application manifest page requires limit 1..=256 and a bounded offset");
	}
	if params.offset > 0 && params.expected_sha256.is_none() {
		bail!("application manifest continuation requires expected_sha256");
	}
	if params.expected_sha256.as_ref().is_some_and(|digest| {
		digest.len() != 64
			|| !digest
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	}) {
		bail!("application identity must be a lowercase complete SHA-256");
	}
	if matches!(params.collection, ApplicationCollection::Summary) && params.offset != 0 {
		bail!("application manifest summary has no continuation rows");
	}
	if params.kind == ApplicationKind::Jar
		&& matches!(
			params.collection,
			ApplicationCollection::Components | ApplicationCollection::Permissions
		) {
		bail!("JAR main manifests expose summary or attributes collections");
	}
	Ok(())
}

fn hex(bytes: &[u8]) -> String {
	let mut output = String::with_capacity(bytes.len().saturating_mul(2));
	for byte in bytes {
		let _ = write!(output, "{byte:02x}");
	}
	output
}

fn sha256(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

fn number(row: &Value, field: &str) -> Result<u64> {
	row.get(field)
		.and_then(Value::as_u64)
		.ok_or_else(|| anyhow!("archive index omitted manifest {field}"))
}

fn crc32(bytes: &[u8]) -> u32 {
	crc32fast::hash(bytes)
}

fn decode_manifest(
	compressed: &[u8],
	method: u16,
	declared_bytes: usize,
	declared_crc: u32,
) -> Result<Vec<u8>> {
	if compressed.len() > MAX_MANIFEST_BYTES || declared_bytes > MAX_MANIFEST_BYTES {
		bail!("selected manifest exceeds its 4 MiB compressed or decompressed budget");
	}
	let bytes =
		match method {
			0 => {
				if compressed.len() != declared_bytes {
					bail!("stored manifest compressed and uncompressed sizes differ");
				}
				compressed.to_vec()
			}
			8 => {
				// One extra byte detects an understated size without allowing expansion
				// beyond the fixed budget. Both stream end and full input consumption
				// are required; truncated, concatenated and trailing data are rejected.
				let mut output = vec![0_u8; declared_bytes + 1];
				let mut decoder = Decompress::new(false);
				let status = decoder
					.decompress(compressed, &mut output, FlushDecompress::Finish)
					.context("invalid raw-deflate manifest")?;
				if status != Status::StreamEnd
					|| decoder.total_in() != compressed.len() as u64
					|| decoder.total_out() != declared_bytes as u64
				{
					bail!("deflate manifest does not exactly match its declared size and stream boundary");
				}
				output.truncate(declared_bytes);
				output
			}
			_ => bail!("selected manifest supports only ZIP stored or deflate compression"),
		};
	if crc32(&bytes) != declared_crc {
		bail!("selected manifest CRC32 does not match the ZIP directory");
	}
	Ok(bytes)
}

fn capture_manifest(
	file: &mut std::fs::File,
	before: &std::fs::Metadata,
	entry: &Value,
	deadline: Instant,
) -> Result<(String, Vec<u8>)> {
	let offset = number(entry, "payload_offset")?;
	let length = number(entry, "compressed_bytes")?;
	if length > MAX_MANIFEST_BYTES as u64 || offset > before.len() || length > before.len() - offset
	{
		bail!("selected manifest compressed extent is outside its budget or archive");
	}
	let end = offset + length;
	let mut captured = Vec::with_capacity(length as usize);
	let mut digest = Sha256::new();
	let mut position = 0_u64;
	let mut buffer = [0_u8; 64 * 1024];
	file.seek(SeekFrom::Start(0))?;
	while position < before.len() {
		if Instant::now() >= deadline {
			bail!("application manifest inspection exceeded its work deadline");
		}
		let wanted = ((before.len() - position) as usize).min(buffer.len());
		file.read_exact(&mut buffer[..wanted])
			.context("archive changed or became unreadable during full hash")?;
		digest.update(&buffer[..wanted]);
		let next = position + wanted as u64;
		let overlap_start = position.max(offset);
		let overlap_end = next.min(end);
		if overlap_start < overlap_end {
			captured.extend_from_slice(
				&buffer[(overlap_start - position) as usize..(overlap_end - position) as usize],
			);
		}
		position = next;
	}
	#[cfg(unix)]
	super::rea_files::ensure_unchanged(before, &file.metadata()?)?;
	if captured.len() as u64 != length {
		bail!("manifest payload was not captured completely during the archive hash");
	}
	Ok((hex(&digest.finalize()), captured))
}

fn inspect_file(
	mut file: std::fs::File,
	before: std::fs::Metadata,
	params: &InspectApplicationParams,
) -> Result<Value> {
	validate(params)?;
	if before.len() == 0 || before.len() > MAX_ARCHIVE_BYTES {
		bail!("application archive must contain 1 byte through 512 MiB");
	}
	let deadline = Instant::now() + Duration::from_secs(240);
	let directory = super::rea_artifact_zip::inspect_application_directory(&mut file)?;
	let entry = directory["result"]["rows"]
		.as_array()
		.ok_or_else(|| anyhow!("archive index omitted fixed manifest rows"))?
		.iter()
		.find(|entry| entry["name"].as_str() == Some(params.kind.member()))
		.ok_or_else(|| {
			anyhow!(
				"application archive has no fixed {} entry",
				params.kind.member()
			)
		})?;
	let flags = number(entry, "flags")?;
	if flags & !0x080e != 0 || entry["encrypted"] != false {
		bail!("selected manifest uses encryption or unsupported ZIP flags");
	}
	let method = u16::try_from(number(entry, "compression_method")?)?;
	if method != 0 && method != 8 {
		bail!("selected manifest supports only ZIP stored or deflate compression");
	}
	let size = usize::try_from(number(entry, "uncompressed_bytes")?)?;
	if size > MAX_MANIFEST_BYTES {
		bail!("selected manifest exceeds its 4 MiB decompressed budget");
	}
	let declared_crc = u32::from_str_radix(
		entry["declared_crc32"]
			.as_str()
			.ok_or_else(|| anyhow!("archive index omitted manifest CRC32"))?,
		16,
	)?;
	let (digest, compressed) = capture_manifest(&mut file, &before, entry, deadline)?;
	if params
		.expected_sha256
		.as_ref()
		.is_some_and(|expected| expected != &digest)
	{
		bail!("application archive SHA-256 changed; obtain a new first-page identity");
	}
	let bytes = decode_manifest(&compressed, method, size, declared_crc)?;
	let parsed = parser::parse(&bytes, params.kind, deadline)?;
	let rows = match params.collection {
		ApplicationCollection::Summary => &[][..],
		ApplicationCollection::Components => parsed.components.as_slice(),
		ApplicationCollection::Permissions => parsed.permissions.as_slice(),
		ApplicationCollection::Attributes => parsed.attributes.as_slice(),
	};
	if params.offset > rows.len() {
		bail!("application declaration page offset exceeds the selected collection");
	}
	let end = params.offset.saturating_add(params.limit).min(rows.len());
	Ok(json!({
		"record_format":"hepta.rea-application-manifest.v1",
		"rea_evidence_compatible":false,
		"kind":params.kind,
		"source":{
			"sha256":digest,"byte_length":before.len(),"identity_scope":"complete_archive",
			"central_directory_sha256":directory["source"]["central_directory_sha256"],
			"observed_version":directory["source"]["observed_version"],
			"archive_entry_count":directory["entry_count"],
			"descriptor_scope":"one admitted descriptor for ZIP structure, full hash and selected payload"
		},
		"manifest":{
			"name":params.kind.member(),"sha256":sha256(&bytes),"byte_length":bytes.len(),
			"compressed_bytes":compressed.len(),"payload_offset":entry["payload_offset"],
			"compression_method":method,"crc32":format!("{declared_crc:08x}"),"crc32_verified":true,
			"format":parsed.format
		},
		"summary":parsed.summary,
		"collection":params.collection,"total_rows":rows.len(),"offset":params.offset,
		"next_offset":(end < rows.len()).then_some(end),"rows":&rows[params.offset..end],
		"coverage":{
			"zip_structure":"existing bounded classic ZIP directory and local-header validation",
			"manifest_payload":"fixed selected entry only, exact decompressed size and CRC32 checked",
			"archive_other_payloads":"not decompressed or CRC-verified",
			"signatures":"not verified","resources":"not resolved","code":"not parsed or executed"
		},
		"budgets":{
			"archive_max_bytes":MAX_ARCHIVE_BYTES,"manifest_max_compressed_bytes":MAX_MANIFEST_BYTES,
			"manifest_max_decompressed_bytes":MAX_MANIFEST_BYTES,"archive_max_entries":50_000,
			"response_max_bytes":MAX_RESPONSE_BYTES,"page_max_rows":256
		},
		"limitations":[
			"Declarations describe captured bytes and do not establish package authenticity, installability, component existence, actual permissions or execution behavior.",
			"APK attributes preserve namespace, raw text, typed data and resource IDs; resources.arsc and Android framework interpretation are not evaluated.",
			"JAR inspection covers the main manifest section only; per-entry attributes, class loading, signatures and Class-Path targets are not inspected.",
			"ZIP64, multi-volume archives, styled AXML string pools and unsupported XML chunk extensions are rejected by this bounded format subset.",
			"Full-file SHA-256 binds captured bytes; metadata checks detect ordinary concurrent writes, not a privileged writer restoring metadata while racing reads.",
			"No package is installed, no code is executed, no arbitrary member is extracted and no network request is made."
		]
	}))
}

async fn inspect_with_roots(params: InspectApplicationParams, roots: &[PathBuf]) -> Result<String> {
	validate(&params)?;
	static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
	let permit = Arc::clone(SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2))))
		.try_acquire_owned()
		.context("application manifest parser is busy; retry after another inspection finishes")?;
	let (file, before) = super::rea_files::open_confined(Path::new(&params.path), roots).await?;
	if before.len() == 0 || before.len() > MAX_ARCHIVE_BYTES {
		bail!("application archive must contain 1 byte through 512 MiB");
	}
	let file = file.into_std().await;
	tokio::task::spawn_blocking(move || {
		// Own the slot throughout blocking work, even if the awaiting request
		// is cancelled. This read-only worker never opens another source path.
		let _permit = permit;
		let result = serde_json::to_string(&inspect_file(file, before, &params)?)?;
		if result.len() > MAX_RESPONSE_BYTES {
			bail!("application manifest response exceeds 1 MiB; reduce the selected page");
		}
		Ok::<_, anyhow::Error>(result)
	})
	.await
	.context("application manifest inspection task failed")?
}

pub async fn inspect_application(params: InspectApplicationParams) -> Result<String> {
	validate(&params)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	inspect_with_roots(params, roots).await
}

#[cfg(test)]
#[path = "rea_application_tests.rs"]
mod tests;
