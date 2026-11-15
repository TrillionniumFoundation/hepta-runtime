// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const MAX_RESULT_BYTES: usize = 64 * 1024;
const MAX_RECORD_BYTES: usize = 96 * 1024;
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResultState {
	Unknown,
	Stored,
	Overflow,
	RefusedDto,
	NotCompleted,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
	request_id: String,
	owner: String,
	tool_name: String,
	accepted_unix_ms: u128,
	policy_binding: String,
	state: ResultState,
	payload_base64: Option<String>,
	payload_bytes: Option<usize>,
	payload_sha256: Option<String>,
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
	device: u64,
	inode: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveAnchor {
	schema: u8,
	root: DirectoryIdentity,
	legacy: DirectoryIdentity,
	store: DirectoryIdentity,
	archive: DirectoryIdentity,
	shards: Vec<DirectoryIdentity>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveMarker {
	schema: u8,
	anchor_sha256: String,
}
fn valid_id(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_tool(value: &str) -> bool {
	matches!(value, "host_list" | "host_health" | "effective_config")
}
fn digest(data: &[u8]) -> String {
	Sha256::digest(data)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}
fn base64(data: &[u8]) -> String {
	const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
	for row in data.chunks(3) {
		let n = ((row[0] as u32) << 16)
			| ((row.get(1).copied().unwrap_or(0) as u32) << 8)
			| row.get(2).copied().unwrap_or(0) as u32;
		out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
		out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
		out.push(if row.len() > 1 {
			ALPHABET[((n >> 6) & 63) as usize] as char
		} else {
			'='
		});
		out.push(if row.len() > 2 {
			ALPHABET[(n & 63) as usize] as char
		} else {
			'='
		});
	}
	out
}
fn unbase64(text: &str) -> Result<Vec<u8>> {
	if text.len() > MAX_RESULT_BYTES.div_ceil(3) * 4 || !text.len().is_multiple_of(4) {
		bail!("retained bytes refused");
	}
	fn value(b: u8) -> Option<u32> {
		match b {
			b'A'..=b'Z' => Some((b - b'A') as u32),
			b'a'..=b'z' => Some((b - b'a' + 26) as u32),
			b'0'..=b'9' => Some((b - b'0' + 52) as u32),
			b'+' => Some(62),
			b'/' => Some(63),
			_ => None,
		}
	}
	let mut output = Vec::new();
	for row in text.as_bytes().as_chunks::<4>().0 {
		let a = value(row[0]).ok_or_else(|| anyhow!("retained bytes refused"))?;
		let b = value(row[1]).ok_or_else(|| anyhow!("retained bytes refused"))?;
		let c = if row[2] == b'=' {
			0
		} else {
			value(row[2]).ok_or_else(|| anyhow!("retained bytes refused"))?
		};
		let d = if row[3] == b'=' {
			0
		} else {
			value(row[3]).ok_or_else(|| anyhow!("retained bytes refused"))?
		};
		let n = (a << 18) | (b << 12) | (c << 6) | d;
		output.push((n >> 16) as u8);
		if row[2] != b'=' {
			output.push((n >> 8) as u8);
		}
		if row[3] != b'=' {
			output.push(n as u8);
		}
	}
	if output.len() > MAX_RESULT_BYTES || base64(&output) != text {
		bail!("retained bytes refused");
	}
	Ok(output)
}

// The descriptor, staging and inode checks precede these original byte checks.
fn validate(filename: &str, bytes: &[u8]) -> Result<Record> {
	let id = filename
		.strip_suffix(".json")
		.filter(|id| valid_id(id))
		.ok_or_else(|| anyhow!("invalid retained result filename"))?;
	let _ = id;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("request audit metadata size refused");
	}
	let record: Record = serde_json::from_slice(&bytes)?;
	if !valid_id(&record.request_id)
		|| !valid_id(&record.owner)
		|| !valid_tool(&record.tool_name)
		|| !valid_id(&record.policy_binding)
		|| filename != format!("{}.json", record.request_id)
	{
		bail!("request audit metadata identity refused");
	}
	match record.state {
		ResultState::Stored => {
			let payload = unbase64(
				record
					.payload_base64
					.as_deref()
					.ok_or_else(|| anyhow!("retained result refused"))?,
			)?;
			if record.payload_bytes != Some(payload.len())
				|| record.payload_sha256.as_deref() != Some(digest(&payload).as_str())
			{
				bail!("retained result integrity refused");
			}
		}
		_ if record.payload_base64.is_some()
			|| record.payload_bytes.is_some()
			|| record.payload_sha256.is_some() =>
		{
			bail!("retained result state refused")
		}
		_ => {}
	}
	Ok(record)
}
