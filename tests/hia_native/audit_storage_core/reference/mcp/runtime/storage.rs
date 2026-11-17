// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Observer adapter around exact target record I/O functions.
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};

#[path = "trace.rs"]
mod trace;

const MAX_RECORD_BYTES: usize = 2048;
include!("original_types.rs.txt");
include!("original_io.rs.txt");

fn word(raw: &[u8], at: usize) -> Result<u64> {
	let bytes: [u8; 8] = raw
		.get(at..at + 8)
		.ok_or_else(|| anyhow!("fixture word extent"))?
		.try_into()?;
	Ok(u64::from_le_bytes(bytes))
}

fn put(raw: &mut [u8], at: usize, value: u64) {
	raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn text(raw: &[u8], at: u64, size: u64) -> Result<String> {
	let at: usize = at.try_into()?;
	let size: usize = size.try_into()?;
	let end = at
		.checked_add(size)
		.ok_or_else(|| anyhow!("fixture extent overflow"))?;
	Ok(std::str::from_utf8(
		raw.get(at..end)
			.ok_or_else(|| anyhow!("fixture text extent"))?,
	)?
	.to_owned())
}

fn decode_projection(raw: &[u8]) -> Result<Record> {
	if raw.len() < 128 || &raw[..8] != b"HAJPR001" || word(raw, 8)? != 1 {
		bail!("fixture Record projection");
	}
	let request_id = text(raw, word(raw, 64)?, word(raw, 72)?)?;
	let owner = text(raw, word(raw, 80)?, word(raw, 88)?)?;
	let tool_name = text(raw, word(raw, 96)?, word(raw, 104)?)?;
	let state = match word(raw, 40)? {
		0 => DurableState::Unknown,
		1 => DurableState::Completed,
		2 => DurableState::Failed,
		_ => bail!("fixture state"),
	};
	let elapsed_ms = match word(raw, 16)? {
		0 => None,
		1 => Some(word(raw, 48)?),
		_ => bail!("fixture elapsed presence"),
	};
	Ok(Record {
		request_id,
		owner,
		tool_name,
		state,
		accepted_unix_ms: u128::from(word(raw, 24)?) | (u128::from(word(raw, 32)?) << 64),
		elapsed_ms,
	})
}

fn encode_projection(record: &Record) -> Vec<u8> {
	let mut raw =
		vec![0_u8; 128 + record.request_id.len() + record.owner.len() + record.tool_name.len()];
	raw[..8].copy_from_slice(b"HAJPR001");
	put(&mut raw, 8, 1);
	put(&mut raw, 16, u64::from(record.elapsed_ms.is_some()));
	put(&mut raw, 24, record.accepted_unix_ms as u64);
	put(&mut raw, 32, (record.accepted_unix_ms >> 64) as u64);
	put(
		&mut raw,
		40,
		match record.state {
			DurableState::Unknown => 0,
			DurableState::Completed => 1,
			DurableState::Failed => 2,
		},
	);
	put(&mut raw, 48, record.elapsed_ms.unwrap_or(0));
	let mut at = 128;
	for (index, value) in [&record.request_id, &record.owner, &record.tool_name]
		.iter()
		.enumerate()
	{
		put(&mut raw, 64 + index * 16, at as u64);
		put(&mut raw, 72 + index * 16, value.len() as u64);
		raw[at..at + value.len()].copy_from_slice(value.as_bytes());
		at += value.len();
	}
	raw
}

fn error_projection(error: &anyhow::Error) -> Result<(u64, u64)> {
	if let Some(value) = error.downcast_ref::<std::io::Error>() {
		if let Some(errno) = value.raw_os_error() {
			return Ok((1, errno.try_into()?));
		}
		if value.kind() == std::io::ErrorKind::WriteZero {
			return Ok((5, 0));
		}
	}
	if error.downcast_ref::<serde_json::Error>().is_some() {
		return Ok((3, 0));
	}
	if error.downcast_ref::<std::str::Utf8Error>().is_some() {
		return Ok((4, 0));
	}
	let code = match error.to_string().as_str() {
		"invalid request metadata filename" => 1,
		"unexpected private audit staging entry" => 2,
		"unexpected private audit staging identity" => 3,
		"audit staging inode refused" => 4,
		"audit staging hard-link binding refused" => 5,
		"private request audit inode refused" => 6,
		"request audit metadata size refused" => 7,
		"request audit metadata identity refused" => 8,
		"request hot cache binding changed" => 9,
		"private request audit directory refused" => 10,
		"request audit receipt binding changed" => 11,
		"request audit record size refused" => 12,
		_ => bail!("unclassified actual original error: {error:#}"),
	};
	Ok((2, code))
}

pub fn run(directory: &File, frame: &[u8]) -> Result<Vec<u8>> {
	if frame.len() < 128
		|| &frame[..8] != b"HAIORQ01"
		|| word(frame, 40)? != (frame.len() - 128) as u64
	{
		bail!("fixture initial frame");
	}
	let op = word(frame, 8)?;
	let flags = word(frame, 32)?;
	let payload = &frame[128..];
	let result = match op {
		1 => read_record(directory, std::str::from_utf8(payload)?).map(Some),
		2 => {
			let record = decode_projection(payload)?;
			save_raw_with_sync(directory, &record, flags & 1 != 0, flags & 2 != 0).map(|_| None)
		}
		3 => {
			let record = decode_projection(payload)?;
			remove_record(directory, &record, flags & 2 != 0).map(|_| None)
		}
		4 => cleanup_staging(directory, std::str::from_utf8(payload)?).map(|_| None),
		_ => bail!("fixture operation"),
	};
	let mut out = vec![0_u8; 64];
	out[..8].copy_from_slice(b"HAIOOR01");
	put(&mut out, 16, op);
	match result {
		Ok(record) => {
			if let Some(record) = record {
				let encoded = encode_projection(&record);
				put(&mut out, 40, encoded.len() as u64);
				out.extend_from_slice(&encoded);
			}
		}
		Err(error) => {
			eprintln!(
				"OBSERVED_ORIGINAL_ERROR {}",
				serde_json::json!({
					"generation": word(frame, 16)?,
					"display": error.to_string(),
					"debug": format!("{error:#?}"),
					"chain": error.chain().map(ToString::to_string).collect::<Vec<_>>(),
				})
			);
			let (family, code) = error_projection(&error)?;
			put(&mut out, 8, 1);
			put(&mut out, 24, family);
			put(&mut out, 32, code);
		}
	}
	Ok(out)
}
