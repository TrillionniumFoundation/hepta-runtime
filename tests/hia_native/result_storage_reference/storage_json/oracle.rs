// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test framing around the unchanged original retained-storage derives.
use std::io::{self, BufRead, Write};

include!("original_types.rs");

fn word(out: &mut [u8], at: usize, value: u64) {
	out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn string(out: &mut Vec<u8>, slot: usize, value: Option<&str>) {
	if let Some(value) = value {
		let at = out.len();
		word(out, 64 + slot * 16, at as u64);
		word(out, 72 + slot * 16, value.len() as u64);
		out.extend_from_slice(value.as_bytes());
	}
}

fn project(kind: u64, raw: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
	let mut out = vec![0; 256];
	out[..8].copy_from_slice(b"HRSTJ001");
	word(&mut out, 8, kind);
	match kind {
		1 => {
			let value: Record = serde_json::from_slice(raw)?;
			let flags = u64::from(value.payload_base64.is_some())
				| (u64::from(value.payload_bytes.is_some()) << 1)
				| (u64::from(value.payload_sha256.is_some()) << 2);
			word(&mut out, 16, flags);
			word(&mut out, 24, value.accepted_unix_ms as u64);
			word(&mut out, 32, (value.accepted_unix_ms >> 64) as u64);
			word(
				&mut out,
				40,
				match value.state {
					ResultState::Unknown => 0,
					ResultState::Stored => 1,
					ResultState::Overflow => 2,
					ResultState::RefusedDto => 3,
					ResultState::NotCompleted => 4,
				},
			);
			word(&mut out, 48, value.payload_bytes.unwrap_or(0) as u64);
			for (slot, text) in [
				Some(value.request_id.as_str()),
				Some(value.owner.as_str()),
				Some(value.tool_name.as_str()),
				Some(value.policy_binding.as_str()),
				value.payload_base64.as_deref(),
				value.payload_sha256.as_deref(),
			]
			.into_iter()
			.enumerate()
			{
				string(&mut out, slot, text);
			}
		}
		2 => {
			let value: ArchiveAnchor = serde_json::from_slice(raw)?;
			word(&mut out, 24, value.schema as u64);
			word(&mut out, 56, value.shards.len() as u64);
			for (slot, directory) in [&value.root, &value.legacy, &value.store, &value.archive]
				.into_iter()
				.enumerate()
			{
				word(&mut out, 64 + slot * 16, directory.device);
				word(&mut out, 72 + slot * 16, directory.inode);
			}
			for directory in value.shards {
				out.extend_from_slice(&directory.device.to_le_bytes());
				out.extend_from_slice(&directory.inode.to_le_bytes());
			}
		}
		3 => {
			let value: ArchiveMarker = serde_json::from_slice(raw)?;
			word(&mut out, 24, value.schema as u64);
			string(&mut out, 0, Some(&value.anchor_sha256));
		}
		_ => unreachable!(),
	}
	Ok(out)
}

fn invoke(wire: &[u8]) -> (u32, Vec<u8>) {
	if wire.len() < 24 || wire.len() > 98328 || &wire[..8] != b"HRSTQ001" {
		return (u32::MAX, vec![]);
	}
	let kind = u64::from_le_bytes(wire[8..16].try_into().unwrap());
	let size = u64::from_le_bytes(wire[16..24].try_into().unwrap());
	if !(1..=3).contains(&kind) || size != (wire.len() - 24) as u64 || (kind == 3 && size > 1024) {
		return (u32::MAX, vec![]);
	}
	match project(kind, &wire[24..]) {
		Ok(bytes) => (bytes.len() as u32, bytes),
		Err(_) => (u32::MAX, vec![]),
	}
}

fn decode(text: &str) -> Vec<u8> {
	assert_eq!(text.len() % 2, 0);
	text.as_bytes()
		.chunks_exact(2)
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn main() -> io::Result<()> {
	let mut stdout = io::BufWriter::new(io::stdout().lock());
	for line in io::stdin().lock().lines() {
		let (code, bytes) = invoke(&decode(&line?));
		write!(stdout, "{code:08x}:")?;
		for byte in bytes {
			write!(stdout, "{byte:02x}")?;
		}
		writeln!(stdout)?;
		stdout.flush()?;
	}
	Ok(())
}
