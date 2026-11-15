// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test framing around unchanged original audit metadata serde derives.
use std::io::{self, BufRead, Write};

include!("original_types.rs");

fn word(out: &mut [u8], at: usize, value: u64) {
	out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn string(out: &mut Vec<u8>, slot: usize, value: &str) {
	let at = out.len();
	word(out, 64 + slot * 16, at as u64);
	word(out, 72 + slot * 16, value.len() as u64);
	out.extend_from_slice(value.as_bytes());
}

fn directories(
	out: &mut Vec<u8>,
	root: Identity,
	legacy: Identity,
	archive: Identity,
	shards: &[Identity],
) {
	for (slot, value) in [root, legacy, archive].into_iter().enumerate() {
		word(out, 64 + slot * 16, value[0]);
		word(out, 72 + slot * 16, value[1]);
	}
	word(out, 56, shards.len() as u64);
	for value in shards {
		out.extend_from_slice(&value[0].to_le_bytes());
		out.extend_from_slice(&value[1].to_le_bytes());
	}
}

fn project(kind: u64, raw: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
	let mut out = vec![0; 256];
	out[..8].copy_from_slice(b"HRAJJ001");
	word(&mut out, 8, kind);
	match kind {
		1 => {
			let value: Record = serde_json::from_slice(raw)?;
			word(&mut out, 16, u64::from(value.elapsed_ms.is_some()));
			word(&mut out, 24, value.accepted_unix_ms as u64);
			word(&mut out, 32, (value.accepted_unix_ms >> 64) as u64);
			word(
				&mut out,
				40,
				match value.state {
					DurableState::Unknown => 0,
					DurableState::Completed => 1,
					DurableState::Failed => 2,
				},
			);
			word(&mut out, 48, value.elapsed_ms.unwrap_or(0));
			for (slot, text) in [&value.request_id, &value.owner, &value.tool_name]
				.into_iter()
				.enumerate()
			{
				string(&mut out, slot, text);
			}
		}
		2 => {
			let value: ArchiveAnchor = serde_json::from_slice(raw)?;
			for (slot, number) in [
				value.root_device,
				value.root_inode,
				value.archive_device,
				value.archive_inode,
			]
			.into_iter()
			.enumerate()
			{
				word(&mut out, 64 + slot * 8, number);
			}
		}
		3 => {
			let value: ShardAnchor = serde_json::from_slice(raw)?;
			word(&mut out, 24, value.format as u64);
			directories(
				&mut out,
				value.root,
				value.legacy,
				value.archive,
				&value.shards,
			);
		}
		4 => {
			let value: InitIntent = serde_json::from_slice(raw)?;
			word(&mut out, 16, u64::from(value.archive.is_some()));
			word(&mut out, 24, value.format as u64);
			directories(
				&mut out,
				value.root,
				value.legacy,
				value.archive.unwrap_or([0, 0]),
				&value.shards,
			);
		}
		_ => unreachable!(),
	}
	Ok(out)
}

fn invoke(wire: &[u8]) -> (u32, Vec<u8>) {
	if wire.len() < 24 || wire.len() > 65560 || &wire[..8] != b"HRAJQ001" {
		return (u32::MAX, vec![]);
	}
	let kind = u64::from_le_bytes(wire[8..16].try_into().unwrap());
	let size = u64::from_le_bytes(wire[16..24].try_into().unwrap());
	if !(1..=4).contains(&kind) || size != (wire.len() - 24) as u64 || (kind <= 2 && size > 2048) {
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
