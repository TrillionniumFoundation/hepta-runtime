// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test framing around unchanged original audit types, with no alternate JSON implementation.
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

include!("original_types.rs");

fn word(out: &mut [u8], at: usize, value: u64) {
	out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn project_record<S: AsRef<str>>(record: &RecordFields<S>) -> Vec<u8> {
	let mut out = vec![0; 128];
	out[..8].copy_from_slice(b"HAJPR001");
	word(&mut out, 8, 1);
	word(&mut out, 16, u64::from(record.elapsed_ms.is_some()));
	word(&mut out, 24, record.accepted_unix_ms as u64);
	word(&mut out, 32, (record.accepted_unix_ms >> 64) as u64);
	word(&mut out, 40, match record.state {
		DurableState::Unknown => 0,
		DurableState::Completed => 1,
		DurableState::Failed => 2,
	});
	word(&mut out, 48, record.elapsed_ms.unwrap_or(0));
	for (index, text) in [record.request_id.as_ref(), record.owner.as_ref(), record.tool_name.as_ref()].into_iter().enumerate() {
		let offset = out.len();
		word(&mut out, 64 + index * 16, offset as u64);
		word(&mut out, 72 + index * 16, text.len() as u64);
		out.extend_from_slice(text.as_bytes());
	}
	out
}

fn project_anchor(anchor: &ArchiveAnchor) -> Vec<u8> {
	let mut out = vec![0; 128];
	out[..8].copy_from_slice(b"HAJPR001");
	word(&mut out, 8, 2);
	for (index, value) in [anchor.root_device, anchor.root_inode, anchor.archive_device, anchor.archive_inode].into_iter().enumerate() {
		word(&mut out, 64 + index * 8, value);
	}
	out
}

fn serialize_projection(kind: u64, raw: &[u8]) -> Option<Vec<u8>> {
	if raw.len() < 128 || &raw[..8] != b"HAJPR001" || get(raw, 8) != kind
		|| get(raw, 56) != 0 || get(raw, 112) != 0 || get(raw, 120) != 0 {
		return None;
	}
	if kind == 2 {
		if raw.len() != 128 || raw[16..64].iter().chain(raw[96..128].iter()).any(|value| *value != 0) {
			return None;
		}
		return serde_json::to_vec(&ArchiveAnchor {
			root_device: get(raw, 64), root_inode: get(raw, 72),
			archive_device: get(raw, 80), archive_inode: get(raw, 88),
		}).ok();
	}
	let present = get(raw, 16);
	if present > 1 || get(raw, 40) > 2 || (present == 0 && get(raw, 48) != 0) {
		return None;
	}
	let mut cursor = 128usize;
	let mut strings = Vec::new();
	for index in 0..3 {
		let size = usize::try_from(get(raw, 72 + index * 16)).ok()?;
		if get(raw, 64 + index * 16) != cursor as u64 || size > raw.len() - cursor {
			return None;
		}
		strings.push(std::str::from_utf8(&raw[cursor..cursor + size]).ok()?);
		cursor += size;
	}
	if cursor != raw.len() { return None; }
	let value = RecordFields {
		request_id: strings[0], owner: strings[1], tool_name: strings[2],
		state: match get(raw, 40) {
			0 => DurableState::Unknown, 1 => DurableState::Completed, 2 => DurableState::Failed,
			_ => unreachable!(),
		},
		accepted_unix_ms: u128::from(get(raw, 24)) | (u128::from(get(raw, 32)) << 64),
		elapsed_ms: if present == 0 { None } else { Some(get(raw, 48)) },
	};
	serde_json::to_vec(&value).ok()
}

fn invoke(wire: &[u8], capacity: usize, workspace: usize) -> (u32, Vec<u8>) {
	let invalid = (u32::MAX, vec![]);
	if wire.len() < 24 || wire.len() >= 0xfffffffe || &wire[..8] != b"HAJRQ001"
		|| get(wire, 16) != (wire.len() - 24) as u64 {
		return invalid;
	}
	let op = get(wire, 8);
	if !(1..=5).contains(&op) || ((op == 1 || op == 2 || op == 5) && wire.len() > 2072) {
		return invalid;
	}
	if workspace < 8192 { return (0xfffffffe, vec![]); }
	let payload = &wire[24..];
	let result = match op {
		1 => serde_json::from_slice::<Record>(payload).ok().map(|value| project_record(&value)),
		2 => serde_json::from_slice::<ArchiveAnchor>(payload).ok().map(|value| project_anchor(&value)),
		3 => serialize_projection(1, payload),
		4 => serialize_projection(2, payload),
		5 => serde_json::from_slice::<RecordFields<&str>>(payload).ok().map(|value| project_record(&value)),
		_ => unreachable!(),
	};
	match result {
		Some(bytes) if bytes.len() > capacity || bytes.len() >= 0xfffffffe => (0xfffffffe, vec![]),
		Some(bytes) => (bytes.len() as u32, bytes),
		None => invalid,
	}
}

fn decode(text: &str) -> Vec<u8> {
	assert_eq!(text.len() % 2, 0);
	text.as_bytes().chunks_exact(2)
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn main() -> io::Result<()> {
	let mut stdout = io::BufWriter::new(io::stdout().lock());
	for line in io::stdin().lock().lines() {
		let line = line?;
		let fields: Vec<&str> = line.split(' ').collect();
		assert_eq!(fields.len(), 3);
		let capacity = fields[0].parse::<usize>().unwrap();
		let workspace = fields[1].parse::<usize>().unwrap();
		let (code, bytes) = invoke(&decode(fields[2]), capacity, workspace);
		write!(stdout, "{code:08x}:")?;
		for byte in bytes { write!(stdout, "{byte:02x}")?; }
		writeln!(stdout)?;
	}
	stdout.flush()
}
