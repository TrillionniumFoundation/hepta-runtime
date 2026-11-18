// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
fn fnv1a_8(content: &str) -> u8 {
	const FNV_OFFSET: u32 = 2166136261;
	const FNV_PRIME: u32 = 16777619;

	let mut hash = FNV_OFFSET;
	for byte in content.bytes() {
		hash ^= byte as u32;
		hash = hash.wrapping_mul(FNV_PRIME);
	}

	// Fold 32 -> 16 -> 8 via XOR
	let h16 = ((hash >> 16) ^ (hash & 0xFFFF)) as u16;
	((h16 >> 8) ^ (h16 & 0xFF)) as u8
}

pub fn line_hash(content: &str) -> String {
	format!("{:02x}", fnv1a_8(content))
}

pub fn line_id(line_1idx: usize, content: &str) -> String {
	format!("{}:{}", line_1idx, line_hash(content))
}

pub fn line_id_at(lines: &[&str], line_1idx: usize) -> String {
	line_id(line_1idx, lines[line_1idx - 1])
}

pub fn verify_line_id(line: usize, expected_hash: &str, lines: &[&str]) -> Result<usize, String> {
	let total = lines.len();
	if line == 0 || line > total {
		let mut msg = format!(
			"Line id \"{line}:{expected_hash}\" is out of range: the file has {total} lines."
		);
		push_relocation(&mut msg, expected_hash, line, lines);
		msg.push_str("\nRe-view the file for fresh ids.");
		return Err(msg);
	}

	if line_hash(lines[line - 1]) == expected_hash {
		return Ok(line);
	}

	const CONTEXT: usize = 2;
	let win_start = line.saturating_sub(CONTEXT).max(1);
	let win_end = (line + CONTEXT).min(total);
	let mut msg = format!(
		"Line id \"{line}:{expected_hash}\" does not match: line {line} is now \"{}\". Current content:\n",
		line_id_at(lines, line)
	);
	for i in win_start..=win_end {
		msg.push_str(&format!("{}|{}\n", line_id_at(lines, i), lines[i - 1]));
	}
	push_relocation(&mut msg, expected_hash, line, lines);
	msg.push_str(&format!(
		"\nRetry with these ids, or view start={win_start} end={win_end} for more."
	));
	Err(msg)
}

fn push_relocation(msg: &mut String, expected_hash: &str, expected_line: usize, lines: &[&str]) {
	let mut candidates: Vec<usize> = lines
		.iter()
		.enumerate()
		.filter(|(_, l)| line_hash(l) == expected_hash)
		.map(|(i, _)| i + 1)
		.collect();
	if candidates.is_empty() {
		return;
	}
	candidates.sort_by_key(|&n| n.abs_diff(expected_line));
	let shown: Vec<String> = candidates
		.iter()
		.take(3)
		.map(|&n| line_id_at(lines, n))
		.collect();
	msg.push_str(&format!(
		"Hash {expected_hash} now matches {} (content moved, or hash paired with the wrong line).",
		shown.join(", ")
	));
}

pub(crate) fn resolve_line_index(index: i64, total_lines: usize) -> Result<usize, String> {
	if index == 0 {
		return Err("Line numbers are 1-indexed, use 1 for first line".to_string());
	}
	if index > 0 {
		let pos_index = index as usize;
		if pos_index > total_lines {
			return Err(format!(
				"Line {index} exceeds file length ({total_lines} lines)"
			));
		}
		Ok(pos_index)
	} else {
		let from_end = index
			.checked_neg()
			.map(|v| v as usize)
			.unwrap_or(usize::MAX);
		if from_end > total_lines {
			return Err(format!(
				"Negative index {index} exceeds file length ({total_lines} lines)"
			));
		}
		Ok(total_lines - from_end + 1)
	}
}

pub(crate) fn resolve_line_index_clamped(
	index: i64,
	total_lines: usize,
) -> Result<(usize, bool), String> {
	if index == 0 {
		return Err("Line numbers are 1-indexed, use 1 for first line".to_string());
	}
	if index > 0 {
		let pos = index as usize;
		if pos > total_lines {
			Ok((total_lines, true))
		} else {
			Ok((pos, false))
		}
	} else {
		let from_end = index
			.checked_neg()
			.map(|v| v as usize)
			.unwrap_or(usize::MAX);
		if from_end > total_lines {
			// Negative index past the beginning — clamp to first line.
			Ok((1, true))
		} else {
			Ok((total_lines - from_end + 1, false))
		}
	}
}
// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
use std::io::{self, BufRead, Write};

fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn decode_length(raw: &[u8], at: &mut usize) -> usize {
    let mut result = 0usize;
    let mut shift = 0u32;
    loop {
        let part = raw[*at];
        *at += 1;
        result |= ((part & 127) as usize) << shift;
        if part < 128 {
            return result;
        }
        shift += 7;
    }
}

fn apply(raw: &[u8]) -> Vec<u8> {
    assert!(raw.len() >= 64 && &raw[..8] == b"HLINE001");
    let operation = word(raw, 8);
    let bits = word(raw, 16);
    let count = word(raw, 24) as usize;
    let hash_size = word(raw, 32) as usize;
    assert_eq!(word(raw, 40) as usize, raw.len() - 64);
    assert_eq!(word(raw, 48), 0);
    assert_eq!(word(raw, 56), 0);
    let result = match operation {
        1 => {
            let expected = std::str::from_utf8(&raw[64..64 + hash_size]).unwrap();
            let mut at = 64 + hash_size;
            let mut lines = Vec::with_capacity(count);
            for _ in 0..count {
                let size = decode_length(raw, &mut at);
                lines.push(std::str::from_utf8(&raw[at..at + size]).unwrap());
                at += size;
            }
            assert_eq!(at, raw.len());
            verify_line_id(bits as usize, expected, &lines).map(|value| (value, false))
        }
        2 => resolve_line_index(bits as i64, count).map(|value| (value, false)),
        3 => resolve_line_index_clamped(bits as i64, count),
        _ => panic!("unsupported typed original operation"),
    };
    let mut out = b"HLINER01".to_vec();
    match result {
        Ok((value, clamped)) => {
            for word in [0, value as u64, u64::from(clamped), 0] {
                out.extend(word.to_le_bytes());
            }
        }
        Err(error) => {
            for word in [1, 0, 0, error.len() as u64] {
                out.extend(word.to_le_bytes());
            }
            out.extend(error.as_bytes());
        }
    }
    out
}

fn main() {
    assert_eq!(usize::BITS, 64);
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let raw: Vec<u8> = (0..line.len()).step_by(2)
            .map(|at| u8::from_str_radix(&line[at..at + 2], 16).unwrap()).collect();
        let result = apply(&raw);
        out.write_all(b"OK ").unwrap();
        for byte in result {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out.write_all(b"\n").unwrap();
        out.flush().unwrap();
    }
}
