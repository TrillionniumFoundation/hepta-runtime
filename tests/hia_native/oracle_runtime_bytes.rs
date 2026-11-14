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
//! Independent oracle: original pinned Rust functions, with a binary test driver.
//! Original: TrillionniumFoundation/hepta-runtime a0dcdda1991ec536d5e2d252c006a778993fa566.
//! line_hash.rs and config/execution predicates below are copied without edits.
#![allow(dead_code)]
use std::io::{Read, Write};

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

/// 2-char hex content hash of a single line.
pub fn line_hash(content: &str) -> String {
	format!("{:02x}", fnv1a_8(content))
}

/// Composite id "N:hh" for a 1-indexed line with the given content.
pub fn line_id(line_1idx: usize, content: &str) -> String {
	format!("{}:{}", line_1idx, line_hash(content))
}

/// Composite id for a 1-indexed line looked up in `lines`.
pub fn line_id_at(lines: &[&str], line_1idx: usize) -> String {
	line_id(line_1idx, lines[line_1idx - 1])
}

/// Verify a composite id against the current file lines. Returns the 1-indexed
/// line on success. On mismatch the error is self-contained: it shows the
/// current content around the target with fresh ids, where the expected hash
/// actually is, and suggests a ranged `view` — so the model can retarget from
/// the error alone instead of re-reading the whole file. It does not claim WHY
/// the id is off: a neighbour's hash pasted next to the wrong line number looks
/// exactly like a one-line shift, and the fix is the same either way.
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

/// Append where content with this hash actually is (nearest to `expected_line`
/// first, up to 3) so a moved line or a mis-paired hash is a one-step fix.
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

// ── Line number resolution ─────────────────────────────────────────────────────────
//
// Shared by every tool that targets lines by number. Negative indices count from the
// end (-1 = last line). `checked_neg` guards i64::MIN, whose negation overflows.

/// Resolve a possibly-negative line index to a 1-indexed line number (strict).
/// Line 0 and out-of-range indices are errors.
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

/// View-only variant: clamp out-of-bounds indices to the nearest valid line instead of
/// erroring. Returns `(resolved_index, was_clamped)`. Line 0 is still rejected — it's a
/// spec violation, not out-of-bounds.
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


pub fn valid_name(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 128
		&& value
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
}

fn valid_text(s: &str) -> bool {
	!s.is_empty() && s.len() <= 256 && s.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_digest(s: &str) -> bool {
	s.len() == 64
		&& s.bytes().any(|byte| byte != b'0')
		&& s.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}


fn get_u64(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn pack(values: &[u64]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn oracle(raw: &[u8], capacity: u64) -> (u64, Vec<u8>) {
    const INVALID: u64 = 0xffff_ffff;
    const NO_SPACE: u64 = 0xffff_fffe;
    if raw.len() < 40 || &raw[..8] != b"HRTKERN1" {
        return (INVALID, vec![]);
    }
    let op = get_u64(raw, 8);
    let a = get_u64(raw, 16);
    let b = get_u64(raw, 24);
    let c = get_u64(raw, 32);
    if !(1..=8).contains(&op)
        || ((3..=5).contains(&op) && raw.len() != 40)
        || (op != 5 && c != 0)
        || ((op == 1 || op >= 6) && a != 0)
        || ((op <= 2 || op >= 6) && b != 0)
    {
        return (INVALID, vec![]);
    }
    let data = &raw[40..];
    let output = match op {
        1 => line_hash(std::str::from_utf8(data).expect("original str domain")).into_bytes(),
        2 => line_id(a as usize, std::str::from_utf8(data).expect("original str domain")).into_bytes(),
        3 | 4 => {
            let index = a as i64;
            let resolved = if op == 3 {
                resolve_line_index(index, b as usize).map(|line| (line, false))
            } else {
                resolve_line_index_clamped(index, b as usize)
            };
            match resolved {
                Ok((line, clamped)) => pack(&[line as u64, u64::from(clamped)]),
                Err(_) => return (if index == 0 {0xffff_fffd} else if index > 0 {0xffff_fffc} else {0xffff_fffb}, vec![]),
            }
        },
        5 => {
            // jobs.rs READ_CODE: reject offset > size, clamp 1..16384, read min(limit, size-offset).
            // This pure planning check cannot attest descriptor identity or actual stream.read bytes.
            if a > b { return (0xffff_fffa, vec![]); }
            let limit = c.clamp(1, 16384);
            let count = limit.min(b - a);
            let next = a + count;
            pack(&[count, next, u64::from(next >= b), limit])
        },
        6 => vec![u8::from(valid_name(std::str::from_utf8(data).expect("original str domain")))],
        7 => vec![u8::from(valid_digest(std::str::from_utf8(data).expect("original str domain")))],
        8 => vec![u8::from(valid_text(std::str::from_utf8(data).expect("original str domain")))],
        _ => unreachable!(),
    };
    if output.len() as u64 > capacity {
        (NO_SPACE, vec![])
    } else {
        (output.len() as u64, output)
    }
}

fn main() {
    assert_eq!(usize::BITS, 64, "oracle requires original Linux x86_64 LP64 domain");
    let mut input = Vec::new();
    std::io::stdin().lock().read_to_end(&mut input).unwrap();
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    let mut position = 0;
    while position < input.len() {
        assert!(input.len() - position >= 16, "truncated fixture header");
        let length = get_u64(&input, position) as usize;
        let capacity = get_u64(&input, position + 8);
        position += 16;
        assert!(input.len() - position >= length, "truncated fixture body");
        let (returned, bytes) = oracle(&input[position..position + length], capacity);
        position += length;
        output.write_all(&returned.to_le_bytes()).unwrap();
        output.write_all(&(bytes.len() as u64).to_le_bytes()).unwrap();
        output.write_all(&bytes).unwrap();
    }
    output.flush().unwrap();
}
