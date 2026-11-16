// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact production items; verified by the source extraction manifest.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
	/// Plain line number (1-indexed; 0 and negatives carry position-specific meaning per tool).
	Number(i64),
	/// Composite id: 1-indexed line plus its expected 2-char content hash.
	Id { line: usize, hash: String },
}

pub fn parse_endpoint(value: &serde_json::Value) -> Result<Endpoint, String> {
	match value {
		serde_json::Value::Number(n) => n
			.as_i64()
			.map(Endpoint::Number)
			.ok_or_else(|| "line number must be an integer".to_string()),
		serde_json::Value::String(s) => {
			let s = s.trim();
			if s.is_empty() {
				return Err("line value is empty".to_string());
			}
			if let Ok(n) = s.parse::<i64>() {
				return Ok(Endpoint::Number(n));
			}
			if let Some((num, hash)) = s.split_once(':') {
				let line: usize = num.parse().map_err(|_| {
					format!("invalid line id '{s}': expected \"N:hh\" as shown in view output (e.g. \"12:a3\")")
				})?;
				if line == 0 {
					return Err(format!("invalid line id '{s}': lines are 1-indexed"));
				}
				let hash = hash.to_ascii_lowercase();
				if hash.len() != 2 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
					return Err(format!(
						"invalid line id '{s}': the hash part must be 2 hex chars (e.g. \"12:a3\")"
					));
				}
				return Ok(Endpoint::Id { line, hash });
			}
			Err(format!(
				"invalid line value '{s}': pass a line id like \"12:a3\" (from view output) or an integer line number"
			))
		}
		_ => Err(format!(
			"line value must be a line id like \"12:a3\" or an integer line number, got {value}",
		)),
	}
}
