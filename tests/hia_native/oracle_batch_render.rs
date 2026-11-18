// Copyright 2026 Muvon Un Limited
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

//! Exact original post-write batch result, with a typed byte-only test envelope.
#![allow(dead_code)]
#[rustfmt::skip]
mod utils { pub mod line_hash {
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

} }
#[rustfmt::skip]
mod original {
mod delta { use crate::utils::line_hash::line_id_at;
pub fn removed_marker(old: &[&str], first: usize, last: usize) -> String {
	if first == last {
		format!("-{} (1 line)", line_id_at(old, first + 1))
	} else {
		format!(
			"-{}..{} ({} lines)",
			line_id_at(old, first + 1),
			line_id_at(old, last + 1),
			last - first + 1
		)
	}
}

}
pub mod text { use crate::utils::line_hash::line_id_at;
type Result<T> = std::result::Result<T, String>;
#[derive(Debug, Clone)]
struct BatchOperation {
	operation_type: OperationType,
	line_range: LineRange,
	content: String,
	operation_index: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum OperationType {
	Insert,
	Replace,
}

#[derive(Debug, Clone)]
enum LineRange {
	Single(usize),       // Insert after this line (0 = beginning of file)
	Range(usize, usize), // Replace this range (inclusive, 1-indexed)
}

fn incoming_content_lines(content: &str) -> Vec<&str> {
	content
		.lines()
		.map(|line| line.trim_end_matches('\r'))
		.collect()
}

const ECHO_WHOLE_MAX: usize = 3;

// Added lines of an edit result. The model just sent this content, so a longer block
// shows its first and last line (placement and boundaries) and collapses the middle to
// its fresh id range, like removed lines; short blocks are shown whole.
fn push_added_lines(diff: &mut Vec<String>, first_1idx: usize, content_lines: &[&str]) {
	let id = |i: usize| crate::utils::line_hash::line_id(first_1idx + i, content_lines[i]);
	let n = content_lines.len();
	if n <= ECHO_WHOLE_MAX {
		for (i, line) in content_lines.iter().enumerate() {
			diff.push(format!("+{}|{}", id(i), line));
		}
		return;
	}
	diff.push(format!("+{}|{}", id(0), content_lines[0]));
	diff.push(format!(
		"+{}..{} ({} lines as sent)",
		id(1),
		id(n - 2),
		n - 2
	));
	diff.push(format!("+{}|{}", id(n - 1), content_lines[n - 1]));
}

pub(crate) fn shift_note(orig_lines: &[&str], regions: &[(usize, i64)]) -> Option<String> {
	let mut by_end = std::collections::BTreeMap::new();
	for &(end, delta) in regions {
		*by_end.entry(end).or_insert(0i64) += delta;
	}
	let mut total = 0i64;
	let mut parts = Vec::new();
	for (end, delta) in by_end {
		total += delta;
		if delta == 0 || end >= orig_lines.len() {
			continue;
		}
		let anchor = if end == 0 {
			"0".to_string()
		} else {
			line_id_at(orig_lines, end)
		};
		parts.push(format!("after {anchor} {total:+}"));
	}
	(!parts.is_empty()).then(|| format!("shift: lines {}", parts.join(", ")))
}

fn render(original_content: &str, final_content: &str, batch_operations: Vec<BatchOperation>) -> Result<String> {
	let original_lines: Vec<&str> = original_content.lines().collect();
	// Build annotated diff for each operation so the AI can verify edits landed correctly.
	// Context and added lines carry FRESH ids from the final file — usable directly as
	// targets for follow-up edits, no re-view needed. Removed lines carry their old ids.
	const CONTEXT: usize = 2;
	let new_lines: Vec<&str> = final_content.lines().collect();

	let new_prefix = |line_1idx: usize| -> String { line_id_at(&new_lines, line_1idx) };

	let mut diffs: Vec<String> = Vec::new();

	// Sort ops by original start line (ascending) for readable diff output
	let mut display_ops = batch_operations.clone();
	display_ops.sort_by_key(|op| match &op.line_range {
		LineRange::Single(line) => *line,
		LineRange::Range(start, _) => *start,
	});

	// Each op references ORIGINAL line numbers, but the diff is rendered against the FINAL
	// file (`new_lines`/`new_prefix`). Walking ops ascending and accumulating each op's
	// line-count delta keeps every later op's rendered positions (and hash prefixes) aligned
	// with where its content actually landed — without this, every op after the first
	// length-changing one shows wrong line numbers/hashes.
	// Non-overlapping ops are guaranteed by detect_conflicts (replace/replace overlap,
	// equal-anchor inserts, inserts inside a replaced range).
	let mut offset: i64 = 0;

	// 1-indexed position in the final file = original position + offset of prior ops.
	let shift =
		|orig_1idx: usize, offset: i64| -> usize { (orig_1idx as i64 + offset).max(1) as usize };
	// Render context line `new_i` from the final file, if in range.
	let ctx_line = |new_i: usize| -> Option<String> {
		(new_i >= 1 && new_i <= new_lines.len())
			.then(|| format!("{}|{}", new_prefix(new_i), new_lines[new_i - 1]))
	};

	for op in &display_ops {
		match op.operation_type {
			OperationType::Replace => {
				let (start, end) = match op.line_range {
					LineRange::Range(s, e) => (s, e),
					LineRange::Single(line) => (line, line),
				};
				let content_lines = incoming_content_lines(&op.content);
				let old_count = end - start + 1;
				let new_count = content_lines.len();
				let new_start = shift(start, offset);

				let mut diff: Vec<String> = Vec::new();
				// Context before — from the final file, at shifted positions.
				let ctx_before_start = new_start.saturating_sub(CONTEXT).max(1);
				if ctx_before_start > 1 {
					diff.push("...".to_string());
				}
				for new_i in ctx_before_start..new_start {
					diff.extend(ctx_line(new_i));
				}
				// Removed lines collapse to their ORIGINAL id range — the model saw them.
				diff.push(super::delta::removed_marker(
					&original_lines,
					start - 1,
					end - 1,
				));
				// Added lines — at their FINAL positions, ids computed from the
				// added content itself (always correct, no bounds concern).
				push_added_lines(&mut diff, new_start, &content_lines);
				// Context after — from the final file.
				let new_after_start = new_start + new_count;
				let new_after_end = (new_after_start + CONTEXT - 1).min(new_lines.len());
				for new_i in new_after_start..=new_after_end {
					diff.extend(ctx_line(new_i));
				}
				if new_after_end < new_lines.len() {
					diff.push("...".to_string());
				}
				diffs.push(diff.join("\n"));
				offset += new_count as i64 - old_count as i64;
			}
			OperationType::Insert => {
				// For inserts show context lines before and after so the AI can verify placement
				let after = match op.line_range {
					LineRange::Single(line) => line,
					LineRange::Range(start, _) => start,
				};
				let content_lines = incoming_content_lines(&op.content);
				// First inserted line's position in the final file.
				let insert_at = shift(after, offset) + if after == 0 { 0 } else { 1 };
				let mut diff: Vec<String> = Vec::new();

				let ctx_before_start = insert_at.saturating_sub(CONTEXT).max(1);
				if ctx_before_start > 1 {
					diff.push("...".to_string());
				}
				for new_i in ctx_before_start..insert_at {
					diff.extend(ctx_line(new_i));
				}

				push_added_lines(&mut diff, insert_at, &content_lines);

				let after_end = insert_at + content_lines.len();
				let ctx_after_end = (after_end + CONTEXT - 1).min(new_lines.len());
				for new_i in after_end..=ctx_after_end {
					diff.extend(ctx_line(new_i));
				}
				if ctx_after_end < new_lines.len() {
					diff.push("...".to_string());
				}

				diffs.push(diff.join("\n"));
				offset += content_lines.len() as i64;
			}
		}
	}

	// The diff IS the result — plain text, same style as `view` output.
	// LLM reads it to verify edits landed correctly without needing a separate view call.
	let mut diff_output = diffs.join("\n---\n");

	let regions: Vec<(usize, i64)> = batch_operations
		.iter()
		.map(|op| {
			let added = incoming_content_lines(&op.content).len() as i64;
			match (&op.operation_type, &op.line_range) {
				(OperationType::Replace, LineRange::Range(s, e)) => {
					(*e, added - (*e - *s + 1) as i64)
				}
				(OperationType::Replace, LineRange::Single(l)) => (*l, added - 1),
				(OperationType::Insert, LineRange::Single(after)) => (*after, added),
				(OperationType::Insert, LineRange::Range(s, _)) => (*s, added),
			}
		})
		.collect();
	if let Some(note) = shift_note(&original_lines, &regions) {
		diff_output.push('\n');
		diff_output.push_str(&note);
	}

	Ok(diff_output)
}

pub fn replay(raw: &[u8]) -> Vec<u8> {
    fn word(raw: &[u8], at: usize) -> usize {
        u64::from_le_bytes(raw[at..at + 8].try_into().unwrap()) as usize
    }
    assert_eq!(&raw[..8], b"HBDIFF01");
    let old_end = 64 + word(raw, 8);
    let new_end = old_end + word(raw, 16);
    assert_eq!(new_end + word(raw, 24), raw.len());
    let old = std::str::from_utf8(&raw[64..old_end]).unwrap();
    let new = std::str::from_utf8(&raw[old_end..new_end]).unwrap();
    let count = word(raw, new_end + 16);
    let mut at = new_end + 48;
    let mut operations = Vec::new();
    for i in 0..count {
        assert_eq!(word(raw, at), i);
        let kind = word(raw, at + 8);
        let start = word(raw, at + 24);
        let end = word(raw, at + 32);
        let size = word(raw, at + 40);
        let content = std::str::from_utf8(&raw[at + 48..at + 48 + size]).unwrap().to_string();
        operations.push(BatchOperation {
            operation_type: if kind == 1 { OperationType::Insert } else { OperationType::Replace },
            line_range: if kind == 1 { LineRange::Single(start) } else { LineRange::Range(start, end) },
            content,
            operation_index: i,
        });
        at += 48 + size;
    }
    assert_eq!(at, raw.len());
    let body = render(old, new, operations).unwrap().into_bytes();
    let mut output = Vec::with_capacity(32 + body.len());
    output.extend_from_slice(b"HBDIFR01");
    output.extend_from_slice(&(body.len() as u64).to_le_bytes());
    output.extend_from_slice(&[0u8; 16]);
    output.extend_from_slice(&body);
    output
}
}
}

fn main() {
	use std::io::{self, Read, Write};
	let mut input = io::stdin().lock();
	let mut output = io::BufWriter::new(io::stdout().lock());
	let mut cases = 0usize;
	let mut input_bytes = 0usize;
	let mut output_bytes = 0usize;
	loop {
		let mut length = [0u8; 8];
		match input.read(&mut length[..1]) {
			Ok(0) => break,
			Ok(1) => (),
			value => panic!("invalid input header: {value:?}"),
		}
		input.read_exact(&mut length[1..]).unwrap();
		let size = u64::from_le_bytes(length) as usize;
		assert!(size <= 512 << 20);
		let mut request = vec![0u8; size];
		input.read_exact(&mut request).unwrap();
		let response = original::text::replay(&request);
		output
			.write_all(&(response.len() as u64).to_le_bytes())
			.unwrap();
		output.write_all(&response).unwrap();
		cases += 1;
		input_bytes += 8 + size;
		output_bytes += 8 + response.len();
	}
	output.flush().unwrap();
	eprintln!(
		"{{\"status\":\"PASS\",\"cases\":{cases},\"input_bytes\":{input_bytes},\"output_bytes\":{output_bytes}}}"
	);
}
