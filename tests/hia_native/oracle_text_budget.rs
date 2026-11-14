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

// Test oracle: exact original owners, compiled with release overflow semantics.
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
pub fn line_hash(content: &str) -> String {
	format!("{:02x}", fnv1a_8(content))
}
pub fn line_id(line_1idx: usize, content: &str) -> String {
	format!("{}:{}", line_1idx, line_hash(content))
}
}
pub mod truncation {
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

// Shared truncation utilities for smart content display across MCP tools

use super::line_hash::line_id;

/// Source code averages ~3.5 chars per token: indentation and punctuation
/// tokenize densely, so the prose figure of 4 undercounts by ~20%.
pub const CHARS_PER_TOKEN: f64 = 3.5;

/// Rough token estimate for budgeting reads, from a byte length.
pub fn estimate_tokens(bytes: usize) -> usize {
	(bytes as f64 / CHARS_PER_TOKEN).ceil() as usize
}

/// Largest tool result octofs sends. Claude Code's stdio transport closes the whole
/// connection on a bigger message, taking every tool with it rather than failing one
/// call (measured on 2.1.284: 15.7 MB delivered, 16.8 MB closed it). Half that leaves
/// room for JSON escaping, which inflates quote-heavy text such as JSONL. Below this,
/// results are never trimmed: clients already persist or cut oversized output.
pub const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;

/// A byte size as the model reads it in an oversized-result error, e.g. "85.2 MB".
pub fn format_megabytes(bytes: usize) -> String {
	format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

/// Render one line as "N:hh|content" — the single line-id format all tools share.
fn render_line(line_1idx: usize, content: &str) -> String {
	format!("{}|{}", line_id(line_1idx, content), content)
}

/// Format content with composite line ids. A ranged view renders exactly the
/// requested lines plus one trailing marker with the remaining/total line count.
pub fn format_content_with_line_numbers(
	lines: &[&str],
	start_line_number: usize,
	view_range: Option<(usize, i64)>,
) -> String {
	let render = |i: usize| render_line(start_line_number + i, lines[i]);

	if let Some((start, end)) = view_range {
		let start_idx = if start == 0 {
			0
		} else {
			start.saturating_sub(1)
		};
		let end_idx = if end == -1 {
			lines.len()
		} else {
			(end as usize).min(lines.len())
		};

		if start_idx >= lines.len() || start_idx > end_idx {
			return if start_idx >= lines.len() {
				format!(
					"Start line {} exceeds content length ({} lines)",
					start,
					lines.len()
				)
			} else {
				format!(
					"Start line {} must be less than or equal to end line {}",
					start, end
				)
			};
		}

		let mut result_lines: Vec<String> = (start_idx..end_idx).map(render).collect();

		// The caller chose this range; the only thing worth adding is how much
		// file lies beyond it. No head/tail context lines — they cost tokens on
		// every ranged read and carry nothing the model asked for.
		let remaining = lines.len() - end_idx;
		if start_idx > 0 || remaining > 0 {
			result_lines.push(if remaining == 0 {
				format!("[end of file, {} lines total]", lines.len())
			} else {
				format!("[... {remaining} more lines, {} total]", lines.len())
			});
		}

		result_lines.join("\n")
	} else {
		(0..lines.len()).map(render).collect::<Vec<_>>().join("\n")
	}
}

/// Format extracted content with composite line ids and smart truncation.
/// `start_line` is the 1-indexed position of `lines[0]` in the source file, so
/// the ids match what a `view` of the source shows.
pub fn format_extracted_content_smart(
	lines: &[&str],
	start_line: usize,
	max_display_lines: Option<usize>,
) -> String {
	let render = |i: usize| render_line(start_line + i, lines[i]);

	let max_lines = max_display_lines.unwrap_or(50);

	if lines.len() <= max_lines {
		(0..lines.len()).map(render).collect::<Vec<_>>().join("\n")
	} else {
		let show_first = (max_lines * 2) / 3;
		let show_last = max_lines - show_first - 1;

		let mut result_lines = Vec::new();

		for i in 0..show_first {
			result_lines.push(render(i));
		}

		let hidden_lines = lines.len() - show_first - show_last;
		result_lines.push(format!("[...{} lines more]", hidden_lines));

		for i in (lines.len() - show_last)..lines.len() {
			result_lines.push(render(i));
		}

		result_lines.join("\n")
	}
}

}}

use std::io::{self, BufRead, Write};
fn hex(raw: &[u8]) -> String { raw.iter().map(|v| format!("{v:02x}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn word(s: &[u8], at: usize) -> u64 { u64::from_le_bytes(s[at..at+8].try_into().unwrap()) }
fn apply(raw: &[u8]) -> Vec<u8> {
 let op=word(raw,8);let a=word(raw,16) as usize;let b=word(raw,24);
 let c=word(raw,32) as usize;let d=word(raw,40) as i64;let count=word(raw,48) as usize;
 let mut at=64;let mut lines=Vec::new();
 for _ in 0..count { let n=word(raw,at) as usize; at+=8; lines.push(std::str::from_utf8(&raw[at..at+n]).unwrap());at+=n; }
 match op {
  1 => (utils::truncation::estimate_tokens(a) as u64).to_le_bytes().to_vec(),
  2 => utils::truncation::format_megabytes(a).into_bytes(),
  3 => utils::truncation::format_content_with_line_numbers(&lines,a,if b==0 {None} else {Some((c,d))}).into_bytes(),
  4 => utils::truncation::format_extracted_content_smart(&lines,a,if b==0 {None} else {Some(c)}).into_bytes(),
  5 => { let mut v=(utils::truncation::MAX_RESULT_BYTES as u64).to_le_bytes().to_vec();v.extend(utils::truncation::CHARS_PER_TOKEN.to_bits().to_le_bytes());v },
  _ => panic!("unknown test operation"),
 }
}
fn main() {
 std::panic::set_hook(Box::new(|_|{}));
 let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
 for line in stdin.lock().lines() {
  let raw=unhex(&line.unwrap());
  match std::panic::catch_unwind(||apply(&raw)) {
   Ok(bytes) => writeln!(&mut out,"OK {}",hex(&bytes)).unwrap(),
   Err(_) => writeln!(&mut out,"PANIC").unwrap(),
  }
 }
}
