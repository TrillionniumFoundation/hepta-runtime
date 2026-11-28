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

//! Actual original conflict, duplicate and ordered batch application owner.
#![allow(dead_code)]
use std::io::{self, Read, Write};
#[rustfmt::skip]
mod original {
type Result<T, E = String> = std::result::Result<T, E>;
macro_rules! anyhow { ($($arg:tt)*) => { format!($($arg)*) }; }
macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*)) }; }
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

const LF_ENDING: &str = "\n";
const CRLF_ENDING: &str = "\r\n";

#[derive(Clone)]
struct EditableLine {
	text: String,
	ending: &'static str,
}

#[derive(Clone)]
pub(crate) struct EditableContent {
	lines: Vec<EditableLine>,
	dominant_ending: &'static str,
	had_trailing_newline: bool,
}

impl EditableContent {
	pub(crate) fn from_raw(raw: &str) -> Self {
		let mut lf_count = 0;
		let mut crlf_count = 0;
		let lines = if raw.is_empty() {
			Vec::new()
		} else {
			raw.split_inclusive('\n')
				.map(|line| {
					if let Some(text) = line.strip_suffix(CRLF_ENDING) {
						crlf_count += 1;
						EditableLine {
							text: text.to_string(),
							ending: CRLF_ENDING,
						}
					} else if let Some(text) = line.strip_suffix(LF_ENDING) {
						lf_count += 1;
						EditableLine {
							text: text.to_string(),
							ending: LF_ENDING,
						}
					} else {
						EditableLine {
							text: line.to_string(),
							ending: "",
						}
					}
				})
				.collect()
		};

		Self {
			lines,
			dominant_ending: if crlf_count > lf_count {
				CRLF_ENDING
			} else {
				LF_ENDING
			},
			had_trailing_newline: raw.ends_with('\n'),
		}
	}

	fn normalized(&self) -> String {
		let mut content = String::new();
		for line in &self.lines {
			content.push_str(&line.text);
			if !line.ending.is_empty() {
				content.push('\n');
			}
		}
		content
	}

	pub(crate) fn rendered(&self) -> String {
		let mut content = String::new();
		for line in &self.lines {
			content.push_str(&line.text);
			content.push_str(line.ending);
		}
		content
	}

	pub(crate) fn insert_lines(
		&mut self,
		position: usize,
		content_lines: &[&str],
		trailing_newline: bool,
	) -> Result<()> {
		if position > self.lines.len() {
			bail!("Invalid internal insertion position {position}");
		}

		let mut inserted: Vec<EditableLine> = content_lines
			.iter()
			.map(|line| EditableLine {
				text: line.trim_end_matches('\r').to_string(),
				ending: self.dominant_ending,
			})
			.collect();
		if inserted.is_empty() {
			return Ok(());
		}

		if position > 0 && self.lines[position - 1].ending.is_empty() {
			self.lines[position - 1].ending = self.dominant_ending;
		}
		if position == self.lines.len() && !trailing_newline {
			let last = inserted.len() - 1;
			inserted[last].ending = "";
		}

		self.lines.splice(position..position, inserted);
		self.had_trailing_newline = trailing_newline;
		Ok(())
	}

	fn replace_normalized_range(
		&mut self,
		start: usize,
		end: usize,
		replacement: &str,
	) -> Result<()> {
		let content = self.normalized();
		if start > end
			|| end > content.len()
			|| !content.is_char_boundary(start)
			|| !content.is_char_boundary(end)
		{
			bail!("Invalid internal replacement range {start}..{end}");
		}

		if self.lines.is_empty() {
			self.lines = lines_with_ending(replacement, self.dominant_ending);
			return Ok(());
		}

		let last_offset = if end > start {
			end - 1
		} else {
			start.min(content.len().saturating_sub(1))
		};
		let mut offset = 0;
		let mut start_line = None;
		let mut end_line = None;
		let mut region_start = 0;
		let mut region_end = 0;

		for (index, line) in self.lines.iter().enumerate() {
			let line_len = line.text.len() + usize::from(!line.ending.is_empty());
			let next_offset = offset + line_len;
			if start_line.is_none()
				&& (start < next_offset
					|| (start == content.len() && index + 1 == self.lines.len()))
			{
				start_line = Some(index);
				region_start = offset;
			}
			if last_offset < next_offset {
				end_line = Some(index);
				region_end = next_offset;
				break;
			}
			offset = next_offset;
		}

		let start_line = start_line.ok_or_else(|| anyhow!("Replacement start is out of bounds"))?;
		let end_line = end_line.ok_or_else(|| anyhow!("Replacement end is out of bounds"))?;
		let mut changed = String::new();
		changed.push_str(&content[region_start..start]);
		changed.push_str(replacement);
		changed.push_str(&content[end..region_end]);

		let mut suffix = self.lines.split_off(end_line + 1);
		self.lines.truncate(start_line);
		let mut changed_lines = lines_with_ending(&changed, self.dominant_ending);
		if !changed.is_empty() && !changed.ends_with('\n') && !suffix.is_empty() {
			let changed_tail = changed_lines
				.pop()
				.ok_or_else(|| anyhow!("Replacement line is missing"))?;
			let suffix_head = suffix.remove(0);
			changed_lines.push(EditableLine {
				text: changed_tail.text + &suffix_head.text,
				ending: self.dominant_ending,
			});
		}
		self.lines.extend(changed_lines);
		self.lines.extend(suffix);
		Ok(())
	}

	fn preserve_trailing_newline(&mut self) {
		if self.lines.is_empty() {
			if self.had_trailing_newline {
				self.lines.push(EditableLine {
					text: String::new(),
					ending: self.dominant_ending,
				});
			}
			return;
		}

		let last = self.lines.len() - 1;
		for line in &mut self.lines[..last] {
			if line.ending.is_empty() {
				line.ending = self.dominant_ending;
			}
		}
		if self.had_trailing_newline {
			if self.lines[last].ending.is_empty() {
				self.lines[last].ending = self.dominant_ending;
			}
		} else if !self.lines[last].text.is_empty() {
			// An empty last line exists only through its terminator: stripping it would
			// delete the blank line the edit wrote, not just the final newline.
			self.lines[last].ending = "";
		}
	}
}

fn lines_with_ending(content: &str, ending: &'static str) -> Vec<EditableLine> {
	if content.is_empty() {
		return Vec::new();
	}
	content
		.split_inclusive('\n')
		.map(|line| {
			if let Some(text) = line.strip_suffix('\n') {
				EditableLine {
					text: text.to_string(),
					ending,
				}
			} else {
				EditableLine {
					text: line.to_string(),
					ending: "",
				}
			}
		})
		.collect()
}

// Operation text is line content, never a source of file-format bytes. In particular,
// `str::lines` does not remove a CR from a final segment without a following newline.
fn incoming_content_lines(content: &str) -> Vec<&str> {
	content
		.lines()
		.map(|line| line.trim_end_matches('\r'))
		.collect()
}

fn is_structural_noise(line: &str) -> bool {
	let trimmed = line.trim();
	// Empty or only whitespace
	if trimmed.is_empty() {
		return true;
	}
	// Strip one optional trailing `,` or `;`
	let core = trimmed.trim_end_matches([',', ';']);
	// Must be exactly one closing bracket/brace/paren after stripping the trailer
	matches!(core, "}" | "]" | ")")
}

// Check whether `content` (the replacement) duplicates the line immediately
// before or after the range [start_line, end_line] (1-indexed) in `file_lines`.
//
// Returns an error string if duplication is detected, Ok(()) otherwise.
// Structural noise lines are exempt — they legitimately appear at boundaries.
fn check_replace_duplicates(
	content_lines: &[&str],
	file_lines: &[&str],
	start_line: usize,
	end_line: usize,
	operation_index: usize,
) -> Result<(), String> {
	if content_lines.is_empty() {
		return Ok(());
	}

	let id = |line_1idx: usize| -> String { line_id_at(file_lines, line_1idx) };
	let range_id = |s: usize, e: usize| -> String { format!("\"{}\"-\"{}\"", id(s), id(e)) };

	// First content line matches the line immediately before the range
	if start_line > 1 {
		let line_before = file_lines[start_line - 2];
		if content_lines[0] == line_before && !is_structural_noise(line_before) {
			return Err(format!(
				"Duplicate line detected in operation {}: content's first line repeats {} ({:?}), \
				the line just before the range {}. Give only the replacement lines, not \
				surrounding context; use str_replace if the repeat is intended.",
				operation_index,
				id(start_line - 1),
				line_before,
				range_id(start_line, end_line)
			));
		}
	}
	// Last content line matches the line immediately after the range
	if end_line < file_lines.len() {
		let line_after = file_lines[end_line];
		let last = content_lines[content_lines.len() - 1];
		if last == line_after && !is_structural_noise(line_after) {
			return Err(format!(
				"Duplicate line detected in operation {}: content's last line repeats {} ({:?}), \
				the line just after the range {}. Give only the replacement lines, not \
				surrounding context; use str_replace if the repeat is intended.",
				operation_index,
				id(end_line + 1),
				line_after,
				range_id(start_line, end_line)
			));
		}
	}
	Ok(())
}

// Check for conflicting operations that would corrupt the file.
//
// Conflict rules:
//   Replace vs Replace — ranges overlap → conflict (both try to modify same lines)
//   Insert  vs Insert  — same anchor line → conflict (ambiguous ordering)
//   Insert  vs Replace — conflict when the insert's gap lies inside the replaced
//                        range (s <= anchor < e): the anchor line is being rewritten,
//                        so where the insert lands would be a guess. Inserting after
//                        the range's last line or before the range is unambiguous.
fn detect_conflicts(operations: &[BatchOperation], file_lines: &[&str]) -> Result<(), String> {
	let id = |line_1idx: usize| -> String {
		// Anchor 0 means "file start" — there is no line to identify, and `0 - 1`
		// would underflow the usize index.
		if line_1idx == 0 {
			"the start of the file".to_string()
		} else {
			line_id_at(file_lines, line_1idx)
		}
	};

	for i in 0..operations.len() {
		for j in (i + 1)..operations.len() {
			let op1 = &operations[i];
			let op2 = &operations[j];

			match (&op1.operation_type, &op2.operation_type) {
				// Two replaces: check if ranges overlap
				(OperationType::Replace, OperationType::Replace) => {
					let (s1, e1) = replace_range(&op1.line_range);
					let (s2, e2) = replace_range(&op2.line_range);
					// Ranges overlap when s1 <= e2 AND s2 <= e1
					if s1 <= e2 && s2 <= e1 {
						return Err(format!(
							"Conflicting operations: operation {} (replace \"{}-{}\") and {} (replace \"{}-{}\") have overlapping ranges",
							op1.operation_index, id(s1), id(e1), op2.operation_index, id(s2), id(e2)
						));
					}
				}
				// Two inserts: conflict only if same anchor line (ambiguous order)
				(OperationType::Insert, OperationType::Insert) => {
					let line1 = insert_anchor(&op1.line_range);
					let line2 = insert_anchor(&op2.line_range);
					if line1 == line2 {
						return Err(format!(
							"Conflicting operations: operation {} and {} both insert after {}",
							op1.operation_index,
							op2.operation_index,
							id(line1)
						));
					}
				}
				(OperationType::Insert, OperationType::Replace)
				| (OperationType::Replace, OperationType::Insert) => {
					let (ins, rep) = if op1.operation_type == OperationType::Insert {
						(op1, op2)
					} else {
						(op2, op1)
					};
					let anchor = insert_anchor(&ins.line_range);
					let (s, e) = replace_range(&rep.line_range);
					if s <= anchor && anchor < e {
						return Err(format!(
							"Conflicting operations: operation {} inserts after {}, inside the range operation {} replaces (\"{}-{}\"). Put those lines in the replacement content instead.",
							ins.operation_index, id(anchor), rep.operation_index, id(s), id(e)
						));
					}
				}
			}
		}
	}
	Ok(())
}

// Extract the (start, end) range from a replace operation's LineRange
fn replace_range(line_range: &LineRange) -> (usize, usize) {
	match line_range {
		LineRange::Range(start, end) => (*start, *end),
		LineRange::Single(line) => (*line, *line),
	}
}

// Extract the anchor line from an insert operation's LineRange
fn insert_anchor(line_range: &LineRange) -> usize {
	match line_range {
		LineRange::Single(line) => *line,
		LineRange::Range(start, _) => *start,
	}
}

// Apply all operations to the original file content.
//
// Two-phase approach: replaces first, then inserts.
// All line numbers reference the ORIGINAL file. Replaces among themselves are
// applied in reverse order (highest start first) so earlier replaces don't shift
// later ones. After all replaces, we compute an offset map so inserts can find
// their correct position in the (now modified) line array.
async fn apply_batch_operations(
	original: &EditableContent,
	operations: &[BatchOperation],
) -> Result<EditableContent> {
	let mut lines = original.lines.clone();
	let original_len = lines.len();

	// Separate into replaces and inserts
	let mut replaces: Vec<&BatchOperation> = operations
		.iter()
		.filter(|op| op.operation_type == OperationType::Replace)
		.collect();
	let mut inserts: Vec<&BatchOperation> = operations
		.iter()
		.filter(|op| op.operation_type == OperationType::Insert)
		.collect();

	// Sort replaces by start position descending (highest first)
	replaces.sort_by(|a, b| {
		let sa = match &a.line_range {
			LineRange::Range(s, _) => *s,
			LineRange::Single(l) => *l,
		};
		let sb = match &b.line_range {
			LineRange::Range(s, _) => *s,
			LineRange::Single(l) => *l,
		};
		sb.cmp(&sa)
	});

	// Phase 1: Apply all replaces (reverse order preserves original line refs)
	// Track each replace's offset: (original_end, delta) where delta = new_lines - old_lines
	let mut replace_deltas: Vec<(usize, usize, i64)> = Vec::with_capacity(replaces.len());

	for operation in &replaces {
		let (start, end) = match operation.line_range {
			LineRange::Range(start, end) => (start, end),
			LineRange::Single(line) => (line, line),
		};

		// Validate line range (1-indexed)
		if start == 0 || end == 0 {
			return Err(anyhow!("Line numbers must be 1-indexed (start from 1)"));
		}
		if start > original_len || end > original_len {
			return Err(anyhow!(
				"Line range [{}, {}] is beyond file length {}",
				start,
				end,
				original_len
			));
		}
		if start > end {
			return Err(anyhow!("Invalid line range: start {} > end {}", start, end));
		}

		let old_count = end - start + 1;
		let content_lines: Vec<EditableLine> = incoming_content_lines(&operation.content)
			.into_iter()
			.map(|text| EditableLine {
				text: text.to_string(),
				ending: original.dominant_ending,
			})
			.collect();
		let new_count = content_lines.len();

		// Remove old lines (0-indexed)
		let start_idx = start - 1;
		for _ in 0..old_count {
			lines.remove(start_idx);
		}

		// Insert new content
		for (i, line) in content_lines.into_iter().enumerate() {
			lines.insert(start_idx + i, line);
		}

		replace_deltas.push((start, end, new_count as i64 - old_count as i64));
	}

	// Phase 2: Apply inserts with adjusted positions.
	// For each insert's original anchor line, compute how much it shifted due to replaces.
	// Sort inserts descending so they don't interfere with each other.
	inserts.sort_by(|a, b| {
		let la = match &a.line_range {
			LineRange::Single(l) => *l,
			LineRange::Range(s, _) => *s,
		};
		let lb = match &b.line_range {
			LineRange::Single(l) => *l,
			LineRange::Range(s, _) => *s,
		};
		lb.cmp(&la)
	});

	for operation in &inserts {
		let original_anchor = match operation.line_range {
			LineRange::Single(line) => line,
			_ => return Err(anyhow!("Insert operation must use single line number")),
		};

		// Validate against original file length
		if original_anchor > original_len {
			return Err(anyhow!(
				"Insert position {} is beyond file length {}",
				original_anchor,
				original_len
			));
		}

		// A replace at [s,e] with delta D shifts everything after line e by D; an
		// anchor before the range is unaffected, and one inside it was rejected by
		// detect_conflicts.
		let mut adjusted = original_anchor as i64;
		for &(_, re, delta) in &replace_deltas {
			if original_anchor >= re {
				adjusted += delta;
			}
		}

		let insert_pos = adjusted.max(0) as usize;

		// Split content by lines and insert
		let content_lines: Vec<EditableLine> = incoming_content_lines(&operation.content)
			.into_iter()
			.map(|text| EditableLine {
				text: text.to_string(),
				ending: original.dominant_ending,
			})
			.collect();

		if insert_pos == 0 {
			for (i, line) in content_lines.into_iter().enumerate() {
				lines.insert(i, line);
			}
		} else {
			let clamped = insert_pos.min(lines.len());
			for (i, line) in content_lines.into_iter().enumerate() {
				lines.insert(clamped + i, line);
			}
		}
	}

	let mut result = original.clone();
	result.lines = lines;
	result.preserve_trailing_newline();
	Ok(result)
}


async fn checked_apply(original: &EditableContent, batch_operations: Vec<BatchOperation>) -> Result<EditableContent> {
	let original_content = original.normalized();
	let original_lines: Vec<&str> = original_content.lines().collect();
	// Check for conflicts between operations
	if let Err(conflict_error) = detect_conflicts(&batch_operations, &original_lines) {
		bail!("{}", conflict_error);
	}

	// Duplicate-line detection: validate operations against original content before applying.
	// Catches the #1 AI mistake of including surrounding/already-existing lines.
	let orig_line_id = |line_1idx: usize| -> String {
		// Anchor 0 means "file start" — no line to identify, and `0 - 1` underflows.
		if line_1idx == 0 {
			"the start of the file".to_string()
		} else {
			line_id_at(&original_lines, line_1idx)
		}
	};
	for op in &batch_operations {
		let content_lines = incoming_content_lines(&op.content);
		if content_lines.is_empty() {
			continue;
		}
		match op.operation_type {
			OperationType::Replace => {
				let (start, end) = match op.line_range {
					LineRange::Range(s, e) => (s, e),
					LineRange::Single(line) => (line, line),
				};
				if let Err(e) = check_replace_duplicates(
					&content_lines,
					&original_lines,
					start,
					end,
					op.operation_index,
				) {
					bail!("{}", e);
				}
			}
			OperationType::Insert => {
				// insert_after=N means content goes between line N and line N+1.
				let insert_after = match op.line_range {
					LineRange::Single(line) => line,
					_ => continue, // malformed; apply_batch_operations will catch it
				};
				// Single-line insert: content[0] must not duplicate the line right after
				// the insert point, unless it is structural noise.
				if content_lines.len() == 1 {
					if insert_after < original_lines.len() {
						let line_after = original_lines[insert_after];
						if content_lines[0] == line_after && !is_structural_noise(line_after) {
							bail!(
								"Duplicate line detected in operation {}: inserting after {} repeats {} ({:?}), which already exists.",
								op.operation_index, orig_line_id(insert_after), orig_line_id(insert_after + 1), line_after
							);
						}
					}
				} else {
					// Multi-line insert (>=2 lines): full block match is unambiguous duplication — no noise exemption.
					let available = original_lines.len().saturating_sub(insert_after);
					let check_len = content_lines.len().min(available);
					if check_len >= 2
						&& content_lines[..check_len]
							== original_lines[insert_after..insert_after + check_len]
					{
						bail!(
							"Duplicate block detected in operation {}: the {} lines inserted after {} already exist at {}-{}.",
							op.operation_index, check_len, orig_line_id(insert_after), orig_line_id(insert_after + 1), orig_line_id(insert_after + check_len)
						);
					}
				}
			}
		}
	}

	let edited = apply_batch_operations(original, &batch_operations)
		.await
		.map_err(|e| anyhow!("Failed to apply operations: {}", e))?;
	Ok(edited)
}

pub fn evaluate(raw: &str, rows: Vec<(usize, u64, usize, usize, String)>, mode: u64) -> Vec<u8> {
	let original = EditableContent::from_raw(raw);
	let count = rows.len();
	let operations = rows.into_iter().map(|(index, kind, start, end, content)| BatchOperation {
		operation_type: if kind == 1 { OperationType::Insert } else { OperationType::Replace },
		line_range: if kind == 1 { LineRange::Single(start) } else { LineRange::Range(start, end) },
		content, operation_index: index,
	}).collect();
	let result = crate::ready(checked_apply(&original, operations));
	let (owner, error) = match result { Ok(value) => (value, String::new()), Err(error) => (original, error) };
	let normalized = owner.normalized();
	let rendered = owner.rendered();
	let mut output = b"HBAPLR01".to_vec();
	let selected = if !error.is_empty() { 0 } else if mode == 0 { rendered.len() } else if mode == 1 { normalized.len() } else { normalized.len() + rendered.len() };
	for value in [usize::from(!error.is_empty()), if error.is_empty() { count } else { 0 }, owner.dominant_ending.len(), usize::from(owner.had_trailing_newline), owner.lines.len(), normalized.len(), rendered.len(), selected, error.len()] {
		output.extend_from_slice(&(value as u64).to_le_bytes());
	}
	if error.is_empty() {
		if mode != 0 { output.extend_from_slice(normalized.as_bytes()); }
		if mode != 1 { output.extend_from_slice(rendered.as_bytes()); }
	}
	output.extend_from_slice(error.as_bytes());
	output
}
}

struct NoWake;
impl std::task::Wake for NoWake {
	fn wake(self: std::sync::Arc<Self>) {}
}
fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
	let waker = std::task::Waker::from(std::sync::Arc::new(NoWake));
	let mut context = std::task::Context::from_waker(&waker);
	match std::pin::pin!(future).as_mut().poll(&mut context) {
		std::task::Poll::Ready(value) => value,
		std::task::Poll::Pending => panic!("pure original owner unexpectedly suspended"),
	}
}
fn word(input: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}
fn evaluate(input: &[u8]) -> Vec<u8> {
	assert!(input.len() >= 112 && &input[..8] == b"HBACT001");
	let mode = word(input, 8);
	assert!(mode <= 2);
	for offset in [32, 40, 48, 56] {
		assert_eq!(word(input, offset), 0);
	}
	let size = word(input, 16) as usize;
	let raw = std::str::from_utf8(&input[64..64 + size]).unwrap();
	let plan = &input[64 + size..];
	assert_eq!(word(input, 24) as usize, plan.len());
	assert_eq!(&plan[..8], b"HBPLR001");
	assert_eq!(word(plan, 8), 0);
	let count = word(plan, 16) as usize;
	assert!((1..=50).contains(&count));
	assert_eq!(word(plan, 24) as usize, plan.len() - 48);
	assert_eq!(word(plan, 32), 0);
	assert_eq!(word(plan, 40), 0);
	let mut at = 48;
	let mut rows = Vec::new();
	for index in 0..count {
		assert_eq!(word(plan, at) as usize, index);
		let kind = word(plan, at + 8);
		assert!(kind == 1 || kind == 2);
		assert_eq!(word(plan, at + 16), kind);
		let start = word(plan, at + 24) as usize;
		let end = word(plan, at + 32) as usize;
		let length = word(plan, at + 40) as usize;
		at += 48;
		let content = std::str::from_utf8(&plan[at..at + length])
			.unwrap()
			.to_owned();
		at += length;
		rows.push((index, kind, start, end, content));
	}
	assert_eq!(at, plan.len());
	original::evaluate(raw, rows, mode)
}
fn main() -> io::Result<()> {
	let mut input = io::BufReader::new(io::stdin().lock());
	let mut output = io::BufWriter::new(io::stdout().lock());
	let mut tag = [0; 8];
	input.read_exact(&mut tag)?;
	assert_eq!(&tag, b"HBAREQ01");
	output.write_all(b"HBARES01")?;
	let mut cases = 0_u64;
	let mut bytes = 8_u64;
	loop {
		let mut size = [0; 8];
		let first = input.read(&mut size[..1])?;
		if first == 0 {
			break;
		}
		input.read_exact(&mut size[1..])?;
		let length = u64::from_le_bytes(size) as usize;
		assert!((112..=536870912).contains(&length));
		let mut frame = vec![0; length];
		input.read_exact(&mut frame)?;
		let result = evaluate(&frame);
		output.write_all(&(result.len() as u64).to_le_bytes())?;
		output.write_all(&result)?;
		cases += 1;
		bytes += 8 + result.len() as u64;
	}
	output.flush()?;
	eprintln!("{{\"status\":\"PASS\",\"rust_oracle_cases\":{cases},\"output_bytes\":{bytes}}}");
	Ok(())
}
