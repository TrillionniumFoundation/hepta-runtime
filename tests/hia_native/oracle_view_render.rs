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


// Test adapter only; every original function body is extracted byte-for-byte.
#![allow(dead_code)]
use std::cell::RefCell;
use std::future::Future;
use std::io::{self, BufRead, Write};
use std::pin::pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll, Wake, Waker};
type Result<T> = std::result::Result<T, String>;
macro_rules! anyhow { ($($arg:tt)*) => { format!($($arg)*) }; }
macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*)) }; }

#[derive(Default)]
struct State {
    flags: u64, start: i64, end: i64, first: String, current: String,
    first_stat: u64, current_stat: u64, range_phase: bool,
    actual_read: bool, range: Option<(usize, i64)>, hints: Vec<String>,
    rendered: Option<String>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
static CACHE: LazyLock<mcp::fs::delta::ViewCache> = LazyLock::new(Default::default);

mod utils {
    pub mod line_hash {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
	/// Plain line number (1-indexed; 0 and negatives carry position-specific meaning per tool).
	Number(i64),
	/// Composite id: 1-indexed line plus its expected 2-char content hash.
	Id { line: usize, hash: String },
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

mod mcp {
    pub mod request_ctx {
        pub fn with_view_cache<F, T>(f: F) -> Option<T>
        where F: FnOnce(&super::fs::delta::ViewCache) -> T {
            if crate::STATE.with(|s| s.borrow().flags & 8 != 0) { Some(f(&crate::CACHE)) }
            else { None }
        }
        pub fn push_hint(text: &str) {
            crate::STATE.with(|s| { let mut s=s.borrow_mut();
                if s.flags & 8 != 0 { s.hints.push(text.to_owned()); }
            });
        }
        pub fn drain_hints() -> Vec<String> {
            crate::STATE.with(|s| std::mem::take(&mut s.borrow_mut().hints))
        }
    }
    pub mod fs {
        #[derive(Clone)] pub struct PathSource;
        pub struct Metadata { pub size: u64 }
        pub mod text_editing {
            pub fn lock_key_for_source(_: &super::PathSource) -> String { "fixture".to_owned() }
        }
        pub async fn io_exists(_: &PathSource) -> crate::Result<bool> { Ok(true) }
        pub async fn io_is_file(_: &PathSource) -> crate::Result<bool> { Ok(true) }
        pub async fn io_metadata(_: &PathSource) -> crate::Result<Metadata> {
            crate::STATE.with(|s| { let s=s.borrow();
                if s.range_phase {
                    if s.flags & 64 == 0 { Err("fixture metadata read failure".to_owned()) }
                    else { Ok(Metadata { size: s.first_stat }) }
                } else { Ok(Metadata { size: s.current_stat }) }
            })
        }
        pub async fn io_read_to_string(_: &PathSource) -> crate::Result<String> {
            crate::STATE.with(|s| { let mut s=s.borrow_mut();
                if s.range_phase {
                    if s.flags & 32 != 0 { Err("fixture first read failure".to_owned()) }
                    else { Ok(s.first.clone()) }
                } else { s.actual_read=true; Ok(s.current.clone()) }
            })
        }
        pub mod delta {
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

//! Delta views — a whole-file `view` of a file this session already served
//! returns only what changed since, in the same diff style as edit results.
//!
//! The cache holds, per session and per file, the last content the model saw
//! in full. Whole-file views set it; this server's own writes keep it in step
//! (see `note_write`); ranged views and searches leave it alone because they
//! show the model only part of the file.

use std::collections::HashMap;
use std::sync::Mutex;

use super::text_editing::lock_key_for_source;
use super::PathSource;
use crate::mcp::request_ctx::with_view_cache;
use crate::utils::line_hash::line_id_at;
use crate::utils::truncation::format_content_with_line_numbers;

/// Files above this size are served in full every time: holding multi-MB
/// artifacts per session is not worth the delta.
const MAX_CACHED_BYTES: usize = 1024 * 1024;
/// Context lines around each hunk, matching edit diffs.
const CONTEXT: usize = 2;
/// Edit-distance ceiling for a delta. Beyond it the full file is about as
/// short, and the Myers trace (O(D²) memory) would start to cost.
const MAX_EDIT_DISTANCE: usize = 500;

/// Last full content served per file, keyed like the file locks.
// ponytail: unbounded per session (1MB cap per entry); add LRU eviction if a
// session ever views thousands of large files.
#[derive(Debug, Default)]
pub struct ViewCache {
	entries: Mutex<HashMap<String, String>>,
}

impl ViewCache {
	/// Publication can outlive its request. An owned publisher clears this
	/// session directly, without relying on a request-local cache context.
	pub(crate) fn forget_all(&self) {
		if let Ok(mut entries) = self.entries.lock() {
			entries.clear();
		}
	}

	fn get(&self, key: &str) -> Option<String> {
		self.entries.lock().ok()?.get(key).cloned()
	}

	fn set(&self, key: String, content: String) {
		let Ok(mut entries) = self.entries.lock() else {
			return;
		};
		if content.len() > MAX_CACHED_BYTES {
			entries.remove(&key);
		} else {
			entries.insert(key, content);
		}
	}

	fn forget(&self, key: &str) {
		if let Ok(mut entries) = self.entries.lock() {
			entries.remove(key);
		}
	}

	/// A directory relocation invalidates its cached descendants as well as
	/// the directory key. Use an explicit separator boundary so `old` cannot
	/// invalidate a sibling named `old2`. Other sessions keep separate caches.
	fn forget_subtree(&self, key: &str) {
		let prefix = format!("{}/", key.trim_end_matches('/'));
		if let Ok(mut entries) = self.entries.lock() {
			entries.retain(|name, _| name != key && !name.starts_with(&prefix));
		}
	}
}

/// Line-ending agnostic form: views and edits both work on `lines()`.
fn normalize(content: &str) -> String {
	content.replace("\r\n", "\n")
}

/// Record a write this server performed. The entry stays valid only if the
/// model's picture was current before the write (`before` matches the cache);
/// otherwise it is dropped so the next whole-file view is served in full.
pub fn note_write(source: &PathSource, before: &str, after: &str) {
	let key = lock_key_for_source(source);
	let before = normalize(before);
	with_view_cache(|cache| {
		if cache.get(&key).as_deref() == Some(before.as_str()) {
			cache.set(key.clone(), normalize(after));
		} else {
			cache.forget(&key);
		}
	});
}

/// Record a file the model created: it authored every line.
pub fn note_create(source: &PathSource, content: &str) {
	let key = lock_key_for_source(source);
	with_view_cache(|cache| cache.set(key.clone(), normalize(content)));
}

/// Drop the entry for a file whose content the model can no longer predict.
pub fn forget(source: &PathSource) {
	let key = lock_key_for_source(source);
	with_view_cache(|cache| cache.forget(&key));
}

/// Invalidate the directory itself and all cached file paths beneath it.
/// Moving a directory makes every descendant's previous cache identity stale;
/// invalidating only the directory key would retain misleading file deltas.
pub fn forget_subtree(source: &PathSource) {
	let key = lock_key_for_source(source);
	with_view_cache(|cache| cache.forget_subtree(&key));
}

/// Render a whole-file view: the full file the first time (or when `full`),
/// afterwards only the hunks changed since the model last saw it.
pub fn render_whole_file(source: &PathSource, content: &str, full: bool) -> String {
	let key = lock_key_for_source(source);
	let current = normalize(content);
	let previous = if full {
		None
	} else {
		with_view_cache(|cache| cache.get(&key)).flatten()
	};
	with_view_cache(|cache| cache.set(key.clone(), current.clone()));

	let new_lines: Vec<&str> = current.lines().collect();
	match previous {
		Some(prev) if prev == current => format!(
			"[unchanged since you last viewed or edited it: {} lines. Pass full: true to re-read.]",
			new_lines.len()
		),
		Some(prev) => {
			let old_lines: Vec<&str> = prev.lines().collect();
			match render_delta(&old_lines, &new_lines) {
				Some(delta) => delta,
				None => format!(
					"[changed since your last view: too many changes for a delta, full content follows]\n{}",
					format_content_with_line_numbers(&new_lines, 1, None)
				),
			}
		}
		None if new_lines.is_empty() => "[empty file, 0 lines]".to_string(),
		None => format_content_with_line_numbers(&new_lines, 1, None),
	}
}

/// Hunks with fresh ids for kept/added lines; removed lines collapse to their
/// old id range since the model already saw them. `None` when the change is
/// too large for a delta to pay off.
pub fn render_delta(old: &[&str], new: &[&str]) -> Option<String> {
	let ops = diff_lines(old, new, MAX_EDIT_DISTANCE)?;

	// Hunks are op-index ranges around each change, merged when their context touches.
	let mut hunks: Vec<(usize, usize)> = Vec::new();
	for (i, op) in ops.iter().enumerate() {
		if matches!(op, DiffOp::Equal(..)) {
			continue;
		}
		let start = i.saturating_sub(CONTEXT);
		let end = (i + CONTEXT).min(ops.len() - 1);
		match hunks.last_mut() {
			Some(last) if start <= last.1 + 1 => last.1 = last.1.max(end),
			_ => hunks.push((start, end)),
		}
	}

	let mut out = vec![format!(
		"[changed since your last view: {} hunk(s), {} lines now]",
		hunks.len(),
		new.len()
	)];
	for &(start, end) in &hunks {
		if start > 0 {
			out.push("...".to_string());
		}
		let mut i = start;
		while i <= end {
			match ops[i] {
				DiffOp::Equal(_, j) => out.push(format!("{}|{}", line_id_at(new, j + 1), new[j])),
				DiffOp::Insert(j) => out.push(format!("+{}|{}", line_id_at(new, j + 1), new[j])),
				DiffOp::Delete(first) => {
					let mut last = first;
					while i < end {
						let DiffOp::Delete(k) = ops[i + 1] else { break };
						last = k;
						i += 1;
					}
					out.push(removed_marker(old, first, last));
				}
			}
			i += 1;
		}
	}
	if hunks.last().is_some_and(|&(_, end)| end + 1 < ops.len()) {
		out.push("...".to_string());
	}
	Some(out.join("\n"))
}

/// Removed lines as an old-id range (0-based inclusive indices into `old`).
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

/// One step of a line diff; indices are 0-based into `old` / `new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffOp {
	Equal(usize, usize),
	Delete(usize),
	Insert(usize),
}

/// Myers line diff, O((N+M)·D). `None` once the edit distance exceeds `max_d`.
pub fn diff_lines(old: &[&str], new: &[&str], max_d: usize) -> Option<Vec<DiffOp>> {
	let n = old.len();
	let m = new.len();
	let max_d = max_d.min(n + m);
	// Diagonal k = x - y lives at v[k + offset]; the spare slots keep k±1 in range.
	let offset = max_d as i64 + 1;
	let at = |k: i64| (k + offset) as usize;
	let mut v = vec![0usize; 2 * max_d + 3];
	let mut trace: Vec<Vec<usize>> = Vec::new();

	for d in 0..=max_d as i64 {
		trace.push(v.clone());
		let mut k = -d;
		while k <= d {
			let down = k == -d || (k != d && v[at(k - 1)] < v[at(k + 1)]);
			let mut x = if down { v[at(k + 1)] } else { v[at(k - 1)] + 1 };
			let mut y = (x as i64 - k) as usize;
			while x < n && y < m && old[x] == new[y] {
				x += 1;
				y += 1;
			}
			v[at(k)] = x;
			if x >= n && y >= m {
				return Some(backtrack(&trace, n, m, offset));
			}
			k += 2;
		}
	}
	None
}

fn backtrack(trace: &[Vec<usize>], n: usize, m: usize, offset: i64) -> Vec<DiffOp> {
	let at = |k: i64| (k + offset) as usize;
	let mut ops = Vec::new();
	let (mut x, mut y) = (n, m);
	for (d, v) in trace.iter().enumerate().rev() {
		let d = d as i64;
		let k = x as i64 - y as i64;
		let prev_k = if k == -d || (k != d && v[at(k - 1)] < v[at(k + 1)]) {
			k + 1
		} else {
			k - 1
		};
		let prev_x = v[at(prev_k)];
		let prev_y = prev_x as i64 - prev_k;
		while x > prev_x && y as i64 > prev_y {
			x -= 1;
			y -= 1;
			ops.push(DiffOp::Equal(x, y));
		}
		if d > 0 {
			if x == prev_x {
				ops.push(DiffOp::Insert(y - 1));
			} else {
				ops.push(DiffOp::Delete(x - 1));
			}
			x = prev_x;
			y = prev_y as usize;
		}
	}
	ops.reverse();
	ops
}


            // Test-only access to the unchanged original cache methods.
            pub fn reset(previous: Option<String>) {
                crate::CACHE.forget_all();
                if let Some(text)=previous { crate::CACHE.set("fixture".to_owned(),text); }
            }
            pub fn cached() -> Option<String> { crate::CACHE.get("fixture") }
        }
        pub mod file_ops {
            use super::{io_exists,io_is_file,io_metadata,io_read_to_string,PathSource};
            use crate::utils::truncation::format_content_with_line_numbers;
            use crate::Result;
            pub(crate) const MAX_VIEW_FILE_BYTES: u64 = 5 * 1024 * 1024;
fn format_file_content_with_numbers(lines: &[&str], line_range: Option<(usize, i64)>) -> String {
	format_content_with_line_numbers(lines, 1, line_range)
}

pub async fn view_file_spec(
	source: &PathSource,
	line_range: Option<(usize, i64)>,
	full: bool,
) -> Result<String> {
	if !io_exists(source).await? {
		bail!("File not found");
	}

	if !io_is_file(source).await? {
		bail!("Path is not a file");
	}

	// Check file size to avoid loading very large files
	let metadata = io_metadata(source)
		.await
		.map_err(|e| anyhow!("Permission denied. Cannot read file: {}", e))?;
	if metadata.size > MAX_VIEW_FILE_BYTES {
		bail!("File is too large (>5MB)");
	}

	// Read the file content
	let content = io_read_to_string(source)
		.await
		.map_err(|e| anyhow!("Permission denied. Cannot read file: {}", e))?;

	// Whole-file views go through the session delta cache; ranged views render
	// exactly what was asked and leave the cache alone.
	let Some(range) = line_range else {
		return Ok(super::delta::render_whole_file(source, &content, full));
	};
	let lines: Vec<&str> = content.lines().collect();

	let content_with_numbers = format_file_content_with_numbers(&lines, Some(range));

	// Defensive: the range is pre-clamped in resolve_view_range, but if the formatter ever
	// returns its out-of-range error string, surface it as an error rather than content.
	if content_with_numbers.starts_with("Start line") {
		bail!("{}", content_with_numbers);
	}

	// Return plain text content
	Ok(content_with_numbers)
}
        }
        pub mod core {
            use super::{file_ops,io_metadata,io_read_to_string,PathSource};
            use crate::utils::line_hash::{Endpoint,resolve_line_index_clamped};
            use crate::utils::truncation::{MAX_RESULT_BYTES,format_megabytes};
            use crate::Result;
            pub struct McpToolCall;
fn resolve_endpoint_to_line(
	ep: &Endpoint,
	total_lines: usize,
	clamped: &mut bool,
) -> Result<usize> {
	let n = match ep {
		Endpoint::Number(n) => *n,
		Endpoint::Id { line, .. } => *line as i64,
	};
	let (line, was) = resolve_line_index_clamped(n, total_lines)
		.map_err(|e| anyhow!("Invalid lines parameter: {e}"))?;
	*clamped |= was;
	Ok(line)
}

async fn resolve_view_range(
	start_ep: Option<Endpoint>,
	end_ep: Option<Endpoint>,
	source: &PathSource,
) -> Result<Option<(usize, i64)>> {
	if start_ep.is_none() && end_ep.is_none() {
		return Ok(None);
	}

	// Same limit view_file_spec enforces — check before loading so a huge file isn't
	// read fully here just to resolve a range and then be rejected downstream.
	if let Ok(meta) = io_metadata(source).await {
		if meta.size > file_ops::MAX_VIEW_FILE_BYTES {
			bail!("File is too large (>5MB)");
		}
	}

	let total_lines = io_read_to_string(source)
		.await
		.map(|c| c.lines().count())
		.unwrap_or(0);

	if total_lines == 0 {
		// Empty/unreadable file: there is nothing to clamp a range against, so render the
		// (empty) whole file rather than erroring on an out-of-bounds line.
		return Ok(None);
	}

	let start_ep = start_ep.unwrap_or(Endpoint::Number(1));
	let end_ep = end_ep.unwrap_or(Endpoint::Number(-1));

	let mut clamped = false;
	let mut start = resolve_endpoint_to_line(&start_ep, total_lines, &mut clamped)?;
	let mut end = resolve_endpoint_to_line(&end_ep, total_lines, &mut clamped)?;
	// Transposed endpoints name exactly one range, so serve it and say what was
	// read. Erroring here costs a whole round-trip to be told the obvious.
	if start > end {
		std::mem::swap(&mut start, &mut end);
		crate::mcp::request_ctx::push_hint(&format!(
			"start was after end, so the range was read as [{start}, {end}]."
		));
	}
	if clamped {
		crate::mcp::request_ctx::push_hint(&format!(
			"Range clamped to [{start}, {end}]: the file has {total_lines} lines (negative indices count from the end)."
		));
	}
	Ok(Some((start, end as i64)))
}

pub async fn execute_view(call: &McpToolCall) -> Result<String> {
	let result = render_view(call).await?;
	if result.len() > MAX_RESULT_BYTES {
		bail!(
			"Result is {}, too large to return in one tool result (limit {}). Narrow `path`, `pattern` or `content`, or read the file in `start`/`end` ranges.",
			format_megabytes(result.len()),
			format_megabytes(MAX_RESULT_BYTES)
		);
	}
	Ok(result)
}
            // The scope of this oracle starts after endpoint parsing and path
            // routing; the actual original range and file functions still run.
            async fn render_view(_: &McpToolCall) -> Result<String> {
                let (flags,start,end)=crate::STATE.with(|s| {
                    let mut s=s.borrow_mut();s.range_phase=true;(s.flags,s.start,s.end)
                });
                let source=PathSource;
                let range=resolve_view_range(
                    if flags & 1 != 0 { Some(Endpoint::Number(start)) } else { None },
                    if flags & 2 != 0 { Some(Endpoint::Number(end)) } else { None },
                    &source).await;
                crate::STATE.with(|s| { let mut s=s.borrow_mut();s.range_phase=false;
                    if let Ok(value)=&range {s.range=*value;}
                });
                let result=file_ops::view_file_spec(&source,range?,flags & 4 != 0).await;
                crate::STATE.with(|s| {s.borrow_mut().rendered=result.as_ref().ok().cloned();});
                result
            }
        }
    }
}
use mcp::request_ctx;
fn append_hints(mut result: String) -> String {
	let hints = request_ctx::drain_hints();
	if !hints.is_empty() {
		result.push_str("\n\n");
		for hint in hints {
			result.push_str("⚠️ ");
			result.push_str(&hint);
			result.push('\n');
		}
	}
	result
}

struct NoWake;
impl Wake for NoWake { fn wake(self: Arc<Self>) {} }
fn block_on<F: Future>(future: F) -> F::Output {
    let waker=Waker::from(Arc::new(NoWake));let mut cx=Context::from_waker(&waker);
    let mut future=pin!(future);
    match future.as_mut().poll(&mut cx) { Poll::Ready(result)=>result,
        Poll::Pending=>panic!("test fixture must not suspend") }
}
fn word(s: &[u8], at: usize) -> u64 {u64::from_le_bytes(s[at..at+8].try_into().unwrap())}
fn put(out: &mut Vec<u8>, value: u64) {out.extend_from_slice(&value.to_le_bytes());}
fn hex(raw: &[u8]) -> String {raw.iter().map(|v| format!("{v:02x}")).collect()}
fn unhex(s: &str) -> Vec<u8> {(0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()}
fn apply(raw: &[u8]) -> Vec<u8> {
    assert_eq!(&raw[..8],b"HVIEW001");let operation=word(raw,8);let flags=word(raw,16);
    let a=word(raw,40) as usize;let b=word(raw,48) as usize;
    let first=std::str::from_utf8(&raw[96..96+a]).unwrap().to_owned();
    let current=std::str::from_utf8(&raw[96+a..96+a+b]).unwrap().to_owned();
    let previous=std::str::from_utf8(&raw[96+a+b..]).unwrap().to_owned();
    let first_stat=word(raw,64);let current_stat=word(raw,72);
    STATE.with(|s| *s.borrow_mut()=State {flags,start:word(raw,24) as i64,end:word(raw,32) as i64,
        first:first.clone(),current:current.clone(),first_stat,current_stat,..State::default()});
    mcp::fs::delta::reset(if flags & 16 != 0 {Some(previous.clone())} else {None});
    let result=block_on(mcp::fs::core::execute_view(&mcp::fs::core::McpToolCall));
    let (actual_read,range,hints,rendered)=STATE.with(|s| {let s=s.borrow();
        (s.actual_read,s.range,s.hints.clone(),s.rendered.clone())});
    let first_count=if flags & 3 != 0 && !(flags & 64 != 0 && first_stat > 5*1024*1024) && flags & 32 == 0 {
        first.lines().count() as u64
    } else {0};
    let current_count=if actual_read {current.lines().count() as u64} else {0};
    let normalized=if actual_read {current.replace("\r\n","\n")} else {String::new()};
    let action=if flags & 8 != 0 && actual_read && range.is_none() {
        if normalized.len() <= 1024*1024 {1} else {2}
    } else {0};
    if action==1 {assert_eq!(mcp::fs::delta::cached().as_ref(),Some(&normalized));}
    if action==2 {assert!(mcp::fs::delta::cached().is_none());}
    let mut kind=if !actual_read {
        if result.as_ref().err().unwrap().starts_with("File is too large") {5} else {6}
    } else if range.is_some() {4}
      else if flags & 24 == 24 && flags & 4 == 0 {if normalized==previous {1} else {2}}
      else {0};
    let mut status=if operation==1 {(!actual_read) as u64} else {result.is_err() as u64};
    let mut body=if operation==1 && actual_read {String::new()}
        else {match result {Ok(s)=>s,Err(e)=>e}};
    if operation==2 && actual_read {
        if let Some(text)=rendered {
            if text.len()>8*1024*1024 {kind=7;status=1;}
            else if kind==2 && text.starts_with("[changed since your last view: too many changes") {kind=3;}
        }
    }
    let body_size=body.len();
    let hint_mask=if status==0 {hints.iter().fold(0u64,|mask,h|mask|
        if h.starts_with("start was after end") {1} else {2})} else {0};
    if operation==2 && status==0 {body=append_hints(body);}
    let cached=if action==1 {normalized.as_bytes()} else {&[]};
    let mut out=b"HVIEWR01".to_vec();
    for value in [status,body.len() as u64,action,cached.len() as u64,range.is_some() as u64,
        range.map(|p|p.0 as u64).unwrap_or(0),range.map(|p|p.1 as u64).unwrap_or(0),
        first_count,current_count,hint_mask,kind,normalized.len() as u64,body_size as u64,0,0] {
        put(&mut out,value);
    }
    out.extend_from_slice(body.as_bytes());out.extend_from_slice(cached);out
}
fn main() {
    std::panic::set_hook(Box::new(|_|{}));
    let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let raw=unhex(&line.unwrap());
        match std::panic::catch_unwind(||apply(&raw)) {
            Ok(bytes)=>writeln!(&mut out,"OK {}",hex(&bytes)).unwrap(),
            Err(_)=>writeln!(&mut out,"PANIC").unwrap(),
        }
    }
}
