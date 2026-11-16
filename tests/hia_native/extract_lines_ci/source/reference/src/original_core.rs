// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact production items; verified by the source extraction manifest.
use super::{delta, text_editing};
use super::remote::{io_exists, io_read_to_string, PathSource};
use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const MAX_HISTORY_PER_FILE: usize = 10;


const MAX_HISTORY_TOTAL_BYTES: usize = 64 * 1024 * 1024;


#[derive(Default)]
struct HistoryStore {
	files: HashMap<String, Vec<String>>,
	// One entry per snapshot push, oldest first. May reference paths whose oldest
	// snapshot is already gone (undo pops, per-file cap) — eviction skips those.
	order: std::collections::VecDeque<String>,
	total_bytes: usize,
}


impl HistoryStore {
	fn push(&mut self, key: String, content: String, byte_cap: usize) {
		self.total_bytes += content.len();
		let history = self.files.entry(key.clone()).or_default();
		if history.len() >= MAX_HISTORY_PER_FILE {
			let removed = history.remove(0);
			self.total_bytes -= removed.len();
		}
		history.push(content);
		self.order.push_back(key);

		// Over budget: drop the globally oldest snapshots. `len() > 1` keeps the
		// snapshot just pushed even if it alone exceeds the cap — evicting it
		// would silently break undo for the file being edited right now.
		while self.total_bytes > byte_cap && self.order.len() > 1 {
			let Some(oldest) = self.order.pop_front() else {
				break;
			};
			let Some(history) = self.files.get_mut(&oldest) else {
				continue;
			};
			if history.is_empty() {
				self.files.remove(&oldest);
				continue;
			}
			let removed = history.remove(0);
			self.total_bytes -= removed.len();
			if history.is_empty() {
				self.files.remove(&oldest);
			}
		}
	}

	fn pop(&mut self, key: &str) -> Option<String> {
		let history = self.files.get_mut(key)?;
		let content = history.pop()?;
		self.total_bytes -= content.len();
		if history.is_empty() {
			self.files.remove(key);
		}
		Some(content)
	}
}


static FILE_HISTORY: OnceLock<Mutex<HistoryStore>> = OnceLock::new();


fn file_history() -> &'static Mutex<HistoryStore> {
	FILE_HISTORY.get_or_init(|| Mutex::new(HistoryStore::default()))
}


pub async fn save_file_history(source: &PathSource) -> Result<()> {
	if io_exists(source).await? {
		let content = io_read_to_string(source).await?;
		// Use the same canonicalized key as the file lock map so undo history
		// follows the file even when callers pass aliased paths.
		let path_str = text_editing::lock_key_for_source(source);
		file_history()
			.lock()
			.map_err(|_| anyhow!("Failed to acquire lock on file history"))?
			.push(path_str, content, MAX_HISTORY_TOTAL_BYTES);
	}
	Ok(())
}


pub async fn undo_edit(source: &PathSource) -> Result<String> {
	// Serialize with other writers on the same file — without this, an undo racing a
	// concurrent str_replace/batch_edit could interleave the pop and write and lose data.
	let file_lock = text_editing::acquire_file_lock(source).await?;
	let _lock_guard = file_lock.lock().await;

	let path_str = text_editing::lock_key_for_source(source);
	let previous_content = file_history()
		.lock()
		.map_err(|_| anyhow!("Failed to acquire lock on file history"))?
		.pop(&path_str);

	if let Some(prev_content) = previous_content {
		text_editing::atomic_write(source, &prev_content).await?;
		// The restored content is not what the model last saw as a whole.
		delta::forget(source);

		Ok(format!(
			"Successfully undid the last edit to {}",
			source.display()
		))
	} else {
		bail!("No more undo history for this file (up to 10 levels are stored per file).");
	}
}



use super::super::McpToolCall;
use super::remote::{resolve_path_source, io_create_dir_all};
use crate::utils::line_hash::{self, Endpoint, resolve_line_index};
use crate::utils::truncation::format_extracted_content_smart;
use serde_json::Value;

fn parse_optional_endpoint(value: Option<&Value>, name: &str) -> Result<Option<Endpoint>> {
	match value {
		Some(v) if !v.is_null() => Ok(Some(
			line_hash::parse_endpoint(v).map_err(|e| anyhow!("Invalid '{name}': {e}"))?,
		)),
		_ => Ok(None),
	}
}

pub async fn execute_extract_lines(call: &McpToolCall) -> Result<String> {
	// Validate and extract from_path parameter
	let from_path = match call.parameters.get("from_path") {
		Some(Value::String(p)) => {
			if p.trim().is_empty() {
				bail!("Parameter 'from_path' cannot be empty");
			}
			p.clone()
		}
		Some(_) => {
			bail!("Parameter 'from_path' must be a string");
		}
		None => {
			bail!("Missing required parameter 'from_path'");
		}
	};

	// Validate and extract from_start / from_end endpoints (line number or line id).
	// from_end omitted → single line (defaults to from_start). Resolution is deferred
	// until after the source file is read.
	let from_start_ep = match call.parameters.get("from_start") {
		Some(v) if !v.is_null() => {
			line_hash::parse_endpoint(v).map_err(|e| anyhow!("Invalid 'from_start': {e}"))?
		}
		_ => bail!("Missing required parameter 'from_start' (line number or line id)"),
	};
	let from_end_ep = parse_optional_endpoint(call.parameters.get("from_end"), "from_end")?
		.unwrap_or_else(|| from_start_ep.clone());

	// Validate and extract append_path parameter
	let append_path = match call.parameters.get("append_path") {
		Some(Value::String(p)) => {
			if p.trim().is_empty() {
				bail!("Parameter 'append_path' cannot be empty");
			}
			p.clone()
		}
		Some(_) => {
			bail!("Parameter 'append_path' must be a string");
		}
		None => {
			bail!("Missing required parameter 'append_path'");
		}
	};

	// Validate and extract append_line parameter: 0 (start), -1 (end), N (after line N),
	// or a line id. Id verification is deferred until after the target file is read.
	let append_line_ep = match call.parameters.get("append_line") {
		Some(v) if !v.is_null() => {
			line_hash::parse_endpoint(v).map_err(|e| anyhow!("Invalid 'append_line': {e}"))?
		}
		_ => {
			bail!("Missing required parameter 'append_line' (0 = start, -1 = end, N, or a line id)")
		}
	};

	// Read source file
	let from_source = resolve_path_source(&from_path, &call.workdir);
	if !io_exists(&from_source).await? {
		bail!("Source file does not exist: {from_path}");
	}

	let source_content = match io_read_to_string(&from_source).await {
		Ok(content) => content,
		Err(e) => {
			bail!("Failed to read source file '{from_path}': {e}");
		}
	};

	// Split content into lines and resolve negative indices
	let source_lines: Vec<&str> = source_content.lines().collect();
	let total_lines = source_lines.len();

	// Resolve from_start / from_end endpoints to 1-indexed line numbers (strict — no
	// clamping). Line ids are verified against the source content; a stale id fails
	// with the current content instead of silently copying the wrong lines.
	let resolve_extract_endpoint = |ep: &Endpoint, which: &str| -> Result<usize> {
		match ep {
			Endpoint::Number(n) => resolve_line_index(*n, total_lines)
				.map_err(|e| anyhow!("Invalid from_{which}: {e}")),
			Endpoint::Id { line, hash } => line_hash::verify_line_id(*line, hash, &source_lines)
				.map_err(|e| anyhow!("Invalid from_{which}: {e}")),
		}
	};
	let from_start = resolve_extract_endpoint(&from_start_ep, "start")?;
	let from_end = resolve_extract_endpoint(&from_end_ep, "end")?;
	if from_start > from_end {
		bail!(
			"from_start (line {from_start}) is after from_end (line {from_end}) — the range must go forward"
		);
	}
	let from_range = (from_start, from_end);

	// Extract the specified lines (convert to 0-indexed)
	let extracted_lines: Vec<&str> = source_lines[(from_range.0 - 1)..from_range.1]
		.iter()
		.map(|line| line.trim_end_matches('\r'))
		.collect();

	// Confirmation echo with SOURCE-position line ids (content hashes stay valid
	// wherever the lines land in the target).
	let extracted_content_display = format_extracted_content_smart(
		&extracted_lines,
		from_range.0, // Start line number (1-indexed)
		// Deliberate 30-line cap: this is a confirmation echo, not data transfer —
		// the model chose this exact content, the marker preserves the hidden count,
		// and the full result is on disk behind `view`.
		Some(30),
	);

	// Preserve original newline structure by checking if source content ends with newline
	// and if we're extracting the last line (for file writing purposes)
	let source_ends_with_newline = source_content.ends_with('\n');
	let extracting_last_line = from_range.1 == total_lines;

	let extracted_content =
		if extracted_lines.len() == 1 && extracting_last_line && !source_ends_with_newline {
			// Single line extraction from end of file without trailing newline
			extracted_lines[0].to_string()
		} else if extracting_last_line && source_ends_with_newline {
			// Extracting from end and source has trailing newline - preserve it
			format!("{}\n", extracted_lines.join("\n"))
		} else {
			// Normal case - join lines with newlines
			extracted_lines.join("\n")
		};

	// Handle target file - create parent directories if needed
	let append_source = resolve_path_source(&append_path, &call.workdir);
	if let Some(parent_source) = append_source.parent() {
		if let Err(e) = io_create_dir_all(&parent_source).await {
			bail!("Failed to create parent directories for '{append_path}': {e}");
		}
	}

	// extract_lines modifies the target just like text_editor/batch_edit do — take the
	// same per-file lock so concurrent writers serialize instead of clobbering each other.
	let file_lock = text_editing::acquire_file_lock(&append_source).await?;
	let _lock_guard = file_lock.lock().await;

	// Read existing target file content or create empty if doesn't exist
	let target_content = if io_exists(&append_source).await? {
		match io_read_to_string(&append_source).await {
			Ok(content) => content,
			Err(e) => {
				bail!("Failed to read target file '{append_path}': {e}");
			}
		}
	} else {
		String::new()
	};

	let target_lines: Vec<&str> = target_content.lines().collect();

	// Resolve append_line: line id → verified line number, or keep integer as-is (0/-1/N).
	let append_line: i64 = match append_line_ep {
		Endpoint::Number(n) => {
			if n < -1 {
				bail!(
					"Invalid append_line {n}: use 0 (beginning), -1 (end), N (after line N), or a line id"
				);
			}
			n
		}
		Endpoint::Id { line, hash } => {
			if target_content.is_empty() {
				bail!(
					"Cannot use a line id for append_line on an empty or non-existent target file"
				);
			}
			let line = line_hash::verify_line_id(line, &hash, &target_lines)
				.map_err(|e| anyhow::anyhow!("Invalid append_line: {e}"))?;
			line as i64
		}
	};

	let insert_after = if append_line == -1 {
		target_lines.len()
	} else {
		append_line as usize
	};
	if insert_after > target_lines.len() {
		bail!(
			"Insert position {insert_after} exceeds target file length ({} lines) in '{append_path}'",
			target_lines.len()
		);
	}
	let trailing_newline = if target_content.is_empty() || append_line == -1 {
		extracted_content.ends_with('\n')
	} else {
		target_content.ends_with('\n')
	};
	let mut edited = text_editing::EditableContent::from_raw(&target_content);
	edited.insert_lines(insert_after, &extracted_lines, trailing_newline)?;
	let final_content = edited.rendered();

	// Snapshot the target for undo_edit, then write atomically — same guarantees as
	// every other edit path (no partial file on interruption, permissions preserved).
	save_file_history(&append_source).await?;
	if let Err(e) = text_editing::atomic_write(&append_source, &final_content).await {
		bail!("Failed to write to target file '{append_path}': {e}");
	}
	delta::note_write(&append_source, &target_content, &final_content);

	// Return success result with useful information
	let lines_extracted = from_range.1 - from_range.0 + 1;
	let position_desc = match append_line {
		0 => "beginning of file".to_string(),
		-1 => "end of file".to_string(),
		n => format!("after line {n}"),
	};

	let mut out = format!(
		"Appended {lines_extracted} lines ({}-{}) from '{from_path}' to '{append_path}' at {position_desc}:\n{extracted_content_display}",
		from_range.0,
		from_range.1
	);
	let target_orig: Vec<&str> = target_content.lines().collect();
	let anchor = if append_line == -1 {
		target_orig.len()
	} else {
		append_line as usize
	};
	if let Some(note) = text_editing::shift_note(&target_orig, &[(anchor, lines_extracted as i64)])
	{
		out.push('\n');
		out.push_str(&note);
	}
	Ok(out)
}
