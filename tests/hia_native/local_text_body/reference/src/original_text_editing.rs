// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact production items; verified by the source extraction manifest.
use super::core::save_file_history;
use super::remote::{io_exists, io_metadata, io_read_to_string, io_remove_file, io_write, PathSource};
use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::Mutex as AsyncMutex;
use crate::utils::line_hash::line_id_at;

static FILE_LOCKS: OnceLock<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>> = OnceLock::new();


fn get_file_locks() -> &'static Mutex<HashMap<String, Arc<AsyncMutex<()>>>> {
	FILE_LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}


pub fn lock_key_for(path: &Path) -> String {
	if let Ok(canon) = path.canonicalize() {
		return canon.to_string_lossy().to_string();
	}
	// File may not exist yet (create) or has been removed (delete+undo).
	// Canonicalize the parent and append the file name so the key stays
	// consistent across the file's lifetime.
	if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
		if let Ok(canon_parent) = parent.canonicalize() {
			return canon_parent.join(name).to_string_lossy().to_string();
		}
	}
	path.to_string_lossy().to_string()
}


pub fn lock_key_for_source(source: &PathSource) -> String {
	match source {
		PathSource::Local(p) => lock_key_for(p),
		PathSource::Remote { .. } => source.lock_key(),
	}
}


const LOCK_MAP_SWEEP_THRESHOLD: usize = 1024;


pub(crate) async fn acquire_file_lock(source: &PathSource) -> Result<Arc<AsyncMutex<()>>> {
	let key = lock_key_for_source(source);

	let file_lock = {
		let mut locks = get_file_locks().lock().expect("file locks poisoned");
		// Bound the map for long-lived sessions: an entry whose Arc strong_count is 1
		// is held ONLY by the map itself — we hold the map mutex, so no task can be
		// cloning it concurrently, hence nobody owns or awaits that lock. Dropping it
		// is safe; the next acquire of that path simply creates a fresh one.
		if locks.len() > LOCK_MAP_SWEEP_THRESHOLD {
			locks.retain(|_, lock| Arc::strong_count(lock) > 1);
		}
		locks
			.entry(key)
			.or_insert_with(|| Arc::new(AsyncMutex::new(())))
			.clone()
	};

	Ok(file_lock)
}


pub async fn delete_file_spec(source: &PathSource) -> Result<String> {
	if !io_exists(source).await? {
		bail!("File does not exist: {}", source.display());
	}
	let meta = io_metadata(source).await?;
	if meta.is_dir {
		bail!(
			"{} is a directory; use shell `rm -r` for directories.",
			source.display()
		);
	}

	let file_lock = acquire_file_lock(source).await?;
	let _lock_guard = file_lock.lock().await;

	// Snapshot for undo before unlinking.
	save_file_history(source).await?;

	io_remove_file(source)
		.await
		.map_err(|e| anyhow!("Failed to delete '{}': {}", source.display(), e))?;
	super::delta::forget(source);

	Ok(format!("Successfully deleted {}", source.display()))
}


fn normalize_whitespace(s: &str) -> String {
	s.lines()
		.map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
		.collect::<Vec<_>>()
		.join("\n")
}


fn find_all_positions(haystack: &str, needle: &str) -> Vec<usize> {
	let mut positions = Vec::new();
	let mut start = 0;
	while let Some(pos) = haystack[start..].find(needle) {
		positions.push(start + pos);
		start += pos + needle.len();
	}
	positions
}


fn byte_offset_to_line(content: &str, offset: usize) -> usize {
	content[..offset].matches('\n').count() + 1
}


fn similarity_ratio(a: &str, b: &str) -> f64 {
	let a_lines: Vec<&str> = a.lines().collect();
	let b_lines: Vec<&str> = b.lines().collect();
	if a_lines.is_empty() && b_lines.is_empty() {
		return 1.0;
	}
	let max_lines = a_lines.len().max(b_lines.len());
	let mut total = 0.0;
	for i in 0..max_lines {
		let la = a_lines.get(i).unwrap_or(&"");
		let lb = b_lines.get(i).unwrap_or(&"");
		total += line_similarity(la, lb);
	}
	total / max_lines as f64
}


fn line_similarity(a: &str, b: &str) -> f64 {
	let a_chars: Vec<char> = a.chars().collect();
	let b_chars: Vec<char> = b.chars().collect();
	let total = a_chars.len() + b_chars.len();
	if total == 0 {
		return 1.0;
	}
	let lcs_len = lcs_length(&a_chars, &b_chars);
	(2.0 * lcs_len as f64) / total as f64
}


fn lcs_length(a: &[char], b: &[char]) -> usize {
	// Cap to avoid quadratic blowup on very large inputs
	const MAX_CHARS: usize = 2000;
	let a = if a.len() > MAX_CHARS {
		&a[..MAX_CHARS]
	} else {
		a
	};
	let b = if b.len() > MAX_CHARS {
		&b[..MAX_CHARS]
	} else {
		b
	};

	let mut prev = vec![0usize; b.len() + 1];
	let mut curr = vec![0usize; b.len() + 1];
	for &ac in a {
		for (j, &bc) in b.iter().enumerate() {
			curr[j + 1] = if ac == bc {
				prev[j] + 1
			} else {
				prev[j + 1].max(curr[j])
			};
		}
		std::mem::swap(&mut prev, &mut curr);
		curr.iter_mut().for_each(|v| *v = 0);
	}
	*prev.last().unwrap_or(&0)
}


fn diagnose_mismatch(expected: &str, actual: &str) -> String {
	let exp_norm = normalize_whitespace(expected);
	let act_norm = normalize_whitespace(actual);
	if exp_norm == act_norm {
		return "whitespace/indentation mismatch only".to_string();
	}
	// Check if it's just leading whitespace per line
	let exp_trimmed: Vec<&str> = expected.lines().map(|l| l.trim()).collect();
	let act_trimmed: Vec<&str> = actual.lines().map(|l| l.trim()).collect();
	if exp_trimmed == act_trimmed {
		return "indentation mismatch only".to_string();
	}
	"content differs".to_string()
}


fn find_closest_matches(content: &str, needle: &str, top_n: usize) -> Vec<(usize, String, f64)> {
	let content_lines: Vec<&str> = content.lines().collect();
	let needle_lines: Vec<&str> = needle.lines().collect();
	let needle_count = needle_lines.len().max(1);

	if content_lines.len() < needle_count {
		return Vec::new();
	}

	let mut candidates: Vec<(usize, String, f64)> = Vec::new();

	for start in 0..=(content_lines.len() - needle_count) {
		let window: String = content_lines[start..start + needle_count].join("\n");
		let sim = similarity_ratio(needle, &window);
		// Only consider windows with at least 40% similarity
		if sim >= 0.4 {
			candidates.push((start + 1, window, sim));
		}
	}

	// Sort by similarity descending
	candidates.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
	candidates.truncate(top_n);
	candidates
}


fn detect_indent(text: &str) -> &str {
	for line in text.lines() {
		if !line.trim().is_empty() {
			let trimmed = line.trim_start();
			return &line[..line.len() - trimmed.len()];
		}
	}
	""
}


fn adjust_indentation(new_text: &str, provided_old: &str, actual_old: &str) -> String {
	let provided_indent = detect_indent(provided_old);
	let actual_indent = detect_indent(actual_old);

	if provided_indent == actual_indent {
		return new_text.to_string();
	}

	// Determine if we're using tabs or spaces from the actual file
	let provided_len = provided_indent.len();

	new_text
		.lines()
		.map(|line| {
			if line.trim().is_empty() {
				return line.to_string();
			}
			// Strip the provided indent prefix if present, then prepend actual indent
			if provided_len > 0 && line.starts_with(provided_indent) {
				format!("{}{}", actual_indent, &line[provided_len..])
			} else {
				// Line doesn't start with expected indent — prepend the delta
				let line_indent_len = line.len() - line.trim_start().len();
				if line_indent_len >= provided_len {
					// Extra indent beyond base — preserve the extra part
					format!("{}{}", actual_indent, &line[provided_len..])
				} else {
					// Less indent than base — just prepend actual
					format!("{}{}", actual_indent, line.trim_start())
				}
			}
		})
		.collect::<Vec<_>>()
		.join("\n")
}


fn build_str_replace_diff(
	orig_lines: &[&str],
	new_lines: &[&str],
	start: usize,
	old_line_count: usize,
	new_line_count: usize,
	as_sent: bool,
) -> String {
	const CONTEXT: usize = 2;
	let mut diff: Vec<String> = Vec::new();

	// Context before (identical in both files — render with final-file ids)
	let ctx_before_start = start.saturating_sub(CONTEXT);
	if ctx_before_start > 0 {
		diff.push("...".to_string());
	}
	for i in ctx_before_start..start {
		diff.push(format!("{}|{}", line_id_at(new_lines, i + 1), new_lines[i]));
	}

	// Removed lines collapse to their old id range — the model supplied them.
	if old_line_count > 0 {
		diff.push(super::delta::removed_marker(
			orig_lines,
			start,
			start + old_line_count - 1,
		));
	}

	// Added lines — at their final positions with fresh ids, rendered from the final file:
	// a match starting or ending mid-line rewrites whole lines, and the id belongs to the
	// whole line, not to the sent fragment. The block starts at `start + 1` (1-indexed).
	let added = &new_lines[start..start + new_line_count];
	if as_sent {
		push_added_lines(&mut diff, start + 1, added);
	} else {
		for (i, line) in added.iter().enumerate() {
			diff.push(format!(
				"+{}|{}",
				line_id_at(new_lines, start + 1 + i),
				line
			));
		}
	}

	// Context after: read from new_lines (already has the replacement applied)
	let new_after_start = start + new_line_count; // 0-indexed in new_lines
	let ctx_after_end = (new_after_start + CONTEXT).min(new_lines.len());
	for i in new_after_start..ctx_after_end {
		diff.push(format!("{}|{}", line_id_at(new_lines, i + 1), new_lines[i]));
	}
	if ctx_after_end < new_lines.len() {
		diff.push("...".to_string());
	}

	let delta = new_lines.len() as i64 - orig_lines.len() as i64;
	diff.extend(shift_note(orig_lines, &[(start + old_line_count, delta)]));

	diff.join("\n")
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


pub async fn atomic_write(source: &PathSource, content: &str) -> Result<()> {
	match source {
		PathSource::Local(path) => {
			let parent_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
			let tmp_path = parent_dir.join(format!(
				".octofs_tmp_{}.tmp",
				path.file_name().unwrap_or_default().to_string_lossy()
			));

			// Snapshot existing permissions before we overwrite, so we can re-apply them to the temp
			// file before the rename swaps inodes. None means the target didn't exist yet.
			let original_perms = match tokio::fs::metadata(path).await {
				Ok(meta) => Some(meta.permissions()),
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
				Err(e) => {
					return Err(anyhow!(
						"Failed to read metadata for '{}': {}",
						path.display(),
						e
					))
				}
			};

			tokio::fs::write(&tmp_path, content).await.map_err(|e| {
				anyhow!("Failed to write temp file for '{}': {}", path.display(), e)
			})?;

			if let Some(perms) = original_perms {
				if let Err(e) = tokio::fs::set_permissions(&tmp_path, perms).await {
					let _ = tokio::fs::remove_file(&tmp_path).await;
					return Err(anyhow!(
						"Failed to preserve permissions on '{}': {}",
						path.display(),
						e
					));
				}
			}

			if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
				// Clean up temp file on rename failure
				let _ = tokio::fs::remove_file(&tmp_path).await;
				return Err(anyhow!(
					"Failed to atomically replace '{}': {}",
					path.display(),
					e
				));
			}
			Ok(())
		}
		PathSource::Remote { .. } => {
			io_write(source, content.as_bytes()).await?;
			Ok(())
		}
	}
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


fn incoming_content_lines(content: &str) -> Vec<&str> {
	content
		.lines()
		.map(|line| line.trim_end_matches('\r'))
		.collect()
}


fn sanitize_incoming_content(content: &str) -> String {
	content
		.split('\n')
		.map(|line| line.trim_end_matches('\r'))
		.collect::<Vec<_>>()
		.join("\n")
}


fn unescape_literals(s: &str) -> String {
	s.replace("\\n", "\n")
		.replace("\\t", "\t")
		.replace("\\r", "\r")
}


async fn apply_unique_replacement(
	source: &PathSource,
	original: &EditableContent,
	content: &str,
	old_text: &str,
	new_text: &str,
) -> Result<String> {
	let orig_lines: Vec<&str> = content.lines().collect();
	let old_line_count = old_text.lines().count();
	// Find the 0-indexed start line of the match
	let match_offset = content.find(old_text).unwrap_or(0);
	let match_start = byte_offset_to_line(content, match_offset) - 1;

	save_file_history(source).await?;
	let mut edited = original.clone();
	edited.replace_normalized_range(match_offset, match_offset + old_text.len(), new_text)?;
	edited.preserve_trailing_newline();
	let new_content = edited.normalized();
	atomic_write(source, &edited.rendered()).await?;
	super::delta::note_write(source, content, &new_content);

	let new_lines: Vec<&str> = new_content.lines().collect();
	Ok(build_str_replace_diff(
		&orig_lines,
		&new_lines,
		match_start,
		old_line_count,
		new_text.lines().count(),
		true,
	))
}


async fn apply_replace_all(
	source: &PathSource,
	original: &EditableContent,
	content: &str,
	old_text: &str,
	new_text: &str,
) -> Result<String> {
	let positions = find_all_positions(content, old_text);
	save_file_history(source).await?;
	let mut edited = original.clone();
	for &position in positions.iter().rev() {
		edited.replace_normalized_range(position, position + old_text.len(), new_text)?;
	}
	edited.preserve_trailing_newline();
	let new_content = edited.normalized();
	atomic_write(source, &edited.rendered()).await?;
	super::delta::note_write(source, content, &new_content);

	let new_lines: Vec<&str> = new_content.lines().collect();
	// Each occurrence shifts later ones by the length delta; map original offsets
	// to final-file offsets to name the landing line of every replacement.
	let delta = new_text.len() as i64 - old_text.len() as i64;
	let sites: Vec<String> = positions
		.iter()
		.enumerate()
		.map(|(i, &pos)| {
			let new_pos = (pos as i64 + delta * i as i64).max(0) as usize;
			let line = byte_offset_to_line(&new_content, new_pos.min(new_content.len()))
				.min(new_lines.len().max(1));
			if new_lines.is_empty() {
				format!("line {line}")
			} else {
				line_id_at(&new_lines, line)
			}
		})
		.collect();

	let orig_lines: Vec<&str> = content.lines().collect();
	let line_delta = new_text.matches('\n').count() as i64 - old_text.matches('\n').count() as i64;
	let regions: Vec<(usize, i64)> = positions
		.iter()
		.map(|&pos| {
			// Last line the match touches: a trailing newline belongs to that line,
			// not the next one.
			let end = pos + old_text.trim_end_matches('\n').len();
			(byte_offset_to_line(content, end), line_delta)
		})
		.collect();

	let mut out = format!(
		"Replaced {} occurrences. Replacements start at: {}",
		positions.len(),
		sites.join(", ")
	);
	if let Some(note) = shift_note(&orig_lines, &regions) {
		out.push('\n');
		out.push_str(&note);
	}
	Ok(out)
}


pub async fn str_replace_spec(
	source: &PathSource,
	old_text: &str,
	new_text: &str,
	replace_all: bool,
) -> Result<String> {
	if !io_exists(source).await? {
		bail!("File not found");
	}

	// Acquire file lock to prevent concurrent writes
	let file_lock = acquire_file_lock(source).await?;
	let _lock_guard = file_lock.lock().await;

	// Read the file content. Content-addressed matching is its own staleness check:
	// old_text either still matches uniquely or the error below explains why not.
	let raw = io_read_to_string(source)
		.await
		.map_err(|e| anyhow!("Permission denied. Cannot read file: {}", e))?;

	let original = EditableContent::from_raw(&raw);
	let content = original.normalized();
	let old_text = old_text.replace("\r\n", "\n");
	let new_text = sanitize_incoming_content(new_text);
	let old_text = old_text.as_str();
	let new_text = new_text.as_str();

	// === Stage 1: Exact match ===
	let occurrences = content.matches(old_text).count();

	if replace_all && occurrences >= 1 {
		return apply_replace_all(source, &original, &content, old_text, new_text).await;
	}

	if occurrences == 1 {
		return apply_unique_replacement(source, &original, &content, old_text, new_text).await;
	}

	if occurrences > 1 {
		// Multiple exact matches — show locations with line ids so the model can
		// switch to `batch_edit` without another view.
		let positions = find_all_positions(&content, old_text);
		let file_lines: Vec<&str> = content.lines().collect();
		let locations: Vec<String> = positions
			.iter()
			.enumerate()
			.map(|(i, &offset)| {
				let line = byte_offset_to_line(&content, offset);
				format!("  {}. {}", i + 1, line_id_at(&file_lines, line))
			})
			.collect();

		bail!(
			"Found {} matches at:\n{}\nAdd context to make old_text unique, pass replace_all: true, or use batch_edit with one of these ids.",
			occurrences,
			locations.join("\n")
		);
	}

	// === Stage 1.5: Escaped-literal recovery ===
	// A double-escaped old_text (JSON "\\n" arriving as backslash-n) never matches.
	// If interpreting the escapes yields a match, use it instead of bouncing an
	// error back — new_text gets the same interpretation for consistency.
	if old_text.contains("\\n") || old_text.contains("\\t") || old_text.contains("\\r") {
		let un_old = unescape_literals(old_text);
		if un_old != old_text {
			let un_occurrences = content.matches(&un_old).count();
			let un_new = sanitize_incoming_content(&unescape_literals(new_text));
			if replace_all && un_occurrences >= 1 {
				crate::mcp::request_ctx::push_hint(
					"Literal \\n/\\t in old_text were treated as real newlines/tabs.",
				);
				return apply_replace_all(source, &original, &content, &un_old, &un_new).await;
			}
			if un_occurrences == 1 {
				crate::mcp::request_ctx::push_hint(
					"Literal \\n/\\t in old_text were treated as real newlines/tabs.",
				);
				return apply_unique_replacement(source, &original, &content, &un_old, &un_new)
					.await;
			}
		}
	}

	// === Stage 2: Whitespace-normalized fuzzy match ===
	let norm_old = normalize_whitespace(old_text);
	let norm_content = normalize_whitespace(&content);
	let norm_occurrences = norm_content.matches(&norm_old).count();

	if norm_occurrences == 1 {
		// Found exactly one whitespace-normalized match — map back to original content
		// We need to find the actual text in the original content that corresponds
		let content_lines: Vec<&str> = content.lines().collect();
		let old_lines: Vec<&str> = old_text.lines().collect();
		let old_line_count = old_lines.len();

		let mut match_start = None;
		for start in 0..=content_lines.len().saturating_sub(old_line_count) {
			let window: Vec<&str> = content_lines[start..start + old_line_count].to_vec();
			let window_norm: Vec<String> = window
				.iter()
				.map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
				.collect();
			let old_norm: Vec<String> = old_lines
				.iter()
				.map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
				.collect();
			if window_norm == old_norm {
				match_start = Some(start);
				break;
			}
		}

		if let Some(start) = match_start {
			let actual_old = content_lines[start..start + old_line_count].join("\n");
			let adjusted_new = adjust_indentation(new_text, old_text, &actual_old);
			let match_offset = content.find(&actual_old).unwrap_or(0);

			save_file_history(source).await?;
			let mut edited = original.clone();
			edited.replace_normalized_range(
				match_offset,
				match_offset + actual_old.len(),
				&adjusted_new,
			)?;
			edited.preserve_trailing_newline();
			let new_content = edited.normalized();
			atomic_write(source, &edited.rendered()).await?;
			super::delta::note_write(source, &content, &new_content);

			crate::mcp::request_ctx::push_hint(
				"Matched with whitespace normalized; indentation adjusted to the file.",
			);

			let new_lines: Vec<&str> = new_content.lines().collect();
			let diff = build_str_replace_diff(
				&content_lines,
				&new_lines,
				start,
				old_line_count,
				adjusted_new.lines().count(),
				false,
			);
			return Ok(diff);
		}
	}

	// === Stage 3: No match — provide rich diagnostics ===
	let candidates = find_closest_matches(&content, old_text, 3);

	let mut msg = String::from("No exact match found (pass raw text, no \\n/\\t escapes).\n");

	if candidates.is_empty() {
		msg.push_str("Nothing similar in the file.");
	} else {
		let diag_lines: Vec<&str> = content.lines().collect();

		msg.push_str("Closest matches:\n");
		let old_line_count = old_text.lines().count();
		for (i, (line_num, window, sim)) in candidates.iter().enumerate() {
			let diagnosis = diagnose_mismatch(old_text, window);
			let end_line = line_num + old_line_count - 1;
			msg.push_str(&format!(
				"\n  {}. {} .. {} ({:.0}% similar, {})\n",
				i + 1,
				line_id_at(&diag_lines, *line_num),
				line_id_at(&diag_lines, end_line),
				sim * 100.0,
				diagnosis
			));
			// Show first 3 lines of the candidate as preview
			for (j, line) in window.lines().take(3).enumerate() {
				msg.push_str(&format!(
					"     {}|{}\n",
					line_id_at(&diag_lines, line_num + j),
					line
				));
			}
			if old_line_count > 3 {
				msg.push_str(&format!("     ... ({} more lines)\n", old_line_count - 3));
			}
		}
		msg.push_str("\nFix old_text, or use batch_edit with these ids.");
	}

	bail!("{}", msg);
}


const ECHO_WHOLE_MAX: usize = 3;


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


