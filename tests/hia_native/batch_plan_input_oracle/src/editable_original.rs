// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
use anyhow::{anyhow, bail, Result};
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
