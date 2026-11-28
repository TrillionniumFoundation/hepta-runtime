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

// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Test-only typed transport, appended to the complete unchanged original owner.
use std::io::{self, BufRead, Write};
fn word(raw: &[u8], at: usize) -> u64 { u64::from_le_bytes(raw[at..at+8].try_into().unwrap()) }
fn unhex(text: &str) -> Vec<u8> { (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at+2],16).unwrap()).collect() }
fn hex(raw: &[u8]) -> String { raw.iter().map(|v| format!("{v:02x}")).collect() }
fn apply(raw: &[u8]) -> Vec<u8> {
    assert_eq!(&raw[..8], b"HEDIT001");
    let mode = word(raw,8); let rawlen=word(raw,16) as usize; let count=word(raw,24);
    let mut owner = EditableContent::from_raw(std::str::from_utf8(&raw[48..48+rawlen]).unwrap());
    let mut at=48+rawlen; let mut done=0u64; let mut message=String::new();
    for _ in 0..count {
        let op=word(raw,at);let a=word(raw,at+8) as usize;let b=word(raw,at+16);let size=word(raw,at+24) as usize;
        let text=std::str::from_utf8(&raw[at+32..at+32+size]).unwrap();
        let result = match op {
            1 => owner.insert_lines(a,&incoming_content_lines(text),b!=0),
            2 => owner.replace_normalized_range(a,b as usize,text),
            3 => {owner.preserve_trailing_newline();Ok(())},
            _ => panic!("bad operation")
        };
        match result { Ok(()) => done+=1, Err(error) => {message=error.to_string();break;} }
        at+=32+size;
    }
    let normalized=owner.normalized();let rendered=owner.rendered();
    let body=if mode==0 {rendered.as_bytes()} else {normalized.as_bytes()};
    let mut out=b"HEDRES01".to_vec();
    for value in [(!message.is_empty()) as u64,done,owner.dominant_ending.len() as u64,owner.had_trailing_newline as u64,
        owner.lines.len() as u64,normalized.len() as u64,rendered.len() as u64,body.len() as u64,message.len() as u64] {
        out.extend(value.to_le_bytes());
    }
    out.extend(body);out.extend(message.as_bytes());out
}
fn main() {
    let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {writeln!(&mut out,"OK {}",hex(&apply(&unhex(&line.unwrap())))).unwrap();}
}
