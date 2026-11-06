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

//! Bounded UTF-16 line ranges for retained source-map text. Positions are offsets
//! in the decoded JavaScript string, including positions inside an astral pair.

use anyhow::{bail, Context, Result};

pub(super) const MAX_EMBEDDED_LINES: usize = 1_000_000;

#[derive(Clone, Copy)]
struct Line {
	start: u32,
	length: u32,
}

#[derive(Clone)]
pub(super) struct LineIndex {
	lines: Vec<Line>,
	utf16_units: u32,
}

impl LineIndex {
	pub(super) fn from_text(text: &str, indexed_lines: &mut usize) -> Result<Self> {
		let remaining = MAX_EMBEDDED_LINES
			.checked_sub(*indexed_lines)
			.context("source-map embedded line budget is invalid")?;
		let mut count = 1_usize;
		let mut previous_cr = false;
		if count > remaining {
			bail!("source-map embedded content exceeds 1000000 indexed lines");
		}
		// Count before allocation: the whole map shares this budget, including
		// empty sources and leaves of nested indexed maps.
		for character in text.chars() {
			if matches!(character, '\r' | '\n' | '\u{2028}' | '\u{2029}')
				&& !(character == '\n' && previous_cr)
			{
				count += 1;
				if count > remaining {
					bail!("source-map embedded content exceeds 1000000 indexed lines");
				}
			}
			previous_cr = character == '\r';
		}
		let mut lines = Vec::new();
		lines
			.try_reserve_exact(count)
			.context("source-map embedded line index allocation failed")?;
		let mut characters = text.chars().peekable();
		let mut start = 0_u32;
		let mut offset = 0_u32;
		while let Some(character) = characters.next() {
			if matches!(character, '\r' | '\n' | '\u{2028}' | '\u{2029}') {
				lines.push(Line {
					start,
					length: offset - start,
				});
				let width = if character == '\r' && characters.peek() == Some(&'\n') {
					characters.next();
					2
				} else {
					1
				};
				offset = offset
					.checked_add(width)
					.context("source-map embedded UTF-16 offset exceeds 32 bits")?;
				start = offset;
			} else {
				offset = offset
					.checked_add(character.len_utf16() as u32)
					.context("source-map embedded UTF-16 offset exceeds 32 bits")?;
			}
		}
		lines.push(Line {
			start,
			length: offset - start,
		});
		*indexed_lines += count;
		Ok(Self {
			lines,
			utf16_units: offset,
		})
	}

	/// Internal mapping lines are zero-based; the public report stays one-based.
	pub(super) fn offset(&self, line: u32, column: u32) -> Option<u32> {
		let selected = self.lines.get(usize::try_from(line).ok()?)?;
		(column <= selected.length).then(|| selected.start + column)
	}

	pub(super) fn line_count(&self) -> usize {
		self.lines.len()
	}

	pub(super) fn utf16_units(&self) -> u32 {
		self.utf16_units
	}
}

#[cfg(test)]
#[path = "rea_source_map_content_tests.rs"]
mod tests;
