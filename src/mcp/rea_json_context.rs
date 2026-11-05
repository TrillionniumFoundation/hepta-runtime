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

//! Bounded UTF-16 context for the pinned V8 syntax-error spelling.
//! The caller validates UTF-8 independently before emitting any observation.
//! Only twenty prefix units, ten prior units and twenty error-window units are
//! retained. A window that cuts a surrogate pair is deliberately unrepresentable
//! in Rust JSON strings and leaves the existing native profile gap intact.

const PREFIX: usize = 20;
const BEFORE: usize = 10;

pub(super) struct Context {
	prefix: [u16; PREFIX],
	prefix_len: usize,
	history: [u16; BEFORE],
	history_len: usize,
	history_cursor: usize,
	window: [u16; PREFIX],
	window_len: Option<usize>,
	code_point: u32,
	remaining: u8,
}

impl Context {
	pub(super) fn new() -> Self {
		Self {
			prefix: [0; PREFIX],
			prefix_len: 0,
			history: [0; BEFORE],
			history_len: 0,
			history_cursor: 0,
			window: [0; PREFIX],
			window_len: None,
			code_point: 0,
			remaining: 0,
		}
	}

	/// Called before consuming the ASCII token that first breaks the grammar.
	pub(super) fn mark(&mut self) {
		for index in 0..self.history_len {
			self.window[index] =
				self.history[(self.history_cursor + BEFORE - self.history_len + index) % BEFORE];
		}
		self.window_len = Some(self.history_len);
	}

	pub(super) fn accept(&mut self, byte: u8) {
		if self.remaining != 0 {
			self.code_point = (self.code_point << 6) | u32::from(byte & 0x3f);
			self.remaining -= 1;
			if self.remaining == 0 {
				let point = self.code_point;
				if point <= 0xffff {
					self.unit(point as u16);
				} else {
					let point = point - 0x10000;
					self.unit(0xd800 | (point >> 10) as u16);
					self.unit(0xdc00 | (point & 0x3ff) as u16);
				}
			}
			return;
		}
		match byte {
			0..=0x7f => self.unit(u16::from(byte)),
			0xc2..=0xdf => {
				self.code_point = u32::from(byte & 0x1f);
				self.remaining = 1;
			}
			0xe0..=0xef => {
				self.code_point = u32::from(byte & 0x0f);
				self.remaining = 2;
			}
			0xf0..=0xf4 => {
				self.code_point = u32::from(byte & 0x07);
				self.remaining = 3;
			}
			_ => {}
		}
	}

	fn unit(&mut self, value: u16) {
		if self.prefix_len < PREFIX {
			self.prefix[self.prefix_len] = value;
			self.prefix_len += 1;
		}
		self.history[self.history_cursor] = value;
		self.history_cursor = (self.history_cursor + 1) % BEFORE;
		self.history_len = (self.history_len + 1).min(BEFORE);
		if let Some(count) = &mut self.window_len {
			if *count < PREFIX {
				self.window[*count] = value;
				*count += 1;
			}
		}
	}

	pub(super) fn unexpected(&self, token: u8, position: usize, length: usize) -> Option<String> {
		let token = char::from(token);
		if length <= PREFIX {
			let source = String::from_utf16(&self.prefix[..self.prefix_len]).ok()?;
			return Some(
				if matches!(
					source.as_str(),
					"undefined" | "NaN" | "Infinity" | "[object Object]"
				) {
					format!("\"{source}\" is not valid JSON")
				} else {
					format!("Unexpected token '{token}', \"{source}\" is not valid JSON")
				},
			);
		}
		let count = self.window_len?;
		let start = position.saturating_sub(BEFORE);
		let end = position.saturating_add(BEFORE).min(length);
		let needed = end - start;
		if count < needed {
			return None;
		}
		let source = String::from_utf16(&self.window[..needed]).ok()?;
		let leading = if position < BEFORE { "" } else { "..." };
		let trailing = if end == length { "" } else { "..." };
		Some(format!(
			"Unexpected token '{token}', {leading}\"{source}\"{trailing} is not valid JSON"
		))
	}
}
