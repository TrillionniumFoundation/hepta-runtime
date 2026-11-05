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

//! EOF diagnostics for the frozen small-file JSON.parse profile.
//!
//! This observer recognizes an unfinished, otherwise grammatical JSON prefix.
//! It neither parses values nor accepts a document. The owned reader validates
//! UTF-8, enforces its budgets, and must observe physical EOF; the value parser
//! must independently report EOF before any diagnostic here can become public.
//! Any non-EOF syntax error disables the observer. No input bytes or values are
//! retained, and the fixed stack covers the reader's existing depth profile.

#[derive(Clone, Copy)]
enum Frame {
	RootValue,
	RootEnd,
	ArrayFirst,
	ArrayValue,
	ArrayEnd,
	ObjectFirst,
	ObjectKey,
	ObjectColon,
	ObjectValue,
	ObjectEnd,
}

#[derive(Clone, Copy)]
enum Escape {
	None,
	Backslash,
	Unicode(u8),
}

#[derive(Clone, Copy)]
enum Number {
	Minus,
	Zero,
	Integer,
	Point,
	Fraction,
	Exponent,
	ExponentSign,
	ExponentDigits,
}

#[derive(Clone, Copy)]
enum Token {
	None,
	String { key: bool, escape: Escape },
	Literal { remaining: &'static [u8] },
	Number(Number),
}

pub(super) struct Tracker {
	// Root plus 121 container prefixes: the owner rejects value depth >120.
	frames: [Frame; 122],
	depth: usize,
	token: Token,
	valid_prefix: bool,
	position: usize,
	line: usize,
	column: usize,
	previous_cr: bool,
}

impl Tracker {
	pub(super) fn new() -> Self {
		Self {
			frames: [Frame::RootValue; 122],
			depth: 1,
			token: Token::None,
			valid_prefix: true,
			position: 0,
			line: 1,
			column: 1,
			previous_cr: false,
		}
	}

	/// The caller's UTF-8 validator runs before this observer for each chunk.
	/// A partial code point cannot yield a diagnostic until the caller validates
	/// its continuation and observes EOF. UTF-8 continuation bytes add no units.
	pub(super) fn accept(&mut self, bytes: &[u8]) {
		for &byte in bytes {
			if !self.valid_prefix {
				break;
			}
			let units = match byte {
				0x80..=0xbf => 0,
				0xf0..=0xf4 => 2,
				_ => 1,
			};
			self.position += units;
			if byte == b'\r' {
				self.line += 1;
				self.column = 1;
			} else if byte == b'\n' {
				if !self.previous_cr {
					self.line += 1;
				}
				self.column = 1;
			} else {
				self.column += units;
			}
			self.previous_cr = byte == b'\r';
			self.accept_byte(byte);
		}
	}

	fn accept_byte(&mut self, byte: u8) {
		match self.token {
			Token::None => self.accept_structure(byte),
			Token::String { key, escape } => self.accept_string(byte, key, escape),
			Token::Literal { remaining } => {
				if remaining[0] != byte {
					self.valid_prefix = false;
				} else if remaining.len() == 1 {
					self.token = Token::None;
					self.complete_value();
				} else {
					self.token = Token::Literal {
						remaining: &remaining[1..],
					};
				}
			}
			Token::Number(number) => self.accept_number(byte, number),
		}
	}

	fn accept_structure(&mut self, byte: u8) {
		if matches!(byte, b' ' | b'\n' | b'\r' | b'\t') {
			return;
		}
		match (self.frames[self.depth - 1], byte) {
			(Frame::ArrayFirst | Frame::ArrayEnd, b']')
			| (Frame::ObjectFirst | Frame::ObjectEnd, b'}') => {
				self.depth -= 1;
				self.complete_value();
			}
			(Frame::ArrayEnd, b',') => self.frames[self.depth - 1] = Frame::ArrayValue,
			(Frame::ObjectEnd, b',') => self.frames[self.depth - 1] = Frame::ObjectKey,
			(Frame::ObjectFirst | Frame::ObjectKey, b'"') => {
				self.token = Token::String {
					key: true,
					escape: Escape::None,
				};
			}
			(Frame::ObjectColon, b':') => self.frames[self.depth - 1] = Frame::ObjectValue,
			(Frame::RootValue | Frame::ArrayFirst | Frame::ArrayValue | Frame::ObjectValue, _) => {
				self.start_value(byte)
			}
			_ => self.valid_prefix = false,
		}
	}

	fn start_value(&mut self, byte: u8) {
		match byte {
			b'[' => self.push(Frame::ArrayFirst),
			b'{' => self.push(Frame::ObjectFirst),
			b'"' => {
				self.token = Token::String {
					key: false,
					escape: Escape::None,
				};
			}
			b't' => self.token = Token::Literal { remaining: b"rue" },
			b'f' => self.token = Token::Literal { remaining: b"alse" },
			b'n' => self.token = Token::Literal { remaining: b"ull" },
			b'-' => self.token = Token::Number(Number::Minus),
			b'0' => self.token = Token::Number(Number::Zero),
			b'1'..=b'9' => self.token = Token::Number(Number::Integer),
			_ => self.valid_prefix = false,
		}
	}

	fn push(&mut self, frame: Frame) {
		if self.depth == self.frames.len() {
			self.valid_prefix = false;
		} else {
			self.frames[self.depth] = frame;
			self.depth += 1;
		}
	}

	fn complete_value(&mut self) {
		let frame = &mut self.frames[self.depth - 1];
		*frame = match *frame {
			Frame::RootValue => Frame::RootEnd,
			Frame::ArrayFirst | Frame::ArrayValue => Frame::ArrayEnd,
			Frame::ObjectValue => Frame::ObjectEnd,
			_ => {
				self.valid_prefix = false;
				return;
			}
		};
	}

	fn accept_string(&mut self, byte: u8, key: bool, escape: Escape) {
		let next = match (escape, byte) {
			(Escape::None, b'"') => {
				self.token = Token::None;
				if key {
					self.frames[self.depth - 1] = Frame::ObjectColon;
				} else {
					self.complete_value();
				}
				return;
			}
			(Escape::None, b'\\') => Escape::Backslash,
			(Escape::None, 0..=0x1f) => {
				self.valid_prefix = false;
				return;
			}
			(Escape::None, _) => Escape::None,
			(Escape::Backslash, b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
				Escape::None
			}
			(Escape::Backslash, b'u') => Escape::Unicode(4),
			(Escape::Unicode(remaining), _) if byte.is_ascii_hexdigit() => {
				if remaining == 1 {
					Escape::None
				} else {
					Escape::Unicode(remaining - 1)
				}
			}
			_ => {
				self.valid_prefix = false;
				return;
			}
		};
		self.token = Token::String { key, escape: next };
	}

	fn accept_number(&mut self, byte: u8, number: Number) {
		use Number::*;
		let next = match (number, byte) {
			(Minus, b'0') => Zero,
			(Minus, b'1'..=b'9') | (Integer, b'0'..=b'9') => Integer,
			(Zero | Integer, b'.') => Point,
			(Zero | Integer | Fraction, b'e' | b'E') => Exponent,
			(Point | Fraction, b'0'..=b'9') => Fraction,
			(Exponent, b'+' | b'-') => ExponentSign,
			(Exponent | ExponentSign | ExponentDigits, b'0'..=b'9') => ExponentDigits,
			(Zero, b'0'..=b'9') | (Minus | Point | Exponent | ExponentSign, _) => {
				self.valid_prefix = false;
				return;
			}
			_ => {
				self.token = Token::None;
				self.complete_value();
				// This byte terminates the number; it still belongs to the
				// surrounding grammar. Count its source position only once.
				self.accept_structure(byte);
				return;
			}
		};
		self.token = Token::Number(next);
	}

	pub(super) fn finish(mut self) -> Option<String> {
		if !self.valid_prefix {
			return None;
		}
		let message = match self.token {
			Token::Literal { .. }
			| Token::String {
				escape: Escape::Backslash,
				..
			} => return Some("Unexpected end of JSON input".into()),
			Token::String {
				escape: Escape::None,
				..
			} => "Unterminated string",
			Token::String {
				escape: Escape::Unicode(_),
				..
			} => "Bad Unicode escape",
			Token::Number(Number::Minus) => "No number after minus sign",
			Token::Number(Number::Point) => "Unterminated fractional number",
			Token::Number(Number::Exponent | Number::ExponentSign) => {
				"Exponent part is missing a number"
			}
			Token::None | Token::Number(_) => {
				if matches!(self.token, Token::Number(_)) {
					self.complete_value();
				}
				match self.frames[self.depth - 1] {
					Frame::RootValue
					| Frame::ArrayFirst
					| Frame::ArrayValue
					| Frame::ObjectValue => {
						return Some("Unexpected end of JSON input".into());
					}
					Frame::RootEnd => return None,
					Frame::ArrayEnd => "Expected ',' or ']' after array element",
					Frame::ObjectFirst => "Expected property name or '}'",
					Frame::ObjectKey => "Expected double-quoted property name",
					Frame::ObjectColon => "Expected ':' after property name",
					Frame::ObjectEnd => "Expected ',' or '}' after property value",
				}
			}
		};
		Some(format!(
			"{message} in JSON at position {} (line {} column {})",
			self.position, self.line, self.column
		))
	}
}
