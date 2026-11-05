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

//! Bounded syntax diagnostics for the frozen Node 22 small-file JSON profile.
//!
//! The observer never accepts a value. A separate value parser must reject the
//! document, while its owner independently checks UTF-8, budgets and physical
//! EOF. The first grammar failure retains at most twenty UTF-16 context units;
//! complete documents, values and arbitrary token contents are never buffered.
//! Error wording and context windows follow Node v22.23.4's V8 JSON parser.
//! A diagnostic containing an unpaired UTF-16 unit stays an explicit profile
//! gap: converting it to U+FFFD would change the original public observation.

const CONTEXT: usize = 10;
const SHORT: usize = CONTEXT * 2;

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

#[derive(Clone, Copy)]
enum ErrorKind {
	Positioned(&'static str),
	Unexpected(u16),
}

struct FirstError {
	kind: ErrorKind,
	position: usize,
	line: usize,
	column: usize,
	context: [u16; SHORT],
	context_len: usize,
	context_limit: usize,
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
	first: [u16; SHORT],
	first_len: usize,
	previous: [u16; CONTEXT],
	previous_len: usize,
	error: Option<FirstError>,
	utf8_value: u32,
	utf8_remaining: u8,
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
			first: [0; SHORT],
			first_len: 0,
			previous: [0; CONTEXT],
			previous_len: 0,
			error: None,
			utf8_value: 0,
			utf8_remaining: 0,
		}
	}

	/// Each chunk has already passed the owner's incremental UTF-8 validator.
	/// Decoding here preserves code-unit positions and context across any byte
	/// split, including one in the middle of a supplementary character.
	pub(super) fn accept(&mut self, bytes: &[u8]) {
		for &byte in bytes {
			if !self.valid_prefix {
				return;
			}
			if self.utf8_remaining > 0 {
				if !(0x80..=0xbf).contains(&byte) {
					self.valid_prefix = false;
					return;
				}
				self.utf8_value = (self.utf8_value << 6) | u32::from(byte & 0x3f);
				self.utf8_remaining -= 1;
				if self.utf8_remaining == 0 {
					if let Some(character) = char::from_u32(self.utf8_value) {
						self.accept_character(character);
					} else {
						self.valid_prefix = false;
					}
				}
			} else {
				match byte {
					0..=0x7f => self.accept_character(char::from(byte)),
					0xc2..=0xdf => {
						self.utf8_value = u32::from(byte & 0x1f);
						self.utf8_remaining = 1;
					}
					0xe0..=0xef => {
						self.utf8_value = u32::from(byte & 0x0f);
						self.utf8_remaining = 2;
					}
					0xf0..=0xf4 => {
						self.utf8_value = u32::from(byte & 0x07);
						self.utf8_remaining = 3;
					}
					_ => self.valid_prefix = false,
				}
			}
		}
	}

	fn accept_character(&mut self, character: char) {
		// Positions refer to the start of the offending code unit. In
		// particular, a rejected CR/LF has not yet advanced its own line.
		if self.error.is_none() {
			self.accept_grammar(character);
		}
		let mut encoded = [0_u16; 2];
		let units = character.encode_utf16(&mut encoded);
		for &unit in units.iter() {
			if self.first_len < SHORT {
				self.first[self.first_len] = unit;
				self.first_len += 1;
			}
			if let Some(error) = &mut self.error {
				if error.context_len < error.context_limit {
					error.context[error.context_len] = unit;
					error.context_len += 1;
				}
			} else if self.previous_len < CONTEXT {
				self.previous[self.previous_len] = unit;
				self.previous_len += 1;
			} else {
				self.previous.copy_within(1.., 0);
				self.previous[CONTEXT - 1] = unit;
			}
		}
		self.position += units.len();
		if character == '\r' {
			self.line += 1;
			self.column = 1;
		} else if character == '\n' {
			if !self.previous_cr {
				self.line += 1;
			}
			self.column = 1;
		} else {
			self.column += units.len();
		}
		self.previous_cr = character == '\r';
	}

	fn reject(&mut self, kind: ErrorKind) {
		let mut context = [0_u16; SHORT];
		context[..self.previous_len].copy_from_slice(&self.previous[..self.previous_len]);
		self.error = Some(FirstError {
			kind,
			position: self.position,
			line: self.line,
			column: self.column,
			context,
			context_len: self.previous_len,
			context_limit: self.previous_len + CONTEXT,
		});
	}

	fn unexpected(&mut self, character: char) {
		let kind = match character {
			'0'..='9' | '-' => ErrorKind::Positioned("Unexpected number in JSON"),
			'"' => ErrorKind::Positioned("Unexpected string in JSON"),
			_ => {
				let mut encoded = [0_u16; 2];
				ErrorKind::Unexpected(character.encode_utf16(&mut encoded)[0])
			}
		};
		self.reject(kind);
	}

	fn accept_grammar(&mut self, character: char) {
		match self.token {
			Token::None => self.accept_structure(character),
			Token::String { key, escape } => self.accept_string(character, key, escape),
			Token::Literal { remaining } => {
				if u32::from(remaining[0]) != u32::from(character) {
					self.unexpected(character);
				} else if remaining.len() == 1 {
					self.token = Token::None;
					self.complete_value();
				} else {
					self.token = Token::Literal {
						remaining: &remaining[1..],
					};
				}
			}
			Token::Number(number) => self.accept_number(character, number),
		}
	}

	fn accept_structure(&mut self, character: char) {
		if matches!(character, ' ' | '\n' | '\r' | '\t') {
			return;
		}
		let message = match (self.frames[self.depth - 1], character) {
			(Frame::ArrayFirst | Frame::ArrayEnd, ']')
			| (Frame::ObjectFirst | Frame::ObjectEnd, '}') => {
				self.depth -= 1;
				self.complete_value();
				return;
			}
			(Frame::ArrayEnd, ',') => {
				self.frames[self.depth - 1] = Frame::ArrayValue;
				return;
			}
			(Frame::ObjectEnd, ',') => {
				self.frames[self.depth - 1] = Frame::ObjectKey;
				return;
			}
			(Frame::ObjectFirst | Frame::ObjectKey, '"') => {
				self.token = Token::String {
					key: true,
					escape: Escape::None,
				};
				return;
			}
			(Frame::ObjectColon, ':') => {
				self.frames[self.depth - 1] = Frame::ObjectValue;
				return;
			}
			(Frame::RootValue | Frame::ArrayFirst | Frame::ArrayValue | Frame::ObjectValue, _) => {
				self.start_value(character);
				return;
			}
			(Frame::RootEnd, _) => "Unexpected non-whitespace character after JSON",
			(Frame::ArrayEnd, _) => "Expected ',' or ']' after array element in JSON",
			(Frame::ObjectFirst, _) => "Expected property name or '}' in JSON",
			(Frame::ObjectKey, _) => "Expected double-quoted property name in JSON",
			(Frame::ObjectColon, _) => "Expected ':' after property name in JSON",
			(Frame::ObjectEnd, _) => "Expected ',' or '}' after property value in JSON",
		};
		self.reject(ErrorKind::Positioned(message));
	}

	fn start_value(&mut self, character: char) {
		match character {
			'[' => self.push(Frame::ArrayFirst),
			'{' => self.push(Frame::ObjectFirst),
			'"' => {
				self.token = Token::String {
					key: false,
					escape: Escape::None,
				};
			}
			't' => self.token = Token::Literal { remaining: b"rue" },
			'f' => self.token = Token::Literal { remaining: b"alse" },
			'n' => self.token = Token::Literal { remaining: b"ull" },
			'-' => self.token = Token::Number(Number::Minus),
			'0' => self.token = Token::Number(Number::Zero),
			'1'..='9' => self.token = Token::Number(Number::Integer),
			_ => self.unexpected(character),
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

	fn accept_string(&mut self, character: char, key: bool, escape: Escape) {
		let next = match (escape, character) {
			(Escape::None, '"') => {
				self.token = Token::None;
				if key {
					self.frames[self.depth - 1] = Frame::ObjectColon;
				} else {
					self.complete_value();
				}
				return;
			}
			(Escape::None, '\\') => Escape::Backslash,
			(Escape::None, '\0'..='\u{1f}') => {
				self.reject(ErrorKind::Positioned(
					"Bad control character in string literal in JSON",
				));
				return;
			}
			(Escape::None, _) => Escape::None,
			(Escape::Backslash, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') => Escape::None,
			(Escape::Backslash, 'u') => Escape::Unicode(4),
			(Escape::Backslash, _) => {
				if u32::from(character) > 0xff {
					self.unexpected(character);
				} else {
					self.reject(ErrorKind::Positioned("Bad escaped character in JSON"));
				}
				return;
			}
			(Escape::Unicode(remaining), _) if character.is_ascii_hexdigit() => {
				if remaining == 1 {
					Escape::None
				} else {
					Escape::Unicode(remaining - 1)
				}
			}
			(Escape::Unicode(_), _) => {
				self.reject(ErrorKind::Positioned("Bad Unicode escape in JSON"));
				return;
			}
		};
		self.token = Token::String { key, escape: next };
	}

	fn accept_number(&mut self, character: char, number: Number) {
		use Number::*;
		let next = match (number, character) {
			(Minus, '0') => Zero,
			(Minus, '1'..='9') | (Integer, '0'..='9') => Integer,
			(Zero | Integer, '.') => Point,
			(Zero | Integer | Fraction, 'e' | 'E') => Exponent,
			(Point | Fraction, '0'..='9') => Fraction,
			(Exponent, '+' | '-') => ExponentSign,
			(Exponent | ExponentSign | ExponentDigits, '0'..='9') => ExponentDigits,
			(Zero, '0'..='9') => {
				self.reject(ErrorKind::Positioned("Unexpected number in JSON"));
				return;
			}
			(Minus, _) => {
				self.reject(ErrorKind::Positioned("No number after minus sign in JSON"));
				return;
			}
			(Point, _) => {
				self.reject(ErrorKind::Positioned(
					"Unterminated fractional number in JSON",
				));
				return;
			}
			(Exponent | ExponentSign, _) => {
				self.reject(ErrorKind::Positioned(
					"Exponent part is missing a number in JSON",
				));
				return;
			}
			_ => {
				self.token = Token::None;
				self.complete_value();
				// This character terminates the number and still belongs to
				// the surrounding grammar. Its position is counted only once.
				self.accept_structure(character);
				return;
			}
		};
		self.token = Token::Number(next);
	}

	pub(super) fn has_syntax_error(&self) -> bool {
		self.error.is_some()
	}

	fn syntax_message(&self, error: &FirstError) -> Option<String> {
		match error.kind {
			ErrorKind::Positioned(message) => Some(format!(
				"{message} at position {} (line {} column {})",
				error.position, error.line, error.column
			)),
			ErrorKind::Unexpected(unit) => {
				// V8 has four exact full-string exceptions, without trimming.
				if self.position <= SHORT {
					let source = String::from_utf16(&self.first[..self.first_len]).ok()?;
					if matches!(
						source.as_str(),
						"[object Object]" | "undefined" | "Infinity" | "NaN"
					) {
						return Some(format!("\"{source}\" is not valid JSON"));
					}
					let token = String::from_utf16(&[unit]).ok()?;
					return Some(format!(
						"Unexpected token '{token}', \"{source}\" is not valid JSON"
					));
				}
				let token = String::from_utf16(&[unit]).ok()?;
				let context = String::from_utf16(&error.context[..error.context_len]).ok()?;
				let before = if error.position >= CONTEXT { "..." } else { "" };
				let after = if error.position < self.position - CONTEXT {
					"..."
				} else {
					""
				};
				Some(format!(
					"Unexpected token '{token}', {before}\"{context}\"{after} is not valid JSON"
				))
			}
		}
	}

	pub(super) fn finish(mut self) -> Option<String> {
		if !self.valid_prefix || self.utf8_remaining != 0 {
			return None;
		}
		if let Some(error) = &self.error {
			return self.syntax_message(error);
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
