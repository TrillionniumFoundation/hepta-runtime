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

// Independent test-only reference. The production service never executes Rust.
// regex 1.13.1 / regex-syntax 0.8.11 / regex-automata 0.4.18 are locked to
// the original runtime's registry checksums. No custom regex implementation.
use std::io::{self, BufRead, Write};
include!("ast_projection.rs");
include!("hir_projection.rs");
use regex_automata::nfa::thompson::{Compiler, Config, WhichCaptures};
use regex_syntax::hir::{Class, HirKind};

fn push(out: &mut Vec<u8>, value: u64) {
	out.extend(value.to_le_bytes());
}
fn word(raw: &[u8], at: usize) -> Option<u64> {
	Some(u64::from_le_bytes(raw.get(at..at + 8)?.try_into().ok()?))
}
fn decode(raw: &str) -> Option<Vec<u8>> {
	if raw.len() % 2 != 0 {
		return None;
	}
	raw.as_bytes()
		.chunks_exact(2)
		.map(|x| Some(((x[0] as char).to_digit(16)? * 16 + (x[1] as char).to_digit(16)?) as u8))
		.collect()
}
fn encode(raw: &[u8]) -> String {
	let mut s = String::with_capacity(raw.len() * 2);
	for b in raw {
		use std::fmt::Write;
		write!(&mut s, "{b:02x}").unwrap();
	}
	s
}
fn native_names(out: &mut Vec<u8>, numeric: bool) {
	let mut ranges = Vec::new();
	let mut start = None;
	let mut last = 0;
	for cp in 0..=0x10ffff {
		let selected = char::from_u32(cp)
			.map(|c| {
				if numeric {
					c.is_alphanumeric()
				} else {
					c.is_alphabetic()
				}
			})
			.unwrap_or(false);
		if selected {
			if start.is_none() {
				start = Some(cp)
			}
			last = cp;
		} else if let Some(a) = start.take() {
			ranges.push((a, last));
		}
	}
	if let Some(a) = start.take() {
		ranges.push((a, last));
	}
	push(out, ranges.len() as u64);
	for (a, b) in ranges {
		push(out, a as u64);
		push(out, b as u64);
	}
}
fn run(raw: &[u8]) -> (u32, Vec<u8>) {
	let invalid = || (0xffffffff, Vec::new());
	if raw.get(..8) != Some(b"HREGX001") || raw.len() < 32 {
		return invalid();
	}
	let op = word(raw, 8).unwrap();
	let n = word(raw, 16).unwrap();
	let h = word(raw, 24).unwrap();
	if n > raw.len() as u64 - 32 || h != raw.len() as u64 - 32 - n {
		return invalid();
	}
	let pattern = match std::str::from_utf8(&raw[32..32 + n as usize]) {
		Ok(x) => x,
		Err(_) => return invalid(),
	};
	let hay = match std::str::from_utf8(&raw[32 + n as usize..]) {
		Ok(x) => x,
		Err(_) => return invalid(),
	};
	if op >= 9 && op <= 12 {
		if h != 0 {
			return invalid();
		}
		let reverse = op == 10 || op == 12;
		let text = if op >= 11 {
			format!(r"\A(?:{pattern})\z")
		} else {
			pattern.to_owned()
		};
		let hir = match regex_syntax::Parser::new().parse(&text) {
			Ok(h) => h,
			Err(e) => return (1, e.to_string().into_bytes()),
		};
		let build = |limit| {
			Compiler::new()
				.configure(
					Config::new()
						.utf8(true)
						.reverse(reverse)
						.nfa_size_limit(Some(limit))
						.shrink(false)
						.which_captures(if reverse {
							WhichCaptures::None
						} else {
							WhichCaptures::All
						}),
				)
				.build_from_hir(&hir)
		};
		let max = 10 * (1 << 20);
		let nfa = match build(max) {
			Ok(n) => n,
			Err(_) => return (2, (max as u64).to_le_bytes().to_vec()),
		};
		let (mut lo, mut hi) = (0, max);
		while lo < hi {
			let mid = lo + (hi - lo) / 2;
			if build(mid).is_ok() {
				hi = mid;
			} else {
				lo = mid + 1;
			}
		}
		let mut out = Vec::new();
		push(&mut out, lo as u64);
		push(&mut out, nfa.states().len() as u64);
		push(&mut out, nfa.memory_usage() as u64);
		return (0, out);
	}
	if op == 5 || op == 6 {
		if h != 0 {
			return invalid();
		}
		let text = if op == 6 {
			format!(r"\A(?:{pattern})\z")
		} else {
			pattern.to_owned()
		};
		return project_ast(&text);
	}
	if op == 7 || op == 8 {
		if h != 0 {
			return invalid();
		}
		let text = if op == 8 {
			format!(r"\A(?:{pattern})\z")
		} else {
			pattern.to_owned()
		};
		return project_hir(&text);
	}
	if op == 4 {
		if n != 0 || h != 0 {
			return invalid();
		}
		let mut out = Vec::new();
		for x in [
			char::UNICODE_VERSION.0,
			char::UNICODE_VERSION.1,
			char::UNICODE_VERSION.2,
		] {
			push(&mut out, x as u64);
		}
		native_names(&mut out, false);
		native_names(&mut out, true);
		return (0, out);
	}
	if op == 3 {
		if h != 0 {
			return invalid();
		}
		return match regex_syntax::Parser::new().parse(pattern) {
			Ok(hir) => match hir.kind() {
				HirKind::Class(Class::Unicode(class)) => {
					let mut out = Vec::new();
					push(&mut out, class.ranges().len() as u64);
					for r in class.ranges() {
						push(&mut out, r.start() as u64);
						push(&mut out, r.end() as u64);
					}
					(0, out)
				}
				HirKind::Literal(lit) => {
					let text = std::str::from_utf8(&lit.0).unwrap();
					let chars: Vec<_> = text.chars().collect();
					if chars.len() != 1 {
						return (3, Vec::new());
					}
					let mut out = Vec::new();
					push(&mut out, 1);
					push(&mut out, chars[0] as u64);
					push(&mut out, chars[0] as u64);
					(0, out)
				}
				_ => (3, Vec::new()),
			},
			Err(e) => (1, e.to_string().into_bytes()),
		};
	}
	if op != 1 && op != 2 {
		return invalid();
	}
	// Exactly the original RuntimeConfig::validate and privileged_run wrapper.
	let wrapped = if op == 1 {
		format!(r"\A(?:{pattern})\z")
	} else {
		pattern.to_owned()
	};
	let ast = regex_syntax::ast::parse::Parser::new().parse(&wrapped);
	let hir = regex_syntax::Parser::new().parse(&wrapped);
	match regex::Regex::new(&wrapped) {
		Err(regex::Error::Syntax(message)) => (1, message.into_bytes()),
		Err(regex::Error::CompiledTooBig(limit)) => {
			let mut out = Vec::new();
			push(&mut out, limit as u64);
			(2, out)
		}
		Ok(regex) => {
			let mut out = Vec::new();
			push(&mut out, regex.captures_len() as u64);
			push(&mut out, regex.is_match(hay) as u64);
			push(&mut out, ast.is_ok() as u64);
			push(&mut out, hir.is_ok() as u64);
			let hir = hir.unwrap();
			for reverse in [false, true] {
				let config = Config::new()
					.utf8(true)
					.reverse(reverse)
					.nfa_size_limit(Some(10 * (1 << 20)))
					.shrink(false)
					.which_captures(if reverse {
						WhichCaptures::None
					} else {
						WhichCaptures::All
					});
				match Compiler::new().configure(config).build_from_hir(&hir) {
					Ok(nfa) => {
						push(&mut out, nfa.states().len() as u64);
						push(&mut out, nfa.memory_usage() as u64)
					}
					Err(_) => {
						push(&mut out, u64::MAX);
						push(&mut out, u64::MAX)
					}
				}
			}
			(0, out)
		}
		Err(_) => unreachable!(),
	}
}
fn main() {
	let mut stdout = io::BufWriter::new(io::stdout().lock());
	for line in io::stdin().lock().lines() {
		let line = line.unwrap();
		let (code, out) = decode(&line)
			.map(|b| run(&b))
			.unwrap_or((0xffffffff, Vec::new()));
		writeln!(stdout, "{code:08x}:{}", encode(&out)).unwrap();
	}
}
