// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Preserve the frozen Zod length check after a type error. Its `when` guard
//! observes any non-null JSON value with a length, including malformed objects;
//! JavaScript numeric comparison then determines whether to emit another issue.

use super::Validation;
use serde_json::{json, Value};

fn js_space(c: char) -> bool {
	matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}'
		| '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}'
		| '\u{205f}' | '\u{3000}' | '\u{feff}')
}

fn decimal_syntax(text: &str) -> bool {
	let bytes = text.as_bytes();
	let mut index = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
	let mut digits = 0;
	while bytes.get(index).is_some_and(u8::is_ascii_digit) {
		index += 1;
		digits += 1;
	}
	if bytes.get(index) == Some(&b'.') {
		index += 1;
		while bytes.get(index).is_some_and(u8::is_ascii_digit) {
			index += 1;
			digits += 1;
		}
	}
	if digits == 0 {
		return false;
	}
	if matches!(bytes.get(index), Some(b'e' | b'E')) {
		index += 1;
		if matches!(bytes.get(index), Some(b'+' | b'-')) {
			index += 1;
		}
		let exponent_start = index;
		while bytes.get(index).is_some_and(u8::is_ascii_digit) {
			index += 1;
		}
		if index == exponent_start {
			return false;
		}
	}
	index == bytes.len()
}

fn string_number(text: &str) -> f64 {
	let text = text.trim_matches(js_space);
	match text {
		"" => return 0.0,
		"Infinity" | "+Infinity" => return f64::INFINITY,
		"-Infinity" => return f64::NEG_INFINITY,
		_ => {}
	}
	let radix = if text.starts_with("0x") || text.starts_with("0X") {
		Some(16)
	} else if text.starts_with("0b") || text.starts_with("0B") {
		Some(2)
	} else if text.starts_with("0o") || text.starts_with("0O") {
		Some(8)
	} else {
		None
	};
	if let Some(radix) = radix {
		let digits = &text[2..];
		if digits.is_empty() || !digits.chars().all(|c| c.is_ascii() && c.is_digit(radix)) {
			return f64::NAN;
		}
		// Saturation is only above u128::MAX, hence above every possible u64
		// threshold accepted by min_length. It cannot change the comparison.
		return u128::from_str_radix(digits, radix).map_or(f64::INFINITY, |n| n as f64);
	}
	if decimal_syntax(text) {
		text.parse().unwrap_or(f64::NAN)
	} else {
		f64::NAN
	}
}

fn number(value: &Value) -> Result<f64, ()> {
	// JSON cannot contain callable hooks. A present own `toString` masks the
	// normal Object method, so ToPrimitive throws even inside Array.join. Walk
	// the join inputs first, including an array already known to produce NaN.
	let mut pending = vec![value];
	while let Some(value) = pending.pop() {
		match value {
			Value::Object(map) if map.contains_key("toString") => return Err(()),
			Value::Array(values) => pending.extend(values),
			_ => {}
		}
	}
	let mut current = value;
	let mut joined = false;
	loop {
		return Ok(match current {
			Value::Null => 0.0,
			Value::Bool(value) if !joined => u8::from(*value) as f64,
			Value::Bool(_) | Value::Object(_) => f64::NAN,
			Value::Number(value) => value.as_f64().unwrap_or(f64::NAN),
			Value::String(value) => string_number(value),
			Value::Array(values) => match values.as_slice() {
				[] => 0.0,
				[value] => {
					current = value;
					joined = true;
					continue;
				}
				_ => f64::NAN,
			},
		});
	}
}

impl Validation<'_> {
	pub(super) fn min_length(&mut self, value: Option<&Value>, path: &[Value], minimum: u64) {
		let (length, origin) = match value {
			Some(Value::String(text)) => (text.encode_utf16().count() as f64, "string"),
			Some(Value::Array(values)) => (values.len() as f64, "array"),
			Some(Value::Object(map)) => {
				let Some(length) = map.get("length") else {
					return;
				};
				let Ok(length) = number(length) else {
					self.gap = Some("original-length-coercion-exception");
					return;
				};
				(length, "unknown")
			}
			_ => return,
		};
		if length >= minimum as f64 {
			return;
		}
		if origin == "unknown" {
			self.add(
				path,
				format!("Too small: expected unknown to be >={minimum}"),
				vec![json!({"path":path,"reason":"out_of_range","minimum":minimum})],
				false,
			);
		} else {
			self.minimum(path, minimum, origin);
		}
	}
}

#[cfg(test)]
#[path = "rea_evidence_source_length_tests.rs"]
mod tests;
