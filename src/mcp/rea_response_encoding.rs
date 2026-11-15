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

//! Frozen REA JSON-part generation and response-budget accounting.
//!
//! Refusals occur after a complete 64-Ki UTF-16 buffered part, not at the first
//! character crossing the limit. A 16-Ki generator part can itself exceed 64 Ki
//! because short strings and keys are escaped before the threshold is tested.
//! Object order and number formatting are explicit inputs; a serde BTree map
//! does not establish the original JavaScript Object.keys order.
//!
//! These APIs borrow payloads and buffer only bounded serialization fragments.
//! The test-only full-wire reference writer uses one formatter for both JSON representations,
//! avoiding a budget computed for JavaScript numbers followed by a different
//! serde numeric wire representation. It writes the CallToolResult object,
//! without the enclosing JSON-RPC message or its 1024-byte reservation.
//!
//! The input domain is immutable serde JSON: finite numbers, ordinary objects,
//! and valid Unicode strings. Lone JavaScript UTF-16 surrogates, functions,
//! getters, symbols, sparse arrays, and circular references are not represented
//! by `Value`; this module does not silently replace or qualify those values.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{Map, Number, Value};
use std::collections::HashSet;
#[cfg(test)]
use std::io;
use std::io::Write;

const SHORT_STRING_UNITS: usize = 8192;
const JSON_PART_UNITS: usize = 16 * 1024;
const BUFFERED_PART_UNITS: usize = 64 * 1024;
pub(super) const NODE_MAX_STRING_LENGTH: u64 = 536_870_888;
pub(super) const MCP_RESULT_STRING_LIMIT: u64 = NODE_MAX_STRING_LENGTH - 1024;

const STRUCTURED_ENVELOPE: &[u8] =
	br#"{"content":[{"type":"text","text":""}],"structuredContent":null}"#;
const ERROR_ENVELOPE: &[u8] = br#"{"content":[{"type":"text","text":""}],"isError":true}"#;
const META_FRAGMENT: &[u8] =
	br#","_meta":{"provenance":{"untrusted_content":true,"source":"analysis_target"}}"#;

pub(super) type NumberFormatter = fn(&Number) -> Result<String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PathComponent<'a> {
	Key(&'a str),
	Index(usize),
}

/// Supply an exact JavaScript Object.keys sequence for each visited object.
/// Optional producer fields may be filtered through `declared_keys`; unknown
/// fields or missing order information must produce an error, not a guessed
/// BTree fallback. The resolver must be deterministic across measurement and
/// subsequent writing, for the same immutable value.
pub(super) trait ObjectOrder {
	fn keys<'a>(
		&self,
		path: &[PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> Result<Vec<&'a str>>;
}

/// A borrowed JSON document or a small borrowed composition around payloads.
/// Explicit object members are already in their complete original Object.keys
/// order; nested `Value` objects still require the supplied order resolver.
/// `Values` accepts an existing bundle's `Vec<&Value>` without copying records
/// or allocating one recursive wrapper per record. Scalars may borrow from
/// ordinary typed producer fields without first constructing a `Value`.
#[derive(Debug, Clone, Copy)]
pub(super) enum JsonView<'a> {
	Value(&'a Value),
	Object(&'a [(&'a str, JsonView<'a>)]),
	#[cfg_attr(
		not(test),
		allow(
			dead_code,
			reason = "Borrowed composite arrays are covered by the frozen encoder oracle; current production bundles borrow Value arrays."
		)
	)]
	Array(&'a [JsonView<'a>]),
	Values(&'a [&'a Value]),
	#[cfg_attr(
		not(test),
		allow(
			dead_code,
			reason = "Typed borrowed scalars are covered by the frozen encoder oracle; current producers retain JSON Values."
		)
	)]
	String(&'a str),
	#[cfg_attr(
		not(test),
		allow(
			dead_code,
			reason = "Typed borrowed scalars are covered by the frozen encoder oracle; current producers retain JSON Values."
		)
	)]
	Number(&'a Number),
	#[cfg_attr(
		not(test),
		allow(
			dead_code,
			reason = "Typed borrowed scalars are covered by the frozen encoder oracle; current producers retain JSON Values."
		)
	)]
	Bool(bool),
	#[cfg_attr(
		not(test),
		allow(
			dead_code,
			reason = "Typed borrowed scalars are covered by the frozen encoder oracle; current producers retain JSON Values."
		)
	)]
	Null,
}

pub(super) fn pointer(path: &[PathComponent<'_>]) -> String {
	let mut pointer = String::new();
	for part in path {
		pointer.push('/');
		match part {
			PathComponent::Key(key) => pointer.push_str(&key.replace('~', "~0").replace('/', "~1")),
			PathComponent::Index(index) => pointer.push_str(&index.to_string()),
		}
	}
	pointer
}

/// Convert a producer's known insertion sequence into JavaScript enumeration
/// order: present integer-index keys first, numerically, then other keys in
/// insertion order. Missing optional fields are permitted; extra keys are not.
pub(super) fn declared_keys<'a>(
	object: &'a Map<String, Value>,
	insertion: &[&str],
) -> Result<Vec<&'a str>> {
	let mut seen = HashSet::new();
	let mut indices = Vec::new();
	let mut ordinary = Vec::new();
	for name in insertion {
		if !seen.insert(*name) {
			bail!("Duplicate producer object-order key");
		}
		let Some((key, _)) = object.get_key_value(*name) else {
			continue;
		};
		if let Some(index) = array_index(key) {
			indices.push((index, key.as_str()));
		} else {
			ordinary.push(key.as_str());
		}
	}
	if indices.len() + ordinary.len() != object.len() {
		bail!("Producer object order does not cover every member");
	}
	indices.sort_unstable_by_key(|(index, _)| *index);
	Ok(indices
		.into_iter()
		.map(|(_, key)| key)
		.chain(ordinary)
		.collect())
}

fn array_index(key: &str) -> Option<u32> {
	if key.is_empty()
		|| (key.len() > 1 && key.starts_with('0'))
		|| !key.bytes().all(|b| b.is_ascii_digit())
	{
		return None;
	}
	key.parse::<u32>().ok().filter(|index| *index < u32::MAX)
}

fn validate_keys(object: &Map<String, Value>, keys: &[&str]) -> Result<()> {
	if keys.len() != object.len() {
		bail!("Object order is incomplete");
	}
	if keys.iter().any(|key| !object.contains_key(*key)) {
		bail!("Object order contains an unknown member");
	}
	validate_enumeration(keys.iter().copied())
}

fn validate_enumeration<'a>(keys: impl Iterator<Item = &'a str>) -> Result<()> {
	let mut seen = HashSet::new();
	let mut previous_index = None;
	let mut ordinary = false;
	for key in keys {
		if !seen.insert(key) {
			bail!("Object order contains a duplicate member");
		}
		if let Some(index) = array_index(key) {
			if ordinary || previous_index.is_some_and(|previous| previous >= index) {
				bail!("Object order does not follow JavaScript integer-index enumeration");
			}
			previous_index = Some(index);
		} else {
			ordinary = true;
		}
	}
	Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Representations {
	StructuredAndText,
	#[cfg_attr(
		not(test),
		allow(
			dead_code,
			reason = "The frozen error representation is covered by the encoder oracle; native failures currently use their typed error projector."
		)
	)]
	ErrorText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Constraint {
	ReceiveBuffer,
	StringLength,
}

impl Constraint {
	pub(super) fn as_str(self) -> &'static str {
		match self {
			Self::ReceiveBuffer => "receive-buffer",
			Self::StringLength => "string-length",
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Budget {
	pub(super) bytes: u64,
	pub(super) representations: Representations,
	pub(super) target_content: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Measurement {
	Fits {
		bytes: u64,
		code_units: u64,
		json_bytes: u64,
		json_code_units: u64,
	},
	Overflow {
		bytes_at_least: u64,
		code_units_at_least: u64,
		constraint: Constraint,
	},
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JsonMeasurement {
	Fits { bytes: u64 },
	Overflow { bytes_at_least: u64 },
}

fn units(text: &str) -> usize {
	if text.is_ascii() {
		text.len()
	} else {
		text.encode_utf16().count()
	}
}

struct PartGenerator<'a, F> {
	sink: &'a mut F,
	buffer: String,
	units: usize,
}

impl<F: FnMut(&str) -> Result<bool>> PartGenerator<'_, F> {
	fn append(&mut self, text: &str) {
		self.buffer.push_str(text);
		self.units += units(text);
	}
	fn flush(&mut self) -> Result<bool> {
		if self.buffer.is_empty() {
			return Ok(true);
		}
		let mut part = std::mem::take(&mut self.buffer);
		self.units = 0;
		let keep = (self.sink)(&part)?;
		part.clear();
		self.buffer = part;
		Ok(keep)
	}
	fn long_string(&mut self, text: &str) -> Result<bool> {
		if !self.flush()? || !(self.sink)("\"")? {
			return Ok(false);
		}
		let mut start = 0;
		while start < text.len() {
			let mut chunk_units = 0;
			let mut end = start;
			for (offset, character) in text[start..].char_indices() {
				if chunk_units + character.len_utf16() > SHORT_STRING_UNITS {
					break;
				}
				chunk_units += character.len_utf16();
				end = start + offset + character.len_utf8();
			}
			let quoted = serde_json::to_string(&text[start..end])?;
			if !(self.sink)(&quoted[1..quoted.len() - 1])? {
				return Ok(false);
			}
			start = end;
		}
		(self.sink)("\"")
	}
	fn string(&mut self, text: &str) -> Result<bool> {
		if text.len() <= SHORT_STRING_UNITS
			|| text.encode_utf16().take(SHORT_STRING_UNITS + 1).count() <= SHORT_STRING_UNITS
		{
			self.append(&serde_json::to_string(text)?);
			Ok(true)
		} else {
			self.long_string(text)
		}
	}
}

enum Members<'a> {
	ValueArray(&'a [Value]),
	ValueObject {
		values: &'a Map<String, Value>,
		keys: Vec<&'a str>,
	},
	Array(&'a [JsonView<'a>]),
	Values(&'a [&'a Value]),
	Object(&'a [(&'a str, JsonView<'a>)]),
}
struct Frame<'a> {
	members: Members<'a>,
	index: usize,
	written: usize,
	path_length: usize,
}

/// Port of jsonParts(value, false), with no recursion and no guessed order.
#[cfg(test)]
fn json_parts<O: ObjectOrder + ?Sized, F: FnMut(&str) -> Result<bool>>(
	value: &Value,
	order: &O,
	number: NumberFormatter,
	sink: &mut F,
) -> Result<bool> {
	json_view_parts(JsonView::Value(value), order, number, sink)
}

fn json_view_parts<'a, O: ObjectOrder + ?Sized, F: FnMut(&str) -> Result<bool>>(
	value: JsonView<'a>,
	order: &O,
	number: NumberFormatter,
	sink: &mut F,
) -> Result<bool> {
	let mut output = PartGenerator {
		sink,
		buffer: String::new(),
		units: 0,
	};
	let mut stack: Vec<Frame<'a>> = Vec::new();
	let mut path: Vec<PathComponent<'a>> = Vec::new();
	let mut pending = Some(value);
	loop {
		if let Some(value) = pending.take() {
			match value {
				JsonView::Value(Value::Null) | JsonView::Null => output.append("null"),
				JsonView::Value(Value::Bool(true)) | JsonView::Bool(true) => output.append("true"),
				JsonView::Value(Value::Bool(false)) | JsonView::Bool(false) => {
					output.append("false")
				}
				JsonView::Value(Value::Number(value)) | JsonView::Number(value) => {
					output.append(&number(value)?)
				}
				JsonView::Value(Value::String(value)) => {
					if !output.string(value)? {
						return Ok(false);
					}
				}
				JsonView::String(value) => {
					if !output.string(value)? {
						return Ok(false);
					}
				}
				JsonView::Value(Value::Array(values)) => {
					stack.push(Frame {
						members: Members::ValueArray(values),
						index: 0,
						written: 0,
						path_length: path.len(),
					});
					output.append("[");
				}
				JsonView::Value(Value::Object(values)) => {
					let keys = order.keys(&path, values).with_context(|| {
						format!("Object order unavailable at {}", pointer(&path))
					})?;
					validate_keys(values, &keys)
						.with_context(|| format!("Invalid object order at {}", pointer(&path)))?;
					stack.push(Frame {
						members: Members::ValueObject { values, keys },
						index: 0,
						written: 0,
						path_length: path.len(),
					});
					output.append("{");
				}
				JsonView::Object(values) => {
					validate_enumeration(values.iter().map(|(key, _)| *key)).with_context(
						|| format!("Invalid explicit object order at {}", pointer(&path)),
					)?;
					stack.push(Frame {
						members: Members::Object(values),
						index: 0,
						written: 0,
						path_length: path.len(),
					});
					output.append("{");
				}
				JsonView::Array(values) => {
					stack.push(Frame {
						members: Members::Array(values),
						index: 0,
						written: 0,
						path_length: path.len(),
					});
					output.append("[");
				}
				JsonView::Values(values) => {
					stack.push(Frame {
						members: Members::Values(values),
						index: 0,
						written: 0,
						path_length: path.len(),
					});
					output.append("[");
				}
			}
		}
		if output.units >= JSON_PART_UNITS && !output.flush()? {
			return Ok(false);
		}
		let Some(frame) = stack.last_mut() else {
			break;
		};
		path.truncate(frame.path_length);
		let next = match &frame.members {
			Members::ValueArray(values) => values.get(frame.index).map(|value| {
				(
					PathComponent::Index(frame.index),
					None,
					JsonView::Value(value),
				)
			}),
			Members::ValueObject { values, keys } => keys
				.get(frame.index)
				.map(|key| {
					values
						.get(*key)
						.map(|value| (PathComponent::Key(key), Some(*key), JsonView::Value(value)))
						.ok_or_else(|| anyhow!("Object changed after key admission"))
				})
				.transpose()?,
			Members::Array(values) => values
				.get(frame.index)
				.map(|value| (PathComponent::Index(frame.index), None, *value)),
			Members::Values(values) => values.get(frame.index).map(|value| {
				(
					PathComponent::Index(frame.index),
					None,
					JsonView::Value(value),
				)
			}),
			Members::Object(values) => values
				.get(frame.index)
				.map(|(key, value)| (PathComponent::Key(key), Some(*key), *value)),
		};
		if let Some((component, key, value)) = next {
			frame.index += 1;
			if frame.written > 0 {
				output.append(",");
			}
			if let Some(key) = key {
				if !output.string(key)? {
					return Ok(false);
				}
				output.append(":");
			}
			frame.written += 1;
			path.push(component);
			pending = Some(value);
		} else {
			output.append(match &frame.members {
				Members::ValueArray(_) | Members::Array(_) | Members::Values(_) => "]",
				Members::ValueObject { .. } | Members::Object(_) => "}",
			});
			stack.pop();
		}
	}
	output.flush()
}

/// Exactly bufferedJsonParts(jsonParts(value)): do not split a generator part
/// larger than 64 Ki UTF-16 units. The next part is computed before flushing
/// the existing buffer, as in the source generator's for-of loop.
#[cfg(test)]
fn buffered_parts<O: ObjectOrder + ?Sized, F: FnMut(&str) -> Result<bool>>(
	value: &Value,
	order: &O,
	number: NumberFormatter,
	mut sink: F,
) -> Result<bool> {
	buffered_view_parts(JsonView::Value(value), order, number, &mut sink)
}

fn buffered_view_parts<O: ObjectOrder + ?Sized, F: FnMut(&str) -> Result<bool>>(
	value: JsonView<'_>,
	order: &O,
	number: NumberFormatter,
	mut sink: F,
) -> Result<bool> {
	let mut buffer = String::new();
	let mut buffered_units = 0;
	let complete = json_view_parts(value, order, number, &mut |part| {
		let part_units = units(part);
		if buffered_units + part_units > BUFFERED_PART_UNITS && !buffer.is_empty() {
			if !sink(&buffer)? {
				return Ok(false);
			}
			buffer.clear();
			buffered_units = 0;
		}
		buffer.push_str(part);
		buffered_units += part_units;
		Ok(true)
	})?;
	if !complete {
		return Ok(false);
	}
	if buffer.is_empty() {
		Ok(true)
	} else {
		sink(&buffer)
	}
}

fn escaped_extra(text: &str) -> u64 {
	text.chars()
		.map(|character| match character {
			'"' | '\\' | '\u{8}' | '\t' | '\n' | '\u{c}' | '\r' => 1,
			character if character < ' ' => 5,
			_ => 0,
		})
		.sum()
}

fn envelope(budget: Budget) -> u64 {
	let base = match budget.representations {
		Representations::StructuredAndText => STRUCTURED_ENVELOPE.len() - 4,
		Representations::ErrorText => ERROR_ENVELOPE.len(),
	};
	(base
		+ if budget.target_content {
			META_FRAGMENT.len()
		} else {
			0
		}) as u64
}

#[cfg(test)]
pub(super) fn measure<O: ObjectOrder + ?Sized>(
	value: &Value,
	order: &O,
	number: NumberFormatter,
	budget: Budget,
) -> Result<Measurement> {
	measure_view(JsonView::Value(value), order, number, budget)
}

pub(super) fn measure_view<O: ObjectOrder + ?Sized>(
	value: JsonView<'_>,
	order: &O,
	number: NumberFormatter,
	budget: Budget,
) -> Result<Measurement> {
	let mut bytes = envelope(budget);
	let mut code_units = bytes;
	let mut json_bytes = 0u64;
	let mut json_code_units = 0u64;
	let mut refusal = None;
	let representations = if budget.representations == Representations::StructuredAndText {
		2
	} else {
		1
	};
	buffered_view_parts(value, order, number, |part| {
		let length = part.len() as u64;
		let length_units = units(part) as u64;
		let extra = escaped_extra(part);
		json_bytes = json_bytes
			.checked_add(length)
			.context("JSON byte count overflow")?;
		json_code_units = json_code_units
			.checked_add(length_units)
			.context("JSON code-unit count overflow")?;
		bytes = bytes
			.checked_add(representations * length + extra)
			.context("Response byte count overflow")?;
		code_units = code_units
			.checked_add(representations * length_units + extra)
			.context("Response code-unit count overflow")?;
		if bytes > budget.bytes || code_units > MCP_RESULT_STRING_LIMIT {
			refusal = Some(Measurement::Overflow {
				bytes_at_least: bytes,
				code_units_at_least: code_units,
				constraint: if code_units > MCP_RESULT_STRING_LIMIT {
					Constraint::StringLength
				} else {
					Constraint::ReceiveBuffer
				},
			});
			return Ok(false);
		}
		Ok(true)
	})?;
	Ok(refusal.unwrap_or(Measurement::Fits {
		bytes,
		code_units,
		json_bytes,
		json_code_units,
	}))
}

/// Equivalent to measureMcpResultWithinBudget for an already formed result.
/// A caller checking the final native wire must supply that wire's actual
/// object order and numeric formatter, not an upstream-order assumption.
#[cfg(test)]
pub(super) fn measure_json<O: ObjectOrder + ?Sized>(
	value: &Value,
	order: &O,
	number: NumberFormatter,
	budget_bytes: u64,
) -> Result<JsonMeasurement> {
	measure_json_view(JsonView::Value(value), order, number, budget_bytes)
}

#[cfg(test)]
pub(super) fn measure_json_view<O: ObjectOrder + ?Sized>(
	value: JsonView<'_>,
	order: &O,
	number: NumberFormatter,
	budget_bytes: u64,
) -> Result<JsonMeasurement> {
	let mut bytes = 0u64;
	let complete = buffered_view_parts(value, order, number, |part| {
		bytes = bytes
			.checked_add(part.len() as u64)
			.context("JSON byte count overflow")?;
		Ok(bytes <= budget_bytes)
	})?;
	Ok(if complete {
		JsonMeasurement::Fits { bytes }
	} else {
		JsonMeasurement::Overflow {
			bytes_at_least: bytes,
		}
	})
}

#[cfg(test)]
pub(super) fn write_json<O: ObjectOrder + ?Sized, W: Write>(
	value: &Value,
	order: &O,
	number: NumberFormatter,
	output: &mut W,
) -> Result<()> {
	write_json_view(JsonView::Value(value), order, number, output)
}

pub(super) fn write_json_view<O: ObjectOrder + ?Sized, W: Write>(
	value: JsonView<'_>,
	order: &O,
	number: NumberFormatter,
	output: &mut W,
) -> Result<()> {
	json_view_parts(value, order, number, &mut |part| {
		output.write_all(part.as_bytes())?;
		Ok(true)
	})?;
	Ok(())
}

#[cfg(test)]
struct EscapeWriter<'a, W> {
	output: &'a mut W,
}
#[cfg(test)]
impl<W: Write> Write for EscapeWriter<'_, W> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
		let mut start = 0;
		for (offset, character) in text.char_indices() {
			if character == '"' || character == '\\' || character < ' ' {
				self.output.write_all(&bytes[start..offset])?;
				match character {
					'"' => self.output.write_all(b"\\\"")?,
					'\\' => self.output.write_all(b"\\\\")?,
					'\u{8}' => self.output.write_all(b"\\b")?,
					'\t' => self.output.write_all(b"\\t")?,
					'\n' => self.output.write_all(b"\\n")?,
					'\u{c}' => self.output.write_all(b"\\f")?,
					'\r' => self.output.write_all(b"\\r")?,
					control => {
						const HEX: &[u8; 16] = b"0123456789abcdef";
						let byte = control as u8;
						self.output.write_all(&[
							b'\\',
							b'u',
							b'0',
							b'0',
							HEX[usize::from(byte >> 4)],
							HEX[usize::from(byte & 15)],
						])?;
					}
				}
				start = offset + character.len_utf8();
			}
		}
		self.output.write_all(&bytes[start..])?;
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		self.output.flush()
	}
}

/// Refusal writes no output. Success streams the same bytes that were counted,
/// without creating a complete escaped document. The caller still owns its
/// output's atomicity and may stage before sending if its Write can fail.
#[cfg(test)]
pub(super) fn write_tool_result<O: ObjectOrder + ?Sized, W: Write>(
	value: &Value,
	order: &O,
	number: NumberFormatter,
	budget: Budget,
	output: &mut W,
) -> Result<Measurement> {
	write_tool_result_view(JsonView::Value(value), order, number, budget, output)
}

#[cfg(test)]
pub(super) fn write_tool_result_view<O: ObjectOrder + ?Sized, W: Write>(
	value: JsonView<'_>,
	order: &O,
	number: NumberFormatter,
	budget: Budget,
	output: &mut W,
) -> Result<Measurement> {
	let measurement = measure_view(value, order, number, budget)?;
	if matches!(measurement, Measurement::Overflow { .. }) {
		return Ok(measurement);
	}
	output.write_all(br#"{"content":[{"type":"text","text":""#)?;
	write_json_view(
		value,
		order,
		number,
		&mut EscapeWriter {
			output: &mut *output,
		},
	)?;
	output.write_all(br#""}]"#)?;
	match budget.representations {
		Representations::StructuredAndText => {
			output.write_all(b",\"structuredContent\":")?;
			write_json_view(value, order, number, output)?;
		}
		Representations::ErrorText => output.write_all(b",\"isError\":true")?,
	}
	if budget.target_content {
		output.write_all(META_FRAGMENT)?;
	}
	output.write_all(b"}")?;
	Ok(measurement)
}

#[cfg(test)]
#[path = "rea_response_encoding_tests.rs"]
mod tests;
