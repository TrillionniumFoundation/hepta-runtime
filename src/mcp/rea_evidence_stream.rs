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

//! Hash the borrowed semantic record without allocating its escaped JSON.
//! A long control-character string can serialize to six times its byte size.

use super::{canonical_js_number, field, obj, subject};
use anyhow::{bail, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

// All names are ASCII; this order is also UTF-16 code-unit order.
const FIELDS: &[&str] = &[
	"analysis_profile",
	"authority",
	"confidence",
	"environment",
	"evidence_links",
	"limitations",
	"locations",
	"normalized_result",
	"operation",
	"parameters",
	"predicate_type",
	"provider",
	"raw_result",
	"relationship_coverage",
	"subject",
];

struct HashWriter(Sha256);
impl Write for HashWriter {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.update(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn canonical<W: Write>(value: &Value, output: &mut W, depth: usize) -> Result<()> {
	if depth > 128 {
		bail!("REA subset canonicalization depth exceeded");
	}
	match value {
		Value::Null => output.write_all(b"null")?,
		Value::Bool(true) => output.write_all(b"true")?,
		Value::Bool(false) => output.write_all(b"false")?,
		Value::Number(number) => output.write_all(canonical_js_number(number)?.as_bytes())?,
		Value::String(text) => serde_json::to_writer(output, text)?,
		Value::Array(values) => {
			output.write_all(b"[")?;
			for (index, value) in values.iter().enumerate() {
				if index > 0 {
					output.write_all(b",")?;
				}
				canonical(value, output, depth + 1)?;
			}
			output.write_all(b"]")?;
		}
		Value::Object(values) => {
			let mut ordered: Vec<_> = values.iter().collect();
			ordered.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
			output.write_all(b"{")?;
			for (index, (key, value)) in ordered.into_iter().enumerate() {
				if index > 0 {
					output.write_all(b",")?;
				}
				serde_json::to_writer(&mut *output, key)?;
				output.write_all(b":")?;
				canonical(value, output, depth + 1)?;
			}
			output.write_all(b"}")?;
		}
	}
	Ok(())
}

pub(crate) fn semantic_digest(record: &Value) -> Result<String> {
	let map = obj(record, "Evidence")?;
	let subject = subject(field(map, "subject")?)?;
	let mut output = HashWriter(Sha256::new());
	output.write_all(b"{")?;
	for (index, key) in FIELDS.iter().enumerate() {
		if index > 0 {
			output.write_all(b",")?;
		}
		serde_json::to_writer(&mut output, key)?;
		output.write_all(b":")?;
		let value = if *key == "subject" {
			&subject
		} else {
			field(map, key)?
		};
		canonical(value, &mut output, 1)?;
	}
	output.write_all(b"}")?;
	Ok(output
		.0
		.finalize()
		.into_iter()
		.map(|byte| format!("{byte:02x}"))
		.collect())
}

pub(crate) fn canonical_digest(value: &Value) -> Result<String> {
	let mut output = HashWriter(Sha256::new());
	canonical(value, &mut output, 0)?;
	Ok(output
		.0
		.finalize()
		.into_iter()
		.map(|byte| format!("{byte:02x}"))
		.collect())
}

pub(crate) fn write_canonical<W: Write>(value: &Value, output: &mut W) -> Result<()> {
	canonical(value, output, 0)
}

fn equal(left: &Value, right: &Value, depth: usize) -> Result<bool> {
	if depth > 128 {
		bail!("REA subset canonicalization depth exceeded");
	}
	Ok(match (left, right) {
		(Value::Number(a), Value::Number(b)) => canonical_js_number(a)? == canonical_js_number(b)?,
		(Value::Array(a), Value::Array(b)) => {
			if a.len() != b.len() {
				return Ok(false);
			}
			for (a, b) in a.iter().zip(b) {
				if !equal(a, b, depth + 1)? {
					return Ok(false);
				}
			}
			true
		}
		(Value::Object(a), Value::Object(b)) => {
			if a.len() != b.len() {
				return Ok(false);
			}
			for (key, a) in a {
				if !b
					.get(key)
					.map(|b| equal(a, b, depth + 1))
					.transpose()?
					.unwrap_or(false)
				{
					return Ok(false);
				}
			}
			true
		}
		_ => left == right,
	})
}

/// Compare semantic content itself, not two hashes. Hash collisions must not
/// permit a second record to overwrite an already retained observation.
pub(crate) fn semantic_equal(left: &Value, right: &Value) -> Result<bool> {
	let left = obj(left, "Evidence")?;
	let right = obj(right, "Evidence")?;
	if !equal(
		&subject(field(left, "subject")?)?,
		&subject(field(right, "subject")?)?,
		1,
	)? {
		return Ok(false);
	}
	for key in FIELDS.iter().filter(|key| **key != "subject") {
		if !equal(field(left, key)?, field(right, key)?, 1)? {
			return Ok(false);
		}
	}
	Ok(true)
}
