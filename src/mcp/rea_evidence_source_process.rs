// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Frozen REA 6.8.0 process-capture boundary validation, without execution.
//!
//! Zod's parsed projection is used only to check commitments. The source record
//! remains unchanged, including fields stripped by non-strict nested schemas.

use super::{
	child, internal, rea_evidence, HashWriter, KeyOrderResolver, SourceResult, Validation,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

#[path = "rea_evidence_source_process_coverage.rs"]
mod coverage;
#[path = "rea_evidence_source_process_schema.rs"]
mod schema;
#[path = "rea_evidence_source_process_semantics.rs"]
mod semantics;

const COLLECTIONS: &[&str] = &[
	"frames",
	"rendered_frames",
	"interaction_events",
	"lifecycle",
	"process_samples",
	"filesystem_checkpoints",
];

pub(super) fn authenticate<'a>(
	value: &Value,
	order: Option<&'a KeyOrderResolver<'a>>,
) -> SourceResult<()> {
	let mut validation = Validation::new(order);
	schema::capture(Some(value), &[], &mut validation);
	if !validation.aborted_from(0) && validation.gap.is_none() {
		semantics::validate(value, &mut validation)?;
	}
	validation.finish()
}

impl Validation<'_> {
	fn process_unknown(&mut self, map: &Map<String, Value>, fields: &[&str], path: &[Value]) {
		// The pinned Zod object parser drops this own key even in strict mode.
		// Constructor/prototype-shaped names other than this exact key remain
		// ordinary unknown fields and retain their source-order diagnostics.
		let mut allowed = fields.to_vec();
		allowed.push("__proto__");
		self.unknown(map, &allowed, path);
	}
}

fn boolean(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	if !matches!(value, Some(Value::Bool(_))) {
		v.invalid_type(value, path, "boolean");
	}
}

fn null(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	if value != Some(&Value::Null) {
		v.invalid_type(value, path, "null");
	}
}

/// Zod's integer check aborts fractional inputs; range checks remain refinable.
fn integer(value: Option<&Value>, path: &[Value], minimum: Option<bool>, v: &mut Validation<'_>) {
	integer_checks(value, path, minimum, false, v);
}

fn safe_positive(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	// z.int().safe() retains two safe-range checks in the frozen Zod build.
	// Fractional inputs abort once; out-of-range integers produce both issues.
	integer_checks(value, path, Some(true), true, v);
}

fn integer_checks(
	value: Option<&Value>,
	path: &[Value],
	minimum: Option<bool>,
	explicit_safe: bool,
	v: &mut Validation<'_>,
) {
	let Some(number) = value.and_then(Value::as_f64) else {
		v.invalid_type(value, path, "number");
		return;
	};
	if number.fract() != 0.0 {
		v.invalid_type(value, path, "int");
		return;
	}
	for _ in 0..if explicit_safe { 2 } else { 1 } {
		if number > 9_007_199_254_740_991.0 {
			v.add(
				path,
				"Too big: expected int to be <=9007199254740991".into(),
				vec![json!({"path":path,"reason":"out_of_range","maximum":9007199254740991u64})],
				false,
			);
		}
		if number < -9_007_199_254_740_991.0 {
			v.add(
				path,
				"Too small: expected int to be >=-9007199254740991".into(),
				vec![json!({"path":path,"reason":"out_of_range","minimum":-9007199254740991i64})],
				false,
			);
		}
	}
	if let Some(positive) = minimum {
		if number < 0.0 || (positive && number == 0.0) {
			let bound = if positive { ">0" } else { ">=0" };
			v.add(
				path,
				format!("Too small: expected number to be {bound}"),
				vec![json!({"path":path,"reason":"out_of_range","minimum":0})],
				false,
			);
		}
	}
}

fn integers(
	map: &Map<String, Value>,
	keys: &[&str],
	path: &[Value],
	positive: bool,
	v: &mut Validation<'_>,
) {
	for key in keys {
		integer(map.get(*key), &child(path, *key), Some(positive), v);
	}
}

fn strings(
	map: &Map<String, Value>,
	keys: &[&str],
	path: &[Value],
	nonempty: bool,
	v: &mut Validation<'_>,
) {
	for key in keys {
		v.string(map.get(*key), &child(path, *key), nonempty);
	}
}

fn array(
	value: Option<&Value>,
	path: &[Value],
	v: &mut Validation<'_>,
	item: fn(Option<&Value>, &[Value], &mut Validation<'_>),
) {
	if let Some(values) = v.array(value, path) {
		for (index, value) in values.iter().enumerate() {
			item(Some(value), &child(path, index), v);
		}
	}
}

fn rows(value: &Value) -> &[Value] {
	value.as_array().map_or(&[], Vec::as_slice)
}

fn number(value: &Value) -> f64 {
	value.as_f64().unwrap_or(0.0)
}

fn bytes(value: &Value) -> f64 {
	value.as_str().map_or(0, str::len) as f64
}

fn issue(v: &mut Validation<'_>, condition: bool, path: &str, message: &str) {
	if !condition {
		let path: Vec<Value> = path.split('.').map(|part| json!(part)).collect();
		v.custom(&path, message, false);
	}
}

/// JSON object/array values have distinct identities in the upstream parsed
/// scenario and comparison objects. Structural equality must not erase that.
fn js_equal(left: Option<&Value>, right: Option<&Value>) -> bool {
	match (left, right) {
		(None, None) | (Some(Value::Null), Some(Value::Null)) => true,
		(Some(Value::Bool(a)), Some(Value::Bool(b))) => a == b,
		(Some(Value::String(a)), Some(Value::String(b))) => a == b,
		(Some(Value::Number(a)), Some(Value::Number(b))) => a.as_f64() == b.as_f64(),
		(Some(a @ (Value::Array(_) | Value::Object(_))), Some(b)) => std::ptr::eq(a, b),
		_ => false,
	}
}

fn digest(write: impl FnOnce(&mut HashWriter) -> SourceResult<()>) -> SourceResult<String> {
	let mut writer = HashWriter(Sha256::new());
	write(&mut writer)?;
	Ok(writer
		.0
		.finalize()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect())
}

fn write_fields(writer: &mut HashWriter, fields: &[(&str, &Value)]) -> SourceResult<()> {
	writer.write_all(b"{").map_err(internal)?;
	for (index, (key, value)) in fields.iter().enumerate() {
		if index > 0 {
			writer.write_all(b",").map_err(internal)?;
		}
		serde_json::to_writer(&mut *writer, key).map_err(internal)?;
		writer.write_all(b":").map_err(internal)?;
		rea_evidence::write_canonical(value, writer).map_err(internal)?;
	}
	writer.write_all(b"}").map_err(internal)
}

fn record_digest(value: &Value) -> SourceResult<String> {
	let mut fields: Vec<_> = value
		.as_object()
		.into_iter()
		.flat_map(|map| map.iter())
		.filter(|(key, _)| key.as_str() != "__proto__")
		.map(|(key, value)| (key.as_str(), value))
		.collect();
	fields.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
	digest(|writer| write_fields(writer, &fields))
}

fn normalization_digest(value: &Value) -> SourceResult<String> {
	digest(|writer| {
		writer.write_all(b"{\"paths\":").map_err(internal)?;
		rea_evidence::write_canonical(&value["paths"], writer).map_err(internal)?;
		writer.write_all(b",\"patterns\":[").map_err(internal)?;
		for (index, pattern) in rows(&value["patterns"]).iter().enumerate() {
			if index > 0 {
				writer.write_all(b",").map_err(internal)?;
			}
			write_fields(
				writer,
				&[
					("pattern", &pattern["pattern"]),
					("replacement", &pattern["replacement"]),
				],
			)?;
		}
		writer.write_all(b"]").map_err(internal)?;
		for key in ["pids", "ports", "time_bucket_ms"] {
			writer.write_all(b",").map_err(internal)?;
			serde_json::to_writer(&mut *writer, key).map_err(internal)?;
			writer.write_all(b":").map_err(internal)?;
			rea_evidence::write_canonical(&value[key], writer).map_err(internal)?;
		}
		writer.write_all(b"}").map_err(internal)
	})
}

#[cfg(test)]
#[path = "rea_evidence_source_process_tests.rs"]
mod tests;
