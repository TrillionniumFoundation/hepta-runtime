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

//! Original JavaScript field order for the admitted native REA producers.
//!
//! The annotated schemas come from unsorted original tools/list bytes, with
//! producer-source and original-record checks recorded beside the schemas.
//! This is a closed-world order resolver, not a general JSON Schema validator.
//! Unknown producer shapes and genuinely different applicable orders fail.
//! Array union candidates are carried to the visited element, avoiding a full
//! records/items scan for every local order query. Payloads remain borrowed.

use super::rea_evidence_file;
use super::rea_response_encoding::{declared_keys, pointer, ObjectOrder, PathComponent};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

/// Creation provenance is not recoverable from semantic Evidence JSON: APK
/// inline views and the direct analysis-view tool can have the same semantic
/// identity but different parameters.view insertion order. Retention must keep
/// the first record's origin; immediate delivery uses the current call's origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum RecordOrigin {
	NativeTool,
	ApkToolDerived,
	AnalysisViewToolDerived,
	#[default]
	Unknown,
}

pub(super) struct RecordOrder<'a> {
	record: &'a Value,
	origin: RecordOrigin,
}
pub(super) struct BundleOrder<'a> {
	records: &'a [&'a Value],
	origins: &'a [RecordOrigin],
	imported_orders: Option<&'a [Option<Arc<rea_evidence_file::ObjectOrder>>]>,
	unknowns: Option<&'a [&'a Value]>,
}
pub(super) struct BundleSummaryOrder<'a>(pub(super) &'a Value);

impl<'a> RecordOrder<'a> {
	pub(super) fn new(record: &'a Value, origin: RecordOrigin) -> Self {
		Self { record, origin }
	}
}
impl<'a> BundleOrder<'a> {
	pub(super) fn new(records: &'a [&'a Value], origins: &'a [RecordOrigin]) -> Result<Self> {
		ensure!(
			records.len() == origins.len(),
			"Bundle record/origin counts differ"
		);
		Ok(Self {
			records,
			origins,
			imported_orders: None,
			unknowns: None,
		})
	}

	pub(super) fn with_imports(
		records: &'a [&'a Value],
		origins: &'a [RecordOrigin],
		imported_orders: &'a [Option<Arc<rea_evidence_file::ObjectOrder>>],
		unknowns: &'a [&'a Value],
	) -> Result<Self> {
		ensure!(
			records.len() == imported_orders.len(),
			"Bundle import order count differs"
		);
		let mut result = Self::new(records, origins)?;
		result.imported_orders = Some(imported_orders);
		result.unknowns = Some(unknowns);
		Ok(result)
	}
}

struct Schemas {
	elf: Value,
	apk: Value,
	bundle: Value,
}
static ANY_SCHEMA: Value = Value::Bool(true);

fn schemas() -> Result<&'static Schemas> {
	static SCHEMAS: OnceLock<std::result::Result<Schemas, String>> = OnceLock::new();
	SCHEMAS
		.get_or_init(|| {
			let parse = |text: &str| -> Result<Value> {
				let value: Value = serde_json::from_str(text)?;
				validate_annotations(&value)?;
				Ok(value)
			};
			(|| {
				Ok(Schemas {
					elf: parse(include_str!(
						"rea_frozen/response-order/inspect_elf_notes.ordered.json"
					))?,
					apk: parse(include_str!(
						"rea_frozen/response-order/inspect_apk_signature.ordered.json"
					))?,
					bundle: parse(include_str!(
						"rea_frozen/response-order/get_evidence_bundle.ordered.json"
					))?,
				})
			})()
			.map_err(|error: anyhow::Error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow!("Frozen response-order schemas: {error}"))
}

fn validate_annotations(root: &Value) -> Result<()> {
	let mut pending = vec![root];
	while let Some(value) = pending.pop() {
		match value {
			Value::Object(object) => {
				if let Some(properties) = object.get("properties") {
					let properties = properties
						.as_object()
						.context("Schema properties are not an object")?;
					let names = object
						.get("x-hepta-object-order")
						.and_then(Value::as_array)
						.context("Missing original schema property sequence")?;
					let mut seen = HashSet::new();
					for name in names {
						let name = name.as_str().context("Non-string original property name")?;
						ensure!(
							properties.contains_key(name) && seen.insert(name),
							"Invalid original schema property sequence"
						);
					}
					ensure!(
						seen.len() == properties.len(),
						"Incomplete original schema property sequence"
					);
				}
				pending.extend(object.values());
			}
			Value::Array(values) => pending.extend(values),
			_ => {}
		}
	}
	Ok(())
}

fn reference<'a>(root: &'a Value, name: &str) -> Result<&'a Value> {
	ensure!(
		name.starts_with("#/"),
		"External response-order schema reference is unsupported"
	);
	root.pointer(&name[1..])
		.with_context(|| format!("Missing response-order schema reference {name}"))
}

fn equal_literal(a: &Value, b: &Value) -> bool {
	if a.is_number() && b.is_number() {
		a.as_f64() == b.as_f64()
	} else {
		a == b
	}
}

fn type_matches(kind: &str, value: &Value) -> Result<bool> {
	Ok(match kind {
		"object" => value.is_object(),
		"array" => value.is_array(),
		"string" => value.is_string(),
		"boolean" => value.is_boolean(),
		"null" => value.is_null(),
		"number" => value.as_f64().is_some_and(f64::is_finite),
		"integer" => value
			.as_f64()
			.is_some_and(|v| v.is_finite() && v.fract() == 0.0),
		_ => bail!("Unsupported frozen response-order schema type"),
	})
}

/// Shape discriminators only. Ordinary object properties are inspected, but
/// array bodies are not scanned: the actual indexed member is checked when
/// its path is visited. Scalar pattern strings do not establish object order.
fn shape(
	root: &Value,
	schema: &Value,
	value: &Value,
	ancestors: &mut Vec<*const Value>,
) -> Result<bool> {
	let identity = std::ptr::from_ref(schema);
	ensure!(
		!ancestors.contains(&identity),
		"Cyclic response-order schema reference"
	);
	ancestors.push(identity);
	let answer = (|| {
		if !shape_base(root, schema, value, ancestors)? {
			return Ok(false);
		}
		if let Some(name) = schema.get("$ref").and_then(Value::as_str) {
			if !shape(root, reference(root, name)?, value, ancestors)? {
				return Ok(false);
			}
		}
		for (name, exactly_one) in [("anyOf", false), ("oneOf", true)] {
			if let Some(choices) = schema.get(name) {
				let mut matched = 0;
				for choice in choices.as_array().context("Schema union is not an array")? {
					if shape(root, choice, value, ancestors)? {
						matched += 1;
					}
				}
				if matched == 0 || (exactly_one && matched != 1) {
					return Ok(false);
				}
			}
		}
		Ok(true)
	})();
	ancestors.pop();
	answer
}

fn shape_base(
	root: &Value,
	schema: &Value,
	value: &Value,
	ancestors: &mut Vec<*const Value>,
) -> Result<bool> {
	if let Some(allowed) = schema.as_bool() {
		return Ok(allowed);
	}
	ensure!(
		schema.is_object(),
		"Frozen schema node is not an object or boolean"
	);
	if schema.as_object().is_some_and(Map::is_empty) {
		return Ok(true);
	}
	if let Some(kind) = schema.get("type") {
		if !type_matches(
			kind.as_str()
				.context("Unsupported union type declaration")?,
			value,
		)? {
			return Ok(false);
		}
	}
	if let Some(constant) = schema.get("const") {
		if !equal_literal(constant, value) {
			return Ok(false);
		}
	}
	if let Some(values) = schema.get("enum") {
		if !values
			.as_array()
			.context("Schema enum is not an array")?
			.iter()
			.any(|v| equal_literal(v, value))
		{
			return Ok(false);
		}
	}
	if let Some(number) = value.as_f64() {
		for (key, exclusive, lower) in [
			("minimum", false, true),
			("maximum", false, false),
			("exclusiveMinimum", true, true),
			("exclusiveMaximum", true, false),
		] {
			if let Some(bound) = schema.get(key).and_then(Value::as_f64) {
				if (lower && number < bound)
					|| (exclusive && number == bound)
					|| (!lower && number > bound)
				{
					return Ok(false);
				}
			}
		}
	}
	if let Some(object) = value.as_object() {
		if let Some(required) = schema.get("required") {
			for name in required
				.as_array()
				.context("Schema required is not an array")?
			{
				if !object.contains_key(name.as_str().context("Non-string required property")?) {
					return Ok(false);
				}
			}
		}
		let properties = schema.get("properties").and_then(Value::as_object);
		for (name, item) in object {
			if let Some(member) = properties.and_then(|p| p.get(name)) {
				if !shape(root, member, item, ancestors)? {
					return Ok(false);
				}
			} else if let Some(additional) = schema.get("additionalProperties") {
				if !shape(root, additional, item, ancestors)? {
					return Ok(false);
				}
			}
		}
	}
	if let Some(array) = value.as_array() {
		if schema
			.get("minItems")
			.and_then(Value::as_u64)
			.is_some_and(|n| (array.len() as u64) < n)
			|| schema
				.get("maxItems")
				.and_then(Value::as_u64)
				.is_some_and(|n| (array.len() as u64) > n)
		{
			return Ok(false);
		}
		if let Some(prefix) = schema.get("prefixItems") {
			for (item, member) in array
				.iter()
				.zip(prefix.as_array().context("Invalid prefixItems")?)
			{
				if !shape(root, member, item, ancestors)? {
					return Ok(false);
				}
			}
		}
	}
	Ok(true)
}

fn expanded<'s>(
	root: &'s Value,
	schema: &'s Value,
	value: &Value,
	ancestors: &mut Vec<*const Value>,
) -> Result<Vec<&'s Value>> {
	let identity = std::ptr::from_ref(schema);
	ensure!(
		!ancestors.contains(&identity),
		"Cyclic response-order schema reference"
	);
	ancestors.push(identity);
	let answer = (|| {
		if !shape_base(root, schema, value, &mut Vec::new())? {
			return Ok(Vec::new());
		}
		if let Some(name) = schema.get("$ref").and_then(Value::as_str) {
			return expanded(root, reference(root, name)?, value, ancestors);
		}
		for (name, exactly_one) in [("oneOf", true), ("anyOf", false)] {
			if let Some(choices) = schema.get(name) {
				let matching = choices
					.as_array()
					.context("Invalid schema union")?
					.iter()
					.map(|choice| Ok((choice, shape(root, choice, value, &mut Vec::new())?)))
					.collect::<Result<Vec<_>>>()?
					.into_iter()
					.filter_map(|(choice, yes)| yes.then_some(choice))
					.collect::<Vec<_>>();
				ensure!(
					!exactly_one || matching.len() <= 1,
					"Ambiguous response-order oneOf"
				);
				let mut output = Vec::new();
				for choice in matching {
					output.extend(expanded(root, choice, value, ancestors)?);
				}
				return Ok(output);
			}
		}
		Ok(vec![schema])
	})();
	ancestors.pop();
	answer
}

struct Located<'s, 'v> {
	candidates: Vec<&'s Value>,
	value: &'v Value,
}

fn locate<'s, 'v>(
	root: &'s Value,
	candidates: Vec<&'s Value>,
	value: &'v Value,
	path: &[PathComponent<'_>],
) -> Result<Located<'s, 'v>> {
	let mut candidates = candidates;
	let mut current = value;
	for part in path {
		let mut next = Vec::new();
		for schema in candidates {
			for schema in expanded(root, schema, current, &mut Vec::new())? {
				let member = match part {
					PathComponent::Key(key) => schema
						.get("properties")
						.and_then(|p| p.get(*key))
						.or_else(|| schema.get("additionalProperties"))
						.unwrap_or(&ANY_SCHEMA),
					PathComponent::Index(index) => schema
						.get("prefixItems")
						.and_then(Value::as_array)
						.and_then(|p| p.get(*index))
						.or_else(|| schema.get("items"))
						.unwrap_or(&ANY_SCHEMA),
				};
				next.push(member);
			}
		}
		current = match part {
			PathComponent::Key(key) => current.as_object().and_then(|v| v.get(*key)),
			PathComponent::Index(index) => current.as_array().and_then(|v| v.get(*index)),
		}
		.with_context(|| format!("Response-order value path is absent: {}", pointer(path)))?;
		candidates = next;
	}
	let mut final_candidates = Vec::new();
	for schema in candidates {
		final_candidates.extend(expanded(root, schema, current, &mut Vec::new())?);
	}
	ensure!(
		!final_candidates.is_empty(),
		"No admitted response-order schema at {}",
		pointer(path)
	);
	Ok(Located {
		candidates: final_candidates,
		value: current,
	})
}

fn keys_at<'a>(location: Located<'_, '_>, object: &'a Map<String, Value>) -> Result<Vec<&'a str>> {
	ensure!(
		location
			.value
			.as_object()
			.is_some_and(|value| std::ptr::eq(value, object)),
		"Response-order context does not own the serialized object"
	);
	let mut found: Option<Vec<&'a str>> = None;
	for schema in location.candidates {
		let order = if let Some(names) = schema.get("x-hepta-object-order") {
			let names = names
				.as_array()
				.context("Invalid original order annotation")?
				.iter()
				.map(|v| v.as_str().context("Non-string original order annotation"))
				.collect::<Result<Vec<_>>>()?;
			declared_keys(object, &names)?
		} else if object.is_empty() {
			// The empty object has exactly one possible order; no keys are guessed.
			Vec::new()
		} else {
			bail!("No authoritative original order for this object");
		};
		if let Some(previous) = &found {
			ensure!(
				previous == &order,
				"Ambiguous original response object order"
			);
		} else {
			found = Some(order);
		}
	}
	found.context("No applicable original response object order")
}

fn fixed<'a>(
	object: &'a Map<String, Value>,
	order: &[&str],
	required: bool,
) -> Result<Vec<&'a str>> {
	if required {
		ensure!(
			order.iter().all(|name| object.contains_key(*name)),
			"Known producer object is missing required fields"
		);
	}
	declared_keys(object, order)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordKind {
	Elf,
	Apk,
	ApkView,
}

fn record_kind(record: &Value) -> Result<RecordKind> {
	match record.get("operation").and_then(Value::as_str) {
		Some("inspect_elf_notes") => Ok(RecordKind::Elf),
		Some("inspect_apk_signature")
			if record
				.pointer("/normalized_result/parent_operation")
				.is_none() =>
		{
			Ok(RecordKind::Apk)
		}
		Some("inspect_analysis_view")
			if record
				.pointer("/normalized_result/parent_operation")
				.and_then(Value::as_str)
				== Some("inspect_apk_signature") =>
		{
			Ok(RecordKind::ApkView)
		}
		_ => bail!("Original response order is unsupported for this retained producer"),
	}
}

fn has_keys(path: &[PathComponent<'_>], names: &[&str]) -> bool {
	path.len() == names.len()
		&& path
			.iter()
			.zip(names)
			.all(|(part, name)| matches!(part,PathComponent::Key(key) if key==name))
}

impl ObjectOrder for RecordOrder<'_> {
	fn keys<'a>(
		&self,
		path: &[PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> Result<Vec<&'a str>> {
		let kind = record_kind(self.record)?;
		ensure!(
			matches!(
				(kind, self.origin),
				(RecordKind::Elf | RecordKind::Apk, RecordOrigin::NativeTool)
					| (
						RecordKind::ApkView,
						RecordOrigin::ApkToolDerived | RecordOrigin::AnalysisViewToolDerived
					)
			),
			"Missing or incompatible original producer provenance"
		);
		let all = schemas()?;
		let root = if kind == RecordKind::Elf {
			&all.elf
		} else {
			&all.apk
		};
		if has_keys(path, &["parameters"]) {
			let parameters = self
				.record
				.get("parameters")
				.and_then(Value::as_object)
				.context("Missing producer parameters")?;
			ensure!(
				std::ptr::eq(parameters, object),
				"Producer parameter context mismatch"
			);
			return fixed(
				object,
				match kind {
					RecordKind::Elf => &["path", "max_file_bytes", "max_entries"],
					RecordKind::Apk => &["path"],
					RecordKind::ApkView => &["parent_evidence_id", "view"],
				},
				true,
			);
		}
		if kind == RecordKind::ApkView
			&& path.len() >= 2
			&& has_keys(&path[..2], &["parameters", "view"])
		{
			let normalized = locate(
				root,
				vec![root],
				self.record,
				&[
					PathComponent::Key("normalized_result"),
					PathComponent::Key("view"),
				],
			)?;
			let view = self
				.record
				.pointer("/parameters/view")
				.context("Missing original view parameters")?;
			let keys = keys_at(
				locate(root, normalized.candidates, view, &path[2..])?,
				object,
			)?;
			if path.len() == 2 && self.origin == RecordOrigin::ApkToolDerived {
				// ApkSignatureService constructs { kind, ...view } and takes the
				// already-validated route. Direct inspect_analysis_view instead
				// parses apkSignatureViewRequestSchema, whose extend appends kind.
				return fixed(
					object,
					&[
						"kind",
						"ids",
						"schemes",
						"signer_ids",
						"offset",
						"limit",
						"collection",
						"fields",
					],
					false,
				);
			}
			return Ok(keys);
		}
		if kind == RecordKind::ApkView
			&& has_keys(path, &["normalized_result", "summary", "schemes"])
		{
			let schemes = self
				.record
				.pointer("/normalized_result/summary/schemes")
				.and_then(Value::as_object)
				.context("Missing APK summary schemes")?;
			ensure!(std::ptr::eq(schemes, object), "APK scheme context mismatch");
			return fixed(object, &["v1", "v2", "v3", "v3.1"], true);
		}
		keys_at(locate(root, vec![root], self.record, path)?, object)
	}
}

/// The original import reparses the fixed Evidence envelope, while generic
/// JSON members retain the exact acquired file's JavaScript property order.
/// This authority follows the immutable record; it is never caller metadata.
fn imported_record_keys<'a>(
	record: &Value,
	order: &rea_evidence_file::ObjectOrder,
	path: &[PathComponent<'_>],
	object: &'a Map<String, Value>,
) -> Result<Vec<&'a str>> {
	let root = &schemas()?.bundle;
	let schema = root
		.pointer("/$defs/__schema0/anyOf/0/properties/records/items")
		.context("Frozen Evidence schema is absent")?;
	let location = locate(root, vec![schema], record, path)?;
	if location
		.candidates
		.iter()
		.any(|schema| schema.get("x-hepta-object-order").is_some())
		|| object.is_empty()
	{
		return keys_at(location, object);
	}
	ensure!(
		location
			.value
			.as_object()
			.is_some_and(|value| std::ptr::eq(value, object)),
		"Imported order does not own the serialized object"
	);
	let path = path
		.iter()
		.map(|part| match part {
			PathComponent::Key(key) => Value::String((*key).to_owned()),
			PathComponent::Index(index) => serde_json::json!(index),
		})
		.collect::<Vec<_>>();
	let keys = order
		.keys(&path)
		.context("Imported JSON object order is absent")?;
	declared_keys(object, &keys.iter().map(String::as_str).collect::<Vec<_>>())
}

impl ObjectOrder for BundleOrder<'_> {
	fn keys<'a>(
		&self,
		path: &[PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> Result<Vec<&'a str>> {
		if path.is_empty() {
			return fixed(object, &["result"], true);
		}
		if has_keys(path, &["result"]) {
			return fixed(
				object,
				&[
					"artifacts",
					"providers",
					"environments",
					"scenarios",
					"captures",
					"unknowns",
					"records",
				],
				true,
			);
		}
		if path.len() >= 3 && has_keys(&path[..2], &["result", "records"]) {
			let PathComponent::Index(index) = path[2] else {
				bail!("Bundle records require an array index");
			};
			let record = self
				.records
				.get(index)
				.copied()
				.context("Bundle record index is out of range")?;
			let origin = self
				.origins
				.get(index)
				.copied()
				.context("Bundle record origin is absent")?;
			if let Some(order) = self
				.imported_orders
				.and_then(|orders| orders.get(index))
				.and_then(Option::as_deref)
			{
				return imported_record_keys(record, order, &path[3..], object);
			}
			return RecordOrder::new(record, origin).keys(&path[3..], object);
		}
		if path.len() >= 3 && has_keys(&path[..2], &["result", "unknowns"]) {
			let PathComponent::Index(index) = path[2] else {
				bail!("Bundle unknowns require an array index");
			};
			let unknown = self
				.unknowns
				.and_then(|unknowns| unknowns.get(index))
				.copied()
				.context("Bundle unknown index is out of range")?;
			let root = &schemas()?.bundle;
			let schema = root
				.pointer("/$defs/__schema0/anyOf/0/properties/unknowns/items")
				.context("Frozen unknown schema is absent")?;
			return keys_at(locate(root, vec![schema], unknown, &path[3..])?, object);
		}
		match path {
			[PathComponent::Key("result"), PathComponent::Key("artifacts"), PathComponent::Index(_)] => {
				fixed(object, &["digest", "format", "architecture"], true)
			}
			[PathComponent::Key("result"), PathComponent::Key("artifacts"), PathComponent::Index(_), PathComponent::Key("digest")] => {
				fixed(object, &["sha256"], true)
			}
			[PathComponent::Key("result"), PathComponent::Key("providers"), PathComponent::Index(_)] => {
				fixed(object, &["id", "name", "version"], true)
			}
			[PathComponent::Key("result"), PathComponent::Key("environments"), PathComponent::Index(_)] => {
				fixed(
					object,
					&["id", "platform", "architecture", "isolation"],
					true,
				)
			}
			[PathComponent::Key("result"), PathComponent::Key("scenarios"), PathComponent::Index(_)] => {
				fixed(object, &["evidence_id", "operation", "authority"], true)
			}
			[PathComponent::Key("result"), PathComponent::Key("captures"), PathComponent::Index(_)] => {
				fixed(object, &["evidence_id", "predicate_type"], true)
			}
			_ => bail!("No admitted bundle manifest order at {}", pointer(path)),
		}
	}
}

impl ObjectOrder for BundleSummaryOrder<'_> {
	fn keys<'a>(
		&self,
		path: &[PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> Result<Vec<&'a str>> {
		ensure!(
			self.0.pointer("/result/kind").and_then(Value::as_str)
				== Some("evidence-bundle-summary"),
			"BundleSummaryOrder requires the summary result wrapper"
		);
		if has_keys(path, &["result", "filters"]) {
			let filters = self
				.0
				.pointer("/result/filters")
				.and_then(Value::as_object)
				.context("Missing bundle filters")?;
			ensure!(
				std::ptr::eq(filters, object),
				"Bundle filter context mismatch"
			);
			return fixed(
				object,
				&[
					"evidence_id",
					"operation",
					"target_sha256",
					"analysis_profile_digest",
					"procedure_address",
				],
				false,
			);
		}
		let root = &schemas()?.bundle;
		keys_at(locate(root, vec![root], self.0, path)?, object)
	}
}

#[cfg(test)]
#[path = "rea_response_order_tests.rs"]
mod tests;
