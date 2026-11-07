// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Frozen HIA tool schemas and bounded validation at both process boundaries.
//!
//! The admitted catalog uses a deliberately small JSON Schema vocabulary. An
//! unknown keyword is a build-time contract error, never an ignored constraint.
//! Input is checked before a job is admitted; output is checked before a worker
//! report can become an MCP result. This is not a HIA semantic verifier.

use anyhow::{bail, Context, Result};
use regex::Regex;
use rmcp::model::{CallToolResult, ContentBlock, JsonObject};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

pub(super) const CATALOG_BYTES: &[u8] = include_bytes!("hia_tool_catalog.json");
pub(super) const CONTRACT_VERSION: &str = "hepta.hia.agent-native.v1";
pub(super) const MAX_WORKER_BYTES: usize = 512 * 1024;
pub(super) const TOOLS: &[&str] = &[
	"hia_describe",
	"hia_artifact",
	"hia_read",
	"hia_context",
	"hia_inspect",
	"hia_candidate",
	"hia_verify",
	"hia_emit",
	"hia_evaluate",
	"hia_adopt",
	"hia_rollback",
];

struct ToolSchemas {
	input: Arc<JsonObject>,
	output: Arc<JsonObject>,
}

struct Catalog {
	tools: BTreeMap<String, ToolSchemas>,
	patterns: BTreeMap<String, Regex>,
}

fn catalog() -> &'static Catalog {
	static CATALOG: OnceLock<Catalog> = OnceLock::new();
	CATALOG.get_or_init(|| {
		let source: Value =
			serde_json::from_slice(CATALOG_BYTES).expect("embedded HIA catalog JSON");
		let mut patterns = BTreeMap::new();
		let mut tools = BTreeMap::new();
		for tool in source["tools"].as_array().expect("embedded HIA tool array") {
			let name = tool["name"].as_str().expect("embedded HIA tool name");
			assert!(TOOLS.contains(&name), "unregistered embedded HIA tool");
			for kind in ["inputSchema", "outputSchema"] {
				validate_vocabulary(&tool[kind], &mut patterns)
					.expect("unsupported embedded HIA schema vocabulary");
			}
			let schemas = ToolSchemas {
				input: Arc::new(
					tool["inputSchema"]
						.as_object()
						.expect("HIA input object")
						.clone(),
				),
				output: Arc::new(
					tool["outputSchema"]
						.as_object()
						.expect("HIA output object")
						.clone(),
				),
			};
			assert!(
				tools.insert(name.to_owned(), schemas).is_none(),
				"duplicate HIA tool"
			);
		}
		assert_eq!(tools.len(), TOOLS.len(), "incomplete embedded HIA catalog");
		Catalog { tools, patterns }
	})
}

pub(super) fn sha256(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

pub(super) fn catalog_sha256() -> String {
	sha256(CATALOG_BYTES)
}

pub(super) fn input_schema(name: &str) -> Arc<JsonObject> {
	catalog()
		.tools
		.get(name)
		.map(|t| Arc::clone(&t.input))
		.unwrap_or_else(|| Arc::new(Map::from_iter([("not".into(), json!({}))])))
}

pub(super) fn output_schema(name: &str) -> Arc<JsonObject> {
	catalog()
		.tools
		.get(name)
		.map(|t| Arc::clone(&t.output))
		.unwrap_or_else(|| Arc::new(Map::from_iter([("not".into(), json!({}))])))
}

fn validate_vocabulary(schema: &Value, patterns: &mut BTreeMap<String, Regex>) -> Result<()> {
	if schema.is_boolean() {
		return Ok(());
	}
	let fields = schema
		.as_object()
		.context("schema must be object or boolean")?;
	for (key, value) in fields {
		match key.as_str() {
			"$schema" | "description" | "type" | "const" | "enum" | "required" | "minimum"
			| "maximum" | "minLength" | "maxLength" | "minItems" | "maxItems" | "uniqueItems" => {}
			"pattern" => {
				let pattern = value.as_str().context("schema pattern must be text")?;
				patterns.insert(pattern.into(), Regex::new(pattern)?);
			}
			"properties" => {
				for subschema in value
					.as_object()
					.context("properties must be object")?
					.values()
				{
					validate_vocabulary(subschema, patterns)?;
				}
			}
			"additionalProperties" | "items" | "contains" | "not" | "if" | "then" => {
				validate_vocabulary(value, patterns)?;
			}
			"oneOf" | "anyOf" | "allOf" => {
				for subschema in value
					.as_array()
					.context("schema alternatives must be array")?
				{
					validate_vocabulary(subschema, patterns)?;
				}
			}
			_ => bail!("unimplemented HIA schema keyword: {key}"),
		}
	}
	Ok(())
}

fn matches_type(value: &Value, kind: &str) -> bool {
	match kind {
		"object" => value.is_object(),
		"array" => value.is_array(),
		"string" => value.is_string(),
		"boolean" => value.is_boolean(),
		"null" => value.is_null(),
		"integer" => {
			value.as_i64().is_some()
				|| value.as_u64().is_some()
				|| value
					.as_f64()
					.is_some_and(|number| number.is_finite() && number.fract() == 0.0)
		}
		"number" => value.is_number(),
		_ => false,
	}
}

fn check(schema: &Value, value: &Value, path: &str, depth: usize) -> Result<()> {
	if depth > 64 {
		bail!("HIA schema validation depth exceeded");
	}
	if let Some(allow) = schema.as_bool() {
		if !allow {
			bail!("{path}: value is forbidden");
		}
		return Ok(());
	}
	let rule = schema.as_object().context("invalid embedded HIA schema")?;
	if let Some(kind) = rule.get("type") {
		let valid = kind.as_str().is_some_and(|kind| matches_type(value, kind))
			|| kind.as_array().is_some_and(|kinds| {
				kinds
					.iter()
					.any(|kind| kind.as_str().is_some_and(|kind| matches_type(value, kind)))
			});
		if !valid {
			bail!("{path}: unexpected JSON type");
		}
	}
	if rule.get("const").is_some_and(|expected| expected != value) {
		bail!("{path}: value differs from the required constant");
	}
	if let Some(choices) = rule.get("enum").and_then(Value::as_array) {
		if !choices.contains(value) {
			bail!("{path}: unsupported value");
		}
	}
	for kind in ["oneOf", "anyOf", "allOf"] {
		if let Some(choices) = rule.get(kind).and_then(Value::as_array) {
			let matched = choices
				.iter()
				.filter(|choice| check(choice, value, path, depth + 1).is_ok())
				.count();
			if (kind == "oneOf" && matched != 1)
				|| (kind == "anyOf" && matched == 0)
				|| (kind == "allOf" && matched != choices.len())
			{
				bail!("{path}: {kind} constraints are not satisfied");
			}
		}
	}
	if let Some(forbidden) = rule.get("not") {
		if check(forbidden, value, path, depth + 1).is_ok() {
			bail!("{path}: forbidden field combination");
		}
	}
	if let Some(condition) = rule.get("if") {
		if check(condition, value, path, depth + 1).is_ok() {
			if let Some(consequence) = rule.get("then") {
				check(consequence, value, path, depth + 1)?;
			}
		}
	}
	if let Some(object) = value.as_object() {
		if let Some(required) = rule.get("required").and_then(Value::as_array) {
			for key in required {
				let key = key.as_str().context("invalid embedded required key")?;
				if !object.contains_key(key) {
					bail!("{path}.{key}: required field is absent");
				}
			}
		}
		let properties = rule.get("properties").and_then(Value::as_object);
		for (key, item) in object {
			if let Some(subschema) = properties.and_then(|props| props.get(key)) {
				check(subschema, item, &format!("{path}.{key}"), depth + 1)?;
			} else if let Some(other) = rule.get("additionalProperties") {
				check(other, item, &format!("{path}.{key}"), depth + 1)?;
			}
		}
	}
	if let Some(items) = value.as_array() {
		for (key, lower) in [("minItems", true), ("maxItems", false)] {
			if let Some(bound) = rule.get(key).and_then(Value::as_u64) {
				if (lower && (items.len() as u64) < bound)
					|| (!lower && (items.len() as u64) > bound)
				{
					bail!("{path}: array length is outside its bound");
				}
			}
		}
		if rule.get("uniqueItems") == Some(&Value::Bool(true)) {
			for (index, item) in items.iter().enumerate() {
				if items[..index].contains(item) {
					bail!("{path}: repeated array item");
				}
			}
		}
		if let Some(item_schema) = rule.get("items") {
			for (index, item) in items.iter().enumerate() {
				check(item_schema, item, &format!("{path}[{index}]"), depth + 1)?;
			}
		}
		if let Some(contains) = rule.get("contains") {
			if !items
				.iter()
				.any(|item| check(contains, item, path, depth + 1).is_ok())
			{
				bail!("{path}: required array member is absent");
			}
		}
	}
	if let Some(text) = value.as_str() {
		for (key, lower) in [("minLength", true), ("maxLength", false)] {
			if let Some(bound) = rule.get(key).and_then(Value::as_u64) {
				let count = text.chars().count() as u64;
				if (lower && count < bound) || (!lower && count > bound) {
					bail!("{path}: string length is outside its bound");
				}
			}
		}
		if let Some(pattern) = rule.get("pattern").and_then(Value::as_str) {
			if !catalog()
				.patterns
				.get(pattern)
				.is_some_and(|pattern| pattern.is_match(text))
			{
				bail!("{path}: string does not match its declared pattern");
			}
			// JSON numbers cannot losslessly represent every generation. The
			// protocol uses decimal strings and still rejects values above u64.
			if pattern == "^(0|[1-9][0-9]{0,19})$" && text.parse::<u64>().is_err() {
				bail!("{path}: unsigned decimal exceeds u64");
			}
		}
	}
	if let Some(number) = value.as_f64() {
		if rule
			.get("minimum")
			.and_then(Value::as_f64)
			.is_some_and(|min| number < min)
			|| rule
				.get("maximum")
				.and_then(Value::as_f64)
				.is_some_and(|max| number > max)
		{
			bail!("{path}: number is outside its bound");
		}
	}
	Ok(())
}

pub(super) fn validate_input(tool: &str, arguments: &Value) -> Result<()> {
	if tool == "hia_resource_read" {
		let fields = arguments
			.as_object()
			.context("resource arguments must be an object")?;
		if fields
			.keys()
			.any(|key| !matches!(key.as_str(), "uri" | "max_bytes"))
		{
			bail!("unknown HIA resource argument");
		}
		let uri = fields
			.get("uri")
			.and_then(Value::as_str)
			.context("HIA resource URI absent")?;
		if !valid_uri(uri) {
			bail!("invalid HIA artifact URI");
		}
		if fields.get("max_bytes").is_some_and(|size| {
			!size
				.as_u64()
				.is_some_and(|size| (512..=65536).contains(&size))
		}) {
			bail!("HIA resource page bound must be 512..65536");
		}
		return Ok(());
	}
	let schema = catalog().tools.get(tool).context("unregistered HIA tool")?;
	check(
		&Value::Object(schema.input.as_ref().clone()),
		arguments,
		"arguments",
		0,
	)?;
	// JSON escaping can expand a legal 65,536-character capture beyond 256 KiB.
	// The provider separately bounds the complete bound worker envelope.
	if serde_json::to_vec(arguments)?.len() > MAX_WORKER_BYTES {
		bail!("HIA arguments exceed the admitted serialized bound");
	}
	Ok(())
}

pub(super) fn validate_output(tool: &str, result: &Value) -> Result<()> {
	let name = if tool == "hia_resource_read" {
		"hia_read"
	} else {
		tool
	};
	let schema = catalog()
		.tools
		.get(name)
		.context("unregistered HIA result")?;
	check(
		&Value::Object(schema.output.as_ref().clone()),
		result,
		"response",
		0,
	)
}

pub(super) fn valid_uri(uri: &str) -> bool {
	uri.strip_prefix("hia://artifacts/").is_some_and(|suffix| {
		!suffix.is_empty()
			&& suffix.len() <= 192
			&& suffix.as_bytes()[0].is_ascii_alphanumeric()
			&& suffix
				.bytes()
				.all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
	})
}

pub(super) fn wire(response: Value) -> Result<CallToolResult> {
	let text = serde_json::to_string(&response)?;
	let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
	result.is_error = Some(matches!(
		response["status"].as_str(),
		Some("rejected" | "unknown")
	));
	result.structured_content = Some(response);
	if serde_json::to_vec(&result)?.len() > crate::utils::truncation::MAX_RESULT_BYTES {
		bail!("HIA serialized MCP response exceeds the runtime limit");
	}
	Ok(result)
}

#[cfg(test)]
#[path = "hia_contract_tests.rs"]
mod tests;
