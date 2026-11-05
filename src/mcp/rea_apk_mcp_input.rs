// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Frozen REA 6.8.0 APK MCP schema diagnostics. This layer validates the
//! advertised input before file access; service defaults and typed filesystem
//! errors remain the APK service's responsibility. Whole non-object arguments
//! are rejected by the raw MCP protocol boundary before reaching this module.
//!
//! The declaration order and abort behavior are observable: bounds/regex
//! failures permit superRefine, while type/enum/discriminator/unknown-key
//! failures prevent it. Public Node MCP goldens cover their combinations.

use super::rea_contract::Failure;
use serde_json::{json, Map, Value};
use std::collections::HashSet;

const OPERATION: &str = "inspect_apk_signature";
const SCHEMES: &[&str] = &["v1", "v2", "v3", "v3.1"];
const SIGNER_FIELDS: &[&str] = &[
	"id",
	"scheme",
	"index",
	"certificate",
	"certificate_sha256",
	"signatures",
	"public_key_bytes",
	"uninterpreted_signed_data_bytes",
	"uninterpreted_signer_bytes",
	"min_sdk",
	"max_sdk",
	"signature_file",
	"block_file",
	"signer_infos",
	"decode_error",
];
const DIGEST_FIELDS: &[&str] = &[
	"uninterpreted_bytes",
	"signature_algorithm_id",
	"algorithm",
	"declared_digest_hex",
	"matches_apk",
	"id",
	"scheme",
	"index",
	"signer_id",
	"signer_index",
];
const LINEAGE_FIELDS: &[&str] = &[
	"certificate",
	"flags",
	"capabilities",
	"id",
	"scheme",
	"index",
	"signer_id",
	"signer_index",
	"previous_id",
	"certificate_sha256",
];
const VIEW_KEYS: &[&str] = &[
	"ids",
	"schemes",
	"signer_ids",
	"offset",
	"limit",
	"collection",
	"fields",
];

#[derive(Default)]
struct Issues {
	messages: Vec<String>,
	aborted: bool,
}

impl Issues {
	fn add(&mut self, message: String, abort: bool) {
		self.messages.push(message);
		self.aborted |= abort;
	}

	fn invalid_type(&mut self, path: &str, expected: &str, value: Option<&Value>) {
		self.add(
			format!(
				"{path}: Invalid input: expected {expected}, received {}",
				received(value)
			),
			true,
		);
	}

	fn finish(self) -> Result<(), Failure> {
		if self.messages.is_empty() {
			return Ok(());
		}
		let mut failure = Failure::input(
			OPERATION,
			vec![json!({
				"path": [], "reason": "invalid_value", "message": self.messages.join(", ")
			})],
		);
		failure.0["message"] = json!(format!(
			"The arguments for MCP tool {OPERATION} do not match its advertised input schema."
		));
		Err(failure)
	}
}

fn received(value: Option<&Value>) -> &'static str {
	match value {
		None => "undefined",
		Some(Value::Null) => "null",
		Some(Value::Bool(_)) => "boolean",
		Some(Value::Number(_)) => "number",
		Some(Value::String(_)) => "string",
		Some(Value::Array(_)) => "array",
		Some(Value::Object(_)) => "object",
	}
}

fn path(value: Option<&Value>, issues: &mut Issues) {
	let Some(text) = value.and_then(Value::as_str) else {
		issues.invalid_type("path", "string", value);
		// This additional length issue on [] is actual frozen Zod behavior.
		if value.is_some_and(|value| value.as_array().is_some_and(Vec::is_empty)) {
			issues.add(
				"path: Too small: expected array to have >=1 items".into(),
				false,
			);
		}
		return;
	};
	if text.is_empty() {
		issues.add(
			"path: Too small: expected string to have >=1 characters".into(),
			false,
		);
	}
	if text.contains('\0') {
		issues.add(
			"path: Local filesystem paths cannot contain NUL".into(),
			false,
		);
	}
	if !text.starts_with('/') {
		issues.add(
			"path: must be an absolute local filesystem path".into(),
			false,
		);
	}
}

fn choice(value: &Value, path: &str, allowed: &[&str], issues: &mut Issues) {
	if !value.as_str().is_some_and(|text| allowed.contains(&text)) {
		let options = allowed
			.iter()
			.map(|text| format!("\"{text}\""))
			.collect::<Vec<_>>()
			.join("|");
		issues.add(
			format!("{path}: Invalid option: expected one of {options}"),
			true,
		);
	}
}

fn strings(value: Option<&Value>, path: &str, allowed: Option<&[&str]>, issues: &mut Issues) {
	let Some(value) = value else { return };
	let Some(array) = value.as_array() else {
		issues.invalid_type(path, "array", Some(value));
		return;
	};
	for (index, value) in array.iter().enumerate() {
		let item_path = format!("{path}.{index}");
		if let Some(allowed) = allowed {
			choice(value, &item_path, allowed, issues);
		} else if !value.is_string() {
			issues.invalid_type(&item_path, "string", Some(value));
		}
	}
}

fn position(value: Option<&Value>, path: &str, positive: bool, issues: &mut Issues) {
	let Some(value) = value else { return };
	let Some(number) = value.as_f64() else {
		issues.invalid_type(path, "number", Some(value));
		return;
	};
	if number.fract() != 0.0 {
		issues.add(
			format!("{path}: Invalid input: expected int, received number"),
			true,
		);
		return;
	}
	if number > 9_007_199_254_740_991.0 {
		issues.add(
			format!("{path}: Too big: expected int to be <=9007199254740991"),
			false,
		);
	}
	if number < -9_007_199_254_740_991.0 {
		issues.add(
			format!("{path}: Too small: expected int to be >=-9007199254740991"),
			false,
		);
	}
	if positive && number <= 0.0 {
		issues.add(
			format!("{path}: Too small: expected number to be >0"),
			false,
		);
	} else if !positive && number < 0.0 {
		issues.add(
			format!("{path}: Too small: expected number to be >=0"),
			false,
		);
	}
}

fn unknown(
	map: &Map<String, Value>,
	allowed: &[&str],
	path: &str,
	order: Option<&[String]>,
	issues: &mut Issues,
) {
	let mut keys = Vec::new();
	let mut seen = HashSet::new();
	if let Some(order) = order {
		for key in order {
			if map.contains_key(key)
				&& !allowed.contains(&key.as_str())
				&& seen.insert(key.as_str())
			{
				keys.push(key.as_str());
			}
		}
	}
	// Ordering metadata can never authorize a key. A missing/incomplete internal
	// hint falls back to the actual map and still rejects every unknown property.
	for key in map.keys() {
		if !allowed.contains(&key.as_str()) && seen.insert(key.as_str()) {
			keys.push(key.as_str());
		}
	}
	if keys.is_empty() {
		return;
	}
	// The frozen formatter quotes names literally, including embedded quotes,
	// backslashes and newlines. JSON encoding of the enclosing error is separate.
	let quoted = keys
		.iter()
		.map(|key| format!("\"{key}\""))
		.collect::<Vec<_>>()
		.join(", ");
	let prefix = if path.is_empty() {
		String::new()
	} else {
		format!("{path}: ")
	};
	let noun = if keys.len() == 1 { "key" } else { "keys" };
	issues.add(format!("{prefix}Unrecognized {noun}: {quoted}"), true);
}

fn view(value: &Value, order: Option<&[String]>, issues: &mut Issues) {
	let Some(map) = value.as_object() else {
		issues.invalid_type("view", "object", Some(value));
		return;
	};
	let fields = match map.get("collection").and_then(Value::as_str) {
		Some("signers") => SIGNER_FIELDS,
		Some("digests") => DIGEST_FIELDS,
		Some("lineage") => LINEAGE_FIELDS,
		_ => {
			issues.add("view.collection: Invalid discriminator value. Expected 'signers' | 'digests' | 'lineage'".into(), true);
			return;
		}
	};
	// Match the source shape declaration, not the alphabetized JSON Schema.
	strings(map.get("ids"), "view.ids", None, issues);
	strings(map.get("schemes"), "view.schemes", Some(SCHEMES), issues);
	strings(map.get("signer_ids"), "view.signer_ids", None, issues);
	position(map.get("offset"), "view.offset", false, issues);
	position(map.get("limit"), "view.limit", true, issues);
	strings(map.get("fields"), "view.fields", Some(fields), issues);
	unknown(map, VIEW_KEYS, "view", order, issues);
}

pub(super) fn validate(
	raw: &Value,
	argument_keys: Option<&[String]>,
	view_keys: Option<&[String]>,
) -> Result<(), Failure> {
	let empty = Map::new();
	let map = raw.as_object().unwrap_or(&empty);
	let mut issues = Issues::default();
	path(map.get("path"), &mut issues);
	if let Some(detail) = map.get("detail") {
		choice(detail, "detail", &["summary", "complete"], &mut issues);
	}
	if let Some(value) = map.get("view") {
		view(value, view_keys, &mut issues);
	}
	unknown(
		map,
		&["path", "detail", "view"],
		"",
		argument_keys,
		&mut issues,
	);
	if !issues.aborted
		&& map.get("detail").is_some_and(|value| value == "complete")
		&& map.contains_key("view")
	{
		issues.add(
			"view: view requires summary delivery; omit it for complete Evidence".into(),
			false,
		);
	}
	issues.finish()
}

#[cfg(test)]
#[path = "rea_apk_mcp_input_tests.rs"]
mod tests;
