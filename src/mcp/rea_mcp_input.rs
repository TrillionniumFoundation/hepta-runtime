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

//! Frozen MCP argument-error projection. This is separate from service input
//! validation: the upstream MCP boundary aggregates schema diagnostics into
//! one correction issue, while application errors retain their field paths.

use super::rea_contract::Failure;
use serde_json::{json, Map, Value};

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

fn string(value: Option<&Value>, path: &str, nonempty: bool, errors: &mut Vec<String>) -> bool {
	if !value.is_some_and(Value::is_string) {
		errors.push(format!(
			"{path}: Invalid input: expected string, received {}",
			received(value)
		));
		// Zod's min-length check also reports an empty array after the type
		// diagnostic. This observable behavior was captured over real MCP.
		if nonempty && value.is_some_and(|v| v.as_array().is_some_and(Vec::is_empty)) {
			errors.push(format!(
				"{path}: Too small: expected array to have >=1 items"
			));
		}
		return false;
	}
	if nonempty && value.and_then(Value::as_str) == Some("") {
		errors.push(format!(
			"{path}: Too small: expected string to have >=1 characters"
		));
	}
	true
}

fn integer(
	value: Option<&Value>,
	path: &str,
	minimum: u64,
	maximum: u64,
	errors: &mut Vec<String>,
) {
	let Some(value) = value else {
		return;
	};
	let Some(number) = value.as_f64() else {
		errors.push(format!(
			"{path}: Invalid input: expected number, received {}",
			received(Some(value))
		));
		return;
	};
	if number.fract() != 0.0 {
		errors.push(format!(
			"{path}: Invalid input: expected int, received number"
		));
		return;
	}
	if number > 9_007_199_254_740_991.0 {
		errors.push(format!(
			"{path}: Too big: expected int to be <=9007199254740991"
		));
	}
	if number < -9_007_199_254_740_991.0 {
		errors.push(format!(
			"{path}: Too small: expected int to be >=-9007199254740991"
		));
	}
	if number < minimum as f64 {
		errors.push(format!(
			"{path}: Too small: expected number to be >={minimum}"
		));
	}
	if number > maximum as f64 {
		errors.push(format!(
			"{path}: Too big: expected number to be <={maximum}"
		));
	}
}

fn unknown(
	map: &Map<String, Value>,
	allowed: &[&str],
	prefix: &str,
	order: Option<&[String]>,
	errors: &mut Vec<String>,
) {
	let keys: Vec<&str> = match order {
		Some(keys) => keys
			.iter()
			.map(String::as_str)
			.filter(|key| map.contains_key(*key) && !allowed.contains(key))
			.collect(),
		None => map
			.keys()
			.map(String::as_str)
			.filter(|key| !allowed.contains(key))
			.collect(),
	};
	if keys.is_empty() {
		return;
	}
	let names = keys
		.iter()
		.map(|key| format!("\"{key}\""))
		.collect::<Vec<_>>()
		.join(", ");
	let lead = if prefix.is_empty() {
		String::new()
	} else {
		format!("{prefix}: ")
	};
	let noun = if keys.len() == 1 { "key" } else { "keys" };
	errors.push(format!("{lead}Unrecognized {noun}: {names}"));
}

fn finish(operation: &str, errors: Vec<String>) -> Result<(), Failure> {
	if errors.is_empty() {
		return Ok(());
	}
	let mut failure = Failure::input(
		operation,
		vec![json!({"path":[],"reason":"invalid_value","message":errors.join(", ")})],
	);
	failure.0["message"] = json!(format!(
		"The arguments for MCP tool {operation} do not match its advertised input schema."
	));
	Err(failure)
}

pub(super) fn elf(raw: &Value) -> Result<(), Failure> {
	elf_ordered(raw, None)
}

pub(super) fn elf_ordered(raw: &Value, argument_keys: Option<&[String]>) -> Result<(), Failure> {
	let empty = Map::new();
	let map = raw.as_object().unwrap_or(&empty);
	let mut errors = Vec::new();
	if string(map.get("path"), "path", true, &mut errors)
		&& map["path"].as_str().is_some_and(|path| path.contains('\0'))
	{
		errors.push("path: Local filesystem paths cannot contain NUL".to_owned());
	}
	integer(
		map.get("max_file_bytes"),
		"max_file_bytes",
		64,
		536_870_912,
		&mut errors,
	);
	integer(map.get("max_entries"), "max_entries", 1, 256, &mut errors);
	unknown(
		map,
		&["path", "max_file_bytes", "max_entries"],
		"",
		argument_keys,
		&mut errors,
	);
	finish("inspect_elf_notes", errors)
}

pub(super) fn bundle(raw: &Value) -> Result<(), Failure> {
	bundle_ordered(raw, None, None)
}

pub(super) fn bundle_ordered(
	raw: &Value,
	argument_keys: Option<&[String]>,
	filter_keys: Option<&[String]>,
) -> Result<(), Failure> {
	let empty = Map::new();
	let map = raw.as_object().unwrap_or(&empty);
	let mut errors = Vec::new();
	if map
		.get("detail")
		.is_some_and(|value| value != "complete" && value != "summary")
	{
		errors.push("detail: Invalid option: expected one of \"complete\"|\"summary\"".to_owned());
	}
	if let Some(filters) = map.get("filters") {
		if let Some(filters) = filters.as_object() {
			for key in [
				"evidence_id",
				"operation",
				"target_sha256",
				"analysis_profile_digest",
				"procedure_address",
			] {
				let Some(value) = filters.get(key) else {
					continue;
				};
				let path = format!("filters.{key}");
				let nonempty = matches!(key, "operation" | "procedure_address");
				if !string(Some(value), &path, nonempty, &mut errors) || nonempty {
					continue;
				}
				let prefix = if key == "evidence_id" { "ev_" } else { "" };
				let valid = value
					.as_str()
					.and_then(|text| text.strip_prefix(prefix))
					.is_some_and(|tail| {
						tail.len() == 64
							&& tail
								.bytes()
								.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
					});
				if !valid {
					errors.push(if key == "evidence_id" {
						format!("{path}: Expected a ev_ prefixed lowercase sha256 digest")
					} else {
						format!("{path}: Invalid string: must match pattern /^[a-f0-9]{{64}}$/u")
					});
				}
			}
			unknown(
				filters,
				&[
					"evidence_id",
					"operation",
					"target_sha256",
					"analysis_profile_digest",
					"procedure_address",
				],
				"filters",
				filter_keys,
				&mut errors,
			);
		} else {
			errors.push(format!(
				"filters: Invalid input: expected object, received {}",
				received(Some(filters))
			));
		}
	}
	unknown(map, &["detail", "filters"], "", argument_keys, &mut errors);
	finish("get_evidence_bundle", errors)
}
