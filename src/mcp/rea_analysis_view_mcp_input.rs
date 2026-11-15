// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Frozen analysis-view input projection for the summary/APK contract slice.
//!
//! Actual public MCP returns ordinary structured AnalysisInputError issues for
//! this tool, not the APK tool's SDK diagnostic string. The issue order follows
//! source, view, then unknown root fields. Order hints cannot authorize keys.
//!
//! This module never reads a file, resolves a retained ID, or authenticates an
//! inline record. `InlineEvidencePending` requires the shared Evidence validator
//! before use. Its nested record issues must be prefixed with source/evidence.
//! A recognized but unimplemented view kind is an explicit capability gap; it
//! is neither successful validation nor an invented upstream schema rejection.

use super::rea_contract::Failure;
use serde_json::{json, Map, Value};
use std::collections::HashSet;

const OPERATION: &str = "inspect_analysis_view";
const SOURCE_KINDS: &[&str] = &["retained-evidence", "inline", "evidence-file"];
// Frozen source declaration order, independently observed in MCP diagnostics.
const VIEW_KINDS: &[&str] = &[
	"devicetree",
	"beam",
	"python-pyc",
	"native-exports",
	"javascript-routes",
	"function-matches",
	"source-to-bundle",
	"summary",
	"go",
	"rust",
	"desktop-application",
	"facet",
	"item",
	"page",
	"javascript",
	"javascript-facts",
	"native",
	"native-inventory",
	"inventory",
	"wasm",
	"macho",
	"interface-builder",
	"evm",
	"managed",
	"managed-members",
	"android",
	"api-surface",
	"environment-manifest",
	"environment-state",
	"environment-coverage",
	"capture",
	"protobuf",
	"qlog",
	"pcap",
	"dart-aot",
	"il2cpp-metadata",
	"apk-signature",
	"model-artifact",
	"gpu-code-objects",
];
const SCHEMES: &[&str] = &["v1", "v2", "v3", "v3.1"];
const COLLECTIONS: &[&str] = &["signers", "digests", "lineage"];
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

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Validation {
	/// Outer schema passed. Retained lookup/file acquisition is still required.
	Supported,
	/// Outer schema passed, but the complete inline record is not authenticated.
	InlineEvidencePending,
	/// This kind exists upstream, but its view shape has not been validated here.
	CapabilityGap { kind: String },
}

fn issue(path: &[Value], reason: &str, expected: Value) -> Value {
	json!({"path":path, "reason":reason, "expected":expected})
}

fn missing_or_type(value: Option<&Value>, path: &[Value], expected: &str) -> Value {
	issue(
		path,
		if value.is_none() {
			"missing_argument"
		} else {
			"invalid_type"
		},
		json!(expected),
	)
}

fn object<'a>(
	value: Option<&'a Value>,
	path: &[Value],
	issues: &mut Vec<Value>,
) -> Option<&'a Map<String, Value>> {
	match value.and_then(Value::as_object) {
		Some(map) => Some(map),
		None => {
			issues.push(missing_or_type(value, path, "object"));
			None
		}
	}
}

fn discriminator<'a>(
	value: Option<&'a Value>,
	path: &[Value],
	allowed: &[&str],
	issues: &mut Vec<Value>,
) -> Option<&'a str> {
	match value
		.and_then(Value::as_str)
		.filter(|text| allowed.contains(text))
	{
		Some(text) => Some(text),
		None => {
			issues.push(issue(
				path,
				if value.is_none() {
					"missing_argument"
				} else {
					"invalid_value"
				},
				json!(allowed),
			));
			None
		}
	}
}

fn unknown(
	map: &Map<String, Value>,
	allowed: &[&str],
	path: &[Value],
	order: Option<&[String]>,
	issues: &mut Vec<Value>,
) {
	let mut seen = HashSet::new();
	for key in order.into_iter().flatten().chain(map.keys()) {
		if !map.contains_key(key) || allowed.contains(&key.as_str()) || !seen.insert(key.as_str()) {
			continue;
		}
		let mut nested = path.to_vec();
		nested.push(json!(key));
		issues.push(json!({"path":nested,"reason":"unknown_argument"}));
	}
}

fn evidence_id(value: Option<&Value>, path: &[Value], issues: &mut Vec<Value>) {
	let Some(text) = value.and_then(Value::as_str) else {
		issues.push(missing_or_type(value, path, "string"));
		return;
	};
	if text.len() != 67
		|| !text.starts_with("ev_")
		|| !text.as_bytes()[3..]
			.iter()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
	{
		issues.push(
			json!({"path":path,"reason":"invalid_format","expected":"regex",
            "message":"Expected a ev_ prefixed lowercase sha256 digest"}),
		);
	}
}

fn file_path(value: Option<&Value>, issues: &mut Vec<Value>) {
	let path = [json!("source"), json!("path")];
	let Some(text) = value.and_then(Value::as_str) else {
		issues.push(missing_or_type(value, &path, "string"));
		// The shared frozen string/min parser also reports the bound for [].
		if value.is_some_and(|v| v.as_array().is_some_and(Vec::is_empty)) {
			issues.push(json!({"path":path,"reason":"out_of_range","minimum":1}));
		}
		return;
	};
	if text.is_empty() {
		issues.push(json!({"path":path,"reason":"out_of_range","minimum":1}));
	}
	if text.contains('\0') {
		issues.push(json!({"path":path,"reason":"invalid_format","expected":"regex","message":"Local filesystem paths cannot contain NUL"}));
	}
	if !text.starts_with('/') {
		issues.push(json!({"path":path,"reason":"invalid_format","expected":"regex","message":"must be an absolute local filesystem path"}));
	}
}

fn source(value: Option<&Value>, order: Option<&[String]>, issues: &mut Vec<Value>) -> bool {
	let prefix = [json!("source")];
	let Some(map) = object(value, &prefix, issues) else {
		return false;
	};
	let Some(kind) = discriminator(
		map.get("kind"),
		&[json!("source"), json!("kind")],
		SOURCE_KINDS,
		issues,
	) else {
		return false;
	};
	let mut pending = false;
	match kind {
		"retained-evidence" => {
			evidence_id(
				map.get("evidence_id"),
				&[json!("source"), json!("evidence_id")],
				issues,
			);
			unknown(map, &["kind", "evidence_id"], &prefix, order, issues);
		}
		"evidence-file" => {
			file_path(map.get("path"), issues);
			if map.contains_key("evidence_id") {
				evidence_id(
					map.get("evidence_id"),
					&[json!("source"), json!("evidence_id")],
					issues,
				);
			}
			unknown(
				map,
				&["kind", "path", "evidence_id"],
				&prefix,
				order,
				issues,
			);
		}
		"inline" => {
			let path = [json!("source"), json!("evidence")];
			match map.get("evidence") {
				None => issues.push(missing_or_type(None, &path, "nonoptional")),
				Some(Value::Object(_)) => pending = true,
				value => issues.push(missing_or_type(value, &path, "object")),
			}
			unknown(map, &["kind", "evidence"], &prefix, order, issues);
		}
		_ => unreachable!("validated source discriminator"),
	}
	pending
}

fn array(value: Option<&Value>, field: &str, allowed: Option<&[&str]>, issues: &mut Vec<Value>) {
	let Some(value) = value else {
		return;
	};
	let path = [json!("view"), json!(field)];
	let Some(items) = value.as_array() else {
		issues.push(missing_or_type(Some(value), &path, "array"));
		return;
	};
	for (index, item) in items.iter().enumerate() {
		let path = [json!("view"), json!(field), json!(index)];
		if let Some(allowed) = allowed {
			if !item.as_str().is_some_and(|text| allowed.contains(&text)) {
				issues.push(issue(&path, "invalid_value", json!(allowed)));
			}
		} else if !item.is_string() {
			issues.push(missing_or_type(Some(item), &path, "string"));
		}
	}
}

fn position(value: Option<&Value>, field: &str, positive: bool, issues: &mut Vec<Value>) {
	let Some(value) = value else {
		return;
	};
	let path = [json!("view"), json!(field)];
	let Some(number) = value.as_f64() else {
		issues.push(missing_or_type(Some(value), &path, "number"));
		return;
	};
	if number.fract() != 0.0 {
		issues.push(missing_or_type(Some(value), &path, "int"));
		return;
	}
	if number > 9_007_199_254_740_991.0 {
		issues
			.push(json!({"path":path,"reason":"out_of_range","maximum":9_007_199_254_740_991_i64}));
	}
	if number < -9_007_199_254_740_991.0 {
		issues.push(
			json!({"path":path,"reason":"out_of_range","minimum":-9_007_199_254_740_991_i64}),
		);
	}
	if number < 0.0 || (positive && number == 0.0) {
		issues.push(json!({"path":path,"reason":"out_of_range","minimum":0}));
	}
}

fn view(
	value: Option<&Value>,
	order: Option<&[String]>,
	issues: &mut Vec<Value>,
) -> Option<String> {
	let prefix = [json!("view")];
	let map = object(value, &prefix, issues)?;
	let kind = discriminator(
		map.get("kind"),
		&[json!("view"), json!("kind")],
		VIEW_KINDS,
		issues,
	)?;
	if kind == "summary" {
		unknown(map, &["kind"], &prefix, order, issues);
		return None;
	}
	if kind != "apk-signature" {
		return Some(kind.to_owned());
	}
	let collection = discriminator(
		map.get("collection"),
		&[json!("view"), json!("collection")],
		COLLECTIONS,
		issues,
	)?;
	let fields = match collection {
		"signers" => SIGNER_FIELDS,
		"digests" => DIGEST_FIELDS,
		"lineage" => LINEAGE_FIELDS,
		_ => unreachable!("validated APK collection"),
	};
	array(map.get("ids"), "ids", None, issues);
	array(map.get("schemes"), "schemes", Some(SCHEMES), issues);
	array(map.get("signer_ids"), "signer_ids", None, issues);
	position(map.get("offset"), "offset", false, issues);
	position(map.get("limit"), "limit", true, issues);
	array(map.get("fields"), "fields", Some(fields), issues);
	unknown(
		map,
		&[
			"kind",
			"collection",
			"ids",
			"schemes",
			"signer_ids",
			"offset",
			"limit",
			"fields",
		],
		&prefix,
		order,
		issues,
	);
	None
}

pub(super) fn validate(
	raw: &Value,
	argument_keys: Option<&[String]>,
	source_keys: Option<&[String]>,
	view_keys: Option<&[String]>,
) -> Result<Validation, Failure> {
	let mut issues = Vec::new();
	let Some(map) = object(Some(raw), &[], &mut issues) else {
		return Err(Failure::input(OPERATION, issues));
	};
	let inline_pending = source(map.get("source"), source_keys, &mut issues);
	let gap = view(map.get("view"), view_keys, &mut issues);
	unknown(map, &["source", "view"], &[], argument_keys, &mut issues);
	// An unimplemented view is never advertised as having passed its schema.
	if let Some(kind) = gap {
		return Ok(Validation::CapabilityGap { kind });
	}
	if !issues.is_empty() {
		return Err(Failure::input(OPERATION, issues));
	}
	Ok(if inline_pending {
		Validation::InlineEvidencePending
	} else {
		Validation::Supported
	})
}

#[cfg(test)]
#[path = "rea_analysis_view_mcp_input_tests.rs"]
mod tests;
