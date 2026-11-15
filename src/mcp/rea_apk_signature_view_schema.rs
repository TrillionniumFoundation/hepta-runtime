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

//! Frozen report admission for retained APK views, independent of the binary DTO.
//!
//! The public report admits safe signed SDK integers and capability integers
//! wider than u32. Binary decoding has narrower physical fields; authenticated
//! imported Evidence must not accidentally inherit those representation limits.

use super::{ApkViewError, ApkViewIssue};
use serde_json::{json, Value};

pub(super) const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
pub(super) const SCHEMES: &[&str] = &["v1", "v2", "v3", "v3.1"];
pub(super) const SIGNER_FIELDS: &[&str] = &[
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
pub(super) const DIGEST_FIELDS: &[&str] = &[
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
pub(super) const LINEAGE_FIELDS: &[&str] = &[
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

#[derive(Clone, Copy)]
enum Schema {
	String,
	NonemptyString,
	Digest,
	Hex,
	Boolean,
	Integer { minimum: i64, maximum: i64 },
	Enum(&'static [&'static str]),
	Nullable(&'static Schema),
	Array(&'static Schema),
	Object(&'static [(&'static str, Schema)]),
}

const POSITION: Schema = Schema::Integer {
	minimum: 0,
	maximum: MAX_SAFE_INTEGER,
};
const SDK: Schema = Schema::Nullable(&Schema::Integer {
	minimum: -MAX_SAFE_INTEGER,
	maximum: MAX_SAFE_INTEGER,
});
const ALGORITHM_ID: Schema = Schema::Integer {
	minimum: 0,
	maximum: u32::MAX as i64,
};
const ALGORITHM: Schema = Schema::Enum(&["sha256", "sha512", "verity-sha256", "unknown"]);
const NULLABLE_STRING: Schema = Schema::Nullable(&Schema::String);
const NULLABLE_BOOL: Schema = Schema::Nullable(&Schema::Boolean);
const CERTIFICATE: Schema = Schema::Nullable(&Schema::Object(&[
	("sha256_fingerprint", Schema::Digest),
	("subject", NULLABLE_STRING),
	("issuer", NULLABLE_STRING),
	("serial_number", NULLABLE_STRING),
	("not_before", NULLABLE_STRING),
	("not_after", NULLABLE_STRING),
	("public_key_algorithm", NULLABLE_STRING),
]));
const DIGEST_RECORD: Schema = Schema::Object(&[
	("uninterpreted_bytes", POSITION),
	("signature_algorithm_id", ALGORITHM_ID),
	("algorithm", ALGORITHM),
	("declared_digest_hex", Schema::Hex),
	("matches_apk", NULLABLE_BOOL),
]);
const SIGNATURE_RECORD: Schema = Schema::Object(&[
	("signature_algorithm_id", ALGORITHM_ID),
	("algorithm", ALGORITHM),
	("signature_bytes", POSITION),
	("uninterpreted_bytes", POSITION),
]);
const LINEAGE_RECORD: Schema = Schema::Object(&[
	("certificate", CERTIFICATE),
	("flags", POSITION),
	(
		"capabilities",
		Schema::Object(&[
			("installed_data", Schema::Boolean),
			("shared_uid", Schema::Boolean),
			("permission", Schema::Boolean),
			("rollback", Schema::Boolean),
			("auth", Schema::Boolean),
		]),
	),
]);
const SIGNER: Schema = Schema::Object(&[
	("uninterpreted_signed_data_bytes", POSITION),
	("uninterpreted_signer_bytes", POSITION),
	("certificate", CERTIFICATE),
	("digests", Schema::Array(&DIGEST_RECORD)),
	("signatures", Schema::Array(&SIGNATURE_RECORD)),
	("public_key_bytes", POSITION),
	("min_sdk", SDK),
	("max_sdk", SDK),
]);
const SIGNER_V3: Schema = Schema::Object(&[
	("uninterpreted_signed_data_bytes", POSITION),
	("uninterpreted_signer_bytes", POSITION),
	("certificate", CERTIFICATE),
	("digests", Schema::Array(&DIGEST_RECORD)),
	("signatures", Schema::Array(&SIGNATURE_RECORD)),
	("public_key_bytes", POSITION),
	("min_sdk", SDK),
	("max_sdk", SDK),
	(
		"rotation",
		Schema::Object(&[
			("present", Schema::Boolean),
			("lineage", Schema::Array(&LINEAGE_RECORD)),
			("decode_error", NULLABLE_STRING),
		]),
	),
]);
const SIGNER_V1: Schema = Schema::Object(&[
	("signature_file", Schema::String),
	("block_file", Schema::String),
	("certificate", CERTIFICATE),
	(
		"certificates",
		Schema::Array(&Schema::Object(&[
			("sha256_fingerprint", Schema::Digest),
			("subject", NULLABLE_STRING),
		])),
	),
	(
		"signer_infos",
		Schema::Array(&Schema::Object(&[
			(
				"identified_by",
				Schema::Enum(&["issuer-and-serial", "subject-key-identifier"]),
			),
			("certificate_sha256", Schema::Nullable(&Schema::Digest)),
			("digest_algorithm_oid", Schema::String),
			("signature_algorithm_oid", Schema::String),
		])),
	),
	("decode_error", NULLABLE_STRING),
]);
const REPORT: Schema = Schema::Object(&[
	(
		"artifact",
		Schema::Object(&[
			("path", Schema::NonemptyString),
			("sha256", Schema::Digest),
			("bytes", POSITION),
		]),
	),
	(
		"schemes",
		Schema::Object(&[
			(
				"v1",
				Schema::Object(&[
					("present", Schema::Boolean),
					("has_manifest", Schema::Boolean),
					("signature_files", Schema::Array(&Schema::String)),
					("block_files", Schema::Array(&Schema::String)),
					("signers", Schema::Array(&SIGNER_V1)),
				]),
			),
			(
				"v2",
				Schema::Object(&[
					("present", Schema::Boolean),
					("signers", Schema::Array(&SIGNER)),
					("uninterpreted_bytes", POSITION),
				]),
			),
			(
				"v3",
				Schema::Object(&[
					("present", Schema::Boolean),
					("signers", Schema::Array(&SIGNER_V3)),
					("uninterpreted_bytes", POSITION),
				]),
			),
			(
				"v3.1",
				Schema::Object(&[
					("present", Schema::Boolean),
					("signers", Schema::Array(&SIGNER_V3)),
					("uninterpreted_bytes", POSITION),
				]),
			),
		]),
	),
	(
		"source_stamp",
		Schema::Object(&[
			("present", Schema::Boolean),
			("certificate", CERTIFICATE),
			("decode_error", NULLABLE_STRING),
		]),
	),
	(
		"posture",
		Schema::Object(&[
			("v1_only", Schema::Boolean),
			("schemes_agree_on_signer", NULLABLE_BOOL),
			("signer_change_declared_by_rotation", NULLABLE_BOOL),
			("v1_signers_match_block_signers", NULLABLE_BOOL),
			("rotation_present", Schema::Boolean),
			("source_stamp_present", Schema::Boolean),
			(
				"strongest_scheme",
				Schema::Enum(&["none", "v1", "v2", "v3", "v3.1"]),
			),
			("self_consistent", NULLABLE_BOOL),
		]),
	),
	("runtime_execution", Schema::Enum(&["not-performed"])),
]);

fn type_issue(path: &[Value], value: Option<&Value>, expected: &str) -> ApkViewIssue {
	let mut issue = ApkViewIssue::new(
		path,
		if value.is_none() {
			"missing_argument"
		} else {
			"invalid_type"
		},
	);
	issue.expected = Some(json!(expected));
	issue
}

fn integer_issues(
	value: Option<&Value>,
	path: &[Value],
	minimum: i64,
	maximum: i64,
	issues: &mut Vec<ApkViewIssue>,
) {
	let Some(number) = value.and_then(Value::as_f64) else {
		issues.push(type_issue(path, value, "number"));
		return;
	};
	if number.fract() != 0.0 {
		issues.push(type_issue(path, value, "int"));
		return;
	}
	// Zod's integer admission checks safe representation before extra bounds.
	if number < -(MAX_SAFE_INTEGER as f64) {
		issues.push(ApkViewIssue::minimum(path, -MAX_SAFE_INTEGER));
	} else if number > MAX_SAFE_INTEGER as f64 {
		issues.push(ApkViewIssue::maximum(path, MAX_SAFE_INTEGER));
	}
	if number < minimum as f64 && minimum > -MAX_SAFE_INTEGER {
		issues.push(ApkViewIssue::minimum(path, minimum));
	}
	if number > maximum as f64 && maximum < MAX_SAFE_INTEGER {
		issues.push(ApkViewIssue::maximum(path, maximum));
	}
}

fn validate(
	schema: Schema,
	value: Option<&Value>,
	path: &mut Vec<Value>,
	issues: &mut Vec<ApkViewIssue>,
) {
	match schema {
		Schema::Nullable(inner) => {
			if !value.is_some_and(Value::is_null) {
				validate(*inner, value, path, issues);
			}
		}
		Schema::Object(fields) => {
			let Some(object) = value.and_then(Value::as_object) else {
				issues.push(type_issue(path, value, "object"));
				return;
			};
			for (name, field) in fields {
				path.push(json!(name));
				validate(*field, object.get(*name), path, issues);
				path.pop();
			}
			for name in object
				.keys()
				.filter(|name| !fields.iter().any(|(field, _)| field == name))
			{
				path.push(json!(name));
				issues.push(ApkViewIssue::new(path, "unknown_argument"));
				path.pop();
			}
		}
		Schema::Array(element) => {
			let Some(array) = value.and_then(Value::as_array) else {
				issues.push(type_issue(path, value, "array"));
				return;
			};
			for (index, value) in array.iter().enumerate() {
				path.push(json!(index));
				validate(*element, Some(value), path, issues);
				path.pop();
			}
		}
		Schema::Integer { minimum, maximum } => {
			integer_issues(value, path, minimum, maximum, issues)
		}
		Schema::Boolean => {
			if !value.is_some_and(Value::is_boolean) {
				issues.push(type_issue(path, value, "boolean"));
			}
		}
		Schema::Enum(values) => {
			if !value
				.and_then(Value::as_str)
				.is_some_and(|value| values.contains(&value))
			{
				let mut issue = ApkViewIssue::new(path, "invalid_value");
				issue.expected = Some(json!(values));
				issues.push(issue);
			}
		}
		Schema::String | Schema::NonemptyString | Schema::Digest | Schema::Hex => {
			let Some(text) = value.and_then(Value::as_str) else {
				issues.push(type_issue(path, value, "string"));
				return;
			};
			let pattern = match schema {
				Schema::NonemptyString if text.is_empty() => {
					issues.push(ApkViewIssue::minimum(path, 1));
					None
				}
				Schema::Digest if text.len() != 64 || !lower_hex(text) => Some("/^[a-f0-9]{64}$/u"),
				Schema::Hex if text.len() % 2 != 0 || !lower_hex(text) => {
					Some("/^(?:[a-f0-9]{2})*$/")
				}
				_ => None,
			};
			if let Some(pattern) = pattern {
				let mut issue = ApkViewIssue::new(path, "invalid_format");
				issue.expected = Some(json!("regex"));
				issue.message = Some(format!("Invalid string: must match pattern {pattern}"));
				issues.push(issue);
			}
		}
	}
}

pub(super) fn lower_hex(text: &str) -> bool {
	text.bytes()
		.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn validate_report(report: &Value) -> Result<(), ApkViewError> {
	let mut issues = Vec::new();
	validate(
		REPORT,
		Some(report),
		&mut vec![json!("source"), json!("normalized_result")],
		&mut issues,
	);
	if issues.is_empty() {
		Ok(())
	} else {
		Err(ApkViewError::input(issues))
	}
}

/// Validate and normalize only the frozen APK branch; no caller-controlled cap is added.
pub(super) fn normalize_view(view: &Value) -> Result<Value, ApkViewError> {
	let mut issues = Vec::new();
	let mut path = vec![json!("view")];
	if view["kind"] == "summary" {
		validate(
			Schema::Object(&[("kind", Schema::Enum(&["summary"]))]),
			Some(view),
			&mut path,
			&mut issues,
		);
	} else if view["kind"] == "apk-signature" {
		let fields = match view["collection"].as_str() {
			Some("signers") => Schema::Array(&Schema::Enum(SIGNER_FIELDS)),
			Some("digests") => Schema::Array(&Schema::Enum(DIGEST_FIELDS)),
			Some("lineage") => Schema::Array(&Schema::Enum(LINEAGE_FIELDS)),
			_ => {
				path.push(json!("collection"));
				let mut issue = ApkViewIssue::new(
					&path,
					if view.get("collection").is_none() {
						"missing_argument"
					} else {
						"invalid_value"
					},
				);
				issue.expected = Some(json!(["signers", "digests", "lineage"]));
				return Err(ApkViewError::input(vec![issue]));
			}
		};
		for (name, schema) in [
			("ids", Schema::Array(&Schema::String)),
			("schemes", Schema::Array(&Schema::Enum(SCHEMES))),
			("signer_ids", Schema::Array(&Schema::String)),
			("offset", POSITION),
			("limit", POSITION),
			("fields", fields),
		] {
			if let Some(value) = view.get(name) {
				path.push(json!(name));
				validate(schema, Some(value), &mut path, &mut issues);
				if name == "limit" && value.as_f64() == Some(0.0) {
					issues.push(ApkViewIssue::minimum(&path, 0));
				}
				path.pop();
			}
		}
		if let Some(object) = view.as_object() {
			for name in object.keys().filter(|name| {
				![
					"kind",
					"collection",
					"ids",
					"schemes",
					"signer_ids",
					"offset",
					"limit",
					"fields",
				]
				.contains(&name.as_str())
			}) {
				path.push(json!(name));
				issues.push(ApkViewIssue::new(&path, "unknown_argument"));
				path.pop();
			}
		}
	} else {
		let mut issue = ApkViewIssue::new(&path, "invalid_value");
		issue.message = Some(
			"APK Evidence supports summary and apk-signature signer/digest/lineage pages".into(),
		);
		return Err(ApkViewError::input(vec![issue]));
	}
	if !issues.is_empty() {
		return Err(ApkViewError::input(issues));
	}
	let mut normalized = view.clone();
	if normalized["kind"] == "apk-signature" {
		if normalized.get("offset").is_none() {
			normalized["offset"] = json!(0);
		}
		if normalized.get("limit").is_none() {
			normalized["limit"] = json!(32);
		}
	}
	Ok(normalized)
}
