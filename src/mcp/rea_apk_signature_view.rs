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

//! Frozen APK summary and selected pages over authenticated retained facts.
//!
//! This module performs no I/O. The caller authenticates and retains the complete
//! parent Evidence, owns cancellation/publication, and seals the returned value
//! with its canonical digest before creating derived analysis-view Evidence.

use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

#[path = "rea_apk_signature_view_schema.rs"]
mod schema;

const MESSAGE_BYTE_LIMIT: usize = 256 * 1024;
const IDENTITY_FIELDS: &[&str] = &[
	"id",
	"scheme",
	"index",
	"signer_id",
	"signer_index",
	"certificate_sha256",
];

/// Secret-safe caller correction metadata, compatible with the frozen input error.
#[derive(Clone, Debug, Serialize)]
pub struct ApkViewIssue {
	pub path: Vec<Value>,
	pub reason: &'static str,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub expected: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub minimum: Option<i64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub maximum: Option<i64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub message: Option<String>,
}

impl ApkViewIssue {
	fn new(path: &[Value], reason: &'static str) -> Self {
		Self {
			path: path.to_vec(),
			reason,
			expected: None,
			minimum: None,
			maximum: None,
			message: None,
		}
	}
	fn minimum(path: &[Value], minimum: i64) -> Self {
		Self {
			minimum: Some(minimum),
			..Self::new(path, "out_of_range")
		}
	}
	fn maximum(path: &[Value], maximum: i64) -> Self {
		Self {
			maximum: Some(maximum),
			..Self::new(path, "out_of_range")
		}
	}
}

/// A failed view has no projected value and cannot be mistaken for an empty page.
#[derive(Clone, Debug, Serialize)]
pub struct ApkViewError {
	#[serde(rename = "_tag")]
	pub tag: &'static str,
	pub operation: &'static str,
	pub issues: Vec<ApkViewIssue>,
}

impl ApkViewError {
	fn input(issues: Vec<ApkViewIssue>) -> Self {
		Self {
			tag: "AnalysisInputError",
			operation: "inspect_analysis_view",
			issues,
		}
	}
}

impl std::fmt::Display for ApkViewError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(formatter, "Invalid analysis input for {}", self.operation)
	}
}
impl std::error::Error for ApkViewError {}

/// Validate the complete frozen public result, including every nested strict field.
pub fn validate_static_report(report: &Value) -> Result<(), ApkViewError> {
	schema::validate_report(report)
}

/// Validate and default a summary/page selection before acquiring its artifact.
pub fn normalize_static_view(view: &Value) -> Result<Value, ApkViewError> {
	schema::normalize_view(view)
}

// These accessors are used only after complete report/selection validation. In
// particular, absent optional selectors are distinct from explicit empty arrays.
fn array(value: &Value) -> &[Value] {
	value.as_array().map(Vec::as_slice).unwrap_or_default()
}
fn integer(value: &Value) -> u64 {
	value
		.as_u64()
		.unwrap_or_else(|| value.as_f64().unwrap_or_default() as u64)
}
fn certificate_digest(certificate: &Value) -> Value {
	certificate["sha256_fingerprint"].clone()
}
fn signer_id(sha256: &str, scheme: &str, index: usize) -> String {
	format!("apk:{sha256}:{scheme}:signer:{index}")
}

fn message_cost(value: &str) -> usize {
	value
		.encode_utf16()
		.count()
		.saturating_mul(18)
		.saturating_add(6)
		.saturating_mul(3)
}

fn bounded_messages(values: &[String], parent_id: &str, field: &str) -> Vec<String> {
	// canonicalOrdering.js compares Unicode code points, unlike canonical JSON's
	// UTF-16 object-key order. UTF-8 lexical ordering agrees for valid Unicode.
	let unique = values.iter().map(String::as_str).collect::<BTreeSet<_>>();
	let total = unique
		.iter()
		.fold(0usize, |sum, text| sum.saturating_add(message_cost(text)));
	if total <= MESSAGE_BYTE_LIMIT {
		return unique.into_iter().map(str::to_owned).collect();
	}
	let notice = |omitted: usize| {
		format!("{omitted} additional {field} omitted from this view; consult source parent Evidence {parent_id} for the complete list (the caller-supplied record, or its retaining session).")
	};
	let mut remaining = MESSAGE_BYTE_LIMIT.saturating_sub(message_cost(&notice(unique.len())));
	let mut retained = Vec::new();
	for value in &unique {
		let cost = message_cost(value);
		if cost <= remaining {
			remaining -= cost;
			retained.push((*value).to_owned());
		}
	}
	let omitted = unique.len() - retained.len();
	if omitted != 0 {
		retained.push(notice(omitted));
	}
	retained
}

fn add_uninterpreted(total: &mut u64, value: &Value) -> Result<(), ApkViewError> {
	*total = total.saturating_add(integer(value));
	if *total > schema::MAX_SAFE_INTEGER as u64 {
		// The source permits each count, but the projected safe-integer count must
		// remain representable. Never wrap a large imported report to zero.
		return Err(ApkViewError::input(vec![ApkViewIssue::maximum(
			&[
				json!("source"),
				json!("normalized_result"),
				json!("schemes"),
			],
			schema::MAX_SAFE_INTEGER,
		)]));
	}
	Ok(())
}

fn summarize(report: &Value) -> Result<(Value, Vec<String>), ApkViewError> {
	let sha256 = report["artifact"]["sha256"].as_str().unwrap_or_default();
	let mut unknowns = vec!["Declared signer and rotation identities are unverified; authenticity and v1 entry coverage remain unknown.".to_owned()];
	if let Some(error) = report["source_stamp"]["decode_error"].as_str() {
		unknowns.push(format!("Source stamp: {error}"));
	}
	let mut identities = Vec::new();
	let mut schemes = Map::new();
	let mut digest_count = 0usize;
	let mut lineage_count = 0usize;
	let mut unknown_identity = false;
	let mut unknown_lineage = false;
	let mut uninterpreted = 0u64;
	for scheme in schema::SCHEMES {
		let block = &report["schemes"][scheme];
		let signers = array(&block["signers"]);
		schemes.insert(
			(*scheme).into(),
			json!({"present":block["present"], "signers":signers.len()}),
		);
		if *scheme != "v1" {
			add_uninterpreted(&mut uninterpreted, &block["uninterpreted_bytes"])?;
		}
		for (index, signer) in signers.iter().enumerate() {
			identities.push(json!({
				"id":signer_id(sha256, scheme, index), "scheme":scheme, "index":index,
				"certificate_sha256":certificate_digest(&signer["certificate"]),
			}));
			if signer["certificate"].is_null() {
				unknown_identity = true;
				unknowns.push(format!(
					"{scheme} signer {index} has no resolved declared certificate identity."
				));
			}
			if let Some(error) = signer["decode_error"].as_str() {
				unknowns.push(format!("{scheme} signer {index}: {error}"));
			}
			if *scheme != "v1" {
				add_uninterpreted(
					&mut uninterpreted,
					&signer["uninterpreted_signed_data_bytes"],
				)?;
				add_uninterpreted(&mut uninterpreted, &signer["uninterpreted_signer_bytes"])?;
				digest_count += array(&signer["digests"]).len();
				for collection in ["digests", "signatures"] {
					for record in array(&signer[collection]) {
						add_uninterpreted(&mut uninterpreted, &record["uninterpreted_bytes"])?;
					}
				}
			}
			if matches!(*scheme, "v3" | "v3.1") {
				lineage_count += array(&signer["rotation"]["lineage"]).len();
				if let Some(error) = signer["rotation"]["decode_error"].as_str() {
					unknown_lineage = true;
					unknowns.push(format!("{scheme} signer {index} lineage: {error}"));
				}
			}
		}
	}
	let summary = json!({
		"artifact":report["artifact"], "schemes":schemes,
		"counts":{"signers":identities.len(), "digests":digest_count, "lineage":lineage_count},
		"signers":identities,
		"source_stamp":{
			"present":report["source_stamp"]["present"],
			"certificate_sha256":certificate_digest(&report["source_stamp"]["certificate"]),
			"decode_error":report["source_stamp"]["decode_error"],
		},
		"posture":report["posture"],
		"source_coverage":{
			"scope":"declared-signing-records", "uninterpreted_bytes":uninterpreted,
			"signer_identity":if unknown_identity {"partial"} else {"complete-within-records"},
			"lineage_decoding":if unknown_lineage {"partial"} else {"complete-within-records"},
			"signature_verification":"not-performed", "v1_entry_coverage":"unknown", "authenticity":"unknown",
		},
	});
	Ok((summary, unknowns))
}

struct Selection<'a> {
	collection: &'a str,
	ids: Option<BTreeSet<&'a str>>,
	schemes: Option<BTreeSet<&'a str>>,
	signers: Option<BTreeSet<&'a str>>,
	fields: Option<BTreeSet<&'a str>>,
	offset: u64,
	limit: u64,
}

impl<'a> Selection<'a> {
	fn new(view: &'a Value) -> Self {
		let set = |key| {
			view.get(key)
				.map(|value| array(value).iter().filter_map(Value::as_str).collect())
		};
		Self {
			collection: view["collection"].as_str().unwrap_or_default(),
			ids: set("ids"),
			schemes: set("schemes"),
			signers: set("signer_ids"),
			fields: set("fields"),
			offset: integer(&view["offset"]),
			limit: integer(&view["limit"]),
		}
	}
	fn selected(&self, id: &str, signer_id: &str) -> bool {
		self.ids.as_ref().is_none_or(|ids| ids.contains(id))
			&& self
				.signers
				.as_ref()
				.is_none_or(|ids| ids.contains(signer_id))
	}
	fn include(&self, key: &str) -> bool {
		IDENTITY_FIELDS.contains(&key)
			|| self
				.fields
				.as_ref()
				.is_none_or(|fields| fields.contains(key))
	}
	fn put(&self, row: &mut Map<String, Value>, key: &str, value: impl FnOnce() -> Value) {
		if self.include(key) {
			row.insert(key.into(), value());
		}
	}
}

fn signer_row(
	selection: &Selection<'_>,
	signer: &Value,
	id: &str,
	scheme: &str,
	index: usize,
) -> Value {
	let mut row = Map::new();
	for (key, value) in [
		("id", json!(id)),
		("scheme", json!(scheme)),
		("index", json!(index)),
	] {
		row.insert(key.into(), value);
	}
	selection.put(&mut row, "certificate_sha256", || {
		certificate_digest(&signer["certificate"])
	});
	for key in [
		"certificate",
		"uninterpreted_signed_data_bytes",
		"uninterpreted_signer_bytes",
		"public_key_bytes",
		"min_sdk",
		"max_sdk",
		"signature_file",
		"block_file",
		"decode_error",
	] {
		selection.put(&mut row, key, || signer[key].clone());
	}
	for key in ["signatures", "signer_infos"] {
		selection.put(&mut row, key, || {
			signer.get(key).cloned().unwrap_or_else(|| json!([]))
		});
	}
	Value::Object(row)
}

fn child_row(
	selection: &Selection<'_>,
	node: &Value,
	id: &str,
	signer_id: &str,
	scheme: &str,
	index: usize,
	signer_index: usize,
) -> Value {
	let mut row = Map::new();
	if let Some(object) = node.as_object() {
		for (key, value) in object {
			selection.put(&mut row, key, || value.clone());
		}
	}
	for (key, value) in [
		("id", json!(id)),
		("scheme", json!(scheme)),
		("index", json!(index)),
		("signer_id", json!(signer_id)),
		("signer_index", json!(signer_index)),
	] {
		row.insert(key.into(), value);
	}
	if selection.collection == "lineage" {
		selection.put(&mut row, "certificate_sha256", || {
			certificate_digest(&node["certificate"])
		});
		selection.put(&mut row, "previous_id", || {
			if index == 0 {
				Value::Null
			} else {
				json!(format!("{signer_id}:lineage:{}", index - 1))
			}
		});
	}
	Value::Object(row)
}

fn page(report: &Value, view: &Value) -> (Vec<Value>, Value) {
	let selection = Selection::new(view);
	let sha256 = report["artifact"]["sha256"].as_str().unwrap_or_default();
	let mut items = Vec::new();
	let mut total = 0u64;
	for scheme in schema::SCHEMES {
		if selection
			.schemes
			.as_ref()
			.is_some_and(|schemes| !schemes.contains(scheme))
		{
			continue;
		}
		for (signer_index, signer) in array(&report["schemes"][scheme]["signers"])
			.iter()
			.enumerate()
		{
			let signer_id = signer_id(sha256, scheme, signer_index);
			if selection.collection == "signers" {
				if !selection.selected(&signer_id, &signer_id) {
					continue;
				}
				total += 1;
				if total > selection.offset && (items.len() as u64) < selection.limit {
					items.push(signer_row(
						&selection,
						signer,
						&signer_id,
						scheme,
						signer_index,
					));
				}
			} else {
				let nodes = if selection.collection == "digests" {
					&signer["digests"]
				} else {
					&signer["rotation"]["lineage"]
				};
				for (index, node) in array(nodes).iter().enumerate() {
					let id = format!("{signer_id}:{}:{index}", selection.collection);
					if !selection.selected(&id, &signer_id) {
						continue;
					}
					total += 1;
					if total > selection.offset && (items.len() as u64) < selection.limit {
						items.push(child_row(
							&selection,
							node,
							&id,
							&signer_id,
							scheme,
							index,
							signer_index,
						));
					}
				}
			}
		}
	}
	let examined = items.len() as u64;
	let exhausted = selection.offset >= total || selection.offset + examined >= total;
	let coverage = json!({
		"status":if examined == 0 {"empty"} else {"page"}, "examined":examined, "total":total,
		"next_offset":if exhausted {None} else {Some(selection.offset + examined)}, "exhausted":exhausted,
	});
	(items, coverage)
}

/// Project a complete authenticated parent without reopening the selected artifact.
///
/// `subject` is the Evidence subject (`local_path`, `digest.sha256`), or `None`.
/// The caller must seal the returned projection with the shared canonical digest;
/// this function does not authenticate the parent or publish a retained receipt.
pub fn project_static_view(
	report: &Value,
	parent_id: &str,
	subject: Option<&Value>,
	limitations: &[String],
	view: &Value,
) -> Result<Value, ApkViewError> {
	let digest = parent_id
		.strip_prefix("ev_")
		.filter(|digest| digest.len() == 64 && schema::lower_hex(digest));
	let Some(digest) = digest else {
		let mut issue = ApkViewIssue::new(&[json!("source")], "invalid_format");
		issue.message = Some("Parent Evidence ID is not a digest-backed identifier.".into());
		return Err(ApkViewError::input(vec![issue]));
	};
	let view = normalize_static_view(view)?;
	validate_static_report(report)?;
	if subject
		.filter(|subject| !subject.is_null())
		.is_some_and(|subject| {
			subject["local_path"] != report["artifact"]["path"]
				|| subject["digest"]["sha256"] != report["artifact"]["sha256"]
		}) {
		let mut issue = ApkViewIssue::new(&[json!("source"), json!("subject")], "invalid_value");
		issue.message = Some("APK subject does not match its recorded artifact".into());
		return Err(ApkViewError::input(vec![issue]));
	}
	let (summary, unknowns) = summarize(report)?;
	let mut result = json!({
		"kind":view["kind"], "view":view,
		"parent_evidence_id":parent_id, "parent_operation":"inspect_apk_signature", "parent_digest":digest,
		"artifact":{"path":report["artifact"]["path"], "sha256":report["artifact"]["sha256"]},
		"limitations":bounded_messages(limitations, parent_id, "limitations"),
		"unknowns":bounded_messages(&unknowns, parent_id, "unknowns"),
	});
	if view["kind"] == "summary" {
		result["summary"] = summary;
		result["coverage"] = json!({"status":"complete-within-view", "examined":1, "total":1, "next_offset":null, "exhausted":true});
	} else {
		let (items, coverage) = page(report, &view);
		result["source_coverage"] = summary["source_coverage"].clone();
		result["items"] = json!(items);
		result["coverage"] = coverage;
	}
	Ok(result)
}

#[cfg(test)]
#[path = "rea_apk_signature_view_tests.rs"]
mod tests;
