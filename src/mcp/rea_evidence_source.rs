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

//! Authenticate an owned Evidence source without cloning its result payloads.
//!
//! The frozen source is REA 6.8.0 evidence.ts, evidenceBundle.ts and
//! application/analysisView/evidenceFileSource.ts. File admission, strict UTF-8
//! JSON decoding, live resource admission and cancellation belong to the caller.
//! In particular, the upstream 8 MiB native JSON parser threshold is not a file
//! size limit. Successful authentication does not establish provider truth.
//! The frozen REA contract is MIT licensed; see LICENSES/REA-MIT.txt.

use super::rea_evidence;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;

/// Ordering comes only from the trusted parser of this exact owned source.
/// Paths are relative to the supplied record or file JSON root. A bundle record
/// is therefore addressed through ["records", index, ...]. Caller metadata is
/// never an ordering authority.
pub(super) type KeyOrderResolver<'a> = dyn Fn(&[Value]) -> Option<Vec<String>> + 'a;

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(super) enum SourceError {
	/// Projected issues are relative to the Evidence record root. Inline callers
	/// prefix ["source", "evidence"]; file callers use wrong-kind/contentIssues.
	InvalidRecord {
		issues: Vec<Value>,
		description: String,
	},
	/// An original bundle-validation user message, not a guessed integrity label.
	InvalidBundle { message: String },
	/// An original selector message for ["source", "evidence_id"].
	Selection { message: String },
	/// A known native profile boundary; never reported as corrupt source data.
	ProfileGap { feature: &'static str },
	/// A frozen schema coercion throws instead of yielding a validation issue.
	/// The public SDK delivers this exact text as an error CallToolResult.
	SchemaException { message: &'static str },
	/// Unexpected implementation failure, separate from caller correction facts.
	Internal { message: String },
}

impl fmt::Display for SourceError {
	fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidRecord { description, .. } => output.write_str(description),
			Self::InvalidBundle { message }
			| Self::Selection { message }
			| Self::Internal { message } => output.write_str(message),
			Self::SchemaException { message } => output.write_str(message),
			Self::ProfileGap { feature } => {
				write!(output, "Evidence source profile gap: {feature}")
			}
		}
	}
}

impl std::error::Error for SourceError {}
type SourceResult<T> = Result<T, SourceError>;

#[path = "rea_evidence_source_length.rs"]
mod length_checks;
#[path = "rea_evidence_source_process.rs"]
mod process_capture;
#[path = "rea_residual_unknown.rs"]
mod residual_unknown;

/// The complete authenticated candidate is still private until one session
/// commits all records and revisions together. No input payload is executed.
#[derive(Debug)]
pub(super) struct AuthenticatedBundle {
	pub(super) records: Vec<Value>,
	pub(super) unknowns: Vec<Value>,
}

#[derive(Debug)]
pub(super) enum ImportSourceError {
	Source(SourceError),
	SingleRecord { evidence_id: String },
}

impl From<SourceError> for ImportSourceError {
	fn from(error: SourceError) -> Self {
		Self::Source(error)
	}
}

/// Validate an already authenticated union before publishing it. This shares
/// the exact graph rules with standalone file authentication.
pub(super) fn validate_unknown_union(
	unknowns: &[&Value],
	records: &[&Value],
) -> Result<(), String> {
	residual_unknown::validate_graph(unknowns, records)
}

const FORMATS: &[&str] = &[
	"hopper",
	"analysis-database",
	"mach-o",
	"elf",
	"pe",
	"dos-mz",
	"dos-com",
	"zip",
	"ipa",
	"apk",
	"msix",
	"appx",
	"hap",
	"hsp",
	"app-pack",
	"asar",
	"godot-pck",
	"dmg",
	"pkg",
	"plist",
	"javascript",
	"source-map",
	"directory",
	"file",
	"unknown",
	"mach-o-universal",
	"javascript-bundle",
	"entitlements",
	"pyinstaller",
	"node-sea",
	"raw-binary",
	"gamecube-dol",
];
const ARCHITECTURES: &[&str] = &[
	"x86", "x86_64", "arm", "arm64", "arm64_32", "mips", "6502", "riscv", "powerpc", "m68k",
	"hexagon",
];
const DETECTED_ARCHITECTURES: &[&str] = &[
	"x86", "x86_64", "arm", "arm64", "arm64_32", "mips", "riscv", "powerpc", "hexagon",
];
const CONFIDENCE: &[&str] = &["observed", "derived", "inferred"];
const AUTHORITY: &[&str] = &[
	"shipped-artifact",
	"controlled-replay",
	"historical-reference",
	"external-service",
	"analyst-inference",
];
const ISOLATION: &[&str] = &["none", "process", "container", "virtual-machine"];
const RECORD_FIELDS: &[&str] = &[
	"evidence_id",
	"subject",
	"provider",
	"analysis_profile",
	"predicate_type",
	"operation",
	"parameters",
	"caller_input_path",
	"raw_result",
	"normalized_result",
	"confidence",
	"authority",
	"environment",
	"limitations",
	"relationship_coverage",
	"locations",
	"evidence_links",
];
const SEMANTIC_FIELDS: &[&str] = &[
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
const LEGACY_ID_MESSAGE: &str = "Evidence uses an earlier relationship_coverage identity commitment: explicit null was omitted from that digest. Recreate this observation with the current REA release; re-exporting the old bundle cannot update its identity.";

/// Share the frozen length-check behavior with the MCP input schema boundary.
/// Type checks remain the caller's responsibility and precede these messages.
pub(super) fn minimum_length_messages(
	value: Option<&Value>,
	minimum: u64,
) -> SourceResult<Vec<String>> {
	let mut validation = Validation::new(None);
	validation.min_length(value, &[], minimum);
	let messages = std::mem::take(&mut validation.issues)
		.into_iter()
		.map(|issue| issue.message)
		.collect();
	validation.finish()?;
	Ok(messages)
}

fn child(path: &[Value], key: impl Into<Value>) -> Vec<Value> {
	let mut result = path.to_vec();
	result.push(key.into());
	result
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

struct Issue {
	path: Vec<Value>,
	message: String,
	projected: Vec<Value>,
	aborted: bool,
}

struct Validation<'a> {
	issues: Vec<Issue>,
	order: Option<&'a KeyOrderResolver<'a>>,
	gap: Option<&'static str>,
}

impl<'a> Validation<'a> {
	fn new(order: Option<&'a KeyOrderResolver<'a>>) -> Self {
		Self {
			issues: Vec::new(),
			order,
			gap: None,
		}
	}

	fn add(&mut self, path: &[Value], message: String, projected: Vec<Value>, aborted: bool) {
		self.issues.push(Issue {
			path: path.to_vec(),
			message,
			projected,
			aborted,
		});
	}

	fn invalid_type(&mut self, value: Option<&Value>, path: &[Value], expected: &str) {
		self.add(path, format!("Invalid input: expected {expected}, received {}", received(value)),
			vec![json!({"path":path,"reason":if value.is_none(){"missing_argument"}else{"invalid_type"},"expected":expected})], true);
	}

	fn custom(&mut self, path: &[Value], message: &str, aborted: bool) {
		self.add(
			path,
			message.into(),
			vec![json!({"path":path,"reason":"invalid_value","message":message})],
			aborted,
		);
	}

	fn object<'v>(
		&mut self,
		value: Option<&'v Value>,
		path: &[Value],
	) -> Option<&'v Map<String, Value>> {
		match value.and_then(Value::as_object) {
			Some(value) => Some(value),
			None => {
				self.invalid_type(value, path, "object");
				None
			}
		}
	}

	fn array<'v>(&mut self, value: Option<&'v Value>, path: &[Value]) -> Option<&'v [Value]> {
		match value.and_then(Value::as_array) {
			Some(value) => Some(value),
			None => {
				self.invalid_type(value, path, "array");
				None
			}
		}
	}

	fn minimum(&mut self, path: &[Value], minimum: u64, origin: &str) {
		let unit = if origin == "string" {
			"characters"
		} else {
			"items"
		};
		self.add(
			path,
			format!("Too small: expected {origin} to have >={minimum} {unit}"),
			vec![json!({"path":path,"reason":"out_of_range","minimum":minimum})],
			false,
		);
	}

	fn string<'v>(
		&mut self,
		value: Option<&'v Value>,
		path: &[Value],
		nonempty: bool,
	) -> Option<&'v str> {
		let text = value.and_then(Value::as_str);
		if text.is_none() {
			self.invalid_type(value, path, "string");
		}
		if nonempty {
			self.min_length(value, path, 1);
		}
		text
	}

	fn digest(&mut self, value: Option<&Value>, path: &[Value], prefix: &str) {
		let Some(text) = self.string(value, path, false) else {
			return;
		};
		let valid = text.strip_prefix(prefix).is_some_and(|tail| {
			tail.len() == 64
				&& tail
					.bytes()
					.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
		});
		if !valid {
			let message = if prefix.is_empty() {
				"Invalid string: must match pattern /^[a-f0-9]{64}$/u".into()
			} else {
				format!("Expected a {prefix} prefixed lowercase sha256 digest")
			};
			self.add(
				path,
				message.clone(),
				vec![
					json!({"path":path,"reason":"invalid_format","expected":"regex","message":message}),
				],
				false,
			);
		}
	}

	fn nul_free(&mut self, value: Option<&Value>, path: &[Value]) {
		if self
			.string(value, path, false)
			.is_some_and(|text| text.contains('\0'))
		{
			let message = "Local filesystem paths cannot contain NUL";
			self.add(
				path,
				message.into(),
				vec![
					json!({"path":path,"reason":"invalid_format","expected":"regex","message":message}),
				],
				false,
			);
		}
	}

	fn choice(&mut self, value: Option<&Value>, path: &[Value], allowed: &[&str]) {
		if value
			.and_then(Value::as_str)
			.is_some_and(|text| allowed.contains(&text))
		{
			return;
		}
		let message = if allowed.len() == 1 {
			format!("Invalid input: expected {:?}", allowed[0])
		} else {
			format!(
				"Invalid option: expected one of {}",
				allowed
					.iter()
					.map(|s| format!("{s:?}"))
					.collect::<Vec<_>>()
					.join("|")
			)
		};
		self.add(
			path,
			message,
			vec![json!({"path":path,"reason":"invalid_value","expected":allowed})],
			true,
		);
	}

	fn discriminator(&mut self, value: Option<&Value>, path: &[Value], allowed: &[&str]) -> bool {
		if value
			.and_then(Value::as_str)
			.is_some_and(|text| allowed.contains(&text))
		{
			return true;
		}
		let options = allowed
			.iter()
			.map(|s| format!("'{s}'"))
			.collect::<Vec<_>>()
			.join(" | ");
		self.add(path, format!("Invalid discriminator value. Expected {options}"),
			vec![json!({"path":path,"reason":if value.is_none(){"missing_argument"}else{"invalid_value"},"expected":allowed})], true);
		false
	}

	fn unknown(&mut self, map: &Map<String, Value>, allowed: &[&str], path: &[Value]) {
		if self.gap == Some("original-length-coercion-exception") {
			return;
		}
		let mut keys: Vec<&str> = map
			.keys()
			.map(String::as_str)
			.filter(|key| *key != "__proto__" && !allowed.contains(key))
			.collect();
		if keys.is_empty() {
			return;
		}
		let hints = self
			.order
			.and_then(|resolver| resolver(path))
			.map(|mut keys| {
				keys.retain(|key| key != "__proto__" || map.contains_key(key));
				keys
			});
		if keys.len() > 1 {
			let Some(hints) = hints.as_ref() else {
				self.gap = Some("unknown-key-order-metadata-unavailable");
				return;
			};
			let mut seen = BTreeSet::new();
			if hints.len() != map.len()
				|| hints
					.iter()
					.any(|key| !map.contains_key(key) || !seen.insert(key))
			{
				self.gap = Some("unknown-key-order-metadata-invalid");
				return;
			}
			// The validated order is already a permutation of this exact object.
			// Filtering it once preserves the original error order without a
			// quadratic rank search for each comparison on wide invalid objects.
			keys = hints
				.iter()
				.map(String::as_str)
				.filter(|key| *key != "__proto__" && !allowed.contains(key))
				.collect();
		}
		let labels = keys
			.iter()
			.map(|key| format!("\"{key}\""))
			.collect::<Vec<_>>()
			.join(", ");
		let noun = if keys.len() == 1 { "key" } else { "keys" };
		let projected = keys
			.iter()
			.map(|key| json!({"path":child(path,*key),"reason":"unknown_argument"}))
			.collect();
		self.add(
			path,
			format!("Unrecognized {noun}: {labels}"),
			projected,
			true,
		);
	}

	fn aborted_from(&self, start: usize) -> bool {
		self.issues[start..].iter().any(|issue| issue.aborted)
	}

	fn finish(self) -> SourceResult<()> {
		if let Some(feature) = self.gap {
			return Err(if feature == "original-length-coercion-exception" {
				SourceError::SchemaException {
					message: "Cannot convert object to primitive value",
				}
			} else {
				SourceError::ProfileGap { feature }
			});
		}
		if self.issues.is_empty() {
			return Ok(());
		}
		let first = &self.issues[0];
		let location = if first.path.is_empty() {
			"the document root".into()
		} else {
			first
				.path
				.iter()
				.map(|part| {
					part.as_str()
						.map_or_else(|| part.to_string(), str::to_owned)
				})
				.collect::<Vec<_>>()
				.join(".")
		};
		let more = if self.issues.len() == 1 {
			String::new()
		} else {
			format!(" ({} more issues)", self.issues.len() - 1)
		};
		let description = format!("at {location}: {}{more}", first.message);
		Err(SourceError::InvalidRecord {
			issues: self
				.issues
				.into_iter()
				.flat_map(|issue| issue.projected)
				.collect(),
			description,
		})
	}
}

enum Children<'a> {
	Array(std::slice::Iter<'a, Value>),
	Object(serde_json::map::Values<'a>),
}

impl<'a> Children<'a> {
	fn next(&mut self) -> Option<&'a Value> {
		match self {
			Self::Array(values) => values.next(),
			Self::Object(values) => values.next(),
		}
	}
}

/// Scratch grows with depth, never with the number of siblings in a payload.
fn deeper_than(root: &Value, limit: usize) -> bool {
	let mut current = (root, 0);
	let mut frames: Vec<(Children<'_>, usize)> = Vec::new();
	loop {
		let (value, depth) = current;
		if depth > limit {
			return true;
		}
		match value {
			Value::Array(values) => frames.push((Children::Array(values.iter()), depth)),
			Value::Object(values) => frames.push((Children::Object(values.values()), depth)),
			_ => {}
		}
		loop {
			let Some((children, depth)) = frames.last_mut() else {
				return false;
			};
			if let Some(value) = children.next() {
				current = (value, *depth + 1);
				break;
			}
			frames.pop();
		}
	}
}

impl Validation<'_> {
	fn json_value(&mut self, value: Option<&Value>, path: &[Value], object: bool) {
		let Some(value) = value else {
			self.invalid_type(value, path, "nonoptional");
			return;
		};
		if deeper_than(value, 1000) {
			self.custom(
				path,
				"JSON value exceeds maximum nesting depth of 1000. This release has no runtime override.",
				true,
			);
		} else if object && !value.is_object() {
			self.custom(path, "Expected JSON object", true);
		}
	}

	fn strings(&mut self, value: Option<&Value>, path: &[Value], nonempty: bool, min_count: bool) {
		if let Some(values) = self.array(value, path) {
			for (index, value) in values.iter().enumerate() {
				self.string(Some(value), &child(path, index), nonempty);
			}
		}
		if min_count {
			self.min_length(value, path, 1);
		}
	}

	fn unsigned(&mut self, value: Option<&Value>, path: &[Value]) {
		let Some(number) = value.and_then(Value::as_f64) else {
			self.invalid_type(value, path, "number");
			return;
		};
		if number.fract() != 0.0 {
			self.invalid_type(value, path, "int");
			return;
		}
		if number > 9_007_199_254_740_991.0 {
			self.add(
				path,
				"Too big: expected int to be <=9007199254740991".into(),
				vec![json!({"path":path,"reason":"out_of_range","maximum":9007199254740991u64})],
				false,
			);
		}
		if number < -9_007_199_254_740_991.0 {
			self.add(
				path,
				"Too small: expected int to be >=-9007199254740991".into(),
				vec![json!({"path":path,"reason":"out_of_range","minimum":-9007199254740991i64})],
				false,
			);
		}
		if number < 0.0 {
			self.add(
				path,
				"Too small: expected number to be >=0".into(),
				vec![json!({"path":path,"reason":"out_of_range","minimum":0})],
				false,
			);
		}
	}

	fn provider(&mut self, value: Option<&Value>, path: &[Value], committed: bool) {
		let Some(map) = self.object(value, path) else {
			return;
		};
		self.string(map.get("id"), &child(path, "id"), true);
		self.string(map.get("name"), &child(path, "name"), true);
		let version = map.get("version");
		if committed || version != Some(&Value::Null) {
			self.string(version, &child(path, "version"), committed);
		}
		self.unknown(map, &["id", "name", "version"], path);
	}

	fn subject(&mut self, value: Option<&Value>, path: &[Value], manifest: bool) {
		let Some(map) = self.object(value, path) else {
			return;
		};
		let formats = if manifest {
			&FORMATS[..FORMATS.len() - 1]
		} else {
			FORMATS
		};
		if !self.discriminator(map.get("format"), &child(path, "format"), formats) {
			return;
		}
		if !manifest {
			self.string(map.get("name"), &child(path, "name"), true);
		}
		let digest_path = child(path, "digest");
		if let Some(digest) = self.object(map.get("digest"), &digest_path) {
			self.digest(digest.get("sha256"), &child(&digest_path, "sha256"), "");
			self.unknown(digest, &["sha256"], &digest_path);
		}
		if !manifest {
			self.nul_free(map.get("local_path"), &child(path, "local_path"));
		}
		let architecture = map.get("architecture");
		let allowed = match map["format"].as_str() {
			Some("gamecube-dol") => &["powerpc"],
			Some("raw-binary") => ARCHITECTURES,
			_ => DETECTED_ARCHITECTURES,
		};
		if map["format"] == "gamecube-dol" || architecture != Some(&Value::Null) {
			self.choice(architecture, &child(path, "architecture"), allowed);
		}
		self.unknown(
			map,
			if manifest {
				&["digest", "format", "architecture"]
			} else {
				&["name", "digest", "local_path", "format", "architecture"]
			},
			path,
		);
	}

	fn profile(&mut self, value: Option<&Value>, path: &[Value]) -> SourceResult<()> {
		let start = self.issues.len();
		let Some(map) = self.object(value, path) else {
			return Ok(());
		};
		self.provider(map.get("provider"), &child(path, "provider"), true);
		self.json_value(map.get("parameters"), &child(path, "parameters"), true);
		self.digest(map.get("digest"), &child(path, "digest"), "");
		self.unknown(map, &["provider", "parameters", "digest"], path);
		if !self.aborted_from(start) && self.gap.is_none() {
			if map.values().any(|value| deeper_than(value, 126)) {
				self.gap = Some("canonical-json-depth-over-127");
				return Ok(());
			}
			let digest = digest_fields(&[
				("parameters", &map["parameters"]),
				("provider", &map["provider"]),
			])?;
			if map["digest"].as_str() != Some(&digest) {
				self.custom(
					&child(path, "digest"),
					"Analysis profile digest does not match its parameters",
					false,
				);
			}
		}
		Ok(())
	}

	fn environment(&mut self, value: Option<&Value>, path: &[Value]) {
		let Some(map) = self.object(value, path) else {
			return;
		};
		for key in ["id", "platform", "architecture"] {
			self.string(map.get(key), &child(path, key), true);
		}
		self.choice(map.get("isolation"), &child(path, "isolation"), ISOLATION);
		self.unknown(map, &["id", "platform", "architecture", "isolation"], path);
	}

	fn limited_directions(&mut self, value: &Value, path: &[Value]) {
		let branches: &[&[&str]] = &[&["callers"], &["callees"], &["callers", "callees"]];
		let mut failures = Vec::new();
		for allowed in branches {
			let mut branch = Validation::new(None);
			if let Some(values) = value.as_array() {
				for (index, literal) in allowed.iter().enumerate() {
					branch.choice(values.get(index), &child(path, index), &[*literal]);
				}
				for (index, value) in values.iter().enumerate().skip(allowed.len()) {
					if value.as_str().is_some_and(|text| allowed.contains(&text)) {
						continue;
					}
					let item_path = child(path, index);
					let projected = allowed
						.iter()
						.map(
							|literal| json!({"path":item_path,"reason":"invalid_value","expected":[literal]}),
						)
						.collect();
					branch.add(&item_path, "Invalid input".into(), projected, true);
				}
				if values.len() > allowed.len() {
					branch.add(
						path,
						format!("Too big: expected array to have <={} items", allowed.len()),
						vec![json!({"path":path,"reason":"out_of_range","maximum":allowed.len()})],
						false,
					);
				}
			} else {
				branch.invalid_type(Some(value), path, "tuple");
			}
			if branch.issues.is_empty() {
				return;
			}
			failures.push(branch);
		}
		if let Some(index) = failures.iter().position(|branch| !branch.aborted_from(0)) {
			self.issues.extend(failures.swap_remove(index).issues);
			return;
		}
		let mut unique = BTreeSet::new();
		let mut projected = Vec::new();
		for issue in failures
			.into_iter()
			.flat_map(|branch| branch.issues)
			.flat_map(|issue| issue.projected)
		{
			if unique.insert(issue.to_string()) {
				projected.push(issue);
			}
		}
		self.add(path, "Invalid input".into(), projected, true);
	}

	fn coverage(&mut self, value: Option<&Value>, path: &[Value]) {
		let Some(map) = self.object(value, path) else {
			return;
		};
		if !self.discriminator(
			map.get("status"),
			&child(path, "status"),
			&["complete", "partial", "unknown"],
		) {
			return;
		}
		let Some(state) = map["status"].as_str() else {
			return;
		};
		if state == "partial" {
			self.strings(
				map.get("limitations"),
				&child(path, "limitations"),
				true,
				true,
			);
		}
		if state == "unknown" {
			self.string(map.get("reason"), &child(path, "reason"), true);
		}
		if let Some(value) = map
			.get("limited_directions")
			.filter(|_| state != "complete")
		{
			self.limited_directions(value, &child(path, "limited_directions"));
		}
		if let Some(value) = map.get("diagnostics") {
			self.strings(Some(value), &child(path, "diagnostics"), true, true);
		}
		let fields: &[&str] = match state {
			"partial" => &["status", "limitations", "limited_directions", "diagnostics"],
			"unknown" => &["status", "reason", "limited_directions", "diagnostics"],
			_ => &["status", "diagnostics"],
		};
		self.unknown(map, fields, path);
	}

	fn location(&mut self, value: Option<&Value>, path: &[Value]) {
		let Some(map) = self.object(value, path) else {
			return;
		};
		if !self.discriminator(
			map.get("kind"),
			&child(path, "kind"),
			&[
				"address",
				"address-range",
				"artifact-path",
				"file-offset",
				"file-offset-range",
			],
		) {
			return;
		}
		let fields: &[&str] = match map["kind"].as_str() {
			Some("address") => {
				self.string(map.get("address"), &child(path, "address"), true);
				&["kind", "address"]
			}
			Some("address-range") => {
				for key in ["start", "end"] {
					self.string(map.get(key), &child(path, key), true);
				}
				&["kind", "start", "end"]
			}
			Some("artifact-path") => {
				self.string(map.get("path"), &child(path, "path"), true);
				&["kind", "path"]
			}
			Some("file-offset") => {
				self.unsigned(map.get("offset"), &child(path, "offset"));
				&["kind", "offset"]
			}
			_ => {
				for key in ["start", "end"] {
					self.unsigned(map.get(key), &child(path, key));
				}
				&["kind", "start", "end"]
			}
		};
		self.unknown(map, fields, path);
	}

	fn record(&mut self, value: &Value, path: &[Value]) -> SourceResult<()> {
		let start = self.issues.len();
		let Some(map) = self.object(Some(value), path) else {
			return Ok(());
		};
		self.digest(map.get("evidence_id"), &child(path, "evidence_id"), "ev_");
		if map.get("subject") != Some(&Value::Null) {
			self.subject(map.get("subject"), &child(path, "subject"), false);
		}
		self.provider(map.get("provider"), &child(path, "provider"), false);
		if map.get("analysis_profile") != Some(&Value::Null) {
			self.profile(
				map.get("analysis_profile"),
				&child(path, "analysis_profile"),
			)?;
		}
		self.string(
			map.get("predicate_type"),
			&child(path, "predicate_type"),
			true,
		);
		self.string(map.get("operation"), &child(path, "operation"), true);
		self.json_value(map.get("parameters"), &child(path, "parameters"), true);
		if let Some(value) = map.get("caller_input_path") {
			self.nul_free(Some(value), &child(path, "caller_input_path"));
		}
		self.json_value(map.get("raw_result"), &child(path, "raw_result"), false);
		self.json_value(
			map.get("normalized_result"),
			&child(path, "normalized_result"),
			false,
		);
		self.choice(
			map.get("confidence"),
			&child(path, "confidence"),
			CONFIDENCE,
		);
		self.choice(map.get("authority"), &child(path, "authority"), AUTHORITY);
		if map.get("environment") != Some(&Value::Null) {
			self.environment(map.get("environment"), &child(path, "environment"));
		}
		self.strings(
			map.get("limitations"),
			&child(path, "limitations"),
			false,
			false,
		);
		if map.get("relationship_coverage") != Some(&Value::Null) {
			self.coverage(
				map.get("relationship_coverage"),
				&child(path, "relationship_coverage"),
			);
		}
		let locations = child(path, "locations");
		if let Some(values) = self.array(map.get("locations"), &locations) {
			for (index, value) in values.iter().enumerate() {
				self.location(Some(value), &child(&locations, index));
			}
		}
		let links = child(path, "evidence_links");
		if let Some(values) = self.array(map.get("evidence_links"), &links) {
			for (index, value) in values.iter().enumerate() {
				self.digest(Some(value), &child(&links, index), "ev_");
			}
		}
		self.unknown(map, RECORD_FIELDS, path);
		if !self.aborted_from(start)
			&& self.gap.is_none()
			&& !map["analysis_profile"].is_null()
			&& map["analysis_profile"]["provider"] != map["provider"]
		{
			self.custom(
				&child(&child(path, "analysis_profile"), "provider"),
				"Analysis profile provider does not match Evidence provider",
				false,
			);
		}
		Ok(())
	}
}

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

fn internal(error: impl fmt::Display) -> SourceError {
	SourceError::Internal {
		message: error.to_string(),
	}
}

fn checked_array(value: &Value) -> SourceResult<&[Value]> {
	value
		.as_array()
		.map(Vec::as_slice)
		.ok_or_else(|| internal("validated Evidence array changed shape"))
}

fn checked_string(value: &Value) -> SourceResult<&str> {
	value
		.as_str()
		.ok_or_else(|| internal("validated Evidence string changed shape"))
}

fn digest_fields(fields: &[(&str, &Value)]) -> SourceResult<String> {
	let mut output = HashWriter(Sha256::new());
	output.write_all(b"{").map_err(internal)?;
	for (index, (key, value)) in fields.iter().enumerate() {
		if index > 0 {
			output.write_all(b",").map_err(internal)?;
		}
		serde_json::to_writer(&mut output, key).map_err(internal)?;
		output.write_all(b":").map_err(internal)?;
		rea_evidence::write_canonical(value, &mut output).map_err(internal)?;
	}
	output.write_all(b"}").map_err(internal)?;
	Ok(output
		.0
		.finalize()
		.into_iter()
		.map(|byte| format!("{byte:02x}"))
		.collect())
}

fn record_digest(record: &Value, legacy: bool) -> SourceResult<String> {
	let mut output = HashWriter(Sha256::new());
	output.write_all(b"{").map_err(internal)?;
	for (index, key) in SEMANTIC_FIELDS
		.iter()
		.filter(|key| !legacy || **key != "relationship_coverage")
		.enumerate()
	{
		if index > 0 {
			output.write_all(b",").map_err(internal)?;
		}
		serde_json::to_writer(&mut output, key).map_err(internal)?;
		output.write_all(b":").map_err(internal)?;
		let value = &record[*key];
		if *key == "subject" && !value.is_null() {
			output.write_all(b"{\"architecture\":").map_err(internal)?;
			rea_evidence::write_canonical(&value["architecture"], &mut output).map_err(internal)?;
			output.write_all(b",\"digest\":").map_err(internal)?;
			rea_evidence::write_canonical(&value["digest"], &mut output).map_err(internal)?;
			output.write_all(b",\"format\":").map_err(internal)?;
			rea_evidence::write_canonical(&value["format"], &mut output).map_err(internal)?;
			output.write_all(b"}").map_err(internal)?;
		} else {
			rea_evidence::write_canonical(value, &mut output).map_err(internal)?;
		}
	}
	output.write_all(b"}").map_err(internal)?;
	Ok(format!(
		"ev_{}",
		output
			.0
			.finalize()
			.into_iter()
			.map(|byte| format!("{byte:02x}"))
			.collect::<String>()
	))
}

fn authenticate_identity(
	record: &Value,
	path: &[Value],
	validation: &mut Validation<'_>,
) -> SourceResult<()> {
	for key in SEMANTIC_FIELDS {
		if deeper_than(&record[*key], 127) {
			return Err(SourceError::ProfileGap {
				feature: "canonical-json-depth-over-127",
			});
		}
	}
	if record["evidence_id"].as_str() != Some(&record_digest(record, false)?) {
		let legacy = record["relationship_coverage"].is_null()
			&& record["evidence_id"].as_str() == Some(&record_digest(record, true)?);
		validation.custom(
			&child(path, "evidence_id"),
			if legacy {
				LEGACY_ID_MESSAGE
			} else {
				"Evidence semantic identifier does not match its record"
			},
			false,
		);
	}
	Ok(())
}

fn strip_proto(value: &mut Value) {
	if let Some(map) = value.as_object_mut() {
		map.remove("__proto__");
	}
}

fn normalize_record_schema(value: &mut Value) {
	strip_proto(value);
	for path in [
		"/subject",
		"/subject/digest",
		"/provider",
		"/analysis_profile",
		"/analysis_profile/provider",
		"/environment",
		"/relationship_coverage",
	] {
		if let Some(value) = value.pointer_mut(path) {
			strip_proto(value);
		}
	}
	if let Some(values) = value.get_mut("locations").and_then(Value::as_array_mut) {
		for value in values {
			strip_proto(value);
		}
	}
}

/// Authenticate an owned inline record. The caller applies the chosen view's
/// inline admission budget before calling this function, as the frozen Service
/// does. Payload ownership transfers into the returned immutable Arc.
pub(super) fn authenticate_inline(record: Value) -> SourceResult<Arc<Value>> {
	authenticate_inline_with_order(record, None)
}

pub(super) fn authenticate_inline_with_order<'a>(
	mut record: Value,
	order: Option<&'a KeyOrderResolver<'a>>,
) -> SourceResult<Arc<Value>> {
	normalize_record_schema(&mut record);
	let mut validation = Validation::new(order);
	validation.record(&record, &[])?;
	if !validation.aborted_from(0) && validation.gap.is_none() {
		authenticate_identity(&record, &[], &mut validation)?;
	}
	validation.finish()?;
	Ok(Arc::new(record))
}

fn bundle_schema_error(error: SourceError) -> SourceError {
	match error {
		SourceError::InvalidRecord { description, .. } => SourceError::InvalidBundle {
			message: format!(
				"Evidence bundle does not match the bundle schema {description}. Supply an unmodified bundle produced by this REA identity format. Recreate observations from earlier formats; re-exporting an old bundle does not update its identities."
			),
		},
		other => other,
	}
}

fn bundle_constraint(message: &str) -> SourceError {
	SourceError::InvalidBundle {
		message: format!(
			"Evidence bundle validation failed: {message}. Recreate or re-export the bundle, then try again."
		),
	}
}

fn bundle_shape<'a>(
	value: &mut Value,
	order: Option<&'a KeyOrderResolver<'a>>,
) -> SourceResult<()> {
	strip_proto(value);
	let mut validation = Validation::new(order);
	let Some(map) = value.as_object_mut() else {
		validation.invalid_type(Some(value), &[], "object");
		return validation.finish();
	};
	for field in [
		"artifacts",
		"providers",
		"environments",
		"scenarios",
		"captures",
		"unknowns",
		"records",
	] {
		let path = vec![json!(field)];
		let Some(values) = map.get_mut(field).and_then(Value::as_array_mut) else {
			validation.invalid_type(map.get(field), &path, "array");
			continue;
		};
		for (index, value) in values.iter_mut().enumerate() {
			let path = child(&path, index);
			match field {
				"records" => normalize_record_schema(value),
				"unknowns" => {}
				_ => {
					strip_proto(value);
					if field == "artifacts" {
						if let Some(digest) = value.get_mut("digest") {
							strip_proto(digest);
						}
					}
				}
			}
			match field {
				"artifacts" => validation.subject(Some(value), &path, true),
				"providers" => validation.provider(Some(value), &path, false),
				"environments" => validation.environment(Some(value), &path),
				"records" => validation.record(value, &path)?,
				"unknowns" => residual_unknown::validate_shape(value, &path, &mut validation)?,
				"scenarios" | "captures" => {
					let Some(item) = validation.object(Some(value), &path) else {
						continue;
					};
					validation.digest(item.get("evidence_id"), &child(&path, "evidence_id"), "ev_");
					if field == "scenarios" {
						validation.string(item.get("operation"), &child(&path, "operation"), true);
						validation.choice(
							item.get("authority"),
							&child(&path, "authority"),
							&["controlled-replay"],
						);
						validation.unknown(item, &["evidence_id", "operation", "authority"], &path);
					} else {
						validation.string(
							item.get("predicate_type"),
							&child(&path, "predicate_type"),
							true,
						);
						validation.unknown(item, &["evidence_id", "predicate_type"], &path);
					}
				}
				_ => {}
			}
		}
	}
	validation.unknown(
		map,
		&[
			"artifacts",
			"providers",
			"environments",
			"scenarios",
			"captures",
			"unknowns",
			"records",
		],
		&[],
	);
	validation.finish()
}

/// These manifest members have only strings and fixed nested digest objects.
/// Their declaration-order JSON is the upstream uniqueSorted key; Rust UTF-8
/// string order agrees with Unicode code point order for admitted strings.
fn manifest_key(value: &Value, fields: &[&str]) -> String {
	let fields = fields
		.iter()
		.map(|key| format!("{}:{}", json!(key), value[*key]))
		.collect::<Vec<_>>();
	format!("{{{}}}", fields.join(","))
}

fn equal_manifest<'a>(actual: &Value, expected: impl IntoIterator<Item = &'a Value>) -> bool {
	let Some(actual) = actual.as_array() else {
		return false;
	};
	let mut expected = expected.into_iter();
	for item in actual {
		if expected.next().is_none_or(|expected| item != expected) {
			return false;
		}
	}
	expected.next().is_none()
}

fn canonical_bundle(value: &Value) -> SourceResult<bool> {
	let unknowns = checked_array(&value["unknowns"])?;
	let mut prior_unknown: Option<(&str, u64)> = None;
	for unknown in unknowns {
		let key = (
			checked_string(&unknown["unknown_id"])?,
			unknown["revision"]
				.as_u64()
				.ok_or_else(|| internal("validated unknown revision is unavailable"))?,
		);
		if prior_unknown.is_some_and(|prior| prior >= key) {
			return Ok(false);
		}
		prior_unknown = Some(key);
	}
	let records = checked_array(&value["records"])?;
	let mut artifacts = BTreeMap::new();
	let mut providers = BTreeMap::new();
	let mut environments = BTreeMap::new();
	let mut scenarios = Vec::new();
	let mut captures = Vec::new();
	let mut previous: Option<&str> = None;
	for record in records {
		let id = checked_string(&record["evidence_id"])?;
		if previous.is_some_and(|previous| previous >= id) {
			return Ok(false);
		}
		previous = Some(id);
		let subject = &record["subject"];
		if !subject.is_null() {
			// Only these bounded identity fields are copied; display strings and
			// raw/normalized results remain in the original owned record.
			let artifact = json!({"digest":subject["digest"],"format":subject["format"],"architecture":subject["architecture"]});
			let mut check = Validation::new(None);
			check.subject(Some(&artifact), &[], true);
			check.finish().map_err(bundle_schema_error)?;
			artifacts.insert(
				manifest_key(&artifact, &["digest", "format", "architecture"]),
				artifact,
			);
		}
		let provider = &record["provider"];
		providers.insert(manifest_key(provider, &["id", "name", "version"]), provider);
		let environment = &record["environment"];
		if !environment.is_null() {
			environments.insert(
				manifest_key(
					environment,
					&["id", "platform", "architecture", "isolation"],
				),
				environment,
			);
		}
		if record["authority"] == "controlled-replay" {
			scenarios.push(record);
		}
		if record["predicate_type"] == "rea.process-capture" {
			captures.push(record);
		}
	}
	if !equal_manifest(&value["artifacts"], artifacts.values())
		|| !equal_manifest(&value["providers"], providers.into_values())
		|| !equal_manifest(&value["environments"], environments.into_values())
	{
		return Ok(false);
	}
	for (field, expected, keys) in [
		(
			"scenarios",
			scenarios,
			&["evidence_id", "operation", "authority"][..],
		),
		("captures", captures, &["evidence_id", "predicate_type"][..]),
	] {
		let actual = checked_array(&value[field])?;
		if actual.len() != expected.len() {
			return Ok(false);
		}
		if actual
			.iter()
			.zip(expected)
			.any(|(item, record)| keys.iter().any(|key| item[*key] != record[*key]))
		{
			return Ok(false);
		}
	}
	Ok(true)
}

fn bundle_authenticate<'a>(
	value: &mut Value,
	order: Option<&'a KeyOrderResolver<'a>>,
) -> SourceResult<()> {
	bundle_shape(value, order).map_err(bundle_schema_error)?;
	bundle_semantics(value, order)
}

fn bundle_semantics<'a>(
	value: &Value,
	order: Option<&'a KeyOrderResolver<'a>>,
) -> SourceResult<()> {
	let records = checked_array(&value["records"])?;
	let mut ids = BTreeSet::new();
	for record in records {
		if !ids.insert(checked_string(&record["evidence_id"])?) {
			return Err(bundle_constraint(
				"Evidence bundle contains duplicate record IDs",
			));
		}
	}
	let unknowns = checked_array(&value["unknowns"])?;
	residual_unknown::validate_graph(
		&unknowns.iter().collect::<Vec<_>>(),
		&records.iter().collect::<Vec<_>>(),
	)
	.map_err(|message| bundle_constraint(&message))?;
	for (index, record) in records.iter().enumerate() {
		let mut validation = Validation::new(order);
		authenticate_identity(record, &[json!("records"), json!(index)], &mut validation)?;
		validation.finish().map_err(bundle_schema_error)?;
	}
	if !canonical_bundle(value)? {
		return Err(bundle_constraint(
			"Evidence bundle manifests are not canonical",
		));
	}
	for (index, record) in records.iter().enumerate() {
		if record["predicate_type"] != "rea.process-capture" {
			continue;
		}
		let resolver = |path: &[Value]| {
			let mut prefixed = vec![json!("records"), json!(index), json!("normalized_result")];
			prefixed.extend_from_slice(path);
			order.and_then(|resolve| resolve(&prefixed))
		};
		let capture_order: Option<&KeyOrderResolver<'_>> =
			order.map(|_| &resolver as &KeyOrderResolver<'_>);
		if let Err(error) =
			process_capture::authenticate(&record["normalized_result"], capture_order)
		{
			return Err(match error {
				SourceError::InvalidRecord { description, .. } => SourceError::InvalidBundle {
					message: format!("Process capture record {} has an invalid normalized_result ({description}). Recreate or re-export the bundle, then try again.", checked_string(&record["evidence_id"])?),
				},
				other => other,
			});
		}
	}
	Ok(())
}

fn list_record_ids(records: &[Value]) -> SourceResult<String> {
	let mut labels = Vec::new();
	let mut bytes = 0usize;
	for record in records {
		let separator = if labels.is_empty() { "" } else { ", " };
		let remaining = 2048 - bytes;
		let id = checked_string(&record["evidence_id"])?;
		let operation = checked_string(&record["operation"])?;
		let mut label = format!("{id} (operation omitted)");
		if operation.encode_utf16().take(remaining + 1).count() <= remaining {
			let complete = format!("{id} ({operation})");
			if serde_json::to_vec(&format!("{separator}{complete}"))
				.map_err(internal)?
				.len() <= remaining
			{
				label = complete;
			}
		}
		let encoded = serde_json::to_vec(&format!("{separator}{label}"))
			.map_err(internal)?
			.len();
		if encoded > remaining {
			break;
		}
		labels.push(label);
		bytes += encoded;
	}
	let omitted = records.len() - labels.len();
	let listed = labels.join(", ");
	Ok(if omitted > 0 {
		format!("{listed} and {omitted} more")
	} else {
		listed
	})
}

#[cfg(test)]
pub(super) fn authenticate_file(
	value: Value,
	path: &str,
	evidence_id: Option<&str>,
) -> SourceResult<Arc<Value>> {
	authenticate_file_with_order(value, path, evidence_id, None)
}

pub(super) fn authenticate_file_with_order<'a>(
	mut value: Value,
	path: &str,
	evidence_id: Option<&str>,
	order: Option<&'a KeyOrderResolver<'a>>,
) -> SourceResult<Arc<Value>> {
	if !value
		.as_object()
		.is_some_and(|map| map.contains_key("records"))
	{
		let record = authenticate_inline_with_order(value, order)?;
		if let Some(selected) =
			evidence_id.filter(|selected| record["evidence_id"].as_str() != Some(*selected))
		{
			return Err(SourceError::Selection {
				message: format!(
					"Evidence file {path} holds {}, not selected record {selected}.",
					checked_string(&record["evidence_id"])?
				),
			});
		}
		return Ok(record);
	}
	bundle_authenticate(&mut value, order)?;
	let records = checked_array(&value["records"])?;
	let selected = if let Some(id) = evidence_id {
		let Some(index) = records
			.iter()
			.position(|record| record["evidence_id"].as_str() == Some(id))
		else {
			return Err(SourceError::Selection {
				message: format!(
					"Evidence bundle {path} holds no record {id}. It holds {}.",
					list_record_ids(records)?
				),
			});
		};
		index
	} else {
		if records.is_empty() {
			return Err(SourceError::Selection {
				message: format!("Evidence bundle {path} holds no records."),
			});
		}
		if records.len() > 1 {
			return Err(SourceError::Selection {
				message: format!(
					"Evidence bundle {path} holds {} records; select one with source.evidence_id. It holds {}.",
					records.len(),
					list_record_ids(records)?
				),
			});
		}
		0
	};
	let Value::Object(mut map) = value else {
		return Err(internal("validated bundle changed shape"));
	};
	let Some(Value::Array(mut records)) = map.remove("records") else {
		return Err(internal("validated bundle records changed shape"));
	};
	Ok(Arc::new(records.swap_remove(selected)))
}

/// Unlike a file-backed view, public import requires all seven bundle arrays.
/// A valid standalone Evidence record has the upstream wrong-kind diagnostic;
/// Ordinary record validation failures retain the bundle-schema diagnostic;
/// unexpected schema exceptions propagate exactly as the original fallback.
pub(super) fn authenticate_import_with_order<'a>(
	mut value: Value,
	order: Option<&'a KeyOrderResolver<'a>>,
) -> Result<AuthenticatedBundle, ImportSourceError> {
	if let Err(shape_error) = bundle_shape(&mut value, order) {
		if !matches!(&shape_error, SourceError::InvalidRecord { .. }) {
			return Err(shape_error.into());
		}
		normalize_record_schema(&mut value);
		let mut validation = Validation::new(order);
		let checked = validation.record(&value, &[]).and_then(|_| {
			if !validation.aborted_from(0) && validation.gap.is_none() {
				authenticate_identity(&value, &[], &mut validation)?;
			}
			Ok(())
		});
		return match checked.and_then(|()| validation.finish()) {
			Ok(()) => Err(ImportSourceError::SingleRecord {
				evidence_id: checked_string(&value["evidence_id"])?.to_owned(),
			}),
			Err(SourceError::InvalidRecord { .. }) => Err(bundle_schema_error(shape_error).into()),
			Err(other) => Err(other.into()),
		};
	}
	bundle_semantics(&value, order)?;
	let Value::Object(mut bundle) = value else {
		return Err(internal("authenticated bundle lost its object").into());
	};
	let Some(Value::Array(records)) = bundle.remove("records") else {
		return Err(internal("authenticated records are unavailable").into());
	};
	let Some(Value::Array(unknowns)) = bundle.remove("unknowns") else {
		return Err(internal("authenticated unknowns are unavailable").into());
	};
	Ok(AuthenticatedBundle { records, unknowns })
}

#[cfg(test)]
#[path = "rea_evidence_source_tests.rs"]
mod tests;
