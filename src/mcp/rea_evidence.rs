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

//! REA 6.8.0 canonical Evidence ID verification for a deliberately limited
//! JSON-safe-integer profile. This is not full upstream Zod schema validation.
//! Source: morluto/rea 93b8b82d src/domain/evidence.ts and canonicalDigest.ts.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt::{self, Write};
use std::path::Path;

use super::{rea_files, runtime};

const MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EXACT_JS_INT: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct VerifyEvidenceParams {
	/// Absolute path to a JSON Evidence record within a configured controller workspace.
	pub path: String,
}

/// JSON parsing which refuses duplicate keys, including deeply nested objects.
#[derive(Debug)]
struct UniqueJson(Value);

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
	type Value = UniqueJson;

	fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str("JSON with no repeated object members")
	}
	fn visit_unit<E: DeError>(self) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(Value::Null))
	}
	fn visit_none<E: DeError>(self) -> std::result::Result<Self::Value, E> {
		self.visit_unit()
	}
	fn visit_bool<E: DeError>(self, x: bool) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(json!(x)))
	}
	fn visit_i64<E: DeError>(self, x: i64) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(Value::Number(Number::from(x))))
	}
	fn visit_u64<E: DeError>(self, x: u64) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(Value::Number(Number::from(x))))
	}
	fn visit_f64<E: DeError>(self, x: f64) -> std::result::Result<Self::Value, E> {
		Number::from_f64(x)
			.map(|v| UniqueJson(Value::Number(v)))
			.ok_or_else(|| E::custom("nonfinite JSON value"))
	}
	fn visit_str<E: DeError>(self, x: &str) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(json!(x)))
	}
	fn visit_string<E: DeError>(self, x: String) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(Value::String(x)))
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Self::Value, A::Error> {
		let mut values = Vec::new();
		while let Some(UniqueJson(value)) = a.next_element::<UniqueJson>()? {
			values.push(value);
		}
		Ok(UniqueJson(Value::Array(values)))
	}
	fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Self::Value, A::Error> {
		let mut map = Map::new();
		while let Some((key, UniqueJson(value))) = a.next_entry::<String, UniqueJson>()? {
			if map.contains_key(&key) {
				return Err(A::Error::custom(format!("duplicate JSON member {key}")));
			}
			map.insert(key, value);
		}
		Ok(UniqueJson(Value::Object(map)))
	}
}
impl<'de> Deserialize<'de> for UniqueJson {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
		deserializer.deserialize_any(UniqueVisitor)
	}
}

pub(super) fn parse_unique_json(data: &[u8]) -> Result<Value> {
	let record: UniqueJson = serde_json::from_slice(data)
		.context("JSON object contains duplicates or invalid fields")?;
	Ok(record.0)
}

fn canonical(value: &Value, out: &mut String, depth: usize) -> Result<()> {
	if depth > 128 {
		bail!("REA subset canonicalization depth exceeded");
	}
	match value {
		Value::Null => out.push_str("null"),
		Value::Bool(true) => out.push_str("true"),
		Value::Bool(false) => out.push_str("false"),
		Value::String(s) => out.push_str(&serde_json::to_string(s)?),
		Value::Number(n) => {
			if let Some(i) = n.as_i64() {
				if i < -(MAX_EXACT_JS_INT as i64) {
					bail!("REA numeric member exceeds exact JavaScript integer range");
				}
				write!(out, "{i}")?;
			} else if let Some(u) = n.as_u64() {
				if u > MAX_EXACT_JS_INT {
					bail!("REA numeric member exceeds exact JavaScript integer range");
				}
				write!(out, "{u}")?;
			} else {
				bail!("fractional or exponent JSON number is not qualified by subset verifier");
			}
		}
		Value::Array(values) => {
			out.push('[');
			for (i, member) in values.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				canonical(member, out, depth + 1)?;
			}
			out.push(']');
		}
		Value::Object(values) => {
			let mut sorted: Vec<_> = values.iter().collect();
			sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
			out.push('{');
			for (i, (key, member)) in sorted.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				out.push_str(&serde_json::to_string(key)?);
				out.push(':');
				canonical(member, out, depth + 1)?;
			}
			out.push('}');
		}
	}
	Ok(())
}

fn canonical_sha(value: &Value) -> Result<String> {
	let mut encoded = String::new();
	canonical(value, &mut encoded, 0)?;
	let digest = Sha256::digest(encoded.as_bytes());
	let mut result = String::with_capacity(64);
	for b in digest {
		write!(result, "{b:02x}")?;
	}
	Ok(result)
}

fn obj<'a>(v: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
	v.as_object()
		.ok_or_else(|| anyhow!("{label} must be object"))
}
fn field<'a>(m: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
	m.get(name)
		.ok_or_else(|| anyhow!("REA Evidence requires field {name} (even when null)"))
}
fn nonempty<'a>(v: &'a Value, label: &str) -> Result<&'a str> {
	let text = v
		.as_str()
		.ok_or_else(|| anyhow!("{label} must be string"))?;
	if text.is_empty() {
		bail!("{label} cannot be empty");
	}
	Ok(text)
}
fn exact_fields(m: &Map<String, Value>, required: &[&str], optional: &[&str]) -> Result<()> {
	for key in required {
		field(m, key)?;
	}
	for key in m.keys() {
		if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
			bail!("unexpected REA Evidence member {key}");
		}
	}
	Ok(())
}
fn hash_form(v: &Value, prefix: &str) -> Result<()> {
	let text = nonempty(v, "digest")?;
	let Some(digest) = text.strip_prefix(prefix) else {
		bail!("unexpected evidence digest prefix");
	};
	if digest.len() != 64
		|| !digest
			.bytes()
			.all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
	{
		bail!("invalid lowercase SHA-256 digest shape");
	}
	Ok(())
}
fn provider(v: &Value) -> Result<()> {
	let p = obj(v, "provider")?;
	exact_fields(p, &["id", "name", "version"], &[])?;
	nonempty(field(p, "id")?, "provider.id")?;
	nonempty(field(p, "name")?, "provider.name")?;
	if !field(p, "version")?.is_null() {
		nonempty(field(p, "version")?, "provider.version")?;
	}
	Ok(())
}
fn subject(v: &Value) -> Result<Value> {
	if v.is_null() {
		return Ok(Value::Null);
	}
	let s = obj(v, "subject")?;
	exact_fields(
		s,
		&["name", "local_path", "digest", "format", "architecture"],
		&[],
	)?;
	nonempty(field(s, "name")?, "subject.name")?;
	let path = field(s, "local_path")?
		.as_str()
		.ok_or_else(|| anyhow!("local_path not string"))?;
	if path.contains('\0') {
		bail!("local_path contains NUL");
	}
	nonempty(field(s, "format")?, "subject.format")?;
	if !field(s, "architecture")?.is_null() {
		nonempty(field(s, "architecture")?, "subject.architecture")?;
	}
	let digest = obj(field(s, "digest")?, "subject.digest")?;
	exact_fields(digest, &["sha256"], &[])?;
	hash_form(
		&Value::String(format!(
			"sha_{}",
			nonempty(field(digest, "sha256")?, "subject.sha256")?
		)),
		"sha_",
	)?;
	Ok(
		json!({"digest":field(s,"digest")?, "format":field(s,"format")?, "architecture":field(s,"architecture")?}),
	)
}
fn profile(v: &Value, owner: &Value) -> Result<()> {
	if v.is_null() {
		return Ok(());
	}
	let p = obj(v, "analysis_profile")?;
	exact_fields(p, &["provider", "parameters", "digest"], &[])?;
	provider(field(p, "provider")?)?;
	if field(p, "provider")? != owner {
		bail!("analysis_profile provider does not match Evidence provider");
	}
	obj(field(p, "parameters")?, "profile parameters")?;
	let checksum = nonempty(field(p, "digest")?, "profile digest")?;
	hash_form(&Value::String(format!("sha_{checksum}")), "sha_")?;
	let unsigned = json!({"provider":field(p,"provider")?, "parameters":field(p,"parameters")?});
	if checksum != canonical_sha(&unsigned)? {
		bail!("analysis_profile digest mismatch");
	}
	Ok(())
}
fn coverage(v: &Value) -> Result<()> {
	if v.is_null() {
		return Ok(());
	}
	let m = obj(v, "relationship_coverage")?;
	let state = nonempty(field(m, "status")?, "coverage.status")?;
	match state {
		"complete" => exact_fields(m, &["status"], &["diagnostics"])?,
		"partial" => exact_fields(
			m,
			&["status", "limitations"],
			&["limited_directions", "diagnostics"],
		)?,
		"unknown" => exact_fields(
			m,
			&["status", "reason"],
			&["limited_directions", "diagnostics"],
		)?,
		_ => bail!("invalid relationship coverage status"),
	}
	if state == "unknown" {
		nonempty(field(m, "reason")?, "coverage.reason")?;
	}
	if state == "partial" {
		let arr = field(m, "limitations")?
			.as_array()
			.ok_or_else(|| anyhow!("coverage limitations not array"))?;
		if arr.is_empty() || arr.iter().any(|v| v.as_str().is_none_or(str::is_empty)) {
			bail!("invalid coverage limitations");
		}
	}
	if let Some(dir) = m.get("limited_directions") {
		let arr = dir
			.as_array()
			.ok_or_else(|| anyhow!("limited directions not array"))?;
		let direction: Vec<_> = arr.iter().map(Value::as_str).collect();
		if !matches!(
			direction.as_slice(),
			[Some("callers")] | [Some("callees")] | [Some("callers"), Some("callees")]
		) {
			bail!("invalid limited directions");
		}
	}
	if let Some(notes) = m.get("diagnostics") {
		let arr = notes
			.as_array()
			.ok_or_else(|| anyhow!("coverage diagnostics not array"))?;
		if arr.is_empty() || arr.iter().any(|v| v.as_str().is_none_or(str::is_empty)) {
			bail!("invalid coverage diagnostics");
		}
	}
	Ok(())
}

fn verify_record(record: &Value) -> Result<Value> {
	let m = obj(record, "Evidence")?;
	exact_fields(
		m,
		&[
			"evidence_id",
			"subject",
			"provider",
			"analysis_profile",
			"predicate_type",
			"operation",
			"parameters",
			"raw_result",
			"normalized_result",
			"confidence",
			"authority",
			"environment",
			"limitations",
			"relationship_coverage",
			"locations",
			"evidence_links",
		],
		&["caller_input_path"],
	)?;
	hash_form(field(m, "evidence_id")?, "ev_")?;
	let subject_identity = subject(field(m, "subject")?)?;
	provider(field(m, "provider")?)?;
	profile(field(m, "analysis_profile")?, field(m, "provider")?)?;
	nonempty(field(m, "predicate_type")?, "predicate_type")?;
	nonempty(field(m, "operation")?, "operation")?;
	obj(field(m, "parameters")?, "parameters")?;
	let confidence = nonempty(field(m, "confidence")?, "confidence")?;
	if !["observed", "derived", "inferred"].contains(&confidence) {
		bail!("invalid confidence");
	}
	let authority = nonempty(field(m, "authority")?, "authority")?;
	if ![
		"shipped-artifact",
		"controlled-replay",
		"historical-reference",
		"external-service",
		"analyst-inference",
	]
	.contains(&authority)
	{
		bail!("invalid evidence authority");
	}
	let limits = field(m, "limitations")?
		.as_array()
		.ok_or_else(|| anyhow!("limitations not array"))?;
	if limits.iter().any(|x| x.as_str().is_none()) {
		bail!("nonstring evidence limitation");
	}
	let locations = field(m, "locations")?
		.as_array()
		.ok_or_else(|| anyhow!("locations not array"))?;
	for location in locations {
		let item = obj(location, "location")?;
		let kind = nonempty(field(item, "kind")?, "location kind")?;
		match kind {
			"address" => {
				exact_fields(item, &["kind", "address"], &[])?;
				nonempty(field(item, "address")?, "address")?;
			}
			"address-range" => {
				exact_fields(item, &["kind", "start", "end"], &[])?;
				nonempty(field(item, "start")?, "start")?;
				nonempty(field(item, "end")?, "end")?;
			}
			"artifact-path" => {
				exact_fields(item, &["kind", "path"], &[])?;
				nonempty(field(item, "path")?, "path")?;
			}
			"file-offset" => {
				exact_fields(item, &["kind", "offset"], &[])?;
				if field(item, "offset")?.as_u64().is_none() {
					bail!("bad file-offset");
				}
			}
			"file-offset-range" => {
				exact_fields(item, &["kind", "start", "end"], &[])?;
				if field(item, "start")?.as_u64().is_none()
					|| field(item, "end")?.as_u64().is_none()
				{
					bail!("bad file range");
				}
			}
			_ => bail!("invalid evidence location"),
		}
	}
	let links = field(m, "evidence_links")?
		.as_array()
		.ok_or_else(|| anyhow!("evidence_links not array"))?;
	for link in links {
		hash_form(link, "ev_")?;
	}
	coverage(field(m, "relationship_coverage")?)?;
	if !field(m, "environment")?.is_null() {
		let env = obj(field(m, "environment")?, "environment")?;
		exact_fields(env, &["id", "platform", "architecture", "isolation"], &[])?;
		for key in ["id", "platform", "architecture"] {
			nonempty(field(env, key)?, key)?;
		}
		if !["none", "process", "container", "virtual-machine"]
			.contains(&nonempty(field(env, "isolation")?, "isolation")?)
		{
			bail!("bad isolation");
		}
	}
	if let Some(path) = m.get("caller_input_path") {
		let text = path
			.as_str()
			.ok_or_else(|| anyhow!("caller_input_path not string"))?;
		if text.contains('\0') {
			bail!("caller_input_path contains NUL");
		}
	}
	let projected = json!({
		"subject":subject_identity,
		"provider":field(m,"provider")?,
		"analysis_profile":field(m,"analysis_profile")?,
		"predicate_type":field(m,"predicate_type")?,
		"operation":field(m,"operation")?,
		"parameters":field(m,"parameters")?,
		"raw_result":field(m,"raw_result")?,
		"normalized_result":field(m,"normalized_result")?,
		"confidence":field(m,"confidence")?,
		"authority":field(m,"authority")?,
		"environment":field(m,"environment")?,
		"limitations":field(m,"limitations")?,
		"relationship_coverage":field(m,"relationship_coverage")?,
		"locations":field(m,"locations")?,
		"evidence_links":field(m,"evidence_links")?
	});
	let expected = format!("ev_{}", canonical_sha(&projected)?);
	let supplied = nonempty(field(m, "evidence_id")?, "evidence_id")?;
	if supplied != expected {
		bail!("REA semantic digest mismatch (including relationship_coverage)");
	}
	Ok(json!({
		"status":"subset_digest_verified",
		"evidence_id":expected,
		"rea_full_schema_qualified":false,
		"numeric_profile":"safe_integer_only",
		"upstream_source":"morluto/rea@93b8b82db70279e40f484114cff9dc1958dc14ee",
		"limitations":[
			"Digest matches REA canonical semantic projection for safe-integer JSON subset only",
			"Full upstream Zod schema and fractional-number canonicalization are not qualified",
			"A matching hash does not prove provider truth or artifact authenticity"
		]
	}))
}

pub async fn verify_evidence(params: VerifyEvidenceParams) -> Result<String> {
	let bytes = rea_files::read_bounded(
		Path::new(&params.path),
		&runtime::runtime_config()?.controller_workspace_roots,
		MAX_BYTES,
	)
	.await?;
	let record: UniqueJson = serde_json::from_slice(&bytes)
		.context("REA evidence must have no duplicate JSON object keys")?;
	let result = verify_record(&record.0)?;
	Ok(serde_json::to_string(&result)?)
}

#[cfg(test)]
#[path = "rea_evidence_tests.rs"]
mod rea_evidence_tests;
