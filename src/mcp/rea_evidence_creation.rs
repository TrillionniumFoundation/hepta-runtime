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

//! Construct the complete frozen REA 6.8.0 Evidence envelope from an owned
//! observation. Protocol normalization follows the MIT-licensed REA producer;
//! see LICENSES/REA-MIT.txt. Provider identity is supplied by the operation,
//! never accepted from a public inspect request. Construction is distinct from
//! operation qualification and does not assert provider truth or authenticity.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Map, Value};
use std::path::Path;

use super::{canonical_sha, field, obj, semantic_record_content, verify_record};

fn optional<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
	map.get(name).filter(|value| !value.is_null())
}

fn defaulted(map: &Map<String, Value>, name: &str, default: Value) -> Value {
	optional(map, name).cloned().unwrap_or(default)
}

/// Create a record using the exact public producer defaults, including the
/// explicit null relationship-coverage commitment introduced before 6.8.0.
/// The input convention is REA's observation object (camelCase for optional
/// producer fields); the returned record uses the public snake_case schema.
pub(crate) fn create_record(
	target: Option<&Value>,
	provider: &Value,
	observation: &Value,
) -> Result<Value> {
	let observation = obj(observation, "Evidence observation")?;
	let provider = obj(provider, "Evidence provider")?;
	let subject = match target {
		None => Value::Null,
		Some(target) => {
			let target = obj(target, "Evidence target")?;
			let path = field(target, "path")?
				.as_str()
				.ok_or_else(|| anyhow!("Evidence target.path must be string"))?;
			let name = Path::new(path)
				.file_name()
				.and_then(|part| part.to_str())
				.filter(|name| !name.is_empty())
				.unwrap_or("artifact");
			let format = field(target, "format")?
				.as_str()
				.ok_or_else(|| anyhow!("Evidence target.format must be string"))?;
			// This is the authenticated npm 6.8.0 subject vocabulary. The
			// separately pinned Git tree contains additional source-only formats.
			if !matches!(
				format,
				"hopper"
					| "analysis-database"
					| "mach-o" | "elf"
					| "pe" | "dos-mz"
					| "dos-com" | "raw-binary"
					| "gamecube-dol"
					| "zip" | "ipa" | "apk"
					| "msix" | "appx"
					| "hap" | "hsp" | "app-pack"
					| "asar" | "godot-pck"
					| "dmg" | "pkg" | "plist"
					| "javascript" | "source-map"
					| "directory" | "file"
					| "unknown" | "mach-o-universal"
					| "javascript-bundle"
					| "entitlements"
					| "pyinstaller" | "node-sea"
			) {
				bail!("Evidence target.format is outside the frozen npm 6.8.0 contract");
			}
			json!({
				"name": name,
				"digest": {"sha256": field(target, "sha256")?},
				"format": format,
				"architecture": defaulted(target, "architecture", Value::Null),
				"local_path": path
			})
		}
	};
	let mut limitations = Vec::new();
	if target.is_none() {
		limitations.push(defaulted(
			observation,
			"subjectUnavailableReason",
			json!("Artifact identity is unavailable for this observation."),
		));
	}
	if let Some(values) = optional(observation, "limitations") {
		limitations.extend(
			values
				.as_array()
				.ok_or_else(|| anyhow!("Evidence observation.limitations must be array"))?
				.iter()
				.cloned(),
		);
	}
	let mut record = json!({
		"evidence_id": format!("ev_{}", "0".repeat(64)),
		"subject": subject,
		"provider": {
			"id": field(provider, "id")?,
			"name": field(provider, "name")?,
			"version": field(provider, "version")?
		},
		"analysis_profile": defaulted(observation, "analysisProfile", Value::Null),
		"predicate_type": defaulted(observation, "predicateType", json!("rea.analysis")),
		"operation": field(observation, "operation")?,
		"parameters": field(observation, "parameters")?,
		"raw_result": defaulted(observation, "rawResult", Value::Null),
		"normalized_result": field(observation, "result")?,
		"confidence": defaulted(observation, "confidence", json!("observed")),
		"authority": defaulted(observation, "authority", json!("shipped-artifact")),
		"environment": defaulted(observation, "environment", Value::Null),
		"limitations": limitations,
		"relationship_coverage": defaulted(observation, "relationshipCoverage", Value::Null),
		"locations": defaulted(observation, "locations", json!([])),
		"evidence_links": defaulted(observation, "evidenceLinks", json!([]))
	});
	let digest = canonical_sha(&semantic_record_content(&record)?)?;
	record["evidence_id"] = json!(format!("ev_{digest}"));
	verify_record(&record)?;
	Ok(record)
}

#[cfg(test)]
#[path = "rea_evidence_creation_tests.rs"]
mod tests;
