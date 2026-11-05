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

//! Complete, authenticated observations retained by one native MCP session.
//! Clones of a server share this registry; unrelated sessions never do.

use super::rea_contract::{self, Failure};
use super::rea_evidence;
use rmcp::model::CallToolResult;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(super) struct EvidenceSession {
	records: Mutex<BTreeMap<String, Value>>,
}

impl EvidenceSession {
	/// Validate identity before publication. A repeated semantic record keeps
	/// its first display metadata, as the frozen session ledger does.
	pub(super) fn record(&self, evidence: Value) -> Result<Value, Failure> {
		rea_evidence::verify_record(&evidence)
			.map_err(|error| Failure::integrity(error.to_string()))?;
		let id = evidence["evidence_id"]
			.as_str()
			.ok_or_else(|| Failure::integrity("Missing evidence identifier"))?
			.to_owned();
		let mut records = self
			.records
			.lock()
			.map_err(|_| Failure::integrity("Evidence session registry is unavailable"))?;
		if let Some(existing) = records.get(&id) {
			let left = rea_evidence::semantic_record_content(existing)
				.map_err(|error| Failure::integrity(error.to_string()))?;
			let right = rea_evidence::semantic_record_content(&evidence)
				.map_err(|error| Failure::integrity(error.to_string()))?;
			// Canonical IEEE-754 projection also makes integer/f64 spellings
			// identical, matching JavaScript's single Number representation.
			let mut left_json = String::new();
			let mut right_json = String::new();
			rea_evidence::canonical(&left, &mut left_json, 0)
				.map_err(|error| Failure::integrity(error.to_string()))?;
			rea_evidence::canonical(&right, &mut right_json, 0)
				.map_err(|error| Failure::integrity(error.to_string()))?;
			if left_json != right_json {
				return Err(Failure::integrity("Conflicting evidence record"));
			}
		} else {
			records.insert(id.clone(), evidence);
		}
		Ok(json!({"kind":"retained-evidence","evidence_id":id}))
	}

	pub(super) fn get_bundle(&self, raw: Value) -> CallToolResult {
		if let Err(error) = super::rea_mcp_input::bundle(&raw) {
			return error.wire();
		}
		let options = match BundleOptions::parse(&raw) {
			Ok(value) => value,
			Err(error) => return error.wire(),
		};
		let records = match self.records.lock() {
			Ok(records) => records,
			Err(_) => return Failure::integrity("Evidence session registry is unavailable").wire(),
		};
		let value = if options.summary {
			summarize(&records, &options.filters)
		} else {
			bundle(&records)
		};
		drop(records);
		rea_contract::success("get_evidence_bundle", json!({"result":value}), None)
	}
}

#[derive(Debug)]
struct BundleOptions {
	summary: bool,
	filters: Map<String, Value>,
}

impl BundleOptions {
	fn parse(raw: &Value) -> Result<Self, Failure> {
		const OP: &str = "get_evidence_bundle";
		let mut issues = Vec::new();
		let Some(map) = rea_contract::object(raw, &mut issues) else {
			return Err(Failure::input(OP, issues));
		};
		let summary = match map.get("detail") {
			None => false,
			Some(Value::String(detail)) if detail == "complete" => false,
			Some(Value::String(detail)) if detail == "summary" => true,
			Some(_) => {
				issues.push(
					json!({"path":["detail"],"reason":"invalid_value","expected":["complete","summary"]}),
				);
				false
			}
		};
		let mut filters = Map::new();
		if let Some(value) = map.get("filters") {
			if let Some(selected) = value.as_object() {
				for (key, digest) in [
					("evidence_id", true),
					("operation", false),
					("target_sha256", true),
					("analysis_profile_digest", true),
					("procedure_address", false),
				] {
					let Some(value) = selected.get(key) else {
						continue;
					};
					let Some(text) = value.as_str() else {
						issues.push(
							json!({"path":["filters",key],"reason":"invalid_type","expected":"string"}),
						);
						continue;
					};
					if digest {
						let prefix = if key == "evidence_id" { "ev_" } else { "" };
						let valid = text.strip_prefix(prefix).is_some_and(|tail| {
							tail.len() == 64
								&& tail
									.bytes()
									.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
						});
						if !valid {
							issues.push(json!({"path":["filters",key],"reason":"invalid_format","expected":"regex","message":format!("Invalid string: must match pattern /^{prefix}[a-f0-9]{{64}}$/u")}));
						}
					} else if text.is_empty() {
						issues.push(
							json!({"path":["filters",key],"reason":"out_of_range","minimum":1}),
						);
					}
					filters.insert(key.to_owned(), value.clone());
				}
				rea_contract::unknown_keys(
					selected,
					&[
						"evidence_id",
						"operation",
						"target_sha256",
						"analysis_profile_digest",
						"procedure_address",
					],
					&["filters"],
					&mut issues,
				);
			} else {
				issues
					.push(json!({"path":["filters"],"reason":"invalid_type","expected":"object"}));
			}
		}
		rea_contract::unknown_keys(map, &["detail", "filters"], &[], &mut issues);
		if !issues.is_empty() {
			return Err(Failure::input(OP, issues));
		}
		if !summary && map.contains_key("filters") {
			return Err(Failure::input(
				OP,
				vec![json!({"path":["filters"],"reason":"invalid_value",
				"message":"Record filters require detail: summary; complete returns the canonical bundle.","expected":"detail: summary"})],
			));
		}
		Ok(Self { summary, filters })
	}
}

/// Object property order is explicit in these sort keys. The frozen bundle
/// uses JSON.stringify + Unicode scalar ordering, not canonical digest order.
fn manifest_key(value: &Value, keys: &[&str]) -> String {
	let fields: Vec<String> = keys
		.iter()
		.map(|key| format!("{}:{}", json!(key), value[key]))
		.collect();
	format!("{{{}}}", fields.join(","))
}

fn bundle(records: &BTreeMap<String, Value>) -> Value {
	let mut artifacts = BTreeMap::new();
	let mut providers = BTreeMap::new();
	let mut environments = BTreeMap::new();
	let mut scenarios = Vec::new();
	let mut captures = Vec::new();
	for evidence in records.values() {
		if !evidence["subject"].is_null() {
			let subject = &evidence["subject"];
			let artifact = json!({"digest":subject["digest"],"format":subject["format"],"architecture":subject["architecture"]});
			artifacts.insert(
				manifest_key(&artifact, &["digest", "format", "architecture"]),
				artifact,
			);
		}
		let provider = &evidence["provider"];
		providers.insert(
			manifest_key(provider, &["id", "name", "version"]),
			provider.clone(),
		);
		let environment = &evidence["environment"];
		if !environment.is_null() {
			environments.insert(
				manifest_key(
					environment,
					&["id", "platform", "architecture", "isolation"],
				),
				environment.clone(),
			);
		}
		if evidence["authority"] == "controlled-replay" {
			scenarios.push(json!({"evidence_id":evidence["evidence_id"],"operation":evidence["operation"],"authority":evidence["authority"]}));
		}
		if evidence["predicate_type"] == "rea.process-capture" {
			captures.push(
				json!({"evidence_id":evidence["evidence_id"],"predicate_type":evidence["predicate_type"]}),
			);
		}
	}
	json!({"artifacts":artifacts.into_values().collect::<Vec<_>>(),
		"providers":providers.into_values().collect::<Vec<_>>(),
		"environments":environments.into_values().collect::<Vec<_>>(),
		"scenarios":scenarios,"captures":captures,"unknowns":[],
		"records":records.values().collect::<Vec<_>>()})
}

fn native_summary(record: &Value) -> Value {
	if record["operation"] != "analyze_function" {
		return json!({"available":false,"reason":"different-operation"});
	}
	let result = &record["normalized_result"];
	let procedure = &result["procedure"];
	if !procedure["address"].is_string()
		|| (!procedure["name"].is_null() && !procedure["name"].is_string())
	{
		return json!({"available":false,"reason":"not-recorded-or-incompatible"});
	}
	let flow = &result["native_value_flow"];
	let value_flow = if flow.is_null() {
		json!({"status":"not-recorded"})
	} else if flow["available"] == false && flow["reason"].is_string() {
		json!({"status":"unavailable","reason":flow["reason"]})
	} else if flow["available"] == true
		&& flow["truncated"].is_boolean()
		&& [
			"omitted_operations_lower_bound",
			"known_omitted_inputs",
			"known_omitted_edges",
		]
		.iter()
		.all(|key| {
			flow.get(*key).is_none_or(|v| {
				v.as_f64().is_some_and(|n| {
					n.fract() == 0.0 && (0.0..=9_007_199_254_740_991.0).contains(&n)
				})
			})
		}) {
		json!({"status":"observed","truncated":flow["truncated"],
			"omitted_operations_lower_bound":flow["omitted_operations_lower_bound"],
			"known_omitted_inputs":flow["known_omitted_inputs"],"known_omitted_edges":flow["known_omitted_edges"]})
	} else {
		json!({"status":"unknown","reason":"Value-flow metadata has an incompatible representation."})
	};
	json!({"available":true,"procedure_address":procedure["address"],"procedure_name":procedure["name"],"value_flow":value_flow})
}

fn summarize(records: &BTreeMap<String, Value>, filters: &Map<String, Value>) -> Value {
	let mut selected = Vec::new();
	for record in records.values() {
		if [
			("evidence_id", &record["evidence_id"]),
			("operation", &record["operation"]),
			("target_sha256", &record["subject"]["digest"]["sha256"]),
			(
				"analysis_profile_digest",
				&record["analysis_profile"]["digest"],
			),
		]
		.iter()
		.any(|(key, value)| filters.get(*key).is_some_and(|filter| filter != *value))
		{
			continue;
		}
		let native = native_summary(record);
		if filters.get("procedure_address").is_some_and(|filter| {
			native["available"] != true || filter != &native["procedure_address"]
		}) {
			continue;
		}
		selected.push(json!({"evidence_id":record["evidence_id"],"subject":record["subject"],
			"provider":record["provider"],"operation":record["operation"],"confidence":record["confidence"],
			"authority":record["authority"],"analysis_profile_digest":record["analysis_profile"]["digest"],
			"retention":"complete-record","limitation_count":record["limitations"].as_array().map_or(0,Vec::len),
			"native_dossier":native}));
	}
	json!({"kind":"evidence-bundle-summary","filters":filters,"total_retained_records":records.len(),
		"matching_records":selected.len(),"unknown_revisions":0,"records":selected})
}

#[cfg(test)]
#[path = "rea_evidence_session_tests.rs"]
mod tests;
