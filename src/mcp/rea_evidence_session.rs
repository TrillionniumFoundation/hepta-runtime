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
use super::rea_response_encoding::JsonView;
use super::rea_response_order::{BundleOrder, RecordOrigin};
use rmcp::model::CallToolResult;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub(super) struct EvidenceSession {
	records: Mutex<BTreeMap<String, SessionRecord>>,
}

/// Payload and its first producing entry point are published atomically.
#[derive(Clone, Debug)]
struct SessionRecord {
	evidence: Arc<Value>,
	origin: RecordOrigin,
}

pub(super) struct RetainedRecord {
	pub(super) evidence: Arc<Value>,
	pub(super) reference: Value,
	/// The current invocation; the registry separately keeps its first origin.
	pub(super) origin: RecordOrigin,
}

/// Immutable ownership of one session's complete records at selection time.
/// Payloads are shared, so export and projection do not duplicate large reports.
#[derive(Clone, Debug)]
pub(super) struct EvidenceSnapshot {
	records: BTreeMap<String, Arc<Value>>,
}

impl EvidenceSnapshot {
	pub(super) fn record_count(&self) -> usize {
		self.records.len()
	}
	pub(super) fn unknown_count(&self) -> usize {
		0
	}

	pub(super) fn write_canonical<W: std::io::Write>(&self, output: &mut W) -> anyhow::Result<()> {
		fn array<'a, W: std::io::Write>(
			output: &mut W,
			values: impl IntoIterator<Item = &'a Value>,
		) -> anyhow::Result<()> {
			output.write_all(b"[")?;
			for (index, value) in values.into_iter().enumerate() {
				if index != 0 {
					output.write_all(b",")?;
				}
				rea_evidence::write_canonical(value, output)?;
			}
			output.write_all(b"]")?;
			Ok(())
		}
		let view = bundle(&self.records);
		// ASCII bundle member names have the same canonical UTF-16 order.
		output.write_all(b"{\"artifacts\":")?;
		array(output, &view.artifacts)?;
		output.write_all(b",\"captures\":")?;
		array(output, &view.captures)?;
		output.write_all(b",\"environments\":")?;
		array(output, &view.environments)?;
		output.write_all(b",\"providers\":")?;
		array(output, &view.providers)?;
		output.write_all(b",\"records\":")?;
		array(output, view.records)?;
		output.write_all(b",\"scenarios\":")?;
		array(output, &view.scenarios)?;
		output.write_all(b",\"unknowns\":")?;
		array(output, &view.unknowns)?;
		output.write_all(b"}")?;
		Ok(())
	}
}

impl EvidenceSession {
	pub(super) fn snapshot(&self) -> Result<EvidenceSnapshot, Failure> {
		let records = self
			.records
			.lock()
			.map_err(|_| Failure::integrity("Evidence session registry is unavailable"))?;
		Ok(EvidenceSnapshot {
			records: records
				.iter()
				.map(|(id, entry)| (id.clone(), Arc::clone(&entry.evidence)))
				.collect(),
		})
	}

	pub(super) fn lookup(&self, id: &str) -> Result<Option<Arc<Value>>, Failure> {
		let records = self
			.records
			.lock()
			.map_err(|_| Failure::integrity("Evidence session registry is unavailable"))?;
		Ok(records.get(id).map(|entry| Arc::clone(&entry.evidence)))
	}
	/// Validate identity before publication. A repeated semantic record keeps
	/// its first display metadata, as the frozen session ledger does.
	#[cfg(test)]
	pub(super) fn record(&self, evidence: Value) -> Result<RetainedRecord, Failure> {
		self.record_with_origin(evidence, RecordOrigin::Unknown)
	}

	pub(super) fn record_with_origin(
		&self,
		evidence: Value,
		origin: RecordOrigin,
	) -> Result<RetainedRecord, Failure> {
		self.record_checked(evidence, origin, || Ok(()))
	}

	/// Check cancellation again after digest/conflict validation, immediately
	/// before the publication point. The caller handles later cancellation with
	/// the complete retained reference; records are never rolled back by ID.
	pub(super) fn record_if_active(
		&self,
		evidence: Value,
		origin: RecordOrigin,
		cancellation: &tokio_util::sync::CancellationToken,
		operation: &str,
	) -> Result<RetainedRecord, Failure> {
		self.record_checked(evidence, origin, || {
			if cancellation.is_cancelled() {
				Err(Failure::cancelled(operation))
			} else {
				Ok(())
			}
		})
	}

	fn record_checked(
		&self,
		evidence: Value,
		origin: RecordOrigin,
		active: impl Fn() -> Result<(), Failure>,
	) -> Result<RetainedRecord, Failure> {
		active()?;
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
		let evidence = Arc::new(evidence);
		if let Some(existing) = records.get(&id) {
			if !rea_evidence::semantic_equal(&existing.evidence, &evidence)
				.map_err(|error| Failure::integrity(error.to_string()))?
			{
				return Err(Failure::integrity("Conflicting evidence record"));
			}
			active()?;
		} else {
			active()?;
			records.insert(
				id.clone(),
				SessionRecord {
					evidence: Arc::clone(&evidence),
					origin,
				},
			);
		}
		Ok(RetainedRecord {
			evidence,
			origin,
			reference: json!({"kind":"retained-evidence","evidence_id":id}),
		})
	}

	pub(super) fn get_bundle(&self, raw: Value) -> CallToolResult {
		if let Err(error) = super::rea_mcp_input::bundle(&raw) {
			return error.wire();
		}
		let options = match BundleOptions::parse(&raw) {
			Ok(value) => value,
			Err(error) => return error.wire(),
		};
		let registry = match self.records.lock() {
			Ok(records) => records,
			Err(_) => return Failure::integrity("Evidence session registry is unavailable").wire(),
		};
		// Clone only Arc handles while holding the mutex. Response measurement
		// and encoding run against an immutable selection after releasing it.
		let selected_origins: Vec<RecordOrigin> =
			registry.values().map(|entry| entry.origin).collect();
		let records: BTreeMap<String, Arc<Value>> = registry
			.iter()
			.map(|(id, entry)| (id.clone(), Arc::clone(&entry.evidence)))
			.collect();
		drop(registry);
		if options.summary {
			let value = summarize(&records, &options.filters);
			drop(records);
			rea_contract::success("get_evidence_bundle", json!({"result":value}), None)
		} else {
			// The view borrows payloads. Serialization checks the transport
			// bound before constructing a second owned JSON representation.
			#[derive(serde::Serialize)]
			struct ResultView<'a> {
				result: BundleView<'a>,
			}
			let complete = ResultView {
				result: bundle(&records),
			};
			let view = &complete.result;
			let artifacts: Vec<&Value> = view.artifacts.iter().collect();
			let providers: Vec<&Value> = view.providers.iter().collect();
			let environments: Vec<&Value> = view.environments.iter().collect();
			let scenarios: Vec<&Value> = view.scenarios.iter().collect();
			let captures: Vec<&Value> = view.captures.iter().collect();
			let unknowns: Vec<&Value> = view.unknowns.iter().collect();
			let fields = [
				("artifacts", JsonView::Values(&artifacts)),
				("providers", JsonView::Values(&providers)),
				("environments", JsonView::Values(&environments)),
				("scenarios", JsonView::Values(&scenarios)),
				("captures", JsonView::Values(&captures)),
				("unknowns", JsonView::Values(&unknowns)),
				("records", JsonView::Values(&view.records)),
			];
			let result = [("result", JsonView::Object(&fields))];
			let order = match BundleOrder::new(&view.records, &selected_origins) {
				Ok(order) => order,
				Err(error) => {
					return Failure::output("get_evidence_bundle", error.to_string()).wire()
				}
			};
			// Generic records without recorded producer provenance have no known
			// source order. Their Fits size is order independent; overflow never fabricates
			// a source order. Production producers always supply an explicit origin.
			let known = !selected_origins.contains(&RecordOrigin::Unknown);
			let original_order: Option<&dyn super::rea_response_encoding::ObjectOrder> =
				known.then_some(&order);
			rea_contract::deliver_view(
				"get_evidence_bundle",
				JsonView::Object(&result),
				original_order,
				None,
				false,
				true,
				|| serde_json::to_value(&complete),
			)
		}
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

#[derive(serde::Serialize)]
struct BundleView<'a> {
	artifacts: Vec<Value>,
	providers: Vec<Value>,
	environments: Vec<Value>,
	scenarios: Vec<Value>,
	captures: Vec<Value>,
	unknowns: Vec<Value>,
	records: Vec<&'a Value>,
}

fn bundle(records: &BTreeMap<String, Arc<Value>>) -> BundleView<'_> {
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
	BundleView {
		artifacts: artifacts.into_values().collect(),
		providers: providers.into_values().collect(),
		environments: environments.into_values().collect(),
		scenarios,
		captures,
		unknowns: vec![],
		records: records.values().map(Arc::as_ref).collect(),
	}
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

fn summarize(records: &BTreeMap<String, Arc<Value>>, filters: &Map<String, Value>) -> Value {
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
