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

//! Deterministic selected-source and Electron channel candidate graph. A shared
//! string does not establish a live process pair, listener or reachable path.

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::{
	ast, graph_identity, source_identities, validate_request, JavascriptGraphCollection,
	WorkerRequest, MAX_RESPONSE_BYTES, MAX_ROWS, PARSER_VERSION,
};

fn source_position(value: &Value) -> (&str, u64, u64) {
	(
		value["source_id"].as_str().unwrap_or_default(),
		value["span"]["start"].as_u64().unwrap_or_default(),
		value["span"]["end"].as_u64().unwrap_or_default(),
	)
}

fn module_candidates(source: &str, specifier: Option<&str>, ids: &BTreeSet<&str>) -> Value {
	let Some(specifier) = specifier else {
		return json!({"status":"dynamic_specifier","source_ids":[]});
	};
	if !specifier.starts_with("./") && !specifier.starts_with("../") {
		return json!({"status":"external_or_bare_specifier","source_ids":[]});
	}
	if specifier.contains(['\\', '?', '#', ':']) || specifier.chars().any(char::is_control) {
		return json!({"status":"unsupported_specifier_syntax","source_ids":[]});
	}
	let mut components: Vec<_> = source.split('/').collect();
	components.pop();
	for component in specifier.split('/') {
		match component {
			"." | "" => {}
			".." => {
				if components.pop().is_none() {
					return json!({"status":"outside_selected_logical_root","source_ids":[]});
				}
			}
			_ => components.push(component),
		}
	}
	let target = components.join("/");
	if ids.contains(target.as_str()) {
		return json!({"status":"selected_source_exact_path","source_ids":[target]});
	}
	let mut candidates = Vec::new();
	for extension in ["js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx"] {
		for candidate in [
			format!("{target}.{extension}"),
			format!("{target}/index.{extension}"),
		] {
			if ids.contains(candidate.as_str()) {
				candidates.push(candidate);
			}
		}
	}
	candidates.sort();
	json!({
		"status":if candidates.is_empty(){"no_selected_source_candidate"}else{"selected_source_extension_candidates"},
		"source_ids":candidates
	})
}

fn ipc_edges(calls: &[Value]) -> Result<Vec<Value>> {
	let mut receivers: BTreeMap<(&str, &str), Vec<&Value>> = BTreeMap::new();
	for call in calls {
		if let (Some(role), Some(channel)) = (call["role"].as_str(), call["channel"].as_str()) {
			if matches!(
				role,
				"invoke_handler" | "message_handler" | "renderer_handler"
			) {
				receivers.entry((role, channel)).or_default().push(call);
			}
		}
	}
	let mut edges = Vec::new();
	for call in calls {
		let (Some(role), Some(channel)) = (call["role"].as_str(), call["channel"].as_str()) else {
			continue;
		};
		let receiver_role = match role {
			"invoke_sender" => "invoke_handler",
			"message_sender" => "message_handler",
			"renderer_sender" => "renderer_handler",
			_ => continue,
		};
		if let Some(candidates) = receivers.get(&(receiver_role, channel)) {
			for receiver in candidates {
				if edges.len() >= MAX_ROWS {
					bail!("Electron channel candidate graph exceeds 10000 edges");
				}
				edges.push(json!({
					"from":call["node_id"],"to":receiver["node_id"],
					"channel":channel,"relation":"same_channel_candidate",
					"sender_role":role,"receiver_role":receiver_role,
					"runtime_observed":false,"process_pair_proven":false
				}));
			}
		}
	}
	Ok(edges)
}

pub(super) fn report(request: &WorkerRequest) -> Result<Value> {
	validate_request(request)?;
	let sources = source_identities(request);
	let digest = graph_identity(&sources)?;
	if request
		.expected_graph_sha256
		.as_ref()
		.is_some_and(|expected| expected != &digest)
	{
		bail!("JavaScript source set changed; obtain a new first-page graph identity");
	}
	let ids: BTreeSet<_> = request
		.sources
		.iter()
		.map(|source| source.id.as_str())
		.collect();
	let mut modules: Vec<_> = request.sources.iter().collect();
	modules.sort_by(|left, right| left.id.cmp(&right.id));
	let mut imports = Vec::new();
	let mut exports = Vec::new();
	let mut calls = Vec::new();
	let mut unknowns = Vec::new();
	let mut statistics = Vec::new();
	for source in modules {
		let inspected = ast::inspect(source)?;
		statistics.push(json!({
			"source_id":source.id,"ast_nodes":inspected.node_count,
			"lexical_scopes":inspected.scope_count,"syntax_valid":true
		}));
		imports.extend(inspected.imports);
		exports.extend(inspected.exports);
		calls.extend(inspected.electron_calls);
		unknowns.extend(inspected.unknowns);
		if imports.len() + exports.len() + calls.len() + unknowns.len() > MAX_ROWS {
			bail!("JavaScript selected-source graph exceeds 10000 observations");
		}
	}
	for records in [&mut imports, &mut exports, &mut calls, &mut unknowns] {
		records.sort_by(|left, right| source_position(left).cmp(&source_position(right)));
	}
	for import in &mut imports {
		import["target_candidates"] = module_candidates(
			import["source_id"].as_str().unwrap_or_default(),
			import["specifier"].as_str(),
			&ids,
		);
		import["runtime_resolution_proven"] = json!(false);
	}
	for (index, call) in calls.iter_mut().enumerate() {
		call["node_id"] = json!(format!("electron-call-{index}"));
	}
	let edges = ipc_edges(&calls)?;
	let collection = match request.collection {
		JavascriptGraphCollection::Summary => &[][..],
		JavascriptGraphCollection::Imports => imports.as_slice(),
		JavascriptGraphCollection::Exports => exports.as_slice(),
		JavascriptGraphCollection::ElectronCalls => calls.as_slice(),
		JavascriptGraphCollection::IpcEdges => edges.as_slice(),
		JavascriptGraphCollection::Unknowns => unknowns.as_slice(),
	};
	if request.offset > collection.len() {
		bail!("JavaScript graph offset exceeds its selected collection");
	}
	let rows: Vec<_> = collection
		.iter()
		.skip(request.offset)
		.take(request.limit)
		.cloned()
		.collect();
	let end = request.offset + rows.len();
	let report = json!({
		"record_format":"hepta.rea-javascript-graph.v1",
		"rea_evidence_compatible":false,
		"graph_sha256":digest,
		"identity_scope":"complete_selected_source_bytes_and_explicit_grammars",
		"parser":{"name":"oxc","version":PARSER_VERSION,"semantic_syntax_checks":true},
		"sources":sources,
		"source_statistics":statistics,
		"counts":{
			"sources":request.sources.len(),"imports":imports.len(),"exports":exports.len(),
			"electron_calls":calls.len(),"ipc_candidate_edges":edges.len(),
			"reported_unknowns":unknowns.len()
		},
		"collection":request.collection,"total_rows":collection.len(),
		"offset":request.offset,"next_offset":(end<collection.len()).then_some(end),"rows":rows,
		"javascript_executed":false,"dependencies_opened":false,"network_requests":0,
		"coverage":"selected_ast_modules_and_lexical_electron_candidates",
		"complete_application_graph":false,
		"limitations":[
			"Only explicitly selected files are admitted. Package declarations, imports, source maps, ASAR files, dependencies, preload paths and URLs are never followed or executed.",
			"Relative import links identify selected logical-path candidates, not Node, bundler or TypeScript module resolution. Type-only records are retained and are not runtime dependencies.",
			"Electron receivers use lexical symbols from electron imports, unshadowed require calls and direct aliases. Reassigned bindings are excluded; property mutation, eval, factories, indirect calls and interprocedural dataflow are not resolved.",
			"A matching literal channel and API role produces a candidate edge only. Branch reachability, process identity, window ownership, listener registration, sender validation, payload compatibility and runtime message delivery are unobserved.",
			"Dynamic expressions remain unknown. Reported unknowns cover detected syntax patterns, not an exhaustive list of every unmodeled application behavior.",
			"CommonJS assignments are syntactic observations; export replacement, alias mutation and final runtime module values are not evaluated. Preload declarations and contextBridge keys do not prove actual renderer exposure.",
			"Source positions are UTF-8 byte offsets. Parser diagnostics, lone-surrogate strings and exceeded resource bounds refuse the inspection; recovered invalid ASTs are not promoted to valid graphs.",
			"The source-set hash binds copied source bytes and grammars. It is not an atomic multi-file filesystem snapshot, a REA ev_ identity, or an assertion of runtime execution."
		]
	});
	if serde_json::to_vec(&report)?.len() > MAX_RESPONSE_BYTES {
		bail!("JavaScript graph response exceeds 1 MiB; reduce the selected page");
	}
	Ok(report)
}
