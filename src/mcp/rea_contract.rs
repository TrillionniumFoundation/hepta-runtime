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

//! Shared wire projection for the frozen REA operation contracts.
//!
//! Application failures stay tool results, with target-content provenance.
//! They are not converted to JSON-RPC routing errors or lossy text previews.

use rmcp::model::{CallToolResult, ContentBlock, JsonObject};
use serde_json::{json, Map, Value};
use std::io::{self, Write};
use std::sync::{Arc, OnceLock};

pub(super) const RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const ENVELOPE_RESERVATION: usize = 1024;

#[derive(Debug, Clone)]
pub(super) struct Failure(pub Value);

impl Failure {
	pub(super) fn input(operation: &str, issues: Vec<Value>) -> Self {
		let mut error = json!({
			"code":"invalid_request", "category":"invalid_input",
			"message":"Analysis input is invalid. Check the arguments and try again.",
			"retryable":false,
			"remediation":{"action":format!("Read the declared input schema or CLI usage for {operation}; if using MCP and the catalog may be stale, call tools/list. Correct the listed fields, then retry. Do not repeat the unchanged call.")},
			"recovery":{"kind":"inspect_input_contract","operation":operation}
		});
		if !issues.is_empty() {
			error["details"] = json!({"operation":operation,"issues":issues});
		}
		Self(error)
	}

	pub(super) fn output(operation: &str, reason: impl Into<String>) -> Self {
		let message = "Analysis returned an unreadable result. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";
		Self(
			json!({"code":"unreadable_output","category":"execution_failure",
			"message":message,"retryable":false,"remediation":{"action":message},
			"details":{"operation":operation,"reason":reason.into()}}),
		)
	}

	pub(super) fn integrity(reason: impl Into<String>) -> Self {
		let message =
			"Evidence is invalid or has changed. Recreate or re-import it, then try again.";
		Self(
			json!({"code":"evidence_integrity_mismatch","category":"integrity_mismatch",
			"message":message,"retryable":false,"remediation":{"action":message},
			"details":{"reason":reason.into()}}),
		)
	}

	pub(super) fn cancelled(operation: &str) -> Self {
		let message = "Analysis was cancelled. Start it again when ready.";
		Self(
			json!({"code":"cancelled","category":"cancelled","message":message,
			"retryable":true,"remediation":{"action":message},
			"details":{"operation":operation,"cleanup":"complete"}}),
		)
	}

	pub(super) fn timeout(operation: &str, timeout_ms: u64) -> Self {
		Self(json!({"code":"provider_timeout","category":"timeout",
			"message":format!("REA's {operation} operation reached its {timeout_ms}ms server/provider deadline. This is not a client-side timeout; extending only the MCP client's deadline does not change this budget."),
			"retryable":true,
			"remediation":{"action":format!("Inspect any partial Evidence, provider diagnostics and reported session/provider cleanup state for {operation}. Reduce the request if supported, or resolve the reported provider condition before retrying. Do not repeat the unchanged call or retry while work or cleanup may still be active.")},
			"recovery":{"kind":"inspect_timeout_state","operation":operation,"timeout_ms":timeout_ms},
			"details":{"operation":operation,"timeout_ms":timeout_ms}}))
	}

	pub(super) fn unsupported(operation: &str, path: &str, reason: &str) -> Self {
		Self(
			json!({"code":"unsupported_target","category":"unsupported_target",
			"message":format!("Unsupported target for {operation} at {path}: {reason}"),
			"retryable":false,
			"remediation":{"action":"Select a target supported by this operation or choose an operation supporting the reported target format."},
			"details":{"operation":operation,"path":path,"reason":reason}}),
		)
	}

	pub(super) fn access(operation: &str, path: &str, system_code: &str) -> Self {
		Self(json!({"code":"access_denied","category":"unavailable",
			"message":"Host filesystem permissions denied read access to the selected path.","retryable":false,
			"remediation":{"action":"Check the current process's read access to the selected path. Retry with a readable local file."},
			"details":{"operation":operation,"path":path,"system_code":system_code,"boundary":"filesystem-read"}}))
	}

	pub(super) fn changed(operation: &str, path: &str, reason: &str) -> Self {
		Self(
			json!({"code":"artifact_changed","category":"integrity_mismatch",
			"message":"The selected artifact changed during acquisition; no stable snapshot was decoded.","retryable":true,
			"remediation":{"action":"Wait until the selected file is stable. For an active binary session, reopen the target with open_binary before retrying so REA acquires its current identity; for a CLI command or target-free tool, rerun the operation."},
			"details":{"operation":operation,"path":path,"reason":reason,"boundary":"stable-artifact-read"}}),
		)
	}

	pub(super) fn resource(
		operation: &str,
		resource: &str,
		reason: &str,
		limits: Value,
		retryable: bool,
		remediation: &str,
	) -> Self {
		Self(
			json!({"code":"resource_constraint","category":"resource_constraint",
			"message":reason,"retryable":retryable,"remediation":{"action":remediation},
			"details":{"operation":operation,"resource":resource,"reason":reason,"reported_limits":limits}}),
		)
	}

	pub(super) fn partial(mut self, observation: Value) -> Self {
		if self.0.get("details").is_none() {
			self.0["details"] = json!({});
		}
		self.0["details"]["partial_observation"] = observation;
		self
	}

	pub(super) fn wire(self) -> CallToolResult {
		let mut result = CallToolResult::error(vec![ContentBlock::text(
			json!({"error":self.0}).to_string(),
		)]);
		result.meta = Some(target_meta());
		result
	}
}

fn target_meta() -> rmcp::model::MetaObject {
	let mut meta = JsonObject::new();
	meta.insert(
		"provenance".to_owned(),
		json!({"untrusted_content":true,"source":"analysis_target"}),
	);
	rmcp::model::MetaObject(meta)
}

/// Stop the serializer at the receive budget instead of allocating an
/// unbounded second JSON representation merely to measure it.
struct BoundedCounter {
	bytes: usize,
	limit: usize,
}
impl Write for BoundedCounter {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.bytes = self.bytes.saturating_add(bytes.len());
		if self.bytes > self.limit {
			return Err(io::Error::other("REA MCP result exceeds receive budget"));
		}
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

pub(super) fn success(operation: &str, value: Value, retained: Option<Value>) -> CallToolResult {
	let limit = RESPONSE_BYTES - ENVELOPE_RESERVATION;
	let mut counter = BoundedCounter { bytes: 0, limit };
	let raw_fits = serde_json::to_writer(&mut counter, &value).is_ok();
	if raw_fits {
		let mut result = CallToolResult::structured(value);
		// Frozen REA omits isError on success; the SDK's constructor inserts false.
		result.is_error = None;
		result.meta = Some(target_meta());
		let mut delivered = BoundedCounter { bytes: 0, limit };
		if serde_json::to_writer(&mut delivered, &result).is_ok() {
			return result;
		}
	}
	let mut error = Failure::resource(operation, "transport",
		"Complete result exceeds the native MCP response budget.",
		json!({"maximum_response_bytes":RESPONSE_BYTES,"result_budget_bytes":limit}), false,
		"Discover retained records with rea_get_evidence_bundle and detail: summary. A complete result requires a client and server with a sufficient response budget.");
	if let Some(reference) = retained {
		error = error.partial(reference);
	}
	error.wire()
}

/// Input objects are parsed explicitly: a JSON number such as 1.0 or 1e0 is
/// an integer in the upstream schema, although serde's u64 visitor rejects it.
pub(super) fn object<'a>(
	value: &'a Value,
	issues: &mut Vec<Value>,
) -> Option<&'a Map<String, Value>> {
	match value.as_object() {
		Some(map) => Some(map),
		None => {
			issues.push(json!({"path":[],"reason":"invalid_type","expected":"object"}));
			None
		}
	}
}

pub(super) fn unknown_keys(
	map: &Map<String, Value>,
	allowed: &[&str],
	prefix: &[&str],
	issues: &mut Vec<Value>,
) {
	for key in map.keys().filter(|key| !allowed.contains(&key.as_str())) {
		let mut path: Vec<Value> = prefix.iter().map(|s| json!(s)).collect();
		path.push(json!(key));
		issues.push(json!({"path":path,"reason":"unknown_argument"}));
	}
}

pub(super) fn integer(
	map: &Map<String, Value>,
	key: &str,
	default: u64,
	minimum: u64,
	maximum: u64,
	issues: &mut Vec<Value>,
) -> u64 {
	let Some(value) = map.get(key) else {
		return default;
	};
	let Some(number) = value
		.as_f64()
		.filter(|number| number.is_finite() && number.fract() == 0.0)
	else {
		issues.push(json!({"path":[key],"reason":"invalid_type","expected": if value.is_number() {"int"} else {"number"}}));
		return default;
	};
	if number < minimum as f64 {
		issues.push(json!({"path":[key],"reason":"out_of_range","minimum":minimum}));
	}
	if number > maximum as f64 {
		issues.push(json!({"path":[key],"reason":"out_of_range","maximum":maximum}));
	}
	if number < 0.0 || number > u64::MAX as f64 {
		default
	} else {
		number as u64
	}
}

pub(super) fn elf_input_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/inspect_elf_notes.input.json"
				))
				.expect("frozen ELF input schema"),
			)
		})
		.clone()
}
pub(super) fn elf_output_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/inspect_elf_notes.output.json"
				))
				.expect("frozen ELF output schema"),
			)
		})
		.clone()
}
pub(super) fn bundle_input_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/get_evidence_bundle.input.json"
				))
				.expect("frozen bundle input schema"),
			)
		})
		.clone()
}
pub(super) fn bundle_output_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/get_evidence_bundle.output.json"
				))
				.expect("frozen bundle output schema"),
			)
		})
		.clone()
}
