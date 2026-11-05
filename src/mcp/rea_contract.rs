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
	/// Frozen Zod coercion exceptions are plain SDK error text, not a JSON
	/// analysis failure. Only internal validators construct this representation.
	pub(super) fn schema_exception(message: &'static str) -> Self {
		Self(Value::String(message.to_owned()))
	}

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

	pub(super) fn adapter(provider: &str, operation: &str) -> Self {
		let message = "Analysis could not complete. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";
		Self(
			json!({"code":"execution_failure","category":"execution_failure",
			"message":message,"retryable":false,"remediation":{"action":message},
			"details":{"provider_id":provider,"operation":operation}}),
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
		let text = match self.0 {
			Value::String(message) => message,
			value => json!({"error":value}).to_string(),
		};
		let mut result = CallToolResult::error(vec![ContentBlock::text(text)]);
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

const NODE_STRING_CODE_UNITS: usize = 536_870_888;
const RESERVED_STRING_CODE_UNITS: usize = NODE_STRING_CODE_UNITS - 1024;

/// This is an explicitly selected counting order, not a reconstruction of an
/// unknown JavaScript producer. Complete JSON byte and escape totals are
/// independent of member order. Only a Fits result can use that fact; an
/// overflow requires its actual producer order.
struct CountingOrder;
impl super::rea_response_encoding::ObjectOrder for CountingOrder {
	fn keys<'a>(
		&self,
		_path: &[super::rea_response_encoding::PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> anyhow::Result<Vec<&'a str>> {
		let keys: Vec<&str> = object.keys().map(String::as_str).collect();
		super::rea_response_encoding::declared_keys(object, &keys)
	}
}

struct WireMeasurement {
	bytes: u64,
	code_units: u64,
	constraint: &'static str,
}

/// A checked destination for the already measured, admitted JSON text.
struct MeasuredText {
	bytes: Vec<u8>,
	limit: usize,
}
impl Write for MeasuredText {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
			return Err(io::Error::other(
				"Response encoder exceeded its measured text size",
			));
		}
		self.bytes.extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

pub(super) fn success(operation: &str, value: Value, retained: Option<Value>) -> CallToolResult {
	let bundle_summary = value
		.get("result")
		.and_then(|value| value.get("kind"))
		.is_some_and(|kind| kind == "evidence-bundle-summary");
	let summary_order = super::rea_response_order::BundleSummaryOrder(&value);
	let order: Option<&dyn super::rea_response_encoding::ObjectOrder> = if bundle_summary {
		Some(&summary_order)
	} else {
		None
	};
	deliver_view(
		operation,
		super::rea_response_encoding::JsonView::Value(&value),
		order,
		retained,
		bundle_summary,
		operation != "export_evidence_bundle",
		|| Ok(value.clone()),
	)
}

pub(super) fn success_borrowed(
	operation: &str,
	value: &Value,
	retained: Option<Value>,
	origin: super::rea_response_order::RecordOrigin,
) -> CallToolResult {
	let order = super::rea_response_order::RecordOrder::new(value, origin);
	deliver_view(
		operation,
		super::rea_response_encoding::JsonView::Value(value),
		Some(&order),
		retained,
		false,
		true,
		|| Ok(value.clone()),
	)
}

/// Borrow even large retained payloads while checking their complete delivery.
/// `materialize` runs only after admission; refusal never deep-clones a bundle.
pub(super) fn deliver_view(
	operation: &str,
	value: super::rea_response_encoding::JsonView<'_>,
	original_order: Option<&dyn super::rea_response_encoding::ObjectOrder>,
	retained: Option<Value>,
	bundle_summary: bool,
	target_content: bool,
	materialize: impl FnOnce() -> serde_json::Result<Value>,
) -> CallToolResult {
	use super::rea_response_encoding::{self as encoding, Budget, Measurement, Representations};
	let response_bytes = match response_budget() {
		Ok(value) => value,
		Err(error) => return error.wire(),
	};
	let budget = Budget {
		bytes: (response_bytes - ENVELOPE_RESERVATION) as u64,
		representations: Representations::StructuredAndText,
		target_content,
	};
	let formatter = super::rea_evidence::canonical_js_number;
	let order = original_order.unwrap_or(&CountingOrder);
	let measured = match encoding::measure_view(value, order, formatter, budget) {
		Ok(value) => value,
		Err(error) => {
			return Failure::output(
				operation,
				format!("Complete result measurement failed: {error:#}"),
			)
			.wire()
		}
	};
	if matches!(measured, Measurement::Overflow { .. }) && original_order.is_none() {
		return Failure::output(operation, "Complete result exceeds its response budget, but its original producer field order is unavailable; no approximate overflow count was reported.").wire();
	}
	let json_bytes = match measured {
		Measurement::Overflow {
			bytes_at_least,
			code_units_at_least,
			constraint,
		} => {
			let measured = WireMeasurement {
				bytes: bytes_at_least,
				code_units: code_units_at_least,
				constraint: constraint.as_str(),
			};
			return overflow(
				operation,
				response_bytes,
				&measured,
				retained,
				bundle_summary,
			)
			.wire();
		}
		Measurement::Fits { json_bytes, .. } => match usize::try_from(json_bytes) {
			Ok(size) => size,
			Err(_) => {
				return Failure::output(
					operation,
					"Admitted JSON size is not addressable on this host.",
				)
				.wire()
			}
		},
	};
	let mut output = MeasuredText {
		bytes: Vec::new(),
		limit: json_bytes,
	};
	if output.bytes.try_reserve_exact(json_bytes).is_err() {
		return Failure::resource(
			operation,
			"memory",
			"Host memory could not hold the admitted response text.",
			json!({"response_text_bytes":json_bytes}),
			false,
			"Retry with sufficient host memory, or export the retained Evidence.",
		)
		.wire();
	}
	if let Err(error) = encoding::write_json_view(value, order, formatter, &mut output) {
		return Failure::output(
			operation,
			format!("Complete result encoding failed: {error:#}"),
		)
		.wire();
	}
	if output.bytes.len() != json_bytes {
		return Failure::output(
			operation,
			"Response encoder changed its measured JSON size.",
		)
		.wire();
	}
	let text = match String::from_utf8(output.bytes) {
		Ok(text) => text,
		Err(error) => return Failure::output(operation, error.to_string()).wire(),
	};
	let structured = match materialize() {
		Ok(value) => value,
		Err(error) => return Failure::output(operation, error.to_string()).wire(),
	};
	let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
	result.is_error = None;
	result.structured_content = Some(structured);
	result.meta = target_content.then(target_meta);
	result
}

pub(super) fn response_budget() -> Result<usize, Failure> {
	static BUDGET: OnceLock<Result<usize, String>> = OnceLock::new();
	BUDGET.get_or_init(|| {
		let Some(value) = std::env::var_os("REA_MCP_MAX_RESPONSE_BYTES") else { return Ok(RESPONSE_BYTES); };
		let valid = value.to_str().and_then(|text| {
			if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) { return None; }
			text.parse::<u64>().ok().filter(|number| (RESPONSE_BYTES as u64..=9_007_199_254_740_991).contains(number)).and_then(|number| usize::try_from(number).ok())
		});
		valid.ok_or_else(|| "REA_MCP_MAX_RESPONSE_BYTES must be a decimal safe integer at least 10485760 bytes, the default stdio receive-buffer size.".to_owned())
	}).clone().map_err(|reason| Failure(json!({"code":"configuration_invalid","category":"invalid_input",
		"message":format!("REA configuration is invalid: {reason}"),"retryable":false,
		"remediation":{"action":"Correct REA_MCP_MAX_RESPONSE_BYTES in the environment that starts REA (your shell or the MCP client's registration), then rerun."},
		"details":{"settings":[{"setting":"REA_MCP_MAX_RESPONSE_BYTES","constraint":reason}]}})))
}

fn overflow(
	operation: &str,
	response_bytes: usize,
	measured: &WireMeasurement,
	retained: Option<Value>,
	bundle_summary: bool,
) -> Failure {
	let next = if retained.is_some() {
		"Export retained evidence to consume the complete analysis, or use complete CLI JSON output."
	} else if operation == "get_evidence_bundle" && bundle_summary {
		"Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable."
	} else if operation == "get_evidence_bundle" {
		"Discover retained records with get_evidence_bundle and detail: summary, then inspect compatible records through inspect_analysis_view using an exact Evidence reference. Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable."
	} else {
		"Use complete CLI JSON output to consume the analysis."
	};
	let string_limit = measured.constraint == "string-length";
	let facts = if string_limit {
		format!("REA's reserved single-string limit is {RESERVED_STRING_CODE_UNITS} UTF-16 code units, below Node's single-string ceiling of {NODE_STRING_CODE_UNITS} UTF-16 code units. This release has no runtime override for either limit, and REA_MCP_MAX_RESPONSE_BYTES does not raise them.")
	} else {
		format!("The effective REA_MCP_MAX_RESPONSE_BYTES value is {response_bytes} bytes (floor 10485760 bytes, 10 MiB). A change requires restarting the REA process and a matching client receive buffer. It does not raise REA's reserved single-string limit of {RESERVED_STRING_CODE_UNITS} UTF-16 code units or Node's single-string ceiling of {NODE_STRING_CODE_UNITS} UTF-16 code units. This release has no runtime override for either limit.")
	};
	let summary = if string_limit {
		"The operation completed, but its complete MCP response exceeds REA's reserved single-string limit."
	} else {
		"The operation completed, but its complete MCP response exceeds the stdio response budget. The analysis result was not truncated."
	};
	let mut limits = json!({"boundary":"mcp-response","default_receive_buffer_bytes":RESPONSE_BYTES,
		"result_budget_bytes":response_bytes-ENVELOPE_RESERVATION,"max_string_code_units":RESERVED_STRING_CODE_UNITS,
		"response_bytes_at_least":measured.bytes,"response_code_units_at_least":measured.code_units,"constraint":measured.constraint});
	if let Some(reference) = retained {
		limits["evidence_id"] = reference["evidence_id"].clone();
		limits["evidence_reference"] = reference;
	}
	Failure::resource(
		operation,
		"transport",
		&format!("{summary} {facts} {next}"),
		limits,
		false,
		&format!("{next} {facts}"),
	)
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

pub(super) fn apk_input_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/inspect_apk_signature.input.json"
				))
				.expect("frozen APK input schema"),
			)
		})
		.clone()
}

pub(super) fn apk_output_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/inspect_apk_signature.output.json"
				))
				.expect("frozen APK output schema"),
			)
		})
		.clone()
}

pub(super) fn view_input_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/inspect_analysis_view.input.json"
				))
				.expect("frozen analysis view input schema"),
			)
		})
		.clone()
}

pub(super) fn view_output_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/inspect_analysis_view.output.json"
				))
				.expect("frozen analysis view output schema"),
			)
		})
		.clone()
}
