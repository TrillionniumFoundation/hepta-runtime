// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::mcp::rea_mcp_transport::ReaMcpTransport;
use rmcp::model::{
	CallToolRequestParams, CallToolResponse, CreateTaskResult, JsonRpcError, MetaObject,
	ServerCapabilities, Task, TaskStatus,
};
use rmcp::{ServerHandler, ServiceExt};
use std::sync::{
	atomic::{AtomicUsize, Ordering},
	Arc,
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn context(id: Value, modern: bool) -> FrameContext {
	FrameContext {
		operation: "inspect_apk_signature",
		id: serde_json::from_value(id).unwrap(),
		modern,
		limit: rea_contract::RESPONSE_BYTES,
	}
}

fn runtime_metadata() -> MetaObject {
	MetaObject(
		serde_json::from_value(json!({
			"request_id":"owned-runtime-request", "ack":{"audit_durable":true,"retained":"complete"}
		}))
		.unwrap(),
	)
}

#[test]
fn sdk_response_and_error_serialization_counts_all_fields_and_newline() {
	for modern in [false, true] {
		let frame = context(json!("雪\n\"\\\u{2028}"), modern);
		let mut result = CallToolResult::structured(json!({"number":1.0,"text":"雪\n\""}));
		result.meta = Some(runtime_metadata());
		frame.normalize_replacement(&mut result);
		let result = ServerResult::CallToolResult(result);
		let encoded = serde_json::to_vec(&JsonRpcResponse {
			jsonrpc: JsonRpcVersion2_0,
			id: frame.id.clone(),
			result: &result,
		})
		.unwrap();
		assert_eq!(frame.count_result(&result), Ok(encoded.len() + 1));
		let error = ErrorData::invalid_params("雪\n\"\\", Some(json!({"detail":1.0})));
		let actual =
			serde_json::to_vec(&JsonRpcError::new(Some(frame.id.clone()), error.clone())).unwrap();
		let borrowed = serde_json::to_vec(&ErrorFrame {
			jsonrpc: JsonRpcVersion2_0,
			id: Some(&frame.id),
			error: &error,
		})
		.unwrap();
		assert_eq!(actual, borrowed);
		assert_eq!(frame.count_error(&error), Ok(actual.len() + 1));
	}
}

#[test]
fn serialization_failure_is_distinct_from_budget_overflow() {
	struct Invalid;
	impl Serialize for Invalid {
		fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
			Err(serde::ser::Error::custom("independent failing serializer"))
		}
	}
	let frame = context(json!(1), true);
	assert_eq!(frame.count(&Invalid), Err(CountFailure::Encoding));
	assert!(matches!(
		frame.count(&"x".repeat(frame.limit)),
		Err(CountFailure::Overflow(_))
	));
}

#[test]
fn structured_original_spelling_is_counted_before_final_frame_admission() {
	let mut frame = context(json!(1), true);
	let text = format!(
		r#"{{"operation":"inspect_analysis_view","value":0.0000001,"padding":"{}"}}"#,
		"x".repeat(4096)
	);
	let mut complete = CallToolResult::success(vec![rmcp::model::ContentBlock::text(text.clone())]);
	complete.structured_content = Some(serde_json::from_str(&text).unwrap());
	let result = ServerResult::CallToolResult(complete);
	let sdk = serde_json::to_vec(&JsonRpcResponse {
		jsonrpc: JsonRpcVersion2_0,
		id: frame.id.clone(),
		result: &result,
	})
	.unwrap();
	frame.limit = sdk.len() + 1;
	assert!(matches!(
		frame.count_result(&result),
		Err(CountFailure::Overflow(_))
	));
	let bounded = frame.finish(Ok(result)).unwrap();
	let ServerResult::CallToolResult(refusal) = &bounded else {
		panic!("bounded tool refusal required")
	};
	assert_eq!(refusal.is_error, Some(true));
	assert!(frame.count_result(&bounded).is_ok());
}

#[test]
fn same_id_minimal_protocol_error_is_smaller_than_valid_admitted_requests() {
	let names = [
		"rea_inspect_elf_notes",
		"rea_inspect_apk_signature_evidence",
		"rea_inspect_analysis_view",
		"rea_get_evidence_bundle",
		"rea_export_evidence_bundle",
	];
	// Include alternate valid input spellings which the SDK canonically encodes.
	let ids = [
		"0",
		"-9223372036854775808",
		"9223372036854775807",
		r#""""#,
		r#""\u0022\u005c\u0000\u000a\u0008\u0009\u000c\u000d""#,
		"\"雪😀\u{2028}\u{2029}/\"",
		r#""\ud83d\ude00\u96ea""#,
	];
	for name in names {
		for id_token in ids {
			let raw = format!(
				r#"{{"jsonrpc":"2.0","id":{id_token},"method":"tools/call","params":{{"name":"{name}"}}}}"#
			) + "\n";
			let request: rmcp::model::ClientJsonRpcMessage = serde_json::from_str(&raw).unwrap();
			let rmcp::model::JsonRpcMessage::Request(request) = request else {
				panic!("request expected")
			};
			let error = JsonRpcError::new(Some(request.id), ErrorData::internal_error("", None));
			let encoded = serde_json::to_vec(&error).unwrap();
			assert!(
				encoded.len() + 1 < raw.len(),
				"same-ID minimal envelope expanded"
			);
		}
	}
}

#[derive(Clone, Copy)]
enum Outcome {
	Small,
	Large,
	RpcError,
	RawProtocolError,
	Task,
}

#[derive(Clone)]
struct Handler {
	calls: Arc<AtomicUsize>,
	outcome: Outcome,
}

impl ServerHandler for Handler {
	async fn call_tool(
		&self,
		request: CallToolRequestParams,
		context: RequestContext<RoleServer>,
	) -> Result<CallToolResponse, ErrorData> {
		self.calls.fetch_add(1, Ordering::SeqCst);
		match self.outcome {
			Outcome::RawProtocolError => Err(context
				.extensions
				.get::<ReaRawArguments>()
				.and_then(ReaRawArguments::protocol_error)
				.expect("fixture requires a real raw argument protocol error")),
			Outcome::RpcError => Err(ErrorData::invalid_params(
				"independent protocol refusal ".repeat(32),
				Some(json!({"preserve":"only while bounded"})),
			)),
			Outcome::Task => Ok(CallToolResponse::Task(CreateTaskResult::new(Task::new(
				"unexpected-selected-tool-task",
				TaskStatus::Working,
				"2026-11-05T00:00:00Z",
				"2026-11-05T00:00:00Z",
			)))),
			Outcome::Small | Outcome::Large => {
				let bytes = if matches!(self.outcome, Outcome::Large) {
					2 * 1024 * 1024
				} else {
					13
				};
				let mut result = CallToolResult::structured(json!({
					"evidence_id":format!("ev_{}","a".repeat(64)),
					"payload":"x".repeat(bytes), "number":1.0, "text":"雪\n\"\\"
				}));
				if request.name.as_ref() != "rea_export_evidence_bundle" {
					result.meta = Some(runtime_metadata());
				}
				Ok(CallToolResponse::Complete(result))
			}
		}
	}

	fn get_info(&self) -> ServerConfig {
		ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
			.with_protocol_version(ProtocolVersion::V_2026_07_28)
	}
}

struct WireResult {
	raw_bytes: usize,
	value: Value,
	input_bytes: usize,
}

async fn exchange<S: Service<RoleServer>>(
	service: S,
	version: &str,
	request: Vec<u8>,
	raw_admission: bool,
) -> WireResult {
	let input_bytes = request.len();
	let (server, client) = tokio::io::duplex(64 * 1024);
	let (read, write) = tokio::io::split(server);
	let owner = tokio::spawn(async move {
		if raw_admission {
			let running = service
				.serve(ReaMcpTransport::new(read, write))
				.await
				.unwrap();
			running.waiting().await.unwrap();
		} else {
			let running = service.serve((read, write)).await.unwrap();
			running.waiting().await.unwrap();
		}
	});
	let (read, mut write) = tokio::io::split(client);
	let mut read = BufReader::new(read);
	let initialize = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
        "protocolVersion":version,"capabilities":{},"clientInfo":{"name":"frame-boundary-test","version":"1"}}});
	let mut initialize = serde_json::to_vec(&initialize).unwrap();
	initialize.push(b'\n');
	write.write_all(&initialize).await.unwrap();
	let mut reply = String::new();
	tokio::time::timeout(Duration::from_secs(15), read.read_line(&mut reply))
		.await
		.unwrap()
		.unwrap();
	let initialized: Value = serde_json::from_str(&reply).unwrap();
	// `initialize` is the legacy lifecycle even when a new version is offered.
	// Modern requests below explicitly select their version in complete _meta.
	let negotiated = if version == "2026-07-28" {
		"2025-11-25"
	} else {
		version
	};
	assert_eq!(initialized["result"]["protocolVersion"], negotiated);
	write
		.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
		.await
		.unwrap();
	tokio::time::timeout(Duration::from_secs(15), write.write_all(&request))
		.await
		.unwrap()
		.unwrap();
	reply.clear();
	tokio::time::timeout(Duration::from_secs(15), read.read_line(&mut reply))
		.await
		.unwrap()
		.unwrap();
	let raw_bytes = reply.len();
	let value: Value = serde_json::from_str(&reply).unwrap();
	let request_value: Value = serde_json::from_slice(&request).unwrap();
	assert!(
		value["id"] == request_value["id"],
		"response changed the request ID"
	);
	write.shutdown().await.unwrap();
	drop(write);
	drop(read);
	tokio::time::timeout(Duration::from_secs(15), owner)
		.await
		.unwrap()
		.unwrap();
	WireResult {
		raw_bytes,
		value,
		input_bytes,
	}
}

fn call(params: Value, id: Value) -> Vec<u8> {
	let mut bytes =
		serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}))
			.unwrap();
	bytes.push(b'\n');
	bytes
}

fn tool_params(name: &str, modern: bool) -> Value {
	let mut params = json!({"name":name});
	if modern {
		params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}});
	}
	params
}

fn maximal_call(params: Value) -> Vec<u8> {
	let base = call(params.clone(), json!(""));
	let bytes = call(
		params,
		json!("i".repeat(rea_contract::RESPONSE_BYTES - base.len())),
	);
	assert_eq!(bytes.len(), rea_contract::RESPONSE_BYTES);
	bytes
}

fn handler(outcome: Outcome) -> Handler {
	Handler {
		calls: Arc::new(AtomicUsize::new(0)),
		outcome,
	}
}

#[tokio::test]
async fn actual_sdk_legacy_and_modern_frames_match_counted_serialization() {
	for (version, modern) in [("2024-11-05", false), ("2026-07-28", true)] {
		let h = handler(Outcome::Small);
		let wire = exchange(
			ReaFramedService::new(h.clone()),
			version,
			call(
				tool_params("rea_inspect_elf_notes", modern),
				json!("雪\n\"\\"),
			),
			true,
		)
		.await;
		assert_eq!(h.calls.load(Ordering::SeqCst), 1);
		assert_eq!(wire.value["result"].get("resultType").is_some(), modern);
		assert_eq!(
			wire.value["result"]["_meta"]["request_id"],
			"owned-runtime-request"
		);
		let result: ServerResult = serde_json::from_value(wire.value["result"].clone()).unwrap();
		let frame = context(wire.value["id"].clone(), modern);
		assert_eq!(frame.count_result(&result), Ok(wire.raw_bytes));
	}
}

#[tokio::test]
async fn actual_sdk_large_complete_result_preserves_final_metadata_or_content_free_scope() {
	for name in ["rea_inspect_elf_notes", "rea_export_evidence_bundle"] {
		let h = handler(Outcome::Large);
		let wire = exchange(
			ReaFramedService::new(h.clone()),
			"2026-07-28",
			call(tool_params(name, true), json!("i".repeat(7 * 1024 * 1024))),
			true,
		)
		.await;
		assert_eq!(h.calls.load(Ordering::SeqCst), 1);
		assert!(wire.raw_bytes <= rea_contract::RESPONSE_BYTES);
		assert_eq!(wire.value["result"]["isError"], true);
		let body: Value =
			serde_json::from_str(wire.value["result"]["content"][0]["text"].as_str().unwrap())
				.unwrap();
		assert_eq!(
			body["error"]["details"]["reported_limits"]["boundary"],
			"native-mcp-frame"
		);
		assert_eq!(
			body["error"]["details"]["reported_limits"]["evidence_id"],
			format!("ev_{}", "a".repeat(64))
		);
		if name == "rea_export_evidence_bundle" {
			assert!(wire.value["result"].get("_meta").is_none());
		} else {
			assert_eq!(wire.value["result"]["_meta"]["ack"]["audit_durable"], true);
		}
	}
}

#[tokio::test]
async fn actual_sdk_rpc_error_and_unexpected_task_cannot_escape_frame_accounting() {
	for outcome in [Outcome::RpcError, Outcome::Task] {
		let h = handler(outcome);
		let wire = exchange(
			ReaFramedService::new(h.clone()),
			"2026-07-28",
			maximal_call(tool_params("rea_inspect_elf_notes", true)),
			true,
		)
		.await;
		assert_eq!(h.calls.load(Ordering::SeqCst), 1);
		assert!(wire.raw_bytes <= rea_contract::RESPONSE_BYTES);
		assert!(wire.value.get("error").is_some());
		assert!(wire.value.get("result").is_none());
	}
}

#[tokio::test]
async fn actual_sdk_pre_dispatch_protocol_error_requires_the_outer_service_boundary() {
	let raw = maximal_call(json!({"name":"rea_inspect_elf_notes","_meta":{
		"io.modelcontextprotocol/protocolVersion":"2999-01-01"
	}}));
	let baseline = handler(Outcome::Small);
	let old = exchange(baseline.clone(), "2026-07-28", raw.clone(), true).await;
	assert_eq!(
		baseline.calls.load(Ordering::SeqCst),
		0,
		"SDK rejection must precede call_tool"
	);
	assert!(old.value.get("error").is_some());
	assert!(
		old.raw_bytes > rea_contract::RESPONSE_BYTES,
		"baseline must demonstrate the actual unguarded overflow"
	);
	let guarded = handler(Outcome::Small);
	let new = exchange(
		ReaFramedService::new(guarded.clone()),
		"2026-07-28",
		raw,
		true,
	)
	.await;
	assert_eq!(guarded.calls.load(Ordering::SeqCst), 0);
	assert!(new.raw_bytes <= rea_contract::RESPONSE_BYTES);
	assert!(new.value.get("error").is_some());
	println!(
		"{}",
		json!({"case":"sdk-pre-dispatch-protocol-error", "input_bytes":old.input_bytes,
        "unguarded_response_bytes":old.raw_bytes,"guarded_response_bytes":new.raw_bytes,
        "handler_calls_before_and_after":0,"same_id_preserved":true})
	);
}

#[tokio::test]
async fn actual_sdk_minimal_fallback_fits_the_largest_admitted_id_for_both_protocols() {
	for version in ["2024-11-05", "2026-07-28"] {
		let h = handler(Outcome::Large);
		let wire = exchange(
			ReaFramedService::new(h),
			version,
			maximal_call(tool_params(
				"rea_inspect_elf_notes",
				version == "2026-07-28",
			)),
			true,
		)
		.await;
		assert_eq!(wire.input_bytes, rea_contract::RESPONSE_BYTES);
		assert!(wire.raw_bytes <= rea_contract::RESPONSE_BYTES);
		if version == "2024-11-05" {
			assert_eq!(wire.value["error"]["message"], "");
		}
		println!(
			"{}",
			json!({"case":"maximum-admitted-id", "protocol":version,
            "input_bytes":wire.input_bytes,"output_bytes":wire.raw_bytes,"same_id_preserved":true})
		);
	}
}

#[tokio::test]
async fn absent_private_admission_and_non_rea_tools_preserve_original_sdk_behavior() {
	for (raw_admission, name) in [(false, "rea_inspect_elf_notes"), (true, "ordinary_tool")] {
		let wire = exchange(
			ReaFramedService::new(handler(Outcome::RpcError)),
			"2026-07-28",
			maximal_call(tool_params(name, true)),
			raw_admission,
		)
		.await;
		assert!(wire.raw_bytes > rea_contract::RESPONSE_BYTES);
		assert!(wire.value["error"]["message"]
			.as_str()
			.unwrap()
			.starts_with("independent protocol refusal"));
	}
}

#[test]
fn wrapper_preserves_inner_advertised_configuration_and_protocol_versions() {
	let h = handler(Outcome::Small);
	let info = ServerHandler::get_info(&h);
	let versions = ServerHandler::supported_protocol_versions(&h).into_owned();
	let wrapped = ReaFramedService::new(h);
	assert_eq!(Service::get_info(&wrapped), info);
	assert_eq!(
		Service::supported_protocol_versions(&wrapped).as_ref(),
		versions.as_slice()
	);
}

/// Malformed arguments are still a bounded, privately captured raw frame.
/// The real handler rejects them before producing a business result, so that
/// refusal must pass the same final SDK frame guard as every other outcome.
#[tokio::test]
async fn actual_sdk_malformed_arguments_remain_under_final_frame_budget() {
	for modern in [false, true] {
		for arguments in [
			Value::Null,
			json!(true),
			json!(7),
			json!("value"),
			json!([]),
		] {
			let mut params = tool_params("rea_inspect_elf_notes", modern);
			params["arguments"] = arguments.clone();
			let raw = maximal_call(params);
			let version = if modern { "2026-07-28" } else { "2024-11-05" };
			let baseline = handler(Outcome::RawProtocolError);
			let old = exchange(baseline.clone(), version, raw.clone(), true).await;
			assert_eq!(baseline.calls.load(Ordering::SeqCst), 1);
			assert_eq!(old.value["error"]["code"], -32602);
			assert!(
				old.raw_bytes > rea_contract::RESPONSE_BYTES,
				"unguarded malformed-argument fixture must demonstrate a real overflow"
			);
			let guarded = handler(Outcome::RawProtocolError);
			let new = exchange(ReaFramedService::new(guarded.clone()), version, raw, true).await;
			assert_eq!(guarded.calls.load(Ordering::SeqCst), 1);
			println!(
				"{}",
				json!({
					"case":"raw-argument-protocol-error", "modern":modern, "arguments":arguments,
					"input_bytes":old.input_bytes, "unguarded_response_bytes":old.raw_bytes,
					"guarded_response_bytes":new.raw_bytes, "same_id_preserved":true
				})
			);
			assert!(
				new.raw_bytes <= rea_contract::RESPONSE_BYTES,
				"admitted malformed arguments escaped final frame accounting: {} bytes",
				new.raw_bytes
			);
			assert!(new.value.get("error").is_some());
			assert!(new.value.get("result").is_none());
		}
	}
}

#[tokio::test]
async fn actual_sdk_small_raw_argument_protocol_errors_preserve_diagnostics() {
	for arguments in [
		Value::Null,
		json!(false),
		json!(1),
		json!("value"),
		json!([]),
	] {
		let mut params = tool_params("rea_inspect_elf_notes", true);
		params["arguments"] = arguments;
		let raw = call(params, json!("raw-shape-error"));
		let old = exchange(
			handler(Outcome::RawProtocolError),
			"2026-07-28",
			raw.clone(),
			true,
		)
		.await;
		let new = exchange(
			ReaFramedService::new(handler(Outcome::RawProtocolError)),
			"2026-07-28",
			raw,
			true,
		)
		.await;
		assert_eq!(new.value, old.value);
		assert_eq!(new.value["error"]["code"], -32602);
	}
}
