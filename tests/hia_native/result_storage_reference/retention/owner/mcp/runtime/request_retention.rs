// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification projection of the original retained-result owner.
use super::config::runtime_config;
use anyhow::Result;
use rmcp::model::CallToolResult;
use serde_json::Value;
pub const ID_META: &str = "io.hepta.runtime/request-v8";
fn valid_id(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn keys(value: &Value, expected: &[&str]) -> bool {
	value.as_object().is_some_and(|m| {
		m.len() == expected.len() && expected.iter().all(|key| m.contains_key(*key))
	})
}
fn safe_dto(tool: &str, result: &CallToolResult) -> Result<bool> {
	let wire = serde_json::to_value(result)?;
	if result.is_error == Some(true)
		|| result.structured_content.is_some()
		|| result.content.len() != 1
	{
		return Ok(false);
	}
	if !wire["_meta"]
		.as_object()
		.is_some_and(|m| m.len() == 1 && m.contains_key(ID_META))
	{
		return Ok(false);
	}
	let marker = &wire["_meta"][ID_META];
	if !keys(
		marker,
		&["request_id", "automatic_retry", "delivery_proven"],
	) || marker["request_id"].as_str().is_none_or(|id| !valid_id(id))
		|| marker["automatic_retry"] != false
		|| marker["delivery_proven"] != false
	{
		return Ok(false);
	}
	let content = &wire["content"][0];
	if !keys(content, &["type", "text"]) || content["type"] != "text" {
		return Ok(false);
	}
	let Some(text) = content["text"].as_str() else {
		return Ok(false);
	};
	let parsed: Value = serde_json::from_str(text)?;
	match tool {
		"host_list" => {
			let expected: Value = serde_json::from_str(&super::inspect::host_list()?)?;
			Ok(parsed == expected
				&& keys(&parsed, &["hosts"])
				&& parsed["hosts"].as_array().is_some_and(|hosts| {
					hosts.len() <= 256
						&& hosts.iter().all(|h| {
							keys(
								h,
								&[
									"name",
									"platform",
									"execution_mode",
									"operator_tools",
									"allow_execute",
									"allow_pty",
									"allow_write",
									"privileged_actions",
								],
							)
						})
				}))
		}
		"effective_config" => {
			let expected: Value = serde_json::from_str(
				&super::effective_config::effective_config(Default::default())?,
			)?;
			Ok(parsed == expected
				&& keys(
					&parsed,
					&[
						"schema",
						"scope",
						"semantics",
						"redaction",
						"policy_mutation_supported",
						"target_probe_performed",
						"controller",
						"hosts",
						"limits",
					],
				) && keys(
				&parsed["controller"],
				&["workspace_root_count", "file_workspace_roots_configured"],
			) && keys(
				&parsed["limits"],
				&[
					"concurrent_execution",
					"maximum_summary_host_entries",
					"maximum_summary_response_bytes",
				],
			) && parsed["hosts"].as_array().is_some_and(|hosts| {
				hosts.len() <= 256
					&& hosts.iter().all(|h| {
						keys(
							h,
							&[
								"alias",
								"platform",
								"execution_mode",
								"permissions",
								"file_api",
								"named_privileged_action_count",
								"checkpoint_pin_configured",
							],
						) && keys(
							&h["permissions"],
							&[
								"allow_execute",
								"allow_pty",
								"allow_write",
								"allow_job_network",
								"allow_detached_fallback",
							],
						) && keys(
							&h["file_api"],
							&[
								"read_root_count",
								"write_root_count",
								"read_paths_configured",
								"write_paths_authorized_and_configured",
							],
						)
					})
			}))
		}
		"host_health" => {
			let Some(alias) = parsed["host"].as_str() else {
				return Ok(false);
			};
			let Ok(host) = runtime_config()?.host(alias) else {
				return Ok(false);
			};
			let healthy = parsed["status"] == "healthy";
			Ok(keys(
				&parsed,
				&[
					"schema",
					"host",
					"platform",
					"transport",
					"status",
					"reachable",
					"authenticated",
					"ssh_roundtrip_ms",
					"timeout_ms",
					"measurement",
					"diagnostics_redacted",
				],
			) && parsed["schema"] == "hepta-host-health-v1"
				&& parsed["transport"] == "ssh"
				&& parsed["platform"] == serde_json::to_value(host.platform)?
				&& [
					"healthy",
					"ssh_failed",
					"invalid_response",
					"transport_error",
					"timeout",
				]
				.iter()
				.any(|v| parsed["status"] == *v)
				&& parsed["reachable"] == healthy
				&& parsed["authenticated"] == healthy
				&& parsed["diagnostics_redacted"] == true
				&& parsed["timeout_ms"] == 10000
				&& parsed["ssh_roundtrip_ms"]
					.as_f64()
					.is_some_and(|v| v.is_finite() && (0.0..=60000.0).contains(&v))
				&& parsed["measurement"]
					== "SSH invocation roundtrip including connection setup or reuse, authentication, remote shell startup and fixed response; not ICMP RTT.")
		}
		_ => Ok(false),
	}
}
pub fn observe(tool: &str, result: &CallToolResult) -> bool {
	safe_dto(tool, result).unwrap_or(false)
}

use crate::utils::json_size::serialized_json_size;
use rmcp::model::{CallToolResponse, ErrorData, MetaObject};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
const MAX_RESULT_BYTES: usize = 64 * 1024;
pub const ACK_META: &str = "io.hepta.runtime/retention-v8";
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResultState {
	Unknown,
	Stored,
	Overflow,
	RefusedDto,
	NotCompleted,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
	request_id: String,
	owner: String,
	tool_name: String,
	accepted_unix_ms: u128,
	policy_binding: String,
	state: ResultState,
	payload_base64: Option<String>,
	payload_bytes: Option<usize>,
	payload_sha256: Option<String>,
}
fn digest(data: &[u8]) -> String {
	Sha256::digest(data)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}
fn base64(data: &[u8]) -> String {
	const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
	for row in data.chunks(3) {
		let n = ((row[0] as u32) << 16)
			| ((row.get(1).copied().unwrap_or(0) as u32) << 8)
			| row.get(2).copied().unwrap_or(0) as u32;
		out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
		out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
		out.push(if row.len() > 1 {
			ALPHABET[((n >> 6) & 63) as usize] as char
		} else {
			'='
		});
		out.push(if row.len() > 2 {
			ALPHABET[(n & 63) as usize] as char
		} else {
			'='
		});
	}
	out
}
pub fn attach_ack(
	result: &mut Result<CallToolResponse, ErrorData>,
	state: &str,
	audit_durable: bool,
) {
	let ack = json!({"result_state":state,"audit_completion_durable":audit_durable,
		"semantics":"native_generated_result_before_retention_ack_and_transport_normalization; delivery unproven","automatic_retry":false});
	match result {
		Ok(CallToolResponse::Complete(value)) => {
			let meta = value.meta.get_or_insert_with(MetaObject::new);
			let mut ack = ack;
			if let Some(original) = meta.remove(ACK_META) {
				ack["original_metadata"] = original;
			}
			meta.insert(ACK_META.into(), ack);
		}
		Err(error) => {
			let mut ack = ack;
			let mut data = match error.data.take() {
				Some(Value::Object(mut value)) => {
					if let Some(original) = value.remove(ACK_META) {
						ack["original_metadata"] = original;
					}
					Value::Object(value)
				}
				Some(value) => json!({"original_error_data":value}),
				None => json!({}),
			};
			data[ACK_META] = ack;
			error.data = Some(data);
		}
		_ => {}
	}
}

struct ProjectionIdentity {
	request_id: String,
	owner: String,
	tool_name: String,
	accepted_unix_ms: u128,
}
struct ProjectionIntent {
	record: Record,
}

// Only the original pure transition follows. No descriptor or durability work is substituted.
pub fn project(input: &Value, result: Option<CallToolResult>) -> Result<(String, String)> {
	let identity = ProjectionIdentity {
		request_id: input["request_id"].as_str().unwrap().to_owned(),
		owner: input["owner"].as_str().unwrap().to_owned(),
		tool_name: input["tool"].as_str().unwrap().to_owned(),
		accepted_unix_ms: input["accepted"].as_str().unwrap().parse()?,
	};
	let binding = input["policy_binding"].as_str().unwrap().to_owned();
	let record = Record {
		request_id: identity.request_id,
		owner: identity.owner,
		tool_name: identity.tool_name,
		accepted_unix_ms: identity.accepted_unix_ms,
		policy_binding: binding,
		state: ResultState::Unknown,
		payload_base64: None,
		payload_bytes: None,
		payload_sha256: None,
	};
	if input["operation"] == 1 {
		return Ok(("unknown".into(), serde_json::to_string(&record)?));
	}
	let mut intent = ProjectionIntent { record };
	let state = if let Some(result) = result {
		let bytes = serde_json::to_vec(&result)?;
		let mut final_preview = Ok(result.clone().into());
		attach_ack(&mut final_preview, "stored", false);
		let final_bytes = match final_preview {
			Ok(CallToolResponse::Complete(value)) => serialized_json_size(&value)?,
			_ => MAX_RESULT_BYTES + 1,
		};
		if bytes.len() > MAX_RESULT_BYTES || final_bytes > MAX_RESULT_BYTES {
			intent.record.state = ResultState::Overflow;
			"overflow"
		} else if result
			.meta
			.as_ref()
			.and_then(|m| m.get(ID_META))
			.and_then(|v| v.get("request_id"))
			.and_then(Value::as_str)
			!= Some(intent.record.request_id.as_str())
			|| !safe_dto(&intent.record.tool_name, &result).unwrap_or(false)
		{
			intent.record.state = ResultState::RefusedDto;
			"not_retained_dto"
		} else {
			intent.record.payload_bytes = Some(bytes.len());
			intent.record.payload_sha256 = Some(digest(&bytes));
			intent.record.payload_base64 = Some(base64(&bytes));
			intent.record.state = ResultState::Stored;
			"stored"
		}
	} else {
		intent.record.state = ResultState::NotCompleted;
		"not_completed"
	};
	Ok((state.to_owned(), serde_json::to_string(&intent.record)?))
}

pub fn sizes(result: &Option<CallToolResult>) -> (usize, usize) {
	let Some(value) = result else { return (0, 0) };
	let raw = serde_json::to_vec(value).unwrap().len();
	let mut preview = Ok(value.clone().into());
	attach_ack(&mut preview, "stored", false);
	let Ok(CallToolResponse::Complete(value)) = preview else {
		unreachable!()
	};
	(raw, serialized_json_size(&value).unwrap())
}
