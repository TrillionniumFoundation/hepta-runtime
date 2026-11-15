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
