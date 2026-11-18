// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Test-only fixed three-route projection. The outer audit/result lifecycle
// is intentionally not replaced by this reference or counted as closed.
pub mod mcp;
pub mod utils;
use mcp::runtime;
use rmcp::{
	handler::server::{
		tool::{ToolCallContext, ToolRoute, ToolRouter},
		wrapper::Parameters,
		ServerHandler,
	},
	model::{
		CacheScope, CallToolRequestParams, CallToolResponse, ExperimentalCapabilities,
		Implementation, JsonObject, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
		ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
	},
	service::RequestContext,
	ErrorData, RoleServer, ServiceExt,
};
use std::{path::PathBuf, sync::Arc};
const CLAUDE_CHANNEL_CAPABILITY: &str = "claude/channel";
#[derive(Clone)]
struct Reference;

const RUNTIME_TOOL_NAMES: &[&str] = &[
	"hia_describe",
	"hia_artifact",
	"hia_read",
	"hia_context",
	"hia_inspect",
	"hia_candidate",
	"hia_verify",
	"hia_emit",
	"hia_evaluate",
	"hia_adopt",
	"hia_rollback",
	"execution_shadow_admit",
	"effective_config",
	"usage_stats",
	"request_archive",
	"request_history",
	"request_status",
	"request_result",
	"request_start",
	"request_cancel",
	"operation_start",
	"operation_status",
	"operation_result",
	"operation_cancel",
	"host_health",
	"read_multiple_files",
	"search_start",
	"search_results",
	"search_list",
	"search_stop",
	"stream_handoff_prepare",
	"stream_handoff_status",
	"stream_handoff_read",
	"stream_handoff_write",
	"stream_handoff_close",
	"stream_handoff_list",
	"process_checkpoint",
	"pdf_security",
	"binary_patch_inode",
	"document_render",
	"worksheet_recalculate",
	"worksheet_edit",
	"pdf_edit",
	"file_info",
	"binary_read",
	"binary_write",
	"binary_upload",
	"document_read",
	"image_read",
	"document_write",
	"document_edit",
	"shell_start",
	"host_processes",
	"host_signal",
	"sudo_start",
	"host_list",
	"process_start",
	"process_status",
	"process_read",
	"process_wait",
	"process_cancel",
	"process_list",
	"process_list_page",
	"pty_start",
	"pty_read",
	"pty_write",
	"pty_close",
	"pty_list",
	"hardware_snapshot",
	"service_status",
	"network_inspect",
	"privileged_action",
	"rea_inspect_artifact",
	"rea_inspect_model",
	"rea_read_model",
	"rea_inspect_web_capture",
	"rea_compare_web_captures",
	"rea_replay_web_entry",
	"rea_inspect_javascript_package",
	"rea_inspect_javascript_graph",
	"rea_inspect_source_map",
	"rea_inspect_elf_notes",
	"rea_get_evidence_bundle",
	"rea_read_evidence_bundle",
	"rea_close_evidence_snapshot",
	"rea_inspect_apk_signature_evidence",
	"rea_inspect_analysis_view",
	"rea_export_evidence_bundle",
	"rea_import_evidence_bundle",
	"rea_model_session_open",
	"rea_model_session_query",
	"rea_model_session_read",
	"rea_model_session_list",
	"rea_inspect_application",
	"rea_inspect_apk_signature",
	"rea_inspect_archive",
	"rea_inspect_asar",
	"rea_read_asar_member",
	"rea_static_profiles",
	"rea_static_start",
	"rea_static_status",
	"rea_static_read",
	"rea_static_cancel",
	"rea_verify_evidence",
	"rea_retain_preview",
	"rea_read_preview",
	"weight_profiles",
	"weight_artifact_patch",
	"weight_artifact_restore",
	"weight_linear_forward",
	"weight_open",
	"weight_call",
	"weight_status",
	"weight_read",
	"weight_close",
];

const WEIGHT_WORKER_TOOL_NAMES: &[&str] = &[
	"weight_profiles",
	"weight_open",
	"weight_call",
	"weight_status",
	"weight_read",
	"weight_close",
];
#[rustfmt::skip]
mod hia_contract {
pub(super) const TOOLS: &[&str] = &[
	"hia_describe",
	"hia_artifact",
	"hia_read",
	"hia_context",
	"hia_inspect",
	"hia_candidate",
	"hia_verify",
	"hia_emit",
	"hia_evaluate",
	"hia_adopt",
	"hia_rollback",
];
}
fn route_host_list(
	service: &Reference,
	params: Parameters<runtime::inspect::HostListParams>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
	Box::pin(service.host_list(params))
}
fn route_effective_config(
	service: &Reference,
	params: Parameters<runtime::effective_config::EffectiveConfigParams>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
	Box::pin(service.effective_config(params))
}
fn route_execution_shadow_admit(
	service: &Reference,
	params: Parameters<runtime::execution::ShadowExecutionIntentParams>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
	Box::pin(service.execution_shadow_admit(params))
}
fn strip_null_variants(value: &mut serde_json::Value) {
	match value {
		serde_json::Value::Object(obj) => {
			for nested in obj.values_mut() {
				strip_null_variants(nested);
			}

			let collapsed_type =
				obj.get_mut("type")
					.and_then(|t| t.as_array_mut())
					.and_then(|types| {
						types.retain(|t| t.as_str() != Some("null"));
						(types.len() == 1).then(|| types[0].clone())
					});
			if let Some(single) = collapsed_type {
				obj.insert("type".to_string(), single);
			}

			for key in ["anyOf", "oneOf"] {
				let only = obj
					.get_mut(key)
					.and_then(|v| v.as_array_mut())
					.and_then(|variants| {
						variants.retain(|v| v.get("type").and_then(|t| t.as_str()) != Some("null"));
						(variants.len() == 1).then(|| variants[0].clone())
					});
				if let Some(serde_json::Value::Object(only)) = only {
					obj.remove(key);
					for (k, v) in only {
						obj.entry(k).or_insert(v);
					}
				}
			}
		}
		serde_json::Value::Array(items) => {
			for item in items.iter_mut() {
				strip_null_variants(item);
			}
		}
		_ => {}
	}
}

fn strip_generator_noise(schema: &mut serde_json::Map<String, serde_json::Value>) {
	schema.remove("$schema");
	schema.remove("format");
	if schema
		.get("default")
		.is_some_and(serde_json::Value::is_null)
	{
		schema.remove("default");
	}
	for (key, value) in schema.iter_mut() {
		match (key.as_str(), value) {
			("properties" | "$defs", serde_json::Value::Object(named)) => {
				for sub in named.values_mut() {
					if let serde_json::Value::Object(sub) = sub {
						strip_generator_noise(sub);
					}
				}
			}
			(_, serde_json::Value::Object(sub)) => strip_generator_noise(sub),
			(_, serde_json::Value::Array(items)) => {
				for item in items {
					if let serde_json::Value::Object(sub) = item {
						strip_generator_noise(sub);
					}
				}
			}
			_ => {}
		}
	}
}

fn supports_cache_hints(context: &RequestContext<RoleServer>) -> bool {
	context
		.protocol_version()
		.is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}
impl Reference {
	async fn host_list(
		&self,
		Parameters(_params): Parameters<runtime::inspect::HostListParams>,
	) -> Result<String, String> {
		runtime::inspect::host_list().map_err(|error| error.to_string())
	}

	async fn effective_config(
		&self,
		Parameters(params): Parameters<runtime::effective_config::EffectiveConfigParams>,
	) -> Result<String, String> {
		runtime::effective_config::effective_config(params).map_err(|error| error.to_string())
	}

	async fn execution_shadow_admit(
		&self,
		Parameters(params): Parameters<runtime::execution::ShadowExecutionIntentParams>,
	) -> Result<String, String> {
		runtime::execution::admit_shadow_intent(params).map_err(|error| error.to_string())
	}
	fn tool_router() -> ToolRouter<Self> {
		ToolRouter::new()
.with_route(ToolRoute::new(Tool::new("host_list","List configured runtime host names and their capability flags. SSH destinations and credentials are never accepted from tool input.",Arc::new(Default::default()))
.with_title("Host List")
.with_input_schema::<runtime::inspect::HostListParams>()
.with_annotations(ToolAnnotations::from_raw(None,Some(true),Some(false),Some(true),Some(false))),route_host_list))
.with_route(ToolRoute::new(Tool::new("effective_config","Read bounded effective Hepta capabilities and configured host aliases from a strict allowlist projection. Returns authorization switches and counts, never SSH destinations, private paths, credentials, environment values, privileged commands or raw policy. Does not modify configuration; administrator changes require reviewed version-controlled configuration and rollback.",Arc::new(Default::default()))
.with_title("Read Redacted Effective Configuration")
.with_input_schema::<runtime::effective_config::EffectiveConfigParams>()
.with_annotations(ToolAnnotations::from_raw(None,Some(true),Some(false),Some(true),Some(false))),route_effective_config))
.with_route(ToolRoute::new(Tool::new("execution_shadow_admit","Validate and hash a canonical execution_intent v1 against an allowlisted host. Shadow only: never starts a process, grants FinalUse or acknowledges an effect.",Arc::new(Default::default()))
.with_title("Execution Shadow Admission")
.with_input_schema::<runtime::execution::ShadowExecutionIntentParams>()
.with_annotations(ToolAnnotations::from_raw(None,Some(true),Some(false),Some(true),Some(false))),route_execution_shadow_admit))
	}
}
impl ServerHandler for Reference {
	fn get_info(&self) -> ServerConfig {
		ServerConfig::new(
			// Resources (read/list) advertise automatically promoted shell jobs
			// as handles. `subscribe` is advertised because resource updates are
			// deliverable both ways: on a `subscriptions/listen` stream (the
			// 2026-07-28 contract path, see `listen` below) and as the
			// unsolicited push legacy clients expect (the `shell` notifier's
			// fallback path). `claude/channel` lets Claude Code sessions that
			// enabled octofs as a channel receive job exits (see
			// `notify_claude_channel`).
			ServerCapabilities::builder()
				.enable_experimental_with(ExperimentalCapabilities::from([(
					CLAUDE_CHANNEL_CAPABILITY.to_string(),
					JsonObject::new(),
				)]))
				.enable_tools()
				.enable_resources()
				.enable_resources_subscribe()
				.build(),
		)
		.with_server_info(Implementation::from_build_env())
		.with_protocol_version(ProtocolVersion::V_2026_07_28)
		.with_instructions(
			"Filesystem tools. File lines render as `N:hh|content`; `N:hh` is the line id edit \
				 tools target, and edit results are diffs with fresh ids, so edits chain without \
				 re-viewing files. Reuse returned content and ids; read complete relevant blocks, \
				 then act on them. Each response costs a round trip: first decide what you need \
				 next, then request every call that doesn't depend on another's result in that one \
				 response."
				.to_string(),
		)
	}
	async fn list_tools(
		&self,
		_request: Option<PaginatedRequestParams>,
		context: RequestContext<RoleServer>,
	) -> Result<ListToolsResult, ErrorData> {
		let runtime_enabled = runtime::config::maybe_runtime_config().is_some();
		let tools = Self::tool_router()
			.list_all()
			.into_iter()
			.filter(|tool| {
				if hia_contract::TOOLS.contains(&tool.name.as_ref())
					&& runtime::config::maybe_runtime_config()
						.is_none_or(|config| config.hia_worker.is_none())
				{
					return false;
				}
				if tool.name.starts_with("rea_static_")
					&& runtime::config::maybe_runtime_config()
						.is_none_or(|c| c.rea_static_profiles.is_empty())
				{
					return false;
				}
				if WEIGHT_WORKER_TOOL_NAMES.contains(&tool.name.as_ref())
					&& runtime::config::maybe_runtime_config()
						.is_none_or(|c| c.weight_workers.is_empty())
				{
					return false;
				}
				if runtime_enabled {
					tool.name.as_ref() != "shell"
				} else {
					!RUNTIME_TOOL_NAMES.contains(&tool.name.as_ref())
				}
			})
			.map(|mut tool| {
				if hia_contract::TOOLS.contains(&tool.name.as_ref()) {
					return tool;
				}
				// Frozen producer schemas are contracts, including nullable variants
				// and schema-version metadata; they are not schemars generator noise.
				if matches!(
					tool.name.as_ref(),
					"rea_inspect_elf_notes"
						| "rea_get_evidence_bundle"
						| "rea_inspect_apk_signature_evidence"
						| "rea_inspect_analysis_view"
						| "rea_export_evidence_bundle"
						| "rea_import_evidence_bundle"
				) {
					return tool;
				}
				let mut schema = tool.input_schema.as_ref().clone();
				for value in schema.values_mut() {
					strip_null_variants(value);
				}
				strip_generator_noise(&mut schema);
				tool.input_schema = Arc::new(schema);
				tool
			})
			.collect();
		let result = ListToolsResult::with_all_items(tools);
		if !supports_cache_hints(&context) {
			return Ok(result);
		}
		// ttl 0 matches rmcp's generated handler; the list is identical for every caller.
		Ok(result.with_ttl_ms(0).with_cache_scope(CacheScope::Public))
	}
	async fn call_tool(
		&self,
		request: CallToolRequestParams,
		context: RequestContext<RoleServer>,
	) -> Result<CallToolResponse, ErrorData> {
		let router = Self::tool_router();
		if router.get(request.name.as_ref()).is_none() {
			return Err(ErrorData::invalid_params(
				"tool not found in this runtime mode",
				None,
			));
		}
		router
			.call(ToolCallContext::new(self, request, context))
			.await
	}
}
fn main() {
	let args: Vec<_> = std::env::args_os().collect();
	if args.len() == 2 && args[1] == "--catalog" {
		let tools = Reference::tool_router()
			.list_all()
			.into_iter()
			.map(|mut tool| {
				let mut schema = tool.input_schema.as_ref().clone();
				for value in schema.values_mut() {
					strip_null_variants(value);
				}
				strip_generator_noise(&mut schema);
				tool.input_schema = Arc::new(schema);
				tool
			})
			.collect();
		let mut result = ListToolsResult::with_all_items(tools);
		result.result_type = None;
		println!("{}", serde_json::to_string(&result).unwrap());
		result.result_type = Some(rmcp::model::ResultType::COMPLETE);
		println!(
			"{}",
			serde_json::to_string(&result.with_ttl_ms(0).with_cache_scope(CacheScope::Public))
				.unwrap()
		);
		return;
	}
	assert_eq!(args.len(), 3);
	assert_eq!(args[1], "--runtime-config");
	let installed = runtime::config::RuntimeConfig::load(&PathBuf::from(&args[2]))
		.and_then(runtime::config::init_runtime);
	if let Err(error) = installed {
		eprintln!("{error}");
		std::process::exit(78);
	}
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap()
		.block_on(async {
			if let Ok(service) = Reference
				.serve((tokio::io::stdin(), tokio::io::stdout()))
				.await
			{
				let _ = service.waiting().await;
			}
		});
}
