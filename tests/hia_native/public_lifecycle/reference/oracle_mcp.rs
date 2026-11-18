// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Actual public Read routes, outer call_tool and shared audit/result/Async owners.
//! Index activation, group commit and Async producers are outside this reference.
pub mod mcp;
pub mod utils;
use mcp::runtime;
use tracing::warn;
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
struct Reference {
	search_owner: Arc<Option<String>>,
	/// Trusted metadata authority, fixed for each native session.
	owner_binding: Arc<runtime::caller_scope::SessionOwnerBinding>,
	operation_crypto: Option<Arc<runtime::operation_crypto::ResultCryptoScope>>,
}


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
fn route_request_status(service: &Reference,
    params: Parameters<runtime::request_results::RequestStatusParams>,
    context: RequestContext<RoleServer>)
    -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
    Box::pin(service.request_status(params, context))
}
fn route_request_result(service: &Reference,
    params: Parameters<runtime::request_results::RequestResultParams>,
    context: RequestContext<RoleServer>)
    -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
    Box::pin(service.request_result(params, context))
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
	async fn request_status(
		&self,
		Parameters(params): Parameters<runtime::request_results::RequestStatusParams>,
		context: RequestContext<RoleServer>,
	) -> Result<String, String> {
		let scope = self
			.owner_binding
			.resolve(&context, self.search_owner.as_ref().as_deref())
			.map_err(|e| e.to_string())?;
		let async_observation =
			runtime::request_async::observation(scope.owner(), &params.request_id)
				.await
				.map_err(|error| error.to_string())?;
		let request_id = params.request_id.clone();
		let text = match runtime::request_results::request_status(scope.owner(), params).await {
			Ok(text) => text,
			Err(error) => {
				let absent_at_first_observation = async_observation
					.as_ref()
					.and_then(|observation| observation.get("audit_metadata_available"))
					== Some(&serde_json::Value::Bool(false));
				if !absent_at_first_observation
					|| runtime::request_audit::optional_observation(scope.owner(), &request_id)
						.await
						.map_err(|error| error.to_string())?
						.is_some()
				{
					return Err(error.to_string());
				}
				serde_json::json!({
					"request_id": request_id, "dispatch_state": "unknown", "result_state": "unavailable",
					"inner_receipt_available": false, "automatic_retry": false,
					"metadata_lookup_does_not_prove_delivery_or_business_success": true
				})
				.to_string()
			}
		};
		let mut value: serde_json::Value =
			serde_json::from_str(&text).map_err(|_| "request status unavailable".to_string())?;
		if let Some(observation) = async_observation {
			if let (Some(object), Some(extra)) = (value.as_object_mut(), observation.as_object()) {
				object.extend(extra.clone());
			}
		}
		scope
			.annotate(value.to_string(), false)
			.map_err(|error| error.to_string())
	}
	async fn request_result(
		&self,
		Parameters(params): Parameters<runtime::request_results::RequestResultParams>,
		context: RequestContext<RoleServer>,
	) -> Result<String, String> {
		let scope = self
			.owner_binding
			.resolve(&context, self.search_owner.as_ref().as_deref())
			.map_err(|e| e.to_string())?;
		runtime::request_async::observation(scope.owner(), &params.request_id)
			.await
			.map_err(|error| error.to_string())?;
		runtime::request_results::request_result(scope.owner(), params)
			.await
			.and_then(|text| scope.annotate(text, false))
			.map_err(|e| e.to_string())
	}

	async fn host_health(
		&self,
		Parameters(params): Parameters<runtime::health::HostHealthParams>,
	) -> Result<String, String> {
		runtime::health::host_health(params)
			.await
			.map_err(|error| error.to_string())
	}
	fn tool_router() -> ToolRouter<Self> {
		ToolRouter::new()
.with_route(ToolRoute::new(Tool::new("request_start","Admit one background request from the explicit host_list, host_health or effective_config typed whitelist. Requires a private idempotency key: identical retries under the same verified HTTP credential or native stdio session return the original server-generated inner request_id without redispatch; changed arguments or policy refuse reuse. Durable private key hashes precede admission and effects. Independent requests have no runtime active-count ceiling; durable key history is never silently evicted or rebound. Response acknowledges admission, not dispatch completion or transport delivery. Use request_status/request_result for the inner id. A controller restart makes unfinished work unknown; no request is automatically replayed or resumed. Users sharing a private credential share this scope; no authenticated ChatGPT caller isolation. No arbitrary tools, commands, addresses or process ids.",Arc::new(Default::default()))
.with_title("Start Idempotent Owned Read Request")
.with_input_schema::<runtime::request_async::RequestStartParams>()
.with_annotations(ToolAnnotations::from_raw(None,Some(false),Some(false),Some(false),Some(false))),route_request_start))
.with_route(ToolRoute::new(Tool::new("request_cancel","Request cancellation of this controller's own background Rust future using the exact request_start inner request_id and the same verified private credential or native stdio session. Current policy must still authorize the immutable key binding. Never accepts an OS pid, command or arbitrary tool. Cancellation does not kill arbitrary processes or prove remote work stopped; effects started before cancellation may continue. Result settlement cannot be cancelled and late cancellation never discards a retained original result. Missing futures after controller restart remain unknown and are never recreated or replayed.",Arc::new(Default::default()))
.with_title("Cancel Owned Read Request Future")
.with_input_schema::<runtime::request_async::RequestCancelParams>()
.with_annotations(ToolAnnotations::from_raw(None,Some(false),Some(false),Some(true),Some(false))),route_request_cancel))
.with_route(ToolRoute::new(Tool::new("request_history","Read bounded redacted dispatch metadata owned by the verified private HTTP operator credential; the same credential resumes its retained metadata after reconnect or controller restart. All users sharing that credential share this scope; this is not authenticated ChatGPT caller isolation. Stdio remains native-session-only. Independent retained-record cursors; server request identity, canonical tool name, timing and observed status only. Unknown effects must never be replayed automatically. Records prove neither delivery nor business success. Transport-invalid requests and facade-local refusals are outside native dispatch history.",Arc::new(Default::default()))
.with_title("Read Credential or Native Session Request History")
.with_input_schema::<runtime::request_audit::RequestHistoryParams>()
.with_annotations(ToolAnnotations::from_raw(None,Some(true),Some(false),Some(true),Some(false))),route_request_history))
.with_route(ToolRoute::new(Tool::new("request_status","Read dispatch and bounded original-result retention state by an exact server-generated request id owned by the verified private HTTP credential or this stdio native session. Never accepts caller-selected owner. Retention currently supports only host_list, host_health and effective_config validated DTO results; other tools, history and result lookup are metadata-only. Configuration changes revoke retained-result access. Unknown, unavailable or overflow does not prove an effect failed; never replay automatically. Does not prove delivery, business completion, ChatGPT caller isolation or early-return asynchronous execution.",Arc::new(Default::default()))
.with_title("Read Owned Request Status")
.with_input_schema::<runtime::request_results::RequestStatusParams>()
.with_annotations(ToolAnnotations::from_raw(None,Some(true),Some(false),Some(true),Some(false))),route_request_status))
.with_route(ToolRoute::new(Tool::new("request_result","Page immutable serialized original native CallToolResult bytes using an exact server-generated owned request id and independent byte offset. At most 16384 bytes per page, base64 plus full SHA256; at most 64 KiB retained per result. Only validated host_list, host_health and effective_config DTO successes are retained; arbitrary output, errors, request parameters and credentials are not stored. Original boundary includes the server request identity before retention acknowledgement and transport-version normalization. The same verified private HTTP credential may resume after restart only while the complete current policy binding is unchanged; stdio remains native-session-only. Unknown, overflow, expired or unretained results are refused without replay. Not universal DC get_tool_result equivalence, early-return async start, business completion or authenticated ChatGPT caller isolation.",Arc::new(Default::default()))
.with_title("Read Bounded Original Request Result")
.with_input_schema::<runtime::request_results::RequestResultParams>()
.with_annotations(ToolAnnotations::from_raw(None,Some(true),Some(false),Some(true),Some(false))),route_request_result))
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
.with_route(ToolRoute::new(Tool::new("host_health","Measure authenticated SSH reachability and command roundtrip latency for one configured host alias, including authentication and remote startup. Uses a fixed bounded read-only challenge and a 10-second deadline. No caller-supplied network destinations or commands; failures are redacted. This is not ICMP ping or pure network RTT.",Arc::new(Default::default()))
.with_title("Configured Host Health").with_input_schema::<runtime::health::HostHealthParams>()
.with_annotations(ToolAnnotations::from_raw(None,Some(true),Some(false),Some(true),Some(false))),route_host_health))
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
		use runtime::request_audit::AuditCompletion;
		let cancelled = context.ct.clone();
		let router = Self::tool_router();
		let enabled = runtime::config::maybe_runtime_config().is_some();
		let known = router.get(request.name.as_ref());
		let visible = known.is_some()
			&& (!hia_contract::TOOLS.contains(&request.name.as_ref())
				|| runtime::config::maybe_runtime_config()
					.is_some_and(|config| config.hia_worker.is_some()))
			&& if enabled {
				request.name.as_ref() != "shell"
			} else {
				!RUNTIME_TOOL_NAMES.contains(&request.name.as_ref())
			};
		let readonly = known
			.and_then(|tool| tool.annotations.as_ref())
			.and_then(|hints| hints.read_only_hint)
			== Some(true);
		let canonical = known.map_or("_unknown_tool", |tool| tool.name.as_ref());
		// Observation must not change its own totals or keep invalidating the
		// archive index. Only exact canonical metadata routes omit admission.
		let metadata_observer = matches!(
			canonical,
			"request_history" | "request_archive" | "usage_stats"
		);
		let ticket = if enabled && !metadata_observer {
			let scope = self
				.owner_binding
				.resolve(&context, self.search_owner.as_ref().as_deref())
				.map_err(|_| {
					ErrorData::internal_error(
						"request authority unavailable; dispatch refused",
						None,
					)
				})?;
			Some(
				runtime::request_audit::begin_with_read(
					scope.owner(),
					canonical,
					if matches!(canonical, "request_status" | "request_result") {
						match request
							.arguments
							.as_ref()
							.and_then(|a| a.get("request_id"))
							.and_then(serde_json::Value::as_str)
						{
							Some(id) => {
								runtime::request_async::audit_read_target(scope.owner(), id)
									.await
									.map_err(|_| {
										ErrorData::invalid_params(
											"request unavailable to this scope or current policy",
											None,
										)
									})?
							}
							None => None,
						}
					} else {
						None
					},
				)
				.await
				.map_err(|_| {
					ErrorData::internal_error("request audit unavailable; dispatch refused", None)
				})?,
			)
		} else {
			None
		};
		let result_intent = if let Some(ticket) = ticket
			.as_ref()
			.filter(|t| runtime::request_results::eligible(&t.identity().tool_name))
		{
			match runtime::request_results::admit(ticket.identity()).await {
				Ok(intent) => Some(intent),
				Err(_) => {
					let mut result = Err(ErrorData::internal_error(
						"result admission unavailable; tool was not dispatched",
						None,
					));
					runtime::request_results::attach_identity(&mut result, ticket.request_id());
					runtime::request_results::attach_ack(
						&mut result,
						"durability_unknown_not_dispatched",
						false,
					);
					return result;
				}
			}
		} else {
			None
		};
		let mut result = if visible {
			let call = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
			router.call(call).await
		} else {
			Err(ErrorData::invalid_params(
				"tool not found in this runtime mode",
				None,
			))
		};
		if let Some(ticket) = ticket {
			let id = ticket.request_id().to_owned();
			let tool = ticket.identity().tool_name;
			let expose_id = runtime::request_results::exposes_identity(&tool);
			if expose_id {
				runtime::request_results::attach_identity(&mut result, &id);
				runtime::request_results::reserve_final_wire(&mut result, &tool, &id);
			}
			let completion = match &result {
				_ if cancelled.is_cancelled() => AuditCompletion::Unknown,
				Ok(CallToolResponse::Complete(value)) if !value.is_error.unwrap_or(false) => {
					AuditCompletion::Completed
				}
				_ if !visible || readonly => AuditCompletion::Failed,
				_ => AuditCompletion::Unknown,
			};
			let retained = if let Some(intent) = result_intent {
				let response = match &result {
					Ok(CallToolResponse::Complete(value))
						if !cancelled.is_cancelled() && !value.is_error.unwrap_or(false) =>
					{
						Some(value.clone())
					}
					_ => None,
				};
				runtime::request_results::complete(intent, response)
					.await
					.unwrap_or("durability_unknown")
			} else {
				"not_retained_policy"
			};
			let audit_durable = runtime::request_audit::finish(ticket, completion)
				.await
				.is_ok();
			if !audit_durable {
				warn!("request audit completion unavailable; dispatch result preserved; no automatic retry");
			}
			if expose_id {
				runtime::request_results::attach_ack(&mut result, retained, audit_durable);
			}
		}
		result
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
			if let Ok(service) = Reference::new()
				.serve((tokio::io::stdin(), tokio::io::stdout()))
				.await
			{
				let _ = service.waiting().await;
			}
			runtime::request_async::freeze_admission();
			runtime::request_async::shutdown().await;
		});
}

impl Reference {
 fn new()->Self { Self {
			search_owner: Arc::new(runtime::search_jobs::new_owner_id().ok()),
			owner_binding: Arc::new(runtime::caller_scope::SessionOwnerBinding::default()),
			operation_crypto: runtime::operation_crypto::ResultCryptoScope::stdio()
				.ok()
				.map(Arc::new),
 } }
}

fn route_host_health(
	service: &Reference,
	params: Parameters<runtime::health::HostHealthParams>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
	Box::pin(service.host_health(params))
}

fn route_request_history(service: &Reference, params: Parameters<runtime::request_audit::RequestHistoryParams>, context: RequestContext<RoleServer>) -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String,String>> + Send + '_>> { Box::pin(service.request_history(params,context)) }
impl Reference {
	async fn request_history(
		&self,
		Parameters(params): Parameters<runtime::request_audit::RequestHistoryParams>,
		context: RequestContext<RoleServer>,
	) -> Result<String, String> {
		let scope = self
			.owner_binding
			.resolve(&context, self.search_owner.as_ref().as_deref())
			.map_err(|error| error.to_string())?;
		runtime::request_audit::history(scope.owner(), params)
			.await
			.and_then(|result| scope.annotate(result, false))
			.map_err(|error| error.to_string())
	}


}

fn route_request_start(service:&Reference,params:Parameters<runtime::request_async::RequestStartParams>,context:RequestContext<RoleServer>)->std::pin::Pin<Box<dyn std::future::Future<Output=Result<String,String>>+Send+'_>>{Box::pin(service.request_start(params,context))}
impl Reference {
	async fn request_start(
		&self,
		Parameters(params): Parameters<runtime::request_async::RequestStartParams>,
		context: RequestContext<RoleServer>,
	) -> Result<String, String> {
		// Optional cross-process new-effect admission. Must be configured on
		// every controller and ingress before any owner transfer is eligible.
		let _owner_admission = runtime::effect_owner_fence::admit_new_effect()
			.await
			.map_err(|error| error.to_string())?;

		let scope = self
			.owner_binding
			.resolve(&context, self.search_owner.as_ref().as_deref())
			.map_err(|error| error.to_string())?;
		runtime::request_async::start(scope.owner(), params)
			.await
			.and_then(|text| scope.annotate(text, false))
			.map_err(|error| error.to_string())
	}

}

fn route_request_cancel(service:&Reference,params:Parameters<runtime::request_async::RequestCancelParams>,context:RequestContext<RoleServer>)->std::pin::Pin<Box<dyn std::future::Future<Output=Result<String,String>>+Send+'_>>{Box::pin(service.request_cancel(params,context))}
impl Reference {
	async fn request_cancel(
		&self,
		Parameters(params): Parameters<runtime::request_async::RequestCancelParams>,
		context: RequestContext<RoleServer>,
	) -> Result<String, String> {
		let scope = self
			.owner_binding
			.resolve(&context, self.search_owner.as_ref().as_deref())
			.map_err(|error| error.to_string())?;
		runtime::request_async::cancel(scope.owner(), params)
			.await
			.and_then(|text| scope.annotate(text, false))
			.map_err(|error| error.to_string())
	}

}
