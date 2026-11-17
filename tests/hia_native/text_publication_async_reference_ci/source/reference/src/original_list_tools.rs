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
	"rea_evidence_session_checkpoint",
	"rea_evidence_session_resume",
	"rea_evidence_session_list",
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
	"weight_cohort_patch",
	"weight_cohort_restore",
	"weight_linear_forward",
	"weight_guarded_linear_patch",
	"weight_linear_ridge_plan",
	"weight_bellman_plan",
	"weight_continuation_certificate",
	"weight_semantic_replay",
	"weight_semantic_certificate",
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
trait OriginalList { async fn list_tools(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>) -> Result<ListToolsResult, ErrorData>; }
impl OriginalList for OctofsServer {
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
}
