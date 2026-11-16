// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

// Append-only qualification observer. All original server bytes precede this
// function unchanged. It calls the actual generated router and list handler.
#[doc(hidden)]
pub async fn __hia_current_catalog_observe() -> anyhow::Result<serde_json::Value> {
    let server = OctofsServer::new();
    let raw = OctofsServer::tool_router().list_all();
    let raw_tool_wires: Vec<String> = raw
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<_, _>>()?;
    let get_info_wire = serde_json::to_string(&ServerHandler::get_info(&server))?;
    let (transport, peer_transport) = tokio::io::duplex(4096);
    let running = rmcp::service::serve_directly::<RoleServer, _, _, _, _>(
        server.clone(), transport, None,
    );
    let mut observations = Vec::new();
    for version in [None, Some("2024-11-05"), Some("2025-03-26"),
                    Some("2025-06-18"), Some("2025-11-25"), Some("2026-07-27"),
                    Some("2026-07-28"), Some("2026-08-01")] {
        for cursor_case in 0..3 {
            let mut context = RequestContext::new(
                RequestId::Number(observations.len() as i64), running.peer().clone(),
            );
            if let Some(version) = version {
                context.meta.set_protocol_version(serde_json::from_value(
                    serde_json::Value::String(version.to_string()),
                )?);
            }
            let request = match cursor_case {
                0 => None,
                1 => Some(serde_json::from_value(serde_json::json!({}))?),
                _ => Some(serde_json::from_value(serde_json::json!({
                    "cursor": "qualification-cursor-\u{0000}-\u{03bb}"
                }))?),
            };
            let result = ServerHandler::list_tools(&server, request, context).await?;
            observations.push(serde_json::json!({
                "protocol_version": version,
                "cursor_case": cursor_case,
                "tool_count": result.tools.len(),
                "result_wire": serde_json::to_string(&result)?,
            }));
        }
    }
    let close = format!("{:?}", running.cancel().await?);
    drop(peer_transport);
    let configured = runtime::config::maybe_runtime_config();
    Ok(serde_json::json!({
        "schema": "hepta.runtime.current-catalog-observation.v1",
        "target_commit": "d3d75c30719db966b004756f610007a7c723729e",
        "raw_tool_wires": raw_tool_wires,
        "get_info_wire": get_info_wire,
        "runtime_tool_names": RUNTIME_TOOL_NAMES,
        "weight_tool_names": WEIGHT_WORKER_TOOL_NAMES,
        "hia_tool_names": hia_contract::TOOLS,
        "hia_catalog_sha256": hia_contract::catalog_sha256(),
        "runtime_enabled": configured.is_some(),
        "hia_enabled": configured.is_some_and(|c| c.hia_worker.is_some()),
        "rea_enabled": configured.is_some_and(|c| !c.rea_static_profiles.is_empty()),
        "weight_enabled": configured.is_some_and(|c| !c.weight_workers.is_empty()),
        "list_cases": observations,
        "service_close": close,
        "tool_body_calls": 0,
        "worker_readiness_qualified": false,
        "whole_runtime_replaced": false,
        "production_activated": false,
        "old_stack_removal_qualified": false,
    }))
}
