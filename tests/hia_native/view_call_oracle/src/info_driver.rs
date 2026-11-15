// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Actual SDK transport with unchanged original get_info/cache-hint predicate.
// The list contains an explicit empty fixture, not the original tool catalog.
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde_json::{json, Value};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rmcp::model::{ServerConfig, ServerCapabilities, Implementation, ExperimentalCapabilities, JsonObject, ProtocolVersion, ListToolsResult, CacheScope, PaginatedRequestParams};
use rmcp::service::RequestContext;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

const CLAUDE_CHANNEL_CAPABILITY: &str = "claude/channel";
fn supports_cache_hints(context: &RequestContext<RoleServer>) -> bool {
	context
		.protocol_version()
		.is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}
#[derive(Clone)]
struct Probe(Arc<Mutex<Vec<Value>>>);
impl ServerHandler for Probe {
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
    async fn list_tools(&self, _request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>)
        -> Result<ListToolsResult, ErrorData> {
        self.0.lock().unwrap().push(json!({"operation":"list_tools", "protocol_version":context.protocol_version(),
            "capabilities":context.client_capabilities(), "request_id":context.id}));
        let tools: Vec<rmcp::model::Tool> = Vec::new();
		let result = ListToolsResult::with_all_items(tools);
		if !supports_cache_hints(&context) {
			return Ok(result);
		}
		// ttl 0 matches rmcp's generated handler; the list is identical for every caller.
		Ok(result.with_ttl_ms(0).with_cache_scope(CacheScope::Public))
    }
}

async fn run_case(case: Value) -> Value {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let handler = Probe(seen.clone());
    let (client, server) = tokio::io::duplex(65536);
    let service = tokio::spawn(async move {
        match handler.serve(server).await {
            Ok(service) => {
                let result = service.waiting().await;
                json!({"initialized": true, "terminated": format!("{result:?}")})
            }
            Err(error) => json!({"initialized": false, "error": error.to_string()}),
        }
    });
    let (input, mut writer) = tokio::io::split(client);
    let mut reader = tokio::io::BufReader::new(input);
    let mut replies = Vec::new();
    for request in case["messages"].as_array().unwrap() {
        let mut wire = serde_json::to_vec(request).unwrap(); wire.push(b'\n');
        writer.write_all(&wire).await.unwrap();
        if request.get("id").is_none() { continue; }
        let mut line = String::new();
        let size = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await.unwrap().unwrap();
        assert!(size > 0, "actual SDK response missing for {}", case["name"]);
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], request["id"]);
        replies.push(response);
    }
    drop(reader); drop(writer);
    let terminal = tokio::time::timeout(Duration::from_secs(5), service).await.unwrap().unwrap();
    let calls = seen.lock().unwrap().clone();
    json!({"case_id": case["case_id"], "name": case["name"], "responses": replies,
           "handler_observations": calls, "service": terminal, "actual_original_get_info":true, "actual_original_cache_hint_predicate":true, "empty_tool_list_fixture":true, "original_full_list_tools_executed":false, "original_view_body_executed":false})
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let input = io::stdin().lock(); let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let result = run_case(row).await;
        serde_json::to_writer(&mut output, &result).unwrap(); output.write_all(b"\n").unwrap();
    }
    output.flush().unwrap();
}
