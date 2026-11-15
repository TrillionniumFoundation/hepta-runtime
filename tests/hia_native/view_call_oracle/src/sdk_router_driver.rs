// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Test-only actual rmcp transport and its real Parameters extractor/method adapter.
// Original ViewParams/schema are appended unchanged; the typed body is a fixture.
// No original view, session method, policy or filesystem action is executed.
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rmcp::model::{CallToolRequestParams, CallToolResponse};
use rmcp::service::RequestContext;
use rmcp::handler::server::tool::{ToolCallContext, AsyncMethodAdapter};
use rmcp::handler::server::wrapper::Parameters;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[derive(Clone)]
struct Probe(Arc<Mutex<Vec<Value>>>, Arc<std::sync::atomic::AtomicUsize>);

impl Probe {
    fn view(&self, context: RequestContext<RoleServer>, Parameters(params): Parameters<ViewParams>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let observation = json!({"typed": {"ok": true, "value": serde_json::to_value(&params).unwrap()},
                                    "capabilities": context.client_capabilities(),
                                    "protocol_version": context.protocol_version(), "request_id": context.id});
            self.0.lock().unwrap().push(observation.clone());
            if params.path == "fixture:error" {
                Err("fixture result error\n⚠️ \"quoted\"\t中🙂".to_owned())
            } else {
                Ok(serde_json::to_string(&observation).unwrap())
            }
        })
    }
}

impl ServerHandler for Probe {
    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>)
        -> Result<CallToolResponse, ErrorData> {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ToolCallContext::new(self, request, context)
            .invoke::<_, AsyncMethodAdapter<(RequestContext<RoleServer>, Parameters<ViewParams>), Result<String, String>>>(Self::view)
            .await
    }
}

async fn run_case(case: Value) -> Value {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let outer_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler = Probe(seen.clone(), outer_calls.clone());
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
           "handler_observations": calls, "outer_call_tool_entries": outer_calls.load(std::sync::atomic::Ordering::SeqCst), "service": terminal, "actual_sdk_parameters_extractor": true, "actual_sdk_async_method_adapter": true, "original_view_body_executed": false, "ensure_session_method_executed": false})
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
