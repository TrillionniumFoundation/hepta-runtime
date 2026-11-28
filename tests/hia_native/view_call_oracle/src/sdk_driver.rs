// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Test-only actual rmcp transport. Original ViewParams and schema bodies are
// appended unchanged by the source materializer. This is not the view handler.
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rmcp::model::{CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock};
use rmcp::service::RequestContext;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[derive(Clone)]
struct Probe(Arc<Mutex<Vec<Value>>>);

impl ServerHandler for Probe {
    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>) -> Result<CallToolResponse, ErrorData> {
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let typed = match serde_json::from_value::<ViewParams>(arguments) {
            Ok(params) => json!({"ok": true, "value": serde_json::to_value(params).unwrap()}),
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        };
        let observation = json!({"typed": typed, "capabilities": context.client_capabilities(),
                                 "protocol_version": context.protocol_version(), "request_id": context.id});
        self.0.lock().unwrap().push(observation.clone());
        Ok(CallToolResult::success(vec![ContentBlock::text(serde_json::to_string(&observation).unwrap())]).into())
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
           "handler_observations": calls, "service": terminal})
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
