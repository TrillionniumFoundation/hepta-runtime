// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Locked rmcp typed-envelope probe. Its handler records arguments; its body
//! is a test fixture and is never represented as the original View method.
use rmcp::model::{CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{json, Value};
use std::io::{self, BufRead};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[derive(Clone)]
struct Probe(Arc<Mutex<Vec<Value>>>);
impl ServerHandler for Probe {
    async fn call_tool(&self, request: CallToolRequestParams, _context: RequestContext<RoleServer>)
        -> Result<CallToolResponse, ErrorData> {
        let observed = serde_json::to_value(&request.arguments).unwrap();
        self.0.lock().unwrap().push(observed.clone());
        Ok(CallToolResult::success(vec![ContentBlock::text(serde_json::to_string(&observed).unwrap())]).into())
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes().chunks_exact(2).map(|p| {
        (((p[0] as char).to_digit(16).unwrap() << 4) | (p[1] as char).to_digit(16).unwrap()) as u8
    }).collect()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

async fn run_case(wire: &[u8]) -> Value {
    assert!(!wire.ends_with(b"\n"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let handler = Probe(seen.clone());
    let (client, server) = tokio::io::duplex(65536);
    let service = tokio::spawn(async move {
        let service = handler.serve(server).await.unwrap();
        service.waiting().await.unwrap();
    });
    let (input, mut writer) = tokio::io::split(client);
    let mut reader = tokio::io::BufReader::new(input);
    let initial = b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"raw-span-probe\",\"version\":\"1\"}}}\n";
    writer.write_all(initial).await.unwrap();
    let mut initialized = String::new();
    assert!(tokio::time::timeout(Duration::from_secs(5),reader.read_line(&mut initialized)).await.unwrap().unwrap()>0);
    let notification = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
    writer.write_all(notification).await.unwrap();
    writer.write_all(wire).await.unwrap();writer.write_all(b"\n").await.unwrap();
    let following = b"{\"jsonrpc\":\"2.0\",\"id\":101,\"method\":\"tools/call\",\"params\":{\"name\":\"view\",\"arguments\":{\"path\":\"after-one\"}}}\n{\"jsonrpc\":\"2.0\",\"id\":102,\"method\":\"tools/call\",\"params\":{\"name\":\"view\",\"arguments\":{\"path\":\"after-two\"}}}\n";
    writer.write_all(following).await.unwrap();
    let mut replies = Vec::new();let mut reply_bytes = Vec::new();
    loop {
        let mut reply = String::new();
        assert!(tokio::time::timeout(Duration::from_secs(5),reader.read_line(&mut reply)).await.unwrap().unwrap()>0);
        let value: Value = serde_json::from_str(&reply).unwrap();
        let done = value.get("id") == Some(&json!(102));
        replies.push(value);reply_bytes.extend_from_slice(reply.as_bytes());
        assert!(replies.len() <= 3);
        if done { break; }
    }
    let count = replies.len();assert!(count>=2);
    assert_eq!(replies[count-2].get("id"),Some(&json!(101)));
    assert_eq!(replies[count-1].get("id"),Some(&json!(102)));
    drop(reader);drop(writer);
    tokio::time::timeout(Duration::from_secs(5),service).await.unwrap().unwrap();
    let observations=seen.lock().unwrap().clone();let n=observations.len();assert!(n>=2);
    assert_eq!(observations[n-2],json!({"path":"after-one"}));
    assert_eq!(observations[n-1],json!({"path":"after-two"}));
    json!({"request_hex":hex(wire),"case_responses":&replies[..count-2],
        "handler_observations":&observations[..n-2],"following_responses":&replies[count-2..],
        "initialized_response_hex":hex(initialized.as_bytes()),"response_stream_hex":hex(&reply_bytes),
        "typed_sdk_handler_fixture":true,"original_view_body_compared":false})
}

#[tokio::main(flavor="current_thread")]
async fn main() {
    for line in io::stdin().lock().lines() {
        let request=unhex(&line.unwrap());println!("{}",run_case(&request).await);
    }
}
