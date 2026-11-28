// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Observe actual locked SDK message deserialization and serialization.
#![allow(deprecated)]
use rmcp::model::{ClientJsonRpcMessage, GetMeta, ProtocolVersion};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
fn hex(raw: &str) -> anyhow::Result<Vec<u8>> {
	anyhow::ensure!(raw.len() % 2 == 0, "odd hex");
	raw.as_bytes()
		.chunks_exact(2)
		.map(|p| Ok(u8::from_str_radix(std::str::from_utf8(p)?, 16)?))
		.collect()
}
fn main() -> anyhow::Result<()> {
	let mut out = std::io::stdout().lock();
	for line in std::io::stdin().lock().lines() {
		let input: Value = serde_json::from_str(&line?)?;
		let raw = hex(input["hex"].as_str().unwrap())?;
		let result = match serde_json::from_slice::<ClientJsonRpcMessage>(&raw) {
			Err(e) => {
				json!({"label":input["label"],"accepted":false,"diagnostic":{"message":e.to_string(),"category":format!("{:?}",e.classify()),"line":e.line(),"column":e.column()}})
			}
			Ok(message) => {
				let value = serde_json::to_value(&message)?;
				let wire = serde_json::to_string(&message)?;
				match &message {
					ClientJsonRpcMessage::Request(r) => {
						let m = r.request.get_meta();
						let variant = format!("{:?}", r.request)
							.split('(')
							.next()
							.unwrap()
							.to_string();
						json!({"label":input["label"],"accepted":true,"kind":"request","variant":variant,"id":r.id,"method":r.request.method(),"meta":m,"protocol_version":m.protocol_version(),"client_capabilities":m.client_capabilities(),"missing":m.missing_required_keys(&ProtocolVersion::V_2026_07_28),"message":value,"wire":wire})
					}
					ClientJsonRpcMessage::Notification(n) => {
						json!({"label":input["label"],"accepted":true,"kind":"notification","variant":format!("{:?}",n.notification).split('(').next().unwrap(),"meta":n.notification.get_meta(),"message":value,"wire":wire})
					}
					ClientJsonRpcMessage::Response(_) => {
						json!({"label":input["label"],"accepted":true,"kind":"response","message":value,"wire":wire})
					}
					ClientJsonRpcMessage::Error(_) => {
						json!({"label":input["label"],"accepted":true,"kind":"error","message":value,"wire":wire})
					}
				}
			}
		};
		serde_json::to_writer(&mut out, &result)?;
		out.write_all(b"\n")?;
	}
	Ok(())
}
