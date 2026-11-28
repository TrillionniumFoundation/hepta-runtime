// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original captured function bodies; generated with exact source span bindings.
use anyhow::Result;
use serde_json::{json,Value};
use std::path::PathBuf;
use std::time::{SystemTime,UNIX_EPOCH};

struct PreparedAudit {
	path: PathBuf,
	line: Vec<u8>,
}

fn now_ms() -> u128 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis()
}

fn prepare_audit_at(
	path: PathBuf,
	action: &str,
	host: &str,
	subject: &str,
	outcome: &Value,
) -> Result<PreparedAudit> {
	let event = json!({
		"at_unix_ms": now_ms(),
		"action": action,
		"host": host,
		"subject": subject,
		"outcome": outcome,
	});
	let mut line = serde_json::to_vec(&event)?;
	line.push(b'\n');
	Ok(PreparedAudit { path, line })
}


pub fn capture(host:&str,subject:&str,outcome:&Value)->Result<String>{
 let prepared=prepare_audit_at(PathBuf::from("/fixture/audit/events.jsonl"),"native_binary_write",host,subject,outcome)?;
 let _path=prepared.path;
 Ok(String::from_utf8(prepared.line)?)
}
