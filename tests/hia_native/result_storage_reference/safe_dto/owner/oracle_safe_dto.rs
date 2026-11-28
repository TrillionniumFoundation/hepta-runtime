// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Test framing; original configuration, summaries and DTO bodies are unchanged.
//! Qualification projection of the original retained-result owner.
pub mod mcp;
pub mod utils;

use mcp::runtime::{config, effective_config, inspect, request_safe_dto};
use rmcp::model::CallToolResult;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::Path;

fn observed(value: anyhow::Result<String>) -> Value {
	match value {
		Ok(text) => json!({"status": 0, "text": text}),
		Err(error) => json!({"status": 1, "text": error.to_string()}),
	}
}

fn invoke(input: Value) -> Value {
	match input["op"].as_str().unwrap() {
		"summaries" => json!({
			"host_list": observed(inspect::host_list()),
			"effective_config": observed(effective_config::effective_config(Default::default()))
		}),
		"platform" => {
			let alias = input["alias"].as_str().unwrap();
			let result = (|| -> anyhow::Result<Value> {
				let host = config::runtime_config()?.host(alias)?;
				Ok(json!({"status": 0, "alias": alias, "platform": host.platform}))
			})();
			match result {
				Ok(value) => value,
				Err(error) => json!({"status": 1, "error": error.to_string()}),
			}
		}
		"dto" => {
			let mut result: CallToolResult = serde_json::from_value(input["body"].clone()).unwrap();
			if let Some(value) = input["body"].as_object().unwrap().get("structuredContent") {
				result.structured_content = Some(value.clone());
			}
			let canonical = serde_json::to_string(&serde_json::to_value(&result).unwrap()).unwrap();
			let decision = request_safe_dto::observe(input["tool"].as_str().unwrap(), &result);
			json!({"label": input["label"], "canonical_body": canonical, "accepted": decision})
		}
		other => panic!("unknown original fixture operation {other}"),
	}
}

fn main() -> anyhow::Result<()> {
	let args: Vec<_> = std::env::args_os().collect();
	assert!(args.len() == 1 || args.len() == 3);
	if args.len() == 3 {
		assert_eq!(args[1], "--runtime-config");
		let loaded = config::RuntimeConfig::load(Path::new(&args[2]))?;
		config::init_runtime(loaded)?;
	}
	let mut output = io::BufWriter::new(io::stdout().lock());
	for line in io::stdin().lock().lines() {
		let input = serde_json::from_str(&line?)?;
		serde_json::to_writer(&mut output, &invoke(input))?;
		output.write_all(b"\n")?;
		output.flush()?;
	}
	Ok(())
}
