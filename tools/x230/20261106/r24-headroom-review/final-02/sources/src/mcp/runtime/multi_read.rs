// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Descriptor-bound, strict UTF-8 full-file batches with a shared wire-size ceiling.
use super::config::{check_remote_path, runtime_config, ExecutionMode};
use super::ssh::run_python_json;
use anyhow::{bail, Result};
use rmcp::{
	model::{CallToolResult, ContentBlock},
	schemars,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

// Reuse the native descriptor walk without entering its binary operation dispatcher.
const SOURCE: &str = concat!(
	"__name__ = 'hepta_multi_read_helpers'\n",
	include_str!("file_metadata.py"),
	"\n",
	include_str!("binary_file.py"),
	"\n",
	include_str!("multi_read_host.py"),
	"\nrun_multi_read()\n"
);
const MAX_FILE_BYTES: u64 = 65_536;
const MAX_RESPONSE_BYTES: u64 = 262_144;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MultiReadParams {
	/// One configured operator host. Caller-selected SSH targets are unavailable.
	pub host: String,
	/// 1..16 distinct absolute regular-file paths; symlinks and hardlinks are rejected.
	pub paths: Vec<String>,
	/// Full-file byte ceiling, 1..65536; default 16384. Larger files fail, never truncate.
	#[serde(default)]
	pub max_file_bytes: Option<u64>,
	/// Shared serialized MCP text-result ceiling, 1024..262144; default 65536.
	/// Includes JSON escaping. A failed batch returns no partial file content.
	#[serde(default)]
	pub max_response_bytes: Option<u64>,
}

fn validate(p: &MultiReadParams) -> Result<(u64, u64)> {
	if !(1..=16).contains(&p.paths.len()) {
		bail!("read_multiple_files requires 1..16 paths");
	}
	let file = p.max_file_bytes.unwrap_or(16_384);
	let response = p.max_response_bytes.unwrap_or(65_536);
	if !(1..=MAX_FILE_BYTES).contains(&file) {
		bail!("max_file_bytes must be 1..65536; larger files require binary_read");
	}
	if !(1024..=MAX_RESPONSE_BYTES).contains(&response) {
		bail!("max_response_bytes must be 1024..262144");
	}
	let mut seen = std::collections::HashSet::new();
	for path in &p.paths {
		// Reject aliases before protected-prefix checks, rather than normalizing after them.
		if path.len() > 4096
			|| !path.starts_with('/')
			|| path.contains('\0')
			|| path[1..]
				.split('/')
				.any(|part| part.is_empty() || part == "." || part == "..")
		{
			bail!("batch paths must be bounded absolute paths without empty, dot or traversal components");
		}
		if !seen.insert(path) {
			bail!("read_multiple_files paths must be distinct");
		}
	}
	Ok((file, response))
}

fn serialize_result(value: &Value, limit: u64) -> Result<String> {
	let output = serde_json::to_string(value)?;
	let result = CallToolResult::success(vec![ContentBlock::text(output.clone())]);
	if serde_json::to_vec(&result)?.len() as u64 > limit {
		bail!("multi-file response exceeds serialized MCP result byte budget; narrow paths or file sizes");
	}
	Ok(output)
}

fn redacted_transport_error(_error: anyhow::Error) -> anyhow::Error {
	// Legacy transport errors retain helper stdout/stderr and SSH destinations.
	// A failed read must not disclose any earlier source bytes through that chain.
	anyhow::anyhow!("multi-file read could not complete; verify configured read roots, regular single-link files, strict UTF-8 and byte budgets")
}

pub async fn read(p: MultiReadParams) -> Result<String> {
	let (file_limit, response_limit) = validate(&p)?;
	let host = runtime_config()?.host(&p.host)?;
	if host.execution_mode != ExecutionMode::Operator {
		bail!("read_multiple_files requires a configured operator host");
	}
	let mut files = Vec::with_capacity(p.paths.len());
	for path in &p.paths {
		check_remote_path(&p.host, path, false, false, false)?;
		let root = host
			.allowed_read_path_prefixes
			.iter()
			.filter(|root| {
				path == root.as_str()
					|| path.starts_with(&format!("{}/", root.trim_end_matches('/')))
			})
			.max_by_key(|root| root.len());
		let Some(root) = root else {
			bail!("batch file outside configured read roots");
		};
		files.push(json!({"path":path, "root":root}));
	}
	let request = json!({"files":files, "max_file_bytes":file_limit,
        "max_response_bytes":response_limit});
	let value: Value = run_python_json(host, SOURCE, &request, Duration::from_secs(30))
		.await
		.map_err(redacted_transport_error)?;
	serialize_result(&value, response_limit)
}

#[cfg(test)]
#[path = "multi_read_tests.rs"]
mod tests;
