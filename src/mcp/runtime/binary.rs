// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Version-bound, descriptor-relative native binary file tools and atomic uploads.
use super::config::{check_remote_path, runtime_config, ExecutionMode};
use super::ssh::run_python_json;
use anyhow::{bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

const SOURCE: &str = include_str!("binary_file.py");

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileInfoParams {
	pub host: String,
	pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BinaryReadParams {
	pub host: String,
	pub path: String,
	#[serde(default)]
	pub offset: Option<u64>,
	/// Maximum returned bytes; capped at 64 KiB. Use next_offset until eof.
	#[serde(default)]
	pub limit: Option<u64>,
	/// Bind every chunk to the version returned by the first read.
	#[serde(default)]
	pub expected_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BinaryWriteParams {
	pub host: String,
	pub path: String,
	/// Strict base64, up to 1 MiB decoded. Use binary_upload for larger files.
	pub data_base64: String,
	/// Exactly the prior file version, or absent for a create-only write.
	pub expected_version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UploadAction {
	Chunk,
	Commit,
	Abort,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BinaryUploadParams {
	pub host: String,
	pub path: String,
	pub action: UploadAction,
	pub upload_id: String,
	#[serde(default)]
	pub offset: Option<u64>,
	#[serde(default)]
	pub data_base64: Option<String>,
	#[serde(default)]
	pub expected_version: Option<String>,
	#[serde(default)]
	pub size: Option<u64>,
	#[serde(default)]
	pub sha256: Option<String>,
}

async fn rpc(host_name: &str, path: &str, write: bool, mut q: Value) -> Result<String> {
	let host = runtime_config()?.host(host_name)?;
	// This is a trusted-account API, not another route around isolated-host rules.
	if host.execution_mode != ExecutionMode::Operator {
		bail!("native binary tools require an operator host");
	}
	check_remote_path(host_name, path, false, false, write)?;
	let roots = if write {
		&host.allowed_write_path_prefixes
	} else {
		&host.allowed_read_path_prefixes
	};
	let root = roots
		.iter()
		.filter(|root| {
			path == root.as_str() || path.starts_with(&format!("{}/", root.trim_end_matches('/')))
		})
		.max_by_key(|r| r.len());
	let Some(root) = root else {
		bail!("file outside configured roots");
	};
	q["root"] = json!(root);
	q["path"] = json!(path);
	if write {
		super::jobs::audit(
			"native_binary_write",
			host_name,
			path,
			&json!({"op":q["op"]}),
		)?;
	}
	let value: Value = run_python_json(host, SOURCE, &q, Duration::from_secs(30)).await?;
	Ok(serde_json::to_string(&value)?)
}

pub async fn info(p: FileInfoParams) -> Result<String> {
	rpc(&p.host, &p.path, false, json!({"op":"info"})).await
}

pub async fn read(p: BinaryReadParams) -> Result<String> {
	rpc(&p.host,&p.path,false,json!({"op":"read","offset":p.offset,"limit":p.limit.unwrap_or(32768).clamp(1,65536),"expected_version":p.expected_version})).await
}

pub async fn write(p: BinaryWriteParams) -> Result<String> {
	if p.data_base64.len() > 1_398_104 {
		bail!("binary payload exceeds 1 MiB decoded bound");
	}
	rpc(
		&p.host,
		&p.path,
		true,
		json!({"op":"write","data_base64":p.data_base64,"expected_version":p.expected_version}),
	)
	.await
}

pub async fn upload(p: BinaryUploadParams) -> Result<String> {
	if p.upload_id.len() < 8
		|| p.upload_id.len() > 96
		|| !p
			.upload_id
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
	{
		bail!("invalid upload identity");
	}
	let op = match p.action {
		UploadAction::Chunk => {
			if p.expected_version.is_none()
				|| p.data_base64.as_ref().is_none_or(|v| v.len() > 1_398_104)
			{
				bail!("chunk requires expected version and bounded base64 data");
			}
			"upload_chunk"
		}
		UploadAction::Commit => {
			if p.size.is_none()
				|| p.sha256
					.as_ref()
					.is_none_or(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
			{
				bail!("commit requires total size and SHA256");
			}
			"upload_commit"
		}
		UploadAction::Abort => "upload_abort",
	};
	rpc(
		&p.host,
		&p.path,
		true,
		json!({"op":op,"upload_id":p.upload_id,"offset":p.offset,"data_base64":p.data_base64,
        "expected_version":p.expected_version,"size":p.size,"sha256":p.sha256}),
	)
	.await
}

#[cfg(test)]
#[path = "binary_tests.rs"]
mod tests;
