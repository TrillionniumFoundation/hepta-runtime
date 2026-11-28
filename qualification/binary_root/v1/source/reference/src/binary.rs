// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Test-only post-admission effect boundaries are defined in main.rs.
use super::config::{check_remote_path, runtime_config, ExecutionMode};
use super::ssh::run_python_json;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::time::Duration;

const SOURCE: &str = concat!(
	include_str!("file_metadata.py"),
	"\n",
	include_str!("inode_patch.py"),
	"\n",
	include_str!("binary_file.py")
);

// The closed FileObservation enum supplies only info/read. Keep their original
// metadata and descriptor helpers, but avoid parsing unused inode-patch code on
// every remote observation. The general RPC source above retains every writer.
const OBSERVATION_SOURCE: &str = concat!(
	include_str!("file_metadata.py"),
	"\n",
	include_str!("binary_file.py")
);

pub(super) fn observation_source() -> &'static str {
	OBSERVATION_SOURCE
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

fn observation_read_root(host_name: &str, path: &str) -> Result<&'static str> {
	let host = runtime_config()?.host(host_name)?;
	if host.execution_mode != ExecutionMode::Operator {
		bail!("native binary tools require an operator host");
	}
	check_remote_path(host_name, path, false, false, false)?;
	host.allowed_read_path_prefixes
		.iter()
		.filter(|root| {
			path == root.as_str() || path.starts_with(&format!("{}/", root.trim_end_matches('/')))
		})
		.max_by_key(|root| root.len())
		.map(String::as_str)
		.ok_or_else(|| anyhow::anyhow!("file outside configured roots"))
}

pub fn root_query(host: &str, path: &str, write: bool, mode: &str) -> Result<String> {
    match mode {
        "observe" => {
            anyhow::ensure!(!write, "observation fixture is read only");
            Ok(observation_read_root(host, path)?.to_owned())
        },
        "rpc" => {
            let raw = super::ready(rpc(host, path, write, json!({"op":"root_probe"})))?;
            let value: Value = serde_json::from_str(&raw)?;
            Ok(value["root"].as_str().ok_or_else(|| anyhow::anyhow!("captured root absent"))?.to_owned())
        },
        "policy" => {
            check_remote_path(host, path, false, false, write)?;
            Ok(String::new())
        },
        _ => anyhow::bail!("unfrozen root query mode"),
    }
}
