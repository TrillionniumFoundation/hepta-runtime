// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Read-only capability projection of loaded policy without secret-bearing values.
use anyhow::{anyhow, bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use super::config::{runtime_config, ExecutionMode, Platform, RuntimeConfig};
use crate::utils::json_size::serialized_json_size;

const MAX_HOST_ENTRIES: usize = 256;
const MAX_SUMMARY_BYTES: usize = 256 * 1024;
const UNAVAILABLE: &str = "effective runtime configuration is unavailable";
static EFFECTIVE_SUMMARY: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectiveConfigParams {}

#[derive(Serialize)]
struct EffectiveConfigSummary<'a> {
	schema: &'static str,
	scope: &'static str,
	semantics: &'static str,
	redaction: &'static str,
	policy_mutation_supported: bool,
	target_probe_performed: bool,
	controller: ControllerSummary,
	hosts: Vec<HostSummary<'a>>,
	limits: SummaryLimits,
}

#[derive(Serialize)]
struct ControllerSummary {
	workspace_root_count: usize,
	file_workspace_roots_configured: bool,
}

#[derive(Serialize)]
struct HostSummary<'a> {
	alias: &'a str,
	platform: Platform,
	execution_mode: ExecutionMode,
	permissions: PermissionSummary,
	file_api: FileApiSummary,
	named_privileged_action_count: usize,
	checkpoint_pin_configured: bool,
}

#[derive(Serialize)]
struct PermissionSummary {
	allow_execute: bool,
	allow_pty: bool,
	allow_write: bool,
	allow_job_network: bool,
	allow_detached_fallback: bool,
}

#[derive(Serialize)]
struct FileApiSummary {
	read_root_count: usize,
	write_root_count: usize,
	read_paths_configured: bool,
	write_paths_authorized_and_configured: bool,
}

#[derive(Serialize)]
struct SummaryLimits {
	maximum_summary_host_entries: usize,
	maximum_summary_response_bytes: usize,
}

fn render_effective_config(config: Result<&RuntimeConfig>) -> Result<String> {
	// Retrieval and validation errors can contain secret paths, target identities
	// or raw policy fragments. Preserve none of the underlying error chain.
	let config = config.map_err(|_| anyhow!(UNAVAILABLE))?;
	if config.hosts.len() > MAX_HOST_ENTRIES {
		bail!("effective configuration exceeds the bounded host summary limit");
	}
	config.validate().map_err(|_| anyhow!(UNAVAILABLE))?;
	let hosts = config
		.hosts
		.iter()
		.map(|(alias, host)| HostSummary {
			alias,
			platform: host.platform,
			execution_mode: host.execution_mode,
			permissions: PermissionSummary {
				allow_execute: host.allow_execute,
				allow_pty: host.allow_pty,
				allow_write: host.allow_write,
				allow_job_network: host.allow_job_network,
				allow_detached_fallback: host.allow_detached_fallback,
			},
			file_api: FileApiSummary {
				read_root_count: host.allowed_read_path_prefixes.len(),
				write_root_count: host.allowed_write_path_prefixes.len(),
				read_paths_configured: !host.allowed_read_path_prefixes.is_empty(),
				write_paths_authorized_and_configured: host.allow_write
					&& !host.allowed_write_path_prefixes.is_empty(),
			},
			named_privileged_action_count: host.privileged_actions.len(),
			checkpoint_pin_configured: host.checkpoint_binary.is_some()
				&& host.checkpoint_binary_sha256.is_some(),
		})
		.collect();
	// This DTO is an allowlist. Serializing RuntimeConfig and removing selected
	// keys would expose new configuration fields by default. No digest is offered:
	// even a hash of hidden policy can become an oracle for low-entropy secrets.
	let summary = EffectiveConfigSummary {
		schema: "hepta-effective-config-v1",
		scope: "loaded_runtime_policy_capabilities",
		semantics: "Configured flags and counts only; target reachability, path availability, specific argument authorization and existing sudo authorization are not verified.",
		redaction: "capabilities_and_counts_only",
		policy_mutation_supported: false,
		target_probe_performed: false,
		controller: ControllerSummary {
			workspace_root_count: config.controller_workspace_roots.len(),
			file_workspace_roots_configured: !config.controller_workspace_roots.is_empty(),
		},
		hosts,
		limits: SummaryLimits {
			maximum_summary_host_entries: MAX_HOST_ENTRIES,
			maximum_summary_response_bytes: MAX_SUMMARY_BYTES,
		},
	};
	let text = serde_json::to_string_pretty(&summary)?;
	let wire =
		rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(text.clone())]);
	if serialized_json_size(&wire)? > MAX_SUMMARY_BYTES {
		bail!("effective configuration exceeds the bounded response limit");
	}
	Ok(text)
}

fn cached_effective_config(
	cache: &OnceLock<String>,
	compute: impl FnOnce() -> Result<String>,
) -> Result<String> {
	if let Some(summary) = cache.get() {
		return Ok(summary.clone());
	}
	// Only immutable loaded policy reaches the production cache. Failed
	// validation or rendering leaves the cell empty; racing successes agree.
	let summary = compute()?;
	Ok(cache.get_or_init(|| summary).clone())
}

pub fn effective_config(_params: EffectiveConfigParams) -> Result<String> {
	let config = runtime_config().map_err(|_| anyhow!(UNAVAILABLE))?;
	// The loaded RuntimeConfig has no reload or mutation path. Retain just the
	// bounded redacted summary, avoiding repeated private regex compilation.
	cached_effective_config(&EFFECTIVE_SUMMARY, || render_effective_config(Ok(config)))
}

#[cfg(test)]
#[path = "effective_config_tests.rs"]
mod tests;
