// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Test-only installed-value boundary around exact original declarations/functions.
use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
struct InstalledRuntimeConfig { config: RuntimeConfig }
static RUNTIME_CONFIG: OnceLock<InstalledRuntimeConfig> = OnceLock::new();

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
	#[default]
	Linux,
	Macos,
}

/// Administrator-selected trust boundary, never supplied by a tool invocation.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
	#[default]
	Isolated,
	/// Full authority of the configured SSH login, including its existing sudo rights.
	Operator,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivilegedAction {
	pub executable: String,
	#[serde(default)]
	pub fixed_args: Vec<String>,
	#[serde(default)]
	pub allow_extra_args: bool,
	/// One full-match regex per accepted extra argument. Empty means none.
	#[serde(default)]
	pub extra_arg_patterns: Vec<String>,
	#[serde(default = "default_action_timeout")]
	pub timeout_seconds: u64,
}

fn default_action_timeout() -> u64 {
	30
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostConfig {
	/// Optional administrator-pinned CRIU executable. Disabled when absent.
	#[serde(default)]
	pub checkpoint_binary: Option<String>,
	/// Exact SHA256 for the configured CRIU artifact, never supplied by tool callers.
	#[serde(default)]
	pub checkpoint_binary_sha256: Option<String>,
	#[serde(default)]
	pub execution_mode: ExecutionMode,
	/// OpenSSH config alias or user@host target. Never supplied by a tool call.
	pub ssh_target: String,
	#[serde(default)]
	pub platform: Platform,
	/// Absolute per-host directory holding durable job state and logs.
	pub remote_state_dir: String,
	#[serde(default)]
	pub allow_execute: bool,
	#[serde(default)]
	pub allow_pty: bool,
	#[serde(default)]
	pub allow_write: bool,
	/// Allow AF_INET/AF_INET6 from durable jobs. Default false creates a fail-closed
	/// private network namespace restricted to AF_UNIX.
	#[serde(default)]
	pub allow_job_network: bool,
	/// Allow a detached supervisor when user-systemd cannot create the unit.
	/// Keep false on production Linux hosts; macOS requires true in v0.1.
	#[serde(default)]
	pub allow_detached_fallback: bool,
	/// Optional absolute cwd allowlist. Empty means any cwd reachable by the SSH identity.
	#[serde(default)]
	pub allowed_cwd_prefixes: Vec<String>,
	/// Absolute remote read roots for inherited SFTP tools. Empty denies reads.
	#[serde(default)]
	pub allowed_read_path_prefixes: Vec<String>,
	/// Absolute remote write roots. Empty denies writes even when allow_write is true.
	#[serde(default)]
	pub allowed_write_path_prefixes: Vec<String>,
	#[serde(default)]
	pub protected_path_prefixes: Vec<String>,
	#[serde(default)]
	pub protected_argument_substrings: Vec<String>,
	#[serde(default)]
	pub denied_executables: Vec<String>,
	#[serde(default)]
	pub allowed_dangerous_executables: Vec<String>,
	#[serde(default)]
	pub privileged_actions: BTreeMap<String, PrivilegedAction>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeConfig {
	#[serde(default = "default_state_dir")]
	pub state_dir: PathBuf,
	/// Absolute roots exposed through the inherited Octofs local file tools.
	/// Empty denies local file access while runtime mode is enabled.
	#[serde(default)]
	pub controller_workspace_roots: Vec<PathBuf>,
	#[serde(default)]
	pub hosts: BTreeMap<String, HostConfig>,
	/// Named administrator-owned model workers; absent disables all weight tools.
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub weight_workers: BTreeMap<String, crate::mcp::weight_config::WeightWorkerProfile>,
	/// Fixed read-only static analyzers, pinned by executable, version and SHA-256.
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub rea_static_profiles: BTreeMap<String, crate::mcp::rea_provider::ReaStaticProfile>,
	/// Pinned HIA installation and private operator artifact namespace; absent disables HIA.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub hia_worker: Option<crate::mcp::hia_provider::HiaWorkerProfile>,
}

fn default_state_dir() -> PathBuf {
	if let Some(path) = std::env::var_os("HEPTA_RUNTIME_STATE_DIR") {
		return PathBuf::from(path);
	}
	if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
		return PathBuf::from(path).join("hepta-runtime");
	}
	std::env::var_os("HOME")
		.map(PathBuf::from)
		.unwrap_or_else(std::env::temp_dir)
		.join(".local/state/hepta-runtime")
}

impl RuntimeConfig {
	pub fn load(path: &Path) -> Result<Self> {
		let bytes = std::fs::read(path)
			.with_context(|| format!("failed to read runtime config {}", path.display()))?;
		let config: Self = serde_json::from_slice(&bytes)
			.with_context(|| format!("invalid runtime config JSON {}", path.display()))?;
		config.validate()?;
		Ok(config)
	}

	pub fn validate(&self) -> Result<()> {
		if !self.state_dir.is_absolute() {
			bail!("controller state directory must be absolute");
		}
		if self.hosts.is_empty() {
			bail!("runtime config must declare at least one host");
		}
		for root in &self.controller_workspace_roots {
			if !root.is_absolute() {
				bail!(
					"controller workspace root `{}` must be absolute",
					root.display()
				);
			}
		}
		for (name, host) in &self.hosts {
			match (&host.checkpoint_binary, &host.checkpoint_binary_sha256) {
				(None, None) => {}
				(Some(binary), Some(sha)) => {
					if host.execution_mode != ExecutionMode::Operator
						|| host.platform != Platform::Linux
						|| !host.allow_execute
					{
						bail!("checkpoint pin requires an executable Linux operator host `{name}`");
					}
					if !Path::new(binary).is_absolute()
						|| binary.contains(['\0', '\n', '\r'])
						|| Path::new(binary)
							.components()
							.any(|c| matches!(c, Component::ParentDir))
						|| sha.len() != 64 || !sha
						.bytes()
						.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
					{
						bail!("invalid checkpoint executable or SHA256 on `{name}`");
					}
				}
				_ => bail!("checkpoint executable and SHA256 must be paired on `{name}`"),
			}
			if host.execution_mode == ExecutionMode::Operator {
				if !host.protected_path_prefixes.is_empty()
					|| !host.protected_argument_substrings.is_empty()
					|| !host.denied_executables.is_empty()
					|| !host.allowed_cwd_prefixes.is_empty()
					|| !host.allowed_dangerous_executables.is_empty()
				{
					bail!("operator host `{name}` cannot claim command/path sandboxing; use isolated mode or OS permissions");
				}
				if (host.allow_execute || host.allow_pty) && !host.allow_job_network {
					bail!("operator host `{name}` requires explicit allow_job_network=true");
				}
			}
			if !valid_name(name) {
				bail!("invalid host name `{name}`; use letters, digits, dot, underscore or dash");
			}
			if host.ssh_target.trim().is_empty()
				|| host.ssh_target.starts_with('-')
				|| host.ssh_target.contains(['\0', '\n', '\r'])
			{
				bail!("host `{name}` has an invalid ssh_target");
			}
			if host.allow_execute || host.allow_pty {
				let state = Path::new(&host.remote_state_dir);
				if !state.is_absolute() {
					bail!("host `{name}` remote_state_dir must be absolute");
				}
			}
			if host.platform == Platform::Macos && host.allow_execute {
				if !host.allow_detached_fallback {
					bail!("macOS host `{name}` requires allow_detached_fallback for durable jobs");
				}
				if !host.allow_job_network {
					bail!("macOS host `{name}` cannot enforce the Linux private-network sandbox; allow_job_network must be true");
				}
			}
			for prefix in host
				.allowed_cwd_prefixes
				.iter()
				.chain(host.allowed_read_path_prefixes.iter())
				.chain(host.allowed_write_path_prefixes.iter())
				.chain(host.protected_path_prefixes.iter())
			{
				if !Path::new(prefix).is_absolute() {
					bail!("host `{name}` path policy prefix `{prefix}` must be absolute");
				}
			}
			for (action_name, action) in &host.privileged_actions {
				if !valid_name(action_name) || !Path::new(&action.executable).is_absolute() {
					bail!("host `{name}` has invalid privileged action `{action_name}`");
				}
				if action.timeout_seconds == 0 || action.timeout_seconds > 300 {
					bail!("host `{name}` privileged action `{action_name}` timeout must be 1..300 seconds");
				}
				if action.allow_extra_args == action.extra_arg_patterns.is_empty() {
					bail!("host `{name}` privileged action `{action_name}` must pair allow_extra_args with explicit extra_arg_patterns");
				}
				if action.extra_arg_patterns.len() > 32 {
					bail!("host `{name}` privileged action `{action_name}` has too many argument patterns");
				}
				for pattern in &action.extra_arg_patterns {
					Regex::new(&format!(r"\A(?:{pattern})\z")).with_context(|| {
						format!("host `{name}` privileged action `{action_name}` has invalid argument regex")
					})?;
				}
			}
		}
		crate::mcp::weight_config::validate_profiles(self)?;
		crate::mcp::rea_provider::validate_profiles(self)?;
		crate::mcp::hia_provider::validate_profile(self)?;
		Ok(())
	}

	pub fn host(&self, name: &str) -> Result<&HostConfig> {
		self.hosts
			.get(name)
			.ok_or_else(|| anyhow!("unknown host `{name}`; call host_list for configured names"))
	}

	pub fn host_by_alias(&self, alias: &str) -> Option<(&str, &HostConfig)> {
		self.hosts
			.iter()
			.find(|(name, host)| name.as_str() == alias || host.ssh_target == alias)
			.map(|(name, host)| (name.as_str(), host))
	}
}

pub fn runtime_config() -> Result<&'static RuntimeConfig> {
	RUNTIME_CONFIG
		.get()
		.map(|installed| &installed.config)
		.ok_or_else(|| anyhow!("runtime tools are disabled; start with --runtime-config <file>"))
}

pub fn maybe_runtime_config() -> Option<&'static RuntimeConfig> {
	RUNTIME_CONFIG.get().map(|installed| &installed.config)
}

pub fn valid_name(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 128
		&& value
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
}

fn remote_path_allowed(path: &str, prefixes: &[String]) -> bool {
	prefixes.iter().any(|prefix| {
		path == prefix || path.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
	})
}

pub fn check_remote_path(
	alias: &str,
	path: &str,
	user_explicit: bool,
	port_explicit: bool,
	write: bool,
) -> Result<()> {
	let Some(config) = maybe_runtime_config() else {
		return Ok(());
	};
	let Some((name, host)) = config.host_by_alias(alias) else {
		bail!("remote file access to unregistered SSH host `{alias}` is disabled");
	};
	if user_explicit || port_explicit {
		bail!(
			"remote file access must use the registered SSH alias without user or port overrides"
		);
	}
	if !path.starts_with('/') || path == "/~" || path.starts_with("/~/") {
		bail!("remote file access requires an absolute target path");
	}
	if path.split('/').any(|component| component == "..") {
		bail!("remote path traversal is not allowed");
	}
	if let Some(prefix) = host
		.protected_path_prefixes
		.iter()
		.find(|prefix| remote_path_allowed(path, std::slice::from_ref(prefix)))
	{
		bail!("path `{path}` is protected by prefix `{prefix}` on host `{name}`");
	}
	if write {
		if !host.allow_write {
			bail!("remote writes are disabled for host `{name}`");
		}
		if !remote_path_allowed(path, &host.allowed_write_path_prefixes) {
			bail!("path `{path}` is outside configured write roots on host `{name}`");
		}
	} else if !remote_path_allowed(path, &host.allowed_read_path_prefixes) {
		bail!("path `{path}` is outside configured read roots on host `{name}`");
	}
	Ok(())
}

pub fn install_fixture(value: serde_json::Value) -> Result<()> {
    if value.is_null() { return Ok(()); }
    let config: RuntimeConfig = serde_json::from_value(value)?;
    anyhow::ensure!(config.weight_workers.is_empty() && config.rea_static_profiles.is_empty()
        && config.hia_worker.is_none(), "private root fixture excludes worker provider values");
    config.validate()?;
    RUNTIME_CONFIG.set(InstalledRuntimeConfig { config })
        .map_err(|_| anyhow!("fixture configuration already installed"))?;
    Ok(())
}
