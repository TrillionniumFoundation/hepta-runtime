// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
mod config_identity {
use serde::Serialize;
#[derive(Clone, Serialize)]
pub(super) struct LoadProvenance {
	byte_len: usize,
	sha256: String,
}

}
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
struct InstalledRuntimeConfig {
	config: RuntimeConfig,
	load_provenance: Option<config_identity::LoadProvenance>,
	#[cfg(any(target_os = "linux", test))]
	policy_digest: OnceLock<std::result::Result<[u8; 32], serde_json::Error>>,
}

impl InstalledRuntimeConfig {
	fn new(config: RuntimeConfig) -> Self {
		Self {
			config,
			load_provenance: None,
			#[cfg(any(target_os = "linux", test))]
			policy_digest: OnceLock::new(),
		}
	}

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

pub fn runtime_config() -> Result<&'static RuntimeConfig> {
	RUNTIME_CONFIG
		.get()
		.map(|installed| &installed.config)
		.ok_or_else(|| anyhow!("runtime tools are disabled; start with --runtime-config <file>"))
}

pub fn maybe_runtime_config() -> Option<&'static RuntimeConfig> {
	RUNTIME_CONFIG.get().map(|installed| &installed.config)
}

fn canonical_policy_path(path: &Path) -> Result<PathBuf> {
	if !path.is_absolute() {
		bail!("path `{}` must be absolute", path.display());
	}
	// Resolve the spelling that the subsequent filesystem operation will use.
	// Lexically collapsing `link/..` before resolving `link` can authorize an
	// in-root name while the kernel opens a different, out-of-root inode.
	let mut probe = path;
	let mut suffix: Vec<OsString> = Vec::new();
	loop {
		match std::fs::symlink_metadata(probe) {
			Ok(_) => break,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => {
				return Err(error)
					.with_context(|| format!("failed to inspect `{}`", probe.display()));
			}
		}
		// Only absent normal components can be appended to an existing physical
		// ancestor. A dangling symlink is an existing entry and must reach the
		// canonicalize call below, which rejects its unresolved target.
		let name = probe
			.file_name()
			.ok_or_else(|| anyhow!("no existing ancestor for `{}`", path.display()))?;
		suffix.push(name.to_os_string());
		probe = probe
			.parent()
			.ok_or_else(|| anyhow!("no existing ancestor for `{}`", path.display()))?;
	}
	let mut canonical = std::fs::canonicalize(probe)
		.with_context(|| format!("failed to canonicalize `{}`", probe.display()))?;
	for part in suffix.iter().rev() {
		canonical.push(part);
	}
	Ok(canonical)
}

fn path_under(candidate: &Path, root: &Path) -> bool {
	candidate == root || candidate.starts_with(root)
}

pub fn check_local_path(path: &Path) -> Result<()> {
	let Some(config) = maybe_runtime_config() else {
		return Ok(());
	};
	if config.controller_workspace_roots.is_empty() {
		bail!("local file tools are disabled in runtime mode");
	}
	let candidate = canonical_policy_path(path)?;
	for root in &config.controller_workspace_roots {
		let root = std::fs::canonicalize(root).with_context(|| {
			format!(
				"configured controller workspace `{}` is unavailable",
				root.display()
			)
		})?;
		if path_under(&candidate, &root) {
			return Ok(());
		}
	}
	bail!(
		"local path `{}` is outside configured controller workspaces",
		candidate.display()
	)
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

impl RuntimeConfig {
	pub fn host_by_alias(&self, alias: &str) -> Option<(&str, &HostConfig)> {
		self.hosts
			.iter()
			.find(|(name, host)| name.as_str() == alias || host.ssh_target == alias)
			.map(|(name, host)| (name.as_str(), host))
	}

}

pub fn install_for_reference(config: RuntimeConfig) {
    assert!(config.weight_workers.is_empty() && config.rea_static_profiles.is_empty() && config.hia_worker.is_none());
    assert!(RUNTIME_CONFIG.set(InstalledRuntimeConfig::new(config)).is_ok());
}
