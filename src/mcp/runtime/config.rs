use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

static RUNTIME_CONFIG: OnceLock<RuntimeConfig> = OnceLock::new();

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
	#[default]
	Linux,
	Macos,
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
				if !Path::new(prefix).is_absolute()
					|| Path::new(prefix)
						.components()
						.any(|part| matches!(part, Component::ParentDir))
				{
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

pub fn init_runtime(config: RuntimeConfig) -> Result<()> {
	config.validate()?;
	std::fs::create_dir_all(config.state_dir.join("jobs"))?;
	std::fs::create_dir_all(config.state_dir.join("audit"))?;
	RUNTIME_CONFIG
		.set(config)
		.map_err(|_| anyhow!("runtime config was already initialized"))
}

pub fn runtime_config() -> Result<&'static RuntimeConfig> {
	RUNTIME_CONFIG
		.get()
		.ok_or_else(|| anyhow!("runtime tools are disabled; start with --runtime-config <file>"))
}

pub fn maybe_runtime_config() -> Option<&'static RuntimeConfig> {
	RUNTIME_CONFIG.get()
}

pub fn valid_name(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 128
		&& value
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
}

const DEFAULT_DANGEROUS: &[&str] = &[
	"sudo",
	"su",
	"doas",
	"sh",
	"bash",
	"dash",
	"zsh",
	"fish",
	"ksh",
	"ssh",
	"scp",
	"sftp",
	"nohup",
	"setsid",
	"tmux",
	"screen",
	"systemd-run",
	"crontab",
	"at",
	"nsenter",
	"unshare",
	"kill",
	"pkill",
	"killall",
	"systemctl",
	"service",
	"loginctl",
	"reboot",
	"shutdown",
	"poweroff",
	"halt",
	"init",
	"mount",
	"umount",
	"modprobe",
	"insmod",
	"rmmod",
	"apt",
	"apt-get",
	"dpkg",
	"rpm",
	"dnf",
	"yum",
	"snap",
	"docker",
	"podman",
	"virsh",
	"nft",
	"iptables",
	"ip6tables",
];

fn executable_basename(executable: &str) -> &str {
	executable.rsplit('/').next().unwrap_or(executable)
}

fn protected_value(host: &HostConfig, value: &str) -> Option<String> {
	host.protected_path_prefixes
		.iter()
		.chain(host.protected_argument_substrings.iter())
		.find(|prefix| !prefix.is_empty() && value.contains(prefix.as_str()))
		.cloned()
}

const DANGEROUS_ENV: &[&str] = &[
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	"PYTHONPATH",
	"PYTHONHOME",
	"NODE_OPTIONS",
	"BASH_ENV",
	"ENV",
	"PERL5OPT",
	"RUBYOPT",
	"GIT_SSH",
	"GIT_SSH_COMMAND",
	"SSH_ASKPASS",
	"SUDO_ASKPASS",
];

pub fn check_environment(host_name: &str, env: &BTreeMap<String, String>) -> Result<()> {
	let host = runtime_config()?.host(host_name)?;
	for (key, value) in env {
		if DANGEROUS_ENV.contains(&key.as_str()) {
			bail!("environment variable `{key}` is denied on host `{host_name}`");
		}
		if let Some(prefix) = protected_value(host, value) {
			bail!("environment value intersects protected value `{prefix}` on host `{host_name}`");
		}
	}
	Ok(())
}

pub fn check_protected_input(host_name: &str, value: &str) -> Result<()> {
	let host = runtime_config()?.host(host_name)?;
	if let Some(prefix) = protected_value(host, value) {
		bail!("value intersects protected value `{prefix}` on host `{host_name}`");
	}
	Ok(())
}

/// Reject lexical escapes before the allowlist prefix match. The remote
/// execution boundary must independently validate symlink resolution.
fn execution_cwd_allowed(cwd: &str, roots: &[String]) -> bool {
	let path = Path::new(cwd);
	path.is_absolute()
		&& !path
			.components()
			.any(|part| matches!(part, Component::ParentDir))
		&& (roots.is_empty()
			|| roots.iter().any(|prefix| {
				cwd == prefix || cwd.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
			}))
}

pub fn check_execution(
	host_name: &str,
	executable: &str,
	args: &[String],
	cwd: Option<&str>,
	pty: bool,
) -> Result<&'static HostConfig> {
	let config = runtime_config()?;
	let host = config.host(host_name)?;
	if pty && !host.allow_pty {
		bail!("PTY execution is disabled for host `{host_name}`");
	}
	if !pty && !host.allow_execute {
		bail!("process execution is disabled for host `{host_name}`");
	}
	if executable.trim().is_empty() || executable.contains('\0') {
		bail!("executable must be a non-empty absolute path");
	}
	let executable_path = Path::new(executable);
	if !executable_path.is_absolute()
		|| executable_path
			.components()
			.any(|part| matches!(part, Component::ParentDir))
	{
		bail!("executable `{executable}` must be an absolute path without parent traversal");
	}
	if let Some(prefix) = protected_value(host, executable) {
		bail!("executable intersects protected value `{prefix}` on host `{host_name}`");
	}
	let base = executable_basename(executable);
	let explicitly_denied = host
		.denied_executables
		.iter()
		.any(|x| x == base || x == executable);
	let dangerous = DEFAULT_DANGEROUS.contains(&base);
	let explicitly_allowed = host
		.allowed_dangerous_executables
		.iter()
		.any(|x| x == base || x == executable);
	if explicitly_denied || (dangerous && !explicitly_allowed) {
		bail!(
            "executable `{base}` is denied on host `{host_name}`; use a named privileged_action when configured"
        );
	}
	if let Some(cwd) = cwd {
		if !execution_cwd_allowed(cwd, &host.allowed_cwd_prefixes) {
			bail!("cwd `{cwd}` is outside configured execution roots or contains parent traversal on host `{host_name}`");
		}
		if let Some(prefix) = protected_value(host, cwd) {
			bail!("cwd intersects protected value `{prefix}` on host `{host_name}`");
		}
	}
	for arg in args {
		if arg.contains('\0') {
			bail!("arguments may not contain NUL bytes");
		}
		if let Some(prefix) = protected_value(host, arg) {
			bail!("argument intersects protected value `{prefix}` on host `{host_name}`");
		}
	}
	Ok(host)
}

fn normalize_absolute(path: &Path) -> Result<PathBuf> {
	if !path.is_absolute() {
		bail!("path `{}` must be absolute", path.display());
	}
	let mut normalized = PathBuf::from("/");
	for component in path.components() {
		match component {
			Component::RootDir => normalized = PathBuf::from("/"),
			Component::CurDir => {}
			Component::ParentDir => {
				if !normalized.pop() {
					bail!("path `{}` escapes the filesystem root", path.display());
				}
			}
			Component::Normal(part) => normalized.push(part),
			Component::Prefix(_) => bail!("Windows path prefixes are not accepted here"),
		}
	}
	Ok(normalized)
}

fn canonical_policy_path(path: &Path) -> Result<PathBuf> {
	let normalized = normalize_absolute(path)?;
	let mut probe = normalized.as_path();
	let mut suffix: Vec<OsString> = Vec::new();
	while !probe.exists() {
		let name = probe
			.file_name()
			.ok_or_else(|| anyhow!("no existing ancestor for `{}`", normalized.display()))?;
		suffix.push(name.to_os_string());
		probe = probe
			.parent()
			.ok_or_else(|| anyhow!("no existing ancestor for `{}`", normalized.display()))?;
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

pub fn check_remote_write(alias: &str, path: &str) -> Result<()> {
	check_remote_path(alias, path, false, false, true)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn remote_workdir_policy_rejects_lexical_escape_and_nearby_prefixes() {
		let roots = vec!["/srv/project".to_owned()];
		assert!(execution_cwd_allowed("/srv/project", &roots));
		assert!(execution_cwd_allowed("/srv/project/src", &roots));
		assert!(!execution_cwd_allowed("/srv/project/../secret", &roots));
		assert!(!execution_cwd_allowed("/srv/project/src/../../private", &roots));
		assert!(!execution_cwd_allowed("/srv/project-other", &roots));
		assert!(!execution_cwd_allowed("srv/project", &roots));
		assert!(!execution_cwd_allowed("/srv/../etc", &[]));
	}

	#[test]
	fn configured_remote_roots_reject_parent_traversal() {
		let config: RuntimeConfig = serde_json::from_value(serde_json::json!({
			"hosts": {
				"build": {
					"ssh_target": "build",
					"allowed_cwd_prefixes": ["/srv/project/../private"]
				}
			}
		}))
		.expect("config fixture");
		assert!(config.validate().is_err());
	}

	#[test]
	fn names_are_strict() {
		assert!(valid_name("rog-1.example"));
		assert!(!valid_name("rog/1"));
		assert!(!valid_name(&"-".repeat(129)));
	}

	#[test]
	fn basename_is_stable() {
		assert_eq!(executable_basename("/usr/bin/systemctl"), "systemctl");
		assert_eq!(executable_basename("python3"), "python3");
	}

	#[test]
	fn privileged_regexes_are_full_match_capable() {
		let regex = Regex::new(r"\A(?:[a-z0-9_-]+)\z").unwrap();
		assert!(regex.is_match("profile-1"));
		assert!(!regex.is_match("profile-1;id"));
	}
}
