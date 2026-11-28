#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostConfig {
	/// Complete administrator-bound native job bundle; absence retains legacy configuration identity.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub native_jobs: Option<NativeJobEntries>,
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
#[serde(deny_unknown_fields)]
pub struct NativeJobEntries {
	pub entry: NativeJobPin,
	pub submit: NativeJobPin,
	pub observation: NativeJobPin,
	pub cancel: NativeJobPin,
	pub launcher: NativeJobPin,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeJobPin {
	pub executable: String,
	pub sha256: String,
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

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
	#[default]
	Isolated,
	/// Full authority of the configured SSH login, including its existing sudo rights.
	Operator,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
	#[default]
	Linux,
	Macos,
}

fn default_action_timeout() -> u64 {
	30
}

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

fn validate_execution(
	host_name: &str,
	host: &HostConfig,
	executable: &str,
	args: &[String],
	cwd: Option<&str>,
	pty: bool,
) -> Result<()> {
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
	if explicitly_denied
		|| (host.execution_mode == ExecutionMode::Isolated && dangerous && !explicitly_allowed)
	{
		bail!(
			"executable `{base}` is denied on host `{host_name}`; use a named privileged_action when configured"
		);
	}
	if cwd.is_none() && !host.allowed_cwd_prefixes.is_empty() {
		bail!("cwd is required when execution roots are configured for host `{host_name}`");
	}
	if let Some(cwd) = cwd {
		if cwd.contains('\0')
			|| !Path::new(cwd).is_absolute()
			|| Path::new(cwd)
				.components()
				.any(|c| matches!(c, Component::ParentDir))
		{
			bail!("cwd must be an absolute path");
		}
		if !host.allowed_cwd_prefixes.is_empty()
			&& !host.allowed_cwd_prefixes.iter().any(|prefix| {
				cwd == prefix || cwd.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
			}) {
			bail!("cwd `{cwd}` is outside configured execution roots on host `{host_name}`");
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
	Ok(())
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

pub fn check_environment(host_name: &str, host: &HostConfig, env: &BTreeMap<String, String>) -> Result<()> {
	for (key, value) in env {
		if value.contains('\0') {
			bail!("environment values may not contain NUL bytes");
		}
		if host.execution_mode == ExecutionMode::Isolated && DANGEROUS_ENV.contains(&key.as_str()) {
			bail!("environment variable `{key}` is denied on host `{host_name}`");
		}
		if let Some(prefix) = protected_value(host, value) {
			bail!("environment value intersects protected value `{prefix}` on host `{host_name}`");
		}
	}
	Ok(())
}

fn validate_start(params: &ProcessStartParams, host: &HostConfig) -> Result<()> {
	match params.idempotency_key.as_deref() {
		Some(key) if !key.trim().is_empty() && key.len() <= 256 => {}
		_ => bail!("idempotency_key is mandatory and must contain 1..256 nonblank bytes"),
	}
	validate_execution(
		&params.host,
		host,
		&params.executable,
		&params.args,
		params.cwd.as_deref(),
		false,
	)?;
	check_environment(&params.host, host, &params.env)?;
	if params.args.len() > 256 {
		bail!("at most 256 arguments are allowed");
	}
	if params.env.len() > 128 {
		bail!("at most 128 environment variables are allowed");
	}
	for key in params.env.keys() {
		let valid = !key.is_empty()
			&& !key.as_bytes()[0].is_ascii_digit()
			&& key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
		if !valid {
			bail!("invalid environment variable name `{key}`");
		}
	}
	if params
		.stdin
		.as_ref()
		.is_some_and(|value| value.len() > MAX_STDIN_BYTES)
	{
		bail!("stdin exceeds the 1 MiB limit");
	}
	if params
		.timeout_seconds
		.is_some_and(|value| value == 0 || value > 604_800)
	{
		bail!("timeout_seconds must be between 1 and 604800");
	}
	if params.nice.is_some_and(|value| value > 19) {
		bail!("nice must be between 0 and 19");
	}
	if params
		.cpu_quota_percent
		.is_some_and(|value| value == 0 || value > 1000)
	{
		bail!("cpu_quota_percent must be between 1 and 1000");
	}
	if params
		.memory_max_bytes
		.is_some_and(|value| value < 16 * 1024 * 1024)
	{
		bail!("memory_max_bytes must be at least 16 MiB");
	}
	if params
		.idempotency_key
		.as_ref()
		.is_some_and(|value| value.is_empty() || value.len() > 256)
	{
		bail!("idempotency_key must contain 1..256 bytes");
	}
	Ok(())
}

fn validate_new_host_resource_limits(
	platform: Platform,
	params: &ProcessStartParams,
) -> Result<()> {
	if platform == Platform::Macos
		&& (params.cpu_quota_percent.is_some() || params.memory_max_bytes.is_some())
	{
		bail!(
			"macOS detached job backend cannot enforce requested CPU/memory limits;              no new job identity allocated or remote launch submitted"
		);
	}
	Ok(())
}

fn key_only(params: &ProcessStartParams) -> Result<()> {
	match params.idempotency_key.as_deref() {
		Some(key) if !key.trim().is_empty() && key.len() <= 256 => {}
		_ => bail!("idempotency_key is mandatory and must contain 1..256 nonblank bytes"),
	}
	Ok(())
}

fn operator_host<'a>(name: &str, host: &'a HostConfig) -> Result<&'a HostConfig> {
	if host.execution_mode != ExecutionMode::Operator {
		bail!(
			"host `{name}` is isolated; operator authority must be configured by its administrator"
		);
	}
	Ok(host)
}

fn shell_start_prefix(params: ShellStartParams, host: &HostConfig) -> Result<()> {
	operator_host(&params.host, host)?;
	if params.command.len() > 65536 || params.command.contains('\0') {
		bail!("shell source must not contain NUL and is limited to 64 KiB");
	}
	Ok(())
}

const MAX_STDIN_BYTES: usize = 1024 * 1024;

const MAX_LOG_READ_BYTES: u64 = 16 * 1024;

fn page_prefix(params: &ProcessListPageParams) -> Result<usize> {
	let limit = params.limit.unwrap_or(128) as usize;
	if !(1..=128).contains(&limit)
		|| params
			.cursor
			.as_ref()
			.is_some_and(|cursor| cursor.len() > 256)
	{
		bail!("invalid durable job inventory page");
	}
	Ok(limit)
}
