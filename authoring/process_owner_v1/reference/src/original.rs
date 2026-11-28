#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellStartParams {
	pub host: String,
	/// Shell source, including pipelines, redirects and compound commands.
	pub command: String,
	/// Absolute shell executable; defaults to /bin/sh.
	#[serde(default)]
	pub shell: Option<String>,
	#[serde(default)]
	pub cwd: Option<String>,
	#[serde(default)]
	pub env: BTreeMap<String, String>,
	#[serde(default)]
	pub timeout_seconds: Option<u64>,
	#[serde(default)]
	pub idempotency_key: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartParams {
	/// Configured host name, never a raw SSH destination.
	pub host: String,
	/// Executable path or command name. Shell syntax is not accepted.
	pub executable: String,
	#[serde(default)]
	pub args: Vec<String>,
	#[serde(default)]
	pub cwd: Option<String>,
	#[serde(default)]
	pub env: BTreeMap<String, String>,
	/// Optional standard input written once at process start (max 1 MiB).
	#[serde(default)]
	pub stdin: Option<String>,
	/// Optional process timeout. The remote supervisor terminates the process group.
	#[serde(default)]
	pub timeout_seconds: Option<u64>,
	/// Mandatory stable operation key; exact retries reconcile the original durable job.
	#[schemars(required)]
	pub idempotency_key: Option<String>,
	/// Non-negative Unix nice adjustment, 0..19.
	#[serde(default)]
	pub nice: Option<u8>,
	/// Optional transient systemd CPUQuota percentage, 1..1000.
	#[serde(default)]
	pub cpu_quota_percent: Option<u16>,
	/// Optional transient systemd MemoryMax in bytes.
	#[serde(default)]
	pub memory_max_bytes: Option<u64>,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessRefParams {
	pub host: String,
	pub job_id: String,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessReadParams {
	pub host: String,
	pub job_id: String,
	#[serde(default)]
	pub stdout_offset: Option<u64>,
	#[serde(default)]
	pub stderr_offset: Option<u64>,
	/// Maximum bytes returned per stream, capped at 16 KiB with lossless byte cursors.
	#[serde(default)]
	pub limit: Option<u64>,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessWaitParams {
	pub host: String,
	pub job_id: String,
	/// Maximum wait for this call, capped at 30 seconds.
	#[serde(default)]
	pub timeout_seconds: Option<u64>,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessCancelParams {
	pub host: String,
	pub job_id: String,
	/// Grace period before the fallback backend sends SIGKILL, capped at 30 seconds.
	#[serde(default)]
	pub grace_seconds: Option<u64>,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessListParams {
	#[serde(default)]
	pub host: Option<String>,
}
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessListPageParams {
	#[serde(default)]
	pub host: Option<String>,
	/// Opaque controller-local snapshot cursor. Changes, expiry or restart require a fresh first page.
	#[serde(default)]
	pub cursor: Option<String>,
	/// At most 128 identities per page, additionally bounded to a 64 KiB wire response.
	#[serde(default)]
	pub limit: Option<u16>,
}
