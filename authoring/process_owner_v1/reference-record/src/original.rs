#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
	#[default]
	Isolated,
	/// Full authority of the configured SSH login, including its existing sudo rights.
	Operator,
}

macro_rules! job_record_schema {
	($name:ident $(<$parameter:ident>)?, $text:ident $(, $attribute:meta)?) => {
		#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
		$(#[$attribute])?
		struct $name $(<$parameter>)? {
			#[serde(default)]
			execution_mode: ExecutionMode,
			#[serde(default)]
			system_jobctl: bool,
			id: String,
			host: String,
			ssh_target: $text,
			unit: $text,
			remote_job_dir: $text,
			executable: $text,
			args: Vec<$text>,
			cwd: Option<$text>,
			env_keys: Vec<$text>,
			created_unix_ms: u128,
			idempotency_key: Option<String>,
			request_fingerprint: u64,
			#[serde(default)]
			request_digest: Option<$text>,
			#[serde(default = "default_launch_state")]
			launch_state: String,
			#[serde(default)]
			launch_error: Option<$text>,
		}

	};
}

job_record_schema!(JobRecord, String);

fn default_launch_state() -> String {
	"launched".to_string()
}
