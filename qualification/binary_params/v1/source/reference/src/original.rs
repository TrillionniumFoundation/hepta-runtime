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

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InodeAction {
	Apply,
	Status,
	Recover,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InodePatchParams {
	pub host: String,
	pub path: String,
	pub action: InodeAction,
	pub transaction_id: String,
	pub acknowledge_non_atomic: bool,
	#[serde(default)]
	pub preserve_special_bits: bool,
	#[serde(default)]
	pub offset: Option<u64>,
	#[serde(default)]
	pub expected_version: Option<String>,
	#[serde(default)]
	pub expected_sha256: Option<String>,
	#[serde(default)]
	pub data_base64: Option<String>,
}
