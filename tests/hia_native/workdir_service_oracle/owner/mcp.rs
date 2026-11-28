pub mod runtime;
pub mod weight_config;
pub mod rea_provider;
pub mod hia_provider;
pub mod hia_contract;

pub mod fs;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
	pub tool_name: String,
	pub parameters: Value,
	#[serde(default)]
	pub tool_id: String,
	/// Per-session working directory for this call.
	pub workdir: PathBuf,
}
