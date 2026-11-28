// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Qualification-only reference carrier; original extracted bodies remain unchanged.
pub mod runtime;
pub mod weight_config;
pub mod rea_provider;
pub mod hia_provider;
pub mod hia_contract;

pub mod fs;
pub mod request_ctx;
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
