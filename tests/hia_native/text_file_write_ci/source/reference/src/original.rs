// Copyright 2026 Muvon Un Limited
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

// Exact current-target typed declarations, extracted without edits.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TextFileWriteMode {
	Create,
	Replace,
	Append,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TextFileWriteParams {
	/// Controller-local target path under an explicitly configured workspace.
	pub path: String,
	/// Explicit create, replace or append semantics.
	pub mode: TextFileWriteMode,
	/// UTF-8 input up to 64 KiB. Repeated unknown-outcome writes must not be blindly retried.
	pub content: String,
	/// 'absent' for create; lowercase 64-hex original SHA256 for replace or append.
	pub expected_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DirectoryCreateParams {
	/// Directory path in the configured local controller workspace. Remote paths are refused.
	pub path: String,
}
