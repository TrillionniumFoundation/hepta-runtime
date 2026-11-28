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

// MCP schemas, tool routing and the shared runtime request-audit boundary.

// MCP server handlers, session state, and tool parameter schemas.


#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TextEditorCommand {
	Create,
	StrReplace,
	Delete,
	UndoEdit,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TextEditorParams {
	/// Operation to perform.
	pub command: TextEditorCommand,
	/// File path (ssh://user@host:port/path for remote).
	pub path: String,
	/// Content for `create`.
	#[serde(default)]
	pub content: Option<String>,
	/// `str_replace`: exact text to find (required).
	#[serde(default)]
	pub old_text: Option<String>,
	/// `str_replace`: replacement text (required).
	#[serde(default)]
	pub new_text: Option<String>,
	/// `str_replace`: replace every occurrence (rename-style). Default: false.
	#[serde(default)]
	pub replace_all: Option<bool>,
}

#[derive(Clone)]
struct MetadataOnlyServer;
impl MetadataOnlyServer {
	#[tool(
		title = "Text Editor",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		),
		description = "File operations. create: new file only — fails if it exists, parent \
			directories are made. str_replace: raw file text (real newlines, no `N:hh|` \
			prefixes); old_text must match exactly once, or set replace_all: true — on no or \
			multiple matches the error lists candidate line ids for batch_edit. delete: remove a \
			file (not a directory). undo_edit: revert the last edit to `path` (10 levels, delete \
			included). Prefer batch_edit when you already hold line ids."
	)]
	async fn text_editor(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<TextEditorParams>,
	) -> Result<String, String> {
        let _ = (context, params);
        panic!("metadata-only fixture: original filesystem method must never execute")
    }
}
impl rmcp::ServerHandler for MetadataOnlyServer {}
