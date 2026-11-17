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

// Exact target declarations; no filesystem implementation.
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


#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ViewParams {
	/// File or directory. `a|b` searches several roots with `content` (max 32); several
	/// files take parallel view calls. Remote: ssh://[user@]host[:port]/path (host may be an
	/// ~/.ssh/config alias; `ssh://host` or `ssh://host/~/dir` is the login home).
	pub path: String,
	/// First line (inclusive): line id or integer (negative counts from the end, -1 = last).
	/// Default: line 1.
	#[serde(default)]
	#[schemars(schema_with = "line_endpoint_schema")]
	pub start: Option<serde_json::Value>,
	/// Last line (inclusive): line id or integer (negative counts from the end). Default: end
	/// of file; omit both `start` and `end` for the whole file.
	#[serde(default)]
	#[schemars(schema_with = "line_endpoint_schema")]
	pub end: Option<serde_json::Value>,
	/// Ripgrep -g globs bounding listings and searches: without `/` a name at any depth,
	/// with `/` the relative path; `*`, `**`, `?`, `[abc]`, `{rs,toml}`, leading `!`; `|`
	/// joins ordered globs (later wins), e.g. `**/*.rs|!target/**`. Applied after
	/// gitignore/hidden filtering; one line, max 4096 bytes, 64 globs.
	#[serde(default)]
	pub pattern: Option<String>,
	/// Locate code: searches the whole file/tree (`start`/`end` ignored) for a literal
	/// substring, or a Rust regex with `regex: true` (`(?i)` case-insensitive; alternation for
	/// related terms).
	#[serde(default)]
	pub content: Option<String>,
	/// Treat `content` as a regex. Default: false.
	#[serde(default)]
	pub regex: Option<bool>,
	/// Directory depth bound. Default: unlimited, except a bare remote listing (no
	/// `pattern`/`content`) stops at the root entries. Searches walk the whole tree.
	#[serde(default)]
	pub max_depth: Option<usize>,
	/// Include dotfiles and dot-directories.
	#[serde(default)]
	pub include_hidden: Option<bool>,
	/// Lines around each `content` match. Default: 0.
	#[serde(default)]
	pub context: Option<usize>,
	/// Force the complete file when re-viewing a whole file (normally only changed hunks),
	/// e.g. after losing earlier context. No effect on ranges or searches; output limits
	/// unchanged.
	#[serde(default)]
	pub full: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExtractLinesParams {
	/// Source file (ssh://user@host:port/path for remote).
	pub from_path: String,
	/// First line to copy (inclusive): integer or line id (verified against the source).
	#[schemars(schema_with = "line_endpoint_schema")]
	pub from_start: serde_json::Value,
	/// Last line to copy (inclusive): integer or line id. Default: `from_start`.
	#[serde(default)]
	#[schemars(schema_with = "line_endpoint_schema")]
	pub from_end: Option<serde_json::Value>,
	/// Target file the lines are appended to (ssh://user@host:port/path for remote).
	pub append_path: String,
	/// Where to append in the target: 0 = beginning, -1 = end, N = after line N, or a line
	/// id (verified against the target).
	#[schemars(schema_with = "line_endpoint_schema")]
	pub append_line: serde_json::Value,
}
