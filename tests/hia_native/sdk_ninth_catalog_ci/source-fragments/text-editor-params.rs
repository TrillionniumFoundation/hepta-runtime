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
