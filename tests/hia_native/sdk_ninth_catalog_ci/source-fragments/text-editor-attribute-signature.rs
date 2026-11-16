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
