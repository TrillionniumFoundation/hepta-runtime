	#[tool(
		title = "Extract Lines",
		annotations(
			read_only_hint = false,
			destructive_hint = false,
			idempotent_hint = false,
			open_world_hint = false
		),
		description = "Copy a line range from one file and append it into another without \
			retyping it — moving code between files, splitting modules. The source is left \
			untouched; to move, follow with a batch_edit that removes the range."
	)]
	async fn extract_lines(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<ExtractLinesParams>,
	) -> Result<String, String> {
		// Optional cross-process new-effect admission. Must be configured on
		// every controller and ingress before any owner transfer is eligible.
		let _owner_admission = runtime::effect_owner_fence::admit_new_effect()
			.await
			.map_err(|error| error.to_string())?;

		self.ensure_session_workdir(&context);
		let workdir = self.workdir.get_current();
		enforce_runtime_path_spec(&params.from_path, &workdir, false)?;
		enforce_runtime_path_spec(&params.append_path, &workdir, true)?;
		let call = McpToolCall {
			tool_name: "extract_lines".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		request_ctx::with_request_context(self.view_cache.clone(), async move {
			let result = fs::execute_extract_lines(&call)
				.await
				.map_err(|e| e.to_string())?;
			Ok(append_hints(result))
		})
		.await
	}
