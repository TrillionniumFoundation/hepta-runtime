// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

impl OctofsServer {
	async fn text_editor(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<TextEditorParams>,
	) -> Result<String, String> {
		// Optional cross-process new-effect admission. Must be configured on
		// every controller and ingress before any owner transfer is eligible.
		let _owner_admission = runtime::effect_owner_fence::admit_new_effect()
			.await
			.map_err(|error| error.to_string())?;

		self.ensure_session_workdir(&context);
		let workdir = self.workdir.get_current();
		enforce_runtime_path_spec(&params.path, &workdir, true)?;
		let call = McpToolCall {
			tool_name: "text_editor".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		request_ctx::with_request_context(self.view_cache.clone(), async move {
			let result = fs::execute_text_editor(&call)
				.await
				.map_err(|e| e.to_string())?;
			Ok(append_hints(result))
		})
		.await
	}

	fn ensure_session_workdir(&self, context: &RequestContext<RoleServer>) {
		if self
			.session_applied
			.swap(true, std::sync::atomic::Ordering::SeqCst)
		{
			return;
		}
		let Some(capabilities) = context.client_capabilities() else {
			return;
		};
		let Some(experimental) = &capabilities.experimental else {
			return;
		};
		if let Some(session_obj) = experimental.get("session") {
			if let Some(workdir_str) = session_obj.get("workdir").and_then(|v| v.as_str()) {
				let path = std::path::PathBuf::from(workdir_str);
				let policy_allows = runtime::config::maybe_runtime_config().is_none()
					|| runtime::config::check_local_path(&path).is_ok();
				if path.is_absolute() && path.is_dir() && policy_allows {
					self.workdir.set_current(path.clone());
					debug!("Session workdir set from capabilities: {}", path.display());
				} else {
					debug!(
						"Session workdir '{}' is not an absolute directory path, ignoring",
						workdir_str
					);
				}
			}
		}
	}

}

fn enforce_runtime_path_spec(
	path_spec: &str,
	workdir: &std::path::Path,
	write: bool,
) -> Result<(), String> {
	if runtime::config::maybe_runtime_config().is_none() {
		return Ok(());
	}
	if path_spec.starts_with("octofs://") {
		return Err("Octofs background resources are disabled in runtime mode".to_string());
	}
	for raw in path_spec.split('|') {
		let raw = raw.trim();
		if raw.is_empty() {
			return Err("path must not contain an empty root".to_string());
		}
		match fs::remote::resolve_path_source(raw, workdir) {
			fs::PathSource::Local(path) => {
				runtime::config::check_local_path(&path).map_err(|error| error.to_string())?;
			}
			fs::PathSource::Remote {
				host,
				path,
				user_explicit,
				port_explicit,
				..
			} => {
				runtime::config::check_remote_path(
					&host,
					&path,
					user_explicit,
					port_explicit,
					write,
				)
				.map_err(|error| error.to_string())?;
			}
		}
	}
	Ok(())
}


fn append_hints(mut result: String) -> String {
	let hints = request_ctx::drain_hints();
	if !hints.is_empty() {
		result.push_str("\n\n");
		for hint in hints {
			result.push_str("⚠️ ");
			result.push_str(&hint);
			result.push('\n');
		}
	}
	result
}

