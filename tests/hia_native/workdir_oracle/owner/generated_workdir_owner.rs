// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact unchanged public workdir method, schema and path preflight.
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

impl OctofsServer {
	async fn workdir(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<WorkdirParams>,
	) -> Result<String, String> {
		self.ensure_session_workdir(&context);
		let workdir = self.workdir.get_current();
		if !params.reset.unwrap_or(false) {
			if let Some(path) = params.path.as_deref() {
				enforce_runtime_path_spec(path, &workdir, false)?;
			}
		}
		let call = McpToolCall {
			tool_name: "workdir".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		let result = fs::execute_workdir_command(&call)
			.await
			.map_err(|e| e.to_string())?;

		// Update session workdir state based on the structured result
		match &result {
			fs::WorkdirResult::Set { current, .. } => {
				self.workdir.set_current(current.clone());
			}
			fs::WorkdirResult::Reset => {
				self.workdir.reset();
			}
			fs::WorkdirResult::Get { .. } => {}
		}

		Ok(result.to_json_string())
	}
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct WorkdirParams {
	/// Directory to switch into, absolute or relative to the current workdir; required unless
	/// `reset`. Not `"."` (a no-op). Remote: ssh://user@host:port/path; `ssh://host` or
	/// `ssh://host/~/dir` is the login home.
	#[serde(default)]
	pub path: Option<String>,
	/// Revert to the session root.
	#[serde(default)]
	pub reset: Option<bool>,
}
