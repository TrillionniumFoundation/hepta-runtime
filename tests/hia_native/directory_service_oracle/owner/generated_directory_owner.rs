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
// Exact source slices; wrappers only expose the selected original method.
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
	async fn directory_create(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<DirectoryCreateParams>,
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
			tool_name: "directory_create".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		request_ctx::with_request_context(self.view_cache.clone(), async move {
			let result = fs::parity_ops::execute_directory_create(&call)
				.await
				.map_err(|e| e.to_string())?;
			Ok(append_hints(result))
		})
		.await
	}
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

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DirectoryCreateParams {
	/// Directory path in the configured local controller workspace. Remote paths are refused.
	pub path: String,
}
