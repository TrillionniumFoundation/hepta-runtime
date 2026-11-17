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


impl OctofsServer {
	async fn text_file_write(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<TextFileWriteParams>,
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
			tool_name: "text_file_write".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		request_ctx::with_request_context(self.view_cache.clone(), async move {
			let result = fs::text_file_write::execute_text_file_write(&call)
				.await
				.map_err(|e| e.to_string())?;
			Ok(append_hints(result))
		})
		.await
	}
}
