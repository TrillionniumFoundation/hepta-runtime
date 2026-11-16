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

//! Actual current list handler and SDK transport, filtered to installed tools.
//! The original handler, router, schemas, configuration and SDK are unmodified.
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use hepta_runtime::mcp::server::OctofsServer;
use hepta_runtime::mcp::runtime::config::{RuntimeConfig, init_runtime};
use rmcp::{
	model::{ListToolsResult, PaginatedRequestParams, ServerInfo},
	service::RequestContext,
	ErrorData, RoleServer, ServerHandler, ServiceExt,
};
use tokio::io::AsyncWriteExt;

const INSTALLED: [&str; 10] = [
	"batch_edit", "directory_create", "directory_move", "effective_config",
	"execution_shadow_admit", "file_move", "host_list", "text_editor", "view", "workdir",
];

#[derive(Clone)]
struct InstalledCatalog {
	inner: OctofsServer,
	observations: Arc<tokio::sync::Mutex<tokio::fs::File>>,
	sequence: Arc<AtomicU64>,
}

impl ServerHandler for InstalledCatalog {
	fn get_info(&self) -> ServerInfo {
		ServerHandler::get_info(&self.inner)
	}

	async fn list_tools(
		&self,
		request: Option<PaginatedRequestParams>,
		context: RequestContext<RoleServer>,
	) -> Result<ListToolsResult, ErrorData> {
		let before = serde_json::json!({
			"id": context.id,
			"meta": context.meta,
			"protocol_version": context.protocol_version().map(|value| value.to_string()),
			"cursor": request.as_ref().and_then(|value| value.cursor.as_deref()),
		});
		let mut result = ServerHandler::list_tools(&self.inner, request, context).await?;
		let original_result_wire = serde_json::to_string(&result)
			.map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
		result.tools.retain(|tool| INSTALLED.contains(&tool.name.as_ref()));
		let installed_result_wire = serde_json::to_string(&result)
			.map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
		let row = serde_json::json!({
			"sequence": self.sequence.fetch_add(1, Ordering::SeqCst),
			"before": before,
			"original_result_wire": original_result_wire,
			"installed_result_wire": installed_result_wire,
		});
		let mut bytes = serde_json::to_vec(&row)
			.map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
		bytes.push(b'\n');
		let mut file = self.observations.lock().await;
		file.write_all(&bytes).await
			.map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
		file.flush().await
			.map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
		Ok(result)
	}
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let args: Vec<String> = std::env::args().skip(1).collect();
	match args.as_slice() {
		[] => {}
		[flag, path] if flag == "--runtime-config" => {
			let config = RuntimeConfig::load(std::path::Path::new(path))?;
			init_runtime(config)?;
		}
		_ => anyhow::bail!("expected no arguments or --runtime-config PATH"),
	}
	let file = tokio::fs::OpenOptions::new().write(true).create_new(true)
		.open("catalog-observations.jsonl").await?;
	let server = InstalledCatalog {
		inner: OctofsServer::new(),
		observations: Arc::new(tokio::sync::Mutex::new(file)),
		sequence: Arc::new(AtomicU64::new(0)),
	};
	let running = server.serve(rmcp::transport::stdio()).await?;
	let _ = running.waiting().await?;
	Ok(())
}
