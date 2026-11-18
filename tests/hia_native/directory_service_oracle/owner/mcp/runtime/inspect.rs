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
// Qualification-only reference carrier; original extracted bodies remain unchanged.
use anyhow::Result;
use serde_json::{json,Value};
use std::sync::OnceLock;
use super::config::runtime_config;
static HOST_LIST_SUMMARY: OnceLock<String> = OnceLock::new();

fn render_host_list(config: &super::config::RuntimeConfig) -> Result<String> {
	let hosts: Vec<Value> = config
		.hosts
		.iter()
		.map(|(name, host)| {
			json!({
				"name": name,
				"platform": host.platform,
				"execution_mode": host.execution_mode,
				"operator_tools": host.execution_mode == super::config::ExecutionMode::Operator,
				"allow_execute": host.allow_execute,
				"allow_pty": host.allow_pty,
				"allow_write": host.allow_write,
				"privileged_actions": host.privileged_actions.keys().collect::<Vec<_>>(),
			})
		})
		.collect();
	Ok(serde_json::to_string_pretty(&json!({"hosts": hosts}))?)
}

fn cached_host_list(
	cache: &OnceLock<String>,
	config: &super::config::RuntimeConfig,
) -> Result<String> {
	if let Some(summary) = cache.get() {
		return Ok(summary.clone());
	}
	// Loaded policy is immutable. Cache only its public projection, leaving
	// per-request identity, durable audit and result retention on their normal paths.
	let summary = render_host_list(config)?;
	Ok(cache.get_or_init(|| summary).clone())
}

pub fn host_list() -> Result<String> {
	cached_host_list(&HOST_LIST_SUMMARY, runtime_config()?)
}

