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

//! Static package.json declarations for JavaScript/Electron triage. Paths,
//! scripts and dependency specifications remain data and are never resolved.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 10_000;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JavascriptCollection {
	#[default]
	Summary,
	Entries,
	Dependencies,
	Scripts,
}

fn default_limit() -> usize {
	64
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectJavascriptPackageParams {
	/// Absolute package.json file inside configured controller workspace roots.
	pub path: String,
	/// Exact complete-file digest; required for every continuation page.
	pub expected_sha256: Option<String>,
	#[serde(default)]
	pub collection: JavascriptCollection,
	#[serde(default)]
	pub offset: usize,
	/// 1..=256 declarations per page; summary does not return row values.
	#[serde(default = "default_limit")]
	pub limit: usize,
}

fn validate(params: &InspectJavascriptPackageParams) -> Result<()> {
	if !(1..=256).contains(&params.limit) || params.offset > MAX_ROWS {
		bail!("package declaration page requires limit 1..=256 and a bounded offset");
	}
	if params.offset > 0 && params.expected_sha256.is_none() {
		bail!("package declaration continuation requires expected_sha256");
	}
	if params.expected_sha256.as_ref().is_some_and(|value| {
		value.len() != 64
			|| !value
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	}) {
		bail!("package declaration identity must be a lowercase complete SHA-256");
	}
	if matches!(params.collection, JavascriptCollection::Summary) && params.offset != 0 {
		bail!("package summary has no continuation rows");
	}
	Ok(())
}

fn sha256(bytes: &[u8]) -> String {
	let mut output = String::with_capacity(64);
	for byte in Sha256::digest(bytes) {
		let _ = write!(output, "{byte:02x}");
	}
	output
}

fn pointer_segment(value: &str) -> String {
	value.replace('~', "~0").replace('/', "~1")
}

fn bounded_text<'a>(value: &'a Value, label: &str, max: usize) -> Result<&'a str> {
	let text = value
		.as_str()
		.ok_or_else(|| anyhow!("package {label} declaration must be a string"))?;
	if text.len() > max {
		bail!("package {label} declaration exceeds its text limit");
	}
	Ok(text)
}

fn append_row(rows: &mut Vec<Value>, row: Value) -> Result<()> {
	if rows.len() >= MAX_ROWS {
		bail!("package declaration inventory exceeds 10000 rows");
	}
	rows.push(row);
	Ok(())
}

fn leaves(
	value: &Value,
	field: &str,
	pointer: &str,
	depth: usize,
	allow_false: bool,
	rows: &mut Vec<Value>,
) -> Result<()> {
	if depth > 16 {
		bail!("package entry declarations exceed 16 nested levels");
	}
	match value {
		Value::String(_) => {
			bounded_text(value, field, 16 * 1024)?;
			append_row(
				rows,
				json!({"field": field, "json_pointer": pointer, "value": value}),
			)?;
		}
		Value::Null if !allow_false => {
			append_row(
				rows,
				json!({"field": field, "json_pointer": pointer, "value": null}),
			)?;
		}
		Value::Bool(false) if allow_false => {
			append_row(
				rows,
				json!({"field": field, "json_pointer": pointer, "value": false}),
			)?;
		}
		Value::Array(values) if !allow_false => {
			for (index, child) in values.iter().enumerate() {
				leaves(
					child,
					field,
					&format!("{pointer}/{index}"),
					depth + 1,
					allow_false,
					rows,
				)?;
			}
		}
		Value::Object(values) => {
			for (key, child) in values {
				if key.len() > 4096 {
					bail!("package entry declaration key is oversized");
				}
				leaves(
					child,
					field,
					&format!("{pointer}/{}", pointer_segment(key)),
					depth + 1,
					allow_false,
					rows,
				)?;
			}
		}
		_ => bail!("unsupported value in package {field} declaration at {pointer}"),
	}
	Ok(())
}

fn string_map<'a>(
	root: &'a Map<String, Value>,
	field: &str,
) -> Result<Option<&'a Map<String, Value>>> {
	root.get(field)
		.map(|value| {
			value
				.as_object()
				.ok_or_else(|| anyhow!("package {field} must be an object"))
		})
		.transpose()
}

fn report(bytes: &[u8], params: &InspectJavascriptPackageParams) -> Result<Value> {
	validate(params)?;
	if bytes.len() > MAX_FILE_BYTES as usize {
		bail!("package manifest exceeds 2 MiB");
	}
	let digest = sha256(bytes);
	if params
		.expected_sha256
		.as_ref()
		.is_some_and(|expected| expected != &digest)
	{
		bail!("package manifest SHA-256 changed; obtain a new first-page identity");
	}
	let manifest = super::rea_evidence::parse_unique_json(bytes)?;
	let root = manifest
		.as_object()
		.ok_or_else(|| anyhow!("package manifest must be an object"))?;
	for field in [
		"name", "version", "type", "main", "module", "types", "typings",
	] {
		if let Some(value) = root.get(field) {
			bounded_text(value, field, 16 * 1024)?;
		}
	}
	let mut entries = Vec::new();
	for field in ["main", "module", "types", "typings"] {
		if let Some(value) = root.get(field) {
			append_row(
				&mut entries,
				json!({
					"field": field,
					"json_pointer": format!("/{field}"),
					"value": value
				}),
			)?;
		}
	}
	if let Some(bin) = root.get("bin") {
		if bin.is_string() {
			bounded_text(bin, "bin", 16 * 1024)?;
			append_row(
				&mut entries,
				json!({"field": "bin", "json_pointer": "/bin", "value": bin}),
			)?;
		} else {
			let names = bin
				.as_object()
				.ok_or_else(|| anyhow!("package bin must be string or object"))?;
			for (name, value) in names {
				if name.len() > 4096 {
					bail!("package bin name is oversized");
				}
				bounded_text(value, "bin", 16 * 1024)?;
				append_row(
					&mut entries,
					json!({
						"field": "bin",
						"json_pointer": format!("/bin/{}", pointer_segment(name)),
						"value": value
					}),
				)?;
			}
		}
	}
	for field in ["exports", "imports", "browser"] {
		if let Some(value) = root.get(field) {
			leaves(
				value,
				field,
				&format!("/{field}"),
				0,
				field == "browser",
				&mut entries,
			)?;
		}
	}
	let mut dependencies = Vec::new();
	let mut dependency_counts = Map::new();
	let mut electron = Vec::new();
	for field in [
		"dependencies",
		"devDependencies",
		"optionalDependencies",
		"peerDependencies",
	] {
		let mut count = 0;
		if let Some(values) = string_map(root, field)? {
			for (name, value) in values {
				if name.is_empty() || name.len() > 4096 {
					bail!("package dependency name is empty or oversized");
				}
				bounded_text(value, field, 16 * 1024)?;
				let row = json!({
					"group": field,
					"name": name,
					"specification": value,
					"json_pointer": format!("/{field}/{}", pointer_segment(name))
				});
				if name == "electron" {
					electron.push(row.clone());
				}
				append_row(&mut dependencies, row)?;
				count += 1;
			}
		}
		dependency_counts.insert(field.into(), json!(count));
	}
	let mut scripts = Vec::new();
	if let Some(values) = string_map(root, "scripts")? {
		for (name, value) in values {
			if name.is_empty() || name.len() > 4096 {
				bail!("package script name is empty or oversized");
			}
			bounded_text(value, "scripts", 64 * 1024)?;
			append_row(
				&mut scripts,
				json!({
					"name": name,
					"command": value,
					"json_pointer": format!("/scripts/{}", pointer_segment(name))
				}),
			)?;
		}
	}
	let collection = match params.collection {
		JavascriptCollection::Summary => &[][..],
		JavascriptCollection::Entries => entries.as_slice(),
		JavascriptCollection::Dependencies => dependencies.as_slice(),
		JavascriptCollection::Scripts => scripts.as_slice(),
	};
	if params.offset > collection.len() {
		bail!("package declaration offset exceeds its collection");
	}
	let rows: Vec<_> = collection
		.iter()
		.skip(params.offset)
		.take(params.limit)
		.cloned()
		.collect();
	let end = params.offset + rows.len();
	Ok(json!({
		"record_format": "hepta.rea-javascript-package.v1",
		"rea_evidence_compatible": false,
		"source": {
			"sha256": digest,
			"byte_length": bytes.len(),
			"identity_scope": "complete_package_json"
		},
		"summary": {
			"name": root.get("name"),
			"version": root.get("version"),
			"type_declaration": root.get("type"),
			"main_declaration": root.get("main"),
			"entry_declaration_count": entries.len(),
			"exports_declaration_present": root.contains_key("exports"),
			"imports_declaration_present": root.contains_key("imports"),
			"browser_declaration_present": root.contains_key("browser"),
			"dependency_declaration_count": dependencies.len(),
			"dependency_group_counts": dependency_counts,
			"script_count": scripts.len(),
			"electron_dependency_declarations": electron,
			"electron_runtime_observed": false
		},
		"collection": params.collection,
		"total_rows": collection.len(),
		"offset": params.offset,
		"next_offset": (end < collection.len()).then_some(end),
		"rows": rows,
		"javascript_executed": false,
		"dependencies_resolved": false,
		"entry_files_opened": false,
		"coverage": "literal_package_declarations_only",
		"limitations": [
			"Declarations do not prove installed dependency versions, actual entry-file contents, executable behavior, Electron IPC or preload relationships.",
			"Paths, URL-like specifications and scripts are literal data; no JavaScript, package manager, loader or network request runs.",
			"Export/import leaves preserve JSON pointers and array indices but object condition order is not retained or evaluated. This is an inventory, not Node package resolution.",
			"No source-map decoding, ASAR extraction, JavaScript AST or complete npm manifest validation is claimed.",
			"An Electron dependency declaration alone does not establish an Electron application or a running Electron process."
		]
	}))
}

async fn inspect_with_roots(
	params: InspectJavascriptPackageParams,
	roots: &[PathBuf],
) -> Result<String> {
	validate(&params)?;
	static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
	let permit = Arc::clone(SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2))))
		.try_acquire_owned()
		.context("package declaration parser is busy; retry after another inspection finishes")?;
	let bytes =
		super::rea_files::read_bounded(Path::new(&params.path), roots, MAX_FILE_BYTES).await?;
	let rendered = tokio::task::spawn_blocking(move || {
		let _permit = permit;
		let output = serde_json::to_string(&report(&bytes, &params)?)?;
		if output.len() > MAX_RESPONSE_BYTES {
			bail!("package declaration response exceeds 1 MiB; reduce the selected page");
		}
		Ok::<_, anyhow::Error>(output)
	})
	.await
	.context("package declaration task failed")??;
	Ok(rendered)
}

pub async fn inspect_package(params: InspectJavascriptPackageParams) -> Result<String> {
	validate(&params)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	inspect_with_roots(params, roots).await
}

#[cfg(test)]
#[path = "rea_javascript_tests.rs"]
mod rea_javascript_tests;
