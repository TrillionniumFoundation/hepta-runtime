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

//! Bounded, explicit-source JS/TS graph inspection. File admission belongs to
//! the runtime; the isolated parser receives source bytes and logical IDs only.

use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;

#[path = "rea_javascript_ast.rs"]
mod ast;
#[path = "rea_javascript_graph_report.rs"]
mod graph;
#[path = "rea_javascript_graph_worker.rs"]
mod worker;

pub(super) const MAX_SOURCES: usize = 16;
pub(super) const MAX_SOURCE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
pub(super) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_ROWS: usize = 10_000;
pub(super) const PARSER_VERSION: &str = "0.144.0";
pub(super) const GRAPH_PROFILE: &str = "hepta.javascript-selected-source-graph.v4";

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JavascriptSyntax {
	#[default]
	Javascript,
	Typescript,
	Jsx,
	Tsx,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JavascriptModuleKind {
	#[default]
	Module,
	Commonjs,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JavascriptSource {
	/// Unique normalized relative POSIX logical path, e.g. src/main.ts. No traversal.
	pub id: String,
	/// Absolute source file, or an ASAR archive when asar is explicitly supplied, inside configured roots.
	pub path: String,
	/// Explicit packed ASAR member and pinned archive identities. Missing preserves ordinary-file acquisition.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub asar: Option<super::rea_asar::AsarSource>,
	/// Explicit grammar; no package.json, tsconfig or source map is opened implicitly.
	#[serde(default)]
	pub syntax: JavascriptSyntax,
	/// Module or CommonJS parsing, selected by the caller rather than filename guesses.
	#[serde(default)]
	pub module_kind: JavascriptModuleKind,
	/// Optional complete-file lowercase SHA-256 precondition.
	pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JavascriptGraphCollection {
	#[default]
	Summary,
	Imports,
	Exports,
	ElectronCalls,
	IpcEdges,
	Unknowns,
}

fn default_limit() -> usize {
	64
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectJavascriptGraphParams {
	/// 1..=16 explicit files, each <=1 MiB; all selected source bytes total <=4 MiB.
	pub sources: Vec<JavascriptSource>,
	/// Entire selected source-set identity; required for every continuation page.
	pub expected_graph_sha256: Option<String>,
	#[serde(default)]
	pub collection: JavascriptGraphCollection,
	#[serde(default)]
	pub offset: usize,
	/// 1..=256 records per page; summary returns counts and source identities only.
	#[serde(default = "default_limit")]
	pub limit: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdmittedSource {
	pub id: String,
	pub syntax: JavascriptSyntax,
	pub module_kind: JavascriptModuleKind,
	pub text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerRequest {
	pub sources: Vec<AdmittedSource>,
	pub expected_graph_sha256: Option<String>,
	pub collection: JavascriptGraphCollection,
	pub offset: usize,
	pub limit: usize,
}

fn valid_digest(digest: &str) -> bool {
	digest.len() == 64
		&& digest
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn sha256(bytes: &[u8]) -> String {
	let mut output = String::with_capacity(64);
	for byte in Sha256::digest(bytes) {
		let _ = write!(&mut output, "{byte:02x}");
	}
	output
}

pub(super) fn validate_id(id: &str) -> Result<()> {
	if id.is_empty()
		|| id.len() > 512
		|| id.contains(['\\', ':', '?', '#'])
		|| id.chars().any(char::is_control)
		|| id
			.split('/')
			.any(|part| part.is_empty() || part == "." || part == "..")
	{
		bail!("JavaScript source IDs must be normalized relative POSIX paths up to 512 bytes");
	}
	Ok(())
}

fn validate_page(
	collection: JavascriptGraphCollection,
	offset: usize,
	limit: usize,
	expected: Option<&str>,
) -> Result<()> {
	if !(1..=256).contains(&limit) || offset > MAX_ROWS {
		bail!("JavaScript graph page requires limit 1..=256 and offset <=10000");
	}
	if offset > 0 && expected.is_none() {
		bail!("JavaScript graph continuation requires expected_graph_sha256");
	}
	if expected.is_some_and(|digest| !valid_digest(digest)) {
		bail!("JavaScript graph identity must be a lowercase complete SHA-256");
	}
	if matches!(collection, JavascriptGraphCollection::Summary) && offset != 0 {
		bail!("JavaScript graph summary has no continuation rows");
	}
	Ok(())
}

fn validate(params: &InspectJavascriptGraphParams) -> Result<()> {
	validate_page(
		params.collection,
		params.offset,
		params.limit,
		params.expected_graph_sha256.as_deref(),
	)?;
	if params.sources.is_empty() || params.sources.len() > MAX_SOURCES {
		bail!("JavaScript graph requires 1..=16 explicitly selected sources");
	}
	let mut ids = BTreeSet::new();
	let mut paths = BTreeSet::new();
	for source in &params.sources {
		validate_id(&source.id)?;
		if !ids.insert(&source.id)
			|| !paths.insert((
				&source.path,
				source.asar.as_ref().map(|a| a.member.as_str()),
			)) {
			bail!("JavaScript graph source IDs and selected file/member paths must be unique");
		}
		if let Some(asar) = &source.asar {
			asar.validate()?;
		}
		if source
			.expected_sha256
			.as_deref()
			.is_some_and(|digest| !valid_digest(digest))
		{
			bail!("JavaScript source identity must be a lowercase complete SHA-256");
		}
	}
	Ok(())
}

pub(super) fn validate_request(request: &WorkerRequest) -> Result<()> {
	validate_page(
		request.collection,
		request.offset,
		request.limit,
		request.expected_graph_sha256.as_deref(),
	)?;
	if request.sources.is_empty() || request.sources.len() > MAX_SOURCES {
		bail!("JavaScript parser requires 1..=16 selected sources");
	}
	let mut ids = BTreeSet::new();
	let mut total = 0;
	for source in &request.sources {
		validate_id(&source.id)?;
		if !ids.insert(&source.id) {
			bail!("JavaScript parser received duplicate source IDs");
		}
		if source.text.len() > MAX_SOURCE_BYTES {
			bail!("JavaScript source exceeds 1 MiB");
		}
		total += source.text.len();
	}
	if total > MAX_TOTAL_BYTES {
		bail!("JavaScript selected source bytes exceed 4 MiB");
	}
	Ok(())
}

pub(super) fn source_identities(request: &WorkerRequest) -> Vec<Value> {
	let mut sources: Vec<_> = request.sources.iter().collect();
	sources.sort_by(|left, right| left.id.cmp(&right.id));
	sources
		.into_iter()
		.map(|source| {
			json!({
				"id": source.id,
				"syntax": source.syntax,
				"module_kind": source.module_kind,
				"sha256": sha256(source.text.as_bytes()),
				"byte_length": source.text.len()
			})
		})
		.collect()
}

pub(super) fn graph_identity(sources: &[Value]) -> Result<String> {
	Ok(sha256(&serde_json::to_vec(&json!({
		"profile": GRAPH_PROFILE,
		"parser": {"name":"oxc", "version":PARSER_VERSION},
		"sources": sources
	}))?))
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
	if cancellation.is_cancelled() {
		bail!("JavaScript AST inspection cancelled");
	}
	Ok(())
}

async fn inspect_with_roots(
	params: InspectJavascriptGraphParams,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
) -> Result<String> {
	ensure_not_cancelled(cancellation)?;
	validate(&params)?;
	ensure_not_cancelled(cancellation)?;
	static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
	let permit = Arc::clone(SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2))))
		.try_acquire_owned()
		.context("JavaScript graph parser is busy; retry after another inspection finishes")?;
	ensure_not_cancelled(cancellation)?;
	let mut sources = Vec::with_capacity(params.sources.len());
	let mut archive_sources = Vec::new();
	let mut total = 0;
	for source in params.sources {
		ensure_not_cancelled(cancellation)?;
		// Admission uses blocking file operations internally. Retain the slot and
		// finish this read before honoring cancellation, rather than detach it.
		let bytes = if let Some(selection) = &source.asar {
			let (bytes, provenance) = super::rea_asar::read_javascript_source(
				&source.path,
				selection,
				roots,
				cancellation,
			)
			.await?;
			archive_sources.push(json!({"source_id": source.id.clone(), "provenance": provenance}));
			bytes
		} else {
			let read = super::rea_files::read_bounded(
				Path::new(&source.path),
				roots,
				MAX_SOURCE_BYTES as u64,
			)
			.await;
			ensure_not_cancelled(cancellation)?;
			read?
		};
		ensure_not_cancelled(cancellation)?;
		total += bytes.len();
		if total > MAX_TOTAL_BYTES {
			bail!("JavaScript selected source bytes exceed 4 MiB");
		}
		if source
			.expected_sha256
			.as_deref()
			.is_some_and(|expected| expected != sha256(&bytes))
		{
			bail!("JavaScript source {} SHA-256 changed", source.id);
		}
		sources.push(AdmittedSource {
			id: source.id,
			syntax: source.syntax,
			module_kind: source.module_kind,
			text: String::from_utf8(bytes).context("JavaScript source must be valid UTF-8")?,
		});
	}
	let request = WorkerRequest {
		sources,
		expected_graph_sha256: params.expected_graph_sha256,
		collection: params.collection,
		offset: params.offset,
		limit: params.limit,
	};
	validate_request(&request)?;
	let identities = source_identities(&request);
	let expected_graph = graph_identity(&identities)?;
	if request
		.expected_graph_sha256
		.as_ref()
		.is_some_and(|expected| expected != &expected_graph)
	{
		bail!("JavaScript source set changed; obtain a new first-page graph identity");
	}
	ensure_not_cancelled(cancellation)?;
	#[cfg(not(test))]
	let mut result = worker::inspect_isolated(&request, cancellation).await?;
	#[cfg(test)]
	let mut result = graph::report(&request)?;
	ensure_not_cancelled(cancellation)?;
	if result["graph_sha256"] != expected_graph || result["sources"] != json!(identities) {
		bail!("JavaScript worker report is not bound to the controller-admitted source set");
	}
	if !archive_sources.is_empty() {
		archive_sources.sort_by(|a, b| a["source_id"].as_str().cmp(&b["source_id"].as_str()));
		result["archive_sources"] = json!(archive_sources);
	}
	let output = serde_json::to_string(&result)?;
	if output.len() > MAX_RESPONSE_BYTES {
		bail!("JavaScript graph response exceeds 1 MiB; reduce the selected page");
	}
	drop(permit);
	ensure_not_cancelled(cancellation)?;
	Ok(output)
}

pub async fn inspect_graph(
	params: InspectJavascriptGraphParams,
	cancellation: CancellationToken,
) -> Result<String> {
	ensure_not_cancelled(&cancellation)?;
	validate(&params)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	inspect_with_roots(params, roots, &cancellation).await
}

/// Internal one-shot worker entry point; consumes only controller-supplied stdin.
pub fn serve_once() -> Result<()> {
	worker::serve_once()
}

#[cfg(test)]
#[path = "rea_javascript_graph_tests.rs"]
mod tests;
