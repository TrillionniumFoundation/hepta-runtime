// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit native local document/image tools; bounded parser workers and OS file rights.
use super::config::{check_local_path, check_remote_path, runtime_config, ExecutionMode};
use anyhow::{anyhow, bail, Context, Result};
use rmcp::{
	model::{CallToolResult, ContentBlock},
	schemars,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
	io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
	process::Command,
	sync::Semaphore,
};

const WORKER: &str = include_str!("document_local.py");
static WORKERS: Semaphore = Semaphore::const_new(2);

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocumentReadParams {
	/// Read stored spreadsheet cache values instead of formula strings; no recalculation.
	#[serde(default)]
	pub cached_values: bool,
	/// Optional configured operator host. Omit for controller-local documents.
	#[serde(default)]
	pub host: Option<String>,
	/// Absolute path on the selected host (or controller when host is omitted).
	pub path: String,
	#[serde(default)]
	pub expected_sha256: Option<String>,
	#[serde(default)]
	pub offset: Option<u64>,
	#[serde(default)]
	pub length: Option<u16>,
	#[serde(default)]
	pub sheet: Option<String>,
	#[serde(default)]
	pub range: Option<String>,
	/// Optional DOCX document/header/footer XML part, returned with line pagination.
	#[serde(default)]
	pub xml_part: Option<String>,
	/// Return native MCP image content for at most two PDF pages, in addition to text.
	#[serde(default)]
	pub render: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DocumentFormat {
	Pdf,
	Docx,
	Xlsx,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocumentWriteParams {
	/// Optional configured operator host. Omit for controller-local documents.
	#[serde(default)]
	pub host: Option<String>,
	pub path: String,
	pub format: DocumentFormat,
	/// Markdown text for PDF/DOCX; sheet-name to row-array object for XLSX.
	pub content: Value,
	/// Prior source SHA256; use absent for create-only output.
	pub expected_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocumentEditParams {
	/// Optional configured operator host. Omit for controller-local documents.
	#[serde(default)]
	pub host: Option<String>,
	pub path: String,
	pub expected_sha256: String,
	/// DOCX package part; defaults to word/document.xml.
	#[serde(default)]
	pub part: Option<String>,
	pub old_xml: String,
	pub new_xml: String,
	#[serde(default)]
	pub expected_replacements: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PdfPageOperation {
	Delete {
		page_indexes: Vec<u32>,
	},
	Insert {
		page_index: u32,
		#[serde(default)]
		markdown: Option<String>,
		#[serde(default)]
		source_path: Option<String>,
		#[serde(default)]
		source_sha256: Option<String>,
	},
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PdfEditParams {
	#[serde(default)]
	pub host: Option<String>,
	pub path: String,
	pub expected_sha256: String,
	pub output_path: String,
	pub output_expected_sha256: String,
	pub operations: Vec<PdfPageOperation>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorksheetEditParams {
	#[serde(default)]
	pub host: Option<String>,
	pub path: String,
	pub expected_sha256: String,
	#[serde(default)]
	pub sheet: Option<String>,
	pub range: String,
	pub values: Vec<Vec<Value>>,
}

async fn bounded(mut reader: impl AsyncRead + Unpin, max: usize) -> Result<Vec<u8>> {
	let mut bytes = Vec::new();
	let mut buffer = [0u8; 8192];
	loop {
		let n = reader.read(&mut buffer).await?;
		if n == 0 {
			break;
		}
		if bytes.len() + n > max {
			bail!("native document worker exceeded response limit");
		}
		bytes.extend_from_slice(&buffer[..n]);
	}
	Ok(bytes)
}

async fn execute(path: &str, mut input: Value, write: bool) -> Result<CallToolResult> {
	let config = runtime_config()?;
	if !Path::new(path).is_absolute() || path.contains('\0') {
		bail!("absolute local document path required");
	}
	let remote_name = input.get("host").and_then(Value::as_str).map(str::to_owned);
	let mut paths = vec![(path.to_owned(), write && input["op"] != "pdf_edit")];
	if input["op"] == "pdf_edit" {
		paths.push((
			input["output_path"]
				.as_str()
				.context("missing PDF output")?
				.to_owned(),
			true,
		));
		if let Some(operations) = input["operations"].as_array() {
			for operation in operations {
				if let Some(source) = operation.get("source_path").and_then(Value::as_str) {
					paths.push((source.to_owned(), false));
				}
			}
		}
	}
	if let Some(name) = &remote_name {
		let host = config.host(name)?;
		if host.execution_mode != ExecutionMode::Operator {
			bail!("remote documents require a configured operator host");
		}
		for (file, is_write) in &paths {
			check_remote_path(name, file, false, false, *is_write)?;
			if !(*is_write && input["op"] == "write" && input["expected_sha256"] == "absent") {
				check_remote_path(name, file, false, false, false)?;
			}
		}
		input["remote"] = json!({"ssh_target":host.ssh_target,"read_roots":host.allowed_read_path_prefixes,"write_roots":host.allowed_write_path_prefixes});
		input["file_helper"] = json!(include_str!("binary_file.py"));
	} else {
		for (file, _) in &paths {
			check_local_path(Path::new(file))?;
		}
	}
	let parser =
		std::env::var_os("HEPTA_RUNTIME_DOCUMENT_PYTHON").ok_or_else(|| {
			anyhow!("native parser is not configured; administrator must set HEPTA_RUNTIME_DOCUMENT_PYTHON")
		})?;
	if !Path::new(&parser).is_absolute() {
		bail!("configured document interpreter must be absolute");
	}
	let _permit = WORKERS
		.try_acquire()
		.context("document worker capacity reached; no operation started")?;
	input["roots"] = json!(config.controller_workspace_roots);
	let bytes = serde_json::to_vec(&input)?;
	if bytes.len() > 2 * 1024 * 1024 {
		bail!("document request exceeds 2 MiB");
	}
	if write {
		super::jobs::audit(
			"native_document_write",
			"controller",
			path,
			&json!({"op":input["op"]}),
		)?;
	}
	let mut command = Command::new(parser);
	command
		.args(["-I", "-c", WORKER])
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	#[cfg(unix)]
	command.process_group(0);
	let mut child = command.spawn()?;
	let mut stdin = child
		.stdin
		.take()
		.ok_or_else(|| anyhow!("missing parser input"))?;
	let stdout = child
		.stdout
		.take()
		.ok_or_else(|| anyhow!("missing parser output"))?;
	let stderr = child
		.stderr
		.take()
		.ok_or_else(|| anyhow!("missing parser error output"))?;
	let result = tokio::time::timeout(Duration::from_secs(90), async {
		let send = async {
			stdin.write_all(&bytes).await?;
			stdin.shutdown().await?;
			drop(stdin);
			Ok::<(), anyhow::Error>(())
		};
		let wait = async { Ok::<_, anyhow::Error>(child.wait().await?) };
		let (_, out, err, status) = tokio::try_join!(
			send,
			bounded(stdout, 2 * 1024 * 1024),
			bounded(stderr, 65536),
			wait
		)?;
		if !status.success() {
			bail!(
				"document operation failed: {}",
				String::from_utf8_lossy(&err)
			);
		}
		let content: Vec<ContentBlock> = serde_json::from_slice(&out)?;
		Ok::<_, anyhow::Error>(CallToolResult::success(content))
	})
	.await;
	match result {
		Ok(Ok(value)) => Ok(value),
		error => {
			#[cfg(unix)]
			if child.try_wait()?.is_none() {
				if let Some(pid) = child.id() {
					unsafe {
						libc::kill(-(pid as i32), libc::SIGKILL);
					}
				}
			}
			let _ = child.start_kill();
			let _ = child.wait().await;
			match error {Ok(Err(e))=>Err(e),_=>Err(anyhow!("document worker deadline exceeded; reconcile output fingerprint before retrying a write"))}
		}
	}
}

pub async fn read(p: DocumentReadParams, image: bool) -> Result<CallToolResult> {
	let mut q = serde_json::to_value(&p)?;
	q["op"] = json!(if image { "image_read" } else { "read" });
	execute(&p.path, q, false).await
}
pub async fn write(p: DocumentWriteParams) -> Result<CallToolResult> {
	let mut q = serde_json::to_value(&p)?;
	q["op"] = json!("write");
	execute(&p.path, q, true).await
}
pub async fn edit(p: DocumentEditParams) -> Result<CallToolResult> {
	let mut q = serde_json::to_value(&p)?;
	q["op"] = json!("edit_docx");
	execute(&p.path, q, true).await
}

pub async fn edit_pdf(p: PdfEditParams) -> Result<CallToolResult> {
	if p.path == p.output_path || p.operations.is_empty() || p.operations.len() > 100 {
		bail!("PDF edit needs 1..100 operations and a distinct output path");
	}
	let mut q = serde_json::to_value(&p)?;
	q["op"] = json!("pdf_edit");
	execute(&p.path, q, true).await
}

pub async fn edit_worksheet(p: WorksheetEditParams) -> Result<CallToolResult> {
	if p.values.is_empty()
		|| p.values.len() > 5000
		|| p.values.iter().map(Vec::len).sum::<usize>() > 5000
	{
		bail!("worksheet edit exceeds cell limit");
	}
	let mut q = serde_json::to_value(&p)?;
	q["op"] = json!("worksheet_edit");
	execute(&p.path, q, true).await
}

#[cfg(test)]
#[path = "documents_tests.rs"]
mod tests;
