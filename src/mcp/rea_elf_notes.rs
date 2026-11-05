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

//! Frozen inspect_elf_notes contract over admitted local bytes. The child gets
//! a captured snapshot, not a pathname it can reopen or controller credentials.

use super::rea_contract::{self, Failure};
use super::{rea_evidence, rea_evidence_session::EvidenceSession, rea_files, runtime};
use rmcp::model::CallToolResult;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

#[path = "rea_elf_notes_parser.rs"]
mod parser;
#[path = "rea_elf_notes_worker.rs"]
mod worker;

pub(super) const OP: &str = "inspect_elf_notes";
pub(super) const MAX_BYTES: u64 = 536_870_912;
pub(super) const MAX_WORKER_REPLY: usize = 6 * (MAX_BYTES as usize) + 64 * 1024 * 1024;
pub(super) const DEADLINE_MS: u64 = 30_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
	path: String,
	max_file_bytes: u64,
	max_entries: u32,
}

impl Input {
	fn parse(raw: &Value) -> Result<Self, Failure> {
		let mut issues = Vec::new();
		let Some(map) = rea_contract::object(raw, &mut issues) else {
			return Err(Failure::input(OP, issues));
		};
		let path = match map.get("path") {
			None => {
				issues
					.push(json!({"path":["path"],"reason":"missing_argument","expected":"string"}));
				String::new()
			}
			Some(Value::String(text)) => {
				if text.is_empty() {
					issues.push(json!({"path":["path"],"reason":"out_of_range","minimum":1}));
				}
				if text.contains('\0') {
					issues.push(json!({"path":["path"],"reason":"invalid_format","expected":"regex","message":"Invalid string: must match pattern /^[^\\x00]*$/u"}));
				}
				text.clone()
			}
			Some(_) => {
				issues.push(json!({"path":["path"],"reason":"invalid_type","expected":"string"}));
				String::new()
			}
		};
		let max_file_bytes = rea_contract::integer(
			map,
			"max_file_bytes",
			67_108_864,
			64,
			MAX_BYTES,
			&mut issues,
		);
		let max_entries = rea_contract::integer(map, "max_entries", 32, 1, 256, &mut issues) as u32;
		rea_contract::unknown_keys(
			map,
			&["path", "max_file_bytes", "max_entries"],
			&[],
			&mut issues,
		);
		if !issues.is_empty() {
			return Err(Failure::input(OP, issues));
		}
		if !Path::new(&path).is_absolute() {
			return Err(Failure::input(
				OP,
				vec![
					json!({"path":["path"],"reason":"invalid_format","message":"Expected an absolute filesystem path on this host."}),
				],
			));
		}
		Ok(Self {
			path,
			max_file_bytes,
			max_entries,
		})
	}

	fn limits(&self) -> Value {
		json!({"max_file_bytes":self.max_file_bytes,"max_entries":self.max_entries})
	}
	fn file_limit(&self, grew: bool) -> Failure {
		let reason = if grew {
			format!(
				"Selected artifact grew beyond its byte limit: {}",
				self.path
			)
		} else {
			format!(
				"Selected artifact exceeds {} bytes: {}",
				self.max_file_bytes, self.path
			)
		};
		let remediation = if self.max_file_bytes >= MAX_BYTES {
			format!("The image exceeds the {MAX_BYTES}-byte input ceiling this operation accepts; select a smaller artifact.")
		} else {
			format!("Raise max_file_bytes above {} bytes or select a smaller artifact; the limit is the caller-selected input read budget.", self.max_file_bytes)
		};
		Failure::resource(OP, "file-size", &reason, self.limits(), false, &remediation)
	}
}

fn active(cancellation: &CancellationToken) -> Result<(), Failure> {
	if cancellation.is_cancelled() {
		Err(Failure::cancelled(OP))
	} else {
		Ok(())
	}
}

fn acquisition_error(error: anyhow::Error, input: &Input) -> Failure {
	let io = error
		.chain()
		.find_map(|cause| cause.downcast_ref::<std::io::Error>());
	if let Some(code) = io.and_then(std::io::Error::raw_os_error) {
		let name = match code {
			libc::EACCES => "EACCES",
			libc::EPERM => "EPERM",
			libc::ENOENT => "ENOENT",
			libc::ENOTDIR => "ENOTDIR",
			libc::ELOOP => "ELOOP",
			libc::ENAMETOOLONG => "ENAMETOOLONG",
			libc::EISDIR => "EISDIR",
			_ => "EIO",
		};
		if matches!(code, libc::EACCES | libc::EPERM) {
			return Failure::access(OP, &input.path, name);
		}
		if code == libc::ELOOP {
			return regular_selection_error(input);
		}
		if matches!(
			code,
			libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG | libc::EISDIR
		) {
			return Failure::input(
				OP,
				vec![json!({"path":["path"],"reason":"invalid_value",
				"message":format!("Selected ELF image could not be read ({name}): {}.", input.path)})],
			);
		}
	}
	if error.to_string().contains("requires a regular file")
		|| error.to_string().contains("not a workspace root")
	{
		return regular_selection_error(input);
	}
	Failure::output(
		OP,
		format!("Native admitted artifact read failed: {error:#}"),
	)
}

fn regular_selection_error(input: &Input) -> Failure {
	Failure::input(
		OP,
		vec![json!({"path":["path"],"reason":"invalid_format",
		"message":format!("Expected a regular file without a symlink: {}", input.path)})],
	)
}

async fn capture(
	input: &Input,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
) -> Result<(Vec<u8>, String), Failure> {
	active(cancellation)?;
	let path = Path::new(&input.path);
	let (mut file, initial) = rea_files::open_confined(path, roots)
		.await
		.map_err(|error| acquisition_error(error, input))?;
	if initial.len() > input.max_file_bytes {
		return Err(input.file_limit(false));
	}
	let mut bytes = Vec::new();
	bytes
		.try_reserve_exact(initial.len() as usize)
		.map_err(|_| {
			Failure::resource(
				OP,
				"memory",
				"Host memory could not hold the admitted ELF snapshot.",
				input.limits(),
				false,
				"Retry with sufficient memory or a smaller artifact.",
			)
		})?;
	let mut hash = Sha256::new();
	let mut chunk = vec![0_u8; 65_536];
	loop {
		active(cancellation)?;
		let count = file
			.read(&mut chunk)
			.await
			.map_err(|error| acquisition_error(error.into(), input))?;
		if count == 0 {
			break;
		}
		active(cancellation)?;
		if bytes.len() as u64 + count as u64 > input.max_file_bytes {
			return Err(input.file_limit(true));
		}
		bytes.extend_from_slice(&chunk[..count]);
		hash.update(&chunk[..count]);
	}
	let after = file
		.metadata()
		.await
		.map_err(|error| acquisition_error(error.into(), input))?;
	// Re-admit the current name through the same workspace policy. Never follow
	// a substituted symlink or use a pathname reopen to obtain parser bytes.
	let (_current_file, current) = rea_files::open_confined(path, roots).await.map_err(|_| {
		Failure::changed(
			OP,
			&input.path,
			&format!("Artifact changed during read: {}", input.path),
		)
	})?;
	#[cfg(unix)]
	if bytes.len() as u64 != initial.len()
		|| rea_files::ensure_unchanged(&initial, &after).is_err()
		|| rea_files::ensure_unchanged(&initial, &current).is_err()
	{
		return Err(Failure::changed(
			OP,
			&input.path,
			&format!("Artifact changed during read: {}", input.path),
		));
	}
	active(cancellation)?;
	let digest = hash
		.finalize()
		.into_iter()
		.map(|byte| format!("{byte:02x}"))
		.collect();
	Ok((bytes, digest))
}

pub(super) fn parser_failure(failure: &Value, input: &Input) -> Failure {
	let message = failure["message"]
		.as_str()
		.unwrap_or("ELF note parser failed.");
	match failure["kind"].as_str() {
		Some("format") => Failure::input(OP, vec![json!({"path":["path"],"reason":"invalid_format","message":message})]),
		Some("unsupported") => Failure::unsupported(OP, &input.path, message),
		Some("entry_budget") => {
			let remediation = if input.max_entries >= 256 { "The image exceeds the 256-entry note-table ceiling this operation accepts; select a smaller artifact.".to_owned() }
				else { format!("Raise max_entries above {} or select a smaller artifact; the limit is the caller-selected note entry budget.", input.max_entries) };
			Failure::resource(OP, "capacity", message, input.limits(), false, &remediation)
		}
		Some("text_budget") => Failure::resource(OP, "memory", message, input.limits(), false,
			"The ELF note text, hash, and scan budget fixed by the admitted image length plus decoded section names is a fixed allowance. Worker memory limits, inherited limits, and additional host memory do not raise it. Select another complete input within the allowance when that preserves the needed observation. Repeating the unchanged request fails the same way."),
		Some("section_names_budget") => {
			let minimum = failure["minimum_required_bytes"].as_str().unwrap_or("0");
			let remediation = if minimum.parse::<u128>().is_ok_and(|n| n <= MAX_BYTES as u128) {
				format!("Raise max_file_bytes to at least {minimum} bytes to admit the source and decoded ELF section names.")
			} else { format!("The source and decoded ELF section names require {minimum} bytes, above this operation's {MAX_BYTES}-byte maximum; select an image with a smaller section-name table.") };
			Failure::resource(OP, "memory", message, json!({"max_file_bytes":input.max_file_bytes,"minimum_required_bytes":minimum}), false, &remediation)
		}
		_ => Failure::output(OP, "ELF worker returned an unknown failure representation."),
	}
}

fn evidence(report: Value, input: &Input, digest: &str, length: u64) -> Result<Value, Failure> {
	let valid_location =
		|location: &Value| match (location["offset"].as_u64(), location["bytes"].as_u64()) {
			(Some(offset), Some(bytes)) => offset <= length && bytes <= length - offset,
			_ => false,
		};
	let tables = report["tables"]
		.as_array()
		.ok_or_else(|| Failure::output(OP, "ELF worker omitted note tables."))?;
	let entries = report["entries"]
		.as_array()
		.ok_or_else(|| Failure::output(OP, "ELF worker omitted note entries."))?;
	if report["artifact"]["path"] != input.path
		|| report["artifact"]["sha256"] != digest
		|| report["artifact"]["bytes"].as_u64() != Some(length)
		|| length > input.max_file_bytes
		|| entries.len() > input.max_entries as usize
		|| report["coverage"]["examined_entries"]
			.as_u64()
			.is_none_or(|n| n > input.max_entries as u64)
		|| !tables
			.iter()
			.all(|table| valid_location(&table["location"]))
		|| !entries.iter().all(|entry| {
			valid_location(&entry["location"]) && valid_location(&entry["descriptor"]["location"])
		}) {
		return Err(Failure::output(
			OP,
			"ELF note provider returned malformed output or changed artifact identity.",
		));
	}
	let mut locations = vec![json!({"kind":"artifact-path","path":input.path})];
	for table in tables {
		let offset = table["location"]["offset"].as_u64().unwrap_or(0);
		let bytes = table["location"]["bytes"].as_u64().unwrap_or(0);
		locations.push(json!({"kind":"file-offset-range","start":offset,"end":offset+bytes}));
	}
	let architecture = match report["machine"].as_u64() {
		Some(3) => Some("x86"),
		Some(62) => Some("x86_64"),
		Some(8) => Some("mips"),
		Some(20) => Some("powerpc"),
		Some(40) => Some("arm"),
		Some(164) => Some("hexagon"),
		Some(183) => Some("arm64"),
		Some(243) => Some("riscv"),
		_ => None,
	};
	let target =
		json!({"path":input.path,"format":"elf","sha256":digest,"architecture":architecture});
	let provider = json!({"id":"rea-elf-notes","name":"REA ELF note parser","version":"1"});
	let mut observation = serde_json::Map::new();
	observation.insert("operation".to_owned(), json!(OP));
	observation.insert("parameters".to_owned(), json!(input));
	observation.insert("confidence".to_owned(), json!("observed"));
	observation.insert("limitations".to_owned(), report["limitations"].clone());
	observation.insert("locations".to_owned(), Value::Array(locations));
	observation.insert("result".to_owned(), report);
	rea_evidence::create_record_owned(Some(&target), &provider, Value::Object(observation))
		.map_err(|error| Failure::output(OP, format!("Evidence construction failed: {error:#}")))
}

async fn execute(
	input: Input,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
	admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
) -> Result<Value, Failure> {
	static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
	let permit = Arc::new(Arc::clone(SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2))))
		.try_acquire_owned().map_err(|_| Failure::resource(OP,"capacity","Native ELF parser capacity is occupied.",
			json!({"max_concurrent_elf_workers":2}),true,"Wait for an active analysis to complete, then retry within the reported admission limits."))?);
	let (bytes, digest) = capture(&input, roots, cancellation).await?;
	let length = bytes.len() as u64;
	let result = worker::inspect_isolated(
		&input,
		&digest,
		Arc::new(bytes),
		cancellation,
		Arc::clone(&permit),
		Arc::clone(&admission),
	)
	.await?;
	// A normal parser rejection does not retain a record or a partial snapshot
	// in the frozen provider. Only completed Evidence is retained below.
	if result.get("failure").is_some() {
		return Err(parser_failure(&result["failure"], &input));
	}
	let Value::Object(mut result) = result else {
		return Err(Failure::output(
			OP,
			"ELF worker returned a non-object response.",
		));
	};
	let report = result
		.remove("report")
		.ok_or_else(|| Failure::output(OP, "ELF worker omitted its complete report."))?;
	// Identity construction scans the complete report. Keep it off async
	// executor threads and retain both guards if the caller drops while hashing.
	tokio::task::spawn_blocking(move || {
		let _permit = permit;
		let _admission = admission;
		evidence(report, &input, &digest, length)
	})
	.await
	.map_err(|error| Failure::output(OP, format!("Evidence construction worker failed: {error}")))?
}

pub(super) async fn inspect(
	raw: Value,
	session: &EvidenceSession,
	cancellation: CancellationToken,
	owner_admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
) -> CallToolResult {
	if let Err(error) = active(&cancellation) {
		return error.wire();
	}
	if let Err(error) = super::rea_mcp_input::elf(&raw) {
		return error.wire();
	}
	let input = match Input::parse(&raw) {
		Ok(input) => input,
		Err(error) => return error.wire(),
	};
	let config = match runtime::runtime_config() {
		Ok(config) => config,
		Err(error) => return Failure::output(OP, error.to_string()).wire(),
	};
	match execute(
		input,
		&config.controller_workspace_roots,
		&cancellation,
		owner_admission,
	)
	.await
	{
		Err(error) => error.wire(),
		Ok(record) => {
			let retained = match session.record(record) {
				Ok(retained) => retained,
				Err(error) => return error.wire(),
			};
			if cancellation.is_cancelled() {
				return Failure::cancelled(OP).partial(retained.reference).wire();
			}
			rea_contract::success_borrowed(OP, retained.evidence.as_ref(), Some(retained.reference))
		}
	}
}

pub fn run_worker() -> anyhow::Result<()> {
	worker::serve_once()
}

#[cfg(test)]
#[path = "rea_elf_notes_tests.rs"]
mod tests;
