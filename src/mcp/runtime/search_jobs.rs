// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Session-owned durable bounded search lifecycle; terminal pages never consume a shared cursor.
use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use super::config::{check_remote_path, runtime_config, HostConfig};
use super::ssh::run_python_json;

const MAX_RECEIPTS: usize = 1024;
const MAX_PAGE_BYTES: usize = 96 * 1024;
const MAX_RECORD_BYTES: u64 = 16 * 1024;
const TERMINAL: &[&str] = &["completed", "limited", "cancelled", "failed", "interrupted"];
static SEARCH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static INSTANCE: OnceLock<std::result::Result<String, String>> = OnceLock::new();

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchKind {
	/// Literal substring of the root-relative regular-file path.
	Files,
	/// Literal UTF-8 substring in ordinary UTF-8 text files; no regular expressions.
	Content,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchStartParams {
	pub host: String,
	/// Absolute root under this configured host's read policy; symlink components are refused.
	pub root: String,
	/// Literal 1..512 UTF-8 bytes; NUL and newlines are refused.
	pub query: String,
	pub kind: SearchKind,
	#[serde(default)]
	pub include_hidden: bool,
	/// At most 1000 results; default 1000.
	#[serde(default)]
	pub max_results: Option<u16>,
	/// At most 10000 traversed entries; default 10000.
	#[serde(default)]
	pub max_entries: Option<u32>,
	/// At most 64 MiB read; default 64 MiB. Individual files above 4 MiB are skipped.
	#[serde(default)]
	pub max_bytes: Option<u64>,
	/// At most 30 seconds worker wall budget; default 30. Blocking OS I/O may delay termination.
	#[serde(default)]
	pub timeout_seconds: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchRefParams {
	pub search_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchResultsParams {
	pub search_id: String,
	/// Independent zero-based result offset; never advances another caller's cursor.
	#[serde(default)]
	pub cursor: Option<u32>,
	/// 1..32 terminal snapshot records per response; default 32.
	#[serde(default)]
	pub limit: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchListParams {
	/// Last returned opaque search id, for lexicographic pagination.
	#[serde(default)]
	pub after_id: Option<String>,
	/// At most 32 metadata-owner-scoped receipts; default 32.
	#[serde(default)]
	pub limit: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SearchRecord {
	id: String,
	owner: String,
	instance: String,
	host: String,
	ssh_target: String,
	remote_state_dir: String,
	created_unix_ms: u128,
	state: String,
	reason: Option<String>,
	request: SearchStartParams,
}

fn lock() -> &'static Mutex<()> {
	SEARCH_LOCK.get_or_init(|| Mutex::new(()))
}

/// Random entropy failures disable the session's search surface; no predictable fallback.
pub fn new_owner_id() -> Result<String> {
	let mut bytes = [0u8; 32];
	std::fs::File::open("/dev/urandom")
		.context("search identity entropy unavailable")?
		.read_exact(&mut bytes)
		.context("search identity entropy unavailable")?;
	Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn instance() -> Result<&'static str> {
	INSTANCE
		.get_or_init(|| new_owner_id().map_err(|error| error.to_string()))
		.as_ref()
		.map(String::as_str)
		.map_err(|error| anyhow!(error.clone()))
}

fn valid_id(id: &str) -> bool {
	id.len() == 64
		&& id
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_owner(owner: &str) -> Result<()> {
	if !valid_id(owner) {
		bail!("search session identity unavailable");
	}
	Ok(())
}

fn validate_start(params: &SearchStartParams) -> Result<()> {
	if params.query.is_empty()
		|| params.query.len() > 512
		|| params.query.contains(['\0', '\n', '\r'])
	{
		bail!("search query requires 1..512 UTF-8 bytes without NUL/newlines");
	}
	if !Path::new(&params.root).is_absolute()
		|| params.root.len() > 4096
		|| params.root.contains(['\0', '\n', '\r'])
		|| Path::new(&params.root)
			.components()
			.any(|c| matches!(c, Component::ParentDir | Component::CurDir))
	{
		bail!("search root must be an absolute safe path of at most 4096 bytes");
	}
	let limits = limits(params);
	for (key, cap) in [
		("results", 1000),
		("entries", 10000),
		("bytes", 64 * 1024 * 1024),
		("seconds", 30),
	] {
		if !limits[key]
			.as_u64()
			.is_some_and(|value| value > 0 && value <= cap)
		{
			bail!("invalid search {key} resource limit");
		}
	}
	Ok(())
}

fn limits(params: &SearchStartParams) -> Value {
	json!({"results":params.max_results.unwrap_or(1000),"entries":params.max_entries.unwrap_or(10000),
		"bytes":params.max_bytes.unwrap_or(64*1024*1024),"seconds":params.timeout_seconds.unwrap_or(30)})
}

fn page_limit(limit: Option<u16>) -> Result<u16> {
	let limit = limit.unwrap_or(32);
	if !(1..=32).contains(&limit) {
		bail!("search page limit must be 1..32");
	}
	Ok(limit)
}

async fn directory() -> Result<PathBuf> {
	let directory = runtime_config()?.state_dir.join("search");
	tokio::fs::create_dir_all(&directory).await?;
	let metadata = tokio::fs::symlink_metadata(&directory).await?;
	if !metadata.is_dir() || metadata.file_type().is_symlink() {
		bail!("controller search state is not an ordinary directory");
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::{MetadataExt, PermissionsExt};
		if metadata.uid() != unsafe { libc::geteuid() } {
			bail!("controller search state is not owned by this account");
		}
		tokio::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).await?;
	}
	Ok(directory)
}

async fn save(directory: &Path, record: &SearchRecord) -> Result<()> {
	let temporary = directory.join(format!(".{}-{}", record.id, new_owner_id()?));
	let mut options = tokio::fs::OpenOptions::new();
	options.create_new(true).write(true);
	#[cfg(unix)]
	options
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
	let mut file = options.open(&temporary).await?;
	file.write_all(&serde_json::to_vec(record)?).await?;
	file.sync_all().await?;
	drop(file);
	tokio::fs::rename(&temporary, directory.join(format!("{}.json", record.id))).await?;
	let parent = tokio::fs::File::open(directory).await?;
	parent.sync_all().await?;
	Ok(())
}

async fn read_record(path: &Path) -> Result<SearchRecord> {
	let mut options = tokio::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
	let file = options.open(path).await?;
	let metadata = file.metadata().await?;
	if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
		bail!("invalid controller search receipt");
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
			bail!("controller search receipt is not private");
		}
	}
	use tokio::io::AsyncReadExt;
	let mut bytes = Vec::new();
	file.take(MAX_RECORD_BYTES + 1)
		.read_to_end(&mut bytes)
		.await?;
	if bytes.len() as u64 > MAX_RECORD_BYTES {
		bail!("oversize controller search receipt");
	}
	Ok(serde_json::from_slice(&bytes)?)
}

fn reconcile(record: &mut SearchRecord, current_instance: &str) -> bool {
	if record.instance != current_instance && !TERMINAL.contains(&record.state.as_str()) {
		record.state = "interrupted".into();
		record.reason = Some("controller_restarted_no_session_resume".into());
		return true;
	}
	false
}

async fn records(directory: &Path) -> Result<Vec<SearchRecord>> {
	let mut entries = tokio::fs::read_dir(directory).await?;
	let mut result = Vec::new();
	while let Some(entry) = entries.next_entry().await? {
		let name = entry.file_name();
		let Some(name) = name.to_str() else {
			bail!("invalid controller search state entry");
		};
		if name.starts_with('.') {
			continue;
		}
		let Some(id) = name.strip_suffix(".json") else {
			bail!("invalid controller search state entry");
		};
		if !valid_id(id) || result.len() >= MAX_RECEIPTS {
			bail!("invalid or excessive controller search receipts");
		}
		let mut record = read_record(&entry.path()).await?;
		if record.id != id {
			bail!("search receipt identity mismatch");
		}
		if reconcile(&mut record, instance()?) {
			save(directory, &record).await?;
		}
		result.push(record);
	}
	result.sort_by(|a, b| a.id.cmp(&b.id));
	refresh_active(directory, &mut result).await?;
	Ok(result)
}

fn apply_native_terminal(record: &mut SearchRecord, native: &Value) -> bool {
	let Some(state) = native["state"].as_str() else {
		return false;
	};
	if !TERMINAL.contains(&state) || TERMINAL.contains(&record.state.as_str()) {
		return false;
	}
	record.state = state.into();
	record.reason = native["reason"].as_str().map(str::to_owned);
	true
}

async fn refresh_active(directory: &Path, records: &mut [SearchRecord]) -> Result<()> {
	// Session owners may disappear without polling. Only trusted private receipts
	// authorize these bounded internal status reads; no unowned data is returned.
	let active: Vec<_> = records
		.iter()
		.filter(|record| !TERMINAL.contains(&record.state.as_str()))
		.cloned()
		.collect();
	if active.len() > 8 {
		bail!("controller active-search invariant exceeded");
	}
	let mut tasks = tokio::task::JoinSet::new();
	for record in active {
		tasks.spawn(async move {
			let status = rpc(&record, "status", json!({})).await;
			(record.id, status)
		});
	}
	while let Some(outcome) = tasks.join_next().await {
		let (id, status) = outcome.context("search status reconciliation task failed")?;
		if let Ok(native) = status {
			if let Some(record) = records.iter_mut().find(|record| record.id == id) {
				if apply_native_terminal(record, &native) {
					save(directory, record).await?;
				}
			}
		}
	}
	Ok(())
}

async fn owned(directory: &Path, owner: &str, id: &str) -> Result<SearchRecord> {
	validate_owner(owner)?;
	if !valid_id(id) {
		bail!("search unavailable to this session");
	}
	let mut record = read_record(&directory.join(format!("{id}.json")))
		.await
		.map_err(|_| anyhow!("search unavailable to this session"))?;
	if record.owner != owner || record.id != id {
		bail!("search unavailable to this session");
	}
	pinned_host(&record).map_err(|_| anyhow!("search unavailable to this session"))?;
	if reconcile(&mut record, instance()?) {
		save(directory, &record).await?;
	}
	Ok(record)
}

fn pinned_host(record: &SearchRecord) -> Result<&'static HostConfig> {
	let host = runtime_config()?.host(&record.host)?;
	if host.ssh_target != record.ssh_target || host.remote_state_dir != record.remote_state_dir {
		bail!("search host configuration changed; reference refused");
	}
	check_remote_path(&record.host, &record.request.root, false, false, false)?;
	Ok(host)
}

async fn rpc(record: &SearchRecord, action: &str, extra: Value) -> Result<Value> {
	let host = pinned_host(record)?;
	let mut request = json!({"action":action,"owner":record.owner,"search_id":record.id,
		"state_dir":host.remote_state_dir});
	for (key, value) in extra
		.as_object()
		.ok_or_else(|| anyhow!("invalid search helper request"))?
	{
		request[key] = value.clone();
	}
	run_python_json(host, include_str!("search_worker.py"), &request, Duration::from_secs(12))
		.await.map_err(|_| anyhow!("native search helper unavailable or refused; receipt retained, do not relaunch uncertain starts"))
}

fn wire_size(text: &str) -> Result<usize> {
	let envelope =
		rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(text)]);
	Ok(serde_json::to_vec(&envelope)?.len())
}

fn response(value: Value) -> Result<String> {
	let text = serde_json::to_string(&value)?;
	if wire_size(&text)? > MAX_PAGE_BYTES {
		bail!("search response exceeds fixed 96 KiB MCP envelope cap");
	}
	Ok(text)
}

fn brief(record: &SearchRecord) -> Value {
	json!({"search_id":record.id,"host":record.host,"root":record.request.root,
		"kind":record.request.kind,"state":record.state,"reason":record.reason,
		"created_unix_ms":record.created_unix_ms})
}

pub async fn search_start(owner: &str, params: SearchStartParams) -> Result<String> {
	validate_owner(owner)?;
	validate_start(&params)?;
	check_remote_path(&params.host, &params.root, false, false, false)?;
	let host = runtime_config()?.host(&params.host)?;
	if !Path::new(&host.remote_state_dir).is_absolute()
		|| host.remote_state_dir.contains(['\0', '\n', '\r'])
	{
		bail!("configured search state directory is invalid");
	}
	let _guard = lock().lock().await;
	let directory = directory().await?;
	let all = records(&directory).await?;
	if all.len() >= MAX_RECEIPTS {
		bail!("search receipt quota reached; administrator cleanup required");
	}
	if all
		.iter()
		.filter(|r| !TERMINAL.contains(&r.state.as_str()))
		.count()
		>= 8 || all
		.iter()
		.filter(|r| r.owner == owner && !TERMINAL.contains(&r.state.as_str()))
		.count()
		>= 4
	{
		bail!("active search quota reached; collect terminal results or stop own searches first");
	}
	let mut record = SearchRecord {
		id: new_owner_id()?,
		owner: owner.into(),
		instance: instance()?.into(),
		host: params.host.clone(),
		ssh_target: host.ssh_target.clone(),
		remote_state_dir: host.remote_state_dir.clone(),
		created_unix_ms: SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_millis(),
		state: "launching".into(),
		reason: None,
		request: params,
	};
	save(&directory, &record).await?;
	let result = rpc(
		&record,
		"start",
		json!({"root":record.request.root,"query":record.request.query,
		"kind":record.request.kind,"include_hidden":record.request.include_hidden,
		"limits":limits(&record.request),"allowed_roots":host.allowed_read_path_prefixes,
		"protected_roots":host.protected_path_prefixes}),
	)
	.await;
	match result {
		Ok(native) => {
			record.state = "running".into();
			save(&directory, &record).await?;
			response(
				json!({"search":brief(&record),"native":native,"limits":limits(&record.request),
				"session_resume_after_restart":false,"terminal_pages_only":true}),
			)
		}
		Err(_) => {
			record.state = "launch_uncertain".into();
			record.reason = Some("native_start_response_unavailable_do_not_relaunch".into());
			save(&directory, &record).await?;
			response(json!({"search":brief(&record),"launch_uncertain":true}))
		}
	}
}

pub async fn search_results(owner: &str, params: SearchResultsParams) -> Result<String> {
	let limit = page_limit(params.limit)?;
	let cursor = params.cursor.unwrap_or(0);
	if cursor > 1000 {
		bail!("invalid search cursor");
	}
	let _guard = lock().lock().await;
	let directory = directory().await?;
	let mut record = owned(&directory, owner, &params.search_id).await?;
	if record.state == "interrupted" {
		return response(
			json!({"search":brief(&record),"snapshot_ready":false,"results":[],"next_cursor":null}),
		);
	}
	let mut requested_limit = limit;
	let native = loop {
		let native = rpc(
			&record,
			"results",
			json!({"cursor":cursor,"limit":requested_limit}),
		)
		.await?;
		let text = serde_json::to_string(&json!({"search":brief(&record),"snapshot":native}))?;
		if wire_size(&text)? <= MAX_PAGE_BYTES - 1024 || requested_limit == 1 {
			break native;
		}
		requested_limit = (requested_limit / 2).max(1);
	};
	let state = native["state"]
		.as_str()
		.ok_or_else(|| anyhow!("invalid native search state"))?;
	if !TERMINAL.contains(&state) && state != "running" {
		bail!("invalid native search state");
	}
	record.state = state.into();
	record.reason = native["reason"].as_str().map(str::to_owned);
	save(&directory, &record).await?;
	response(json!({"search":brief(&record),"snapshot":native}))
}

pub async fn search_list(owner: &str, params: SearchListParams) -> Result<String> {
	validate_owner(owner)?;
	let limit = page_limit(params.limit)? as usize;
	if params.after_id.as_deref().is_some_and(|id| !valid_id(id)) {
		bail!("invalid search list cursor");
	}
	let _guard = lock().lock().await;
	let directory = directory().await?;
	let all = records(&directory).await?;
	let owned: Vec<_> = all
		.iter()
		// Revoked hosts/roots must not leak even terminal or interrupted receipt metadata.
		.filter(|r| {
			r.owner == owner
				&& pinned_host(r).is_ok()
				&& params.after_id.as_ref().is_none_or(|id| &r.id > id)
		})
		.collect();
	let mut page = Vec::new();
	for record in owned.iter().take(limit) {
		page.push(brief(record));
		let trial = serde_json::to_string(&json!({"searches":page}))?;
		if page.len() > 1 && wire_size(&trial)? > MAX_PAGE_BYTES - 1024 {
			page.pop();
			break;
		}
	}
	let next = if owned.len() > page.len() {
		page.last().map(|r| r["search_id"].clone())
	} else {
		None
	};
	response(json!({"searches":page,"next_after_id":next,"session_resume_after_restart":false}))
}

pub async fn search_stop(owner: &str, params: SearchRefParams) -> Result<String> {
	let _guard = lock().lock().await;
	let directory = directory().await?;
	let mut record = owned(&directory, owner, &params.search_id).await?;
	if TERMINAL.contains(&record.state.as_str()) {
		return response(
			json!({"search":brief(&record),"stop_requested":false,"already_terminal":true}),
		);
	}
	let native = rpc(&record, "stop", json!({})).await?;
	if apply_native_terminal(&mut record, &native) {
		save(&directory, &record).await?;
	}
	response(
		json!({"search":brief(&record),"native":native,"confirmation":"poll search_results for terminal cancellation receipt"}),
	)
}

#[cfg(test)]
#[path = "search_jobs_tests.rs"]
mod tests;
