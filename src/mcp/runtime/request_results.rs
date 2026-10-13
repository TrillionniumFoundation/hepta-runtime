// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded original native results for three reviewed credential-free DTO tools.
//! Request parameters, caller-selected identities, arbitrary output and errors are never stored.
use anyhow::{anyhow, bail, Result};
use rmcp::{
	model::{CallToolResponse, CallToolResult, ErrorData, MetaObject},
	schemars,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
	fs::File,
	io::{Read, Write},
	path::{Path, PathBuf},
	sync::{Mutex, OnceLock},
};

use super::{
	config::runtime_config,
	request_audit::{self, RequestIdentity},
};

const MAX_GLOBAL: usize = 512;
const MAX_OWNER: usize = 128;
const MAX_RESULT_BYTES: usize = 64 * 1024;
const MAX_RECORD_BYTES: usize = 96 * 1024;
const MAX_PAGE_BYTES: usize = 64 * 1024;
const STORE_NAME: &str = "request-results";
pub const ID_META: &str = "io.hepta.runtime/request-v8";
pub const ACK_META: &str = "io.hepta.runtime/retention-v8";
static STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestStatusParams {
	/// Exact server-generated request id from response metadata or owned history.
	pub request_id: String,
}
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestResultParams {
	/// Exact server-generated request id; never a process id or caller-selected owner.
	pub request_id: String,
	/// Independent byte offset into the immutable original native result JSON; default 0.
	#[serde(default)]
	pub offset: Option<u32>,
	/// At most 16384 original bytes per page; default 16384.
	#[serde(default)]
	pub limit: Option<u16>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResultState {
	Unknown,
	Stored,
	Overflow,
	RefusedDto,
	NotCompleted,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
	request_id: String,
	owner: String,
	tool_name: String,
	accepted_unix_ms: u128,
	policy_binding: String,
	state: ResultState,
	payload_base64: Option<String>,
	payload_bytes: Option<usize>,
	payload_sha256: Option<String>,
}
pub struct ResultIntent {
	directory: File,
	root: PathBuf,
	record: Record,
}

pub fn eligible(tool: &str) -> bool {
	matches!(tool, "host_list" | "host_health" | "effective_config")
}
fn valid_id(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_tool(value: &str) -> bool {
	matches!(value, "host_list" | "host_health" | "effective_config")
}
fn store_lock() -> Result<std::sync::MutexGuard<'static, ()>> {
	STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("result state unavailable"))
}
fn new_id() -> Result<String> {
	let mut data = [0u8; 32];
	File::open("/dev/urandom")?.read_exact(&mut data)?;
	Ok(data.iter().map(|b| format!("{b:02x}")).collect())
}
fn digest(data: &[u8]) -> String {
	Sha256::digest(data)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}
pub(crate) fn policy_binding() -> Result<String> {
	let mut hash = Sha256::new();
	hash.update(b"hepta-runtime/result-policy/v1\0");
	hash.update(serde_json::to_vec(runtime_config()?)?);
	Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
fn base64(data: &[u8]) -> String {
	const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
	for row in data.chunks(3) {
		let n = ((row[0] as u32) << 16)
			| ((row.get(1).copied().unwrap_or(0) as u32) << 8)
			| row.get(2).copied().unwrap_or(0) as u32;
		out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
		out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
		out.push(if row.len() > 1 {
			ALPHABET[((n >> 6) & 63) as usize] as char
		} else {
			'='
		});
		out.push(if row.len() > 2 {
			ALPHABET[(n & 63) as usize] as char
		} else {
			'='
		});
	}
	out
}
fn unbase64(text: &str) -> Result<Vec<u8>> {
	if text.len() > MAX_RESULT_BYTES.div_ceil(3) * 4 || !text.len().is_multiple_of(4) {
		bail!("retained bytes refused");
	}
	fn value(b: u8) -> Option<u32> {
		match b {
			b'A'..=b'Z' => Some((b - b'A') as u32),
			b'a'..=b'z' => Some((b - b'a' + 26) as u32),
			b'0'..=b'9' => Some((b - b'0' + 52) as u32),
			b'+' => Some(62),
			b'/' => Some(63),
			_ => None,
		}
	}
	let mut output = Vec::new();
	for row in text.as_bytes().as_chunks::<4>().0 {
		let a = value(row[0]).ok_or_else(|| anyhow!("retained bytes refused"))?;
		let b = value(row[1]).ok_or_else(|| anyhow!("retained bytes refused"))?;
		let c = if row[2] == b'=' {
			0
		} else {
			value(row[2]).ok_or_else(|| anyhow!("retained bytes refused"))?
		};
		let d = if row[3] == b'=' {
			0
		} else {
			value(row[3]).ok_or_else(|| anyhow!("retained bytes refused"))?
		};
		let n = (a << 18) | (b << 12) | (c << 6) | d;
		output.push((n >> 16) as u8);
		if row[2] != b'=' {
			output.push((n >> 8) as u8);
		}
		if row[3] != b'=' {
			output.push(n as u8);
		}
	}
	if output.len() > MAX_RESULT_BYTES || base64(&output) != text {
		bail!("retained bytes refused");
	}
	Ok(output)
}
fn keys(value: &Value, expected: &[&str]) -> bool {
	value.as_object().is_some_and(|m| {
		m.len() == expected.len() && expected.iter().all(|key| m.contains_key(*key))
	})
}
fn safe_dto(tool: &str, result: &CallToolResult) -> Result<bool> {
	let wire = serde_json::to_value(result)?;
	if result.is_error == Some(true)
		|| result.structured_content.is_some()
		|| result.content.len() != 1
	{
		return Ok(false);
	}
	if !wire["_meta"]
		.as_object()
		.is_some_and(|m| m.len() == 1 && m.contains_key(ID_META))
	{
		return Ok(false);
	}
	let marker = &wire["_meta"][ID_META];
	if !keys(
		marker,
		&["request_id", "automatic_retry", "delivery_proven"],
	) || marker["request_id"].as_str().is_none_or(|id| !valid_id(id))
		|| marker["automatic_retry"] != false
		|| marker["delivery_proven"] != false
	{
		return Ok(false);
	}
	let content = &wire["content"][0];
	if !keys(content, &["type", "text"]) || content["type"] != "text" {
		return Ok(false);
	}
	let Some(text) = content["text"].as_str() else {
		return Ok(false);
	};
	let parsed: Value = serde_json::from_str(text)?;
	match tool {
		"host_list" => {
			let expected: Value = serde_json::from_str(&super::inspect::host_list()?)?;
			Ok(parsed == expected
				&& keys(&parsed, &["hosts"])
				&& parsed["hosts"].as_array().is_some_and(|hosts| {
					hosts.len() <= 256
						&& hosts.iter().all(|h| {
							keys(
								h,
								&[
									"name",
									"platform",
									"execution_mode",
									"operator_tools",
									"allow_execute",
									"allow_pty",
									"allow_write",
									"privileged_actions",
								],
							)
						})
				}))
		}
		"effective_config" => {
			let expected: Value = serde_json::from_str(
				&super::effective_config::effective_config(Default::default())?,
			)?;
			Ok(parsed == expected
				&& keys(
					&parsed,
					&[
						"schema",
						"scope",
						"semantics",
						"redaction",
						"policy_mutation_supported",
						"target_probe_performed",
						"controller",
						"hosts",
						"limits",
					],
				) && keys(
				&parsed["controller"],
				&["workspace_root_count", "file_workspace_roots_configured"],
			) && keys(
				&parsed["limits"],
				&[
					"maximum_summary_host_entries",
					"maximum_summary_response_bytes",
				],
			) && parsed["hosts"].as_array().is_some_and(|hosts| {
				hosts.len() <= 256
					&& hosts.iter().all(|h| {
						keys(
							h,
							&[
								"alias",
								"platform",
								"execution_mode",
								"permissions",
								"file_api",
								"named_privileged_action_count",
								"checkpoint_pin_configured",
							],
						) && keys(
							&h["permissions"],
							&[
								"allow_execute",
								"allow_pty",
								"allow_write",
								"allow_job_network",
								"allow_detached_fallback",
							],
						) && keys(
							&h["file_api"],
							&[
								"read_root_count",
								"write_root_count",
								"read_paths_configured",
								"write_paths_authorized_and_configured",
							],
						)
					})
			}))
		}
		"host_health" => {
			let Some(alias) = parsed["host"].as_str() else {
				return Ok(false);
			};
			let Ok(host) = runtime_config()?.host(alias) else {
				return Ok(false);
			};
			let healthy = parsed["status"] == "healthy";
			Ok(keys(&parsed,&["schema","host","platform","transport","status","reachable","authenticated","ssh_roundtrip_ms","timeout_ms","measurement","diagnostics_redacted"]) &&
			parsed["schema"]=="hepta-host-health-v1" && parsed["transport"]=="ssh" && parsed["platform"]==serde_json::to_value(host.platform)? &&
			["healthy","ssh_failed","invalid_response","transport_error","timeout"].iter().any(|v|parsed["status"]==*v) &&
			parsed["reachable"]==healthy && parsed["authenticated"]==healthy && parsed["diagnostics_redacted"]==true &&
			parsed["timeout_ms"]==10000 && parsed["ssh_roundtrip_ms"].as_f64().is_some_and(|v|v.is_finite()&&(0.0..=60000.0).contains(&v)) &&
			parsed["measurement"]=="SSH invocation roundtrip including connection setup or reuse, authentication, remote shell startup and fixed response; not ICMP RTT.")
		}
		_ => Ok(false),
	}
}

fn identity_value(id: &str) -> Value {
	json!({"request_id":id,"automatic_retry":false,"delivery_proven":false})
}
pub fn exposes_identity(tool: &str) -> bool {
	eligible(tool)
		|| matches!(
			tool,
			"request_status" | "request_result" | "request_start" | "request_cancel"
		)
}
/// Preview the largest fixed acknowledgement before any result is retained.
/// DTO methods are read-only; an over-cap result becomes an explicit same-id refusal.
pub fn reserve_final_wire(result: &mut Result<CallToolResponse, ErrorData>, tool: &str, id: &str) {
	let cap = match tool {
		"effective_config" => 256 * 1024,
		"request_status" | "request_result" | "request_start" | "request_cancel" => 64 * 1024,
		_ => return,
	};
	let mut candidate = result.clone();
	attach_ack(&mut candidate, "durability_unknown_not_dispatched", false);
	let too_large = match candidate {
		Ok(CallToolResponse::Complete(ref value)) => {
			serde_json::to_vec(value).map_or(true, |v| v.len() > cap)
		}
		_ => false,
	};
	if too_large {
		*result = Err(ErrorData::internal_error(
			"read-only original result exceeds final wire budget; original result was not retained",
			None,
		));
		attach_identity(result, id);
	}
}
pub fn attach_identity(result: &mut Result<CallToolResponse, ErrorData>, id: &str) {
	let mut marker = identity_value(id);
	match result {
		Ok(CallToolResponse::Complete(value)) => {
			let meta = value.meta.get_or_insert_with(MetaObject::new);
			if let Some(original) = meta.remove(ID_META) {
				marker["original_metadata"] = original;
			}
			meta.insert(ID_META.into(), marker);
		}
		Err(error) => {
			let original = error.data.take();
			let mut data = match original {
				Some(Value::Object(mut value)) => {
					if let Some(prior) = value.remove(ID_META) {
						marker["original_metadata"] = prior;
					}
					Value::Object(value)
				}
				Some(value) => json!({"original_error_data":value}),
				None => json!({}),
			};
			data[ID_META] = marker;
			error.data = Some(data);
		}
		_ => {}
	}
}
pub fn attach_ack(
	result: &mut Result<CallToolResponse, ErrorData>,
	state: &str,
	audit_durable: bool,
) {
	let ack = json!({"result_state":state,"audit_completion_durable":audit_durable,
		"semantics":"native_generated_result_before_retention_ack_and_transport_normalization; delivery unproven","automatic_retry":false});
	match result {
		Ok(CallToolResponse::Complete(value)) => {
			let meta = value.meta.get_or_insert_with(MetaObject::new);
			let mut ack = ack;
			if let Some(original) = meta.remove(ACK_META) {
				ack["original_metadata"] = original;
			}
			meta.insert(ACK_META.into(), ack);
		}
		Err(error) => {
			let mut ack = ack;
			let mut data = match error.data.take() {
				Some(Value::Object(mut value)) => {
					if let Some(original) = value.remove(ACK_META) {
						ack["original_metadata"] = original;
					}
					Value::Object(value)
				}
				Some(value) => json!({"original_error_data":value}),
				None => json!({}),
			};
			data[ACK_META] = ack;
			error.data = Some(data);
		}
		_ => {}
	}
}

#[cfg(unix)]
fn name(value: &str) -> Result<std::ffi::CString> {
	std::ffi::CString::new(value).map_err(|_| anyhow!("invalid private metadata component"))
}

#[cfg(unix)]
fn open_at(directory: &File, component: &str, flags: i32, mode: u32) -> Result<File> {
	use std::os::fd::{AsRawFd, FromRawFd};
	let component = name(component)?;
	let descriptor = unsafe {
		libc::openat(
			directory.as_raw_fd(),
			component.as_ptr(),
			flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			mode,
		)
	};
	if descriptor < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn private_directory(directory: &File) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	let metadata = directory.metadata()?;
	if !metadata.is_dir()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o700
	{
		bail!("private request audit directory refused");
	}
	Ok(())
}

#[cfg(unix)]
fn open_store(root: &Path) -> Result<File> {
	use std::os::fd::{AsRawFd, FromRawFd};
	let raw = root
		.to_str()
		.ok_or_else(|| anyhow!("request audit root is not UTF-8"))?;
	if !root.is_absolute() || raw.split('/').any(|part| part == "." || part == "..") {
		bail!("invalid request audit root");
	}
	let slash = name("/")?;
	let descriptor = unsafe {
		libc::open(
			slash.as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if descriptor < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let mut base = unsafe { File::from_raw_fd(descriptor) };
	for component in raw.split('/').filter(|part| !part.is_empty()) {
		base = open_at(&base, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	}
	let folder = name(STORE_NAME)?;
	let made = unsafe { libc::mkdirat(base.as_raw_fd(), folder.as_ptr(), 0o700) };
	if made < 0 {
		let error = std::io::Error::last_os_error();
		if error.kind() != std::io::ErrorKind::AlreadyExists {
			return Err(error.into());
		}
	} else {
		base.sync_all()?;
	}
	let directory = open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_directory(&directory)?;
	Ok(directory)
}

#[cfg(unix)]
fn validate_file(file: &File) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	let metadata = file.metadata()?;
	if !metadata.is_file()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o600
		|| metadata.nlink() != 1
		|| metadata.len() > MAX_RECORD_BYTES as u64
	{
		bail!("private request audit inode refused");
	}
	Ok(())
}

#[cfg(unix)]
fn read_record(directory: &File, filename: &str) -> Result<Record> {
	let mut file = open_at(directory, filename, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	validate_file(&file)?;
	let mut bytes = Vec::new();
	Read::by_ref(&mut file)
		.take((MAX_RECORD_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("request audit metadata size refused");
	}
	let record: Record = serde_json::from_slice(&bytes)?;
	if !valid_id(&record.request_id)
		|| !valid_id(&record.owner)
		|| !valid_tool(&record.tool_name)
		|| !valid_id(&record.policy_binding)
		|| filename != format!("{}.json", record.request_id)
	{
		bail!("request audit metadata identity refused");
	}
	match record.state {
		ResultState::Stored => {
			let payload = unbase64(
				record
					.payload_base64
					.as_deref()
					.ok_or_else(|| anyhow!("retained result refused"))?,
			)?;
			if record.payload_bytes != Some(payload.len())
				|| record.payload_sha256.as_deref() != Some(digest(&payload).as_str())
			{
				bail!("retained result integrity refused");
			}
		}
		_ if record.payload_base64.is_some()
			|| record.payload_bytes.is_some()
			|| record.payload_sha256.is_some() =>
		{
			bail!("retained result state refused")
		}
		_ => {}
	}
	Ok(record)
}

#[cfg(unix)]
fn directory_scan_result(has_entry: bool, error: i32) -> Result<bool> {
	if has_entry {
		return Ok(true);
	}
	if error != 0 {
		return Err(std::io::Error::from_raw_os_error(error).into());
	}
	Ok(false)
}

#[cfg(unix)]
fn scan_errno(reset: bool) -> Result<i32> {
	#[cfg(target_os = "linux")]
	{
		let pointer = unsafe { libc::__errno_location() };
		if reset {
			unsafe { *pointer = 0 };
		}
		Ok(unsafe { *pointer })
	}
	#[cfg(target_os = "macos")]
	{
		let pointer = unsafe { libc::__error() };
		if reset {
			unsafe { *pointer = 0 };
		}
		Ok(unsafe { *pointer })
	}
	#[cfg(not(any(target_os = "linux", target_os = "macos")))]
	{
		let _ = reset;
		bail!("private audit directory scan is unavailable on this platform")
	}
}

#[cfg(unix)]
fn entries(directory: &File) -> Result<Vec<Record>> {
	use std::os::fd::AsRawFd;
	// A fresh directory file description avoids a shared seek cursor between snapshots.
	let scan = open_at(directory, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let duplicate = unsafe { libc::dup(scan.as_raw_fd()) };
	if duplicate < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let pointer = unsafe { libc::fdopendir(duplicate) };
	if pointer.is_null() {
		unsafe { libc::close(duplicate) };
		return Err(std::io::Error::last_os_error().into());
	}
	struct DirectoryStream(*mut libc::DIR);
	impl Drop for DirectoryStream {
		fn drop(&mut self) {
			unsafe { libc::closedir(self.0) };
		}
	}
	let stream = DirectoryStream(pointer);
	let mut names = Vec::new();
	loop {
		scan_errno(true)?;
		let item = unsafe { libc::readdir(stream.0) };
		if !directory_scan_result(!item.is_null(), scan_errno(false)?)? {
			break;
		}
		let filename = unsafe { std::ffi::CStr::from_ptr((*item).d_name.as_ptr()) }.to_str()?;
		if filename == "." || filename == ".." {
			continue;
		}
		if names.len() >= MAX_GLOBAL + 32 {
			bail!("request audit retention invariant exceeded");
		}
		names.push(filename.to_owned());
	}
	// Remove only verified private staging inodes after an interrupted publication.
	// This cannot remove an active writer because all mutations use STORE_LOCK.
	for filename in names.iter().filter(|value| value.starts_with('.')) {
		cleanup_staging(directory, filename)?;
	}
	let mut result = Vec::new();
	for filename in names.iter().filter(|value| !value.starts_with('.')) {
		if result.len() >= MAX_GLOBAL || !filename.ends_with(".json") {
			bail!("unexpected private request audit entry");
		}
		result.push(read_record(directory, filename)?);
	}
	result.sort_by(|left, right| {
		(left.accepted_unix_ms, &left.request_id).cmp(&(right.accepted_unix_ms, &right.request_id))
	});
	Ok(result)
}

#[cfg(unix)]
fn cleanup_staging(directory: &File, filename: &str) -> Result<()> {
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::MetadataExt;
	let value = filename
		.strip_prefix('.')
		.and_then(|value| value.strip_suffix(".tmp"))
		.ok_or_else(|| anyhow!("unexpected private audit staging entry"))?;
	let (id, nonce) = value
		.split_once('-')
		.ok_or_else(|| anyhow!("unexpected private audit staging identity"))?;
	if !valid_id(id) || !valid_id(nonce) {
		bail!("unexpected private audit staging identity");
	}
	let file = open_at(directory, filename, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	let metadata = file.metadata()?;
	if !metadata.is_file()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o600
		|| !(1..=2).contains(&metadata.nlink())
		|| metadata.len() > MAX_RECORD_BYTES as u64
	{
		bail!("audit staging inode refused");
	}
	if metadata.nlink() == 2 {
		let published = open_at(
			directory,
			&format!("{id}.json"),
			libc::O_RDONLY | libc::O_NONBLOCK,
			0,
		)?;
		let target = published.metadata()?;
		if target.dev() != metadata.dev() || target.ino() != metadata.ino() {
			bail!("audit staging hard-link binding refused");
		}
	}
	let component = name(filename)?;
	if unsafe { libc::unlinkat(directory.as_raw_fd(), component.as_ptr(), 0) } < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	directory.sync_all()?;
	Ok(())
}

#[cfg(unix)]
fn remove_record(directory: &File, id: &str) -> Result<()> {
	use std::os::fd::AsRawFd;
	let filename = name(&format!("{id}.json"))?;
	if unsafe { libc::unlinkat(directory.as_raw_fd(), filename.as_ptr(), 0) } < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	directory.sync_all()?;
	Ok(())
}

#[cfg(unix)]
fn save(directory: &File, record: &Record, replacing: bool) -> Result<()> {
	use std::os::fd::AsRawFd;
	private_directory(directory)?;
	let filename = format!("{}.json", record.request_id);
	if replacing {
		let existing = read_record(directory, &filename)?;
		if existing.owner != record.owner
			|| existing.tool_name != record.tool_name
			|| existing.accepted_unix_ms != record.accepted_unix_ms
		{
			bail!("request audit receipt binding changed");
		}
	}
	let bytes = serde_json::to_vec(record)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("request audit record size refused");
	}
	let temporary = format!(".{}-{}.tmp", record.request_id, new_id()?);
	let mut file = open_at(
		directory,
		&temporary,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	validate_file(&file)?;
	let persisted = (|| -> Result<()> {
		file.write_all(&bytes)?;
		file.sync_all()?;
		drop(file);
		let temp = name(&temporary)?;
		let target = name(&filename)?;
		if replacing {
			if unsafe {
				libc::renameat(
					directory.as_raw_fd(),
					temp.as_ptr(),
					directory.as_raw_fd(),
					target.as_ptr(),
				)
			} < 0
			{
				return Err(std::io::Error::last_os_error().into());
			}
		} else {
			if unsafe {
				libc::linkat(
					directory.as_raw_fd(),
					temp.as_ptr(),
					directory.as_raw_fd(),
					target.as_ptr(),
					0,
				)
			} < 0
			{
				return Err(std::io::Error::last_os_error().into());
			}
			if unsafe { libc::unlinkat(directory.as_raw_fd(), temp.as_ptr(), 0) } < 0 {
				return Err(std::io::Error::last_os_error().into());
			}
		}
		directory.sync_all()?;
		Ok(())
	})();
	if persisted.is_err() {
		if let Ok(temp) = name(&temporary) {
			unsafe { libc::unlinkat(directory.as_raw_fd(), temp.as_ptr(), 0) };
		}
	}
	persisted
}

#[cfg(unix)]
fn admit_at(root: &Path, identity: RequestIdentity, binding: String) -> Result<ResultIntent> {
	if !valid_id(&identity.request_id)
		|| !valid_id(&identity.owner)
		|| !eligible(&identity.tool_name)
		|| !valid_id(&binding)
	{
		bail!("result admission unavailable");
	}
	let _guard = store_lock()?;
	let directory = open_store(root)?;
	let retained = request_audit::retained_ids_at(root)?;
	if !retained.contains(&identity.request_id) {
		bail!("result admission unavailable");
	}
	let mut records = entries(&directory)?;
	for record in records.iter().filter(|r| !retained.contains(&r.request_id)) {
		remove_record(&directory, &record.request_id)?;
	}
	records.retain(|r| retained.contains(&r.request_id));
	if records.len() >= MAX_GLOBAL
		|| records.iter().filter(|r| r.owner == identity.owner).count() >= MAX_OWNER
	{
		bail!("result retention quota unavailable");
	}
	let record = Record {
		request_id: identity.request_id,
		owner: identity.owner,
		tool_name: identity.tool_name,
		accepted_unix_ms: identity.accepted_unix_ms,
		policy_binding: binding,
		state: ResultState::Unknown,
		payload_base64: None,
		payload_bytes: None,
		payload_sha256: None,
	};
	save(&directory, &record, false)?;
	Ok(ResultIntent {
		directory,
		root: root.into(),
		record,
	})
}
#[cfg(not(unix))]
fn admit_at(_root: &Path, _identity: RequestIdentity, _binding: String) -> Result<ResultIntent> {
	bail!("private result retention requires Unix");
}
pub(crate) async fn admit(identity: RequestIdentity) -> Result<ResultIntent> {
	let root = runtime_config()?.state_dir.clone();
	let binding = policy_binding()?;
	tokio::task::spawn_blocking(move || admit_at(&root, identity, binding))
		.await
		.map_err(|_| anyhow!("result admission unavailable; dispatch refused"))?
}
#[cfg(unix)]
fn complete_sync(mut intent: ResultIntent, result: Option<CallToolResult>) -> Result<&'static str> {
	use std::os::unix::fs::MetadataExt;
	let _guard = store_lock()?;
	let current = open_store(&intent.root)?;
	let old = intent.directory.metadata()?;
	let fresh = current.metadata()?;
	if old.dev() != fresh.dev() || old.ino() != fresh.ino() {
		bail!("result storage changed; existing request identity retained");
	}
	let state = if let Some(result) = result {
		let bytes = serde_json::to_vec(&result)?;
		let mut final_preview = Ok(result.clone().into());
		attach_ack(&mut final_preview, "stored", false);
		let final_bytes = match final_preview {
			Ok(CallToolResponse::Complete(value)) => serde_json::to_vec(&value)?.len(),
			_ => MAX_RESULT_BYTES + 1,
		};
		if bytes.len() > MAX_RESULT_BYTES || final_bytes > MAX_RESULT_BYTES {
			intent.record.state = ResultState::Overflow;
			"overflow"
		} else if result
			.meta
			.as_ref()
			.and_then(|m| m.get(ID_META))
			.and_then(|v| v.get("request_id"))
			.and_then(Value::as_str)
			!= Some(intent.record.request_id.as_str())
			|| !safe_dto(&intent.record.tool_name, &result).unwrap_or(false)
		{
			intent.record.state = ResultState::RefusedDto;
			"not_retained_dto"
		} else {
			intent.record.payload_bytes = Some(bytes.len());
			intent.record.payload_sha256 = Some(digest(&bytes));
			intent.record.payload_base64 = Some(base64(&bytes));
			intent.record.state = ResultState::Stored;
			"stored"
		}
	} else {
		intent.record.state = ResultState::NotCompleted;
		"not_completed"
	};
	save(&intent.directory, &intent.record, true)?;
	Ok(state)
}
#[cfg(not(unix))]
fn complete_sync(_intent: ResultIntent, _result: Option<CallToolResult>) -> Result<&'static str> {
	bail!("private result retention requires Unix");
}
pub(crate) async fn complete(
	intent: ResultIntent,
	result: Option<CallToolResult>,
) -> Result<&'static str> {
	tokio::task::spawn_blocking(move || complete_sync(intent, result))
		.await
		.map_err(|_| {
			anyhow!("result completion durability unknown; original request identity retained")
		})?
}
fn page(value: Value) -> Result<String> {
	let text = serde_json::to_string(&value)?;
	let wire = CallToolResult::success(vec![rmcp::model::ContentBlock::text(&text)]);
	if serde_json::to_vec(&wire)?.len() > MAX_PAGE_BYTES {
		bail!("request receipt page exceeds wire limit");
	}
	Ok(text)
}
#[cfg(unix)]
fn lookup_at(root: &Path, identity: &RequestIdentity, binding: &str) -> Result<Option<Record>> {
	let _guard = store_lock()?;
	let directory = open_store(root)?;
	let filename = format!("{}.json", identity.request_id);
	let record = match read_record(&directory, &filename) {
		Ok(record) => record,
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
		{
			return Ok(None)
		}
		Err(_) => bail!("request result unavailable to this scope or current policy"),
	};
	if record.owner != identity.owner
		|| record.tool_name != identity.tool_name
		|| record.accepted_unix_ms != identity.accepted_unix_ms
		|| record.policy_binding != binding
	{
		bail!("request result unavailable to this scope or current policy");
	}
	Ok(Some(record))
}
#[cfg(not(unix))]
fn lookup_at(_root: &Path, _identity: &RequestIdentity, _binding: &str) -> Result<Option<Record>> {
	bail!("private result retention requires Unix");
}
fn result_state(record: Option<&Record>, tool: &str) -> &'static str {
	match record.map(|r| &r.state) {
		Some(ResultState::Stored) => "stored",
		Some(ResultState::Unknown) => "unknown",
		Some(ResultState::Overflow) => "overflow",
		Some(ResultState::RefusedDto) => "not_retained_dto",
		Some(ResultState::NotCompleted) => "not_completed",
		None if eligible(tool) => "not_retained_legacy_or_unavailable",
		None => "not_retained_policy",
	}
}
pub async fn request_status(owner: &str, params: RequestStatusParams) -> Result<String> {
	let observation = request_audit::observation(owner, &params.request_id).await?;
	let identity = observation.identity;
	let tool = identity.tool_name.clone();
	let root = runtime_config()?.state_dir.clone();
	let binding = policy_binding()?;
	let record = tokio::task::spawn_blocking(move || lookup_at(&root, &identity, &binding))
		.await
		.map_err(|_| anyhow!("request result unavailable to this scope or current policy"))??;
	page(
		json!({"request_id":params.request_id,"tool_name":tool,"dispatch_state":observation.state,
		"elapsed_ms":observation.elapsed_ms,"result_state":result_state(record.as_ref(),&tool),
		"result_bytes":record.as_ref().and_then(|r|r.payload_bytes),
		"retained_tools":["host_list","host_health","effective_config"],
		"metadata_lookup_does_not_prove_delivery_or_business_success":true,
		"automatic_retry":false,"early_return_async_start_supported":false}),
	)
}
pub async fn request_result(owner: &str, params: RequestResultParams) -> Result<String> {
	let limit = params.limit.unwrap_or(16384) as usize;
	if !(1..=16384).contains(&limit) {
		bail!("request result page limit must be 1..16384");
	}
	let observation = request_audit::observation(owner, &params.request_id).await?;
	let identity = observation.identity;
	let root = runtime_config()?.state_dir.clone();
	let binding = policy_binding()?;
	let record = tokio::task::spawn_blocking(move || lookup_at(&root, &identity, &binding))
		.await
		.map_err(|_| anyhow!("request result unavailable to this scope or current policy"))??
		.ok_or_else(|| anyhow!("original result was not retained; never replay automatically"))?;
	if record.state != ResultState::Stored {
		bail!("original result unavailable in retained state; never replay automatically");
	}
	let bytes = unbase64(
		record
			.payload_base64
			.as_deref()
			.ok_or_else(|| anyhow!("retained result refused"))?,
	)?;
	if record.payload_bytes != Some(bytes.len())
		|| record.payload_sha256.as_deref() != Some(digest(&bytes).as_str())
	{
		bail!("retained result integrity refused");
	}
	let offset = params.offset.unwrap_or(0) as usize;
	if offset > bytes.len() {
		bail!("request result offset exceeds retained length");
	}
	let end = offset.saturating_add(limit).min(bytes.len());
	page(
		json!({"request_id":params.request_id,"offset":offset,"next_offset":end,"total_bytes":bytes.len(),
		"eof":end==bytes.len(),"data_base64":base64(&bytes[offset..end]),"result_sha256":record.payload_sha256,
		"format":"serialized_native_CallToolResult_with_request_identity_before_retention_ack_and_transport_normalization",
		"immutable_snapshot":true,"automatic_retry":false,"delivery_proven":false}),
	)
}

#[cfg(all(test, unix))]
#[path = "request_results_tests.rs"]
mod tests;
