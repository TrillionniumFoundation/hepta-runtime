// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One bounded Unix-socket exchange for an existing durable weight client job.
//!
//! This is transport only: requests and validated worker response bytes pass
//! through unchanged. It never loads a model or retries after a possible send.

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::rea_evidence::parse_unique_json;
use super::weight_config::{absolute_normal_path, valid_sha256};

const MAX_REQUEST_BYTES: usize = 64 * 1024 + 1;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PACKAGE_FILES: usize = 256;
const MAX_CLIENT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Args, Clone, Debug)]
pub struct WeightClientArgs {
	#[arg(long)]
	pub socket: PathBuf,
	#[arg(long)]
	pub session_id: String,
	#[arg(long)]
	pub worker_path: PathBuf,
	#[arg(long)]
	pub expected_worker_sha256: String,
	#[arg(long)]
	pub expected_package_sha256: Option<String>,
	#[arg(long)]
	pub expected_client_sha256: String,
	#[arg(long, default_value_t = 120_000)]
	pub timeout_ms: u64,
	#[arg(long, default_value_t = 30_000)]
	pub connect_timeout_ms: u64,
}

#[derive(Debug)]
struct ClientFailure {
	code: &'static str,
	message: String,
	uncertain: bool,
}

impl ClientFailure {
	fn new(code: &'static str, message: impl ToString, uncertain: bool) -> Self {
		Self {
			code,
			message: message.to_string().chars().take(1024).collect(),
			uncertain,
		}
	}

	fn frame(&self, request_id: Option<&str>) -> Result<Vec<u8>> {
		let mut frame = serde_json::to_vec(&json!({
			"id": request_id,
			"ok": false,
			"error": {
				"code": self.code,
				"message": self.message,
				"details": {
					"operation_state": if self.uncertain { "unknown" } else { "not_sent" },
					"automatic_retry": false,
					"observation": "weight_status/weight_read on the original request job"
				}
			}
		}))?;
		frame.push(b'\n');
		Ok(frame)
	}
}

type ClientResult<T> = std::result::Result<T, ClientFailure>;

#[derive(Debug)]
struct ClientResponse {
	frame: Vec<u8>,
	succeeded: bool,
}

fn digest_hex(bytes: &[u8]) -> String {
	let mut result = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		let _ = write!(result, "{byte:02x}");
	}
	result
}

fn valid_id(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 128
		&& value
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn validate_options(args: &WeightClientArgs) -> Result<()> {
	for path in [&args.socket, &args.worker_path] {
		if !path.to_str().is_some_and(absolute_normal_path) {
			bail!("weight client paths must be absolute and normalized UTF-8");
		}
	}
	if !valid_id(&args.session_id)
		|| !(1..=600_000).contains(&args.timeout_ms)
		|| !(1..=30_000).contains(&args.connect_timeout_ms)
		|| !valid_sha256(&args.expected_client_sha256)
		|| !valid_sha256(&args.expected_worker_sha256)
		|| args
			.expected_package_sha256
			.as_ref()
			.is_some_and(|pin| !valid_sha256(pin))
	{
		bail!("invalid weight client identity, SHA-256 pin or timeout budget");
	}
	if args.socket.as_os_str().len() >= 104 {
		bail!("Unix socket path must be shorter than 104 bytes");
	}
	Ok(())
}

/// EOF is part of the one-exchange protocol. A second frame or an unterminated
/// reply is rejected; the response deadline also bounds a peer that never closes.
async fn read_frame<R: AsyncRead + Unpin>(input: &mut R, maximum: usize) -> Result<Vec<u8>> {
	let mut bytes = Vec::new();
	input
		.take((maximum + 1) as u64)
		.read_to_end(&mut bytes)
		.await?;
	if bytes.is_empty()
		|| bytes.len() > maximum
		|| bytes.last() != Some(&b'\n')
		|| bytes[..bytes.len() - 1].contains(&b'\n')
	{
		bail!("expected exactly one newline-terminated JSON frame within {maximum} bytes");
	}
	Ok(bytes)
}

fn request_identity(frame: &[u8], session: &str) -> Result<String> {
	let value = parse_unique_json(frame)?;
	let object = value
		.as_object()
		.ok_or_else(|| anyhow!("weight request must be a JSON object"))?;
	let id = value["id"]
		.as_str()
		.filter(|id| valid_id(id))
		.ok_or_else(|| anyhow!("weight request identity is invalid"))?;
	if object.len() != 4
		|| value["session_id"] != session
		|| !value["params"].is_object()
		|| !matches!(
			value["op"].as_str(),
			Some(
				"open"
					| "inspect" | "probe"
					| "intervene" | "analyze"
					| "patch" | "seal"
					| "query" | "close"
			)
		) {
		bail!("weight request session, operation or fields differ from the fixed contract");
	}
	Ok(id.to_owned())
}

fn response_ok(frame: &[u8], request_id: &str) -> Result<bool> {
	if frame.len() > MAX_RESPONSE_BYTES {
		bail!("weight response exceeds its byte budget");
	}
	let response = parse_unique_json(frame)?;
	let object = response
		.as_object()
		.ok_or_else(|| anyhow!("weight response must be a JSON object"))?;
	if response["id"] != request_id || object.len() != 3 {
		bail!("weight response identity or envelope differs from the original request");
	}
	match response["ok"].as_bool() {
		Some(true) if response["result"].is_object() && !object.contains_key("error") => Ok(true),
		Some(false)
			if !object.contains_key("result")
				&& response["error"]["code"].is_string()
				&& response["error"]["message"].is_string()
				&& response["error"]["details"].is_object() =>
		{
			Ok(false)
		}
		_ => bail!("weight response has an invalid result/error envelope"),
	}
}

async fn hash_file(path: &Path, maximum: u64) -> Result<(String, u64)> {
	let mut file = tokio::fs::File::open(path).await?;
	let before = file.metadata().await?;
	if !before.is_file() || before.len() > maximum {
		bail!("identity input is not a regular file within its byte budget");
	}
	let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
	let mut chunk = vec![0u8; before.len().clamp(1, 1024 * 1024) as usize];
	let mut consumed = 0u64;
	loop {
		let count = file.read(&mut chunk).await?;
		if count == 0 {
			break;
		}
		consumed = consumed
			.checked_add(count as u64)
			.filter(|size| *size <= maximum)
			.ok_or_else(|| anyhow!("identity input grew beyond its byte budget"))?;
		hasher.update(&chunk[..count]);
	}
	let after = file.metadata().await?;
	let selected = tokio::fs::metadata(path).await?;
	if consumed != before.len()
		|| !same_identity(&before, &after)
		|| !same_identity(&before, &selected)
	{
		bail!("identity input changed while hashing");
	}
	Ok((digest_hex(hasher.finish().as_ref()), consumed))
}

fn same_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		left.dev() == right.dev()
			&& left.ino() == right.ino()
			&& left.len() == right.len()
			&& left.mtime() == right.mtime()
			&& left.mtime_nsec() == right.mtime_nsec()
			&& left.ctime() == right.ctime()
			&& left.ctime_nsec() == right.ctime_nsec()
	}
	#[cfg(not(unix))]
	{
		left.len() == right.len() && left.modified().ok() == right.modified().ok()
	}
}

/// Match json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)
/// for the package's string-to-hex-digest dictionary, without importing Python.
fn ascii_json_string(text: &str) -> Result<String> {
	let json = serde_json::to_string(text)?;
	let mut output = String::new();
	for character in json.chars() {
		if character.is_ascii() && character != '\u{7f}' {
			output.push(character);
		} else {
			let mut units = [0u16; 2];
			for unit in character.encode_utf16(&mut units) {
				write!(&mut output, "\\u{unit:04x}")?;
			}
		}
	}
	Ok(output)
}

async fn package_files(root: &Path) -> Result<Vec<String>> {
	let mut files = Vec::new();
	let mut entries = tokio::fs::read_dir(root.join("weight_runtime")).await?;
	while let Some(entry) = entries.next_entry().await? {
		let name = entry
			.file_name()
			.into_string()
			.map_err(|_| anyhow!("worker package filename is not UTF-8"))?;
		if name.ends_with(".py") {
			files.push(format!("weight_runtime/{name}"));
			if files.len() >= MAX_PACKAGE_FILES {
				bail!("worker package has too many source files");
			}
		}
	}
	files.sort();
	Ok(files)
}

async fn package_digest(entry: &Path, entry_digest: &str, entry_size: u64) -> Result<String> {
	let root = entry
		.parent()
		.ok_or_else(|| anyhow!("worker path has no parent"))?;
	let filename = entry
		.file_name()
		.and_then(|name| name.to_str())
		.ok_or_else(|| anyhow!("worker filename is not UTF-8"))?;
	let names = package_files(root).await?;
	let mut digests = BTreeMap::from([(filename.to_owned(), entry_digest.to_owned())]);
	let mut total = entry_size;
	for name in &names {
		let (digest, size) = hash_file(&root.join(name), MAX_PACKAGE_BYTES - total).await?;
		total += size;
		digests.insert(name.clone(), digest);
	}
	if names != package_files(root).await? {
		bail!("worker package entries changed while hashing");
	}
	let mut canonical = String::from("{");
	for (index, (name, digest)) in digests.iter().enumerate() {
		if index > 0 {
			canonical.push(',');
		}
		write!(
			&mut canonical,
			"{}:{}",
			ascii_json_string(name)?,
			ascii_json_string(digest)?
		)?;
	}
	canonical.push('}');
	Ok(digest_hex(&Sha256::digest(canonical.as_bytes())))
}

async fn verify_pins(args: &WeightClientArgs) -> Result<()> {
	// On Linux this descriptor names the running executable's inode, even after
	// the configured deployment path is replaced; hashing that path would not.
	#[cfg(target_os = "linux")]
	let executable = PathBuf::from("/proc/self/exe");
	#[cfg(not(target_os = "linux"))]
	let executable = std::env::current_exe()?;
	let (actual, _) = hash_file(&executable, MAX_CLIENT_BYTES).await?;
	if actual != args.expected_client_sha256 {
		bail!("running native client SHA-256 differs from the installed profile");
	}
	let entry = tokio::fs::canonicalize(&args.worker_path).await?;
	let (worker, size) = hash_file(&entry, MAX_PACKAGE_BYTES).await?;
	if worker != args.expected_worker_sha256 {
		bail!("worker entry SHA-256 differs from the installed profile");
	}
	if let Some(expected) = &args.expected_package_sha256 {
		if package_digest(&entry, &worker, size).await? != *expected {
			bail!("worker package SHA-256 differs from the installed profile");
		}
	}
	Ok(())
}

#[cfg(unix)]
async fn connect(args: &WeightClientArgs) -> ClientResult<tokio::net::UnixStream> {
	use std::os::unix::fs::{FileTypeExt, MetadataExt};
	use tokio::time::{sleep_until, timeout_at, Instant};
	let deadline = Instant::now() + Duration::from_millis(args.connect_timeout_ms);
	loop {
		match tokio::fs::symlink_metadata(&args.socket).await {
			Ok(meta) => {
				// UID is process identity, not a caller-controlled profile field.
				let uid = unsafe { libc::getuid() };
				if !meta.file_type().is_socket() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
					return Err(ClientFailure::new(
						"PEER_DENIED",
						"worker socket is not private and same-UID",
						false,
					));
				}
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(ClientFailure::new("TRANSPORT_UNAVAILABLE", error, false)),
		}
		match timeout_at(deadline, tokio::net::UnixStream::connect(&args.socket)).await {
			Ok(Ok(stream)) => {
				let peer = stream
					.peer_cred()
					.map_err(|error| ClientFailure::new("PEER_DENIED", error, false))?;
				let uid = unsafe { libc::getuid() };
				if peer.uid() != uid {
					return Err(ClientFailure::new(
						"PEER_DENIED",
						"worker socket peer UID differs",
						false,
					));
				}
				return Ok(stream);
			}
			Ok(Err(error))
				if matches!(
					error.kind(),
					std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
				) => {}
			Ok(Err(error)) => {
				return Err(ClientFailure::new("TRANSPORT_UNAVAILABLE", error, false))
			}
			Err(_) => {
				return Err(ClientFailure::new(
					"CONNECT_TIMEOUT",
					"worker socket did not become available",
					false,
				))
			}
		}
		if Instant::now() >= deadline {
			return Err(ClientFailure::new(
				"CONNECT_TIMEOUT",
				"worker socket did not become available",
				false,
			));
		}
		sleep_until((Instant::now() + Duration::from_millis(50)).min(deadline)).await;
	}
}

#[cfg(unix)]
async fn exchange(
	args: &WeightClientArgs,
	request: &[u8],
	request_id: &str,
) -> ClientResult<ClientResponse> {
	let mut stream = connect(args).await?;
	let exchange = async {
		stream
			.write_all(request)
			.await
			.map_err(|error| ClientFailure::new("TRANSPORT_UNKNOWN", error, true))?;
		stream
			.shutdown()
			.await
			.map_err(|error| ClientFailure::new("TRANSPORT_UNKNOWN", error, true))?;
		let frame = read_frame(&mut stream, MAX_RESPONSE_BYTES)
			.await
			.map_err(|error| ClientFailure::new("PROTOCOL_ERROR", error, true))?;
		let succeeded = response_ok(&frame, request_id)
			.map_err(|error| ClientFailure::new("PROTOCOL_ERROR", error, true))?;
		Ok(ClientResponse { frame, succeeded })
	};
	tokio::time::timeout(Duration::from_millis(args.timeout_ms), exchange)
		.await
		.map_err(|_| {
			ClientFailure::new(
				"REQUEST_TIMEOUT_UNKNOWN",
				"client deadline expired; observe the original durable job and operation",
				true,
			)
		})?
}

#[cfg(not(unix))]
async fn exchange(
	_args: &WeightClientArgs,
	_request: &[u8],
	_request_id: &str,
) -> ClientResult<ClientResponse> {
	Err(ClientFailure::new(
		"TRANSPORT_UNAVAILABLE",
		"native weight clients require a qualified Unix host",
		false,
	))
}

/// Hidden CLI entry point. Return 0 only for an intact, matching successful
/// worker response; preserve error JSON on stdout before returning exit code 1.
pub async fn run_cli(args: WeightClientArgs) -> Result<i32> {
	let mut request_id = None;
	let result = async {
		validate_options(&args)
			.map_err(|error| ClientFailure::new("INVALID_ARGUMENT", error, false))?;
		let request = tokio::time::timeout(
			Duration::from_secs(5),
			read_frame(&mut tokio::io::stdin(), MAX_REQUEST_BYTES),
		)
		.await
		.map_err(|_| ClientFailure::new("MESSAGE_LIMIT", "stdin frame deadline expired", false))?
		.map_err(|error| ClientFailure::new("MESSAGE_LIMIT", error, false))?;
		let id = request_identity(&request, &args.session_id)
			.map_err(|error| ClientFailure::new("INVALID_REQUEST", error, false))?;
		request_id = Some(id.clone());
		tokio::time::timeout(Duration::from_secs(30), verify_pins(&args))
			.await
			.map_err(|_| {
				ClientFailure::new(
					"IDENTITY_MISMATCH",
					"code identity verification deadline expired",
					false,
				)
			})?
			.map_err(|error| ClientFailure::new("IDENTITY_MISMATCH", error, false))?;
		exchange(&args, &request, &id).await
	}
	.await;
	let (frame, exit_code) = match result {
		Ok(response) => (response.frame, if response.succeeded { 0 } else { 1 }),
		Err(error) => (error.frame(request_id.as_deref())?, 1),
	};
	let mut stdout = tokio::io::stdout();
	stdout
		.write_all(&frame)
		.await
		.context("write bounded weight client result")?;
	stdout.flush().await?;
	Ok(exit_code)
}

#[cfg(test)]
#[path = "weight_native_tests.rs"]
mod tests;
