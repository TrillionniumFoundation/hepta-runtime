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

//! One descriptor-free APK static request over a bounded binary frame.
//! The path is display metadata supplied by the parent; this worker never opens
//! it. Cryptographic preview and its older resource profile are independent.

#[cfg(not(test))]
use super::DEADLINE_MS;
use super::{Failure, MAX_BYTES, MAX_WORKER_REPLY, OP};
use crate::mcp::{rea_apk_signature, rea_worker_transport};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::io;
use std::io::Read;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
const MEMORY_BYTES: libc::rlim_t = 2 * 1024 * 1024 * 1024;
#[cfg(unix)]
const CPU_SECONDS: libc::rlim_t = 20;
const READ_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
	path: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
	input: Input,
	sha256: String,
	bytes: u64,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Reply {
	Report {
		report: Box<rea_apk_signature::ApkSignatureReport>,
		limitations: Vec<String>,
	},
	Failure {
		failure: rea_apk_signature::ApkInspectionError,
	},
}

fn validate_header(header: &Header) -> Result<usize> {
	if u128::from(header.bytes) > MAX_BYTES as u128 {
		bail!("APK static worker frame exceeds the admitted 512 MiB snapshot bound");
	}
	if header.sha256.len() != 64
		|| !header
			.sha256
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	{
		bail!("APK static worker header SHA-256 is not a complete lowercase digest");
	}
	if !std::path::Path::new(&header.input.path).is_absolute() || header.input.path.contains('\0') {
		bail!("APK static worker display path is not an admitted absolute local path");
	}
	usize::try_from(header.bytes).context("APK static worker snapshot length is not representable")
}

fn digest_hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// No payload allocation occurs before the header and fixed input bound pass.
fn read_frame(reader: &mut impl Read) -> Result<(Header, Vec<u8>)> {
	let mut length = [0_u8; 4];
	reader
		.read_exact(&mut length)
		.context("APK static worker header length is truncated")?;
	let length = u32::from_le_bytes(length) as usize;
	if length == 0 || length > rea_worker_transport::MAX_HEADER {
		bail!("APK static worker header exceeds its 64 KiB bound");
	}
	let mut encoded_header = vec![0_u8; length];
	reader
		.read_exact(&mut encoded_header)
		.context("APK static worker header is truncated")?;
	let header: Header = serde_json::from_slice(&encoded_header)
		.context("APK static worker header is not a strict input/sha256/bytes object")?;
	let length = validate_header(&header)?;
	let mut bytes = Vec::new();
	bytes
		.try_reserve_exact(length)
		.context("APK static worker cannot reserve snapshot memory")?;
	bytes.resize(length, 0);
	let mut hash = Sha256::new();
	for chunk in bytes.chunks_mut(READ_CHUNK_BYTES) {
		reader
			.read_exact(chunk)
			.context("APK static worker snapshot is truncated")?;
		hash.update(chunk);
	}
	let mut trailing = [0_u8; 1];
	if reader
		.read(&mut trailing)
		.context("APK static worker cannot establish frame EOF")?
		!= 0
	{
		bail!("APK static worker received trailing frame bytes");
	}
	if digest_hex(&hash.finalize()) != header.sha256 {
		bail!("APK static worker snapshot SHA-256 differs from its admitted identity");
	}
	Ok((header, bytes))
}

fn parse(header: &Header, bytes: &[u8]) -> Reply {
	match rea_apk_signature::inspect_static(bytes)
		.and_then(|inspection| rea_apk_signature::bind_static_path(inspection, &header.input.path))
	{
		Ok(inspection) => Reply::Report {
			report: Box::new(inspection.result),
			limitations: inspection.limitations,
		},
		Err(failure) => Reply::Failure { failure },
	}
}

/// Business refusals are complete typed JSON and exit successfully. Damaged
/// framing, resource installation, I/O and serialization failures return Err.
pub(super) fn serve_once() -> Result<()> {
	#[cfg(not(unix))]
	bail!("APK static isolation is not available on this platform");
	#[cfg(unix)]
	{
		rea_worker_transport::install_limits(MAX_WORKER_REPLY, MEMORY_BYTES, CPU_SECONDS)?;
		let mut stdin = io::stdin().lock();
		let (header, bytes) = read_frame(&mut stdin)?;
		drop(stdin);
		// No source reads, process creation or network access follow this point.
		crate::mcp::rea_seccomp::tighten_after_read()?;
		let reply = parse(&header, &bytes);
		drop(bytes);
		rea_worker_transport::write_json(io::stdout().lock(), &reply, MAX_WORKER_REPLY)
	}
}

#[cfg(not(test))]
pub(super) async fn inspect_isolated(
	path: &str,
	digest: &str,
	bytes: Arc<Vec<u8>>,
	cancellation: &CancellationToken,
	admission: Arc<super::runtime::effect_owner_fence::AdmissionPermit>,
) -> std::result::Result<Value, Failure> {
	if cancellation.is_cancelled() {
		return Err(Failure::cancelled(OP));
	}
	let header = Header {
		input: Input {
			path: path.to_owned(),
		},
		sha256: digest.to_owned(),
		bytes: bytes.len() as u64,
	};
	validate_header(&header).map_err(|error| Failure::output(OP, error.to_string()))?;
	let header =
		serde_json::to_vec(&header).map_err(|error| Failure::output(OP, error.to_string()))?;
	rea_worker_transport::inspect_frame(
		rea_worker_transport::WorkerSpec {
			operation: OP,
			reply_limit: MAX_WORKER_REPLY,
			deadline_ms: DEADLINE_MS,
		},
		"rea-apk-static-worker",
		header,
		bytes,
		cancellation,
		admission,
	)
	.await
}

// Unit builds use the same parser/binder without spawning the unit-test binary
// as a CLI. The generic guard is intentionally not a fence qualification; the
// actual AdmissionPermit and private worker owner are exercised by release gates.
#[cfg(test)]
pub(super) async fn inspect_isolated<A>(
	path: &str,
	digest: &str,
	bytes: Arc<Vec<u8>>,
	cancellation: &CancellationToken,
	_admission: Arc<A>,
) -> std::result::Result<Value, Failure> {
	if cancellation.is_cancelled() {
		return Err(Failure::cancelled(OP));
	}
	let header = Header {
		input: Input {
			path: path.to_owned(),
		},
		sha256: digest.to_owned(),
		bytes: bytes.len() as u64,
	};
	validate_header(&header).map_err(|error| Failure::output(OP, error.to_string()))?;
	if digest_hex(&Sha256::digest(bytes.as_slice())) != digest {
		return Err(Failure::output(
			OP,
			"APK static worker snapshot identity differs",
		));
	}
	serde_json::to_value(parse(&header, &bytes))
		.map_err(|error| Failure::output(OP, error.to_string()))
}

#[cfg(all(test, unix))]
#[path = "rea_apk_static_worker_tests.rs"]
mod tests;
