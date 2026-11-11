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

//! Controller-owned, fail-closed privileged-operation admission.
//!
//! The durable intent precedes the remote side-effect. A transport error after
//! entry is indeterminate and MUST NOT be replayed. An observed terminal result
//! can be served again without executing the operation a second time.
//! This is NOT a final-use authority issuer and does not attest the remote host.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
#[cfg(unix)]
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::sync::{Mutex, MutexGuard};

const LEDGER_VERSION: u8 = 1;
const MAX_RECORD_BYTES: u64 = 3 * 1024 * 1024;
const LOCK_SHARDS: usize = 256;
static OPERATION_LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
	version: u8,
	host: String,
	action: String,
	idempotency_key: String,
	request_digest: String,
	state: String,
	result: Option<Value>,
}

/// An entered operation keeps its admission mutex through the remote call.
pub struct Entered {
	_guard: MutexGuard<'static, ()>,
	path: PathBuf,
	record: Record,
}

pub enum Admission {
	Entered(Entered),
	Observed(Value),
}

fn shard(identity: &str) -> &'static Mutex<()> {
	let locks = OPERATION_LOCKS.get_or_init(|| (0..LOCK_SHARDS).map(|_| Mutex::new(())).collect());
	let index = usize::from(u8::from_str_radix(&identity[..2], 16).expect("SHA-256 hex prefix"));
	&locks[index]
}

fn identity(host: &str, key: &str) -> Result<String> {
	let bytes = serde_json::to_vec(&(host, key))?;
	Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn bound_digest(host: &str, action: &str, payload: &Value) -> Result<String> {
	let canonical = json!({
		"domain": "hepta.runtime.privileged-operation.v1",
		"host": host,
		"action": action,
		"payload": payload,
	});
	Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&canonical)?)))
}

fn ledger_dir(state_dir: &Path) -> Result<PathBuf> {
	let directory = state_dir.join("privileged-actions");
	let mut builder = std::fs::DirBuilder::new();
	builder.recursive(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::DirBuilderExt;
		builder.mode(0o700);
	}
	builder.create(&directory)?;
	let metadata = std::fs::symlink_metadata(&directory)?;
	if !metadata.file_type().is_dir() {
		bail!("privileged ledger directory must not be a symlink or non-directory");
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		if metadata.permissions().mode() & 0o077 != 0 {
			bail!("privileged ledger directory must be owner-private");
		}
	}
	Ok(directory)
}

fn record_path(state_dir: &Path, identity: &str) -> Result<PathBuf> {
	Ok(ledger_dir(state_dir)?.join(format!("{identity}.json")))
}

fn read_record(path: &Path) -> Result<Option<Record>> {
	match std::fs::symlink_metadata(path) {
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => {
			return Err(error).with_context(|| format!("cannot inspect {}", path.display()));
		}
		Ok(metadata) if !metadata.file_type().is_file() => {
			bail!("privileged ledger record is not a regular file: {}", path.display())
		}
		Ok(_) => {}
	}
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW);
	}
	let mut file = options.open(path)?;
	let metadata = file.metadata()?;
	if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
		bail!("invalid or oversized privileged ledger record");
	}
	// Metadata length is only a snapshot. Bound the actual read as well so
	// concurrent growth cannot cause an unbounded allocation before parsing.
	let mut bytes = Vec::new();
	let mut bounded = file.take(MAX_RECORD_BYTES + 1);
	bounded.read_to_end(&mut bytes)?;
	if bytes.len() as u64 > MAX_RECORD_BYTES {
		bail!("oversized privileged ledger record: {}", path.display());
	}
	let record = serde_json::from_slice(&bytes)
		.with_context(|| format!("invalid privileged ledger record {}", path.display()))?;
	Ok(Some(record))
}

fn write_record(path: &Path, record: &Record) -> Result<()> {
	let bytes = serde_json::to_vec(record)?;
	if bytes.len() as u64 > MAX_RECORD_BYTES {
		bail!("privileged ledger record exceeds maximum size");
	}
	// A leftover .tmp following a crash is not silently reused or overwritten.
	let tmp = path.with_extension("json.tmp");
	let mut options = OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	let mut file = options.open(&tmp)?;
	file.write_all(&bytes)?;
	file.sync_all()?;
	drop(file);
	std::fs::rename(&tmp, path)?;
	#[cfg(unix)]
	if let Some(parent) = path.parent() {
		File::open(parent)?.sync_all()?;
	}
	Ok(())
}

/// Admission writes an immutable request identity before any remote effect.
/// An earlier unknown operation must be reconciled, never automatically rerun.
pub async fn admit(
	state_dir: &Path,
	host: &str,
	action: &str,
	key: &str,
	payload: &Value,
) -> Result<Admission> {
	if key.is_empty() || key.len() > 256 || key.trim().is_empty() || key.contains('\0') {
		bail!("privileged_action requires a stable nonblank 1..256-byte idempotency_key");
	}
	if !payload.is_object() {
		bail!("privileged action payload must be a typed object");
	}
	let op_id = identity(host, key)?;
	let _guard = shard(&op_id).lock().await;
	let path = record_path(state_dir, &op_id)?;
	let request_digest = bound_digest(host, action, payload)?;
	if let Some(existing) = read_record(&path)? {
		if existing.version != LEDGER_VERSION
			|| existing.host != host
			|| existing.action != action
			|| existing.idempotency_key != key
			|| existing.request_digest != request_digest
		{
			bail!("privileged_action idempotency conflict or unrecognized ledger version");
		}
		return match (existing.state.as_str(), existing.result) {
			("observed", Some(result)) => Ok(Admission::Observed(result)),
			("entered", None) => bail!(
				"privileged_action outcome indeterminate: remote effect may have occurred; reconcile without replay"
			),
			_ => bail!("privileged_action ledger has an invalid or incomplete terminal state"),
		};
	}
	let record = Record {
		version: LEDGER_VERSION,
		host: host.to_owned(),
		action: action.to_owned(),
		idempotency_key: key.to_owned(),
		request_digest,
		state: "entered".to_owned(),
		result: None,
	};
	write_record(&path, &record)?;
	Ok(Admission::Entered(Entered { _guard, path, record }))
}

impl Entered {
	/// Persist the actually observed remote result before returning to the caller.
	/// A failed persistence leaves the original entered record indeterminate.
	pub fn complete(mut self, result: Value) -> Result<Value> {
		self.record.state = "observed".to_owned();
		self.record.result = Some(result.clone());
		write_record(&self.path, &self.record)?;
		Ok(result)
	}
}

#[cfg(test)]
#[path = "privileged_ledger_tests.rs"]
mod tests;
