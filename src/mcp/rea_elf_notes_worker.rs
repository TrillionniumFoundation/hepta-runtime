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

//! A bounded binary input frame and streamed JSON reply avoid expanding an admitted
//! snapshot into a JSON byte array or allocating its complete escaped report.
//! An independent owner retains both admission guards through child reaping and
//! the unique blocking reader's join, including when the requesting future drops.

#[cfg(not(test))]
use super::DEADLINE_MS;
use super::{parser, Failure, Input, MAX_BYTES, MAX_WORKER_REPLY, OP};
#[cfg(not(test))]
use crate::mcp::rea_worker_transport::WorkerSpec;
use crate::mcp::rea_worker_transport::{self, write_json, MAX_HEADER};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

const MEMORY_BYTES: libc::rlim_t = 2 * 1024 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
	input: Input,
	sha256: String,
	bytes: u64,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Reply {
	Report { report: Box<parser::ElfNotesReport> },
	Failure { failure: FailureReply },
}

#[derive(Serialize)]
struct FailureReply {
	#[serde(flatten)]
	failure: parser::ElfNotesFailure,
	// Format/Unsupported already serialize their message. Never emit duplicate keys.
	#[serde(skip_serializing_if = "Option::is_none")]
	message: Option<String>,
}

fn parse(header: &Header, bytes: &[u8]) -> Reply {
	let artifact = parser::ElfNotesArtifact {
		path: header.input.path.clone(),
		sha256: header.sha256.clone(),
		bytes: header.bytes,
	};
	match parser::parse_elf_notes(
		bytes,
		artifact,
		header.input.max_file_bytes,
		header.input.max_entries,
	) {
		Ok(report) => Reply::Report {
			report: Box::new(report),
		},
		Err(failure) => {
			let message = match &failure {
				parser::ElfNotesFailure::Format { .. }
				| parser::ElfNotesFailure::Unsupported { .. } => None,
				_ => Some(failure.to_string()),
			};
			Reply::Failure {
				failure: FailureReply { failure, message },
			}
		}
	}
}

pub(super) fn serve_once() -> Result<()> {
	#[cfg(not(unix))]
	bail!("ELF isolation is not available on this platform");
	#[cfg(unix)]
	{
		rea_worker_transport::install_limits(MAX_WORKER_REPLY, MEMORY_BYTES, 20)?;
		let mut stdin = io::stdin().lock();
		let mut length = [0_u8; 4];
		stdin.read_exact(&mut length)?;
		let length = u32::from_le_bytes(length) as usize;
		if length == 0 || length > MAX_HEADER {
			bail!("ELF worker header exceeds its bound");
		}
		let mut header = vec![0_u8; length];
		stdin.read_exact(&mut header)?;
		let header: Header = serde_json::from_slice(&header)?;
		if header.bytes > MAX_BYTES
			|| header.bytes > header.input.max_file_bytes
			|| !(64..=MAX_BYTES).contains(&header.input.max_file_bytes)
			|| !(1..=256).contains(&header.input.max_entries)
		{
			bail!("ELF worker frame exceeds admitted bounds");
		}
		let mut bytes = Vec::new();
		bytes
			.try_reserve_exact(header.bytes as usize)
			.context("ELF worker cannot reserve snapshot memory")?;
		bytes.resize(header.bytes as usize, 0);
		stdin.read_exact(&mut bytes)?;
		let mut extra = [0_u8; 1];
		if stdin.read(&mut extra)? != 0 {
			bail!("ELF worker received trailing frame bytes");
		}
		super::super::rea_seccomp::tighten_after_read()?;
		let reply = parse(&header, &bytes);
		// The report owns its text; release the captured image before serialization.
		drop(bytes);
		write_json(io::stdout().lock(), &reply, MAX_WORKER_REPLY)
	}
}

#[cfg(not(test))]
pub(super) async fn inspect_isolated(
	input: &Input,
	digest: &str,
	bytes: Arc<Vec<u8>>,
	cancellation: &CancellationToken,
	lease: Arc<OwnedSemaphorePermit>,
	admission: Arc<super::runtime::effect_owner_fence::AdmissionPermit>,
) -> std::result::Result<Value, Failure> {
	let header = serde_json::to_vec(&Header {
		input: input.clone(),
		sha256: digest.to_owned(),
		bytes: bytes.len() as u64,
	})
	.map_err(|error| Failure::output(OP, error.to_string()))?;
	rea_worker_transport::inspect_frame(
		WorkerSpec {
			operation: OP,
			reply_limit: MAX_WORKER_REPLY,
			deadline_ms: DEADLINE_MS,
		},
		"rea-elf-notes-worker",
		header,
		bytes,
		cancellation,
		lease,
		admission,
	)
	.await
}

#[cfg(test)]
pub(super) async fn inspect_isolated(
	input: &Input,
	digest: &str,
	bytes: Arc<Vec<u8>>,
	cancellation: &CancellationToken,
	_lease: Arc<OwnedSemaphorePermit>,
	_admission: Arc<super::runtime::effect_owner_fence::AdmissionPermit>,
) -> std::result::Result<Value, Failure> {
	super::active(cancellation)?;
	serde_json::to_value(parse(
		&Header {
			input: input.clone(),
			sha256: digest.to_owned(),
			bytes: bytes.len() as u64,
		},
		&bytes,
	))
	.map_err(|error| Failure::output(OP, error.to_string()))
}

#[cfg(test)]
#[path = "rea_elf_notes_worker_tests.rs"]
mod tests;
