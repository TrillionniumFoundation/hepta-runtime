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

//! Internal, stdin-only decoding of one captured recorded-core snapshot.
//!
//! The input uses the existing native worker framing: a little-endian u32 JSON
//! header length, the strict header, exactly `bytes` source bytes, and EOF. No
//! artifact path, historical PID or recorded pathname authorizes a filesystem or
//! process lookup. The worker recomputes the snapshot digest before parsing.
//! An open or partial stdin may wait for its owner: CPU limits do not bound idle
//! reads. The original caller must enforce a wall deadline and reap its child.
//!
//! This native admission profile is distinct from the Python request/reply-file
//! helper. Its complete reply, including the newline, must fit the caller's
//! budget. If even an error cannot fit, stdout stays empty, stderr carries a
//! bounded typed diagnostic, and exit status 76 records failed reply delivery.
//! A header that cannot be decoded has no admitted caller budget; its typed
//! failure uses the fixed 64 MiB ceiling. A decoded tiny budget is never exceeded.

use super::rea_provider::sha256;
use super::rea_recorded_core_parser::{parse_recorded_core, CoreFailure};
use super::rea_worker_transport::write_json;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read, Write};

const FRAME_SCHEMA: &str = "hepta.rea.recorded-core-frame.v1";
const NATIVE_PROFILE: &str = "hepta-native-recorded-core-v1";
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
const OUTPUT_LIMIT_EXIT: i32 = 76;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
	schema: String,
	sha256: String,
	bytes: u64,
	max_file_bytes: u64,
	max_output_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Snapshot {
	sha256: String,
	bytes: u64,
}

/// Observed effective soft limits, not requested ceilings or Python facts.
#[derive(Clone, Copy, Debug, Serialize)]
struct EffectiveLimits {
	address_space_bytes: u64,
	cpu_seconds: u64,
	file_size_bytes: u64,
	open_files: u64,
	core_file_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Reason {
	Protocol,
	InputLimit,
	Integrity,
	Format,
	UnsupportedTarget,
	OutputLimit,
	ResourceLimit,
	Unavailable,
	Decoder,
}

#[derive(Debug)]
struct WorkerFailure {
	reason: Reason,
	message: String,
}

impl WorkerFailure {
	fn new(reason: Reason, message: impl Into<String>) -> Self {
		Self {
			reason,
			message: message.into(),
		}
	}
}

impl From<CoreFailure> for WorkerFailure {
	fn from(failure: CoreFailure) -> Self {
		let reason = match failure.reason {
			"format" => Reason::Format,
			"unsupported-target" => Reason::UnsupportedTarget,
			"budget" => Reason::OutputLimit,
			"resource-limit" => Reason::ResourceLimit,
			"decoder" => Reason::Decoder,
			_ => {
				return Self::new(
					Reason::Decoder,
					"Recorded-core parser returned an unknown failure classification.",
				)
			}
		};
		Self::new(reason, failure.message)
	}
}

#[derive(Serialize)]
#[serde(untagged)]
enum Reply {
	Success {
		ok: bool,
		profile: &'static str,
		snapshot: Snapshot,
		value: Value,
		#[serde(skip_serializing_if = "Option::is_none")]
		reported_limits: Option<EffectiveLimits>,
	},
	Failure {
		ok: bool,
		reason: Reason,
		message: String,
		#[serde(skip_serializing_if = "Option::is_none")]
		snapshot: Option<Snapshot>,
		#[serde(skip_serializing_if = "Option::is_none")]
		reported_limits: Option<EffectiveLimits>,
	},
}

impl Reply {
	fn failure(
		failure: WorkerFailure,
		snapshot: Option<Snapshot>,
		reported_limits: Option<EffectiveLimits>,
	) -> Self {
		Self::Failure {
			ok: false,
			reason: failure.reason,
			message: failure.message,
			snapshot,
			reported_limits,
		}
	}

	fn output_limit(&self) -> Self {
		let (snapshot, reported_limits) = match self {
			Self::Success {
				snapshot,
				reported_limits,
				..
			} => (Some(snapshot.clone()), *reported_limits),
			Self::Failure {
				snapshot,
				reported_limits,
				..
			} => (snapshot.clone(), *reported_limits),
		};
		Self::failure(
			WorkerFailure::new(
				Reason::OutputLimit,
				"Complete recorded-core reply exceeds the requested output budget.",
			),
			snapshot,
			reported_limits,
		)
	}
}

#[derive(Debug)]
struct FrameFailure {
	failure: WorkerFailure,
	output_limit: usize,
}

impl FrameFailure {
	fn new(reason: Reason, message: impl Into<String>, output_limit: usize) -> Self {
		Self {
			failure: WorkerFailure::new(reason, message),
			output_limit,
		}
	}

	fn input(error: io::Error, incomplete: &'static str, output_limit: usize) -> Self {
		let (reason, message) = match error.kind() {
			io::ErrorKind::UnexpectedEof => (Reason::Protocol, incomplete),
			io::ErrorKind::OutOfMemory => (
				Reason::ResourceLimit,
				"Native recorded-core input reported an allocation failure; its exact cause is unknown.",
			),
			_ => (Reason::Decoder, "Native recorded-core input could not be read completely."),
		};
		Self::new(reason, message, output_limit)
	}
}

struct CapturedFrame {
	header: Header,
	snapshot: Snapshot,
	bytes: Vec<u8>,
}

fn read_frame(input: &mut impl Read) -> std::result::Result<CapturedFrame, FrameFailure> {
	let mut prefix = [0_u8; 4];
	input.read_exact(&mut prefix).map_err(|error| {
		FrameFailure::input(
			error,
			"Recorded-core frame lacks a complete header-length prefix.",
			MAX_OUTPUT_BYTES,
		)
	})?;
	let length = u32::from_le_bytes(prefix) as usize;
	if length == 0 || length > MAX_HEADER_BYTES {
		return Err(FrameFailure::new(
			Reason::Protocol,
			"Recorded-core frame header must contain 1 through 16384 bytes.",
			MAX_OUTPUT_BYTES,
		));
	}
	let mut raw_header = vec![0_u8; length];
	input.read_exact(&mut raw_header).map_err(|error| {
		FrameFailure::input(
			error,
			"Recorded-core frame header is truncated.",
			MAX_OUTPUT_BYTES,
		)
	})?;
	let header: Header = serde_json::from_slice(&raw_header).map_err(|_| {
		FrameFailure::new(
			Reason::Protocol,
			"Recorded-core frame JSON does not match the strict header schema.",
			MAX_OUTPUT_BYTES,
		)
	})?;
	// Even a rejected header cannot cause output beyond its stated finite budget.
	let output_limit = header.max_output_bytes.min(MAX_OUTPUT_BYTES);
	if header.schema != FRAME_SCHEMA {
		return Err(FrameFailure::new(
			Reason::Protocol,
			"Recorded-core frame schema is unsupported.",
			output_limit,
		));
	}
	if header.max_output_bytes == 0 || header.max_output_bytes > MAX_OUTPUT_BYTES {
		return Err(FrameFailure::new(
			Reason::Protocol,
			"Recorded-core reply budget must contain 1 through 67108864 bytes.",
			output_limit,
		));
	}
	if header.sha256.len() != 64
		|| !header
			.sha256
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	{
		return Err(FrameFailure::new(
			Reason::Protocol,
			"Recorded-core snapshot SHA-256 must contain 64 lowercase hexadecimal digits.",
			output_limit,
		));
	}
	if header.max_file_bytes == 0
		|| header.max_file_bytes > MAX_INPUT_BYTES
		|| header.bytes > header.max_file_bytes
	{
		return Err(FrameFailure::new(
			Reason::InputLimit,
			"Recorded-core snapshot exceeds the admitted input budget or 256 MiB ceiling.",
			output_limit,
		));
	}
	let length = usize::try_from(header.bytes).map_err(|_| {
		FrameFailure::new(
			Reason::InputLimit,
			"Recorded-core snapshot length exceeds this platform's addressable size.",
			output_limit,
		)
	})?;
	let mut bytes = Vec::new();
	bytes.try_reserve_exact(length).map_err(|_| {
		FrameFailure::new(
			Reason::ResourceLimit,
			"Native recorded-core snapshot allocation failed; the exact allocation cause is unknown.",
			output_limit,
		)
	})?;
	bytes.resize(length, 0);
	input.read_exact(&mut bytes).map_err(|error| {
		FrameFailure::input(
			error,
			"Recorded-core snapshot is shorter than the declared frame length.",
			output_limit,
		)
	})?;
	let mut extra = [0_u8; 1];
	loop {
		match input.read(&mut extra) {
			Ok(0) => break,
			Ok(_) => {
				return Err(FrameFailure::new(
					Reason::Protocol,
					"Recorded-core frame contains trailing bytes after the snapshot.",
					output_limit,
				))
			}
			Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
			Err(error) => {
				return Err(FrameFailure::input(
					error,
					"Recorded-core frame EOF could not be established.",
					output_limit,
				))
			}
		}
	}
	let snapshot = Snapshot {
		sha256: sha256(&bytes),
		bytes: header.bytes,
	};
	if snapshot.sha256 != header.sha256 {
		return Err(FrameFailure::new(
			Reason::Integrity,
			"Captured snapshot SHA-256 does not match the recorded-core frame header.",
			output_limit,
		));
	}
	Ok(CapturedFrame {
		header,
		snapshot,
		bytes,
	})
}

struct ReplySize {
	bytes: usize,
	limit: usize,
	exceeded: bool,
}

impl Write for ReplySize {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if bytes.len() > self.limit.saturating_sub(self.bytes) {
			self.exceeded = true;
			return Err(io::Error::other("recorded-core reply budget exceeded"));
		}
		self.bytes += bytes.len();
		Ok(bytes.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn reply_fits(reply: &Reply, limit: usize) -> Result<bool> {
	let mut count = ReplySize {
		bytes: 0,
		limit,
		exceeded: false,
	};
	if let Err(error) = serde_json::to_writer(&mut count, reply) {
		if count.exceeded {
			return Ok(false);
		}
		return Err(error).context("cannot measure native recorded-core reply");
	}
	// The final newline is part of the wire budget.
	Ok(count.bytes < limit)
}

fn finish_reply(
	output: &mut impl Write,
	diagnostics: &mut impl Write,
	reply: Reply,
	limit: usize,
) -> Result<i32> {
	if reply_fits(&reply, limit)? {
		write_json(output, &reply, limit)?;
		return Ok(0);
	}
	let failure = reply.output_limit();
	if reply_fits(&failure, limit)? {
		write_json(output, &failure, limit)?;
		return Ok(0);
	}
	let diagnostic = Reply::failure(
		WorkerFailure::new(
			Reason::OutputLimit,
			"Complete recorded-core failure reply exceeds the requested output budget.",
		),
		None,
		None,
	);
	write_json(diagnostics, &diagnostic, MAX_DIAGNOSTIC_BYTES)?;
	Ok(OUTPUT_LIMIT_EXIT)
}

fn serve_frame(
	input: &mut impl Read,
	output: &mut impl Write,
	diagnostics: &mut impl Write,
	limits: Option<EffectiveLimits>,
	seal: impl FnOnce() -> Result<()>,
) -> Result<i32> {
	let (reply, limit) = match read_frame(input) {
		Err(failure) => (
			Reply::failure(failure.failure, None, limits),
			failure.output_limit,
		),
		Ok(frame) => {
			let limit = frame.header.max_output_bytes;
			let parsed = match seal() {
				Ok(()) => parse_recorded_core(&frame.bytes, limit).map_err(WorkerFailure::from),
				Err(_) => Err(WorkerFailure::new(
					Reason::Unavailable,
					"Cannot establish the native recorded-core post-read isolation policy.",
				)),
			};
			// The report owns its values; retain only the digest while serializing.
			drop(frame.bytes);
			let reply = match parsed {
				Ok(value) => Reply::Success {
					ok: true,
					profile: NATIVE_PROFILE,
					snapshot: frame.snapshot,
					value,
					reported_limits: limits,
				},
				Err(failure) => Reply::failure(failure, Some(frame.snapshot), limits),
			};
			(reply, limit)
		}
	};
	finish_reply(output, diagnostics, reply, limit)
}

#[cfg(unix)]
fn install_limits() -> Result<EffectiveLimits> {
	super::rea_worker_transport::install_limits(MAX_OUTPUT_BYTES, 3 * 1024 * 1024 * 1024, 30)?;
	let read = |kind| -> Result<u64> {
		let mut observed = libc::rlimit {
			rlim_cur: 0,
			rlim_max: 0,
		};
		if unsafe { libc::getrlimit(kind, &mut observed) } != 0 {
			return Err(io::Error::last_os_error())
				.context("cannot observe effective native recorded-core limit");
		}
		Ok(observed.rlim_cur)
	};
	Ok(EffectiveLimits {
		address_space_bytes: read(libc::RLIMIT_AS)?,
		cpu_seconds: read(libc::RLIMIT_CPU)?,
		file_size_bytes: read(libc::RLIMIT_FSIZE)?,
		open_files: read(libc::RLIMIT_NOFILE)?,
		core_file_bytes: read(libc::RLIMIT_CORE)?,
	})
}

/// Run before Tokio startup. The worker spawns no process and opens no artifact.
/// Callers own the original child, deadlines, cancellation, reaping and pipe joins.
pub fn run_worker() -> Result<i32> {
	#[cfg(not(unix))]
	return finish_reply(
		&mut io::stdout().lock(),
		&mut io::stderr().lock(),
		Reply::failure(
			WorkerFailure::new(
				Reason::Unavailable,
				"Native recorded-core isolation is unavailable on this platform.",
			),
			None,
			None,
		),
		MAX_OUTPUT_BYTES,
	);
	#[cfg(unix)]
	{
		let limits = match install_limits() {
			Ok(limits) => limits,
			Err(_) => {
				return finish_reply(
					&mut io::stdout().lock(),
					&mut io::stderr().lock(),
					Reply::failure(
						WorkerFailure::new(
							Reason::Unavailable,
							"Cannot establish the native recorded-core resource limits.",
						),
						None,
						None,
					),
					MAX_OUTPUT_BYTES,
				)
			}
		};
		serve_frame(
			&mut io::stdin().lock(),
			&mut io::stdout().lock(),
			&mut io::stderr().lock(),
			Some(limits),
			super::rea_seccomp::tighten_after_read,
		)
	}
}

#[cfg(test)]
#[path = "rea_recorded_core_worker_tests.rs"]
mod tests;
