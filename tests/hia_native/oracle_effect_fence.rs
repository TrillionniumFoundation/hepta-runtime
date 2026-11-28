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
//! Binary qualification transport around the complete unchanged original owner.
use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::OnceLock;

static STATE: OnceLock<PathBuf> = OnceLock::new();
mod config {
	pub struct RuntimeConfig {
		pub state_dir: std::path::PathBuf,
	}
	pub fn runtime_config() -> anyhow::Result<RuntimeConfig> {
		Ok(RuntimeConfig {
			state_dir: super::STATE
				.get()
				.ok_or_else(|| anyhow::anyhow!("trusted fixture state missing"))?
				.clone(),
		})
	}
}
include!(concat!(
	env!("OUT_DIR"),
	"/original_effect_fence_reference.rs"
));

fn word(data: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

fn error_code(error: &anyhow::Error) -> Result<u64> {
	let message = error.to_string();
	let code = match message.as_str() {
		"invalid effect owner fence enforcement switch" => 1,
		"required effect owner fence is not fully configured" => 2,
		"invalid owner configuration" => 3,
		"invalid owner identity or controller state root" => 4,
		"effect owner fence requires an absolute private directory" => 5,
		"effect owner fence disallows relative/special components" => 6,
		"invalid authority directory name" => 7,
		"authority directory component unavailable" => 8,
		"effect owner fence root must be current-UID private mode 0700" => 10,
		"effect owner authority file absent" => 11,
		"effect owner authority file must be private regular inode" => 12,
		"effect owner shared lock failed" => 13,
		"effect owner record has an unsafe length" => 14,
		"effect owner record changed while reading" => 15,
		"effect owner record changed or was replaced during admission" => 16,
		"effect owner record invalid" => 17,
		"effect owner record is not an admitted schema/epoch" => 18,
		"effect owner admission frozen; no new effect submitted" => 19,
		"V11 predecessor replay state unavailable" => 20,
		"V11 predecessor cannot alias current effect state" => 21,
		"V11 owner must bind a trusted previous V4 state root" => 22,
		"effect owner mismatch: refusing new effect" => 23,
		"effect owner lock inode changed during admission" => 24,
		"effect owner authority or controller state path was rebound" => 25,
		"V11 process_start requires a new idempotency key" => 26,
		"V11 process_start requires a valid host/idempotency key" => 27,
		"no pinned cross-controller admission authority" => 28,
		"no pinned predecessor epoch" => 29,
		"missing pinned authority path" => 30,
		"predecessor jobs registry must be owner-private" => 31,
		"predecessor replay cache unavailable" => 32,
		"frozen predecessor registry mutated after replay seal" => 33,
		"original V4 accepted this host/idempotency identity; resume original job" => 34,
		"predecessor replay scan exceeded bounded time budget" => 35,
		"non-UTF8 old durable job filename" => 36,
		"uncertain or temporary predecessor job record" => 37,
		"predecessor registry exceeds safe replay scan bound" => 38,
		"invalid predecessor durable job length" => 39,
		"predecessor replay byte count overflow" => 40,
		"predecessor replay scan exceeded bounded source bytes" => 41,
		"predecessor durable record changed during replay inspection" => 42,
		"invalid predecessor durable job identity" => 43,
		"predecessor durable identity mismatch" => 44,
		"predecessor idempotency binding incomplete" => 45,
		"duplicate V4 predecessor idempotency binding" => 46,
		"predecessor registry changed while verifying replay namespace" => 47,
		"V11 PTY start requires a new idempotency key" => 48,
		"V11 PTY admission requires a valid host and idempotency key" => 49,
		"V4 predecessor terminal registry is not private" => 50,
		"V4 predecessor terminal registry changed during replay check" => 51,
		"V4 predecessor state changed during PTY replay check" => 52,
		"Original V4 already owns the PTY idempotency identity; resume the original session" => 53,
		"effect owner admission worker unavailable" => 54,
		_ if error.downcast_ref::<std::io::Error>().is_some() => 9,
		_ => bail!("unclassified actual original error: {error:#}"),
	};
	Ok(code)
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args_os().collect();
	if args.len() != 3 || args[1] != "--state-root" {
		bail!("explicit trusted fixture state required");
	}
	STATE
		.set(PathBuf::from(&args[2]))
		.map_err(|_| anyhow::anyhow!("state already initialized"))?;
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()?;
	let mut permit: Option<original::AdmissionPermit> = None;
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	loop {
		let mut header = [0u8; 8];
		match input.read(&mut header[..1])? {
			0 => break,
			1 => input.read_exact(&mut header[1..])?,
			_ => unreachable!(),
		}
		let n = u64::from_le_bytes(header);
		if !(40..=8 * 1024 * 1024).contains(&n) {
			bail!("invalid fixture frame size");
		}
		let mut wire = vec![0u8; n as usize];
		input.read_exact(&mut wire)?;
		if &wire[..8] != b"HFFCMD01" {
			bail!("invalid fixture magic");
		}
		let op = word(&wire, 8);
		let flags = word(&wire, 16);
		let hostn = word(&wire, 24) as usize;
		let keyn = word(&wire, 32) as usize;
		if flags > 1
			|| hostn > wire.len() - 40
			|| keyn != wire.len() - 40 - hostn
			|| (flags == 0 && keyn != 0)
		{
			bail!("invalid fixture spans");
		}
		if (op == 1 || op == 4) && (flags != 0 || hostn != 0 || keyn != 0) {
			bail!("invalid fixture lifecycle");
		}
		let host = std::str::from_utf8(&wire[40..40 + hostn])?;
		let key = if flags == 1 {
			Some(std::str::from_utf8(&wire[40 + hostn..])?)
		} else {
			None
		};
		let result: Result<()> = match op {
			1 => {
				if permit.is_some() {
					bail!("duplicate fixture permit");
				}
				match runtime.block_on(original::admit_new_effect()) {
					Ok(value) => {
						permit = Some(value);
						Ok(())
					}
					Err(error) => Err(error),
				}
			}
			2 => permit
				.as_ref()
				.context("fixture permit missing")?
				.require_new_process_identity(host, key),
			3 => permit
				.as_ref()
				.context("fixture permit missing")?
				.require_new_pty_identity(host, key),
			4 => {
				drop(permit.take().context("fixture permit missing")?);
				Ok(())
			}
			_ => bail!("invalid fixture operation"),
		};
		let (code, errno) = match result {
			Ok(()) => (0, 0),
			Err(error) => (
				error_code(&error)?,
				error
					.root_cause()
					.downcast_ref::<std::io::Error>()
					.and_then(|e| e.raw_os_error())
					.unwrap_or(0) as u64,
			),
		};
		let (epoch, pred) = permit
			.as_ref()
			.map(|p| p.observed_private_identity())
			.unwrap_or((0, 0));
		let mut response = Vec::with_capacity(40);
		response.extend_from_slice(b"HFFRES01");
		for value in [code, errno, epoch, pred] {
			response.extend_from_slice(&value.to_le_bytes());
		}
		output.write_all(&40u64.to_le_bytes())?;
		output.write_all(&response)?;
		output.flush()?;
	}
	drop(permit);
	Ok(())
}
