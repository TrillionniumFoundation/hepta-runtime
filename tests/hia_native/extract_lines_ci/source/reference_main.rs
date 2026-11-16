// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Private Local extract transport around the byte-exact target body.
//! Framing, setup and read-only observers are fixture code, not replacements
//! for the target endpoint, filesystem, history, cache or rendering functions.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("this original qualification profile is Linux x86-64");

use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

#[rustfmt::skip]
mod mcp {
	include!("original_mod.rs");
	pub mod fs {
		pub mod remote { include!("original_remote.rs"); }
		pub use remote::PathSource;
		pub mod text_editing { include!("original_text_editing.rs"); include!("lock_observer.rs"); }
		pub mod core { include!("original_core.rs"); include!("history_observer.rs"); }
		pub mod delta { include!("original_delta.rs"); include!("cache_observer.rs"); }
	}
	pub mod request_ctx { include!("original_request_ctx.rs"); }
}

#[rustfmt::skip]
mod utils {
	pub mod line_hash { include!("original_line_hash.rs"); }
	pub mod truncation { include!("original_truncation.rs"); }
}

fn word(raw: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(
		raw[offset..offset + 8]
			.try_into()
			.expect("admitted frame word"),
	)
}

fn invalid(message: &str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn output(raw: &[u8]) -> io::Result<()> {
	let mut stream = io::stdout().lock();
	stream.write_all(&(raw.len() as u64).to_le_bytes())?;
	stream.write_all(raw)?;
	stream.flush()
}

fn observation(raw: &[u8]) -> io::Result<()> {
	let mut stream = io::stderr().lock();
	stream.write_all(raw)?;
	stream.flush()
}

fn snapshot(cache: &mcp::fs::delta::ViewCache, phase: u64, generation: u64) -> io::Result<()> {
	observation(&mcp::fs::delta::fixture_snapshot(cache, phase))?;
	observation(&mcp::fs::core::fixture_history_snapshot(phase, generation))?;
	observation(&mcp::fs::text_editing::fixture_lock_snapshot(
		phase, generation,
	))
}

fn endpoint(raw: &[u8]) -> io::Result<serde_json::Value> {
	if raw.len() < 32 || &raw[..8] != b"HIAEP002" || word(raw, 16) != (raw.len() - 32) as u64 {
		return Err(invalid("endpoint fixture frame"));
	}
	let kind = word(raw, 8);
	if kind > 3 || (kind != 0 && word(raw, 24) != 0) || (kind < 2 && raw.len() != 32) {
		return Err(invalid("endpoint fixture fields"));
	}
	Ok(match kind {
		0 => serde_json::Value::from(word(raw, 24) as i64),
		// The private Number-without-i64 tag intentionally represents this
		// typed equivalence class; original parse_endpoint rejects all of it.
		1 => serde_json::Value::from(1.5f64),
		2 => serde_json::Value::String(
			std::str::from_utf8(&raw[32..])
				.map_err(|_| invalid("endpoint UTF-8"))?
				.to_owned(),
		),
		3 => {
			let value: serde_json::Value = serde_json::from_slice(&raw[32..])
				.map_err(|_| invalid("endpoint canonical Value"))?;
			if value.is_string()
				|| value.is_number()
				|| serde_json::to_vec(&value)
					.map_err(|_| invalid("endpoint canonical serialization"))?
					!= raw[32..]
			{
				return Err(invalid("endpoint canonical non-scalar class"));
			}
			value
		}
		_ => unreachable!(),
	})
}

fn admit(raw: &[u8]) -> io::Result<(u64, u64, mcp::McpToolCall)> {
	if raw.len() < 128
		|| &raw[..8] != b"HEXTRQ01"
		|| word(raw, 8) != 1
		|| !matches!(word(raw, 16), 1..=2)
		|| word(raw, 24) == 0
		|| raw[88..128] != [0u8; 40]
	{
		return Err(invalid("non-admitted extract fixture frame"));
	}
	let mut pieces = Vec::new();
	let mut at = 128usize;
	for offset in (32..=80).step_by(8) {
		let count =
			usize::try_from(word(raw, offset)).map_err(|_| invalid("extract field length"))?;
		if count > raw.len() - at {
			return Err(invalid("extract field extent"));
		}
		pieces.push(&raw[at..at + count]);
		at += count;
	}
	if at != raw.len() {
		return Err(invalid("extract trailing bytes"));
	}
	let source = std::str::from_utf8(pieces[2]).map_err(|_| invalid("source display UTF-8"))?;
	let target = std::str::from_utf8(pieces[3]).map_err(|_| invalid("target display UTF-8"))?;
	let workdir = std::env::current_dir()?;
	for (display, path) in [(source, pieces[0]), (target, pieces[1])] {
		let resolved = mcp::fs::remote::resolve_path_source(display, &workdir);
		match resolved {
			mcp::fs::PathSource::Local(local) if local.as_os_str().as_bytes() == path => {}
			_ => {
				return Err(invalid(
					"private Local path capability differs from original resolution",
				))
			}
		}
	}
	let mut parameters = serde_json::Map::new();
	parameters.insert("from_path".into(), serde_json::Value::String(source.into()));
	parameters.insert("from_start".into(), endpoint(pieces[4])?);
	if !pieces[5].is_empty() {
		parameters.insert("from_end".into(), endpoint(pieces[5])?);
	}
	parameters.insert(
		"append_path".into(),
		serde_json::Value::String(target.into()),
	);
	parameters.insert("append_line".into(), endpoint(pieces[6])?);
	Ok((
		word(raw, 16),
		word(raw, 24),
		mcp::McpToolCall {
			tool_name: "extract_lines".into(),
			parameters: serde_json::Value::Object(parameters),
			tool_id: String::new(),
			workdir,
		},
	))
}

async fn original_body(call: &mcp::McpToolCall) -> (anyhow::Result<String>, Vec<String>) {
	let result = mcp::fs::core::execute_extract_lines(call).await;
	(result, mcp::request_ctx::drain_hints())
}

fn main() -> io::Result<()> {
	std::panic::set_hook(Box::new(|_| {}));
	if std::env::args_os().len() != 1 {
		return Err(invalid("fixture does not accept arguments"));
	}
	let runtime = tokio::runtime::Builder::new_current_thread()
		.max_blocking_threads(1)
		.build()?;
	let cache = Arc::new(mcp::fs::delta::ViewCache::default());
	let mut cache_initialized = false;
	let mut history_initialized = false;
	let mut stdin = io::stdin().lock();
	loop {
		let mut length = [0u8; 8];
		if stdin.read(&mut length[..1])? == 0 {
			break;
		}
		stdin.read_exact(&mut length[1..])?;
		let length =
			usize::try_from(u64::from_le_bytes(length)).map_err(|_| invalid("fixture length"))?;
		if !(8..=134217728).contains(&length) {
			return Err(invalid("private fixture frame domain"));
		}
		let mut raw = vec![0u8; length];
		stdin.read_exact(&mut raw)?;
		if &raw[..8] == b"HVCACH01" {
			if raw.len() < 48 {
				return Err(invalid("short cache fixture"));
			}
			if word(&raw, 8) == 0 {
				if cache_initialized || raw.len() != 48 || raw[8..] != [0u8; 40] {
					return Err(invalid("cache setup is permitted once"));
				}
				cache_initialized = true;
				let mut answer = b"HVCAR001".to_vec();
				answer.extend_from_slice(&[0u8; 24]);
				output(&answer)?;
			} else {
				if !cache_initialized {
					return Err(invalid("cache fixture before setup"));
				}
				output(&mcp::fs::delta::fixture_apply(&cache, &raw)?)?;
			}
			continue;
		}
		if &raw[..8] == b"HHISTQ01" {
			if raw.len() < 64 {
				return Err(invalid("short history fixture"));
			}
			if word(&raw, 8) == 0 {
				if history_initialized {
					return Err(invalid("history setup is permitted once"));
				}
				history_initialized = true;
			} else if !history_initialized {
				return Err(invalid("history fixture before setup"));
			}
			output(&mcp::fs::core::fixture_history_apply(&raw)?)?;
			continue;
		}
		if !cache_initialized || !history_initialized {
			return Err(invalid("body before fixture setup"));
		}
		let (context, generation, call) = admit(&raw)?;
		snapshot(&cache, 0, generation)?;
		let body = original_body(&call);
		let (result, hints) = if context == 1 {
			runtime.block_on(mcp::request_ctx::with_request_context(cache.clone(), body))
		} else {
			runtime.block_on(body)
		};
		let (kind, message) = match result {
			Ok(text) => (0u64, text),
			Err(error) => (1, error.to_string()),
		};
		let mut response = b"HEXTRP01".to_vec();
		for value in [1u64, kind, message.len() as u64] {
			response.extend_from_slice(&value.to_le_bytes());
		}
		response.extend_from_slice(message.as_bytes());
		let mut hint_body = Vec::new();
		for hint in &hints {
			hint_body.extend_from_slice(&(hint.len() as u64).to_le_bytes());
			hint_body.extend_from_slice(hint.as_bytes());
		}
		let mut hint_frame = b"HLTBHT01".to_vec();
		for value in [
			48 + hint_body.len() as u64,
			generation,
			1,
			kind,
			hints.len() as u64,
		] {
			hint_frame.extend_from_slice(&value.to_le_bytes());
		}
		hint_frame.extend_from_slice(&hint_body);
		observation(&hint_frame)?;
		snapshot(&cache, 1, generation)?;
		output(&response)?;
	}
	drop(runtime);
	Ok(())
}
