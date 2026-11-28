// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Private serial transport around unchanged Local text-editor body functions.
//!
//! The fixture observes real original cache, history, hints and lock-map state.
//! It does not replace any production matching, history, I/O or error routine.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("this private original qualification profile is Linux x86-64");

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::Arc;

#[rustfmt::skip]
mod mcp {
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
}

fn word(raw: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(raw[offset..offset + 8].try_into().expect("admitted frame word"))
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
	observation(&mcp::fs::text_editing::fixture_lock_snapshot(phase, generation))
}

async fn original_body(operation: u64, source: &mcp::fs::PathSource, old: &str, new: &str,
	replace_all: bool) -> (anyhow::Result<String>, Vec<String>) {
	let result = match operation {
		2 => mcp::fs::text_editing::str_replace_spec(source, old, new, replace_all).await,
		3 => mcp::fs::text_editing::delete_file_spec(source).await,
		4 => mcp::fs::core::undo_edit(source).await,
		_ => unreachable!("admitted body operation"),
	};
	(result, mcp::request_ctx::drain_hints())
}

fn main() -> io::Result<()> {
	std::panic::set_hook(Box::new(|_| {}));
	if std::env::args_os().len() != 1 { return Err(invalid("fixture does not accept arguments")); }
	let runtime = tokio::runtime::Builder::new_current_thread().max_blocking_threads(1).build()?;
	let cache = Arc::new(mcp::fs::delta::ViewCache::default());
	let mut cache_initialized = false;
	let mut history_initialized = false;
	let mut stdin = io::stdin().lock();
	loop {
		let mut length = [0u8; 8];
		if stdin.read(&mut length[..1])? == 0 { break; }
		stdin.read_exact(&mut length[1..])?;
		let length = usize::try_from(u64::from_le_bytes(length)).map_err(|_| invalid("fixture length"))?;
		if !(8..=134217728).contains(&length) { return Err(invalid("private fixture frame domain")); }
		let mut raw = vec![0u8; length];
		stdin.read_exact(&mut raw)?;
		if &raw[..8] == b"HVCACH01" {
			if raw.len() < 48 { return Err(invalid("short cache fixture")); }
			if word(&raw, 8) == 0 {
				if cache_initialized || raw.len() != 48 || raw[8..] != [0u8; 40] {
					return Err(invalid("cache setup is permitted once"));
				}
				cache_initialized = true;
				let mut answer = b"HVCAR001".to_vec(); answer.extend_from_slice(&[0u8; 24]);
				output(&answer)?;
			} else {
				if !cache_initialized { return Err(invalid("cache fixture before setup")); }
				output(&mcp::fs::delta::fixture_apply(&cache, &raw)?)?;
			}
			continue;
		}
		if &raw[..8] == b"HHISTQ01" {
			if raw.len() < 64 { return Err(invalid("short history fixture")); }
			if word(&raw, 8) == 0 {
				if history_initialized { return Err(invalid("history setup is permitted once")); }
				history_initialized = true;
			} else if !history_initialized { return Err(invalid("history fixture before setup")); }
			output(&mcp::fs::core::fixture_history_apply(&raw)?)?;
			continue;
		}
		if !cache_initialized || !history_initialized || raw.len() < 80 || &raw[..8] != b"HLTBRQ01"
			|| raw[64..80] != [0u8; 16]
		{
			return Err(invalid("non-admitted body fixture frame"));
		}
		let operation = word(&raw, 8);
		let context = word(&raw, 16);
		let pn = usize::try_from(word(&raw, 24)).map_err(|_| invalid("path length"))?;
		let on = usize::try_from(word(&raw, 32)).map_err(|_| invalid("old length"))?;
		let nn = usize::try_from(word(&raw, 40)).map_err(|_| invalid("new length"))?;
		let replace_all = word(&raw, 48);
		if !matches!(operation, 2..=4) || !matches!(context, 1..=2) || replace_all > 1
			|| word(&raw, 56) == 0 || (operation != 2 && (on != 0 || nn != 0 || replace_all != 0))
			|| pn > raw.len() - 80 || on > raw.len() - 80 - pn || nn != raw.len() - 80 - pn - on
		{
			return Err(invalid("body fixture fields"));
		}
		let generation = word(&raw, 56);
		let source = mcp::fs::PathSource::Local(PathBuf::from(OsString::from_vec(raw[80..80 + pn].to_vec())));
		let old = std::str::from_utf8(&raw[80 + pn..80 + pn + on]).map_err(|_| invalid("old UTF-8"))?;
		let new = std::str::from_utf8(&raw[80 + pn + on..]).map_err(|_| invalid("new UTF-8"))?;
		snapshot(&cache, 0, generation)?;
		let body = original_body(operation, &source, old, new, replace_all != 0);
		let (result, hints) = if context == 1 {
			runtime.block_on(mcp::request_ctx::with_request_context(cache.clone(), body))
		} else { runtime.block_on(body) };
		let (kind, message) = match result { Ok(text) => (0u64, text), Err(error) => (1, error.to_string()) };
		let mut response = b"HLTBRP01".to_vec();
		for value in [operation, kind, message.len() as u64] { response.extend_from_slice(&value.to_le_bytes()); }
		response.extend_from_slice(message.as_bytes());
		let mut hint_body = Vec::new();
		for hint in &hints {
			hint_body.extend_from_slice(&(hint.len() as u64).to_le_bytes());
			hint_body.extend_from_slice(hint.as_bytes());
		}
		let mut hint_frame = b"HLTBHT01".to_vec();
		for value in [48 + hint_body.len() as u64, generation, operation, kind, hints.len() as u64] {
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
