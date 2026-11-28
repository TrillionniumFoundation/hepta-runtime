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

//! Actual complete original Local batch body behind a typed test transport.
//! This envelope decodes admitted projections and owns task lifetime. It does
//! not replace a function body, perform an edit, or format the owner's result.

use anyhow::{Result, anyhow};
use serde_json::Value;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

#[allow(dead_code)]
mod utils {
	pub mod line_hash {
		include!("../original/line_hash.rs");
	}
}

#[allow(dead_code)]
mod mcp {
	use serde::{Deserialize, Serialize};
	use serde_json::Value;
	use std::path::PathBuf;
	include!("../original/mcp_call.rs");
	pub mod request_ctx {
		include!("../original/request_ctx.rs");
	}
	pub mod fs {
		pub mod remote {
			use anyhow::{Result, anyhow};
			use std::path::{Path, PathBuf};
			use std::time::SystemTime;
			include!("../original/path_source.rs");
			include!("../original/remote_metadata.rs");
			include!("../original/io_metadata_type.rs");
			include!("../original/io_read.rs");
			include!("../original/io_write.rs");
			include!("../original/io_exists.rs");
			include!("../original/io_metadata.rs");
			include!("../original/io_remove.rs");
			mod sftp {
				use super::{PathSource, RemoteMetadata};
				use anyhow::Result;
				pub async fn remote_read_to_string(_: &PathSource) -> Result<String> {
					panic!("Remote is outside this exact Local owner comparison")
				}
				pub async fn remote_write(_: &PathSource, _: &[u8]) -> Result<()> {
					panic!("Remote is outside this exact Local owner comparison")
				}
				pub async fn remote_exists(_: &PathSource) -> Result<bool> {
					panic!("Remote is outside this exact Local owner comparison")
				}
				pub async fn remote_metadata(_: &PathSource) -> Result<RemoteMetadata> {
					panic!("Remote is outside this exact Local owner comparison")
				}
				pub async fn remote_remove_file(_: &PathSource) -> Result<()> {
					panic!("Remote is outside this exact Local owner comparison")
				}
			}
		}
		pub mod text_editing {
			include!("../original/text_editing.rs");
			include!("lock_observer.rs");
		}
		pub mod core {
			use super::remote::{PathSource, io_exists, io_read_to_string};
			use super::{delta, text_editing};
			use anyhow::{Result, anyhow, bail};
			use std::collections::HashMap;
			use std::sync::{Mutex, OnceLock};
			include!("../original/history.rs");
			include!("history_observer.rs");
		}
		pub mod delta {
			use super::remote::PathSource;
			use super::text_editing::lock_key_for_source;
			use crate::mcp::request_ctx::with_view_cache;
			use crate::utils::line_hash::line_id_at;
			use std::collections::HashMap;
			use std::sync::Mutex;
			include!("../original/view_cache.rs");
			include!("../original/removed_marker.rs");
			include!("cache_observer.rs");
		}
	}
}

fn word(frame: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(frame[at..at + 8].try_into().unwrap())
}

fn endpoint(raw: &[u8]) -> Value {
	assert!(raw.len() >= 32);
	assert_eq!(&raw[..8], b"HIAEP001");
	assert_eq!(word(raw, 16) as usize, raw.len() - 32);
	let scalar = word(raw, 24);
	match word(raw, 8) {
		0 => {
			assert_eq!(raw.len(), 32);
			Value::from(scalar as i64)
		}
		1 => {
			assert_eq!(raw.len(), 32);
			assert_eq!(scalar, 0);
			serde_json::from_str("1.0").unwrap()
		}
		2 => {
			assert_eq!(scalar, 0);
			Value::String(String::from_utf8(raw[32..].to_vec()).unwrap())
		}
		3 => {
			assert_eq!(scalar, 0);
			let value: Value = serde_json::from_slice(&raw[32..]).unwrap();
			assert!(!value.is_string() && !value.is_number() && !value.is_null());
			assert_eq!(value.to_string().as_bytes(), &raw[32..]);
			value
		}
		_ => panic!("invalid trusted endpoint frame"),
	}
}

fn decode(frame: &[u8], workdir: &std::path::Path) -> (mcp::McpToolCall, Vec<Value>) {
	let path_size = word(frame, 16) as usize;
	let display_size = word(frame, 24) as usize;
	let display =
		std::str::from_utf8(&frame[64 + path_size..64 + path_size + display_size]).unwrap();
	let mut at = 64 + path_size + display_size;
	let mut operations = Vec::new();
	for _ in 0..word(frame, 32) {
		let words: Vec<u64> = (0..9).map(|index| word(frame, at + index * 8)).collect();
		at += 72;
		assert!(words[..5].iter().all(|word| *word <= 1));
		let mut fields = Vec::new();
		for count in &words[5..] {
			let count = *count as usize;
			fields.push(&frame[at..at + count]);
			at += count;
		}
		if words[0] == 0 {
			assert!(words[1..].iter().all(|word| *word == 0));
			operations.push(Value::Null);
			continue;
		}
		let mut value = serde_json::Map::new();
		if words[1] == 1 {
			value.insert(
				"operation".into(),
				Value::String(std::str::from_utf8(fields[0]).unwrap().into()),
			);
		} else {
			assert!(fields[0].is_empty());
		}
		for (flag, name, bytes) in [(words[2], "start", fields[1]), (words[3], "end", fields[2])] {
			if flag == 1 {
				value.insert(name.into(), endpoint(bytes));
			} else {
				assert!(bytes.is_empty());
			}
		}
		if words[4] == 1 {
			value.insert(
				"content".into(),
				Value::String(std::str::from_utf8(fields[3]).unwrap().into()),
			);
		} else {
			assert!(fields[3].is_empty());
		}
		operations.push(Value::Object(value));
	}
	assert_eq!(at, frame.len());
	let present = word(frame, 48);
	let call = mcp::McpToolCall {
		tool_name: "batch_edit".into(),
		tool_id: "native-original-qualification".into(),
		parameters: if present == 1 {
			serde_json::json!({"path": display})
		} else {
			Value::Null
		},
		workdir: workdir.to_path_buf(),
	};
	// This checks the actual original resolver, never substitutes a test path.
	if present == 1 && !operations.is_empty() && operations.len() <= 50 {
		let resolved = mcp::fs::remote::resolve_path_source(display, &call.workdir);
		let mcp::fs::remote::PathSource::Local(path) = resolved else {
			panic!("Remote path is outside this Local body comparison")
		};
		assert_eq!(path.as_os_str().as_bytes(), &frame[64..64 + path_size]);
	}
	(call, operations)
}

fn answer(result: Result<String>) -> Vec<u8> {
	let (status, body) = match result {
		Ok(body) => (0_u64, body),
		Err(error) => (1_u64, error.to_string()),
	};
	let mut output = b"HFBWR001".to_vec();
	for word in [status, body.len() as u64, 0] {
		output.extend_from_slice(&word.to_le_bytes());
	}
	output.extend_from_slice(body.as_bytes());
	output
}

// Qualification-only serial transport. The included production functions and
// their argument decoder above are unchanged; all observer access is read-only.

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

fn main() -> Result<()> {
	std::panic::set_hook(Box::new(|_| {}));
	if std::env::args_os().len() != 1 {
		return Err(invalid("fixture does not accept arguments").into());
	}
	let workdir = std::env::current_dir()?;
	let runtime = tokio::runtime::Builder::new_current_thread()
		.max_blocking_threads(1)
		.build()?;
	let cache = Arc::new(mcp::fs::delta::ViewCache::default());
	let mut cache_initialized = false;
	let mut history_initialized = false;
	let mut generation = 0u64;
	let mut stdin = io::stdin().lock();
	loop {
		let mut length = [0u8; 8];
		if stdin.read(&mut length[..1])? == 0 {
			break;
		}
		stdin.read_exact(&mut length[1..])?;
		let length = usize::try_from(u64::from_le_bytes(length))
			.map_err(|_| invalid("fixture length"))?;
		if !(8..=536870912).contains(&length) {
			return Err(invalid("private fixture frame domain").into());
		}
		let mut raw = vec![0u8; length];
		stdin.read_exact(&mut raw)?;
		if &raw[..8] == b"HVCACH01" {
			if raw.len() < 48 {
				return Err(invalid("short cache fixture").into());
			}
			if word(&raw, 8) == 0 {
				if cache_initialized || raw.len() != 48 || raw[8..] != [0u8; 40] {
					return Err(invalid("cache setup is permitted once").into());
				}
				cache_initialized = true;
				let mut response = b"HVCAR001".to_vec();
				response.extend_from_slice(&[0u8; 24]);
				output(&response)?;
			} else {
				if !cache_initialized {
					return Err(invalid("cache fixture before setup").into());
				}
				output(&mcp::fs::delta::fixture_apply(&cache, &raw)?)?;
			}
			continue;
		}
		if &raw[..8] == b"HHISTQ01" {
			if raw.len() < 64 {
				return Err(invalid("short history fixture").into());
			}
			if word(&raw, 8) == 0 {
				if history_initialized || raw.len() != 64 || raw[8..] != [0u8; 56] {
					return Err(invalid("history setup is permitted once").into());
				}
				history_initialized = true;
			} else if !history_initialized {
				return Err(invalid("history fixture before setup").into());
			}
			output(&mcp::fs::core::fixture_history_apply(&raw)?)?;
			continue;
		}
		if !cache_initialized || !history_initialized || raw.len() < 64
			|| &raw[..8] != b"HFBWT001"
			|| !(1..=2).contains(&word(&raw, 8))
			|| word(&raw, 16) > raw.len() as u64 - 64
			|| word(&raw, 24) > raw.len() as u64 - 64 - word(&raw, 16)
			|| word(&raw, 40) != raw.len() as u64 - 64 - word(&raw, 16) - word(&raw, 24)
			|| word(&raw, 48) > 1 || word(&raw, 56) != 0
		{
			return Err(invalid("non-admitted Batch fixture frame").into());
		}
		generation = generation.checked_add(1).expect("finite fixture generation");
		let (call, operations) = decode(&raw, &workdir);
		let context = word(&raw, 8);
		snapshot(&cache, 0, generation)?;
		let body = async {
			let result = mcp::fs::text_editing::batch_edit_spec(&call, &operations).await;
			(result, mcp::request_ctx::drain_hints())
		};
		let (result, hints) = if context == 1 {
			runtime.block_on(mcp::request_ctx::with_request_context(cache.clone(), body))
		} else {
			runtime.block_on(body)
		};
		let response = answer(result);
		let mut hint_body = Vec::new();
		for hint in &hints {
			hint_body.extend_from_slice(&(hint.len() as u64).to_le_bytes());
			hint_body.extend_from_slice(hint.as_bytes());
		}
		let mut hint_frame = b"HLBBHT01".to_vec();
		for value in [48 + hint_body.len() as u64, generation, 1, word(&response, 8), hints.len() as u64] {
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
