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
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
		}
		pub mod core {
			use super::remote::{PathSource, io_exists, io_read_to_string};
			use super::{delta, text_editing};
			use anyhow::{Result, anyhow, bail};
			use std::collections::HashMap;
			use std::sync::{Mutex, OnceLock};
			include!("../original/history.rs");
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

fn send(output: &Mutex<io::Stdout>, tag: u64, code: u32, bytes: &[u8]) {
	let mut output = output.lock().unwrap();
	output.write_all(&tag.to_le_bytes()).unwrap();
	let tid = unsafe { libc::syscall(libc::SYS_gettid) as u64 };
	output.write_all(&tid.to_le_bytes()).unwrap();
	output.write_all(&code.to_le_bytes()).unwrap();
	output.write_all(bytes).unwrap();
	output.flush().unwrap();
}

fn main() -> Result<()> {
	// Workdir is trusted caller metadata; capture it before admitting requests.
	// The complete original body and resolver below remain byte-for-byte intact.
	let workdir = std::env::current_dir()?;
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(4)
		.max_blocking_threads(4)
		.enable_time()
		.build()?;
	let active = Arc::new(Mutex::new(HashMap::<u64, tokio::task::AbortHandle>::new()));
	let cache = Arc::new(mcp::fs::delta::ViewCache::default());
	let output = Arc::new(Mutex::new(io::stdout()));
	let invoked = Arc::new(AtomicU64::new(0));
	let completed = Arc::new(AtomicU64::new(0));
	let canceled = Arc::new(AtomicU64::new(0));
	let mut input = io::stdin().lock();
	loop {
		let mut header = [0; 16];
		match input.read(&mut header[..1]) {
			Ok(0) => break,
			Ok(1) => (),
			Ok(_) => unreachable!(),
			Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
			Err(error) => return Err(error.into()),
		}
		input.read_exact(&mut header[1..])?;
		let size = word(&header, 0);
		let tag = word(&header, 8);
		if size == u64::MAX {
			if let Some(handle) = active.lock().unwrap().get(&tag) {
				handle.abort();
			}
			continue;
		}
		if size > 512 << 20 {
			return Err(anyhow!("trusted input allocation capacity"));
		}
		let mut frame = vec![0; size as usize];
		input.read_exact(&mut frame)?;
		if frame.len() < 64
			|| &frame[..8] != b"HFBWT001"
			|| !(1..=2).contains(&word(&frame, 8))
			|| word(&frame, 16) > frame.len() as u64 - 64
			|| word(&frame, 24) > frame.len() as u64 - 64 - word(&frame, 16)
			|| word(&frame, 40) != frame.len() as u64 - 64 - word(&frame, 16) - word(&frame, 24)
			|| word(&frame, 48) > 1
			|| word(&frame, 56) != 0
		{
			send(&output, tag, u32::MAX, &[]);
			continue;
		}
		let (call, operations) = decode(&frame, &workdir);
		let context = word(&frame, 8);
		let mut registered = active.lock().unwrap();
		assert!(!registered.contains_key(&tag));
		assert!(registered.len() < 4);
		let task_cache = cache.clone();
		let invocation_count = invoked.clone();
		let task = runtime.spawn(async move {
			let body = async move {
				invocation_count.fetch_add(1, Ordering::SeqCst);
				mcp::fs::text_editing::batch_edit_spec(&call, &operations).await
			};
			if context == 1 {
				mcp::request_ctx::with_request_context(task_cache, body).await
			} else {
				body.await
			}
		});
		registered.insert(tag, task.abort_handle());
		let task_active = active.clone();
		let task_output = output.clone();
		let complete_count = completed.clone();
		let cancel_count = canceled.clone();
		runtime.spawn(async move {
			let (code, bytes) = match task.await {
				Ok(result) => {
					let bytes = answer(result);
					assert!(bytes.len() < 0xffff0000);
					(bytes.len() as u32, bytes)
				}
				Err(error) if error.is_cancelled() => {
					cancel_count.fetch_add(1, Ordering::SeqCst);
					(0xfffffff7, Vec::new())
				}
				Err(error) => panic!("actual original batch owner panicked: {error}"),
			};
			task_active.lock().unwrap().remove(&tag).unwrap();
			send(&task_output, tag, code, &bytes);
			complete_count.fetch_add(1, Ordering::SeqCst);
		});
	}
	runtime.block_on(async {
		while !active.lock().unwrap().is_empty() || Arc::strong_count(&output) != 1 {
			tokio::time::sleep(std::time::Duration::from_millis(1)).await;
		}
	});
	drop(runtime);
	eprintln!(
		"{{\"status\":\"PASS\",\"original_owner_calls\":{},\"responses\":{},\"canceled\":{}}}",
		invoked.load(Ordering::SeqCst),
		completed.load(Ordering::SeqCst),
		canceled.load(Ordering::SeqCst)
	);
	Ok(())
}
