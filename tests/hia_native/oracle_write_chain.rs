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

//! Qualification transport around complete, byte-preserved original owners.
//! The native internal profile admits four concurrent requests. This envelope
//! uses actual Tokio tasks and abort handles; it never simulates their Drop.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[allow(dead_code)]
mod original {
	pub mod remote {
		use anyhow::{Result, anyhow};
		use std::path::PathBuf;
		include!("../original/path_source_original.rs");
		include!("../original/path_methods_wrapper.rs");
		include!("../original/io_read_original.rs");
		include!("../original/io_write_original.rs");
		include!("../original/io_exists_original.rs");
		mod sftp {
			use super::PathSource;
			use anyhow::Result;
			pub async fn remote_read_to_string(_: &PathSource) -> Result<String> {
				panic!("Remote is outside this exact Local reference domain")
			}
			pub async fn remote_write(_: &PathSource, _: &[u8]) -> Result<()> {
				panic!("Remote is outside this exact Local reference domain")
			}
			pub async fn remote_exists(_: &PathSource) -> Result<bool> {
				panic!("Remote is outside this exact Local reference domain")
			}
		}
	}
	pub mod text_editing {
		use super::remote::{PathSource, io_write};
		use anyhow::{Result, anyhow};
		use std::collections::HashMap;
		use std::path::Path;
		use std::sync::{Arc, Mutex, OnceLock};
		use tokio::sync::Mutex as AsyncMutex;
		include!("../original/file_lock_original.rs");
		include!("../original/atomic_write_original.rs");
	}
	pub mod delta {
		use super::remote::PathSource;
		use super::request_ctx::with_view_cache;
		use super::text_editing::lock_key_for_source;
		use std::collections::HashMap;
		use std::sync::Mutex;
		include!("../original/view_cache_original.rs");
		include!("../original/forget_original.rs");
	}
	pub mod request_ctx {
		use super::delta::ViewCache;
		use std::cell::RefCell;
		use std::sync::Arc;
		include!("../original/request_context_original.rs");
	}
	pub mod core {
		use super::remote::{PathSource, io_exists, io_read_to_string};
		use super::{delta, text_editing};
		use anyhow::{Result, anyhow, bail};
		use std::collections::HashMap;
		use std::sync::{Mutex, OnceLock};
		include!("../original/history_callers_original.rs");
	}
}

fn word(frame: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(frame[at..at + 8].try_into().unwrap())
}

fn answer(op: u64, result: Result<String>) -> Vec<u8> {
	let (status, body) = match result {
		Ok(value) => (0_u64, value),
		Err(error) => (1_u64, error.to_string()),
	};
	let mut out = b"HFWTR001".to_vec();
	out.extend_from_slice(&op.to_le_bytes());
	out.extend_from_slice(&status.to_le_bytes());
	out.extend_from_slice(&(body.len() as u64).to_le_bytes());
	out.extend_from_slice(body.as_bytes());
	out
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
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(4)
		.max_blocking_threads(4)
		.enable_time()
		.build()?;
	let active = Arc::new(Mutex::new(HashMap::<u64, tokio::task::AbortHandle>::new()));
	let cache = Arc::new(original::delta::ViewCache::default());
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
			return Err(anyhow!("trusted transport allocation capacity"));
		}
		let mut frame = vec![0; size as usize];
		input.read_exact(&mut frame)?;
		if frame.len() < 64
			|| &frame[..8] != b"HFWRT001"
			|| !(1..=2).contains(&word(&frame, 8))
			|| !(1..=2).contains(&word(&frame, 16))
			|| word(&frame, 24) != (frame.len() - 64) as u64
			|| frame[32..64].iter().any(|value| *value != 0)
		{
			send(&output, tag, u32::MAX, &[]);
			continue;
		}
		let mut registered = active.lock().unwrap();
		assert!(
			!registered.contains_key(&tag),
			"trusted request tag must be unique"
		);
		assert!(
			registered.len() < 4,
			"trusted profile admits four concurrent requests"
		);
		let source = original::remote::PathSource::Local(PathBuf::from(OsString::from_vec(
			frame[64..].to_vec(),
		)));
		let op = word(&frame, 8);
		let context = word(&frame, 16);
		let task_cache = cache.clone();
		let invocation_count = invoked.clone();
		let task = runtime.spawn(async move {
			let body = async move {
				invocation_count.fetch_add(1, Ordering::SeqCst);
				match op {
					1 => original::core::save_file_history(&source)
						.await
						.map(|()| String::new()),
					2 => original::core::undo_edit(&source).await,
					_ => unreachable!(),
				}
			};
			if context == 1 {
				original::request_ctx::with_request_context(task_cache, body).await
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
					let bytes = answer(op, result);
					(bytes.len() as u32, bytes)
				}
				Err(error) if error.is_cancelled() => {
					cancel_count.fetch_add(1, Ordering::SeqCst);
					(0xfffffff7, Vec::new())
				}
				Err(error) => panic!("original owner panicked: {error}"),
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
