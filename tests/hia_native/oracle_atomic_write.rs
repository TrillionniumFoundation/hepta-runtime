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

//! Qualification only: actual Tokio atomic_write, with a typed binary envelope.

use anyhow::{Result, anyhow};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone)]
pub enum PathSource {
	Local(PathBuf),
	Remote {
		host: String,
		port: u16,
		user: String,
		path: String,
		user_explicit: bool,
		port_explicit: bool,
	},
}

async fn io_write(_: &PathSource, _: &[u8]) -> Result<()> {
	panic!("the local-only reference must never select remote dispatch")
}

include!(concat!(env!("OUT_DIR"), "/atomic_write_original.rs"));

static CANCEL: AtomicBool = AtomicBool::new(false);

extern "C" fn canceled(_: libc::c_int) {
	CANCEL.store(true, Ordering::SeqCst);
}

fn hex(value: &[u8]) -> String {
	value.iter().map(|b| format!("{b:02x}")).collect()
}

fn word(data: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

fn answer(tag: u64, stage: u64, payload: &[u8]) -> Vec<u8> {
	let mut result = b"HRAWR001".to_vec();
	result.extend_from_slice(&tag.to_le_bytes());
	result.extend_from_slice(&stage.to_le_bytes());
	result.extend_from_slice(&(payload.len() as u64).to_le_bytes());
	result.extend_from_slice(payload);
	result
}

fn properties() -> Result<()> {
	for code in 1..=4095 {
		println!(
			"{code}\t{}",
			hex(io::Error::from_raw_os_error(code).to_string().as_bytes())
		);
	}
	println!(
		"65536\t{}",
		hex(std::fs::metadata("a\0b")
			.unwrap_err()
			.to_string()
			.as_bytes())
	);
	println!(
		"65537\t{}",
		hex(io::Error::from(io::ErrorKind::WriteZero)
			.to_string()
			.as_bytes())
	);
	Ok(())
}

fn main() -> Result<()> {
	if std::env::args().nth(1).as_deref() == Some("--properties") {
		return properties();
	}
	unsafe {
		let mut action: libc::sigaction = std::mem::zeroed();
		action.sa_sigaction = canceled as usize;
		action.sa_flags = libc::SA_RESTART;
		libc::sigemptyset(&mut action.sa_mask);
		assert_eq!(
			libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()),
			0
		);
		let mut mask: libc::sigset_t = std::mem::zeroed();
		libc::sigemptyset(&mut mask);
		libc::sigaddset(&mut mask, libc::SIGUSR1);
		assert_eq!(
			libc::sigprocmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut()),
			0
		);
	}
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.max_blocking_threads(1)
		.enable_time()
		.build()?;
	let mut input = io::stdin().lock();
	let mut output = io::stdout().lock();
	loop {
		let mut length = [0; 8];
		let first = input.read(&mut length[..1])?;
		if first == 0 {
			break;
		}
		input.read_exact(&mut length[1..])?;
		let size = u64::from_le_bytes(length);
		if size > 512 << 20 {
			return Err(anyhow!("typed transport capacity"));
		}
		let mut frame = vec![0; size as usize];
		input.read_exact(&mut frame)?;
		let mut code = u32::MAX;
		let mut response = Vec::new();
		let valid = frame.len() >= 64
			&& &frame[..8] == b"HRAWI001"
			&& [1, 2].contains(&word(&frame, 8))
			&& frame[32..64].iter().all(|b| *b == 0)
			&& word(&frame, 16) <= (frame.len() - 64) as u64
			&& word(&frame, 24) == frame.len() as u64 - 64 - word(&frame, 16);
		if valid {
			let path_len = word(&frame, 16) as usize;
			let path = PathBuf::from(OsString::from_vec(frame[64..64 + path_len].to_vec()));
			if let Ok(content) = std::str::from_utf8(&frame[64 + path_len..]) {
				if word(&frame, 8) == 2 && content.is_empty() {
					let parent = path.parent().unwrap_or_else(|| Path::new("."));
					let tmp = parent.join(format!(
						".octofs_tmp_{}.tmp",
						path.file_name().unwrap_or_default().to_string_lossy()
					));
					response = answer(2, 0, tmp.as_os_str().as_bytes());
					code = response.len() as u32;
				} else if word(&frame, 8) == 1 {
					if CANCEL.load(Ordering::SeqCst) {
						code = 0xfffffff7;
					} else {
						let source = PathSource::Local(path);
						let contents = content.to_owned();
						let task =
							runtime.spawn(async move { atomic_write(&source, &contents).await });
						let result = runtime.block_on(async {
							while !task.is_finished() {
								if CANCEL.load(Ordering::SeqCst) {
									task.abort();
									break;
								}
								tokio::time::sleep(std::time::Duration::from_millis(1)).await;
							}
							task.await
						});
						match result {
							Err(e) if e.is_cancelled() => code = 0xfffffff7,
							Err(e) => return Err(e.into()),
							Ok(Ok(())) => response = answer(0, 0, &[]),
							Ok(Err(e)) => {
								let text = e.to_string();
								let stage = if text.starts_with("Failed to read metadata") {
									1
								} else if text.starts_with("Failed to write temp file") {
									2
								} else if text.starts_with("Failed to preserve permissions") {
									3
								} else if text.starts_with("Failed to atomically replace") {
									4
								} else {
									panic!("unrecognized original error: {text}")
								};
								response = answer(1, stage, text.as_bytes());
							}
						}
						if !response.is_empty() {
							code = response.len() as u32;
						}
					}
				}
			}
		}
		output.write_all(&code.to_le_bytes())?;
		output.write_all(&response)?;
		output.flush()?;
		if code == 0xfffffff7 {
			// A single blocking worker gives the qualification envelope a real
			// completion barrier after cancellation. The unchanged owner itself
			// still completes its already-started blocking filesystem operation.
			runtime.block_on(async { tokio::task::spawn_blocking(|| ()).await })?;
		}
		CANCEL.store(false, Ordering::SeqCst);
	}
	drop(runtime);
	Ok(())
}
