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

//! Actual unchanged canonical-key owner under the native typed transport.

use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;

#[allow(dead_code)]
mod original {
	use anyhow::Result;
	use std::collections::HashMap;
	use std::path::{Path, PathBuf};
	use std::sync::{Arc, Mutex, OnceLock};
	use tokio::sync::Mutex as AsyncMutex;
	include!(concat!(env!("OUT_DIR"), "/path_source_original.rs"));
	include!(concat!(env!("OUT_DIR"), "/path_key_original.rs"));
	include!(concat!(env!("OUT_DIR"), "/file_lock_original.rs"));
}

fn word(bytes: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn main() {
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	let (mut rows, mut local, mut remote, mut metadata_projection_calls) =
		(0_u64, 0_u64, 0_u64, 0_u64);
	loop {
		let mut size = [0_u8; 8];
		match input.read(&mut size[..1]) {
			Ok(0) => break,
			Ok(1) => input.read_exact(&mut size[1..]).unwrap(),
			other => panic!("invalid frame header: {other:?}"),
		}
		let mut bytes = vec![0; usize::try_from(u64::from_le_bytes(size)).unwrap()];
		input.read_exact(&mut bytes).unwrap();
		assert!(bytes.len() >= 64 && &bytes[..8] == b"HRLKKEY1");
		let op = word(&bytes, 8);
		let path_length = usize::try_from(word(&bytes, 16)).unwrap();
		let host_length = usize::try_from(word(&bytes, 24)).unwrap();
		let port = u16::try_from(word(&bytes, 32)).unwrap();
		assert_eq!(bytes.len(), 64 + path_length + host_length);
		assert!(bytes[40..64].iter().all(|&value| value == 0));
		let key = match op {
			1 => {
				assert_eq!((host_length, port), (0, 0));
				local += 1;
				let path = std::ffi::OsString::from_vec(bytes[64..].to_vec());
				original::lock_key_for_source(&original::PathSource::Local(path.into()))
			}
			2 => {
				remote += 1;
				let path = String::from_utf8(bytes[64..64 + path_length].to_vec()).unwrap();
				let host = String::from_utf8(bytes[64 + path_length..].to_vec()).unwrap();
				let mut value = None;
				for user in ["", "different-owner"] {
					for user_explicit in [false, true] {
						for port_explicit in [false, true] {
							let candidate =
								original::lock_key_for_source(&original::PathSource::Remote {
									host: host.clone(),
									port,
									user: user.to_owned(),
									path: path.clone(),
									user_explicit,
									port_explicit,
								});
							if let Some(expected) = &value {
								assert_eq!(&candidate, expected);
							} else {
								value = Some(candidate);
							}
							metadata_projection_calls += 1;
						}
					}
				}
				value.unwrap()
			}
			_ => panic!("not in the original typed domain"),
		};
		let mut answer = Vec::with_capacity(32 + key.len());
		answer.extend_from_slice(b"HRLKY001");
		answer.extend_from_slice(&op.to_le_bytes());
		answer.extend_from_slice(&(key.len() as u64).to_le_bytes());
		answer.extend_from_slice(&0_u64.to_le_bytes());
		answer.extend_from_slice(key.as_bytes());
		output
			.write_all(&u32::try_from(answer.len()).unwrap().to_le_bytes())
			.unwrap();
		output.write_all(&answer).unwrap();
		rows += 1;
	}
	output.flush().unwrap();
	eprintln!(
		"{{\"status\":\"PASS\",\"rows\":{rows},\"local_rows\":{local},\"remote_rows\":{remote},\"remote_metadata_projection_calls\":{metadata_projection_calls},\"actual_original_owner_calls\":{}}}",
		local + metadata_projection_calls
	);
}
