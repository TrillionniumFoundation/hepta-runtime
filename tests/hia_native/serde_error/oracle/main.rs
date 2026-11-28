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
//
//! Locked serde_json::from_slice::<Value> error observer, without translation.
use std::io::{Read, Write};

fn word(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn main() -> std::io::Result<()> {
	let probe = std::env::args().nth(1).as_deref() == Some("--probe");
	assert!(std::env::args().count() == if probe { 2 } else { 1 });
	let mut incoming = std::io::stdin().lock();
	let mut outgoing = std::io::stdout().lock();
	let mut count = 0u64;
	loop {
		let mut size = [0; 8];
		if incoming.read(&mut size[..1])? == 0 {
			break;
		}
		incoming.read_exact(&mut size[1..])?;
		let size = u64::from_le_bytes(size) as usize;
		assert!((24..=8388632).contains(&size));
		let mut frame = vec![0; size];
		incoming.read_exact(&mut frame)?;
		assert_eq!(&frame[..8], b"HSJERQ01");
		assert_eq!(word(&frame, 8), 1);
		assert_eq!(word(&frame, 16), (size - 24) as u64);
		let result = serde_json::from_slice::<serde_json::Value>(&frame[24..]);
		let mut reply = vec![0; 64];
		reply[..8].copy_from_slice(b"HSJERR01");
		let probe_value = match result {
			Ok(value) => serde_json::json!({"ordinal":count,"valid":true,"value":value}),
			Err(error) => {
				let category = match error.classify() {
					serde_json::error::Category::Syntax => 1u64,
					serde_json::error::Category::Eof => 2,
					serde_json::error::Category::Data => 3,
					serde_json::error::Category::Io => 4,
				};
				let message = error.to_string();
				for (offset, value) in [
					(8, 1u64),
					(16, category),
					(24, error.line() as u64),
					(32, error.column() as u64),
					(40, message.len() as u64),
				] {
					reply[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
				}
				reply.extend_from_slice(message.as_bytes());
				serde_json::json!({"ordinal":count,"valid":false,"category":category,
					"line":error.line(),"column":error.column(),"message":message})
			}
		};
		if probe {
			serde_json::to_writer(&mut outgoing, &probe_value)?;
			outgoing.write_all(b"\n")?;
		} else {
			outgoing.write_all(&(reply.len() as u32).to_le_bytes())?;
			outgoing.write_all(&(reply.len() as u64).to_le_bytes())?;
			outgoing.write_all(&reply)?;
		}
		count += 1;
	}
	outgoing.flush()?;
	eprintln!("{{\"status\":\"PASS\",\"original_owner_calls\":{count},\"adapter_only_rows\":0}}");
	Ok(())
}
