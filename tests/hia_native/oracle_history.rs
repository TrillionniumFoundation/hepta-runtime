// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Actual original HistoryStore; the surrounding wire adapter is test-only.
#![allow(dead_code)]
use std::collections::HashMap;
use std::io::{self, Read, Write};

#[rustfmt::skip]
mod original {
use std::collections::HashMap;
use std::sync::Mutex;
const MAX_HISTORY_PER_FILE: usize = 10;
const MAX_HISTORY_TOTAL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct HistoryStore {
	files: HashMap<String, Vec<String>>,
	// One entry per snapshot push, oldest first. May reference paths whose oldest
	// snapshot is already gone (undo pops, per-file cap) — eviction skips those.
	order: std::collections::VecDeque<String>,
	total_bytes: usize,
}

impl HistoryStore {
	fn push(&mut self, key: String, content: String, byte_cap: usize) {
		self.total_bytes += content.len();
		let history = self.files.entry(key.clone()).or_default();
		if history.len() >= MAX_HISTORY_PER_FILE {
			let removed = history.remove(0);
			self.total_bytes -= removed.len();
		}
		history.push(content);
		self.order.push_back(key);

		// Over budget: drop the globally oldest snapshots. `len() > 1` keeps the
		// snapshot just pushed even if it alone exceeds the cap — evicting it
		// would silently break undo for the file being edited right now.
		while self.total_bytes > byte_cap && self.order.len() > 1 {
			let Some(oldest) = self.order.pop_front() else {
				break;
			};
			let Some(history) = self.files.get_mut(&oldest) else {
				continue;
			};
			if history.is_empty() {
				self.files.remove(&oldest);
				continue;
			}
			let removed = history.remove(0);
			self.total_bytes -= removed.len();
			if history.is_empty() {
				self.files.remove(&oldest);
			}
		}
	}

	fn pop(&mut self, key: &str) -> Option<String> {
		let history = self.files.get_mut(key)?;
		let content = history.pop()?;
		self.total_bytes -= content.len();
		if history.is_empty() {
			self.files.remove(key);
		}
		Some(content)
	}
}


pub struct Session { inner: Mutex<HistoryStore> }
impl Session {
    pub fn new() -> Self { Self { inner: Mutex::new(HistoryStore::default()) } }
    pub fn invoke(&self, op: u64, key: String, value: String, cap: usize) -> Vec<u8> {
        let mut body = String::new();
        let mut kind = 0u64;
        if op == 3 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = self.inner.lock().unwrap();
                panic!("actual history mutex poison fixture");
            }));
            assert!(result.is_err() && self.inner.is_poisoned());
        } else if op != 0 {
            match self.inner.lock() {
                Err(_) => kind = 3,
                Ok(mut state) => {
                    if op == 1 { state.push(key, value, cap); }
                    else if op == 2 {
                        match state.pop(&key) {
                            Some(content) => { body = content; kind = 1; }
                            None => kind = 2,
                        }
                    } else { panic!("unknown original operation") }
                }
            }
        }
        let state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let snapshots: usize = state.files.values().map(Vec::len).sum();
        let mut output = Vec::with_capacity(64 + body.len());
        output.extend_from_slice(b"HHISTR01");
        for word in [kind, body.len() as u64, state.total_bytes as u64, snapshots as u64,
                     state.order.len() as u64, u64::from(self.inner.is_poisoned()), 0] {
            output.extend_from_slice(&word.to_le_bytes());
        }
        output.extend_from_slice(body.as_bytes());
        output
    }
}
}

fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut sessions = HashMap::new();
    let (mut rows, mut operations, mut lifecycles, mut poisons) = (0u64, 0u64, 0u64, 0u64);
    loop {
        let mut header = [0u8; 8];
        match input.read(&mut header[..1]) {
            Ok(0) => break,
            Ok(1) => input.read_exact(&mut header[1..]).unwrap(),
            _ => panic!("history reference read"),
        }
        let sid = u32::from_le_bytes(header[..4].try_into().unwrap());
        let size = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        assert!((64..=128 << 20).contains(&size));
        let mut raw = vec![0u8; size];
        input.read_exact(&mut raw).unwrap();
        assert_eq!(&raw[..8], b"HHISTQ01");
        let op = word(&raw, 8);
        let cap = word(&raw, 16) as usize;
        let kn = word(&raw, 24) as usize;
        let vn = word(&raw, 32) as usize;
        assert!(op <= 4 && kn <= raw.len() - 64 && vn == raw.len() - 64 - kn);
        assert_eq!((word(&raw, 40), word(&raw, 48), word(&raw, 56)), (0, 0, 0));
        assert!(op == 1 || (cap == 0 && vn == 0));
        assert!(op == 1 || op == 2 || kn == 0);
        let key = std::str::from_utf8(&raw[64..64 + kn]).unwrap().to_owned();
        let value = std::str::from_utf8(&raw[64 + kn..]).unwrap().to_owned();
        if op == 0 {
            assert!(sessions.insert(sid, original::Session::new()).is_none());
        }
        let result = if op == 4 {
            assert!(sessions.remove(&sid).is_some());
            let mut bytes = b"HHISTR01".to_vec();
            bytes.extend_from_slice(&[0u8; 56]);
            bytes
        } else {
            sessions.get(&sid).unwrap().invoke(op, key, value, cap)
        };
        output
            .write_all(&(result.len() as u32).to_le_bytes())
            .unwrap();
        output.write_all(&result).unwrap();
        rows += 1;
        if op == 0 || op == 4 {
            lifecycles += 1;
        } else if op == 3 {
            poisons += 1;
        } else {
            operations += 1;
        }
    }
    assert!(sessions.is_empty());
    output.flush().unwrap();
    eprintln!("{{\"status\":\"PASS\",\"original_history_rows\":{rows},\"original_history_operations\":{operations},\"lifecycle_rows\":{lifecycles},\"poison_rows\":{poisons}}}");
}
