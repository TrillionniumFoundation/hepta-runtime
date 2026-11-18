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

//! Differential oracle for original serial ViewCache state operations.
//!
//! PathSource here carries the already admitted lock key. This adapter does
//! not assert filesystem canonicalization or Tokio task-local implementation.
#![allow(dead_code)]
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::Arc;

thread_local! {
	static CURRENT: RefCell<Option<Arc<original::ViewCache>>> = const { RefCell::new(None) };
}

fn word(raw: &[u8], at: usize) -> usize {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
		.try_into()
		.unwrap()
}

fn response(value: Option<String>) -> Vec<u8> {
	let mut out = b"HVCAR001".to_vec();
	out.extend_from_slice(&u64::from(value.is_some()).to_le_bytes());
	out.extend_from_slice(&(value.as_ref().map_or(0, String::len) as u64).to_le_bytes());
	out.extend_from_slice(&0u64.to_le_bytes());
	if let Some(value) = value {
		out.extend_from_slice(value.as_bytes());
	}
	out
}

#[rustfmt::skip]
mod original {
    use std::collections::HashMap;
    use std::sync::Mutex;
    struct PathSource(String);
    fn lock_key_for_source(source: &PathSource) -> String { source.0.clone() }
    fn with_view_cache<R>(f: impl FnOnce(&ViewCache) -> R) -> Option<R> {
        crate::CURRENT.with(|slot| slot.borrow().as_ref().map(|cache| f(cache)))
    }

// BEGIN EXACT ORIGINAL CACHE OWNER
const MAX_CACHED_BYTES: usize = 1024 * 1024;
/// Context lines around each hunk, matching edit diffs.
const CONTEXT: usize = 2;
/// Edit-distance ceiling for a delta. Beyond it the full file is about as
/// short, and the Myers trace (O(D²) memory) would start to cost.
const MAX_EDIT_DISTANCE: usize = 500;

/// Last full content served per file, keyed like the file locks.
// ponytail: unbounded per session (1MB cap per entry); add LRU eviction if a
// session ever views thousands of large files.
#[derive(Debug, Default)]
pub struct ViewCache {
	entries: Mutex<HashMap<String, String>>,
}

impl ViewCache {
	/// Publication can outlive its request. An owned publisher clears this
	/// session directly, without relying on a request-local cache context.
	pub(crate) fn forget_all(&self) {
		if let Ok(mut entries) = self.entries.lock() {
			entries.clear();
		}
	}

	fn get(&self, key: &str) -> Option<String> {
		self.entries.lock().ok()?.get(key).cloned()
	}

	fn set(&self, key: String, content: String) {
		let Ok(mut entries) = self.entries.lock() else {
			return;
		};
		if content.len() > MAX_CACHED_BYTES {
			entries.remove(&key);
		} else {
			entries.insert(key, content);
		}
	}

	fn forget(&self, key: &str) {
		if let Ok(mut entries) = self.entries.lock() {
			entries.remove(key);
		}
	}

	/// A directory relocation invalidates its cached descendants as well as
	/// the directory key. Use an explicit separator boundary so `old` cannot
	/// invalidate a sibling named `old2`. Other sessions keep separate caches.
	fn forget_subtree(&self, key: &str) {
		let prefix = format!("{}/", key.trim_end_matches('/'));
		if let Ok(mut entries) = self.entries.lock() {
			entries.retain(|name, _| name != key && !name.starts_with(&prefix));
		}
	}
}

/// Line-ending agnostic form: views and edits both work on `lines()`.
fn normalize(content: &str) -> String {
	content.replace("\r\n", "\n")
}

/// Record a write this server performed. The entry stays valid only if the
/// model's picture was current before the write (`before` matches the cache);
/// otherwise it is dropped so the next whole-file view is served in full.
pub fn note_write(source: &PathSource, before: &str, after: &str) {
	let key = lock_key_for_source(source);
	let before = normalize(before);
	with_view_cache(|cache| {
		if cache.get(&key).as_deref() == Some(before.as_str()) {
			cache.set(key.clone(), normalize(after));
		} else {
			cache.forget(&key);
		}
	});
}

/// Record a file the model created: it authored every line.
pub fn note_create(source: &PathSource, content: &str) {
	let key = lock_key_for_source(source);
	with_view_cache(|cache| cache.set(key.clone(), normalize(content)));
}

/// Drop the entry for a file whose content the model can no longer predict.
pub fn forget(source: &PathSource) {
	let key = lock_key_for_source(source);
	with_view_cache(|cache| cache.forget(&key));
}

/// Invalidate the directory itself and all cached file paths beneath it.
/// Moving a directory makes every descendant's previous cache identity stale;
/// invalidating only the directory key would retain misleading file deltas.
pub fn forget_subtree(source: &PathSource) {
	let key = lock_key_for_source(source);
	with_view_cache(|cache| cache.forget_subtree(&key));
}


// END EXACT ORIGINAL CACHE OWNER

    pub fn apply(cache: &ViewCache, raw: &[u8]) -> Option<String> {
        let op = crate::word(raw, 8);
        let flags = crate::word(raw, 16);
        let kn = crate::word(raw, 24);
        let an = crate::word(raw, 32);
        let bn = crate::word(raw, 40);
        assert_eq!(raw.len(), 48 + kn + an + bn);
        let key = std::str::from_utf8(&raw[48..48 + kn]).unwrap();
        let a = &raw[48 + kn..48 + kn + an];
        let b = &raw[48 + kn + an..];
        match op {
            1 if flags == 0 => return cache.get(key),
            1 => return with_view_cache(|cache| cache.get(key)).flatten(),
            2 if flags == 0 => cache.set(key.into(), std::str::from_utf8(a).unwrap().into()),
            2 => { with_view_cache(|cache| cache.set(key.into(), std::str::from_utf8(a).unwrap().into())); }
            3 if flags == 0 => cache.forget(key),
            3 => forget(&PathSource(key.into())),
            4 if flags == 0 => cache.forget_subtree(key),
            4 => forget_subtree(&PathSource(key.into())),
            5 => cache.forget_all(),
            6 => note_create(&PathSource(key.into()), std::str::from_utf8(a).unwrap()),
            7 => note_write(&PathSource(key.into()), std::str::from_utf8(a).unwrap(), std::str::from_utf8(b).unwrap()),
            8 => {
                let action = crate::word(a, 24);
                let size = crate::word(a, 32);
                let start = 128 + crate::word(a, 16);
                assert_eq!(start + size, a.len());
                match action {
                    0 => (),
                    1 => cache.set(key.into(), std::str::from_utf8(&a[start..]).unwrap().into()),
                    2 => cache.forget(key),
                    _ => panic!("non-admitted plan"),
                }
            }
            9 => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _guard = cache.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    panic!("test-only original Mutex poisoning event");
                }));
                assert!(result.is_err());
                assert!(cache.entries.is_poisoned());
            }
            _ => panic!("non-admitted original operation"),
        }
        None
    }
}

fn main() {
	std::panic::set_hook(Box::new(|_| {}));
	let mut stdin = io::stdin().lock();
	let mut stdout = io::BufWriter::new(io::stdout().lock());
	let mut sessions: HashMap<u32, Arc<original::ViewCache>> = HashMap::new();
	loop {
		let mut head = [0u8; 8];
		match stdin.read(&mut head[..1]) {
			Ok(0) => break,
			Ok(1) => stdin.read_exact(&mut head[1..]).unwrap(),
			_ => panic!("partial input header"),
		}
		let id = u32::from_le_bytes(head[..4].try_into().unwrap());
		let length = u32::from_le_bytes(head[4..].try_into().unwrap()) as usize;
		assert!((48..=16 << 20).contains(&length));
		let mut raw = vec![0u8; length];
		stdin.read_exact(&mut raw).unwrap();
		assert_eq!(&raw[..8], b"HVCACH01");
		let op = word(&raw, 8);
		let result = if op == 0 {
			assert!(
				sessions
					.insert(id, Arc::new(original::ViewCache::default()))
					.is_none()
			);
			response(None)
		} else if op == 10 {
			assert!(sessions.remove(&id).is_some());
			response(None)
		} else {
			let cache = sessions.get(&id).unwrap();
			CURRENT.with(|slot| {
				*slot.borrow_mut() = if word(&raw, 16) == 1 {
					Some(cache.clone())
				} else {
					None
				}
			});
			let output = response(original::apply(cache, &raw));
			CURRENT.with(|slot| *slot.borrow_mut() = None);
			output
		};
		stdout
			.write_all(&(result.len() as u32).to_le_bytes())
			.unwrap();
		stdout.write_all(&result).unwrap();
	}
	assert!(
		sessions.is_empty(),
		"every retained session must close explicitly"
	);
	stdout.flush().unwrap();
}
