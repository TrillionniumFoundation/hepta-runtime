// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact target items; verified by the source extraction manifest.
use std::collections::HashMap;
use std::sync::Mutex;
use super::text_editing::lock_key_for_source;
use super::PathSource;
use crate::mcp::request_ctx::with_view_cache;
const MAX_CACHED_BYTES: usize = 1024 * 1024;

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


fn normalize(content: &str) -> String {
	content.replace("\r\n", "\n")
}


pub fn note_create(source: &PathSource, content: &str) {
	let key = lock_key_for_source(source);
	with_view_cache(|cache| cache.set(key.clone(), normalize(content)));
}


