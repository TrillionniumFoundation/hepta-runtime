/// Files above this size are served in full every time: holding multi-MB
/// artifacts per session is not worth the delta.
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
