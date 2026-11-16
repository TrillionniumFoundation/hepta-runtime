// Undo history: per-file snapshots with a global byte budget so a long-lived
// server (HTTP mode, days of edits) cannot grow without bound.
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

static FILE_HISTORY: OnceLock<Mutex<HistoryStore>> = OnceLock::new();

fn file_history() -> &'static Mutex<HistoryStore> {
	FILE_HISTORY.get_or_init(|| Mutex::new(HistoryStore::default()))
}

// Save the current content of a file for undo
pub async fn save_file_history(source: &PathSource) -> Result<()> {
	if io_exists(source).await? {
		let content = io_read_to_string(source).await?;
		// Use the same canonicalized key as the file lock map so undo history
		// follows the file even when callers pass aliased paths.
		let path_str = text_editing::lock_key_for_source(source);
		file_history()
			.lock()
			.map_err(|_| anyhow!("Failed to acquire lock on file history"))?
			.push(path_str, content, MAX_HISTORY_TOTAL_BYTES);
	}
	Ok(())
}

// Undo the last edit to a file
pub async fn undo_edit(source: &PathSource) -> Result<String> {
	// Serialize with other writers on the same file — without this, an undo racing a
	// concurrent str_replace/batch_edit could interleave the pop and write and lose data.
	let file_lock = text_editing::acquire_file_lock(source).await?;
	let _lock_guard = file_lock.lock().await;

	let path_str = text_editing::lock_key_for_source(source);
	let previous_content = file_history()
		.lock()
		.map_err(|_| anyhow!("Failed to acquire lock on file history"))?
		.pop(&path_str);

	if let Some(prev_content) = previous_content {
		text_editing::atomic_write(source, &prev_content).await?;
		// The restored content is not what the model last saw as a whole.
		delta::forget(source);

		Ok(format!(
			"Successfully undid the last edit to {}",
			source.display()
		))
	} else {
		bail!("No more undo history for this file (up to 10 levels are stored per file).");
	}
}

