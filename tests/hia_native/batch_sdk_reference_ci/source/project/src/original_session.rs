// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug)]
pub struct SessionWorkdir {
	/// The session root directory (set at session creation, never changes).
	pub root: PathBuf,
	/// The current working directory (can be changed via workdir tool).
	pub current: RwLock<Option<PathBuf>>,
}

impl SessionWorkdir {
	pub fn new(root: PathBuf) -> Self {
		Self {
			root,
			current: RwLock::new(None),
		}
	}

	/// Get the current working directory, or the root if not set.
	pub fn get_current(&self) -> PathBuf {
		self.current
			.read()
			.ok()
			.and_then(|guard| guard.clone())
			.unwrap_or_else(|| self.root.clone())
	}

	/// Set the current working directory.
	pub fn set_current(&self, path: PathBuf) {
		if let Ok(mut guard) = self.current.write() {
			*guard = Some(path);
		}
	}

	/// Reset to the session root.
	pub fn reset(&self) {
		if let Ok(mut guard) = self.current.write() {
			*guard = None;
		}
	}
}
