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

impl OctofsServer {
	fn ensure_session_workdir(&self, context: &RequestContext<RoleServer>) {
		if self
			.session_applied
			.swap(true, std::sync::atomic::Ordering::SeqCst)
		{
			return;
		}
		let Some(capabilities) = context.client_capabilities() else {
			return;
		};
		let Some(experimental) = &capabilities.experimental else {
			return;
		};
		if let Some(session_obj) = experimental.get("session") {
			if let Some(workdir_str) = session_obj.get("workdir").and_then(|v| v.as_str()) {
				let path = std::path::PathBuf::from(workdir_str);
				let policy_allows = runtime::config::maybe_runtime_config().is_none()
					|| runtime::config::check_local_path(&path).is_ok();
				if path.is_absolute() && path.is_dir() && policy_allows {
					self.workdir.set_current(path.clone());
					debug!("Session workdir set from capabilities: {}", path.display());
				} else {
					debug!(
						"Session workdir '{}' is not an absolute directory path, ignoring",
						workdir_str
					);
				}
			}
		}
	}
}
