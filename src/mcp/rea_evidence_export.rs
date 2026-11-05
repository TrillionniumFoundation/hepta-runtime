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

//! Session-owned, descriptor-confined atomic Evidence export.
//!
//! A blocking owner, rather than the request future, owns every descriptor and
//! the effect admission. Cancellation never abandons a write or cleanup. Failed
//! cleanup retains that same owner in the session registry; another export must
//! release it before allocating a new staging directory. Only names whose
//! descriptor identities were recorded by this operation may be removed.

use super::rea_contract::{self, Failure};
use super::rea_evidence_session::EvidenceSnapshot;
use super::runtime::effect_owner_fence::AdmissionPermit;
use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;

const OPERATION: &str = "export_evidence_bundle";
const WRITE_CHUNK: usize = 64 * 1024;

type Encoder = Box<dyn FnOnce(&mut dyn Write) -> anyhow::Result<()> + Send>;
type PublicationHook = dyn Fn(&Path) + Send + Sync;

#[derive(Debug, Clone)]
struct Input {
	path: String,
	overwrite: bool,
}

impl Input {
	fn parse(raw: &Value) -> Result<Self, Failure> {
		Self::parse_ordered(raw, None)
	}

	fn parse_ordered(raw: &Value, argument_keys: Option<&[String]>) -> Result<Self, Failure> {
		let mut issues = Vec::new();
		let Some(map) = rea_contract::object(raw, &mut issues) else {
			return Err(Failure::input(OPERATION, issues));
		};
		let path = match map.get("path").and_then(Value::as_str) {
			Some(path) => {
				if path.contains('\0') {
					issues.push(json!({"path":["path"],"reason":"invalid_format","expected":"regex","message":"Local filesystem paths cannot contain NUL"}));
				}
				if path.is_empty() {
					issues.push(json!({"path":["path"],"reason":"out_of_range","minimum":1}));
				}
				if !path.starts_with('/') {
					issues.push(json!({"path":["path"],"reason":"invalid_format","expected":"regex","message":"must be an absolute local filesystem path"}));
				}
				path.to_owned()
			}
			None => {
				issues.push(json!({"path":["path"],"reason":"invalid_type","expected":"string"}));
				String::new()
			}
		};
		let overwrite = match map.get("overwrite") {
			None => false,
			Some(Value::Bool(value)) => *value,
			Some(_) => {
				issues.push(
					json!({"path":["overwrite"],"reason":"invalid_type","expected":"boolean"}),
				);
				false
			}
		};
		if let Some(keys) = argument_keys {
			let mut seen = std::collections::HashSet::new();
			for key in keys.iter().filter(|key| {
				map.contains_key(*key) && !matches!(key.as_str(), "path" | "overwrite")
			}) {
				if seen.insert(key.as_str()) {
					issues.push(json!({"path":[key],"reason":"unknown_argument"}));
				}
			}
			// The hint can order diagnostics, but cannot make an argument valid.
			for key in map.keys().filter(|key| {
				!matches!(key.as_str(), "path" | "overwrite") && !seen.contains(key.as_str())
			}) {
				issues.push(json!({"path":[key],"reason":"unknown_argument"}));
			}
		} else {
			rea_contract::unknown_keys(map, &["path", "overwrite"], &[], &mut issues);
		}
		if !issues.is_empty() {
			return Err(Failure::input(OPERATION, issues));
		}
		// Match absoluteCallerPath on POSIX: retain '..' for policy admission and
		// retain the trailing directory requirement; do not resolve it lexically.
		let parts: Vec<_> = path
			.split('/')
			.filter(|p| !p.is_empty() && *p != ".")
			.collect();
		let directory = !parts.is_empty() && (path.ends_with('/') || path.ends_with("/."));
		Ok(Self {
			path: format!("/{}{}", parts.join("/"), if directory { "/" } else { "" }),
			overwrite,
		})
	}
}

/// The raw MCP adapter supplies actual Object.keys order before the SDK's
/// object representation can reorder unknown argument names.
pub(super) fn validate(raw: &Value, argument_keys: Option<&[String]>) -> Result<(), Failure> {
	Input::parse_ordered(raw, argument_keys).map(|_| ())
}

pub(super) fn input_schema() -> Arc<rmcp::model::JsonObject> {
	static SCHEMA: OnceLock<Arc<rmcp::model::JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/export_evidence_bundle.input.json"
				))
				.expect("frozen export input schema"),
			)
		})
		.clone()
}

pub(super) fn output_schema() -> Arc<rmcp::model::JsonObject> {
	static SCHEMA: OnceLock<Arc<rmcp::model::JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/export_evidence_bundle.output.json"
				))
				.expect("frozen export output schema"),
			)
		})
		.clone()
}

#[derive(Debug, Clone, Serialize)]
struct Receipt {
	path: String,
	bytes: u64,
	records: usize,
	unknowns: usize,
}

type Outcome = Result<Receipt, Failure>;

#[derive(Default)]
struct RegistryState {
	closed: bool,
	active: usize,
	#[cfg(unix)]
	pending: Option<Pending>,
	// Fail closed if the server accidentally drops its last session handle while
	// cleanup remains pending. Only confirmed cleanup releases this self-hold.
	keepalive: Option<Arc<ExportRegistry>>,
	// Normal delivery acknowledges and removes its entry. An aborted request
	// cannot perform that acknowledgment, so its actual terminal result remains
	// available to the session owner through take_completed().
	completed: BTreeMap<u64, Value>,
}

impl std::fmt::Debug for RegistryState {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let mut debug = formatter.debug_struct("ExportRegistryState");
		#[cfg(unix)]
		debug.field("pending", &self.pending);
		debug
			.field("closed", &self.closed)
			.field("active", &self.active)
			.field("retains_owner_lifetime", &self.keepalive.is_some())
			.field("unacknowledged_completions", &self.completed.len())
			.finish()
	}
}

/// One registry belongs to exactly one MCP session, never to the process.
pub(super) struct ExportRegistry {
	serial: Arc<tokio::sync::Mutex<()>>,
	state: Mutex<RegistryState>,
	next_id: AtomicU64,
	idle: tokio::sync::Notify,
	on_publication: Arc<PublicationHook>,
}

impl Default for ExportRegistry {
	fn default() -> Self {
		Self::new(Arc::new(|_| {}))
	}
}

impl std::fmt::Debug for ExportRegistry {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ExportRegistry")
			.field("state", &*self.state())
			.finish_non_exhaustive()
	}
}

struct ActiveOwner {
	registry: Arc<ExportRegistry>,
}
impl Drop for ActiveOwner {
	fn drop(&mut self) {
		self.registry.state().active -= 1;
		self.registry.idle.notify_waiters();
	}
}

impl ExportRegistry {
	/// The hook is session-local and runs in the blocking owner immediately
	/// after successful publication, even if delivery or cleanup later fails.
	pub(super) fn new(on_publication: Arc<PublicationHook>) -> Self {
		Self {
			serial: Arc::new(tokio::sync::Mutex::new(())),
			state: Mutex::new(RegistryState::default()),
			next_id: AtomicU64::new(0),
			idle: tokio::sync::Notify::new(),
			on_publication,
		}
	}

	fn admit(self: &Arc<Self>, path: &str) -> Result<Arc<ActiveOwner>, Failure> {
		let mut state = self.state();
		if state.closed {
			return Err(file_failure(path, "io"));
		}
		state.active += 1;
		Ok(Arc::new(ActiveOwner {
			registry: Arc::clone(self),
		}))
	}

	fn state(&self) -> MutexGuard<'_, RegistryState> {
		match self.state.lock() {
			Ok(state) => state,
			Err(poisoned) => poisoned.into_inner(),
		}
	}

	/// Exact retained resource facts; this function does not touch the filesystem.
	pub(super) fn pending(&self) -> Vec<Value> {
		#[cfg(unix)]
		{
			self.state()
				.pending
				.as_ref()
				.map(|p| vec![p.failure.0.clone()])
				.unwrap_or_default()
		}
		#[cfg(not(unix))]
		{
			Vec::new()
		}
	}

	/// Consume completed results whose request future did not receive them.
	pub(super) fn take_completed(&self) -> Vec<Value> {
		std::mem::take(&mut self.state().completed)
			.into_values()
			.collect()
	}

	fn remember(&self, id: u64, outcome: &Outcome) {
		let result = match outcome {
			Ok(receipt) => json!({"result":receipt}),
			Err(failure) => json!({"error":failure.0}),
		};
		self.state().completed.insert(
			id,
			json!({"owner_id":id,"operation":OPERATION,"outcome":result}),
		);
	}

	/// Session close may retry retained cleanup without creating another output.
	/// The independent task still owns a retry if its caller is aborted.
	pub(super) async fn retry_cleanup(self: Arc<Self>) -> Result<(), Failure> {
		let owner = tokio::spawn(async move {
			let serial = Arc::clone(&self.serial).lock_owned().await;
			let registry = Arc::clone(&self);
			tokio::task::spawn_blocking(move || {
				let _serial = serial;
				retry_pending(&registry)
			})
			.await
			.map_err(|error| {
				Failure::output(OPERATION, format!("Export cleanup owner failed: {error}"))
			})?
		});
		owner.await.map_err(|error| {
			Failure::output(
				OPERATION,
				format!("Export cleanup supervision failed: {error}"),
			)
		})?
	}

	/// Stop new export admission, join all previously admitted owners (including
	/// queued owners), then retry retained cleanup. Existing commits are never
	/// relabeled cancelled. A failed close leaves the exact owner retained.
	pub(super) async fn close(self: Arc<Self>) -> Result<(), Failure> {
		self.state().closed = true;
		loop {
			let changed = self.idle.notified();
			tokio::pin!(changed);
			changed.as_mut().enable();
			if self.state().active == 0 {
				break;
			}
			changed.await;
		}
		self.retry_cleanup().await
	}
}

struct CancelOnDrop {
	token: CancellationToken,
	armed: bool,
}

impl Drop for CancelOnDrop {
	fn drop(&mut self) {
		if self.armed {
			self.token.cancel();
		}
	}
}

/// Export a stable Arc-backed session snapshot without copying its payloads.
pub(super) async fn export(
	raw: Value,
	snapshot: EvidenceSnapshot,
	roots: Vec<PathBuf>,
	cancellation: CancellationToken,
	admission: Arc<AdmissionPermit>,
	registry: Arc<ExportRegistry>,
	file_lock: Arc<tokio::sync::Mutex<()>>,
) -> CallToolResult {
	let input = match Input::parse(&raw) {
		Ok(input) => input,
		Err(error) => return wire(Err(error)),
	};
	let records = snapshot.record_count();
	let unknowns = snapshot.unknown_count();
	let encoder: Encoder = Box::new(move |mut writer| snapshot.write_canonical(&mut writer));
	wire(
		run_owned(
			input,
			roots,
			cancellation,
			admission,
			registry,
			records,
			unknowns,
			encoder,
			Hooks::default(),
			file_lock,
		)
		.await,
	)
}

#[allow(clippy::too_many_arguments)]
async fn run_owned(
	input: Input,
	roots: Vec<PathBuf>,
	cancellation: CancellationToken,
	admission: Arc<AdmissionPermit>,
	registry: Arc<ExportRegistry>,
	records: usize,
	unknowns: usize,
	encoder: Encoder,
	hooks: Hooks,
	file_lock: Arc<tokio::sync::Mutex<()>>,
) -> Outcome {
	let activity = registry.admit(&input.path)?;
	let token = cancellation.child_token();
	let mut guard = CancelOnDrop {
		token: token.clone(),
		armed: true,
	};
	let id = registry.next_id.fetch_add(1, Ordering::Relaxed);
	let owner_registry = Arc::clone(&registry);
	let owner = tokio::spawn(async move {
		// The owner, including a queued owner, holds admission until the actual
		// blocking operation finishes. Dropping a request cannot release it.
		let serial = Arc::new(Arc::clone(&owner_registry.serial).lock_owned().await);
		if token.is_cancelled() {
			let result = Err(Failure::cancelled(OPERATION));
			owner_registry.remember(id, &result);
			return result;
		}
		// Retry before acquiring the path lock. A retained cleanup owner may
		// still hold that very lock; acquiring it first would deadlock retries.
		let cleanup_registry = Arc::clone(&owner_registry);
		let cleanup_activity = Arc::clone(&activity);
		let cleanup_serial = Arc::clone(&serial);
		let retried = tokio::task::spawn_blocking(move || {
			let (_activity, _serial) = (cleanup_activity, cleanup_serial);
			retry_pending(&cleanup_registry)
		})
		.await;
		let failed = match retried {
			Ok(Ok(())) => None,
			Ok(Err(error)) => Some(error),
			Err(error) => Some(Failure::output(
				OPERATION,
				format!("Export cleanup owner failed: {error}"),
			)),
		};
		if let Some(error) = failed {
			let result = Err(error);
			owner_registry.remember(id, &result);
			return result;
		}
		let path_guard = tokio::select! {
			biased;
			_ = token.cancelled()=>{let result=Err(Failure::cancelled(OPERATION));owner_registry.remember(id,&result);return result;},
			guard=file_lock.lock_owned()=>Arc::new(guard),
		};
		let retained = Arc::clone(&owner_registry);
		let writing_activity = Arc::clone(&activity);
		let outcome = tokio::task::spawn_blocking(move || {
			let (_activity, _serial) = (writing_activity, serial);
			let outcome = write_owned(
				input, roots, &token, admission, records, unknowns, encoder, hooks, &retained,
				path_guard,
			);
			retained.remember(id, &outcome);
			outcome
		})
		.await;
		match outcome {
			Ok(outcome) => outcome,
			Err(error) => {
				let outcome = Err(Failure::output(
					OPERATION,
					format!("Export owner failed: {error}"),
				));
				owner_registry.remember(id, &outcome);
				outcome
			}
		}
	});
	let outcome = owner.await.map_err(|error| {
		Failure::output(OPERATION, format!("Export supervision failed: {error}"))
	})?;
	guard.armed = false;
	registry.state().completed.remove(&id);
	outcome
}

fn wire(outcome: Outcome) -> CallToolResult {
	let mut result = match outcome {
		Ok(receipt) => rea_contract::success(OPERATION, json!({"result":receipt}), None),
		Err(error) => error.wire(),
	};
	// The frozen contract explicitly lists export as target-content-free.
	result.meta = None;
	result
}

fn file_failure(path: &str, reason: &str) -> Failure {
	let message = match reason {
		"exists" => "Evidence file already exists. Choose another path or allow overwrite.",
		"not-file" => "Evidence path does not point to a regular file. Choose a file and try again.",
		"missing" => "Evidence output directory does not exist. Choose an existing directory and try again.",
		"path-limit" => "Filesystem path-length constraints prevented reading or atomic publication at the selected path. Choose a shorter local path.",
		_ => "Evidence file could not be accessed. Check file permissions and try again.",
	};
	let (code, category) = match reason {
		"path-limit" => ("resource_constraint", "resource_constraint"),
		"io" => ("execution_failure", "execution_failure"),
		_ => ("invalid_request", "invalid_input"),
	};
	let mut value = json!({"code":code,"category":category,"message":message,"retryable":false,
		"remediation":{"action":message},"details":{"operation":"write","reason":reason,"path":path}});
	if reason == "path-limit" {
		value["details"]["boundary"] = json!("filesystem-path");
	}
	Failure(value)
}

fn policy_failure(path: &str, reason: &str) -> Failure {
	Failure(
		json!({"code":"access_denied","category":"unavailable","message":reason,"retryable":false,
		"remediation":{"action":"Choose an absolute local file beneath a configured controller workspace root, with no symlink or parent-directory traversal."},
		"details":{"operation":OPERATION,"path":path,"boundary":"filesystem-write-policy","reason":reason}}),
	)
}

#[cfg(unix)]
fn io_failure(path: &str, error: &io::Error, overwrite: bool) -> Failure {
	let reason = match error.raw_os_error() {
		Some(libc::ENOENT | libc::ENOTDIR) => "missing",
		Some(libc::ENAMETOOLONG) => "path-limit",
		Some(libc::EEXIST) if !overwrite => "exists",
		_ => "io",
	};
	file_failure(path, reason)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Phase {
	Created,
	BeforeWrite,
	BeforeSync,
	BeforeClose,
	BeforePublish,
	Published,
	BeforeUnlink,
	BeforeRmdir,
	BeforeDirectoryClose,
}

#[derive(Clone, Default)]
struct Hooks {
	#[cfg(test)]
	callback: Option<Arc<PhaseCallback>>,
}

#[cfg(test)]
type PhaseCallback = dyn Fn(Phase, &Path) -> io::Result<()> + Send + Sync;

impl std::fmt::Debug for Hooks {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("ExportHooks")
	}
}

impl Hooks {
	fn at(&self, phase: Phase, path: &Path) -> io::Result<()> {
		#[cfg(test)]
		if let Some(callback) = &self.callback {
			return callback(phase, path);
		}
		let _ = (phase, path);
		Ok(())
	}
}

#[cfg(unix)]
mod confined {
	use super::*;
	use std::ffi::{CString, OsStr};
	use std::fs::File;
	use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
	use std::os::unix::ffi::OsStrExt;
	use std::os::unix::fs::MetadataExt;
	use std::path::Component;

	#[derive(Debug, Copy, Clone, PartialEq, Eq)]
	struct Identity {
		device: u64,
		inode: u64,
	}

	impl Identity {
		fn of(metadata: &std::fs::Metadata) -> Self {
			Self {
				device: metadata.dev(),
				inode: metadata.ino(),
			}
		}
		// libc's device and inode field widths differ across Unix targets.
		#[allow(clippy::unnecessary_cast)]
		fn of_stat(stat: &libc::stat) -> Self {
			Self {
				device: stat.st_dev as u64,
				inode: stat.st_ino as u64,
			}
		}
	}

	#[derive(Debug)]
	struct Directory {
		file: Option<File>,
		name: CString,
		identity: Identity,
	}

	#[derive(Debug)]
	struct Stage {
		name: CString,
		path: PathBuf,
		directory: Option<File>,
		directory_identity: Option<Identity>,
		file: Option<File>,
		file_identity: Option<Identity>,
		file_created: bool,
		file_removed: bool,
		published_rename: bool,
		directory_removed: bool,
	}

	#[derive(Debug)]
	pub(super) struct Owner {
		input: Input,
		directories: Vec<Directory>,
		stage: Option<Stage>,
		// A failed cleanup retains the actual admission, not its description.
		_admission: Arc<AdmissionPermit>,
		_file_lock: Arc<tokio::sync::OwnedMutexGuard<()>>,
		hooks: Hooks,
		close_uncertain: Vec<String>,
	}

	#[derive(Debug)]
	pub(super) struct Pending {
		owner: Owner,
		primary: Outcome,
		pub(super) failure: Failure,
	}

	fn cstring(name: &OsStr) -> io::Result<CString> {
		CString::new(name.as_bytes())
			.map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
	}

	fn stat_at(parent: RawFd, name: &CString) -> io::Result<libc::stat> {
		let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
		let result = unsafe {
			libc::fstatat(
				parent,
				name.as_ptr(),
				stat.as_mut_ptr(),
				libc::AT_SYMLINK_NOFOLLOW,
			)
		};
		if result < 0 {
			Err(io::Error::last_os_error())
		} else {
			Ok(unsafe { stat.assume_init() })
		}
	}

	fn directory_at(parent: RawFd, name: &CString) -> io::Result<File> {
		let fd = unsafe {
			libc::openat(
				parent,
				name.as_ptr(),
				libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
			)
		};
		if fd < 0 {
			Err(io::Error::last_os_error())
		} else {
			Ok(unsafe { File::from_raw_fd(fd) })
		}
	}

	fn owned_fd(file: &Option<File>) -> io::Result<RawFd> {
		file.as_ref()
			.map(AsRawFd::as_raw_fd)
			.ok_or_else(|| io::Error::other("Owned export descriptor is unavailable"))
	}

	fn close(file: &mut Option<File>) -> io::Result<()> {
		let Some(file) = file.take() else {
			return Ok(());
		};
		let fd = file.into_raw_fd();
		// Never retry close(EINTR): Linux has consumed the descriptor and another
		// thread may already own its number. Non-Linux ambiguity is retained.
		if unsafe { libc::close(fd) } < 0 {
			Err(io::Error::last_os_error())
		} else {
			Ok(())
		}
	}

	fn regular(stat: &libc::stat) -> bool {
		stat.st_mode & libc::S_IFMT == libc::S_IFREG
	}
	fn is_directory(stat: &libc::stat) -> bool {
		stat.st_mode & libc::S_IFMT == libc::S_IFDIR
	}

	impl Owner {
		fn new(
			input: Input,
			admission: Arc<AdmissionPermit>,
			hooks: Hooks,
			file_lock: Arc<tokio::sync::OwnedMutexGuard<()>>,
		) -> Self {
			Self {
				input,
				directories: Vec::new(),
				stage: None,
				_admission: admission,
				_file_lock: file_lock,
				hooks,
				close_uncertain: Vec::new(),
			}
		}

		fn parent_fd(&self) -> io::Result<RawFd> {
			self.directories
				.last()
				.ok_or_else(|| io::Error::other("Export parent is not admitted"))
				.and_then(|directory| owned_fd(&directory.file))
		}

		fn admit_parent(&mut self, roots: &[PathBuf]) -> Result<CString, Failure> {
			let requested = Path::new(&self.input.path);
			if self.input.path.ends_with('/') || requested == Path::new("/") {
				return Err(file_failure(&self.input.path, "not-file"));
			}
			if roots.is_empty() {
				return Err(policy_failure(
					&self.input.path,
					"REA export denied: no controller workspace roots configured",
				));
			}
			for root in roots {
				if !root.is_absolute() {
					return Err(policy_failure(
						&self.input.path,
						"REA export denied: configured workspace root must be absolute",
					));
				}
				let Ok(relative) = requested.strip_prefix(root) else {
					continue;
				};
				let components = relative
					.components()
					.map(|part| match part {
						Component::Normal(name) => cstring(name).map_err(|error| {
							io_failure(&self.input.path, &error, self.input.overwrite)
						}),
						_ => Err(policy_failure(
							&self.input.path,
							"REA export denied: parent or non-normal path component",
						)),
					})
					.collect::<Result<Vec<_>, _>>()?;
				let Some((destination, parents)) = components.split_last() else {
					return Err(file_failure(&self.input.path, "not-file"));
				};
				let root_name = cstring(root.as_os_str())
					.map_err(|error| io_failure(&self.input.path, &error, self.input.overwrite))?;
				let root_file = directory_at(libc::AT_FDCWD, &root_name)
					.map_err(|error| io_failure(&self.input.path, &error, self.input.overwrite))?;
				self.add_directory(root_name, root_file)?;
				for name in parents {
					let parent = self.parent_fd().map_err(|error| {
						io_failure(&self.input.path, &error, self.input.overwrite)
					})?;
					let file = directory_at(parent, name).map_err(|error| {
						if error.raw_os_error() == Some(libc::ELOOP)
							|| stat_at(parent, name)
								.is_ok_and(|s| s.st_mode & libc::S_IFMT == libc::S_IFLNK)
						{
							policy_failure(
								&self.input.path,
								"REA export denied: symlink directory traversal",
							)
						} else {
							io_failure(&self.input.path, &error, self.input.overwrite)
						}
					})?;
					self.add_directory(name.clone(), file)?;
				}
				return Ok(destination.clone());
			}
			Err(policy_failure(
				&self.input.path,
				"REA export denied: path is outside controller workspace roots",
			))
		}

		fn add_directory(&mut self, name: CString, file: File) -> Result<(), Failure> {
			// Store ownership before any fallible metadata operation.
			self.directories.push(Directory {
				file: Some(file),
				name,
				identity: Identity {
					device: 0,
					inode: 0,
				},
			});
			let metadata = self
				.directories
				.last()
				.and_then(|d| d.file.as_ref())
				.ok_or_else(|| file_failure(&self.input.path, "io"))?
				.metadata()
				.map_err(|error| io_failure(&self.input.path, &error, self.input.overwrite))?;
			if let Some(last) = self.directories.last_mut() {
				last.identity = Identity::of(&metadata);
			}
			Ok(())
		}

		fn check_destination(&self, destination: &CString) -> Result<(), Failure> {
			let parent = self
				.parent_fd()
				.map_err(|e| io_failure(&self.input.path, &e, self.input.overwrite))?;
			match stat_at(parent, destination) {
				Ok(_) if !self.input.overwrite => Err(file_failure(&self.input.path, "exists")),
				Ok(stat) if !regular(&stat) => Err(file_failure(&self.input.path, "not-file")),
				Ok(_) => Ok(()),
				Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
				Err(error) => Err(io_failure(&self.input.path, &error, self.input.overwrite)),
			}
		}

		fn acquire_stage(&mut self) -> io::Result<()> {
			let parent = self.parent_fd()?;
			let mut random = [0u8; 16];
			if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } < 0 {
				return Err(io::Error::last_os_error());
			}
			let suffix = random
				.iter()
				.map(|byte| format!("{byte:02x}"))
				.collect::<String>();
			let name = CString::new(format!(".rea-write-{suffix}")).map_err(io::Error::other)?;
			if unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) } < 0 {
				return Err(io::Error::last_os_error());
			}
			let directory_path = Path::new(&self.input.path)
				.parent()
				.ok_or_else(|| io::Error::other("Export parent missing"))?
				.join(name.to_string_lossy().as_ref());
			self.stage = Some(Stage {
				name,
				path: directory_path,
				directory: None,
				directory_identity: None,
				file: None,
				file_identity: None,
				file_created: false,
				file_removed: false,
				published_rename: false,
				directory_removed: false,
			});
			let stage = self
				.stage
				.as_mut()
				.ok_or_else(|| io::Error::other("Missing staged owner"))?;
			let metadata = stat_at(parent, &stage.name)?;
			if !is_directory(&metadata) {
				return Err(io::Error::other("Staging directory identity changed"));
			}
			stage.directory_identity = Some(Identity::of_stat(&metadata));
			stage.directory = Some(directory_at(parent, &stage.name)?);
			let directory = owned_fd(&stage.directory)?;
			if unsafe { libc::fchmod(directory, 0o700) } < 0 {
				return Err(io::Error::last_os_error());
			}
			let fd = unsafe {
				libc::openat(
					directory,
					c"content".as_ptr(),
					libc::O_WRONLY
						| libc::O_CREAT | libc::O_EXCL
						| libc::O_CLOEXEC | libc::O_NOFOLLOW,
					0o600,
				)
			};
			if fd < 0 {
				return Err(io::Error::last_os_error());
			}
			stage.file = Some(unsafe { File::from_raw_fd(fd) });
			stage.file_created = true;
			if unsafe { libc::fchmod(fd, 0o600) } < 0 {
				return Err(io::Error::last_os_error());
			}
			self.hooks.at(Phase::Created, &stage.path)
		}

		fn close_file(&mut self) -> Vec<String> {
			let mut failures = Vec::new();
			let Some(stage) = self.stage.as_mut() else {
				return failures;
			};
			if let Some(file) = stage.file.as_ref() {
				match file.metadata() {
					Ok(metadata) => stage.file_identity = Some(Identity::of(&metadata)),
					Err(error) => failures.push(format!("stat staged descriptor: {error}")),
				}
			}
			if let Err(error) = close(&mut stage.file) {
				failures.push(format!("close staged descriptor: {error}"));
				#[cfg(not(target_os = "linux"))]
				if error.kind() == io::ErrorKind::Interrupted {
					self.close_uncertain.push(
						"Interrupted staged close has unconfirmed descriptor state".to_owned(),
					);
				}
			}
			failures
		}

		fn verify_directory_chain(&self) -> io::Result<()> {
			let mut parent = libc::AT_FDCWD;
			for directory in &self.directories {
				let stat = stat_at(parent, &directory.name)?;
				if !is_directory(&stat) || Identity::of_stat(&stat) != directory.identity {
					return Err(io::Error::other(
						"Admitted export directory identity changed",
					));
				}
				parent = owned_fd(&directory.file)?;
			}
			Ok(())
		}

		fn verify_stage(&self) -> io::Result<()> {
			let Some(stage) = self.stage.as_ref() else {
				return Err(io::Error::other("Missing staging owner"));
			};
			let stat = stat_at(self.parent_fd()?, &stage.name)?;
			if !is_directory(&stat) || stage.directory_identity != Some(Identity::of_stat(&stat)) {
				return Err(io::Error::other(format!(
					"Staging directory identity changed: {}",
					stage.path.display()
				)));
			}
			if let Some(directory) = stage.directory.as_ref() {
				if stage.directory_identity != Some(Identity::of(&directory.metadata()?)) {
					return Err(io::Error::other(
						"Staging directory descriptor identity changed",
					));
				}
			}
			Ok(())
		}

		fn publish(&mut self, destination: &CString) -> io::Result<()> {
			self.verify_directory_chain()?;
			self.verify_stage()?;
			let parent = self.parent_fd()?;
			let stage = self
				.stage
				.as_mut()
				.ok_or_else(|| io::Error::other("Missing staging owner"))?;
			let directory = owned_fd(&stage.directory)?;
			let stat = stat_at(directory, &CString::from(c"content"))?;
			if !regular(&stat)
				|| stage.file_identity != Some(Identity::of_stat(&stat))
				|| stat.st_mode & 0o777 != 0o600
			{
				return Err(io::Error::other(
					"Staged file identity changed before publication",
				));
			}
			let result = if self.input.overwrite {
				unsafe {
					libc::renameat(directory, c"content".as_ptr(), parent, destination.as_ptr())
				}
			} else {
				unsafe {
					libc::linkat(
						directory,
						c"content".as_ptr(),
						parent,
						destination.as_ptr(),
						0,
					)
				}
			};
			if result < 0 {
				return Err(io::Error::last_os_error());
			}
			stage.published_rename = self.input.overwrite;
			Ok(())
		}

		fn cleanup(&mut self) -> Vec<String> {
			let mut failures = self.close_file();
			failures.extend(self.close_uncertain.iter().cloned());
			if let Some(stage) = self.stage.as_ref() {
				if !stage.directory_removed {
					if let Err(error) = self.verify_stage() {
						failures.push(error.to_string());
						return failures;
					}
					if let Err(error) = self.remove_staged_file() {
						failures.push(error.to_string());
						return failures;
					}
					let parent = match self.parent_fd() {
						Ok(fd) => fd,
						Err(error) => {
							failures.push(error.to_string());
							return failures;
						}
					};
					if let Some(stage) = self.stage.as_mut() {
						if let Err(error) = self.hooks.at(Phase::BeforeRmdir, &stage.path) {
							failures.push(format!("remove staging directory: {error}"));
							return failures;
						}
						if unsafe {
							libc::unlinkat(parent, stage.name.as_ptr(), libc::AT_REMOVEDIR)
						} < 0
						{
							failures.push(format!(
								"remove staging directory {}: {}",
								stage.path.display(),
								io::Error::last_os_error()
							));
							return failures;
						}
						stage.directory_removed = true;
					}
				}
			}
			if let Some(stage) = self.stage.as_mut() {
				if let Err(error) = self.hooks.at(Phase::BeforeDirectoryClose, &stage.path) {
					failures.push(format!("close staging directory: {error}"));
					return failures;
				}
				if let Err(error) = close(&mut stage.directory) {
					failures.push(format!("close staging directory: {error}"));
					#[cfg(not(target_os = "linux"))]
					if error.kind() == io::ErrorKind::Interrupted {
						self.close_uncertain.push(
							"Interrupted staging-directory close has unconfirmed descriptor state"
								.to_owned(),
						);
					}
				}
			}
			for directory in self.directories.iter_mut().rev() {
				if let Err(error) = close(&mut directory.file) {
					failures.push(format!("close admitted directory: {error}"));
					#[cfg(not(target_os = "linux"))]
					if error.kind() == io::ErrorKind::Interrupted {
						self.close_uncertain.push(
							"Interrupted admitted-directory close has unconfirmed descriptor state"
								.to_owned(),
						);
					}
				}
			}
			failures
		}

		fn remove_staged_file(&mut self) -> io::Result<()> {
			let Some(stage) = self.stage.as_mut() else {
				return Ok(());
			};
			if !stage.file_created || stage.file_removed {
				return Ok(());
			}
			let directory = owned_fd(&stage.directory)?;
			match stat_at(directory, &CString::from(c"content")) {
				Err(error)
					if error.raw_os_error() == Some(libc::ENOENT) && stage.published_rename =>
				{
					return Ok(())
				}
				Err(error) => {
					return Err(io::Error::other(format!(
						"Owned staged file cannot be verified at {}: {error}",
						stage.path.join("content").display()
					)))
				}
				Ok(stat)
					if !regular(&stat) || stage.file_identity != Some(Identity::of_stat(&stat)) =>
				{
					return Err(io::Error::other(format!(
						"Staged file identity changed: {}",
						stage.path.join("content").display()
					)))
				}
				Ok(_) => {}
			}
			self.hooks.at(Phase::BeforeUnlink, &stage.path)?;
			if unsafe { libc::unlinkat(directory, c"content".as_ptr(), 0) } < 0 {
				return Err(io::Error::last_os_error());
			}
			stage.file_removed = true;
			Ok(())
		}

		fn resources(&self) -> Vec<String> {
			vec![self
				.stage
				.as_ref()
				.map(|s| s.path.to_string_lossy().into_owned())
				.unwrap_or_else(|| self.input.path.clone())]
		}
	}

	#[derive(Debug)]
	struct CancelledWrite;
	impl std::fmt::Display for CancelledWrite {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			f.write_str("Evidence export cancelled")
		}
	}
	impl std::error::Error for CancelledWrite {}

	struct CancellableWriter<'a> {
		file: &'a mut File,
		token: &'a CancellationToken,
		bytes: u64,
		cancelled: bool,
	}
	impl Write for CancellableWriter<'_> {
		fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
			// Write::write_all retries Interrupted automatically; cancellation must
			// be a terminal writer error, not an endlessly retried EINTR.
			if self.token.is_cancelled() {
				self.cancelled = true;
				return Err(io::Error::other(CancelledWrite));
			}
			let take = bytes.len().min(WRITE_CHUNK);
			let written = self.file.write(&bytes[..take])?;
			self.bytes = self
				.bytes
				.checked_add(written as u64)
				.ok_or_else(|| io::Error::other("Export byte count overflow"))?;
			Ok(written)
		}
		fn flush(&mut self) -> io::Result<()> {
			self.file.flush()
		}
	}

	fn active(token: &CancellationToken) -> Result<(), Failure> {
		if token.is_cancelled() {
			Err(Failure::cancelled(OPERATION))
		} else {
			Ok(())
		}
	}

	fn execute(
		owner: &mut Owner,
		roots: &[PathBuf],
		token: &CancellationToken,
		records: usize,
		unknowns: usize,
		encoder: Encoder,
		on_publication: &PublicationHook,
	) -> Outcome {
		active(token)?;
		let destination = owner.admit_parent(roots)?;
		owner.check_destination(&destination)?;
		active(token)?;
		owner
			.acquire_stage()
			.map_err(|error| io_failure(&owner.input.path, &error, owner.input.overwrite))?;
		let stage = owner
			.stage
			.as_mut()
			.ok_or_else(|| file_failure(&owner.input.path, "io"))?;
		owner
			.hooks
			.at(Phase::BeforeWrite, &stage.path)
			.map_err(|error| io_failure(&owner.input.path, &error, owner.input.overwrite))?;
		let file = stage
			.file
			.as_mut()
			.ok_or_else(|| file_failure(&owner.input.path, "io"))?;
		let writer = CancellableWriter {
			file,
			token,
			bytes: 0,
			cancelled: false,
		};
		let mut buffered = io::BufWriter::with_capacity(WRITE_CHUNK, writer);
		let encoded =
			std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| encoder(&mut buffered)));
		let flushed = if matches!(&encoded, Ok(Ok(()))) {
			buffered.flush()
		} else {
			Ok(())
		};
		// into_parts prevents BufWriter::drop from silently retrying failed I/O.
		// Unwritten bytes belong only to the unpublished staging file.
		let (writer, _unwritten) = buffered.into_parts();
		let bytes = writer.bytes;
		match encoded {
			Ok(Ok(())) => {}
			Ok(Err(_error)) if writer.cancelled => return Err(Failure::cancelled(OPERATION)),
			Ok(Err(error)) => {
				return Err(io_failure(
					&owner.input.path,
					error
						.downcast_ref::<io::Error>()
						.unwrap_or(&io::Error::other("Canonical Evidence serialization failed")),
					owner.input.overwrite,
				))
			}
			Err(_) => return Err(file_failure(&owner.input.path, "io")),
		}
		if let Err(error) = flushed {
			return Err(if writer.cancelled {
				Failure::cancelled(OPERATION)
			} else {
				io_failure(&owner.input.path, &error, owner.input.overwrite)
			});
		}
		active(token)?;
		owner
			.hooks
			.at(Phase::BeforeSync, &stage.path)
			.map_err(|error| io_failure(&owner.input.path, &error, owner.input.overwrite))?;
		writer
			.file
			.sync_all()
			.map_err(|error| io_failure(&owner.input.path, &error, owner.input.overwrite))?;
		owner
			.hooks
			.at(Phase::BeforeClose, &stage.path)
			.map_err(|error| io_failure(&owner.input.path, &error, owner.input.overwrite))?;
		let close_failures = owner.close_file();
		if !close_failures.is_empty() {
			let mut failure = file_failure(&owner.input.path, "io");
			failure.0["details"]["diagnostics"] = json!({"close_failures":close_failures});
			return Err(failure);
		}
		active(token)?;
		let stage_path = owner
			.stage
			.as_ref()
			.ok_or_else(|| file_failure(&owner.input.path, "io"))?
			.path
			.clone();
		owner
			.hooks
			.at(Phase::BeforePublish, &stage_path)
			.map_err(|error| io_failure(&owner.input.path, &error, owner.input.overwrite))?;
		// Repeat the final-name check immediately before publication. The private
		// staging directory excludes other UIDs; hostile same-UID directory edits
		// are not claimed to be serializable with this filesystem transaction.
		owner.check_destination(&destination)?;
		active(token)?;
		owner
			.publish(&destination)
			.map_err(|error| io_failure(&owner.input.path, &error, owner.input.overwrite))?;
		on_publication(Path::new(&owner.input.path));
		// A committed publication wins cancellation arriving after the syscall.
		// A post-publication hook is observation-only, never a false rollback.
		let receipt = Receipt {
			path: owner.input.path.clone(),
			bytes,
			records,
			unknowns,
		};
		if let Err(error) = owner.hooks.at(Phase::Published, &stage_path) {
			let mut failure = published_failure(&receipt);
			failure.0["details"]["diagnostics"] =
				json!({"post_publication_error":error.to_string()});
			return Err(failure);
		}
		Ok(receipt)
	}

	fn published_failure(receipt: &Receipt) -> Failure {
		let mut failure = file_failure(&receipt.path, "io");
		failure.0["message"] =
			json!("The output file was published, but staging cleanup remains incomplete.");
		failure.0["remediation"]["action"]=json!("Use the published file at details.published_path and resolve the reported staging cleanup failure.");
		failure.0["details"]["published"] = json!(true);
		failure.0["details"]["bytes"] = json!(receipt.bytes);
		failure.0["details"]["published_path"] = json!(receipt.path);
		failure
	}

	fn cleanup_failure(primary: &Outcome, owner: &Owner, failures: &[String]) -> Failure {
		let mut failure = match primary {
			Ok(receipt) => published_failure(receipt),
			Err(error) => error.clone(),
		};
		let underlying = failure.0["code"].clone();
		failure.0["code"] = json!("cleanup_incomplete");
		failure.0["retryable"] = json!(false);
		failure.0["details"]["cleanup"] = json!("incomplete");
		failure.0["details"]["cleanup_reason"] = json!(failures.join("; "));
		failure.0["details"]["resources"] = json!(owner.resources());
		failure.0["details"]["execution_failure"] = underlying;
		failure
	}

	#[allow(clippy::too_many_arguments)]
	pub(super) fn write_owned(
		input: Input,
		roots: Vec<PathBuf>,
		token: &CancellationToken,
		admission: Arc<AdmissionPermit>,
		records: usize,
		unknowns: usize,
		encoder: Encoder,
		hooks: Hooks,
		registry: &Arc<ExportRegistry>,
		file_lock: Arc<tokio::sync::OwnedMutexGuard<()>>,
	) -> Outcome {
		let mut owner = Owner::new(input, admission, hooks, file_lock);
		let primary = execute(
			&mut owner,
			&roots,
			token,
			records,
			unknowns,
			encoder,
			registry.on_publication.as_ref(),
		);
		let failures = owner.cleanup();
		if failures.is_empty() {
			return primary;
		}
		let failure = cleanup_failure(&primary, &owner, &failures);
		let mut state = registry.state();
		state.pending = Some(Pending {
			owner,
			primary,
			failure: failure.clone(),
		});
		state.keepalive = Some(Arc::clone(registry));
		Err(failure)
	}

	pub(super) fn retry_pending(registry: &Arc<ExportRegistry>) -> Result<(), Failure> {
		let Some(mut pending) = registry.state().pending.take() else {
			return Ok(());
		};
		let failures = pending.owner.cleanup();
		if failures.is_empty() {
			registry.state().keepalive = None;
			return Ok(());
		}
		let failure = cleanup_failure(&pending.primary, &pending.owner, &failures);
		pending.failure = failure.clone();
		registry.state().pending = Some(pending);
		Err(failure)
	}
}

#[cfg(unix)]
use confined::{retry_pending, write_owned, Pending};

#[cfg(not(unix))]
fn retry_pending(_registry: &Arc<ExportRegistry>) -> Result<(), Failure> {
	Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
fn write_owned(
	input: Input,
	_roots: Vec<PathBuf>,
	_token: &CancellationToken,
	_admission: Arc<AdmissionPermit>,
	_records: usize,
	_unknowns: usize,
	_encoder: Encoder,
	_hooks: Hooks,
	_registry: &Arc<ExportRegistry>,
	_file_lock: Arc<tokio::sync::OwnedMutexGuard<()>>,
) -> Outcome {
	Err(policy_failure(
		&input.path,
		"REA native export requires Unix file-descriptor admission on this build",
	))
}

#[cfg(all(test, unix))]
#[path = "rea_evidence_export_tests.rs"]
mod tests;
