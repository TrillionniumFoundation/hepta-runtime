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

//! Owned, confined acquisition of JSON Evidence files.
//!
//! Parsing is incremental and runs in one blocking owner with the caller's
//! admission guard. Dropping the async waiter cancels that owner; it does not
//! release the guard while descriptor work is still running. Native allocation,
//! token and depth limits are explicit profile boundaries, never the upstream
//! 8 MiB file-size policy (there is no such upstream policy).
//! Frozen REA behavior is MIT licensed; see LICENSES/REA-MIT.txt.

use super::rea_files;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use serde_json::{json, Map, Number, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use tokio_util::sync::CancellationToken;

#[path = "rea_json_eof.rs"]
mod json_eof;

const CHUNK: usize = 64 * 1024;
const NATIVE_JSON_THRESHOLD: u64 = 8 * 1024 * 1024;
const BOM_MESSAGE: &str = "JSON input begins with a UTF-8 byte-order mark (EF BB BF), which strict JSON input does not accept. Save the file as UTF-8 without a byte-order mark.";
const UTF8_MESSAGE: &str = "JSON input is not valid UTF-8";

#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct NativeJsonLimits {
	pub max_materialized_bytes: u64,
	pub max_token_bytes: usize,
	pub max_depth: usize,
}

impl Default for NativeJsonLimits {
	fn default() -> Self {
		Self {
			max_materialized_bytes: 128 * 1024 * 1024,
			max_token_bytes: 16 * 1024 * 1024,
			max_depth: 120,
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum FileReason {
	Missing,
	PathLimit,
	NotFile,
	Io,
}
impl FileReason {
	pub(super) fn as_str(self) -> &'static str {
		match self {
			Self::Missing => "missing",
			Self::PathLimit => "path-limit",
			Self::NotFile => "not-file",
			Self::Io => "io",
		}
	}
}
impl fmt::Display for FileReason {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(super) enum FileReadError {
	File {
		reason: FileReason,
		errno: Option<i32>,
	},
	InvalidJson {
		message: String,
		user_message: Option<String>,
	},
	Cancelled,
	NativeProfileGap {
		feature: &'static str,
		details: Value,
	},
	Cleanup {
		errno: Option<i32>,
		primary: Option<Box<FileReadError>>,
		native_cleanup_incomplete: bool,
	},
	Unexpected {
		message: String,
	},
}

impl fmt::Display for FileReadError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::File { reason, .. } => write!(f, "Evidence bundle read failed: {reason}"),
			Self::InvalidJson { message, .. } | Self::Unexpected { message } => {
				f.write_str(message)
			}
			Self::Cancelled => f.write_str("Evidence file acquisition cancelled"),
			Self::NativeProfileGap { feature, .. } => {
				write!(f, "Native Evidence JSON profile: {feature}")
			}
			Self::Cleanup { errno, .. } => {
				write!(f, "Evidence descriptor close failed (errno {errno:?})")
			}
		}
	}
}
impl std::error::Error for FileReadError {}
type Result<T> = std::result::Result<T, FileReadError>;

#[derive(Debug, Default)]
enum OrderNode {
	#[default]
	Leaf,
	Array(Vec<OrderNode>),
	Object {
		keys: Vec<String>,
		children: BTreeMap<String, OrderNode>,
	},
}

#[derive(Debug, Default)]
pub(super) struct ObjectOrder(OrderNode);

#[path = "rea_evidence_checkpoint_order.rs"]
mod checkpoint_order;
pub(super) use checkpoint_order::StoredObjectOrder;

impl ObjectOrder {
	/// Move the exact parser-owned record subtrees after bundle authentication.
	/// They accompany immutable records through metadata replacement and export.
	pub(super) fn into_record_orders(self) -> Result<Vec<ObjectOrder>> {
		let OrderNode::Object { mut children, .. } = self.0 else {
			return Err(FileReadError::Unexpected {
				message: "Authenticated bundle order is not an object".into(),
			});
		};
		let Some(OrderNode::Array(records)) = children.remove("records") else {
			return Err(FileReadError::Unexpected {
				message: "Authenticated record order is not an array".into(),
			});
		};
		Ok(records.into_iter().map(ObjectOrder).collect())
	}

	/// Metadata is a parallel tree owned by this exact parsed Value. Replacing
	/// a duplicate key also replaces its order subtree, preventing stale hints.
	pub(super) fn keys(&self, path: &[Value]) -> Option<Vec<String>> {
		let mut node = &self.0;
		for part in path {
			node = match node {
				OrderNode::Array(children) => {
					children.get(usize::try_from(part.as_u64()?).ok()?)?
				}
				OrderNode::Object { children, .. } => children.get(part.as_str()?)?,
				OrderNode::Leaf => return None,
			};
		}
		match node {
			OrderNode::Object { keys, .. } => Some(keys.clone()),
			_ => None,
		}
	}
}

#[derive(Debug)]
struct Parsed {
	value: Value,
	order: OrderNode,
}
fn leaf(value: Value) -> Parsed {
	Parsed {
		value,
		order: OrderNode::Leaf,
	}
}

#[derive(Debug)]
pub(super) struct OwnedJson {
	pub value: Value,
	pub object_order: ObjectOrder,
	pub selected_path: String,
	pub input_bytes: u64,
	pub sha256: String,
}

fn gap(feature: &'static str, details: Value) -> FileReadError {
	FileReadError::NativeProfileGap { feature, details }
}
fn active(cancellation: &CancellationToken) -> Result<()> {
	if cancellation.is_cancelled() {
		Err(FileReadError::Cancelled)
	} else {
		Ok(())
	}
}
fn invalid_json(message: &str, user_message: bool) -> FileReadError {
	FileReadError::InvalidJson {
		message: message.into(),
		user_message: user_message.then(|| message.into()),
	}
}
fn physical(error: io::Error) -> FileReadError {
	let errno = error.raw_os_error();
	let reason = match errno {
		Some(libc::ENOENT | libc::ENOTDIR) => FileReason::Missing,
		Some(libc::ENAMETOOLONG) => FileReason::PathLimit,
		_ => FileReason::Io,
	};
	FileReadError::File { reason, errno }
}
fn changed() -> FileReadError {
	FileReadError::File {
		reason: FileReason::Io,
		errno: Some(libc::ESTALE),
	}
}
fn policy(reason: &str) -> FileReadError {
	gap("controller-workspace-admission", json!({"reason":reason}))
}

/// Frozen POSIX error spelling for this Linux admission profile. Interior dots
/// and duplicate separators disappear, but a trailing slash or "/." keeps its
/// directory requirement. No filesystem lookup or symlink resolution occurs.
/// The original caller path remains separate for Evidence selector messages.
pub(super) fn normalized_error_path(path: &str) -> Result<String> {
	if !path.starts_with('/') {
		return Err(policy("an absolute local path is required"));
	}
	if path.contains('\0') {
		return Err(policy("path contains NUL"));
	}
	let mut normalized = String::with_capacity(path.len());
	normalized.push('/');
	for segment in path.split('/') {
		match segment {
			"" | "." => continue,
			".." => return Err(policy("parent or non-normal path component")),
			_ => {}
		}
		if normalized.len() > 1 {
			normalized.push('/');
		}
		normalized.push_str(segment);
	}
	if normalized.len() > 1 && (path.ends_with('/') || path.ends_with("/.")) {
		normalized.push('/');
	}
	Ok(normalized)
}

/// G is the caller's owned admission/lease tuple. It remains in the blocking
/// closure even when this future is aborted or its JoinHandle is dropped.
/// Cancellation is cooperative around descriptor calls; a blocked kernel read
/// is not claimed to have a hard deadline.
pub(super) async fn read_json<G: Send + 'static>(
	path: String,
	roots: Vec<PathBuf>,
	cancellation: CancellationToken,
	ownership: G,
	limits: NativeJsonLimits,
) -> Result<OwnedJson> {
	owned_task(cancellation, ownership, move |stop| {
		read_blocking(&path, &roots, stop, limits)
	})
	.await
}

async fn owned_task<G, F>(
	cancellation: CancellationToken,
	ownership: G,
	work: F,
) -> Result<OwnedJson>
where
	G: Send + 'static,
	F: FnOnce(CancellationToken) -> Result<OwnedJson> + Send + 'static,
{
	let stop = cancellation.child_token();
	let _cancel_on_drop = stop.clone().drop_guard();
	tokio::task::spawn_blocking(move || {
		let _ownership = ownership;
		work(stop)
	})
	.await
	.map_err(|error| FileReadError::Unexpected {
		message: format!("Evidence JSON owner failed: {error}"),
	})?
}

#[cfg(target_os = "linux")]
fn open_confined(
	path: &Path,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
) -> Result<(std::fs::File, std::fs::Metadata)> {
	use std::ffi::CString;
	use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
	use std::os::unix::ffi::OsStrExt;
	use std::path::Component;
	active(cancellation)?;
	let spelling = path.as_os_str().as_bytes();
	let directory_required = spelling.ends_with(b"/") || spelling.ends_with(b"/.");
	if !path.is_absolute() {
		return Err(policy("an absolute local path is required"));
	}
	if roots.is_empty() {
		return Err(policy("no controller workspace roots are configured"));
	}
	for root in roots {
		if !root.is_absolute() {
			return Err(policy("configured workspace root is not absolute"));
		}
		let Ok(relative) = path.strip_prefix(root) else {
			continue;
		};
		let components: Vec<CString> = relative
			.components()
			.map(|component| match component {
				Component::Normal(name) => {
					CString::new(name.as_bytes()).map_err(|_| policy("path contains NUL"))
				}
				_ => Err(policy("parent or non-normal path component")),
			})
			.collect::<Result<_>>()?;
		let Some((last, parents)) = components.split_last() else {
			return Err(FileReadError::File {
				reason: FileReason::NotFile,
				errno: Some(libc::EISDIR),
			});
		};
		let root_name = CString::new(root.as_os_str().as_bytes())
			.map_err(|_| policy("configured root contains NUL"))?;
		let fd = unsafe {
			libc::open(
				root_name.as_ptr(),
				libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
			)
		};
		if fd < 0 {
			return Err(physical(io::Error::last_os_error()));
		}
		let mut directory = unsafe { OwnedFd::from_raw_fd(fd) };
		for name in parents {
			active(cancellation)?;
			let fd = unsafe {
				libc::openat(
					directory.as_raw_fd(),
					name.as_ptr(),
					libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
				)
			};
			if fd < 0 {
				let error = io::Error::last_os_error();
				if error.raw_os_error() == Some(libc::ELOOP)
					|| (error.raw_os_error() == Some(libc::ENOTDIR)
						&& is_named_type(directory.as_raw_fd(), name, libc::S_IFLNK))
				{
					return Err(policy("symlink traversal is not admitted"));
				}
				return Err(physical(error));
			}
			directory = unsafe { OwnedFd::from_raw_fd(fd) };
		}
		active(cancellation)?;
		let fd =
			unsafe {
				libc::openat(
					directory.as_raw_fd(),
					last.as_ptr(),
					libc::O_RDONLY
						| libc::O_CLOEXEC | libc::O_NOFOLLOW
						| libc::O_NONBLOCK | libc::O_NOCTTY
						| if directory_required {
							libc::O_DIRECTORY
						} else {
							0
						},
				)
			};
		if fd < 0 {
			let error = io::Error::last_os_error();
			let errno = error.raw_os_error();
			if errno == Some(libc::ELOOP)
				|| (errno == Some(libc::ENOTDIR)
					&& is_named_type(directory.as_raw_fd(), last, libc::S_IFLNK))
			{
				return Err(policy("symlink traversal is not admitted"));
			}
			if matches!(errno, Some(libc::ENXIO | libc::EOPNOTSUPP))
				&& named_nonregular(directory.as_raw_fd(), last)
			{
				return Err(FileReadError::File {
					reason: FileReason::NotFile,
					errno,
				});
			}
			return Err(physical(error));
		}
		let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
		let metadata = match file.metadata() {
			Ok(metadata) => metadata,
			Err(error) => return close_result(file, Err(physical(error))),
		};
		if !metadata.is_file() {
			return close_result(
				file,
				Err(FileReadError::File {
					reason: FileReason::NotFile,
					errno: metadata.is_dir().then_some(libc::EISDIR),
				}),
			);
		}
		if let Err(error) = active(cancellation) {
			return close_result(file, Err(error));
		}
		return Ok((file, metadata));
	}
	Err(policy("path is outside controller workspace roots"))
}

#[cfg(target_os = "linux")]
fn named_mode(parent: std::os::fd::RawFd, name: &std::ffi::CStr) -> Option<libc::mode_t> {
	let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
	let status = unsafe {
		libc::fstatat(
			parent,
			name.as_ptr(),
			stat.as_mut_ptr(),
			libc::AT_SYMLINK_NOFOLLOW,
		)
	};
	(status == 0).then(|| unsafe { stat.assume_init().st_mode & libc::S_IFMT })
}
#[cfg(target_os = "linux")]
fn is_named_type(parent: std::os::fd::RawFd, name: &std::ffi::CStr, kind: libc::mode_t) -> bool {
	named_mode(parent, name) == Some(kind)
}
#[cfg(target_os = "linux")]
fn named_nonregular(parent: std::os::fd::RawFd, name: &std::ffi::CStr) -> bool {
	named_mode(parent, name).is_some_and(|mode| mode != libc::S_IFREG && mode != libc::S_IFLNK)
}

/// Linux closes the descriptor even when close reports a delayed error. Never
/// retry a numeric fd after close: another thread could already own that number.
#[cfg(target_os = "linux")]
fn close_result<T>(file: std::fs::File, result: Result<T>) -> Result<T> {
	use std::os::fd::IntoRawFd;
	let fd = file.into_raw_fd();
	if unsafe { libc::close(fd) } == 0 {
		result
	} else {
		Err(FileReadError::Cleanup {
			errno: io::Error::last_os_error().raw_os_error(),
			primary: result.err().map(Box::new),
			native_cleanup_incomplete: true,
		})
	}
}

#[cfg(target_os = "linux")]
fn read_blocking(
	path: &str,
	roots: &[PathBuf],
	cancellation: CancellationToken,
	limits: NativeJsonLimits,
) -> Result<OwnedJson> {
	if limits.max_depth > 120
		|| limits.max_depth == 0
		|| limits.max_token_bytes == 0
		|| limits.max_materialized_bytes == 0
	{
		return Err(gap("native-json-limit-configuration", json!(limits)));
	}
	// Validate the admitted lexical profile without changing the caller spelling
	// retained by the Evidence-source selector.
	active(&cancellation)?;
	let _ = normalized_error_path(path)?;
	let (mut file, before) = open_confined(Path::new(path), roots, &cancellation)?;
	let result = read_admitted(&mut file, &before, path, roots, &cancellation, limits);
	let result = close_result(file, result);
	if result.is_ok() {
		active(&cancellation)?;
	}
	result
}

#[cfg(not(target_os = "linux"))]
fn read_blocking(
	_path: &str,
	_roots: &[PathBuf],
	_cancellation: CancellationToken,
	_limits: NativeJsonLimits,
) -> Result<OwnedJson> {
	Err(gap("linux-descriptor-close-lifecycle-required", json!({})))
}

#[cfg(target_os = "linux")]
fn read_admitted(
	file: &mut std::fs::File,
	before: &std::fs::Metadata,
	path: &str,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
	limits: NativeJsonLimits,
) -> Result<OwnedJson> {
	let small = before.len() <= NATIVE_JSON_THRESHOLD;
	let mut first_digest = None;
	let mut early_error = None;
	if small {
		let state = Rc::new(RefCell::new(State::new(cancellation.clone(), limits, true)));
		{
			let mut reader = CheckedReader::new(&mut *file, before.len(), Rc::clone(&state), false);
			let mut chunk = [0_u8; CHUNK];
			while reader
				.read(&mut chunk)
				.map_err(|error| take_reader_error(&state, error))?
				!= 0
			{}
		}
		if state.borrow().bom() {
			early_error = Some(invalid_json(BOM_MESSAGE, true));
		}
		first_digest = Some(state.borrow().digest());
		file.seek(SeekFrom::Start(0)).map_err(physical)?;
	}
	let state = Rc::new(RefCell::new(State::new(
		cancellation.clone(),
		limits,
		small,
	)));
	let parsed = if let Some(error) = early_error {
		Err(error)
	} else {
		parse_reader(&mut *file, before.len(), Rc::clone(&state))
	};
	// An observed physical descriptor failure keeps its origin. Other parse
	// outcomes still pass through the original post-read identity fence.
	let parsed = match parsed {
		Err(error @ FileReadError::File { .. }) | Err(error @ FileReadError::Cancelled) => {
			return Err(error)
		}
		result => result,
	};
	active(cancellation)?;
	let after = file.metadata().map_err(physical)?;
	rea_files::ensure_unchanged(before, &after).map_err(|_| changed())?;
	let current = open_confined(Path::new(path), roots, cancellation);
	let (current_file, current_meta) = match current {
		Err(FileReadError::File {
			reason: FileReason::NotFile,
			..
		}) => return Err(changed()),
		other => other?,
	};
	let identity = rea_files::ensure_unchanged(before, &current_meta).map_err(|_| changed());
	close_result(current_file, identity)?;
	active(cancellation)?;
	let observed = state.borrow();
	// A syntax diagnostic now observes the complete second read as well.
	// Do not publish a message from bytes that changed between the UTF-8 scan
	// and parsing, even when the parsed outcome is an expected rejection.
	if (parsed.is_ok() || observed.eof)
		&& (observed.input_bytes != before.len()
			|| first_digest
				.as_ref()
				.is_some_and(|digest| digest != &observed.digest()))
	{
		return Err(changed());
	}
	let sha256 = observed.digest();
	drop(observed);
	let value = parsed?;
	Ok(OwnedJson {
		value: value.value,
		object_order: ObjectOrder(value.order),
		selected_path: path.into(),
		input_bytes: before.len(),
		sha256,
	})
}

struct State {
	cancellation: CancellationToken,
	limits: NativeJsonLimits,
	materialized: u64,
	failure: Option<FileReadError>,
	input_bytes: u64,
	hash: Sha256,
	prefix: Vec<u8>,
	eof_diagnostic: Option<String>,
	syntax_diagnostic: Option<String>,
	eof: bool,
	small: bool,
}
impl State {
	fn new(cancellation: CancellationToken, limits: NativeJsonLimits, small: bool) -> Self {
		Self {
			cancellation,
			limits,
			materialized: 0,
			failure: None,
			input_bytes: 0,
			hash: Sha256::new(),
			prefix: Vec::new(),
			eof_diagnostic: None,
			syntax_diagnostic: None,
			eof: false,
			small,
		}
	}
	fn digest(&self) -> String {
		self.hash
			.clone()
			.finalize()
			.into_iter()
			.map(|byte| format!("{byte:02x}"))
			.collect()
	}
	fn bom(&self) -> bool {
		self.prefix.starts_with(&[0xef, 0xbb, 0xbf])
	}
	fn fail<E: de::Error>(&mut self, error: FileReadError) -> E {
		if self.failure.is_none() {
			self.failure = Some(error);
		}
		E::custom("owned Evidence JSON boundary refused this value")
	}
	fn admit<E: de::Error>(&mut self, bytes: u64) -> std::result::Result<(), E> {
		if self.cancellation.is_cancelled() {
			return Err(self.fail(FileReadError::Cancelled));
		}
		self.materialized = self.materialized.saturating_add(bytes);
		if self.materialized > self.limits.max_materialized_bytes {
			return Err(self.fail(gap("native-json-materialization-budget", json!({
                "estimated_materialized_bytes":self.materialized,"max_materialized_bytes":self.limits.max_materialized_bytes
            }))));
		}
		Ok(())
	}
}

#[derive(Default)]
struct Utf8 {
	remaining: u8,
	low: u8,
	high: u8,
}
impl Utf8 {
	fn accept(&mut self, byte: u8) -> bool {
		if self.remaining > 0 {
			if byte < self.low || byte > self.high {
				return false;
			}
			self.remaining -= 1;
			self.low = 0x80;
			self.high = 0xbf;
			return true;
		}
		match byte {
			0..=0x7f => return true,
			0xc2..=0xdf => {
				self.remaining = 1;
				self.low = 0x80;
				self.high = 0xbf;
			}
			0xe0 => {
				self.remaining = 2;
				self.low = 0xa0;
				self.high = 0xbf;
			}
			0xed => {
				self.remaining = 2;
				self.low = 0x80;
				self.high = 0x9f;
			}
			0xe1..=0xec | 0xee..=0xef => {
				self.remaining = 2;
				self.low = 0x80;
				self.high = 0xbf;
			}
			0xf0 => {
				self.remaining = 3;
				self.low = 0x90;
				self.high = 0xbf;
			}
			0xf4 => {
				self.remaining = 3;
				self.low = 0x80;
				self.high = 0x8f;
			}
			0xf1..=0xf3 => {
				self.remaining = 3;
				self.low = 0x80;
				self.high = 0xbf;
			}
			_ => return false,
		}
		true
	}
}

#[derive(Default)]
struct TokenMeter {
	quoted: bool,
	escaped: bool,
	count: usize,
}
impl TokenMeter {
	fn accept(&mut self, byte: u8, maximum: usize) -> bool {
		if self.quoted {
			self.count = self.count.saturating_add(1);
			if self.escaped {
				self.escaped = false;
			} else if byte == b'\\' {
				self.escaped = true;
			} else if byte == b'"' {
				self.quoted = false;
			}
		} else if byte == b'"' {
			self.quoted = true;
			self.count = 1;
		} else if matches!(
			byte,
			b' ' | b'\n' | b'\r' | b'\t' | b'{' | b'}' | b'[' | b']' | b',' | b':'
		) {
			self.count = 0;
		} else {
			self.count = self.count.saturating_add(1);
		}
		self.count <= maximum
	}
}

struct CheckedReader<R> {
	inner: R,
	expected: u64,
	state: Rc<RefCell<State>>,
	utf8: Utf8,
	meter: Option<TokenMeter>,
	eof_tracker: Option<json_eof::Tracker>,
}
impl<R> CheckedReader<R> {
	fn new(inner: R, expected: u64, state: Rc<RefCell<State>>, meter: bool) -> Self {
		let eof_tracker = (meter && state.borrow().small).then(json_eof::Tracker::new);
		Self {
			inner,
			expected,
			state,
			utf8: Utf8::default(),
			meter: meter.then(TokenMeter::default),
			eof_tracker,
		}
	}
	fn refuse(&self, error: FileReadError) -> io::Error {
		if self.state.borrow().failure.is_none() {
			self.state.borrow_mut().failure = Some(error);
		}
		io::Error::other("owned Evidence JSON reader refused input")
	}
}
impl<R: Read> Read for CheckedReader<R> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		if output.is_empty() {
			return Ok(0);
		}
		if self.state.borrow().cancellation.is_cancelled() {
			return Err(self.refuse(FileReadError::Cancelled));
		}
		let position = self.state.borrow().input_bytes;
		let limit = output.len().min(
			(self.expected.saturating_sub(position).saturating_add(1)).min(CHUNK as u64) as usize,
		);
		let count = self
			.inner
			.read(&mut output[..limit])
			.map_err(|error| self.refuse(physical(error)))?;
		if self.state.borrow().cancellation.is_cancelled() {
			return Err(self.refuse(FileReadError::Cancelled));
		}
		if count == 0 {
			if position != self.expected {
				return Err(self.refuse(changed()));
			}
			if self.utf8.remaining != 0 {
				let small = self.state.borrow().small;
				return Err(self.refuse(invalid_json(UTF8_MESSAGE, small)));
			}
			let mut state = self.state.borrow_mut();
			state.eof = true;
			if let Some(tracker) = self.eof_tracker.take() {
				if tracker.has_syntax_error() {
					state.syntax_diagnostic = tracker.finish();
				} else {
					state.eof_diagnostic = tracker.finish();
				}
			}
			return Ok(0);
		}
		if position.saturating_add(count as u64) > self.expected {
			return Err(self.refuse(changed()));
		}
		for &byte in &output[..count] {
			if !self.utf8.accept(byte) {
				let small = self.state.borrow().small;
				return Err(self.refuse(invalid_json(UTF8_MESSAGE, small)));
			}
		}
		if let Some(meter) = &mut self.meter {
			let maximum = self.state.borrow().limits.max_token_bytes;
			for &byte in &output[..count] {
				if !meter.accept(byte, maximum) {
					return Err(self.refuse(gap(
						"native-json-token-budget",
						json!({"max_token_bytes":maximum}),
					)));
				}
			}
		}
		if let Some(tracker) = &mut self.eof_tracker {
			tracker.accept(&output[..count]);
		}
		let mut state = self.state.borrow_mut();
		state.input_bytes += count as u64;
		state.hash.update(&output[..count]);
		let needed = 3_usize.saturating_sub(state.prefix.len()).min(count);
		state.prefix.extend_from_slice(&output[..needed]);
		Ok(count)
	}
}

fn take_reader_error(state: &Rc<RefCell<State>>, fallback: io::Error) -> FileReadError {
	state
		.borrow_mut()
		.failure
		.take()
		.unwrap_or_else(|| physical(fallback))
}

fn parse_reader<R: Read>(reader: R, expected: u64, state: Rc<RefCell<State>>) -> Result<Parsed> {
	let guarded = CheckedReader::new(reader, expected, Rc::clone(&state), true);
	let mut buffered = BufReader::with_capacity(CHUNK, guarded);
	let result = {
		let mut parser = serde_json::Deserializer::from_reader(&mut buffered);
		Seed {
			state: Rc::clone(&state),
			depth: 0,
		}
		.deserialize(&mut parser)
		.and_then(|value| parser.end().map(|_| value))
	};
	// Small-file JSON.parse diagnostics can include source after the first
	// error. Drain only this bounded profile through the same checked owner:
	// UTF-8, physical I/O, cancellation and native budgets retain priority.
	// The value parser still decides rejection; the observer never accepts a
	// document, and large-file streaming/error behavior stays unchanged.
	if result.is_err() && state.borrow().small && state.borrow().failure.is_none() {
		let mut discard = [0_u8; CHUNK];
		while buffered
			.read(&mut discard)
			.map_err(|error| take_reader_error(&state, error))?
			!= 0
		{}
	}
	match result {
		Ok(value) => Ok(value),
		Err(error) => {
			let mut state = state.borrow_mut();
			if let Some(error) = state.failure.take() {
				return Err(error);
			}
			if state.bom() {
				return Err(invalid_json(BOM_MESSAGE, true));
			}
			// A physical EOF and an independently observed grammar failure are
			// required. Valid JSON with an unsupported value representation has
			// no syntax diagnostic and remains an explicit native profile gap.
			// IoRead may reach EOF while filling a four-byte Unicode escape
			// after the observer has already found its first invalid hex unit.
			if (error.is_syntax() || error.is_eof()) && state.small && state.eof {
				if let Some(message) = state.syntax_diagnostic.take() {
					return Err(invalid_json(&message, false));
				}
			}
			if error.is_eof() && state.small && state.eof {
				if let Some(message) = state.eof_diagnostic.take() {
					return Err(invalid_json(&message, false));
				}
			}
			Err(gap(
				"json-diagnostic-or-value-representation",
				json!({
					"native_parser":"serde_json 1.0.151", "native_diagnostic":error.to_string(),
					"line":error.line(),"column":error.column()
				}),
			))
		}
	}
}

/// Reuse the native materialization/token/depth fence for already captured
/// private checkpoint bytes. Descriptor admission remains the store owner's job.
pub(super) fn parse_checkpoint_json(
	bytes: &[u8],
	cancellation: &CancellationToken,
) -> Result<(Value, ObjectOrder)> {
	active(cancellation)?;
	let state = Rc::new(RefCell::new(State::new(
		cancellation.clone(),
		NativeJsonLimits::default(),
		bytes.len() as u64 <= NATIVE_JSON_THRESHOLD,
	)));
	let parsed = parse_reader(std::io::Cursor::new(bytes), bytes.len() as u64, state)?;
	active(cancellation)?;
	Ok((parsed.value, ObjectOrder(parsed.order)))
}

struct Seed {
	state: Rc<RefCell<State>>,
	depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed {
	type Value = Parsed;
	fn deserialize<D: de::Deserializer<'de>>(
		self,
		deserializer: D,
	) -> std::result::Result<Parsed, D::Error> {
		{
			let mut state = self.state.borrow_mut();
			if self.depth > state.limits.max_depth {
				let maximum = state.limits.max_depth;
				return Err(state.fail(gap(
					"native-json-depth-budget",
					json!({"max_depth":maximum,"observed_depth":self.depth}),
				)));
			}
			state.admit::<D::Error>(128)?;
		}
		deserializer.deserialize_any(self)
	}
}
fn array_index(key: &str) -> Option<u32> {
	if key.is_empty()
		|| (key.len() > 1 && key.starts_with('0'))
		|| !key.bytes().all(|b| b.is_ascii_digit())
	{
		return None;
	}
	key.parse::<u32>().ok().filter(|&index| index != u32::MAX)
}
fn js_number(number: f64) -> Option<Number> {
	if !number.is_finite() {
		return None;
	}
	if number == 0.0 {
		return Some(0.into());
	}
	if number.fract() == 0.0 {
		if (0.0..18_446_744_073_709_551_616.0).contains(&number) {
			return Some((number as u64).into());
		}
		if (-9_223_372_036_854_775_808.0..0.0).contains(&number) {
			return Some((number as i64).into());
		}
	}
	Number::from_f64(number)
}
impl<'de> Visitor<'de> for Seed {
	type Value = Parsed;
	fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("a JSON value")
	}
	fn visit_unit<E: de::Error>(self) -> std::result::Result<Parsed, E> {
		Ok(leaf(Value::Null))
	}
	fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Parsed, E> {
		Ok(leaf(value.into()))
	}
	fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Parsed, E> {
		self.visit_f64(value as f64)
	}
	fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Parsed, E> {
		self.visit_f64(value as f64)
	}
	fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Parsed, E> {
		js_number(value)
			.map(|value| leaf(Value::Number(value)))
			.ok_or_else(|| {
				self.state
					.borrow_mut()
					.fail(gap("nonfinite-json-number", json!({})))
			})
	}
	fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Parsed, E> {
		self.state
			.borrow_mut()
			.admit::<E>((value.len() as u64).saturating_mul(2).saturating_add(64))?;
		Ok(leaf(Value::String(value.to_owned())))
	}
	fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Parsed, E> {
		self.state
			.borrow_mut()
			.admit::<E>((value.len() as u64).saturating_mul(2).saturating_add(64))?;
		Ok(leaf(Value::String(value)))
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> std::result::Result<Parsed, A::Error> {
		self.state.borrow_mut().admit::<A::Error>(256)?;
		let mut values = Vec::new();
		let mut orders = Vec::new();
		loop {
			let child = Seed {
				state: Rc::clone(&self.state),
				depth: self.depth + 1,
			};
			let Some(value) = access.next_element_seed(child)? else {
				break;
			};
			values
				.try_reserve(1)
				.and_then(|()| orders.try_reserve(1))
				.map_err(|_| {
					self.state
						.borrow_mut()
						.fail(gap("native-json-allocation", json!({"container":"array"})))
				})?;
			values.push(value.value);
			orders.push(value.order);
		}
		Ok(Parsed {
			value: Value::Array(values),
			order: OrderNode::Array(orders),
		})
	}
	fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> std::result::Result<Parsed, A::Error> {
		self.state.borrow_mut().admit::<A::Error>(256)?;
		let mut values = Map::new();
		let mut keys = Vec::new();
		let mut children = BTreeMap::new();
		while let Some(key) = access.next_key::<String>()? {
			self.state
				.borrow_mut()
				.admit::<A::Error>((key.len() as u64).saturating_mul(3).saturating_add(128))?;
			if !values.contains_key(&key) {
				keys.push(key.clone());
			}
			let child = Seed {
				state: Rc::clone(&self.state),
				depth: self.depth + 1,
			};
			let value = access.next_value_seed(child)?;
			values.insert(key.clone(), value.value);
			children.insert(key, value.order);
		}
		// Stable sort retains ordinary keys' first insertion order. Canonical
		// JavaScript array-index names precede them in numeric order.
		keys.sort_by(
			|left, right| match (array_index(left), array_index(right)) {
				(Some(left), Some(right)) => left.cmp(&right),
				(Some(_), None) => std::cmp::Ordering::Less,
				(None, Some(_)) => std::cmp::Ordering::Greater,
				(None, None) => std::cmp::Ordering::Equal,
			},
		);
		Ok(Parsed {
			value: Value::Object(values),
			order: OrderNode::Object { keys, children },
		})
	}
}

#[cfg(all(test, target_os = "linux"))]
#[path = "rea_evidence_file_tests.rs"]
mod tests;
