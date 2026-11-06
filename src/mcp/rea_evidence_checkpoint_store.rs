// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Linux descriptor-relative checkpoint storage. As in the model snapshot
//! store, the blocking commit owns the cross-process lock through parent fsync.
//! Incomplete staging consumes quota and is never a recoverable checkpoint.

use super::{active, Scope, MAX_CHECKPOINTS, MAX_STORE_BYTES, ROOT_NAME};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

const MEMBERS: [&str; 3] = ["bundle.json", "manifest.json", "retention.json"];

fn name(value: &str) -> Result<CString> {
	ensure!(
		!value.is_empty() && value != "." && value != ".." && !value.contains('/'),
		"checkpoint store name is invalid"
	);
	CString::new(value).context("checkpoint store name contains NUL")
}

fn open_at(parent: RawFd, name: &CStr, flags: i32, mode: libc::mode_t) -> Result<File> {
	let fd = unsafe {
		libc::openat(
			parent,
			name.as_ptr(),
			flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
			mode,
		)
	};
	if fd < 0 {
		return Err(std::io::Error::last_os_error())
			.context("checkpoint descriptor admission failed");
	}
	Ok(unsafe { File::from_raw_fd(fd) })
}

fn private_directory(file: &File) -> Result<()> {
	let metadata = file.metadata()?;
	ensure!(
		metadata.is_dir()
			&& metadata.uid() == unsafe { libc::geteuid() }
			&& metadata.mode() & 0o7777 == 0o700,
		"checkpoint directory must be owned and mode 0700"
	);
	Ok(())
}

fn administrator_directory(file: &File) -> Result<()> {
	let metadata = file.metadata()?;
	ensure!(
		metadata.is_dir()
			&& metadata.uid() == unsafe { libc::geteuid() }
			&& metadata.mode() & 0o022 == 0,
		"checkpoint administrator state directory must be owned and not writable by other accounts"
	);
	Ok(())
}

fn open_state_path(path: &Path) -> Result<File> {
	let file = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
		.open(path)
		.context("checkpoint administrator state directory is unavailable")?;
	administrator_directory(&file)?;
	Ok(file)
}

fn require_state_binding(path: &Path, expected: &File) -> Result<()> {
	administrator_directory(expected)?;
	let current = open_state_path(path)?;
	let checked = (|| {
		ensure!(
			same_inode(&expected.metadata()?, &current.metadata()?),
			"checkpoint configured state directory identity changed"
		);
		Ok(())
	})();
	let closed = close_file(current);
	checked?;
	closed
}

fn sync_state_ancestors(
	path: &Path,
	state: &File,
	cancellation: &CancellationToken,
	before_sync: &dyn Fn(&Path) -> Result<()>,
) -> Result<()> {
	require_state_binding(path, state)?;
	// A failed earlier setup may have left any ancestor newly created but
	// unsynced. Every create/reconcile attempt confirms the whole parent chain,
	// including existing directories; syncing only this attempt's mkdirs is
	// insufficient. Ancestor traversal retains the trusted-administrator path
	// policy; only the final configured state directory is opened NOFOLLOW.
	for parent in path.ancestors().skip(1) {
		active(cancellation)?;
		let directory = OpenOptions::new()
			.read(true)
			.custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
			.open(parent)
			.context("checkpoint state ancestor is unavailable for durability confirmation")?;
		let synced = (|| {
			before_sync(parent)?;
			active(cancellation)?;
			directory
				.sync_all()
				.context("checkpoint state ancestor durability is unconfirmed")?;
			active(cancellation)
		})();
		let closed = close_file(directory);
		synced?;
		closed?;
	}
	require_state_binding(path, state)
}

fn private_file(metadata: &Metadata) -> Result<()> {
	ensure!(
		metadata.is_file()
			&& metadata.uid() == unsafe { libc::geteuid() }
			&& metadata.mode() & 0o7777 == 0o600
			&& metadata.nlink() == 1,
		"checkpoint file must be owned, regular, single-linked and mode 0600"
	);
	Ok(())
}

fn same_inode(left: &Metadata, right: &Metadata) -> bool {
	left.dev() == right.dev() && left.ino() == right.ino()
}

fn is_missing(error: &anyhow::Error) -> bool {
	error
		.downcast_ref::<std::io::Error>()
		.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn directory_at(parent: RawFd, child: &str) -> Result<File> {
	let file = open_at(parent, &name(child)?, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_directory(&file)?;
	Ok(file)
}

fn entries(directory: &File, maximum: usize) -> Result<Vec<String>> {
	// dup would share the directory offset with the retained lock descriptor.
	// A fresh openat(".") keeps repeated catalog scans complete and independent.
	let copy = unsafe {
		libc::openat(
			directory.as_raw_fd(),
			c".".as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
		)
	};
	if copy < 0 {
		return Err(std::io::Error::last_os_error())
			.context("cannot open checkpoint directory iterator");
	}
	let stream = unsafe { libc::fdopendir(copy) };
	if stream.is_null() {
		let error = std::io::Error::last_os_error();
		unsafe {
			libc::close(copy);
		}
		return Err(error).context("cannot enumerate checkpoint directory");
	}
	let result = (|| {
		let mut names = Vec::new();
		loop {
			unsafe {
				*libc::__errno_location() = 0;
			}
			let entry = unsafe { libc::readdir(stream) };
			if entry.is_null() {
				let errno = unsafe { *libc::__errno_location() };
				if errno != 0 {
					return Err(std::io::Error::from_raw_os_error(errno))
						.context("checkpoint directory enumeration failed");
				}
				break;
			}
			let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
			if bytes == b"." || bytes == b".." {
				continue;
			}
			ensure!(
				names.len() < maximum,
				"native checkpoint directory-entry budget exceeded ({maximum})"
			);
			let value =
				std::str::from_utf8(bytes).context("checkpoint store contains a non-UTF-8 name")?;
			ensure!(
				value.len() <= 128,
				"checkpoint store name exceeds its budget"
			);
			names.push(value.to_owned());
		}
		names.sort();
		Ok(names)
	})();
	let closed = unsafe { libc::closedir(stream) };
	if closed != 0 {
		return Err(std::io::Error::last_os_error())
			.context("checkpoint directory enumeration cleanup is incomplete");
	}
	result
}

fn close_file(file: File) -> Result<()> {
	let fd = file.into_raw_fd();
	if unsafe { libc::close(fd) } != 0 {
		// Linux closes the descriptor even for late close failures; retrying
		// could close another owner's reused descriptor.
		return Err(std::io::Error::last_os_error()).context("checkpoint file close failed");
	}
	Ok(())
}

fn require_named_directory(parent: &File, child: &str, expected: &File) -> Result<()> {
	private_directory(expected)?;
	let current = directory_at(parent.as_raw_fd(), child)?;
	ensure!(
		same_inode(&expected.metadata()?, &current.metadata()?),
		"checkpoint named directory identity changed"
	);
	Ok(())
}

fn require_named_file(directory: &File, member: &str, expected: &Metadata) -> Result<()> {
	let current = open_at(
		directory.as_raw_fd(),
		&name(member)?,
		libc::O_RDONLY | libc::O_NONBLOCK,
		0,
	)?;
	let checked = (|| {
		let metadata = current.metadata()?;
		private_file(&metadata)?;
		crate::mcp::rea_files::ensure_unchanged(expected, &metadata)
	})();
	let closed = close_file(current);
	checked?;
	closed
}

pub(super) struct Directory {
	state_path: PathBuf,
	state: File,
	root: File,
	name: String,
	file: File,
	read_members: BTreeMap<String, Metadata>,
}

impl Directory {
	pub(super) fn check_binding(&self) -> Result<()> {
		require_state_binding(&self.state_path, &self.state)?;
		require_named_directory(&self.state, ROOT_NAME, &self.root)?;
		require_named_directory(&self.root, &self.name, &self.file)
	}

	pub(super) fn require_complete(&self) -> Result<()> {
		self.check_binding()?;
		ensure!(
			entries(&self.file, MEMBERS.len())? == MEMBERS,
			"checkpoint committed directory has missing or unexpected members"
		);
		Ok(())
	}

	pub(super) fn confirm_read(&self) -> Result<()> {
		self.require_complete()?;
		ensure!(
			self.read_members.len() == MEMBERS.len(),
			"checkpoint complete member observation is missing"
		);
		for (member, metadata) in &self.read_members {
			require_named_file(&self.file, member, metadata)?;
		}
		self.require_complete()
	}

	pub(super) fn read(
		&mut self,
		member: &str,
		maximum: usize,
		cancellation: &CancellationToken,
	) -> Result<Vec<u8>> {
		active(cancellation)?;
		self.check_binding()?;
		ensure!(
			MEMBERS.contains(&member),
			"checkpoint member is not admitted"
		);
		let member_name = name(member)?;
		let mut file = open_at(
			self.file.as_raw_fd(),
			&member_name,
			libc::O_RDONLY | libc::O_NONBLOCK,
			0,
		)?;
		let before = file.metadata()?;
		private_file(&before)?;
		ensure!(
			before.len() <= maximum as u64,
			"native checkpoint {member} byte budget exceeded ({maximum})"
		);
		let read = (|| {
			let mut bytes = Vec::new();
			bytes
				.try_reserve_exact(before.len() as usize)
				.context("native checkpoint read allocation failed")?;
			let mut chunk = [0u8; 64 * 1024];
			loop {
				active(cancellation)?;
				let count = file.read(&mut chunk)?;
				active(cancellation)?;
				if count == 0 {
					break;
				}
				ensure!(
					bytes
						.len()
						.checked_add(count)
						.is_some_and(|total| total <= maximum && total as u64 <= before.len()),
					"checkpoint file grew while being read"
				);
				bytes.extend_from_slice(&chunk[..count]);
			}
			ensure!(
				bytes.len() as u64 == before.len(),
				"checkpoint file length changed while reading"
			);
			let after = file.metadata()?;
			private_file(&after)?;
			crate::mcp::rea_files::ensure_unchanged(&before, &after)?;
			let current = open_at(
				self.file.as_raw_fd(),
				&member_name,
				libc::O_RDONLY | libc::O_NONBLOCK,
				0,
			)?;
			let metadata = current.metadata()?;
			private_file(&metadata)?;
			let unchanged = crate::mcp::rea_files::ensure_unchanged(&before, &metadata);
			close_file(current)?;
			unchanged?;
			Ok(bytes)
		})();
		let closed = close_file(file);
		match (read, closed) {
			(Ok(bytes), Ok(())) => {
				self.check_binding()?;
				if let Some(previous) = self.read_members.get(member) {
					crate::mcp::rea_files::ensure_unchanged(previous, &before)?;
				}
				self.read_members.insert(member.to_owned(), before);
				Ok(bytes)
			}
			(Err(error), Ok(())) => Err(error),
			(Ok(_), Err(error)) => Err(error),
			(Err(primary), Err(cleanup)) => {
				Err(primary.context(format!("checkpoint read cleanup failed: {cleanup}")))
			}
		}
	}
}

pub(super) struct Store {
	state_path: PathBuf,
	state: File,
	root: File,
}

impl Store {
	pub(super) fn open(
		scope: &Scope,
		create: bool,
		exclusive: bool,
		cancellation: &CancellationToken,
	) -> Result<Option<Self>> {
		Self::open_with_parent_sync_hook(scope, create, exclusive, cancellation, &|_| Ok(()))
	}

	pub(super) fn open_with_parent_sync_hook(
		scope: &Scope,
		create: bool,
		exclusive: bool,
		cancellation: &CancellationToken,
		before_parent_sync: &dyn Fn(&Path) -> Result<()>,
	) -> Result<Option<Self>> {
		active(cancellation)?;
		ensure!(
			scope.state_dir.is_absolute()
				&& !scope
					.state_dir
					.components()
					.any(|part| matches!(part, Component::ParentDir)),
			"checkpoint state requires a normal absolute administrator path"
		);
		if create {
			use std::os::unix::fs::DirBuilderExt;
			std::fs::DirBuilder::new()
				.recursive(true)
				.mode(0o700)
				.create(&scope.state_dir)?;
		}
		let state = match open_state_path(&scope.state_dir) {
			Ok(file) => file,
			Err(error) if !create && is_missing(&error) => return Ok(None),
			Err(error) => return Err(error),
		};
		if create {
			sync_state_ancestors(&scope.state_dir, &state, cancellation, before_parent_sync)?;
			let made =
				unsafe { libc::mkdirat(state.as_raw_fd(), name(ROOT_NAME)?.as_ptr(), 0o700) };
			if made != 0
				&& std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
			{
				return Err(std::io::Error::last_os_error())
					.context("cannot create checkpoint store");
			}
			state
				.sync_all()
				.context("checkpoint store parent durability is unconfirmed")?;
		}
		let root = match directory_at(state.as_raw_fd(), ROOT_NAME) {
			Ok(root) => root,
			Err(error) if !create && is_missing(&error) => return Ok(None),
			Err(error) => return Err(error),
		};
		let deadline = Instant::now() + Duration::from_secs(10);
		loop {
			active(cancellation)?;
			let mode = if exclusive {
				libc::LOCK_EX
			} else {
				libc::LOCK_SH
			};
			if unsafe { libc::flock(root.as_raw_fd(), mode | libc::LOCK_NB) } == 0 {
				break;
			}
			let error = std::io::Error::last_os_error();
			if error.kind() != std::io::ErrorKind::WouldBlock {
				return Err(error).context("checkpoint store lock failed");
			}
			ensure!(Instant::now() < deadline, "checkpoint store is busy; retry the same request after the current owner completes");
			std::thread::sleep(Duration::from_millis(10));
		}
		let store = Self {
			state_path: scope.state_dir.clone(),
			state,
			root,
		};
		store.check_binding()?;
		store.storage_bytes()?;
		Ok(Some(store))
	}

	fn check_binding(&self) -> Result<()> {
		require_state_binding(&self.state_path, &self.state)?;
		require_named_directory(&self.state, ROOT_NAME, &self.root)
	}

	pub(super) fn names(&self) -> Result<Vec<String>> {
		self.check_binding()?;
		entries(&self.root, MAX_CHECKPOINTS)
	}

	pub(super) fn checkpoint(&self, id: &str) -> Result<Option<Directory>> {
		self.check_binding()?;
		match directory_at(self.root.as_raw_fd(), id) {
			Ok(file) => Ok(Some(Directory {
				state_path: self.state_path.clone(),
				state: self.state.try_clone()?,
				root: self.root.try_clone()?,
				name: id.to_owned(),
				file,
				read_members: BTreeMap::new(),
			})),
			Err(error) if is_missing(&error) => Ok(None),
			Err(error) => Err(error),
		}
	}

	fn storage_bytes(&self) -> Result<u64> {
		let mut bytes = 0u64;
		for item in self.names()? {
			ensure!(
				item.starts_with(".stage-") || super::valid_id(&item),
				"checkpoint store contains an unrecognized entry"
			);
			let directory = directory_at(self.root.as_raw_fd(), &item)?;
			for member in entries(&directory, MEMBERS.len())? {
				// Every private staged byte consumes quota even when cleanup left
				// a member which cannot be admitted as a committed payload.
				let file = open_at(
					directory.as_raw_fd(),
					&name(&member)?,
					libc::O_RDONLY | libc::O_NONBLOCK,
					0,
				)?;
				let metadata = file.metadata()?;
				private_file(&metadata)?;
				bytes = bytes
					.checked_add(metadata.len())
					.context("checkpoint quota accounting overflow")?;
				close_file(file)?;
				ensure!(bytes <= MAX_STORE_BYTES, "native checkpoint store byte budget exhausted ({MAX_STORE_BYTES}, including incomplete staging)");
			}
		}
		self.check_binding()?;
		Ok(bytes)
	}

	pub(super) fn admit_quota(&self, incoming: u64) -> Result<()> {
		ensure!(self.names()?.len() < MAX_CHECKPOINTS, "native checkpoint count budget exhausted ({MAX_CHECKPOINTS}, including incomplete staging)");
		let bytes = self.storage_bytes()?;
		ensure!(bytes.checked_add(incoming).is_some_and(|total| total <= MAX_STORE_BYTES), "native checkpoint store byte budget exhausted ({MAX_STORE_BYTES}, including incomplete staging)");
		Ok(())
	}

	pub(super) fn confirm_existing(&self) -> Result<()> {
		self.check_binding()?;
		self.root
			.sync_all()
			.context("checkpoint reconciliation did not confirm parent directory durability")?;
		self.check_binding()
	}

	pub(super) fn publish(
		&self,
		id: &str,
		members: [(&str, &[u8]); 3],
		cancellation: &CancellationToken,
		hook: &dyn Fn(CommitPhase) -> Result<()>,
	) -> Result<()> {
		static NEXT: AtomicU64 = AtomicU64::new(0);
		let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
		let stage_name = format!(
			".stage-{}-{stamp:x}-{:x}",
			std::process::id(),
			NEXT.fetch_add(1, Ordering::Relaxed)
		);
		let stage_cname = name(&stage_name)?;
		active(cancellation)?;
		if unsafe { libc::mkdirat(self.root.as_raw_fd(), stage_cname.as_ptr(), 0o700) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot create private checkpoint staging directory");
		}
		let mut stage = Stage {
			root: &self.root,
			file: directory_at(self.root.as_raw_fd(), &stage_name)?,
			name: stage_name,
			members: Vec::new(),
			published: false,
		};
		let result = (|| {
			for (member, bytes) in members {
				stage.write(member, bytes, cancellation)?;
			}
			stage
				.file
				.sync_all()
				.context("checkpoint staging directory durability failed")?;
			self.check_binding()?;
			hook(CommitPhase::BeforeRename)?;
			active(cancellation)?;
			self.check_binding()?;
			stage.check_complete_binding(&stage.name, Some(cancellation))?;
			active(cancellation)?;
			let renamed = unsafe {
				libc::renameat2(
					self.root.as_raw_fd(),
					stage_cname.as_ptr(),
					self.root.as_raw_fd(),
					name(id)?.as_ptr(),
					libc::RENAME_NOREPLACE,
				)
			};
			if renamed != 0 {
				return Err(std::io::Error::last_os_error()).context("checkpoint create-only publication failed; reconcile the same content identity");
			}
			stage.published = true;
			// Once visible, cancellation cannot undo the committed observation.
			// The real parent sync remains inside the blocking owner's guard scope.
			hook(CommitPhase::BeforeParentSync)?;
			stage.check_complete_binding(id, None)?;
			self.root.sync_all()?;
			self.check_binding()?;
			hook(CommitPhase::AfterParentSync)?;
			stage.check_complete_binding(id, None)?;
			self.check_binding()?;
			Ok(())
		})();
		let cleanup = if stage.published {
			Ok(())
		} else {
			stage.cleanup()
		};
		match (result, cleanup) {
			(Ok(()), Ok(())) => Ok(()),
			(Err(error), Ok(())) => Err(error.context(format!("checkpoint {id} did not return a confirmed durable receipt; repeat the identical checkpoint or list to reconcile"))),
			(Ok(()), Err(error)) => Err(error.context("checkpoint staging cleanup is incomplete; no successful receipt is issued")),
			(Err(primary), Err(cleanup)) => Err(primary.context(format!("checkpoint staging cleanup is incomplete: {cleanup}"))),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CommitPhase {
	BeforeRename,
	BeforeParentSync,
	AfterParentSync,
}

struct Stage<'a> {
	root: &'a File,
	file: File,
	name: String,
	members: Vec<StagedMember>,
	published: bool,
}

struct StagedMember {
	name: String,
	metadata: Metadata,
	sha256: String,
	complete: bool,
}

impl Stage<'_> {
	fn check_complete_binding(
		&self,
		selected_name: &str,
		cancellation: Option<&CancellationToken>,
	) -> Result<()> {
		require_named_directory(self.root, selected_name, &self.file)?;
		ensure!(
			entries(&self.file, MEMBERS.len())? == MEMBERS && self.members.len() == MEMBERS.len(),
			"checkpoint staged member set changed"
		);
		for member in &self.members {
			ensure!(
				member.complete,
				"checkpoint staged member did not finish writing"
			);
			require_named_file(&self.file, &member.name, &member.metadata)?;
			if let Some(cancellation) = cancellation {
				// Authenticate actual inode bytes after the mutation hook. A writer
				// that changed a staged file before its final metadata was captured
				// must not turn a valid in-memory payload into a corrupt commit.
				let mut file = open_at(
					self.file.as_raw_fd(),
					&name(&member.name)?,
					libc::O_RDONLY | libc::O_NONBLOCK,
					0,
				)?;
				let checked = (|| {
					crate::mcp::rea_files::ensure_unchanged(&member.metadata, &file.metadata()?)?;
					let mut digest = Sha256::new();
					let mut length = 0u64;
					let mut chunk = [0u8; 64 * 1024];
					loop {
						active(cancellation)?;
						let count = file.read(&mut chunk)?;
						if count == 0 {
							break;
						}
						length = length
							.checked_add(count as u64)
							.context("checkpoint staged length overflow")?;
						ensure!(
							length <= member.metadata.len(),
							"checkpoint staged file grew"
						);
						digest.update(&chunk[..count]);
					}
					ensure!(
						length == member.metadata.len(),
						"checkpoint staged file shrank"
					);
					let actual: String = digest
						.finalize()
						.iter()
						.map(|byte| format!("{byte:02x}"))
						.collect();
					ensure!(
						actual == member.sha256,
						"checkpoint staged contents differ from the authenticated payload"
					);
					crate::mcp::rea_files::ensure_unchanged(&member.metadata, &file.metadata()?)?;
					require_named_file(&self.file, &member.name, &member.metadata)
				})();
				let closed = close_file(file);
				checked?;
				closed?;
			}
		}
		require_named_directory(self.root, selected_name, &self.file)
	}

	fn write(
		&mut self,
		member: &str,
		bytes: &[u8],
		cancellation: &CancellationToken,
	) -> Result<()> {
		ensure!(
			MEMBERS.contains(&member),
			"checkpoint staged member is invalid"
		);
		let mut file = open_at(
			self.file.as_raw_fd(),
			&name(member)?,
			libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
			0o600,
		)?;
		let metadata = file.metadata()?;
		private_file(&metadata)?;
		self.members.push(StagedMember {
			name: member.to_owned(),
			metadata,
			sha256: super::hash(bytes),
			complete: false,
		});
		let written = (|| {
			for chunk in bytes.chunks(64 * 1024) {
				active(cancellation)?;
				file.write_all(chunk)?;
			}
			active(cancellation)?;
			file.sync_all()
				.context("checkpoint staged file durability failed")?;
			let metadata = file.metadata()?;
			private_file(&metadata)?;
			ensure!(
				metadata.len() == bytes.len() as u64,
				"checkpoint staged file length changed"
			);
			Ok(metadata)
		})();
		let closed = close_file(file);
		match (written, closed) {
			(Ok(metadata), Ok(())) => {
				let retained = self
					.members
					.last_mut()
					.context("checkpoint staged member tracking is absent")?;
				retained.metadata = metadata;
				retained.complete = true;
				Ok(())
			}
			(Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
			(Err(primary), Err(cleanup)) => {
				Err(primary.context(format!("checkpoint staged close also failed: {cleanup}")))
			}
		}
	}

	fn cleanup(&mut self) -> Result<()> {
		// Refuse detached/replaced names before touching any staged member.
		require_named_directory(self.root, &self.name, &self.file)?;
		for member in &self.members {
			let current = match open_at(
				self.file.as_raw_fd(),
				&name(&member.name)?,
				libc::O_RDONLY | libc::O_NONBLOCK,
				0,
			) {
				Ok(file) => file,
				Err(error) if is_missing(&error) => continue,
				Err(error) => return Err(error),
			};
			let metadata = current.metadata()?;
			private_file(&metadata)?;
			ensure!(
				same_inode(&member.metadata, &metadata),
				"foreign checkpoint staging inode is retained, not removed"
			);
			close_file(current)?;
		}
		for member in &self.members {
			require_named_directory(self.root, &self.name, &self.file)?;
			let current = match open_at(
				self.file.as_raw_fd(),
				&name(&member.name)?,
				libc::O_RDONLY | libc::O_NONBLOCK,
				0,
			) {
				Ok(file) => file,
				Err(error) if is_missing(&error) => continue,
				Err(error) => return Err(error),
			};
			let metadata = current.metadata()?;
			private_file(&metadata)?;
			ensure!(
				same_inode(&member.metadata, &metadata),
				"foreign checkpoint staging inode is retained, not removed"
			);
			close_file(current)?;
			if unsafe { libc::unlinkat(self.file.as_raw_fd(), name(&member.name)?.as_ptr(), 0) }
				!= 0
			{
				return Err(std::io::Error::last_os_error())
					.context("cannot remove owned checkpoint staging file");
			}
		}
		require_named_directory(self.root, &self.name, &self.file)?;
		if unsafe {
			libc::unlinkat(
				self.root.as_raw_fd(),
				name(&self.name)?.as_ptr(),
				libc::AT_REMOVEDIR,
			)
		} != 0
		{
			return Err(std::io::Error::last_os_error())
				.context("cannot remove owned checkpoint staging directory");
		}
		self.root
			.sync_all()
			.context("checkpoint staging cleanup durability is unconfirmed")
	}
}
