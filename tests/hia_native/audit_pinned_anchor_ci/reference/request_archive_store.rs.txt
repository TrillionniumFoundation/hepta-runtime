// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One admission ledger over the immutable legacy namespace and bounded shards.
//! The legacy directory and index retain their identities. A sticky, inode-bound
//! anchor introduces the sibling namespace before any new record can use it.
use super::*;
use std::os::{fd::AsRawFd, unix::fs::MetadataExt};

pub(super) const SHARD_ROOT: &str = "request-archive-v12";
pub(super) const SHARD_ANCHOR: &str = ".request-archive-v12-anchor.json";
pub(super) const SHARD_INTENT: &str = ".request-archive-v12-init.json";
const SHARDS: usize = 256;
const FLAT_DIRECTORY_LIMIT: u64 = 64 * 1024 * 1024;
const MAX_ANCHOR_BYTES: usize = 64 * 1024;

// Derive the NUL-terminated component from the same spelling used by all
// generic callers. The checked const conversion also rejects interior NULs.
const LEGACY_COMPONENT_BYTES: [u8; ARCHIVE_NAME.len() + 1] = {
	let mut bytes = [0u8; ARCHIVE_NAME.len() + 1];
	let mut index = 0;
	while index < ARCHIVE_NAME.len() {
		bytes[index] = ARCHIVE_NAME.as_bytes()[index];
		index += 1;
	}
	bytes
};
const LEGACY_COMPONENT: &std::ffi::CStr =
	match std::ffi::CStr::from_bytes_with_nul(&LEGACY_COMPONENT_BYTES) {
		Ok(component) => component,
		Err(_) => panic!("invalid private metadata component"),
	};

pub(super) const ORIGINAL_COMPONENT_BYTES: usize = 64 + 5 + 1;

pub(super) fn stack_original_component<'buffer>(
	filename: &str,
	buffer: &'buffer mut [u8; ORIGINAL_COMPONENT_BYTES],
) -> Result<&'buffer std::ffi::CStr> {
	// The caller retains its original canonical filename validation. This
	// checked bound prevents a changed internal caller from panicking or
	// truncating a name; the conversion itself never replaces domain checks.
	if filename.len() != buffer.len() - 1 {
		bail!("invalid private metadata component");
	}
	buffer[..filename.len()].copy_from_slice(filename.as_bytes());
	buffer[filename.len()] = 0;
	std::ffi::CStr::from_bytes_with_nul(buffer)
		.map_err(|_| anyhow!("invalid private metadata component"))
}

type Identity = [u64; 2];
type RegistryKey = [u64; 4];
static STORES: OnceLock<Mutex<HashMap<RegistryKey, Weak<Inner>>>> = OnceLock::new();

#[derive(Clone)]
pub(super) struct Archive(Arc<Inner>);

struct Inner {
	root: Arc<File>,
	legacy: Arc<File>,
	legacy_anchor: PinnedAnchor,
	root_identity: Identity,
	legacy_identity: Identity,
	// Existing tickets and index slots observe activation of the same directory
	// set. A legacy-only epoch can never silently certify newly introduced shards.
	layout: OnceLock<Layout>,
}

struct Layout {
	root: Arc<File>,
	shards: Vec<Arc<File>>,
	anchor: ShardAnchor,
	anchor_stamp: [u64; 10],
	watch: Option<super::super::namespace_version::ContentWatchSet>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ShardAnchor {
	format: u32,
	root: Identity,
	legacy: Identity,
	archive: Identity,
	// Entry i binds the directory named as the two lowercase hex digits of i.
	shards: Vec<Identity>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InitIntent {
	format: u32,
	root: Identity,
	legacy: Identity,
	archive: Option<Identity>,
	shards: Vec<Identity>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InitStep {
	Intent,
	RootCreated,
	RootBound,
	ShardCreated(usize),
	ShardBound(usize),
	Anchor,
	IntentRemoved,
}

fn identity(metadata: &std::fs::Metadata) -> Identity {
	[metadata.dev(), metadata.ino()]
}

fn file_stamp(metadata: &std::fs::Metadata) -> [u64; 10] {
	[
		metadata.dev(),
		metadata.ino(),
		metadata.len(),
		metadata.mode() as u64,
		metadata.uid() as u64,
		metadata.nlink(),
		metadata.mtime() as u64,
		metadata.mtime_nsec() as u64,
		metadata.ctime() as u64,
		metadata.ctime_nsec() as u64,
	]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AnchorStamp {
	device: u64,
	inode: u64,
	mode: u32,
	uid: u32,
	gid: u32,
	links: u64,
	length: u64,
	modified: (i64, i64),
	changed: (i64, i64),
}

impl AnchorStamp {
	fn held(file: &File) -> Result<Self> {
		let value = file.metadata()?;
		Ok(Self {
			device: value.dev(),
			inode: value.ino(),
			mode: value.mode(),
			uid: value.uid(),
			gid: value.gid(),
			links: value.nlink(),
			length: value.len(),
			modified: (value.mtime(), value.mtime_nsec()),
			changed: (value.ctime(), value.ctime_nsec()),
		})
	}

	#[cfg(any(target_os = "linux", target_os = "macos"))]
	#[allow(clippy::unnecessary_cast)] // libc inode/device widths vary across Unix.
	fn named(root: &File, component: &std::ffi::CStr) -> Result<Self> {
		let value = named_stat_with_component(root, component)?
			.ok_or_else(|| anyhow!("request archive legacy anchor disappeared"))?;
		if value.st_size < 0 {
			bail!("request archive legacy anchor size refused");
		}
		Ok(Self {
			device: value.st_dev as u64,
			inode: value.st_ino as u64,
			mode: value.st_mode as u32,
			uid: value.st_uid,
			gid: value.st_gid,
			links: value.st_nlink as u64,
			length: value.st_size as u64,
			modified: (value.st_mtime, value.st_mtime_nsec),
			changed: (value.st_ctime, value.st_ctime_nsec),
		})
	}

	#[cfg(not(any(target_os = "linux", target_os = "macos")))]
	fn named(root: &File, _component: &std::ffi::CStr) -> Result<Self> {
		// Retain full subsecond metadata on other Unix targets without assuming
		// the platform-specific layout of libc::stat's timestamp fields.
		Self::held(&open_at(
			root,
			ARCHIVE_ANCHOR,
			libc::O_RDONLY | libc::O_NONBLOCK,
			0,
		)?)
	}

	#[allow(clippy::unnecessary_cast)] // libc mode widths vary across Unix.
	fn validate(self) -> Result<()> {
		if self.mode & libc::S_IFMT as u32 != libc::S_IFREG as u32
			|| self.mode & 0o7777 != 0o600
			|| self.uid != unsafe { libc::geteuid() }
			|| self.links != 1
			|| self.length > MAX_RECORD_BYTES as u64
		{
			bail!("private request archive legacy anchor refused");
		}
		Ok(())
	}
}

/// An anchor is application-immutable, but its owner can still write mode 0600.
/// Keep the original bytes as well as the complete inode stamp: timestamps are
/// never a substitute for rereading every byte before a fence succeeds.
pub(super) struct PinnedAnchor {
	file: File,
	component: std::ffi::CString,
	record: ArchiveAnchor,
	bytes: Box<[u8]>,
	stamp: AnchorStamp,
}

impl PinnedAnchor {
	pub(super) fn open(root: &File) -> Result<Self> {
		let component = name(ARCHIVE_ANCHOR)?;
		let mut file = open_at(root, ARCHIVE_ANCHOR, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
		let stamp = AnchorStamp::held(&file)?;
		stamp.validate()?;
		if AnchorStamp::named(root, &component)? != stamp {
			bail!("request archive legacy anchor binding changed");
		}
		let mut bytes = Vec::new();
		Read::by_ref(&mut file)
			.take((MAX_RECORD_BYTES + 1) as u64)
			.read_to_end(&mut bytes)?;
		if bytes.len() > MAX_RECORD_BYTES
			|| bytes.len() as u64 != stamp.length
			|| AnchorStamp::held(&file)? != stamp
			|| AnchorStamp::named(root, &component)? != stamp
		{
			bail!("request archive legacy anchor changed while reading");
		}
		let record = serde_json::from_slice(&bytes)?;
		Ok(Self {
			file,
			component,
			record,
			bytes: bytes.into_boxed_slice(),
			stamp,
		})
	}

	pub(super) fn record(&self) -> &ArchiveAnchor {
		&self.record
	}

	fn fence(&self, root: &File) -> Result<()> {
		use std::os::unix::fs::FileExt;
		self.fence_with(root, |file, bytes| file.read_exact_at(bytes, 0))
	}

	fn fence_with(
		&self,
		root: &File,
		read: impl FnOnce(&File, &mut [u8]) -> std::io::Result<()>,
	) -> Result<()> {
		// Validate the pinned policy once against the current caller. Every
		// observed field below must equal this complete, validated stamp.
		self.stamp.validate()?;
		if AnchorStamp::held(&self.file)? != self.stamp
			|| AnchorStamp::named(root, &self.component)? != self.stamp
		{
			bail!("request archive legacy anchor binding changed");
		}
		// Preserve the existing legacy-anchor bound, including valid JSON padded
		// to that full size. Positional reads do not share or mutate an FD cursor.
		let mut bytes = [0_u8; MAX_RECORD_BYTES];
		let actual = &mut bytes[..self.bytes.len()];
		read(&self.file, actual)?;
		if actual != self.bytes.as_ref() {
			bail!("request archive legacy anchor bytes changed");
		}
		if AnchorStamp::held(&self.file)? != self.stamp
			|| AnchorStamp::named(root, &self.component)? != self.stamp
		{
			bail!("request archive legacy anchor changed while reading");
		}
		Ok(())
	}
}

fn missing(error: &anyhow::Error) -> bool {
	error
		.downcast_ref::<std::io::Error>()
		.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn named_stat(directory: &File, filename: &str) -> Result<Option<libc::stat>> {
	let component = name(filename)?;
	named_stat_with_component(directory, &component)
}

fn named_stat_with_component(
	directory: &File,
	component: &std::ffi::CStr,
) -> Result<Option<libc::stat>> {
	let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
	if unsafe {
		libc::fstatat(
			directory.as_raw_fd(),
			component.as_ptr(),
			metadata.as_mut_ptr(),
			libc::AT_SYMLINK_NOFOLLOW,
		)
	} == 0
	{
		return Ok(Some(unsafe { metadata.assume_init() }));
	}
	let error = std::io::Error::last_os_error();
	if error.kind() == std::io::ErrorKind::NotFound {
		Ok(None)
	} else {
		Err(error.into())
	}
}

fn named_directory(directory: &File, filename: &str, held: &File) -> Result<()> {
	let component = name(filename)?;
	named_directory_component(directory, &component, held)
}

fn named_directory_component(
	directory: &File,
	component: &std::ffi::CStr,
	held: &File,
) -> Result<()> {
	let named = named_stat_with_component(directory, component)?
		.ok_or_else(|| anyhow!("request archive directory disappeared"))?;
	let pinned = private_directory_metadata(held)?;
	if named.st_mode & libc::S_IFMT != libc::S_IFDIR
		|| named.st_uid != unsafe { libc::geteuid() }
		|| named.st_mode & 0o7777 != 0o700
		|| (named.st_dev as u64, named.st_ino as u64) != (pinned.dev(), pinned.ino())
	{
		bail!("request archive directory binding changed");
	}
	Ok(())
}

fn shard_component_bytes(prefix: &str) -> Result<[u8; 3]> {
	let pair: [u8; 2] = prefix
		.as_bytes()
		.try_into()
		.map_err(|_| anyhow!("invalid private metadata component"))?;
	Ok([pair[0], pair[1], 0])
}

fn named_shard_directory(directory: &File, prefix: &str, held: &File) -> Result<()> {
	// Both callers retain their original full filename validation. This only
	// changes storage for that same two-byte prefix, never its namespace probe.
	let bytes = shard_component_bytes(prefix)?;
	let component = std::ffi::CStr::from_bytes_with_nul(&bytes)
		.map_err(|_| anyhow!("invalid private metadata component"))?;
	named_directory_component(directory, component, held)
}

fn filename_id(filename: &str) -> Result<&str> {
	filename
		.strip_suffix(".json")
		.filter(|id| valid_id(id))
		.ok_or_else(|| anyhow!("invalid request archive filename"))
}

fn entry_id(filename: &str) -> Result<&str> {
	if !filename.starts_with('.') {
		return filename_id(filename);
	}
	let (id, nonce) = filename
		.strip_prefix('.')
		.and_then(|value| value.strip_suffix(".tmp"))
		.and_then(|value| value.split_once('-'))
		.ok_or_else(|| anyhow!("unexpected request archive staging entry"))?;
	if !valid_id(id) || !valid_id(nonce) {
		bail!("invalid request archive staging identity");
	}
	Ok(id)
}

fn shard_index(id: &str) -> usize {
	fn digit(byte: u8) -> usize {
		if byte <= b'9' {
			(byte - b'0') as usize
		} else {
			(byte - b'a' + 10) as usize
		}
	}
	digit(id.as_bytes()[0]) * 16 + digit(id.as_bytes()[1])
}

fn recover_metadata_link(root: &File, file: &File, prefix: &str) -> Result<()> {
	let metadata = file.metadata()?;
	if metadata.nlink() != 2 {
		return Ok(());
	}
	if !metadata.is_file()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o600
		|| metadata.len() > MAX_ANCHOR_BYTES as u64
	{
		bail!("request archive initialization metadata refused");
	}
	let mut recovered = false;
	walk_directory(root, |entry| {
		let Some(nonce) = entry
			.strip_prefix(prefix)
			.and_then(|value| value.strip_suffix(".tmp"))
		else {
			return Ok(());
		};
		if !valid_id(nonce) {
			return Ok(());
		}
		let candidate = open_at(root, entry, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
		let candidate = candidate.metadata()?;
		if identity(&candidate) != identity(&metadata) {
			return Ok(());
		}
		if recovered || candidate.nlink() != 2 {
			bail!("request archive initialization hard-link binding refused");
		}
		let component = name(entry)?;
		if unsafe { libc::unlinkat(root.as_raw_fd(), component.as_ptr(), 0) } < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		recovered = true;
		Ok(())
	})?;
	if !recovered {
		bail!("request archive initialization hard-link binding refused");
	}
	root.sync_all()?;
	Ok(())
}

fn read_intent(root: &File) -> Result<Option<InitIntent>> {
	let mut file = match open_at(root, SHARD_INTENT, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
		Ok(file) => file,
		Err(error) if missing(&error) => return Ok(None),
		Err(error) => return Err(error),
	};
	let metadata = file.metadata()?;
	if !metadata.is_file()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o600
		|| !(1..=2).contains(&metadata.nlink())
		|| metadata.len() > MAX_ANCHOR_BYTES as u64
	{
		bail!("request archive initialization intent refused");
	}
	let mut bytes = Vec::new();
	Read::by_ref(&mut file)
		.take((MAX_ANCHOR_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_ANCHOR_BYTES || file_stamp(&file.metadata()?) != file_stamp(&metadata) {
		bail!("request archive initialization intent changed");
	}
	let intent: InitIntent = serde_json::from_slice(&bytes)?;
	let legacy = read_archive_anchor(root)?;
	if intent.format != 12
		|| intent.root != identity(&root.metadata()?)
		|| intent.root != [legacy.root_device, legacy.root_inode]
		|| intent.legacy != [legacy.archive_device, legacy.archive_inode]
		|| intent.shards.len() > SHARDS
		|| (intent.archive.is_none() && !intent.shards.is_empty())
	{
		bail!("request archive initialization intent binding changed");
	}
	// Only complete, valid, root-bound metadata may recover a known temporary
	// alias left between create-only link publication and unlink.
	recover_metadata_link(root, &file, ".archive-v12-init-")?;
	if file.metadata()?.nlink() != 1 {
		bail!("request archive initialization intent link count changed");
	}
	Ok(Some(intent))
}

fn persist_intent(root: &File, intent: &InitIntent, initial: bool) -> Result<()> {
	if !initial {
		let old = read_intent(root)?
			.ok_or_else(|| anyhow!("request archive initialization intent disappeared"))?;
		if old.format != 12
			|| old.root != intent.root
			|| old.legacy != intent.legacy
			|| old
				.archive
				.is_some_and(|value| Some(value) != intent.archive)
			|| old.shards.len() > intent.shards.len()
			|| intent.shards.len() > old.shards.len() + 1
			|| intent.shards[..old.shards.len()] != old.shards
		{
			bail!("request archive initialization intent binding changed");
		}
	}
	let temporary = format!(".archive-v12-init-{}.tmp", new_id()?);
	let source = name(&temporary)?;
	let target = name(SHARD_INTENT)?;
	let mut file = open_at(
		root,
		&temporary,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	let result = (|| -> Result<()> {
		let bytes = serde_json::to_vec(intent)?;
		if bytes.len() > MAX_ANCHOR_BYTES {
			bail!("request archive initialization intent size refused");
		}
		file.write_all(&bytes)?;
		file.sync_all()?;
		if initial {
			if unsafe {
				libc::linkat(
					root.as_raw_fd(),
					source.as_ptr(),
					root.as_raw_fd(),
					target.as_ptr(),
					0,
				)
			} < 0
			{
				return Err(std::io::Error::last_os_error().into());
			}
			if unsafe { libc::unlinkat(root.as_raw_fd(), source.as_ptr(), 0) } < 0 {
				return Err(std::io::Error::last_os_error().into());
			}
		} else if unsafe {
			libc::renameat(
				root.as_raw_fd(),
				source.as_ptr(),
				root.as_raw_fd(),
				target.as_ptr(),
			)
		} < 0
		{
			return Err(std::io::Error::last_os_error().into());
		}
		root.sync_all()?;
		Ok(())
	})();
	if result.is_err() {
		unsafe { libc::unlinkat(root.as_raw_fd(), source.as_ptr(), 0) };
	}
	result
}

fn require_empty(directory: &File) -> Result<()> {
	walk_directory(directory, |_| {
		bail!("request archive initialization encountered unexpected data")
	})
}

fn read_anchor(root: &File) -> Result<(ShardAnchor, [u64; 10])> {
	let mut file = open_at(root, SHARD_ANCHOR, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	let metadata = file.metadata()?;
	if !metadata.is_file()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o600
		|| !(1..=2).contains(&metadata.nlink())
		|| metadata.len() > MAX_ANCHOR_BYTES as u64
	{
		bail!("request archive layout anchor refused");
	}
	let mut bytes = Vec::new();
	Read::by_ref(&mut file)
		.take((MAX_ANCHOR_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_ANCHOR_BYTES || file_stamp(&file.metadata()?) != file_stamp(&metadata) {
		bail!("request archive layout anchor changed");
	}
	let anchor: ShardAnchor = serde_json::from_slice(&bytes)?;
	let legacy = read_archive_anchor(root)?;
	if anchor.format != 12
		|| anchor.root != identity(&root.metadata()?)
		|| anchor.root != [legacy.root_device, legacy.root_inode]
		|| anchor.legacy != [legacy.archive_device, legacy.archive_inode]
		|| anchor.shards.len() != SHARDS
	{
		bail!("request archive layout anchor binding changed");
	}
	recover_metadata_link(root, &file, ".archive-v12-anchor-")?;
	let metadata = file.metadata()?;
	if metadata.nlink() != 1 {
		bail!("request archive layout anchor link count changed");
	}
	Ok((anchor, file_stamp(&metadata)))
}

fn publish_anchor(root: &File, anchor: &ShardAnchor) -> Result<()> {
	let temporary = format!(".archive-v12-anchor-{}.tmp", new_id()?);
	let mut file = open_at(
		root,
		&temporary,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	let source = name(&temporary)?;
	let target = name(SHARD_ANCHOR)?;
	let result = (|| -> Result<()> {
		let bytes = serde_json::to_vec(anchor)?;
		if bytes.len() > MAX_ANCHOR_BYTES {
			bail!("request archive layout anchor size refused");
		}
		file.write_all(&bytes)?;
		file.sync_all()?;
		if unsafe {
			libc::linkat(
				root.as_raw_fd(),
				source.as_ptr(),
				root.as_raw_fd(),
				target.as_ptr(),
				0,
			)
		} < 0
		{
			return Err(std::io::Error::last_os_error().into());
		}
		if unsafe { libc::unlinkat(root.as_raw_fd(), source.as_ptr(), 0) } < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		root.sync_all()?;
		Ok(())
	})();
	if result.is_err() {
		unsafe { libc::unlinkat(root.as_raw_fd(), source.as_ptr(), 0) };
	}
	result
}

impl Archive {
	/// The caller holds STORE_LOCK. The registry owns no descriptors or history;
	/// only live tickets and the bounded index retain the immutable directory set.
	pub(super) fn open(root: &File, legacy: File, legacy_anchor: PinnedAnchor) -> Result<Self> {
		let root_identity = identity(&private_directory_metadata(root)?);
		let legacy_identity = identity(&private_directory_metadata(&legacy)?);
		let key = [
			root_identity[0],
			root_identity[1],
			legacy_identity[0],
			legacy_identity[1],
		];
		let mut registry = STORES
			.get_or_init(|| Mutex::new(HashMap::new()))
			.lock()
			.map_err(|_| anyhow!("request archive directory registry unavailable"))?;
		registry.retain(|_, value| value.strong_count() != 0);
		let archive = if let Some(inner) = registry.get(&key).and_then(Weak::upgrade) {
			Self(inner)
		} else {
			let inner = Arc::new(Inner {
				root: Arc::new(root.try_clone()?),
				legacy: Arc::new(legacy),
				legacy_anchor,
				root_identity,
				legacy_identity,
				layout: OnceLock::new(),
			});
			registry.insert(key, Arc::downgrade(&inner));
			Self(inner)
		};
		archive.load_layout()?;
		if archive.0.layout.get().is_none()
			&& archive.0.legacy.metadata()?.len() >= FLAT_DIRECTORY_LIMIT
		{
			archive.initialize_shards()?;
		}
		archive.fence_at(root)?;
		Ok(archive)
	}

	pub(super) fn legacy(&self) -> &File {
		&self.0.legacy
	}
	pub(super) fn root(&self) -> &File {
		&self.0.root
	}
	#[cfg(test)]
	pub(super) fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
		self.0.legacy.metadata()
	}
	pub(super) fn try_clone(&self) -> Result<Self> {
		Ok(self.clone())
	}

	// A shared reader must never perform the recovery/initialization done by
	// open(). Inspect only presence and the original size boundary; leave all
	// control parsing, alias recovery and shard creation to that exclusive path.
	pub(super) fn needs_exclusive_open(&self) -> Result<bool> {
		if self.0.layout.get().is_some() {
			return Ok(false);
		}
		if named_stat(self.root(), SHARD_ANCHOR)?.is_some()
			|| named_stat(self.root(), SHARD_ROOT)?.is_some()
			|| named_stat(self.root(), SHARD_INTENT)?.is_some()
		{
			return Ok(true);
		}
		Ok(self.legacy().metadata()?.len() >= FLAT_DIRECTORY_LIMIT)
	}

	fn load_layout(&self) -> Result<()> {
		if self.0.layout.get().is_some() {
			return Ok(());
		}
		let (anchor, anchor_stamp) = match read_anchor(self.root()) {
			Ok(value) => value,
			Err(error) if missing(&error) => {
				if let Some(intent) = read_intent(self.root())? {
					self.resume_initialization(intent, &mut |_| Ok(()))?;
					return self.load_layout();
				}
				if named_stat(self.root(), SHARD_ROOT)?.is_some() {
					bail!("unanchored request archive shards refused; history never rebound automatically");
				}
				return Ok(());
			}
			Err(error) => return Err(error),
		};
		if anchor.format != 12
			|| anchor.root != self.0.root_identity
			|| anchor.legacy != self.0.legacy_identity
			|| anchor.shards.len() != SHARDS
		{
			bail!("request archive layout binding changed");
		}
		let root = Arc::new(open_at(
			self.root(),
			SHARD_ROOT,
			libc::O_RDONLY | libc::O_DIRECTORY,
			0,
		)?);
		if identity(&private_directory_metadata(&root)?) != anchor.archive {
			bail!("request archive shard root identity changed");
		}
		let mut shards = Vec::with_capacity(SHARDS);
		for index in 0..SHARDS {
			let shard = Arc::new(open_at(
				&root,
				&format!("{index:02x}"),
				libc::O_RDONLY | libc::O_DIRECTORY,
				0,
			)?);
			if identity(&private_directory_metadata(&shard)?) != anchor.shards[index] {
				bail!("request archive shard identity changed");
			}
			shards.push(shard);
		}
		let mut watched = Vec::with_capacity(SHARDS + 2);
		watched.push(self.0.legacy.clone());
		watched.push(root.clone());
		watched.extend(shards.iter().cloned());
		let watch = super::super::namespace_version::ContentWatchSet::new(&watched)?;
		let layout = Layout {
			root,
			shards,
			anchor,
			anchor_stamp,
			watch,
		};
		self.validate_layout(&layout, true)?;
		self.finish_intent(&layout.anchor)?;
		self.0
			.layout
			.set(layout)
			.map_err(|_| anyhow!("request archive layout initialized concurrently"))?;
		Ok(())
	}

	/// Used by the directory-size transition and by mixed-layout tests. There is
	/// no record-count quota and no ENOSPC retry or relocation of legacy originals.
	pub(super) fn initialize_shards(&self) -> Result<()> {
		self.initialize_with(&mut |_| Ok(()))
	}

	fn initialize_with(&self, checkpoint: &mut impl FnMut(InitStep) -> Result<()>) -> Result<()> {
		if self.0.layout.get().is_some() {
			return self.fence_at(self.root());
		}
		if let Some(intent) = read_intent(self.root())? {
			self.resume_initialization(intent, checkpoint)?;
			return self.load_layout();
		}
		self.fence_at(self.root())?;
		let intent = InitIntent {
			format: 12,
			root: self.0.root_identity,
			legacy: self.0.legacy_identity,
			archive: None,
			shards: Vec::new(),
		};
		persist_intent(self.root(), &intent, true)?;
		checkpoint(InitStep::Intent)?;
		self.resume_initialization(intent, checkpoint)?;
		self.load_layout()
	}

	fn resume_initialization(
		&self,
		mut intent: InitIntent,
		checkpoint: &mut impl FnMut(InitStep) -> Result<()>,
	) -> Result<()> {
		self.fence_legacy_at(self.root())?;
		if intent.format != 12
			|| intent.root != self.0.root_identity
			|| intent.legacy != self.0.legacy_identity
			|| intent.shards.len() > SHARDS
			|| (intent.archive.is_none() && !intent.shards.is_empty())
		{
			bail!("request archive initialization intent binding changed");
		}
		if intent.archive.is_none() && named_stat(self.root(), SHARD_ROOT)?.is_none() {
			let component = name(SHARD_ROOT)?;
			if unsafe { libc::mkdirat(self.root().as_raw_fd(), component.as_ptr(), 0o700) } < 0 {
				return Err(std::io::Error::last_os_error().into());
			}
			self.root().sync_all()?;
		}
		let root = open_at(
			self.root(),
			SHARD_ROOT,
			libc::O_RDONLY | libc::O_DIRECTORY,
			0,
		)?;
		let archive_identity = identity(&private_directory_metadata(&root)?);
		if let Some(expected) = intent.archive {
			if archive_identity != expected {
				bail!("request archive initialization root identity changed");
			}
		} else {
			require_empty(&root)?;
			checkpoint(InitStep::RootCreated)?;
			intent.archive = Some(archive_identity);
			persist_intent(self.root(), &intent, false)?;
			checkpoint(InitStep::RootBound)?;
		}
		// A crash may leave exactly the next newly-created empty directory before
		// its inode enters the intent. Any other entry or payload refuses recovery.
		let mut seen = [false; SHARDS];
		walk_directory(&root, |entry| {
			if entry.len() != 2
				|| !entry
					.bytes()
					.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
			{
				bail!("unexpected request archive initialization entry");
			}
			let index = shard_index(entry);
			if index > intent.shards.len() || seen[index] {
				bail!("unrecorded request archive initialization directory");
			}
			seen[index] = true;
			let shard = open_at(&root, entry, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			let found = identity(&private_directory_metadata(&shard)?);
			if index < intent.shards.len() && found != intent.shards[index] {
				bail!("request archive initialization shard identity changed");
			}
			require_empty(&shard)
		})?;
		if seen[..intent.shards.len()].iter().any(|value| !value) {
			bail!("recorded request archive initialization directory disappeared");
		}
		for (index, present) in seen.iter().enumerate().skip(intent.shards.len()) {
			let component = format!("{index:02x}");
			if !*present {
				let name = name(&component)?;
				if unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
					return Err(std::io::Error::last_os_error().into());
				}
			}
			let shard = open_at(&root, &component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			let found = identity(&private_directory_metadata(&shard)?);
			require_empty(&shard)?;
			shard.sync_all()?;
			root.sync_all()?;
			checkpoint(InitStep::ShardCreated(index))?;
			intent.shards.push(found);
			persist_intent(self.root(), &intent, false)?;
			checkpoint(InitStep::ShardBound(index))?;
		}
		root.sync_all()?;
		self.root().sync_all()?;
		self.fence_legacy_at(self.root())?;
		let mut complete = [false; SHARDS];
		walk_directory(&root, |entry| {
			if entry.len() != 2
				|| !entry
					.bytes()
					.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
			{
				bail!("unexpected request archive initialization entry");
			}
			let index = shard_index(entry);
			if complete[index] {
				bail!("duplicate request archive initialization directory");
			}
			complete[index] = true;
			let shard = open_at(&root, entry, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			if identity(&private_directory_metadata(&shard)?) != intent.shards[index] {
				bail!("request archive initialization shard binding changed");
			}
			require_empty(&shard)
		})?;
		if complete.iter().any(|value| !value) {
			bail!("request archive initialization directory missing");
		}
		let anchor = ShardAnchor {
			format: 12,
			root: self.0.root_identity,
			legacy: self.0.legacy_identity,
			archive: archive_identity,
			shards: intent.shards,
		};
		publish_anchor(self.root(), &anchor)?;
		checkpoint(InitStep::Anchor)?;
		self.finish_intent(&anchor)?;
		checkpoint(InitStep::IntentRemoved)
	}

	fn finish_intent(&self, anchor: &ShardAnchor) -> Result<()> {
		let Some(intent) = read_intent(self.root())? else {
			return Ok(());
		};
		if intent.format != 12
			|| intent.root != anchor.root
			|| intent.legacy != anchor.legacy
			|| intent.archive != Some(anchor.archive)
			|| intent.shards != anchor.shards
		{
			bail!("request archive completed initialization binding changed");
		}
		let component = name(SHARD_INTENT)?;
		if unsafe { libc::unlinkat(self.root().as_raw_fd(), component.as_ptr(), 0) } < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		self.root().sync_all()?;
		Ok(())
	}

	fn validate_layout(&self, layout: &Layout, full: bool) -> Result<()> {
		named_directory(self.root(), SHARD_ROOT, &layout.root)?;
		let file = open_at(
			self.root(),
			SHARD_ANCHOR,
			libc::O_RDONLY | libc::O_NONBLOCK,
			0,
		)?;
		if file_stamp(&file.metadata()?) != layout.anchor_stamp {
			bail!("request archive layout anchor changed");
		}
		if full {
			let mut seen = [false; SHARDS];
			walk_directory(&layout.root, |entry| {
				if entry.len() != 2
					|| !entry
						.bytes()
						.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
				{
					bail!("unexpected request archive shard namespace entry");
				}
				let index = shard_index(entry);
				if seen[index] {
					bail!("duplicate request archive shard directory");
				}
				seen[index] = true;
				named_directory(&layout.root, entry, &layout.shards[index])?;
				if identity(&layout.shards[index].metadata()?) != layout.anchor.shards[index] {
					bail!("request archive shard binding changed");
				}
				Ok(())
			})?;
			if seen.iter().any(|value| !value) {
				bail!("request archive shard directory missing");
			}
		}
		Ok(())
	}

	fn fence_legacy_at(&self, root: &File) -> Result<()> {
		if identity(&private_directory_metadata(root)?) != self.0.root_identity {
			bail!("request archive root binding changed");
		}
		self.0.legacy_anchor.fence(root)?;
		let anchor = self.0.legacy_anchor.record();
		if [anchor.root_device, anchor.root_inode] != self.0.root_identity
			|| [anchor.archive_device, anchor.archive_inode] != self.0.legacy_identity
		{
			bail!("request archive legacy anchor binding changed");
		}
		named_directory(root, ARCHIVE_NAME, self.legacy())?;
		Ok(())
	}

	pub(super) fn fence_at(&self, root: &File) -> Result<()> {
		self.fence_legacy_at(root)?;
		if let Some(layout) = self.0.layout.get() {
			self.validate_layout(layout, false)?;
			if named_stat(root, SHARD_INTENT)?.is_some() {
				bail!("request archive initialization intent reappeared");
			}
		} else if named_stat(root, SHARD_ANCHOR)?.is_some()
			|| named_stat(root, SHARD_ROOT)?.is_some()
			|| named_stat(root, SHARD_INTENT)?.is_some()
		{
			// An external process introducing the layout cannot inherit this old
			// process's flat-only epoch. A subsequent open loads the complete set.
			bail!("request archive layout changed before directory set validation");
		}
		Ok(())
	}

	pub(super) fn content_version(
		&self,
	) -> Result<Option<super::super::namespace_version::Version>> {
		self.fence_at(self.root())?;
		if let Some(layout) = self.0.layout.get() {
			match &layout.watch {
				Some(watch) => watch.version(),
				None => Ok(None),
			}
		} else {
			super::super::namespace_version::content_version(self.legacy())
		}
	}

	fn shard_for(&self, id: &str) -> Result<Option<&File>> {
		let Some(layout) = self.0.layout.get() else {
			return Ok(None);
		};
		let index = shard_index(id);
		let shard = &layout.shards[index];
		named_shard_directory(&layout.root, &id[..2], shard)?;
		Ok(Some(shard))
	}

	pub(super) fn existing_directory(&self, filename: &str) -> Result<Option<&File>> {
		let id = filename_id(filename)?;
		let component = name(filename)?;
		self.existing_directory_component(id, &component)
	}

	// Callers bind id and component to one validated filename before lookup.
	// Keep the pair private so another module cannot mix two physical names.
	fn existing_directory_component(
		&self,
		id: &str,
		component: &std::ffi::CStr,
	) -> Result<Option<&File>> {
		Ok(self
			.existing_member_component(id, component)?
			.map(|(directory, _)| directory))
	}

	// Preserve the exact fresh legacy/shard probes, including both physical
	// copies of a duplicate. The selected stat may also establish a content
	// reader's full named-member stamp; it never comes from a prior observation.
	fn existing_member_component(
		&self,
		id: &str,
		component: &std::ffi::CStr,
	) -> Result<Option<(&File, libc::stat)>> {
		let legacy = named_stat_with_component(self.legacy(), component)?;
		let shard = self.shard_for(id)?;
		let sharded = match shard {
			Some(directory) => named_stat_with_component(directory, component)?,
			None => None,
		};
		match (legacy, sharded) {
			(Some(_), Some(_)) => bail!("duplicate request archive identity across namespaces"),
			(Some(metadata), None) => Ok(Some((self.legacy(), metadata))),
			(None, Some(metadata)) => Ok(shard.map(|directory| (directory, metadata))),
			(None, None) => Ok(None),
		}
	}

	pub(super) fn directory_for_existing(&self, filename: &str) -> Result<&File> {
		self.existing_directory(filename)?
			.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound).into())
	}

	pub(super) fn directory_for_write(&self, filename: &str, replacing: bool) -> Result<&File> {
		let id = filename_id(filename)?;
		match (self.existing_directory(filename)?, replacing) {
			(Some(directory), true) => Ok(directory),
			(Some(_), false) => Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into()),
			(None, true) => Err(std::io::Error::from(std::io::ErrorKind::NotFound).into()),
			(None, false) => Ok(self.shard_for(id)?.unwrap_or_else(|| self.legacy())),
		}
	}

	pub(super) fn fence_target(&self, directory: &File) -> Result<()> {
		if directory.as_raw_fd() == self.legacy().as_raw_fd() {
			return named_directory(self.root(), ARCHIVE_NAME, directory);
		}
		let layout = self
			.0
			.layout
			.get()
			.ok_or_else(|| anyhow!("request archive target unavailable"))?;
		let index = layout
			.shards
			.iter()
			.position(|value| value.as_raw_fd() == directory.as_raw_fd())
			.ok_or_else(|| anyhow!("foreign request archive target directory"))?;
		named_directory(&layout.root, &format!("{index:02x}"), directory)
	}

	pub(super) fn fence_record(&self, filename: &str, directory: &File) -> Result<()> {
		let id = filename_id(filename)?;
		let component = name(filename)?;
		self.fence_record_named(id, &component, directory)
			.map(|_| ())
	}

	#[cfg(test)]
	pub(super) fn fence_record_component(
		&self,
		component: &std::ffi::CStr,
		directory: &File,
	) -> Result<()> {
		self.fence_record_stat_component(component, directory)
			.map(|_| ())
	}

	/// One fresh namespace observation also returns its selected named inode.
	/// The caller must validate the full private-file policy and bind the read
	/// descriptor to this stamp; success here alone does not certify its contents.
	pub(super) fn fence_record_stat_component(
		&self,
		component: &std::ffi::CStr,
		directory: &File,
	) -> Result<libc::stat> {
		let filename = component
			.to_str()
			.map_err(|_| anyhow!("invalid request archive filename"))?;
		let id = filename_id(filename)?;
		self.fence_record_named(id, component, directory)
	}

	fn fence_record_named(
		&self,
		id: &str,
		component: &std::ffi::CStr,
		directory: &File,
	) -> Result<libc::stat> {
		let (existing, metadata) = self
			.existing_member_component(id, component)?
			.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
		if existing.as_raw_fd() != directory.as_raw_fd() {
			bail!("request archive record changed physical namespace");
		}
		if directory.as_raw_fd() == self.legacy().as_raw_fd() {
			named_directory_component(self.root(), LEGACY_COMPONENT, directory)?;
			return Ok(metadata);
		}
		let layout = self
			.0
			.layout
			.get()
			.ok_or_else(|| anyhow!("request archive target unavailable"))?;
		// The successful lookup already validated the lowercase hex filename and
		// selected this held shard. Keep the exact FD and final named-directory
		// checks without searching the immutable shard vector a second time.
		let prefix = &id[..2];
		if layout.shards[shard_index(prefix)].as_raw_fd() != directory.as_raw_fd() {
			bail!("foreign request archive target directory");
		}
		named_shard_directory(&layout.root, prefix, directory)?;
		Ok(metadata)
	}

	pub(super) fn read_record(&self, filename: &str) -> Result<Record> {
		self.fence_at(self.root())?;
		let directory = self.directory_for_existing(filename)?;
		let record = super::read_record(directory, filename)?;
		self.fence_record(filename, directory)?;
		self.fence_at(self.root())?;
		Ok(record)
	}

	pub(super) fn walk<'a>(
		&'a self,
		mut visit: impl FnMut(&'a File, &str, u64) -> Result<()>,
	) -> Result<()> {
		self.walk_members(
			&mut (),
			|_, directory, filename, inode| visit(directory, filename, inode),
			|_| Ok(()),
			true,
		)
	}

	/// A strict reader with bounded child work must finish and join that work
	/// before the original complete terminal layout fence, including flat stores.
	pub(super) fn walk_with_finish<'a, S>(
		&'a self,
		state: &mut S,
		visit: impl FnMut(&mut S, &'a File, &str, u64) -> Result<()>,
		finish: impl FnOnce(&mut S) -> Result<()>,
	) -> Result<()> {
		self.walk_members(state, visit, finish, true)
	}

	/// Only complete cold observations may defer cross-namespace duplicates to
	/// their mandatory strict full-identity merge. Each physical member is still
	/// emitted, with its pinned directory, after the same name/shard checks and
	/// complete before/after layout fences. This is not a logical-namespace proof:
	/// callers must finish the exact merge and epoch check before publishing.
	pub(super) fn walk_for_complete_identity_join<'a>(
		&'a self,
		mut visit: impl FnMut(&'a File, &str, u64) -> Result<()>,
	) -> Result<()> {
		self.walk_members(
			&mut (),
			|_, directory, filename, inode| visit(directory, filename, inode),
			|_| Ok(()),
			false,
		)
	}

	fn walk_members<'a, S>(
		&'a self,
		state: &mut S,
		mut visit: impl FnMut(&mut S, &'a File, &str, u64) -> Result<()>,
		finish: impl FnOnce(&mut S) -> Result<()>,
		check_legacy_duplicates: bool,
	) -> Result<()> {
		self.fence_at(self.root())?;
		if let Some(layout) = self.0.layout.get() {
			self.validate_layout(layout, true)?;
		}
		walk_directory_with_inode(self.legacy(), |filename, inode| {
			entry_id(filename)?;
			visit(state, self.legacy(), filename, inode)
		})?;
		let layout = self.0.layout.get();
		if let Some(layout) = layout {
			for (index, shard) in layout.shards.iter().enumerate() {
				walk_directory_with_inode(shard, |filename, inode| {
					let id = entry_id(filename)?;
					if shard_index(id) != index {
						bail!("request archive identity is in the wrong shard");
					}
					if check_legacy_duplicates && !filename.starts_with('.') && {
						let mut bytes = [0u8; ORIGINAL_COMPONENT_BYTES];
						let component = stack_original_component(filename, &mut bytes)?;
						named_stat_with_component(self.legacy(), component)?.is_some()
					} {
						bail!("duplicate request archive identity across namespaces");
					}
					visit(state, shard, filename, inode)
				})?;
			}
		}
		finish(state)?;
		if let Some(layout) = layout {
			self.validate_layout(layout, true)?;
		}
		self.fence_at(self.root())
	}
}

#[cfg(test)]
#[path = "request_archive_store_tests.rs"]
mod tests;
