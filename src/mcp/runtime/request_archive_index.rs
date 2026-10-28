// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Disposable disk B-trees over original receipts. Only a bounded pending cohort
//! and page cache live in memory. Cache I/O never changes an admission outcome.
use super::*;
use redb::{
	Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
#[cfg(test)]
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::Condvar;
use std::time::Duration;

#[path = "request_archive_content.rs"]
mod content;

const CACHE_NAME: &str = ".request-archive-index-v2.redb";
const CACHE_BYTES: usize = 16 * 1024 * 1024;
// This bounds a transient write queue, never the number of retained records.
const MAX_PENDING: usize = 8192;
const BUILD_CHUNK: usize = 512;
// Decode complete disjoint receipt ranges alongside independent original checks.
const COLD_ROW_WORKERS: usize = 4;
// Queries request immediate catch-up. A half-full queue also drains without a
// reader; cache fsync waits for a quiet publication interval.
const FLUSH_WATERMARK: usize = MAX_PENDING / 2;
// Once rows exceed the page cache's approximate working set, random B-tree
// writes must start earlier and stay bounded. Small archives keep coalescing.
const LARGE_ARCHIVE_ROWS: u64 = (CACHE_BYTES / 1024) as u64;
const LARGE_FLUSH_WATERMARK: usize = 128;
const LARGE_WRITE_CHUNK: usize = 256;
const QUERY_WRITE_CHUNK: usize = 128;
const MAINTENANCE_INTERVAL: Duration = Duration::from_millis(500);
const IDLE_SYNC_QUIET: Duration = Duration::from_secs(5);
// Each complete large archive pins 258 directories. Keep active scopes within
// the usual 1024-descriptor process budget; this never limits retained records.
const MAX_INDEXES: usize = 2;
pub(super) const QUERY_BUDGET: Duration = Duration::from_secs(3);
const BUILD_BUDGET: Duration = Duration::from_secs(2400);
const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("receipts");
const IDS: TableDefinition<&[u8], u8> = TableDefinition::new("compact_identity_set");
const ORDER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("owner_time_id");
const COUNTS: TableDefinition<&[u8], u64> = TableDefinition::new("owner_state_tool_counts");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("binding");

// Opt-in, bounded diagnostic state only. Callers declare this before their
// existing guards, so even an early return drops those guards before logging.
// Phase changes only read clocks and update this stack-local accumulator.
#[derive(Clone, Copy)]
enum SteadyPhase {
	Other,
	ClaimPending,
	StoreLockWait,
	State,
	BeginWrite,
	UpdateRows,
	Commit,
	SizeRead,
	SnapshotRead,
	Seal,
}
struct SteadyClock {
	started: Instant,
	last: Instant,
	start_unix_ms: u128,
}
struct SteadyTrace {
	stage: &'static str,
	clock: Option<SteadyClock>,
	phase: SteadyPhase,
	phase_us: [u128; 10],
	rows: usize,
	durable: Option<bool>,
	outcome: &'static str,
}
impl SteadyTrace {
	fn new(stage: &'static str, durable: Option<bool>) -> Self {
		let clock = if std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref()
			== Some(std::ffi::OsStr::new("1"))
		{
			let started = Instant::now();
			Some(SteadyClock {
				started,
				last: started,
				start_unix_ms: SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.map_or(0, |value| value.as_millis()),
			})
		} else {
			None
		};
		Self {
			stage,
			clock,
			phase: SteadyPhase::Other,
			phase_us: [0; 10],
			rows: 0,
			durable,
			outcome: "error_or_unwind",
		}
	}
	fn enter(&mut self, phase: SteadyPhase) {
		if let Some(clock) = &mut self.clock {
			let now = Instant::now();
			self.phase_us[self.phase as usize] += now.duration_since(clock.last).as_micros();
			clock.last = now;
			self.phase = phase;
		}
	}
}
impl Drop for SteadyTrace {
	fn drop(&mut self) {
		self.enter(SteadyPhase::Other);
		let Some(clock) = &self.clock else { return };
		let elapsed = clock.last.duration_since(clock.started);
		if elapsed <= Duration::from_millis(100) {
			return;
		}
		let end_unix_ms = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_or(0, |value| value.as_millis());
		let durable = match self.durable {
			Some(true) => "true",
			Some(false) => "false",
			None => "na",
		};
		// Formatting is static and numeric; no identity, path or error text is
		// emitted. Diagnostic I/O failure must not become a product error.
		let _ = writeln!(std::io::stderr(),
			"archive_index steady_stage={} start_unix_ms={} end_unix_ms={} elapsed_us={} input_rows={} durable={} outcome={} claim_pending_us={} store_lock_wait_us={} state_us={} begin_write_us={} update_rows_us={} commit_us={} size_read_us={} snapshot_read_us={} seal_us={} other_us={}",
			self.stage, clock.start_unix_ms, end_unix_ms, elapsed.as_micros(),
			self.rows, durable, self.outcome,
			self.phase_us[SteadyPhase::ClaimPending as usize],
			self.phase_us[SteadyPhase::StoreLockWait as usize],
			self.phase_us[SteadyPhase::State as usize],
			self.phase_us[SteadyPhase::BeginWrite as usize],
			self.phase_us[SteadyPhase::UpdateRows as usize],
			self.phase_us[SteadyPhase::Commit as usize],
			self.phase_us[SteadyPhase::SizeRead as usize],
			self.phase_us[SteadyPhase::SnapshotRead as usize],
			self.phase_us[SteadyPhase::Seal as usize],
			self.phase_us[SteadyPhase::Other as usize]);
	}
}
// Obsolete experimental private tables are never read or maintained. The whole
// cache seal still covers their pages until a normal cache rebuild replaces them.
type Id = [u8; 32];
static INDEXES: OnceLock<Mutex<VecDeque<Arc<Slot>>>> = OnceLock::new();
#[path = "request_archive_codec.rs"]
mod codec;
#[path = "request_archive_cold.rs"]
mod cold;
#[path = "request_archive_seal.rs"]
mod seal;
use cold::{cold_rows, ScanPlan};

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileStamp {
	device: u64,
	inode: u64,
	mode: u32,
	uid: u32,
	links: u64,
	length: u64,
	modified: (i64, i64),
	changed: (i64, i64),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
	record: Record,
	stamp: FileStamp,
}

// This is only a per-slot maintenance hint. Original receipts, watch fences and
// the existing query deadline still decide every metadata response. In
// particular, no foreground query waits for a seal or a maintenance mutex.
struct MetadataActivity {
	origin: Instant,
	active: AtomicUsize,
	epoch: AtomicU64,
	last_finished_ns: AtomicU64,
}
impl Default for MetadataActivity {
	fn default() -> Self {
		Self {
			origin: Instant::now(),
			active: AtomicUsize::new(0),
			epoch: AtomicU64::new(0),
			last_finished_ns: AtomicU64::new(0),
		}
	}
}
impl MetadataActivity {
	fn timestamp(&self) -> u64 {
		// Zero means that this slot has not published or finished a read yet.
		(self
			.origin
			.elapsed()
			.as_nanos()
			.min(u128::from(u64::MAX - 1)) as u64)
			+ 1
	}
	fn touch(&self) {
		self.last_finished_ns
			.fetch_max(self.timestamp(), Ordering::SeqCst);
		self.epoch.fetch_add(1, Ordering::SeqCst);
	}
	fn enter(&self) -> MetadataRead<'_> {
		self.active.fetch_add(1, Ordering::SeqCst);
		self.epoch.fetch_add(1, Ordering::SeqCst);
		MetadataRead { activity: self }
	}
	fn quiet_epoch(&self) -> Option<u64> {
		let epoch = self.epoch.load(Ordering::SeqCst);
		if self.active.load(Ordering::SeqCst) != 0 {
			return None;
		}
		let finished = self.last_finished_ns.load(Ordering::SeqCst);
		if finished != 0
			&& u128::from(self.timestamp().saturating_sub(finished)) < IDLE_SYNC_QUIET.as_nanos()
		{
			return None;
		}
		if self.active.load(Ordering::SeqCst) != 0 || self.epoch.load(Ordering::SeqCst) != epoch {
			return None;
		}
		Some(epoch)
	}
}
struct MetadataRead<'a> {
	activity: &'a MetadataActivity,
}
impl Drop for MetadataRead<'_> {
	fn drop(&mut self) {
		// Publish the latest completion before the last reader becomes inactive.
		// Concurrent readers can never move the quiet timestamp backwards.
		self.activity.touch();
		self.activity.active.fetch_sub(1, Ordering::SeqCst);
	}
}

struct State {
	database: Option<Arc<Database>>,
	worker: bool,
	busy: bool,
	failed: bool,
	retired: bool,
	pending: BTreeMap<Id, Entry>,
	requested: bool,
	query_flushed: bool,
	large_archive: bool,
	last_publication: Instant,
	version: Option<super::super::namespace_version::Version>,
	generation: u64,
	applied: u64,
}
struct Slot {
	root: File,
	archive: Archive,
	identity: (u64, u64),
	metadata_activity: MetadataActivity,
	state: Mutex<State>,
	wake: Condvar,
	#[cfg(test)]
	parallel_hook: Mutex<Option<ParallelHook>>,
	#[cfg(test)]
	seal_hook: Mutex<Option<SealHook>>,
}

// An observed original/pending record may legally complete, but its stable
// identity and an already terminal outcome cannot change. Preserve this error
// across cold validation; treating it as an empty-cache rebuild would erase the
// very disagreement that the original comparison found.
#[derive(Debug)]
enum OriginalRecordConflict {
	Identity,
	Terminal,
}
impl std::fmt::Display for OriginalRecordConflict {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		out.write_str(match self {
			Self::Identity => "archive index identity changed",
			Self::Terminal => "archive index terminal changed",
		})
	}
}
impl std::error::Error for OriginalRecordConflict {}

#[derive(Debug)]
struct ColdEpochChanged;
impl std::fmt::Display for ColdEpochChanged {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		out.write_str("archive parallel validation epoch changed")
	}
}
impl std::error::Error for ColdEpochChanged {}

#[derive(Clone, Copy)]
struct ParallelEpoch {
	version: super::super::namespace_version::Version,
	generation: u64,
}
impl ParallelEpoch {
	fn capture(slot: &Slot) -> Result<Option<Self>> {
		#[cfg(not(target_os = "linux"))]
		{
			let _ = slot;
			Ok(None)
		}
		#[cfg(target_os = "linux")]
		{
			let _guard = store_lock()?;
			let state = slot
				.state
				.lock()
				.map_err(|_| anyhow!("archive index unavailable"))?;
			let current = content_version(&slot.archive)?;
			if state.failed || state.retired || state.version != current {
				return Ok(None);
			}
			Ok(match current {
				Some(version @ super::super::namespace_version::Version::Watch(..)) => {
					let epoch = Self {
						version,
						generation: state.generation,
					};
					epoch.trace("parallel_epoch_captured");
					Some(epoch)
				}
				_ => None,
			})
		}
	}
	fn check_locked(&self, slot: &Slot, state: &State) -> Result<()> {
		if state.failed
			|| state.retired
			|| state.generation != self.generation
			|| state.version != Some(self.version)
			|| content_version(&slot.archive).ok().flatten() != Some(self.version)
		{
			return Err(ColdEpochChanged.into());
		}
		Ok(())
	}
	fn check(&self, slot: &Slot) -> Result<()> {
		let _guard = store_lock()?;
		let state = slot
			.state
			.lock()
			.map_err(|_| anyhow!("archive index unavailable"))?;
		self.check_locked(slot, &state)
	}
	fn trace(&self, stage: &str) {
		#[cfg(not(target_os = "linux"))]
		let _ = stage;
		#[cfg(target_os = "linux")]
		if std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref()
			== Some(std::ffi::OsStr::new("1"))
		{
			if let super::super::namespace_version::Version::Watch(watch, generation) = self.version
			{
				let complete = stage == "parallel_epoch_publication_complete";
				eprintln!("archive_index cold_stage={stage} watch_id={watch} watch_generation={generation} publication_generation={} full_window={complete}", self.generation);
			}
		}
	}
}
struct ValidatedDatabase {
	database: Database,
	parallel_epoch: Option<ParallelEpoch>,
}
fn publication_result<T>(
	slot: &Slot,
	epoch: Option<&ParallelEpoch>,
	result: Result<T>,
) -> Result<T> {
	// A generic fold/apply error can observe a watch change before publication.
	match epoch {
		Some(epoch) => epoch.check(slot).and(result),
		None => result,
	}
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParallelEvent {
	TableStarted,
	ObservationStarted,
	TablesComplete,
	ObservationComplete,
	NamespaceStarted,
	NamespaceComplete,
	BeforeFold,
	BeforeJoin,
	BeforeMissingTailRepair,
	VerifiedOriginalCoverage,
	AfterCachedBeforeClaim,
	BeforePublish,
	BeforeSnapshotFence,
	SharedScanStarted,
	SharedScanComplete,
}
#[cfg(test)]
type ParallelHook = Arc<dyn Fn(ParallelEvent) + Send + Sync>;
#[cfg(test)]
fn parallel_event(slot: &Slot, event: ParallelEvent) {
	let hook = slot.parallel_hook.lock().unwrap().clone();
	if let Some(hook) = hook {
		hook(event);
	}
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SealEvent {
	Hashing,
	Hashed,
}
#[cfg(test)]
type SealHook = Arc<dyn Fn(SealEvent) + Send + Sync>;
#[cfg(test)]
fn seal_event(slot: &Slot, event: SealEvent) {
	let hook = slot.seal_hook.lock().unwrap().clone();
	if let Some(hook) = hook {
		hook(event);
	}
}

fn background_priority() {
	// Linux nice values are per-thread. Leave metadata/Tokio callers responsive
	// while bounded background hash/stat workers consume the CPU allowance.
	#[cfg(target_os = "linux")]
	unsafe {
		let _ = libc::setpriority(libc::PRIO_PROCESS, 0, 19);
	}
}

fn id(value: &str) -> Result<Id> {
	if value.len() != 64 {
		bail!("invalid archive index identity");
	}
	fn digit(byte: u8) -> Result<u8> {
		match byte {
			b'0'..=b'9' => Ok(byte - b'0'),
			b'a'..=b'f' => Ok(byte - b'a' + 10),
			_ => bail!("invalid identity"),
		}
	}
	let mut bytes = [0u8; 32];
	for (out, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
		*out = digit(pair[0])? * 16 + digit(pair[1])?;
	}
	Ok(bytes)
}

// Cache scans must not promote gigabytes of disposable pages over original
// inode metadata. These advisory, descriptor-local Linux hints change no data
// or validation rule; normal access is restored before serving warm queries.
struct CacheReadHint<'a> {
	_file: &'a File,
}
impl<'a> CacheReadHint<'a> {
	fn release_clean_pages(file: &File) {
		// Only the disposable cache descriptor is advised. Dirty pages remain
		// owned by the kernel; original files and global caches are untouched.
		#[cfg(target_os = "linux")]
		unsafe {
			let _ = libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
		}
		let _ = file;
	}
	fn new(file: &'a File, random: bool) -> Self {
		#[cfg(target_os = "linux")]
		unsafe {
			let _ = libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_NOREUSE);
			let _ = libc::posix_fadvise(
				file.as_raw_fd(),
				0,
				0,
				if random {
					libc::POSIX_FADV_RANDOM
				} else {
					libc::POSIX_FADV_SEQUENTIAL
				},
			);
		}
		let _ = random;
		Self { _file: file }
	}
}
impl Drop for CacheReadHint<'_> {
	fn drop(&mut self) {
		#[cfg(target_os = "linux")]
		unsafe {
			let _ = libc::posix_fadvise(self._file.as_raw_fd(), 0, 0, libc::POSIX_FADV_NORMAL);
		}
	}
}

fn order_key(record: &Record) -> Result<[u8; 80]> {
	let mut key = [0u8; 80];
	key[..32].copy_from_slice(&id(&record.owner)?);
	key[32..48].copy_from_slice(&record.accepted_unix_ms.to_be_bytes());
	key[48..].copy_from_slice(&id(&record.request_id)?);
	Ok(key)
}
fn state_key(record: &Record) -> Result<Vec<u8>> {
	let mut key = id(&record.owner)?.to_vec();
	key.push(b's');
	key.push(match record.state {
		DurableState::Unknown => 0,
		DurableState::Completed => 1,
		DurableState::Failed => 2,
	});
	Ok(key)
}
fn tool_key(record: &Record) -> Result<Vec<u8>> {
	if !valid_tool(&record.tool_name) {
		bail!("invalid archive index tool");
	}
	let mut key = id(&record.owner)?.to_vec();
	key.push(b't');
	key.extend_from_slice(record.tool_name.as_bytes());
	Ok(key)
}
fn content_version(archive: &Archive) -> Result<Option<super::super::namespace_version::Version>> {
	archive.content_version()
}
fn identity(file: &File) -> Result<(u64, u64)> {
	let metadata = file.metadata()?;
	Ok((metadata.dev(), metadata.ino()))
}
fn stamp(archive: &Archive, filename: &str) -> Result<FileStamp> {
	let directory = archive.directory_for_existing(filename)?;
	stamp_at(directory, filename)
}
fn stamp_at(directory: &File, filename: &str) -> Result<FileStamp> {
	let filename = name(filename)?;
	stamp_at_component(directory, &filename)
}
fn stamp_at_component(directory: &File, filename: &std::ffi::CStr) -> Result<FileStamp> {
	let mut raw = std::mem::MaybeUninit::<libc::stat>::uninit();
	if unsafe {
		libc::fstatat(
			directory.as_raw_fd(),
			filename.as_ptr(),
			raw.as_mut_ptr(),
			libc::AT_SYMLINK_NOFOLLOW,
		)
	} < 0
	{
		return Err(std::io::Error::last_os_error().into());
	}
	stamp_from_stat(unsafe { raw.assume_init() })
}
#[allow(clippy::unnecessary_cast)] // libc inode/device widths vary across Unix.
fn stamp_from_stat(raw: libc::stat) -> Result<FileStamp> {
	if raw.st_mode & libc::S_IFMT != libc::S_IFREG
		|| raw.st_mode & 0o7777 != 0o600
		|| raw.st_uid != unsafe { libc::geteuid() }
		|| raw.st_nlink != 1
		|| raw.st_size < 0
		|| raw.st_size > MAX_RECORD_BYTES as _
	{
		bail!("unsafe archive index member");
	}
	#[cfg(any(target_os = "linux", target_os = "macos"))]
	let times = (
		(raw.st_mtime, raw.st_mtime_nsec),
		(raw.st_ctime, raw.st_ctime_nsec),
	);
	#[cfg(not(any(target_os = "linux", target_os = "macos")))]
	let times = ((raw.st_mtime, 0), (raw.st_ctime, 0));
	Ok(FileStamp {
		device: raw.st_dev as u64,
		inode: raw.st_ino as u64,
		mode: raw.st_mode as u32,
		uid: raw.st_uid,
		links: raw.st_nlink as u64,
		length: raw.st_size as u64,
		modified: times.0,
		changed: times.1,
	})
}
fn private_cache(file: &File) -> Result<()> {
	let info = file.metadata()?;
	if !info.is_file()
		|| info.uid() != unsafe { libc::geteuid() }
		|| info.mode() & 0o7777 != 0o600
		|| info.nlink() != 1
	{
		bail!("unsafe archive disk index inode");
	}
	Ok(())
}
fn invalidate(state: &mut State) {
	state.database = None;
	state.pending.clear();
	state.requested = false;
	state.failed = true;
	state.generation = state.generation.wrapping_add(1);
}

/// The caller holds STORE_LOCK. Only bounded queue work happens here; disk
/// maintenance normally runs outside that lock. A waiting reader may drain one
/// bounded cohort under the writer fence to prevent continuous-writer starvation.
fn publication_slot(archive: &Archive) -> Option<Arc<Slot>> {
	let registry = INDEXES.get()?;
	let archive_id = identity(archive.legacy()).ok()?;
	match registry.lock() {
		Ok(registry) => registry
			.iter()
			.find(|slot| slot.identity == archive_id)
			.cloned(),
		Err(_) => None,
	}
}

fn publication_before(slot: &Slot, archive: &Archive) {
	let span = trace::Span::new("index_publication_before", 0, None);
	let before = content_version(archive).ok().flatten();
	if let Ok(mut state) = slot.state.lock() {
		if state.version != before {
			invalidate(&mut state);
		}
	}
	span.record(None);
}

fn publication_after(slot: &Slot, archive: &Archive, records: &[&Record], succeeded: bool) {
	let span = trace::Span::new("index_publication_after", records.len(), None);
	let note = (|| -> Result<()> {
		let mut state = slot
			.state
			.lock()
			.map_err(|_| anyhow!("archive index unavailable"))?;
		if !succeeded {
			invalidate(&mut state);
			return Ok(());
		}
		if !state.failed {
			for record in records {
				let key = id(&record.request_id)?;
				if state.pending.len() >= MAX_PENDING && !state.pending.contains_key(&key) {
					invalidate(&mut state);
					break;
				} else {
					let entry = Entry {
						record: (*record).clone(),
						stamp: stamp(archive, &format!("{}.json", record.request_id))?,
					};
					state.pending.insert(key, entry);
					if state.pending.len() >= flush_watermark(&state) {
						slot.wake.notify_one();
					}
				}
			}
		}
		state.version = content_version(archive)?;
		state.last_publication = Instant::now();
		state.generation = state.generation.wrapping_add(records.len() as u64);
		Ok(())
	})();
	span.record(note.as_ref().err());
	if note.is_err() {
		if let Ok(mut state) = slot.state.lock() {
			invalidate(&mut state);
		}
	}
	// Small write-only bursts remain in a bounded cohort until a reader, the
	// watermark or a quiet interval calls for maintenance.
}

pub(super) fn publication<T>(
	archive: &Archive,
	record: &Record,
	write: impl FnOnce() -> Result<T>,
) -> Result<T> {
	let Some(slot) = publication_slot(archive) else {
		return write();
	};
	publication_before(&slot, archive);
	let result = write();
	publication_after(&slot, archive, &[record], result.is_ok());
	result
}

/// Staging, every file barrier and all serial renames share one watch fence.
/// A partial file failure invalidates only the disposable index, never originals.
pub(super) fn publication_batch(
	archive: &Archive,
	records: &[&Record],
	write: impl FnOnce() -> Vec<Result<()>>,
) -> Vec<Result<()>> {
	if records.is_empty() {
		return write();
	}
	let Some(slot) = publication_slot(archive) else {
		return write();
	};
	publication_before(&slot, archive);
	let result = write();
	publication_after(
		&slot,
		archive,
		records,
		result.len() == records.len() && result.iter().all(Result::is_ok),
	);
	result
}

fn binding(slot: &Slot) -> Result<Vec<u8>> {
	Ok(serde_json::to_vec(&(
		"hepta-disk-index-v2",
		slot.identity.0,
		slot.identity.1,
	))?)
}
fn database(file: File, deadline: Instant) -> Result<Database> {
	open_database(file, deadline).map(|(database, _)| database)
}
fn open_database(file: File, deadline: Instant) -> Result<(Database, bool)> {
	private_cache(&file)?;
	let repaired = Arc::new(AtomicBool::new(false));
	let observed = repaired.clone();
	let mut builder = Database::builder();
	builder.set_cache_size(CACHE_BYTES);
	builder.set_repair_callback(move |session| {
		observed.store(true, Ordering::Relaxed);
		if Instant::now() >= deadline {
			session.abort();
		}
	});
	let database = builder.create_file(file)?;
	Ok((database, repaired.load(Ordering::Relaxed)))
}
fn apply(
	database: &Database,
	entries: impl IntoIterator<Item = Entry>,
	slot: Option<&Slot>,
	durable: bool,
) -> Result<()> {
	apply_traced(database, entries, slot, durable, None)
}
fn apply_traced(
	database: &Database,
	entries: impl IntoIterator<Item = Entry>,
	slot: Option<&Slot>,
	durable: bool,
	mut trace: Option<&mut SteadyTrace>,
) -> Result<()> {
	let mut entries = entries.into_iter().peekable();
	if entries.peek().is_none() && slot.is_none() && !durable {
		return Ok(());
	}
	if let Some(trace) = &mut trace {
		trace.enter(SteadyPhase::BeginWrite);
	}
	let mut transaction = database.begin_write()?;
	if let Some(trace) = &mut trace {
		trace.enter(SteadyPhase::UpdateRows);
	}
	if durable {
		// The original receipt barriers are independent. Save only cache allocator
		// state here so a sealed durable image can reopen without a full repair.
		transaction.set_quick_repair(true);
	}
	transaction.set_durability(if durable {
		Durability::Immediate
	} else {
		Durability::None
	})?;
	{
		let mut rows = transaction.open_table(ROWS)?;
		let mut order = transaction.open_table(ORDER)?;

		let mut ids = transaction.open_table(IDS)?;
		let mut counts = transaction.open_table(COUNTS)?;
		let mut meta = transaction.open_table(META)?;
		if rows.is_empty()? {
			cold::mark_new(&mut meta)?;
			codec::mark_new(&mut meta)?;
		}
		let prior_sum = meta.get("row_image_sum")?.map(|raw| raw.value().to_vec());
		let mut row_sum = match prior_sum {
			Some(raw) => Fingerprint::decode(&raw)?,
			None => {
				// One-time upgrade of an already validated legacy cache. New indexes
				// start from an empty sum, then maintain it with each atomic cohort.
				let mut sum = Fingerprint::default();
				for pair in rows.iter()? {
					let (key, value) = pair?;
					sum.row(key.value(), value.value(), true)?;
				}
				sum
			}
		};
		let mut delta: BTreeMap<Vec<u8>, i64> = BTreeMap::new();
		for entry in entries {
			let key = id(&entry.record.request_id)?;
			let old_raw = rows.get(key.as_slice())?.map(|raw| raw.value().to_vec());
			let old: Option<Entry> = old_raw.as_deref().map(codec::decode).transpose()?;
			let is_new = old.is_none();
			if let Some(old) = old {
				if old.record == entry.record && old.stamp == entry.stamp {
					continue;
				}
				if old.record.owner != entry.record.owner
					|| old.record.tool_name != entry.record.tool_name
					|| old.record.accepted_unix_ms != entry.record.accepted_unix_ms
				{
					return Err(OriginalRecordConflict::Identity.into());
				}
				if old.record.state != DurableState::Unknown
					&& entry.record.state == DurableState::Unknown
				{
					continue;
				}
				if old.record.state != DurableState::Unknown && old.record != entry.record {
					return Err(OriginalRecordConflict::Terminal.into());
				}
				*delta.entry(state_key(&old.record)?).or_default() -= 1;
				*delta.entry(tool_key(&old.record)?).or_default() -= 1;
			}
			*delta.entry(state_key(&entry.record)?).or_default() += 1;
			*delta.entry(tool_key(&entry.record)?).or_default() += 1;
			if let Some(raw) = old_raw {
				row_sum.row(key.as_slice(), &raw, false)?;
			}
			let raw = codec::encode(&entry)?;
			row_sum.row(key.as_slice(), &raw, true)?;
			rows.insert(key.as_slice(), raw.as_slice())?;
			if is_new {
				ids.insert(key.as_slice(), 1)?;
			}
			// Owner, accepted time and identity are immutable across completion.
			// The ORDER value contains only that identity, so a terminal or stamp
			// update normally changes ROWS and counters without rewriting ORDER.
			// Keep the existing repair behavior for a missing/different projection.
			let order_key = order_key(&entry.record)?;
			let order_value = cold::order_value(&entry)?;
			let order_changed = is_new
				|| order
					.get(order_key.as_slice())?
					.is_none_or(|value| value.value() != order_value.as_slice());
			if order_changed {
				order.insert(order_key.as_slice(), order_value.as_slice())?;
			}
		}
		for (key, change) in delta {
			if change == 0 {
				continue;
			}
			let prior = counts.get(key.as_slice())?.map_or(0, |v| v.value());
			let next = if change >= 0 {
				prior.checked_add(change as u64)
			} else {
				prior.checked_sub(change.unsigned_abs())
			}
			.ok_or_else(|| anyhow!("archive index count overflow"))?;
			if next == 0 {
				counts.remove(key.as_slice())?;
			} else {
				counts.insert(key.as_slice(), next)?;
			}
		}
		meta.insert("row_image_sum", row_sum.encode().as_slice())?;
		if let Some(slot) = slot {
			meta.insert("binding", binding(slot)?.as_slice())?;
			meta.insert("complete", b"yes".as_slice())?;
		}
	}
	if let Some(trace) = &mut trace {
		trace.enter(SteadyPhase::Commit);
	}
	transaction.commit()?;
	if let Some(trace) = &mut trace {
		trace.enter(SteadyPhase::Other);
	}
	Ok(())
}

// Keep the standard SHA-256 bytes and seal domains unchanged. ring already
// supplies the runtime's OS-backed crypto and optimized portable CPU dispatch.
struct ArchiveHash(ring::digest::Context);
impl ArchiveHash {
	fn new() -> Self {
		Self(ring::digest::Context::new(&ring::digest::SHA256))
	}
	fn update(&mut self, bytes: impl AsRef<[u8]>) {
		self.0.update(bytes.as_ref());
	}
	fn finalize(self) -> [u8; 32] {
		let mut result = [0u8; 32];
		result.copy_from_slice(self.0.finish().as_ref());
		result
	}
}

// Independent additive fingerprints compare the complete disk indexes with
// the receipt table in constant RAM. Page checksums detect byte corruption;
// these cross-index checks also reject valid-checksum inconsistent tables.
#[derive(Debug, Default, PartialEq, Eq)]
struct Fingerprint([u64; 4]);
impl Fingerprint {
	fn decode(bytes: &[u8]) -> Result<Self> {
		if bytes.len() != 32 {
			bail!("invalid archive row image sum");
		}
		let mut value = Self::default();
		for (out, part) in value.0.iter_mut().zip(bytes.chunks_exact(8)) {
			let mut raw = [0u8; 8];
			raw.copy_from_slice(part);
			*out = u64::from_le_bytes(raw);
		}
		Ok(value)
	}
	fn encode(&self) -> [u8; 32] {
		let mut bytes = [0u8; 32];
		for (out, word) in bytes.chunks_exact_mut(8).zip(self.0) {
			out.copy_from_slice(&word.to_le_bytes());
		}
		bytes
	}
	fn merge(&mut self, other: Self) {
		let mut carry = false;
		for (out, word) in self.0.iter_mut().zip(other.0) {
			let (next, first) = out.overflowing_add(word);
			let (next, second) = next.overflowing_add(u64::from(carry));
			*out = next;
			carry = first || second;
		}
	}
	fn row(&mut self, key: &[u8], value: &[u8], adding: bool) -> Result<()> {
		if key.len() != 32 || value.len() > MAX_RECORD_BYTES * 2 {
			bail!("invalid archive row image");
		}
		let mut hash = ArchiveHash::new();
		hash.update(b"row-image");
		hash.update(key);
		hash.update(value);
		let digest: [u8; 32] = hash.finalize();
		if adding {
			self.add_digest(&digest, 1);
		} else {
			let mut other = Self::default();
			other.add_digest(&digest, 1);
			let mut borrow = false;
			for (out, word) in self.0.iter_mut().zip(other.0) {
				let (next, first) = out.overflowing_sub(word);
				let (next, second) = next.overflowing_sub(u64::from(borrow));
				*out = next;
				borrow = first || second;
			}
		}
		Ok(())
	}
	fn add(&mut self, domain: &[u8], key: &[u8], copies: u64) {
		let mut hash = ArchiveHash::new();
		hash.update(domain);
		hash.update(key);
		let hash: [u8; 32] = hash.finalize();
		self.add_digest(&hash, copies);
	}
	fn add_digest(&mut self, hash: &[u8; 32], copies: u64) {
		let mut carry = 0u128;
		for (out, part) in self.0.iter_mut().zip(hash.chunks_exact(8)) {
			let mut bytes = [0u8; 8];
			bytes.copy_from_slice(part);
			let value = u64::from_le_bytes(bytes) as u128 * copies as u128 + *out as u128 + carry;
			*out = value as u64;
			carry = value >> 64;
		}
	}
}
fn checked_original(slot: &Slot, filename: &str) -> Result<Entry> {
	let _guard = store_lock()?;
	let mut state = slot
		.state
		.lock()
		.map_err(|_| anyhow!("archive index unavailable"))?;
	if state.failed || (state.version.is_some() && content_version(&slot.archive)? != state.version)
	{
		bail!("archive changed outside verified writer");
	}
	let record = slot.archive.read_record(filename)?;
	state.version = content_version(&slot.archive)?;
	Ok(Entry {
		record,
		stamp: stamp(&slot.archive, filename)?,
	})
}
fn fold_cache_changes(db: &Database, slot: &Slot, chunk: &mut Vec<Entry>) -> Result<()> {
	apply(db, std::mem::take(chunk), None, false)?;
	let (pending, _) = take_pending(slot)?;
	apply(db, pending.into_values(), None, false)
}
fn cold_phase(phase: &str, opened: Instant) {
	if std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref() == Some(std::ffi::OsStr::new("1")) {
		eprintln!(
			"archive_index phase={phase} elapsed_ms={}",
			opened.elapsed().as_millis()
		);
	}
}
fn cached(slot: &Slot, deadline: Instant) -> Result<Option<ValidatedDatabase>> {
	let file = match open_at(&slot.root, CACHE_NAME, libc::O_RDWR | libc::O_NONBLOCK, 0) {
		Ok(file) => file,
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
		{
			return Ok(None)
		}
		Err(error) => return Err(error),
	};
	private_cache(&file)?;
	let opened = Instant::now();
	match file.try_lock() {
		Ok(()) => {}
		Err(std::fs::TryLockError::WouldBlock) => {
			return Err(redb::DatabaseError::DatabaseAlreadyOpen.into());
		}
		Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
	}
	let sealed = seal::verified(slot, &file, deadline)?;
	cold_phase(
		if sealed {
			"sealed_integrity"
		} else {
			"full_integrity_required"
		},
		opened,
	);
	let hint_file = file.try_clone()?;
	let (mut db, recovered) = match open_database(file, deadline) {
		Ok(value) => value,
		Err(error) => {
			if error
				.downcast_ref::<redb::DatabaseError>()
				.is_some_and(|e| matches!(e, redb::DatabaseError::DatabaseAlreadyOpen))
			{
				return Err(error);
			}
			return Ok(None);
		}
	};
	tracing::debug!(target: "hepta_archive_index", phase = "database_open", recovered,
		elapsed_ms = opened.elapsed().as_millis() as u64);
	cold_phase("database_open", opened);
	let mut parallel_epoch = None;
	let valid = (|| -> Result<bool> {
		// A successful open after this callback already verified page checksums
		// and rebuilt allocator state. A forced check would repeat all three scans.
		// Clean opens still need that check for external cache corruption. Original
		// inode/stamp and independent table-fingerprint checks below always run.
		if !sealed && !recovered && !db.check_integrity()? {
			return Ok(false);
		}
		// The forced integrity traversal verifies the entire database, including
		// allocator state. Do not disable readahead or evict reuse before it has
		// completed. Bounded table/original validation retains its own advice.
		let _cache_read_hint = CacheReadHint::new(&hint_file, true);
		tracing::debug!(target: "hepta_archive_index", phase = "checksum_verified",
			elapsed_ms = opened.elapsed().as_millis() as u64);
		cold_phase("checksum_verified", opened);
		codec::upgrade(&db, slot, deadline)?;
		cold::upgrade(&db, slot, deadline)?;
		let transaction = db.begin_read()?;
		let meta = transaction.open_table(META)?;
		let expected = binding(slot)?;
		if meta.get("binding")?.is_none_or(|v| v.value() != expected)
			|| meta.get("complete")?.is_none_or(|v| v.value() != b"yes")
		{
			return Ok(false);
		}
		let rows = transaction.open_table(ROWS)?;
		let order = transaction.open_table(ORDER)?;
		let ids = transaction.open_table(IDS)?;
		let counts = transaction.open_table(COUNTS)?;
		let row_sum = meta.get("row_image_sum")?.map(|raw| raw.value().to_vec());
		if sealed && row_sum.is_none() {
			return Ok(false);
		}
		if rows.len()? != order.len()? || rows.len()? != ids.len()? {
			return Ok(false);
		}
		parallel_epoch = ParallelEpoch::capture(slot)?;
		if std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref()
			== Some(std::ffi::OsStr::new("1"))
		{
			let mode = if parallel_epoch.is_some() {
				"parallel_content_watch"
			} else {
				"serial_unavailable_or_unstable_watch"
			};
			eprintln!("archive_index cold_stage=original_observation_schedule mode={mode}");
		}
		let total = cold_rows(
			&db,
			slot,
			&rows,
			&order,
			&ids,
			ScanPlan::new(deadline, Some(&hint_file), parallel_epoch.as_ref()),
			|total| {
				if let Some(expected) = row_sum {
					if Fingerprint::decode(&expected)? != total.row_sum {
						return Ok(false);
					}
				}
				let actual_ids = total
					.actual_ids
					.as_ref()
					.ok_or_else(|| anyhow!("archive identity checker incomplete"))?;
				let actual_order = total
					.actual_order
					.as_ref()
					.ok_or_else(|| anyhow!("archive order checker incomplete"))?;
				let mut actual_counts = Fingerprint::default();
				for pair in counts.iter()? {
					if Instant::now() >= deadline {
						bail!("archive index preparation deadline");
					}
					let (key, value) = pair?;
					if value.value() == 0 {
						return Ok(false);
					}
					actual_counts.add(b"count", key.value(), value.value());
				}
				Ok(actual_ids == &total.ids
					&& actual_order == &total.order
					&& actual_counts == total.counts)
			},
		)?;
		let visited = total.rows;
		let expected_ids = total.ids;
		let mut chunk = Vec::with_capacity(BUILD_CHUNK);
		tracing::debug!(target: "hepta_archive_index", phase = "rows_and_original_stamps",
			rows = visited, elapsed_ms = opened.elapsed().as_millis() as u64);
		cold_phase("rows_and_original_stamps", opened);
		tracing::debug!(target: "hepta_archive_index", phase = "all_table_fingerprints",
			elapsed_ms = opened.elapsed().as_millis() as u64);
		cold_phase("all_table_fingerprints", opened);
		fold_cache_changes(&db, slot, &mut chunk)?;
		// The complete original join already checks and applies all extra IDs.
		// Its coverage must match the independent full namespace enumeration in
		// the same unchanged epoch before the old-snapshot repair can be omitted.
		let (directory_ids, directory_names, joined_coverage) = match (
			parallel_epoch.as_ref(),
			total.namespace,
		) {
			(Some(epoch), Some(coverage)) => {
				epoch.check(slot)?;
				let originals = total
					.originals
					.as_ref()
					.ok_or_else(|| anyhow!("archive original coverage unavailable"))?;
				if !originals.matches_namespace(&coverage.0, coverage.1)
					|| originals.matched != visited
				{
					bail!("archive original and namespace coverage changed");
				}
				#[cfg(test)]
				parallel_event(slot, ParallelEvent::VerifiedOriginalCoverage);
				if std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref()
					== Some(std::ffi::OsStr::new("1"))
				{
					eprintln!("archive_index cold_stage=original_namespace_join_coverage_verified matched_rows={} changed_rows={} extra_rows={} observed_rows={} complete_identity_join=true full_namespace_rescan=true old_snapshot_random_probes=0", originals.matched, originals.changed, originals.extra, originals.rows);
				}
				(coverage.0, coverage.1, true)
			}
			(None, None) => {
				let (ids, names) = cold::directory_coverage(&db, slot, &mut chunk, deadline)?;
				(ids, names, false)
			}
			_ => bail!("archive namespace observation scheduling coverage changed"),
		};
		if !joined_coverage && (directory_ids != expected_ids || directory_names != visited) {
			#[cfg(test)]
			parallel_event(slot, ParallelEvent::BeforeMissingTailRepair);
			let mut names = 0u64;
			slot.archive.walk(|_, filename, _| {
				if Instant::now() >= deadline {
					bail!("archive index preparation deadline");
				}
				if staging(filename)? {
					return Ok(());
				}
				let raw_id = filename
					.strip_suffix(".json")
					.filter(|v| valid_id(v))
					.ok_or_else(|| anyhow!("invalid archive member"))?;
				if ids.get(id(raw_id)?.as_slice())?.is_none() {
					chunk.push(checked_original(slot, filename)?);
				}
				names += 1;
				if names.is_multiple_of(BUILD_CHUNK as u64) {
					fold_cache_changes(&db, slot, &mut chunk)?;
				}
				Ok(())
			})?;
		}
		fold_cache_changes(&db, slot, &mut chunk)?;
		tracing::debug!(target: "hepta_archive_index", phase = "original_directory_coverage",
			elapsed_ms = opened.elapsed().as_millis() as u64);
		cold_phase("original_directory_coverage", opened);
		Ok(true)
	})();
	// An overlap epoch failure must not become a request to rebuild the cache.
	if let Some(epoch) = &parallel_epoch {
		epoch.check(slot)?;
	}
	match valid {
		Ok(true) => {
			// Content disagreement must not become a cache miss and disappear in
			// an empty rebuild. This stage uses a pure reader and retains the
			// existing recovery transitions before its complete final check.
			content::validate_cached(slot, &db, deadline)?;
			if let Some(epoch) = &parallel_epoch {
				epoch.check(slot)?;
			}
			cold_phase("complete_record_contents", opened);
			Ok(Some(ValidatedDatabase {
				database: db,
				parallel_epoch,
			}))
		}
		Err(error) if error.is::<ColdEpochChanged>() || error.is::<OriginalRecordConflict>() => {
			Err(error)
		}
		_ => Ok(None),
	}
}
fn staging(filename: &str) -> Result<bool> {
	if !filename.starts_with('.') {
		return Ok(false);
	}
	let value = filename
		.strip_prefix('.')
		.and_then(|v| v.strip_suffix(".tmp"))
		.and_then(|v| v.split_once('-'));
	if !value.is_some_and(|(request, nonce)| valid_id(request) && valid_id(nonce)) {
		bail!("invalid archive staging member");
	}
	Ok(true)
}
fn take_pending(slot: &Slot) -> Result<(BTreeMap<Id, Entry>, u64)> {
	take_pending_at(slot, false)
}
fn claim_pending(slot: &Slot) -> Result<(BTreeMap<Id, Entry>, u64)> {
	take_pending_at(slot, true)
}
fn take_pending_at(slot: &Slot, in_flight: bool) -> Result<(BTreeMap<Id, Entry>, u64)> {
	let _guard = store_lock()?;
	let mut state = slot
		.state
		.lock()
		.map_err(|_| anyhow!("archive index unavailable"))?;
	if state.failed
		|| state.retired
		|| (state.version.is_some() && content_version(&slot.archive)? != state.version)
	{
		bail!("archive changed outside verified writer");
	}
	// Publish in-flight ownership before releasing STORE_LOCK. A reader must
	// never mistake an already-taken cohort for an empty, fully applied queue.
	if in_flight {
		state.busy = true;
	}
	let boundary = if in_flight && state.large_archive {
		state.pending.keys().nth(LARGE_WRITE_CHUNK).copied()
	} else {
		None
	};
	let pending = match boundary {
		Some(key) => {
			let tail = state.pending.split_off(&key);
			std::mem::replace(&mut state.pending, tail)
		}
		None => std::mem::take(&mut state.pending),
	};
	Ok((pending, state.generation))
}
fn flush_watermark(state: &State) -> usize {
	if state.large_archive {
		LARGE_FLUSH_WATERMARK
	} else {
		FLUSH_WATERMARK
	}
}
fn large_archive(database: &Database) -> Result<bool> {
	let transaction = database.begin_read()?;
	let rows = transaction.open_table(ROWS)?;
	Ok(rows.len()? > LARGE_ARCHIVE_ROWS)
}
fn clean_staging(slot: &Slot) -> Result<()> {
	let _guard = store_lock()?;
	walk_directory(&slot.root, |filename| {
		let Some(nonce) = filename
			.strip_prefix(".disk-index-")
			.and_then(|v| v.strip_suffix(".tmp"))
		else {
			return Ok(());
		};
		if !valid_id(nonce) {
			bail!("invalid disk index staging name");
		}
		let file = open_at(&slot.root, filename, libc::O_RDWR | libc::O_NONBLOCK, 0)?;
		private_cache(&file)?;
		if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
			bail!("disk index staging in use");
		}
		if unsafe { libc::unlinkat(slot.root.as_raw_fd(), name(filename)?.as_ptr(), 0) } < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(())
	})
}
fn build(slot: &Slot) -> Result<ValidatedDatabase> {
	let deadline = Instant::now() + BUILD_BUDGET;
	clean_staging(slot)?;
	if let Some(db) = cached(slot, deadline)? {
		return Ok(db);
	}
	let temporary = format!(".disk-index-{}.tmp", new_id()?);
	let file = open_at(
		&slot.root,
		&temporary,
		libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	let db = database(file, deadline)?;
	let result = (|| -> Result<()> {
		let mut chunk = Vec::with_capacity(BUILD_CHUNK);
		slot.archive.walk(|_, filename, _| {
			if Instant::now() >= deadline {
				bail!("archive index preparation deadline");
			}
			if staging(filename)? {
				return Ok(());
			}
			{
				let _guard = store_lock()?;
				let mut state = slot
					.state
					.lock()
					.map_err(|_| anyhow!("archive index unavailable"))?;
				if state.failed
					|| (state.version.is_some() && content_version(&slot.archive)? != state.version)
				{
					bail!("archive changed outside verified writer");
				}
				let record = slot.archive.read_record(filename)?;
				state.version = content_version(&slot.archive)?;
				chunk.push(Entry {
					record,
					stamp: stamp(&slot.archive, filename)?,
				});
			}
			if chunk.len() == BUILD_CHUNK {
				apply(&db, std::mem::take(&mut chunk), None, false)?;
				let (pending, _) = take_pending(slot)?;
				apply(&db, pending.into_values(), None, false)?;
			}
			Ok(())
		})?;
		apply(&db, chunk, None, false)?;
		let (pending, _) = take_pending(slot)?;
		apply(&db, pending.into_values(), Some(slot), true)?;
		let _guard = store_lock()?;
		// Existing cache inodes were checked before build; check again before
		// replacing that reserved name. Shared ancestors and originals are untouched.
		match open_at(&slot.root, CACHE_NAME, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
			Ok(file) => private_cache(&file)?,
			Err(error)
				if error
					.downcast_ref::<std::io::Error>()
					.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
			Err(error) => return Err(error),
		}
		if unsafe {
			libc::renameat(
				slot.root.as_raw_fd(),
				name(&temporary)?.as_ptr(),
				slot.root.as_raw_fd(),
				name(CACHE_NAME)?.as_ptr(),
			)
		} < 0
		{
			return Err(std::io::Error::last_os_error().into());
		}
		slot.root.sync_all()?;
		Ok(())
	})();
	if let Err(error) = result {
		drop(db);
		unsafe {
			libc::unlinkat(slot.root.as_raw_fd(), name(&temporary)?.as_ptr(), 0);
		}
		return Err(error);
	}
	Ok(ValidatedDatabase {
		database: db,
		parallel_epoch: None,
	})
}
fn worker(slot: &Arc<Slot>) -> Result<()> {
	let ValidatedDatabase {
		database,
		parallel_epoch,
	} = build(slot)?;
	let db = Arc::new(database);
	#[cfg(test)]
	parallel_event(slot, ParallelEvent::AfterCachedBeforeClaim);
	// Fold any local writes that overlapped cold validation before publishing.
	let (pending, generation) =
		publication_result(slot, parallel_epoch.as_ref(), claim_pending(slot))?;
	publication_result(
		slot,
		parallel_epoch.as_ref(),
		apply(&db, pending.into_values(), Some(slot), true),
	)?;
	let large = publication_result(slot, parallel_epoch.as_ref(), large_archive(&db))?;
	#[cfg(test)]
	parallel_event(slot, ParallelEvent::BeforePublish);
	{
		let _guard = store_lock()?;
		let mut state = slot
			.state
			.lock()
			.map_err(|_| anyhow!("archive index unavailable"))?;
		if let Some(epoch) = &parallel_epoch {
			epoch.check_locked(slot, &state)?;
		}
		if state.failed || state.retired {
			bail!("archive index invalidated");
		}
		state.database = Some(db.clone());
		state.large_archive = large;
		state.applied = generation;
		state.requested =
			state.requested && (state.generation != generation || !state.pending.is_empty());
		state.busy = false;
		if let Some(epoch) = &parallel_epoch {
			if let Err(error) = epoch.check_locked(slot, &state) {
				state.database = None;
				return Err(error);
			}
			epoch.trace("parallel_epoch_publication_complete");
		}
		// A long cold build is not an idle interval for its first ready reader.
		slot.metadata_activity.touch();
	}
	let mut dirty = false;
	let mut unsealed = true;
	loop {
		let synchronize_idle = {
			let state = slot
				.state
				.lock()
				.map_err(|_| anyhow!("archive index unavailable"))?;
			let mut state = if !state.busy
				&& (state.requested || state.pending.len() >= flush_watermark(&state))
			{
				state
			} else {
				slot.wake
					.wait_timeout(state, MAINTENANCE_INTERVAL)
					.map_err(|_| anyhow!("archive index unavailable"))?
					.0
			};
			if state.retired || state.failed {
				return Ok(());
			}
			if state.query_flushed {
				dirty = true;
				unsealed = true;
				state.query_flushed = false;
			}
			if state.busy {
				continue;
			}
			let quiet = state.last_publication.elapsed() >= IDLE_SYNC_QUIET;
			if state.pending.is_empty() {
				if (!dirty && !unsealed) || !quiet || slot.metadata_activity.quiet_epoch().is_none()
				{
					continue;
				}
				true
			} else {
				if !state.requested && state.pending.len() < flush_watermark(&state) && !quiet {
					continue;
				}
				false
			}
		};
		if synchronize_idle {
			if dirty {
				// Recheck after releasing state, before starting an idle write.
				if slot.metadata_activity.quiet_epoch().is_none() {
					continue;
				}
				let mut trace = SteadyTrace::new("quiet_checkpoint", Some(true));
				apply_traced(&db, std::iter::empty(), None, true, Some(&mut trace))?;
				trace.outcome = "ok";
			}
			dirty = false;
			let mut trace = SteadyTrace::new("quiet_seal", None);
			trace.enter(SteadyPhase::Seal);
			unsealed = !seal::persist(slot, Instant::now() + BUILD_BUDGET)?;
			trace.enter(SteadyPhase::Other);
			trace.outcome = if unsealed { "not_sealed" } else { "sealed" };
			continue;
		}
		let mut trace = SteadyTrace::new("background_apply", None);
		trace.enter(SteadyPhase::ClaimPending);
		let (pending, generation) = claim_pending(slot)?;
		trace.rows = pending.len();
		trace.enter(SteadyPhase::State);
		{
			let mut state = slot
				.state
				.lock()
				.map_err(|_| anyhow!("archive index unavailable"))?;
			state.busy = true;
		}
		let durable =
			slot.state
				.lock()
				.map_err(|_| anyhow!("archive index unavailable"))?
				.last_publication
				.elapsed() >= IDLE_SYNC_QUIET;
		trace.durable = Some(durable);
		apply_traced(&db, pending.into_values(), None, durable, Some(&mut trace))?;
		trace.enter(SteadyPhase::SizeRead);
		let large = large_archive(&db)?;
		dirty = !durable;
		unsealed = true;
		trace.enter(SteadyPhase::State);
		let mut state = slot
			.state
			.lock()
			.map_err(|_| anyhow!("archive index unavailable"))?;
		if state.failed {
			bail!("archive index invalidated during flush");
		}
		state.applied = generation;
		state.large_archive = large;
		state.requested =
			state.requested && (state.generation != generation || !state.pending.is_empty());
		state.busy = false;
		trace.outcome = "ok";
		// state was declared after trace and is dropped first on every exit.
	}
}
// The registry owns one reference; an actual background worker owns one
// more. Without a worker, a second reference is a live caller, not idle cache
// ownership. In particular, do not retire ready() between slot_at and spawn.
fn can_retire(slot: &Arc<Slot>) -> bool {
	slot.state.lock().is_ok_and(|state| {
		let internal_owners = 1 + usize::from(state.worker);
		!state.busy && Arc::strong_count(slot) <= internal_owners
	})
}
#[derive(Debug)]
struct IndexCapacityBusy;
impl std::fmt::Display for IndexCapacityBusy {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		out.write_str("archive index workers busy")
	}
}
impl std::error::Error for IndexCapacityBusy {}

// The caller holds STORE_LOCK. A full pool is transient contention, distinct
// from unsafe storage or an invalid archive; only that capacity error may wait.
fn try_slot_at(root: &Path, archive: &Archive) -> Result<Arc<Slot>> {
	let key = identity(archive.legacy())?;
	let mut registry = INDEXES
		.get_or_init(|| Mutex::new(VecDeque::new()))
		.lock()
		.map_err(|_| anyhow!("archive index unavailable"))?;
	if let Some(slot) = registry.iter().find(|slot| slot.identity == key) {
		return Ok(slot.clone());
	}
	if registry.len() >= MAX_INDEXES {
		let position = registry.iter().position(can_retire);
		let Some(position) = position else {
			return Err(IndexCapacityBusy.into());
		};
		if let Some(old) = registry.remove(position) {
			if let Ok(mut state) = old.state.lock() {
				state.retired = true;
				old.wake.notify_one();
			}
		}
	}
	let slot = Arc::new(Slot {
		root: audit_root(root)?,
		archive: archive.try_clone()?,
		identity: key,
		metadata_activity: MetadataActivity::default(),
		state: Mutex::new(State {
			database: None,
			worker: false,
			busy: false,
			failed: false,
			retired: false,
			pending: BTreeMap::new(),
			requested: false,
			query_flushed: false,
			large_archive: false,
			last_publication: Instant::now(),
			version: content_version(archive)?,
			generation: 0,
			applied: 0,
		}),
		wake: Condvar::new(),
		#[cfg(test)]
		parallel_hook: Mutex::new(None),
		#[cfg(test)]
		seal_hook: Mutex::new(None),
	});
	registry.push_back(slot.clone());
	Ok(slot)
}
// A caller already holding an index must stay protected from retirement. New
// roots wait only within their original query deadline. Release every store,
// registry and state guard before waiting so current readers/workers can leave
// and authoritative writers can continue; no failed request is redispatched.
fn slot_at_until(root: &Path, archive: &Archive, deadline: Instant) -> Result<Arc<Slot>> {
	loop {
		let result = {
			let _guard = query_lock(deadline)?;
			try_slot_at(root, archive)
		};
		match result {
			Err(error) if error.is::<IndexCapacityBusy>() => {
				let remaining = deadline.saturating_duration_since(Instant::now());
				if remaining.is_zero() {
					bail!("archive metadata query total deadline exceeded");
				}
				std::thread::sleep(remaining.min(Duration::from_millis(1)));
			}
			result => return result,
		}
	}
}

#[cfg(test)]
fn slot_at(root: &Path, archive: &Archive) -> Result<Arc<Slot>> {
	slot_at_until(root, archive, Instant::now() + QUERY_BUDGET)
}

fn large_preparation_hint(root: &File) -> bool {
	// This is only a response-scheduling hint. Every cache byte, table and
	// original still undergoes the normal background validation before serving data.
	let Ok(filename) = name(CACHE_NAME) else {
		return false;
	};
	let mut raw = std::mem::MaybeUninit::<libc::stat>::uninit();
	if unsafe {
		libc::fstatat(
			root.as_raw_fd(),
			filename.as_ptr(),
			raw.as_mut_ptr(),
			libc::AT_SYMLINK_NOFOLLOW,
		)
	} < 0
	{
		return false;
	}
	let raw = unsafe { raw.assume_init() };
	raw.st_mode & libc::S_IFMT == libc::S_IFREG
		&& raw.st_mode & 0o7777 == 0o600
		&& raw.st_uid == unsafe { libc::geteuid() }
		&& raw.st_nlink == 1
		&& raw.st_size > CACHE_BYTES as _
}

fn ready(root: &Path, archive: &Archive, deadline: Instant) -> Result<Arc<Slot>> {
	let _trace = metadata_trace::Stage::new("index_ready");
	let slot = slot_at_until(root, archive, deadline)?;
	let mut started = false;
	loop {
		{
			let _guard = query_lock(deadline)?;
			let mut state = slot
				.state
				.lock()
				.map_err(|_| anyhow!("archive index unavailable"))?;
			let current = content_version(archive)?;
			if current != state.version {
				invalidate(&mut state);
			}
			if state.database.is_some() && !state.failed {
				state.requested =
					state.applied != state.generation || !state.pending.is_empty() || state.busy;
				return Ok(slot.clone());
			}
			if state.failed && started {
				bail!("archive index validation unavailable");
			}
			if !state.worker {
				started = true;
				state.worker = true;
				state.busy = true;
				state.failed = false;
				state.pending.clear();
				state.version = current;
				let worker_slot = slot.clone();
				if let Err(error) = std::thread::Builder::new()
					.name("archive-disk-index".into())
					.spawn(move || {
						background_priority();
						let result = worker(&worker_slot);
						if let Ok(mut state) = worker_slot.state.lock() {
							if result.is_err() {
								invalidate(&mut state);
							}
							state.worker = false;
							state.busy = false;
						}
					}) {
					state.worker = false;
					state.busy = false;
					return Err(error.into());
				}
			}
			state.requested = true;
			slot.wake.notify_one();
			if large_preparation_hint(&slot.root) {
				bail!("archive index preparing; repeat only this metadata query");
			}
		}
		if Instant::now() >= deadline {
			bail!("archive index preparing or validation unavailable; repeat only this metadata query");
		}
		std::thread::sleep(Duration::from_millis(2));
	}
}
pub(super) fn query_lock(deadline: Instant) -> Result<AuditStoreGuard<'static>> {
	let _trace = metadata_trace::Stage::new("store_lock_wait");
	STORE_LOCK
		.get_or_init(AuditStoreLock::default)
		.acquire(Some(deadline))
		.map_err(|error| match error {
			StoreLockFailure::Deadline => anyhow!("archive metadata query total deadline exceeded"),
			StoreLockFailure::Unavailable => anyhow!("archive metadata unavailable"),
		})
}
fn query_database_for_read(
	state: &State,
	archive: &Archive,
	allow_pending: bool,
) -> Result<Arc<Database>> {
	let complete = if state.pending.is_empty() {
		state.applied == state.generation
	} else {
		allow_pending
			&& state.large_archive
			&& state.version.is_some()
			&& state.pending.len() <= QUERY_WRITE_CHUNK
	};
	if state.version != content_version(archive)? || state.failed || state.busy || !complete {
		bail!("archive index preparing");
	}
	state
		.database
		.clone()
		.ok_or_else(|| anyhow!("archive index preparing"))
}
fn query_database(state: &State, archive: &Archive) -> Result<Arc<Database>> {
	query_database_for_read(state, archive, false)
}
fn total(counts: &impl ReadableTable<&'static [u8], u64>, owner: &Id) -> Result<[u64; 3]> {
	let mut values = [0; 3];
	let mut key = owner.to_vec();
	key.push(b's');
	key.push(0);
	for (state, out) in values.iter_mut().enumerate() {
		key[33] = state as u8;
		*out = counts.get(key.as_slice())?.map_or(0, |v| v.value());
	}
	Ok(values)
}

// A watched large archive can answer from its already validated disk image and
// the complete bounded publication tail. STORE_LOCK and state stay held for
// construction, reading originals and the final watch check. No cache write,
// generation advance or pending removal belongs to this read-only view.
#[derive(Default)]
struct PendingView {
	entries: BTreeMap<Id, Entry>,
	delta: BTreeMap<Vec<u8>, i64>,
}
impl PendingView {
	fn new(database: &Database, pending: &BTreeMap<Id, Entry>, deadline: Instant) -> Result<Self> {
		if pending.len() > QUERY_WRITE_CHUNK {
			bail!("archive pending view exceeded its bounded cohort");
		}
		let mut view = Self::default();
		if pending.is_empty() {
			return Ok(view);
		}
		let transaction = database.begin_read()?;
		let rows = transaction.open_table(ROWS)?;
		for (key, entry) in pending {
			if Instant::now() >= deadline {
				bail!("archive metadata query total deadline exceeded");
			}
			if *key != id(&entry.record.request_id)? {
				bail!("archive pending identity changed");
			}
			let old = rows
				.get(key.as_slice())?
				.map(|raw| codec::decode(raw.value()))
				.transpose()?;
			if let Some(old) = old {
				// Match apply's immutable identity and terminal-state rules before
				// computing any counters or replacing an ORDER candidate.
				if old.record == entry.record && old.stamp == entry.stamp {
					continue;
				}
				if old.record.owner != entry.record.owner
					|| old.record.tool_name != entry.record.tool_name
					|| old.record.accepted_unix_ms != entry.record.accepted_unix_ms
				{
					return Err(OriginalRecordConflict::Identity.into());
				}
				if old.record.state != DurableState::Unknown
					&& entry.record.state == DurableState::Unknown
				{
					continue;
				}
				if old.record.state != DurableState::Unknown && old.record != entry.record {
					return Err(OriginalRecordConflict::Terminal.into());
				}
				*view.delta.entry(state_key(&old.record)?).or_default() -= 1;
				*view.delta.entry(tool_key(&old.record)?).or_default() -= 1;
			}
			*view.delta.entry(state_key(&entry.record)?).or_default() += 1;
			*view.delta.entry(tool_key(&entry.record)?).or_default() += 1;
			view.entries.insert(*key, entry.clone());
		}
		Ok(view)
	}
	fn changed_count(prior: u64, change: i64) -> Result<u64> {
		let next = if change >= 0 {
			prior.checked_add(change as u64)
		} else {
			prior.checked_sub(change.unsigned_abs())
		};
		next.ok_or_else(|| anyhow!("archive index count overflow"))
	}
	fn totals(
		&self,
		counts: &impl ReadableTable<&'static [u8], u64>,
		owner: &Id,
	) -> Result<[u64; 3]> {
		let mut values = total(counts, owner)?;
		if self.delta.is_empty() {
			return Ok(values);
		}
		let mut key = owner.to_vec();
		key.extend_from_slice(&[b's', 0]);
		for (state, value) in values.iter_mut().enumerate() {
			key[33] = state as u8;
			*value = Self::changed_count(*value, *self.delta.get(&key).unwrap_or(&0))?;
		}
		Ok(values)
	}
	fn entry(
		&self,
		rows: &impl ReadableTable<&'static [u8], &'static [u8]>,
		key: &Id,
	) -> Result<Option<Entry>> {
		match self.entries.get(key) {
			Some(entry) => Ok(Some(entry.clone())),
			None => rows
				.get(key.as_slice())?
				.map(|raw| codec::decode(raw.value()))
				.transpose(),
		}
	}
}
// Keep the preexisting fallback regression helper; production uses the same
// complete gate with its actual pending view for both watched and unwatched reads.
#[cfg(test)]
fn verify_members(database: &Database, archive: &Archive, deadline: Instant) -> Result<()> {
	content::verify_members(database, archive, &PendingView::default(), deadline)
}

#[cfg(test)]
fn read_snapshot<T>(
	root: &Path,
	archive: &Archive,
	deadline: Instant,
	read: impl FnOnce(&Database, &PendingView) -> Result<T>,
) -> Result<T> {
	read_snapshot_with_mode(root, archive, deadline, SnapshotReadMode::Serial, read)
}

#[derive(Clone, Copy)]
enum SnapshotReadMode {
	#[cfg(test)]
	Serial,
	Usage,
	Pages,
}

fn read_snapshot_with_mode<T>(
	root: &Path,
	archive: &Archive,
	deadline: Instant,
	mode: SnapshotReadMode,
	read: impl FnOnce(&Database, &PendingView) -> Result<T>,
) -> Result<T> {
	loop {
		let slot = ready(root, archive, deadline)?;
		// Signal before waiting for the read fence. Drop covers every retry,
		// successful read and error, without taking state or maintenance locks.
		let _metadata_read = slot.metadata_activity.enter();
		// Declare before STORE_LOCK and state; Drop logs only after both guards.
		let mut trace = SteadyTrace::new("metadata_drain", Some(false));
		trace.enter(SteadyPhase::StoreLockWait);
		let _guard = query_lock(deadline)?;
		metadata_trace::mark("snapshot_lock_acquired", 0, 0);
		if !drain_for_query(&slot, deadline, &mut trace)? {
			trace.enter(SteadyPhase::Other);
			trace.outcome = "preparing";
			drop(_guard);
			std::thread::sleep(Duration::from_millis(1));
			continue;
		}
		trace.enter(SteadyPhase::State);
		let state = slot
			.state
			.lock()
			.map_err(|_| anyhow!("archive index unavailable"))?;
		let readonly_pending = state.large_archive && state.version.is_some();
		let candidate = if readonly_pending {
			query_database_for_read(&state, archive, true)
		} else {
			query_database(&state, archive)
		};
		let Ok(database) = candidate else {
			trace.outcome = "preparing";
			continue;
		};
		trace.enter(SteadyPhase::SnapshotRead);
		let view = if readonly_pending {
			PendingView::new(&database, &state.pending, deadline)?
		} else {
			PendingView::default()
		};
		let content_trace = metadata_trace::Stage::new("complete_original_verification");
		// Watches remain invalidation fences; neither Some nor None certifies
		// original bytes. Check every effective record within this same budget.
		match mode {
			#[cfg(test)]
			SnapshotReadMode::Serial => {
				content::verify_members(&database, archive, &view, deadline)?;
			}
			SnapshotReadMode::Usage => {
				content::verify_usage_members(&database, archive, &view, deadline, &_guard)?;
			}
			SnapshotReadMode::Pages => {
				content::verify_page_members(&database, archive, &view, deadline, &_guard)?;
			}
		}
		drop(content_trace);
		let projection_trace = metadata_trace::Stage::new("page_or_usage_projection");
		let result = read(&database, &view)?;
		drop(projection_trace);
		let _final_trace = metadata_trace::Stage::new("snapshot_final_fences");
		#[cfg(test)]
		parallel_event(&slot, ParallelEvent::BeforeSnapshotFence);
		if Instant::now() >= deadline {
			bail!("archive metadata query total deadline exceeded");
		}
		if readonly_pending {
			query_database_for_read(&state, archive, true)?;
		} else {
			query_database(&state, archive)?;
		}
		// The final watch/layout fence may itself take time. No successful
		// response may leave after the caller's original absolute deadline.
		if Instant::now() >= deadline {
			bail!("archive metadata query total deadline exceeded");
		}
		trace.outcome = if readonly_pending && !state.pending.is_empty() {
			"readonly_pending"
		} else {
			"ok"
		};
		return Ok(result);
	}
}
// The caller holds STORE_LOCK, so authoritative publications cannot continually
// move the target while a metadata query catches up. A watched large tail stays
// read-only; the existing small/unwatched path writes its disposable cohort with
// Durability::None. Original ACK barriers are unchanged in either case.
fn drain_for_query(slot: &Slot, deadline: Instant, trace: &mut SteadyTrace) -> Result<bool> {
	let _trace = metadata_trace::Stage::new("query_drain");
	trace.enter(SteadyPhase::State);
	let mut state = slot
		.state
		.lock()
		.map_err(|_| anyhow!("archive index unavailable"))?;
	if state.failed || state.retired || state.version != content_version(&slot.archive)? {
		bail!("archive index validation unavailable");
	}
	if state.busy {
		return Ok(false);
	}
	if state.pending.is_empty() {
		return Ok(state.applied == state.generation);
	}
	// Let the worker drain a large backlog outside STORE_LOCK. A watched large
	// archive reads a small complete tail without writing random B-tree pages
	// under the authoritative lock. Other scopes keep the original catch-up path.
	if state.large_archive && state.pending.len() > QUERY_WRITE_CHUNK {
		state.requested = true;
		slot.wake.notify_one();
		return Ok(false);
	}
	if state.large_archive && state.version.is_some() {
		trace.rows = state.pending.len();
		state.requested = true;
		slot.wake.notify_one();
		return Ok(true);
	}
	let database = state
		.database
		.clone()
		.ok_or_else(|| anyhow!("archive index preparing"))?;
	let generation = state.generation;
	let pending = std::mem::take(&mut state.pending);
	trace.rows = pending.len();
	state.busy = true;
	state.requested = true;
	drop(state);
	let result = apply_traced(
		&database,
		pending.into_values(),
		None,
		false,
		Some(&mut *trace),
	)
	.and_then(|_| {
		trace.enter(SteadyPhase::SizeRead);
		large_archive(&database)
	});
	trace.enter(SteadyPhase::State);
	let mut state = slot
		.state
		.lock()
		.map_err(|_| anyhow!("archive index unavailable"))?;
	state.busy = false;
	let large = match result {
		Ok(large) => large,
		Err(error) => {
			invalidate(&mut state);
			return Err(error);
		}
	};
	state.query_flushed = true;
	state.large_archive = large;
	state.applied = generation;
	state.requested = false;
	if Instant::now() >= deadline {
		bail!("archive metadata query total deadline exceeded");
	}
	Ok(true)
}
#[cfg(test)]
pub(super) fn page(
	root: &Path,
	archive: &Archive,
	owner: &str,
	cursor: Option<&Record>,
	limit: usize,
	deadline: Instant,
) -> Result<(Vec<Record>, u64)> {
	read_snapshot(root, archive, deadline, |database, view| {
		let transaction = database.begin_read()?;
		let rows = transaction.open_table(ROWS)?;
		let order = transaction.open_table(ORDER)?;
		let counts = transaction.open_table(COUNTS)?;
		page_from_view(
			&rows, &order, &counts, archive, view, owner, cursor, limit, deadline,
		)
	})
}

pub(super) struct PageQuery {
	pub(super) owner: String,
	pub(super) cursor: Option<Record>,
	pub(super) limit: usize,
}

pub(super) struct PageBatch {
	pub(super) values: Vec<Result<String>>,
	pub(super) large: bool,
}

pub(super) struct SharedPageRequest {
	pub(super) owner: String,
	pub(super) after_id: Option<String>,
	pub(super) limit: usize,
}

struct SharedSnapshot {
	database: Arc<Database>,
	version: super::super::namespace_version::Version,
	generation: u64,
	applied: u64,
}

impl SharedSnapshot {
	fn capture(slot: &Slot, state: &State) -> Result<Option<Self>> {
		#[cfg(not(target_os = "linux"))]
		{
			let _ = (slot, state);
			Ok(None)
		}
		#[cfg(target_os = "linux")]
		{
			if state.failed
				|| state.retired
				|| state.busy
				|| !state.large_archive
				|| !state.pending.is_empty()
				|| state.applied != state.generation
			{
				return Ok(None);
			}
			let (
				Some(database),
				Some(version @ super::super::namespace_version::Version::Watch(..)),
			) = (&state.database, state.version)
			else {
				return Ok(None);
			};
			if content_version(&slot.archive)? != Some(version) {
				return Ok(None);
			}
			Ok(Some(Self {
				database: database.clone(),
				version,
				generation: state.generation,
				applied: state.applied,
			}))
		}
	}

	fn check(&self, slot: &Slot, state: &State) -> Result<()> {
		if state.failed
			|| state.retired
			|| state.busy
			|| !state.large_archive
			|| !state.pending.is_empty()
			|| state.generation != self.generation
			|| state.applied != self.applied
			|| state.version != Some(self.version)
			|| !state
				.database
				.as_ref()
				.is_some_and(|database| Arc::ptr_eq(database, &self.database))
			|| content_version(&slot.archive)? != Some(self.version)
		{
			bail!("archive shared snapshot changed");
		}
		Ok(())
	}
}

fn shared_lock_failure(error: StoreLockFailure) -> anyhow::Error {
	match error {
		StoreLockFailure::Deadline => anyhow!("archive metadata query total deadline exceeded"),
		StoreLockFailure::Unavailable => anyhow!("archive metadata unavailable"),
	}
}

fn shared_missing(error: &anyhow::Error) -> bool {
	error
		.downcast_ref::<std::io::Error>()
		.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

// None means only a recognized, still-unresolved publication that the original
// exclusive reader can recover. Never unlink or decode a staging file here.
fn shared_original(archive: &Archive, filename: &str, deadline: Instant) -> Result<Option<Entry>> {
	if Instant::now() >= deadline {
		bail!("archive metadata query total deadline exceeded");
	}
	let request_id = filename
		.strip_suffix(".json")
		.filter(|value| valid_id(value))
		.ok_or_else(|| anyhow!("invalid request metadata filename"))?;
	archive.fence_at(archive.root())?;
	let directory = archive.directory_for_existing(filename)?;
	let staging = format!(".{request_id}-{request_id}.tmp");
	match open_at(directory, &staging, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
		Ok(_) => return Ok(None),
		Err(error) if shared_missing(&error) => {}
		Err(error) => return Err(error),
	}
	let original = open_at(directory, filename, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	if original.metadata()?.nlink() == 2 {
		return Ok(None);
	}
	drop(original);
	let entry = content::read_original(archive, directory, filename, deadline)?;
	archive.fence_at(archive.root())?;
	Ok(Some(entry))
}

fn shared_hot_fence(base: &File, hot: &File, expected: ArchiveStamp) -> Result<()> {
	let named = open_existing_store_at(base)?
		.ok_or_else(|| anyhow!("request hot directory changed during shared read"))?;
	if identity(&named)? != identity(hot)?
		|| archive_stamp(&named)? != expected
		|| archive_stamp(hot)? != expected
		|| !hot_snapshot_cached(hot)?
	{
		bail!("request hot snapshot changed during shared read");
	}
	Ok(())
}

pub(super) fn try_shared_pages(
	root: &Path,
	requests: &[SharedPageRequest],
	deadline: Instant,
) -> Result<Option<PageBatch>> {
	try_shared_pages_with_gate(
		root,
		requests,
		deadline,
		STORE_LOCK.get_or_init(AuditStoreLock::default),
	)
}

// Keep the same complete production body available to deterministic local-gate
// tests. The production wrapper always supplies the original global store gate.
fn try_shared_pages_with_gate(
	root: &Path,
	requests: &[SharedPageRequest],
	deadline: Instant,
	gate: &AuditStoreLock,
) -> Result<Option<PageBatch>> {
	if requests.is_empty() || requests.len() > MAX_METADATA_QUERIES {
		bail!("archive page group exceeded its admitted bound");
	}
	if !cfg!(target_os = "linux") {
		return Ok(None);
	}
	let mut trace = SteadyTrace::new("metadata_drain", Some(false));
	trace.enter(SteadyPhase::StoreLockWait);
	let guard = {
		let _trace = metadata_trace::Stage::new("store_lock_wait");
		gate.acquire_shared(deadline).map_err(shared_lock_failure)?
	};
	metadata_trace::mark("snapshot_lock_acquired", 0, 0);
	let base = audit_root(root)?;
	let Some(hot) = open_existing_store_at(&base)? else {
		return Ok(None);
	};
	let hot_stamp = archive_stamp(&hot)?;
	if !hot_snapshot_cached(&hot)? {
		return Ok(None);
	}
	let legacy = match open_at(&base, ARCHIVE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
		Ok(directory) => directory,
		Err(error) if shared_missing(&error) => return Ok(None),
		Err(error) => return Err(error),
	};
	private_directory(&legacy)?;
	let key = identity(&legacy)?;
	let Some(registry) = INDEXES.get() else {
		return Ok(None);
	};
	let slot = {
		let registry = registry
			.lock()
			.map_err(|_| anyhow!("archive index unavailable"))?;
		registry.iter().find(|slot| slot.identity == key).cloned()
	};
	let Some(slot) = slot else {
		return Ok(None);
	};
	// A cached flat archive can need the original open/load_layout recovery.
	// This pure classification precedes the first full layout fence; a real
	// error from the probe or any subsequent fence never becomes a cache miss.
	if slot.archive.needs_exclusive_open()? {
		return Ok(None);
	}
	slot.archive.fence_at(&base)?;
	let _metadata_read = slot.metadata_activity.enter();
	trace.enter(SteadyPhase::State);
	let snapshot = {
		let state = slot
			.state
			.lock()
			.map_err(|_| anyhow!("archive index unavailable"))?;
		let Some(snapshot) = SharedSnapshot::capture(&slot, &state)? else {
			return Ok(None);
		};
		snapshot
	};
	let mut queries = Vec::with_capacity(requests.len());
	{
		let _trace = metadata_trace::Stage::new("hot_snapshot_and_cursors");
		for request in requests {
			if Instant::now() >= deadline {
				return Err(MetadataQueryDeadline.into());
			}
			let cursor = if let Some(identity) = &request.after_id {
				let filename = format!("{identity}.json");
				// Only absence at the initial lookup is a local missing cursor.
				// All later original, namespace and policy failures are terminal
				// for this observation and cannot be erased by another fallback.
				match slot.archive.directory_for_existing(&filename) {
					Ok(_) => {}
					Err(error) if shared_missing(&error) => {
						queries.push(Err(error));
						continue;
					}
					Err(error) => return Err(error),
				}
				let Some(entry) = shared_original(&slot.archive, &filename, deadline)? else {
					return Ok(None);
				};
				if entry.record.owner != request.owner {
					queries.push(Err(anyhow!(
						"request archive cursor unavailable to this scope"
					)));
					continue;
				}
				Some(entry.record)
			} else {
				None
			};
			queries.push(Ok(PageQuery {
				owner: request.owner.clone(),
				cursor,
				limit: request.limit,
			}));
		}
	}
	trace.enter(SteadyPhase::SnapshotRead);
	let observed = if queries.iter().all(Result::is_err) {
		PageBatch {
			values: queries
				.into_iter()
				.map(|query| query.and_then(|_| bail!("archive page refusal coverage changed")))
				.collect(),
			large: false,
		}
	} else {
		#[cfg(test)]
		parallel_event(&slot, ParallelEvent::SharedScanStarted);
		let view = PendingView::default();
		{
			let _trace = metadata_trace::Stage::new("complete_original_verification");
			content::verify_members(&snapshot.database, &slot.archive, &view, deadline)?;
		}
		#[cfg(test)]
		parallel_event(&slot, ParallelEvent::SharedScanComplete);
		let _trace = metadata_trace::Stage::new("page_or_usage_projection");
		let transaction = snapshot.database.begin_read()?;
		let rows = transaction.open_table(ROWS)?;
		let order = transaction.open_table(ORDER)?;
		let counts = transaction.open_table(COUNTS)?;
		let large = rows.len()? > LARGE_ARCHIVE_ROWS;
		let mut values = Vec::with_capacity(queries.len());
		for query in queries {
			let query = match query {
				Ok(query) => query,
				Err(error) => {
					values.push(Err(error));
					continue;
				}
			};
			let (records, total) = page_from_view_with_reader(
				&rows,
				&order,
				&counts,
				&slot.archive,
				&view,
				&query.owner,
				query.cursor.as_ref(),
				query.limit,
				deadline,
				|archive, filename| {
					shared_original(archive, filename, deadline)?
						.map(|entry| entry.record)
						.ok_or_else(|| {
							anyhow!("archive staging appeared after shared verification")
						})
				},
			)?;
			// Only the initial local cursor refusals remain per-member. Once the
			// complete observation starts, no later failure can expose a sibling
			// success or return to the exclusive recovery path.
			values.push(Ok(archive_page_output(
				records,
				total,
				query.limit,
				deadline,
			)?));
		}
		PageBatch { values, large }
	};
	let _final_trace = metadata_trace::Stage::new("snapshot_final_fences");
	#[cfg(test)]
	parallel_event(&slot, ParallelEvent::BeforeSnapshotFence);
	let state = slot
		.state
		.lock()
		.map_err(|_| anyhow!("archive index unavailable"))?;
	snapshot.check(&slot, &state)?;
	let named_base = audit_root(root)?;
	if identity(&named_base)? != identity(&base)? {
		bail!("request audit root changed during shared read");
	}
	slot.archive.fence_at(&named_base)?;
	shared_hot_fence(&named_base, &hot, hot_stamp)?;
	// The final healthy/deadline observation and reservation release share one
	// queue critical section. State stays held across that linearization point;
	// no reader reservation escapes into Completion or permit publication.
	guard.finish().map_err(shared_lock_failure)?;
	trace.outcome = "shared";
	Ok(Some(observed))
}

pub(super) fn pages(
	root: &Path,
	archive: &Archive,
	queries: Vec<Result<PageQuery>>,
	deadline: Instant,
) -> Result<PageBatch> {
	if queries.is_empty() || queries.len() > MAX_METADATA_QUERIES {
		bail!("archive page group exceeded its admitted bound");
	}
	// Freeze happened before even the hot store or any cursor was opened.
	// All pages share one complete fresh Record join, one immutable transaction
	// and pending view. Large joins use the existing two owned readers; small
	// joins stay serial. Individual selected-record rereads are retained.
	read_snapshot_with_mode(
		root,
		archive,
		deadline,
		SnapshotReadMode::Pages,
		|database, view| {
			let transaction = database.begin_read()?;
			let rows = transaction.open_table(ROWS)?;
			let order = transaction.open_table(ORDER)?;
			let counts = transaction.open_table(COUNTS)?;
			let large = rows.len()? > LARGE_ARCHIVE_ROWS;
			let values = queries
				.into_iter()
				.map(|query| {
					query.and_then(|query| {
						let (records, total) = page_from_view(
							&rows,
							&order,
							&counts,
							archive,
							view,
							&query.owner,
							query.cursor.as_ref(),
							query.limit,
							deadline,
						)?;
						archive_page_output(records, total, query.limit, deadline)
					})
				})
				.collect();
			// No individual success is exposed until read_snapshot's original
			// final namespace/layout and absolute-deadline fences have succeeded.
			Ok(PageBatch { values, large })
		},
	)
}

#[allow(clippy::too_many_arguments)]
fn page_from_view(
	rows: &impl ReadableTable<&'static [u8], &'static [u8]>,
	order: &impl ReadableTable<&'static [u8], &'static [u8]>,
	counts: &impl ReadableTable<&'static [u8], u64>,
	archive: &Archive,
	view: &PendingView,
	owner: &str,
	cursor: Option<&Record>,
	limit: usize,
	deadline: Instant,
) -> Result<(Vec<Record>, u64)> {
	page_from_view_with_reader(
		rows,
		order,
		counts,
		archive,
		view,
		owner,
		cursor,
		limit,
		deadline,
		Archive::read_record,
	)
}

#[allow(clippy::too_many_arguments)]
fn page_from_view_with_reader(
	rows: &impl ReadableTable<&'static [u8], &'static [u8]>,
	order: &impl ReadableTable<&'static [u8], &'static [u8]>,
	counts: &impl ReadableTable<&'static [u8], u64>,
	archive: &Archive,
	view: &PendingView,
	owner: &str,
	cursor: Option<&Record>,
	limit: usize,
	deadline: Instant,
	read_record: impl Fn(&Archive, &str) -> Result<Record>,
) -> Result<(Vec<Record>, u64)> {
	let owner = id(owner)?;
	let mut low = [0u8; 80];
	low[..32].copy_from_slice(&owner);
	let mut high = [255u8; 80];
	high[..32].copy_from_slice(&owner);
	let lower = match cursor {
		Some(record) => std::ops::Bound::Excluded(order_key(record)?.to_vec()),
		None => std::ops::Bound::Included(low.to_vec()),
	};
	let upper = std::ops::Bound::Included(high.to_vec());
	if view.entries.is_empty() {
		// Preserve the original streaming page path when no overlay is needed.
		let mut result = Vec::with_capacity(limit + 1);
		for pair in order
			.range::<&[u8]>((
				lower.as_ref().map(|v| v.as_slice()),
				upper.as_ref().map(|v| v.as_slice()),
			))?
			.take(limit + 1)
		{
			if Instant::now() >= deadline {
				bail!("archive metadata query total deadline exceeded");
			}
			let (ordered_key, key) = pair?;
			let raw = rows
				.get(cold::order_identity(key.value())?)?
				.ok_or_else(|| anyhow!("archive index row missing"))?;
			let entry = codec::decode(raw.value())?;
			if ordered_key.value() != order_key(&entry.record)?
				|| key.value() != cold::order_value(&entry)?
			{
				bail!("archive order projection changed");
			}
			let filename = format!("{}.json", entry.record.request_id);
			let actual = read_record(archive, &filename)?;
			if actual != entry.record || stamp(archive, &filename)? != entry.stamp {
				bail!("archive page identity changed");
			}
			result.push(actual);
		}
		let count = total(counts, &owner)?.iter().sum();
		return Ok((result, count));
	}
	let mut selected = Vec::with_capacity(limit + 1 + view.entries.len());
	for pair in order.range::<&[u8]>((
		lower.as_ref().map(|v| v.as_slice()),
		upper.as_ref().map(|v| v.as_slice()),
	))? {
		if Instant::now() >= deadline {
			bail!("archive metadata query total deadline exceeded");
		}
		let (ordered_key, key) = pair?;
		let identity: Id = cold::order_identity(key.value())?.try_into()?;
		let raw = rows
			.get(identity.as_slice())?
			.ok_or_else(|| anyhow!("archive index row missing"))?;
		let entry = codec::decode(raw.value())?;
		let projected_key = order_key(&entry.record)?;
		if ordered_key.value() != projected_key || key.value() != cold::order_value(&entry)? {
			bail!("archive order projection changed");
		}
		if view.entries.contains_key(&identity) {
			continue;
		}
		selected.push((projected_key, entry));
		if selected.len() == limit + 1 {
			break;
		}
	}
	for entry in view.entries.values() {
		if Instant::now() >= deadline {
			bail!("archive metadata query total deadline exceeded");
		}
		if id(&entry.record.owner)? != owner {
			continue;
		}
		let key = order_key(&entry.record)?;
		if let std::ops::Bound::Excluded(after) = &lower {
			if key.as_slice() <= after.as_slice() {
				continue;
			}
		}
		selected.push((key, entry.clone()));
	}
	selected.sort_unstable_by_key(|entry| entry.0);
	let mut result = Vec::with_capacity(limit + 1);
	for (_, entry) in selected.into_iter().take(limit + 1) {
		if Instant::now() >= deadline {
			bail!("archive metadata query total deadline exceeded");
		}
		let filename = format!("{}.json", entry.record.request_id);
		let actual = read_record(archive, &filename)?;
		if actual != entry.record || stamp(archive, &filename)? != entry.stamp {
			bail!("archive page identity changed");
		}
		result.push(actual);
	}
	let count = view.totals(counts, &owner)?.iter().sum();
	Ok((result, count))
}
pub(super) struct UsageBatch {
	pub(super) values: Vec<Result<Value>>,
	pub(super) large: bool,
}

pub(super) fn usage(
	root: &Path,
	archive: &Archive,
	owners: &[String],
	deadline: Instant,
) -> Result<UsageBatch> {
	if owners.is_empty() || owners.len() > MAX_METADATA_QUERIES {
		bail!("usage query group exceeded its admitted bound");
	}
	read_snapshot_with_mode(
		root,
		archive,
		deadline,
		SnapshotReadMode::Usage,
		|database, view| usage_from_view(database, view, owners, deadline),
	)
}

fn usage_from_view(
	database: &Database,
	view: &PendingView,
	owners: &[String],
	deadline: Instant,
) -> Result<UsageBatch> {
	// Every owner projection uses this one transaction and pending view.
	// The surrounding snapshot retains full validation and the final fences.
	let transaction = database.begin_read()?;
	let rows = transaction.open_table(ROWS)?;
	let order = transaction.open_table(ORDER)?;
	let counts = transaction.open_table(COUNTS)?;
	let large = rows.len()? > LARGE_ARCHIVE_ROWS;
	let values = owners
		.iter()
		.map(|owner| usage_for_owner(&rows, &order, &counts, view, owner, deadline))
		.collect();
	// Local projection/wire errors stay in their own slots. A common final
	// fence error still rejects this entire, not-yet-published result.
	Ok(UsageBatch { values, large })
}

fn usage_for_owner(
	rows: &impl ReadableTable<&'static [u8], &'static [u8]>,
	order: &impl ReadableTable<&'static [u8], &'static [u8]>,
	counts: &impl ReadableTable<&'static [u8], u64>,
	view: &PendingView,
	owner: &str,
	deadline: Instant,
) -> Result<Value> {
	let owner_id = id(owner)?;
	let values = view.totals(counts, &owner_id)?;
	let mut active = 0u64;
	{
		let mut registry = active_registry()?;
		registry.retain(|_, marker| marker.strong_count() > 0);
		for (request_id, marker) in registry.iter() {
			if Instant::now() >= deadline {
				bail!("archive metadata query total deadline exceeded");
			}
			if marker.upgrade().is_some_and(|v| v.load(Ordering::Acquire)) {
				if let Some(entry) = view.entry(rows, &id(request_id)?)? {
					if entry.record.owner == owner && entry.record.state == DurableState::Unknown {
						active += 1;
					}
				}
			}
		}
	}
	let mut tools = BTreeMap::new();
	let mut prefix = owner_id.to_vec();
	prefix.push(b't');
	let mut bytes = 0;
	for pair in counts.range(prefix.as_slice()..)? {
		if Instant::now() >= deadline {
			bail!("archive metadata query total deadline exceeded");
		}
		let (key, count) = pair?;
		if !key.value().starts_with(&prefix) {
			break;
		}
		bytes += key.value().len() + 32;
		if bytes > MAX_PAGE_BYTES {
			bail!("usage tool count wire budget exceeded");
		}
		tools.insert(
			std::str::from_utf8(&key.value()[33..])?.to_owned(),
			count.value(),
		);
	}
	for (key, change) in &view.delta {
		if !key.starts_with(&prefix) || *change == 0 {
			continue;
		}
		let tool = std::str::from_utf8(&key[33..])?;
		let count = PendingView::changed_count(*tools.get(tool).unwrap_or(&0), *change)?;
		if count == 0 {
			tools.remove(tool);
		} else {
			tools.insert(tool.to_owned(), count);
		}
	}
	let mut low = [0u8; 80];
	low[..32].copy_from_slice(&owner_id);
	let mut high = [255u8; 80];
	high[..32].copy_from_slice(&owner_id);
	let mut ordered = order.range(low.as_slice()..=high.as_slice())?;
	let mut first = ordered
		.next()
		.transpose()?
		.map(|(k, _)| k.value()[32..48].try_into().map(u128::from_be_bytes))
		.transpose()?;
	let mut last = ordered
		.next_back()
		.transpose()?
		.map(|(k, _)| k.value()[32..48].try_into().map(u128::from_be_bytes))
		.transpose()?
		.or(first);
	// A publication never changes owner or accepted time and never deletes
	// an original. Pending additions can only extend these exact bounds.
	for entry in view.entries.values() {
		if entry.record.owner == owner {
			let time = entry.record.accepted_unix_ms;
			first = Some(first.map_or(time, |before| before.min(time)));
			last = Some(last.map_or(time, |before| before.max(time)));
		}
	}
	let unknown = values[0]
		.checked_sub(active)
		.ok_or_else(|| anyhow!("archive active count changed"))?;
	let value = json!({"schema":"hepta-private-usage-v1","total_requests":values.iter().sum::<u64>(),"completed":values[1],"failed":values[2],"unknown":unknown,"active":active,"tool_counts":tools,"first_accepted_unix_ms":first,"last_accepted_unix_ms":last,"retention":"archive_metadata_not_evicted_with_hot_cache","coverage":"metadata_retained_at_archive_introduction_and_subsequent_admitted_requests","semantics":"dispatch_observation_not_transport_delivery_or_business_success","contains_parameters_or_output":false,"scope":"same_verified_credential_or_native_session"});
	if wire_size(&value)? > MAX_PAGE_BYTES {
		bail!("usage statistics wire budget exceeded");
	}
	Ok(value)
}

#[cfg(test)]
#[path = "request_archive_index_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "request_archive_parallel_tests.rs"]
mod parallel_tests;

#[cfg(test)]
#[path = "request_usage_projection_tests.rs"]
mod usage_projection_tests;

#[cfg(test)]
#[path = "request_archive_page_batch_tests.rs"]
mod page_batch_tests;
