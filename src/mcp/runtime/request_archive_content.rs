// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Complete bounded Record observations; no cleanup, digest rebase or content lease.
use super::*;
use std::collections::BTreeSet;
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread::{Scope, ScopedJoinHandle};

#[derive(Clone, Copy)]
enum ContentPhase {
	Walk,
	Row,
	Order,
	Pending,
	Name,
	NamespaceBefore,
	StampBefore,
	Open,
	DescriptorBefore,
	Read,
	Parse,
	DescriptorAfter,
	StampAfter,
	NamespaceAfter,
	Compare,
}

const CONTENT_PHASE_NAMES: [&str; 15] = [
	"content_walk_and_fences_us",
	"content_row_lookup_us",
	"content_order_check_us",
	"content_pending_selection_us",
	"content_filename_us",
	"content_namespace_before_us",
	"content_stamp_before_us",
	"content_open_us",
	"content_descriptor_before_us",
	"content_body_read_us",
	"content_parse_and_domain_us",
	"content_descriptor_after_us",
	"content_stamp_after_us",
	"content_namespace_after_us",
	"content_compare_and_close_us",
];

// Static dispatch gives ordinary and parallel reads a zero-sized observer with
// no clocks, counters, allocation, or per-record channel operation.
trait ContentTrace {
	fn enter(&mut self, _phase: ContentPhase) {}
	fn attempt(&mut self) {}
	fn verified(&mut self) {}
	fn complete(&mut self) {}
}

struct UntracedContent;
impl ContentTrace for UntracedContent {}

struct ContentPhases {
	phase: ContentPhase,
	last: Instant,
	nanos: [u128; CONTENT_PHASE_NAMES.len()],
	attempted: u64,
	verified: u64,
	complete: bool,
}

impl ContentPhases {
	fn new() -> Self {
		Self::at(Instant::now())
	}

	fn at(now: Instant) -> Self {
		Self {
			phase: ContentPhase::Walk,
			last: now,
			nanos: [0; CONTENT_PHASE_NAMES.len()],
			attempted: 0,
			verified: 0,
			complete: false,
		}
	}

	fn advance(&mut self, now: Instant) {
		let elapsed = now.saturating_duration_since(self.last).as_nanos();
		let total = &mut self.nanos[self.phase as usize];
		*total = total.saturating_add(elapsed);
		self.last = now;
	}

	fn micros(&self) -> [u64; CONTENT_PHASE_NAMES.len()] {
		self.nanos
			.map(|value| (value / 1_000).min(u64::MAX as u128) as u64)
	}
}

impl ContentTrace for ContentPhases {
	fn enter(&mut self, phase: ContentPhase) {
		self.advance(Instant::now());
		self.phase = phase;
	}

	fn attempt(&mut self) {
		self.attempted = self.attempted.saturating_add(1);
	}

	fn verified(&mut self) {
		self.verified = self.verified.saturating_add(1);
	}

	fn complete(&mut self) {
		self.complete = true;
	}
}

impl Drop for ContentPhases {
	fn drop(&mut self) {
		self.advance(Instant::now());
		// Exactly eighteen bounded, nonblocking events per serial scan, including
		// errors and partial walks. Keep nanosecond sums until this final rounding;
		// rounding each tiny record operation would systematically lose its cost.
		for (phase, value) in CONTENT_PHASE_NAMES.into_iter().zip(self.micros()) {
			metadata_trace::mark(phase, 0, value);
		}
		metadata_trace::mark("content_members_attempted", 0, self.attempted);
		metadata_trace::mark("content_members_verified", 0, self.verified);
		metadata_trace::mark("content_scan_complete", 0, u64::from(self.complete));
	}
}

fn live(deadline: Instant) -> Result<()> {
	if Instant::now() >= deadline {
		bail!("archive metadata query total deadline exceeded");
	}
	Ok(())
}

fn descriptor_matches(file: &File, expected: FileStamp) -> Result<()> {
	// One fresh fstat establishes both the private-inode policy and the entire
	// expected stamp. Calling validate_file first repeated the same fstat;
	// pre-read and post-read observations still remain separate below.
	let metadata = file.metadata()?;
	if !metadata.is_file()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o600
		|| metadata.nlink() != 1
		|| metadata.len() > MAX_RECORD_BYTES as u64
	{
		bail!("private request audit inode refused");
	}
	#[cfg(any(target_os = "linux", target_os = "macos"))]
	let times = (
		(metadata.mtime(), metadata.mtime_nsec()),
		(metadata.ctime(), metadata.ctime_nsec()),
	);
	#[cfg(not(any(target_os = "linux", target_os = "macos")))]
	let times = ((metadata.mtime(), 0), (metadata.ctime(), 0));
	if metadata.dev() != expected.device
		|| metadata.ino() != expected.inode
		|| metadata.mode() != expected.mode
		|| metadata.uid() != expected.uid
		|| metadata.nlink() != expected.links
		|| metadata.len() != expected.length
		|| times != (expected.modified, expected.changed)
	{
		bail!("archive content descriptor changed");
	}
	Ok(())
}

// Deliberately do not call Archive::read_record: that recovery reader may unlink
// staging names. A complete validation walk refuses every staging member instead.
// Reading all bytes here establishes a Record observation, not a historical raw
// SHA comparison or an atomic snapshot against arbitrary concurrent writers.
fn read_original(
	archive: &Archive,
	directory: &File,
	filename: &str,
	deadline: Instant,
) -> Result<Entry> {
	read_original_with_trace(archive, directory, filename, deadline, &mut UntracedContent)
}

fn read_original_with_trace(
	archive: &Archive,
	directory: &File,
	filename: &str,
	deadline: Instant,
	trace: &mut impl ContentTrace,
) -> Result<Entry> {
	trace.enter(ContentPhase::Name);
	live(deadline)?;
	let raw_id = filename
		.strip_suffix(".json")
		.filter(|value| valid_id(value))
		.ok_or_else(|| anyhow!("invalid request metadata filename"))?;
	// Reuse only the owned name representation. Every pre/post namespace,
	// member and descriptor observation below remains independently fresh.
	let component = name(filename)?;
	trace.enter(ContentPhase::NamespaceBefore);
	archive.fence_record_component(&component, directory)?;
	trace.enter(ContentPhase::StampBefore);
	let before = stamp_at_component(directory, &component)?;
	trace.enter(ContentPhase::Open);
	let mut file = open_at_component(directory, &component, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	trace.enter(ContentPhase::DescriptorBefore);
	descriptor_matches(&file, before)?;
	trace.enter(ContentPhase::Read);
	let mut bytes = [0u8; MAX_RECORD_BYTES + 1];
	let mut length = 0;
	loop {
		live(deadline)?;
		let result = file.read(&mut bytes[length..]);
		live(deadline)?;
		let read = match result {
			Ok(read) => read,
			Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
			Err(error) => return Err(error.into()),
		};
		if read == 0 {
			break;
		}
		length += read;
		if length > MAX_RECORD_BYTES {
			bail!("request audit metadata size refused");
		}
	}
	if length as u64 != before.length {
		bail!("archive content length changed");
	}
	trace.enter(ContentPhase::Parse);
	let record: Record = serde_json::from_slice(&bytes[..length])?;
	if !valid_id(&record.request_id)
		|| !valid_id(&record.owner)
		|| !valid_tool(&record.tool_name)
		|| record.request_id != raw_id
	{
		bail!("request audit metadata identity refused");
	}
	trace.enter(ContentPhase::DescriptorAfter);
	descriptor_matches(&file, before)?;
	trace.enter(ContentPhase::StampAfter);
	if stamp_at_component(directory, &component)? != before {
		bail!("archive content member changed");
	}
	trace.enter(ContentPhase::NamespaceAfter);
	archive.fence_record_component(&component, directory)?;
	live(deadline)?;
	trace.enter(ContentPhase::Compare);
	Ok(Entry {
		record,
		stamp: before,
	})
}

fn original_name(filename: &str) -> Result<Id> {
	if staging(filename)? {
		bail!("archive content validation found unresolved staging");
	}
	let raw_id = filename
		.strip_suffix(".json")
		.filter(|value| valid_id(value))
		.ok_or_else(|| anyhow!("archive namespace changed"))?;
	id(raw_id)
}

// Borrow only the expected compact ROW within its original read transaction.
// Authoritative originals still undergo the complete read_original observation.
enum ExpectedRow<'a> {
	Compact(codec::View<'a>),
	Legacy(Entry),
}
impl<'a> ExpectedRow<'a> {
	fn parse(raw: &'a [u8]) -> Result<Self> {
		match codec::view_if_compact(raw)? {
			Some(value) => Ok(Self::Compact(value)),
			None => Ok(Self::Legacy(codec::decode(raw)?)),
		}
	}
	fn order_value(&self) -> Result<Id> {
		match self {
			Self::Compact(value) => Ok(value.identity),
			Self::Legacy(entry) => cold::order_value(entry),
		}
	}
	fn order_key(&self) -> Result<[u8; 80]> {
		match self {
			Self::Compact(value) => {
				let mut key = [0u8; 80];
				key[..32].copy_from_slice(&value.owner);
				key[32..48].copy_from_slice(&value.accepted.to_be_bytes());
				key[48..].copy_from_slice(&value.identity);
				Ok(key)
			}
			Self::Legacy(entry) => order_key(&entry.record),
		}
	}
	fn matches(&self, actual: &Entry) -> Result<bool> {
		match self {
			Self::Compact(value) => {
				// Exhaustive matching makes any future Record field a compile-time
				// obligation. id() retains the canonical lowercase identity domain;
				// decoded JSON escapes remain valid, uppercase aliases do not.
				let Record {
					request_id,
					owner,
					tool_name,
					state,
					accepted_unix_ms,
					elapsed_ms,
				} = &actual.record;
				Ok(id(request_id)? == value.identity
					&& id(owner)? == value.owner
					&& tool_name.as_str() == value.tool
					&& *state == value.state
					&& *accepted_unix_ms == value.accepted
					&& *elapsed_ms == value.elapsed
					&& actual.stamp == value.stamp)
			}
			Self::Legacy(entry) => Ok(actual.record == entry.record && actual.stamp == entry.stamp),
		}
	}
}

// The online caller holds STORE_LOCK and state. Cold validation instead fixes
// the generation/watch before and after this pass and refuses any overlap.
// The database view itself is immutable throughout this complete identity join.
pub(super) fn verify_members(
	database: &Database,
	archive: &Archive,
	view: &PendingView,
	deadline: Instant,
) -> Result<()> {
	verify_members_in_mode(database, archive, view, deadline, None)
}

// Online usage snapshots own the actual global store guard and state.
// Their large views use the bounded reader kernel; cold validation stays serial.
pub(super) fn verify_usage_members(
	database: &Database,
	archive: &Archive,
	view: &PendingView,
	deadline: Instant,
	guard: &AuditStoreGuard<'_>,
) -> Result<()> {
	verify_members_in_mode(database, archive, view, deadline, Some(guard))
}

// A fresh page cohort shares one complete serial observation. On the X230,
// passing tiny originals between reader threads costs more CPU than the reads.
// The caller still owns the store guard, and every original and final fence is
// checked by the same serial kernel used before page-reader parallelization.
pub(super) fn verify_page_members(
	database: &Database,
	archive: &Archive,
	view: &PendingView,
	deadline: Instant,
	_guard: &AuditStoreGuard<'_>,
) -> Result<()> {
	verify_members(database, archive, view, deadline)
}

fn verify_members_in_mode(
	database: &Database,
	archive: &Archive,
	view: &PendingView,
	deadline: Instant,
	online_guard: Option<&AuditStoreGuard<'_>>,
) -> Result<()> {
	live(deadline)?;
	let transaction = database.begin_read()?;
	let rows = transaction.open_table(ROWS)?;
	let order = transaction.open_table(ORDER)?;
	let base_count = rows.len()?;
	if order.len()? != base_count || view.entries.len() > QUERY_WRITE_CHUNK {
		bail!("archive content view coverage changed");
	}
	let mut expected_count = base_count;
	for key in view.entries.keys() {
		live(deadline)?;
		if rows.get(key.as_slice())?.is_none() {
			expected_count = expected_count
				.checked_add(1)
				.ok_or_else(|| anyhow!("archive index count overflow"))?;
		}
	}
	if let Some(guard) = online_guard.filter(|_| base_count > LARGE_ARCHIVE_ROWS) {
		return verify_members_parallel(
			archive,
			(&rows, &order),
			view,
			expected_count,
			deadline,
			guard,
		);
	}
	if metadata_trace::active() {
		verify_members_serial(
			archive,
			(&rows, &order),
			view,
			expected_count,
			deadline,
			&mut ContentPhases::new(),
		)
	} else {
		verify_members_serial(
			archive,
			(&rows, &order),
			view,
			expected_count,
			deadline,
			&mut UntracedContent,
		)
	}
}

fn verify_members_serial(
	archive: &Archive,
	(rows, order): (
		&impl ReadableTable<&'static [u8], &'static [u8]>,
		&impl ReadableTable<&'static [u8], &'static [u8]>,
	),
	view: &PendingView,
	expected_count: u64,
	deadline: Instant,
	trace: &mut impl ContentTrace,
) -> Result<()> {
	let mut seen_pending = BTreeSet::new();
	let mut observed = 0u64;
	archive.walk(|directory, filename, _| {
		let result = (|| {
			live(deadline)?;
			trace.attempt();
			trace.enter(ContentPhase::Row);
			let key = original_name(filename)?;
			// Keep this access guard alive through the full comparison below. No
			// borrowed ROW escapes this member or the immutable ROWS/ORDER view.
			let raw = rows.get(key.as_slice())?;
			let base = raw
				.as_ref()
				.map(|raw| ExpectedRow::parse(raw.value()))
				.transpose()?;
			trace.enter(ContentPhase::Order);
			if let Some(entry) = &base {
				let expected_order = entry.order_value()?;
				if expected_order != key
					|| order
						.get(entry.order_key()?.as_slice())?
						.is_none_or(|value| value.value() != expected_order)
				{
					bail!("archive order projection changed");
				}
			}
			// Validate the base before consulting its pending replacement. An
			// effective terminal row cannot conceal corrupt base bytes or ORDER.
			trace.enter(ContentPhase::Pending);
			let pending = view.entries.get(&key);
			if pending.is_some() {
				if !seen_pending.insert(key) {
					bail!("archive pending identity repeated");
				}
			} else if base.is_none() {
				bail!("archive namespace changed");
			}
			let actual = read_original_with_trace(archive, directory, filename, deadline, trace)?;
			let matches = match pending {
				Some(entry) => actual.record == entry.record && actual.stamp == entry.stamp,
				None => base
					.as_ref()
					.ok_or_else(|| anyhow!("archive namespace changed"))?
					.matches(&actual)?,
			};
			if !matches {
				bail!("archive full record content changed");
			}
			observed = observed
				.checked_add(1)
				.ok_or_else(|| anyhow!("archive index count overflow"))?;
			trace.verified();
			Ok(())
		})();
		trace.enter(ContentPhase::Walk);
		result
	})?;
	if observed != expected_count || seen_pending.len() != view.entries.len() {
		bail!("archive content view coverage changed");
	}
	live(deadline)?;
	trace.complete();
	Ok(())
}

const ORIGINAL_READ_WORKERS: usize = 2;
const ORIGINAL_READ_BATCH: usize = 32;

struct OriginalTask<'a> {
	number: u64,
	archive: &'a Archive,
	directory: &'a File,
	filename: String,
	expected: Entry,
	deadline: Instant,
}

struct OriginalBatch<'a> {
	first: u64,
	tasks: Vec<OriginalTask<'a>>,
}

#[derive(Debug)]
struct OriginalReply {
	first: u64,
	count: u64,
	verified: u64,
	result: Result<()>,
}

struct OriginalLane<'scope, 'env> {
	send: Option<SyncSender<OriginalBatch<'env>>>,
	receive: Option<Receiver<OriginalReply>>,
	thread: Option<ScopedJoinHandle<'scope, u64>>,
	pending: Vec<OriginalTask<'env>>,
	outstanding: Option<(u64, u64)>,
	verified: u64,
}

// Each lane owns at most 32 original tasks, including a coordinator-side partial
// batch. Pending tasks and an outstanding queued/running/unconsumed batch are
// mutually exclusive: receive the previous reply before filling the next batch.
// The two lanes therefore retain at most 64 tasks, not 64 plus a producer queue.
struct OriginalWorkers<'scope, 'env: 'scope> {
	lanes: [OriginalLane<'scope, 'env>; ORIGINAL_READ_WORKERS],
	cancelled: &'env AtomicBool,
	deadline: Instant,
	submitted: u64,
	verified: u64,
	#[cfg(test)]
	hook: Option<&'env (dyn Fn(OriginalWorkerEvent) + Sync)>,
	#[cfg(test)]
	fail_spawn_at: Option<usize>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OriginalWorkerEvent {
	BeforeSpawn(usize),
	Started(usize),
	BatchSubmitted(usize, u64, u64),
	CancellationStarted,
	Exiting(usize),
}

#[cfg(test)]
struct OriginalWorkerExit<'a> {
	hook: Option<&'a (dyn Fn(OriginalWorkerEvent) + Sync)>,
	lane: usize,
}

#[cfg(test)]
impl Drop for OriginalWorkerExit<'_> {
	fn drop(&mut self) {
		if let Some(hook) = self.hook {
			hook(OriginalWorkerEvent::Exiting(self.lane));
		}
	}
}

impl<'scope, 'env: 'scope> OriginalWorkers<'scope, 'env> {
	fn new(cancelled: &'env AtomicBool, deadline: Instant) -> Self {
		Self {
			lanes: std::array::from_fn(|_| OriginalLane {
				send: None,
				receive: None,
				thread: None,
				pending: Vec::new(),
				outstanding: None,
				verified: 0,
			}),
			cancelled,
			deadline,
			submitted: 0,
			verified: 0,
			#[cfg(test)]
			hook: None,
			#[cfg(test)]
			fail_spawn_at: None,
		}
	}

	fn start<F>(&mut self, scope: &'scope Scope<'scope, 'env>, perform: &'env F) -> Result<()>
	where
		F: Fn(OriginalTask<'env>) -> Result<()> + Sync,
	{
		// Self already owns cleanup before even the first spawn. No receiver or
		// sender is cloned; dropping these coordinator ends unblocks both sides.
		for lane in 0..ORIGINAL_READ_WORKERS {
			live(self.deadline)?;
			#[cfg(test)]
			if let Some(hook) = self.hook {
				hook(OriginalWorkerEvent::BeforeSpawn(lane));
			}
			#[cfg(test)]
			if self.fail_spawn_at == Some(lane) {
				return Err(
					std::io::Error::other("synthetic original worker spawn failure").into(),
				);
			}
			let (send_job, receive_job) = std::sync::mpsc::sync_channel::<OriginalBatch<'env>>(1);
			let (send_result, receive_result) = std::sync::mpsc::sync_channel(1);
			self.lanes[lane].send = Some(send_job);
			self.lanes[lane].receive = Some(receive_result);
			let cancelled = self.cancelled;
			let deadline = self.deadline;
			#[cfg(test)]
			let hook = self.hook;
			self.lanes[lane].thread = Some(
				std::thread::Builder::new()
					.name(format!("archive-original-{lane}"))
					.spawn_scoped(scope, move || {
						#[cfg(test)]
						let _exit = OriginalWorkerExit { hook, lane };
						#[cfg(test)]
						if let Some(hook) = hook {
							hook(OriginalWorkerEvent::Started(lane));
						}
						let mut reported = 0u64;
						while let Ok(batch) = receive_job.recv() {
							if cancelled.load(Ordering::Acquire) {
								break;
							}
							let reply = perform_original_batch(batch, cancelled, deadline, perform);
							let verified = reply.verified;
							let failed = reply.result.is_err();
							if send_result.send(reply).is_err() {
								break;
							}
							// Every verified prefix lies within checked, non-wrapping
							// submitted record numbers, even when a batch fails.
							reported += verified;
							if failed {
								break;
							}
						}
						reported
					})?,
			);
		}
		Ok(())
	}

	fn receive(&mut self, lane: usize) -> Result<()> {
		let Some((first, count)) = self.lanes[lane].outstanding.take() else {
			return Ok(());
		};
		live(self.deadline)?;
		let reply = self.lanes[lane]
			.receive
			.as_ref()
			.ok_or_else(|| anyhow!("archive original worker result unavailable"))?
			.recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
			.map_err(|error| {
				anyhow::Error::new(error).context("archive original worker result unavailable")
			})?;
		if reply.first != first || reply.count != count {
			bail!("archive original worker task identity changed");
		}
		// Preserve the actual original-read error, including its source chain;
		// subsequent cancellation/disconnect/join bookkeeping cannot replace it.
		reply.result?;
		if reply.verified != count {
			bail!("archive original worker completion changed");
		}
		live(self.deadline)?;
		self.lanes[lane].verified = self.lanes[lane]
			.verified
			.checked_add(count)
			.ok_or_else(|| anyhow!("archive original worker count overflow"))?;
		self.verified = self
			.verified
			.checked_add(count)
			.ok_or_else(|| anyhow!("archive original worker count overflow"))?;
		Ok(())
	}

	// Called before producing the next expected Entry as well as by submit.
	// Do not hold an extra admitted record while both 32-record lanes are full.
	fn ready_for_record(&mut self) -> Result<usize> {
		let lane =
			((self.submitted / ORIGINAL_READ_BATCH as u64) % ORIGINAL_READ_WORKERS as u64) as usize;
		if self.lanes[lane].pending.is_empty() {
			self.receive(lane)?;
		}
		live(self.deadline)?;
		if self.cancelled.load(Ordering::Acquire) {
			bail!("archive original worker cancelled");
		}
		if self.lanes[lane].outstanding.is_some()
			|| self.lanes[lane].pending.len() >= ORIGINAL_READ_BATCH
		{
			bail!("archive original worker input coverage changed");
		}
		Ok(lane)
	}

	fn dispatch(&mut self, lane: usize) -> Result<()> {
		let count = self.lanes[lane].pending.len();
		if count == 0 {
			return Ok(());
		}
		live(self.deadline)?;
		if self.cancelled.load(Ordering::Acquire) {
			bail!("archive original worker cancelled");
		}
		if count > ORIGINAL_READ_BATCH || self.lanes[lane].outstanding.is_some() {
			bail!("archive original worker input coverage changed");
		}
		let first = self.lanes[lane].pending[0].number;
		let batch = OriginalBatch {
			first,
			tasks: std::mem::take(&mut self.lanes[lane].pending),
		};
		let sender = self.lanes[lane]
			.send
			.as_ref()
			.ok_or_else(|| anyhow!("archive original worker input unavailable"))?;
		// Filling the batch already consumed this lane's previous reply. Its
		// capacity-one channel must have room; never add an unbounded send wait.
		if sender.try_send(batch).is_err() {
			bail!("archive original worker input unavailable");
		}
		self.lanes[lane].outstanding = Some((first, count as u64));
		#[cfg(test)]
		if let Some(hook) = self.hook {
			hook(OriginalWorkerEvent::BatchSubmitted(
				lane,
				first,
				count as u64,
			));
		}
		Ok(())
	}

	fn submit(
		&mut self,
		archive: &'env Archive,
		directory: &'env File,
		filename: &str,
		expected: Entry,
	) -> Result<()> {
		let lane = self.ready_for_record()?;
		let next = self
			.submitted
			.checked_add(1)
			.ok_or_else(|| anyhow!("archive original worker count overflow"))?;
		let task = OriginalTask {
			number: self.submitted,
			archive,
			directory,
			filename: filename.to_owned(),
			expected,
			deadline: self.deadline,
		};
		if self.lanes[lane].pending.is_empty() {
			self.lanes[lane].pending.reserve_exact(ORIGINAL_READ_BATCH);
		}
		self.lanes[lane].pending.push(task);
		self.submitted = next;
		if self.lanes[lane].pending.len() == ORIGINAL_READ_BATCH {
			self.dispatch(lane)?;
		}
		Ok(())
	}

	fn finish(&mut self, expected_count: u64) -> Result<()> {
		metadata_trace::mark("reader_finish", 0, self.submitted);
		// A nonempty partial tail must run through the same original readers
		// before coverage, joins and the walk's terminal namespace fences.
		for lane in 0..ORIGINAL_READ_WORKERS {
			self.dispatch(lane)?;
		}
		for lane in 0..ORIGINAL_READ_WORKERS {
			self.receive(lane)?;
		}
		if self.verified != self.submitted || self.verified != expected_count {
			bail!("archive content view coverage changed");
		}
		self.stop_and_join()?;
		live(self.deadline)
	}

	fn stop_and_join(&mut self) -> Result<()> {
		let _trace = metadata_trace::Stage::new("original_reader_join");
		self.cancelled.store(true, Ordering::Release);
		#[cfg(test)]
		if let Some(hook) = self.hook {
			hook(OriginalWorkerEvent::CancellationStarted);
		}
		for lane in &mut self.lanes {
			drop(lane.send.take());
			drop(lane.receive.take());
			// Never turn producer failure, timeout or unwind into new reads.
			lane.pending.clear();
		}
		let mut failure = None;
		let mut panics: [Option<Box<dyn std::any::Any + Send>>; ORIGINAL_READ_WORKERS] =
			std::array::from_fn(|_| None);
		for (lane, panic) in self.lanes.iter_mut().zip(&mut panics) {
			if let Some(thread) = lane.thread.take() {
				match thread.join() {
					Ok(reported) => {
						if reported != lane.verified && failure.is_none() {
							failure = Some(anyhow!("archive original worker completion changed"));
						}
					}
					Err(payload) => *panic = Some(payload),
				}
			}
		}
		metadata_trace::mark("original_readers_joined", 0, self.verified);
		// All children and their I/O have ended. A worker panic must still
		// unwind through the original coordinator's STORE_LOCK/state guards,
		// preserving their poisoning. Never start a second coordinator unwind.
		let panic = if std::thread::panicking() {
			None
		} else {
			panics.iter_mut().find_map(Option::take)
		};
		if let Some(payload) = panic {
			std::panic::resume_unwind(payload);
		}
		match failure {
			Some(error) => Err(error),
			None => Ok(()),
		}
	}
}

impl Drop for OriginalWorkers<'_, '_> {
	fn drop(&mut self) {
		// This also covers visit errors, deadline, unwind and partial spawn.
		// Secondary cleanup errors must not replace the primary read error.
		let _ = self.stop_and_join();
	}
}

fn perform_original_batch<'a, F>(
	batch: OriginalBatch<'a>,
	cancelled: &AtomicBool,
	deadline: Instant,
	perform: &F,
) -> OriginalReply
where
	F: Fn(OriginalTask<'a>) -> Result<()> + Sync,
{
	let first = batch.first;
	let count = batch.tasks.len() as u64;
	let mut verified = 0u64;
	let result = (|| {
		if count == 0 || count > ORIGINAL_READ_BATCH as u64 || first.checked_add(count).is_none() {
			bail!("archive original worker batch coverage changed");
		}
		for (offset, task) in batch.tasks.into_iter().enumerate() {
			if cancelled.load(Ordering::Acquire) {
				bail!("archive original worker cancelled");
			}
			live(deadline)?;
			if task.number != first + offset as u64 || task.deadline != deadline {
				bail!("archive original worker task identity changed");
			}
			// Keep each task's own directory and the exact original error chain.
			// A failed prefix is never reported or credited as a complete batch.
			perform(task)?;
			live(deadline)?;
			if cancelled.load(Ordering::Acquire) {
				bail!("archive original worker cancelled");
			}
			verified += 1;
		}
		Ok(())
	})();
	OriginalReply {
		first,
		count,
		verified,
		result,
	}
}

fn verify_original_task(task: OriginalTask<'_>) -> Result<()> {
	let actual = read_original(task.archive, task.directory, &task.filename, task.deadline)?;
	if actual.record != task.expected.record || actual.stamp != task.expected.stamp {
		bail!("archive full record content changed");
	}
	Ok(())
}

fn verify_members_parallel(
	archive: &Archive,
	(rows, order): (
		&impl ReadableTable<&'static [u8], &'static [u8]>,
		&impl ReadableTable<&'static [u8], &'static [u8]>,
	),
	view: &PendingView,
	expected_count: u64,
	deadline: Instant,
	_guard: &AuditStoreGuard<'_>,
) -> Result<()> {
	let cancelled = AtomicBool::new(false);
	let _trace = metadata_trace::Stage::new("original_parallel_walk_and_fences");
	std::thread::scope(|scope| {
		let mut state = (OriginalWorkers::new(&cancelled, deadline), BTreeSet::new());
		state.0.start(scope, &verify_original_task)?;
		archive.walk_with_finish(
			&mut state,
			|(workers, seen_pending), directory, filename, _| {
				// Admit space before decoding/cloning this expected record. No
				// additional producer batch accumulates behind two full lanes.
				workers.ready_for_record()?;
				let key = original_name(filename)?;
				let base = rows
					.get(key.as_slice())?
					.map(|raw| codec::decode(raw.value()))
					.transpose()?;
				if let Some(entry) = &base {
					let expected_order = cold::order_value(entry)?;
					if id(&entry.record.request_id)? != key
						|| order
							.get(order_key(&entry.record)?.as_slice())?
							.is_none_or(|value| value.value() != expected_order)
					{
						bail!("archive order projection changed");
					}
				}
				let expected = match view.entries.get(&key) {
					Some(entry) => {
						if !seen_pending.insert(key) {
							bail!("archive pending identity repeated");
						}
						entry.clone()
					}
					None => base.ok_or_else(|| anyhow!("archive namespace changed"))?,
				};
				workers.submit(archive, directory, filename, expected)
			},
			|(workers, seen_pending)| {
				if seen_pending.len() != view.entries.len() {
					bail!("archive content view coverage changed");
				}
				// Actual task coverage and joins precede the walk's full terminal
				// namespace fence, for both flat and sharded archive layouts.
				workers.finish(expected_count)
			},
		)?;
		live(deadline)
	})
}

struct ColdFence {
	version: Option<super::super::super::namespace_version::Version>,
	generation: u64,
}
impl ColdFence {
	fn capture(slot: &Slot, deadline: Instant) -> Result<Self> {
		let _guard = query_lock(deadline)?;
		let state = slot
			.state
			.lock()
			.map_err(|_| anyhow!("archive index unavailable"))?;
		let fence = Self {
			version: state.version,
			generation: state.generation,
		};
		fence.check_locked(slot, &state, deadline)?;
		Ok(fence)
	}
	fn check_locked(&self, slot: &Slot, state: &State, deadline: Instant) -> Result<()> {
		live(deadline)?;
		if state.failed
			|| state.retired
			|| state.generation != self.generation
			|| state.version != self.version
			|| content_version(&slot.archive)? != self.version
		{
			return Err(ColdEpochChanged.into());
		}
		Ok(())
	}
	fn check(&self, slot: &Slot, deadline: Instant) -> Result<()> {
		let _guard = query_lock(deadline)?;
		let state = slot
			.state
			.lock()
			.map_err(|_| anyhow!("archive index unavailable"))?;
		self.check_locked(slot, &state, deadline)
	}
}

// Complete reads may discover a legal original publication ahead of its cache
// even when its stamp happens to equal the old row. Feed only changed entries
// through the original bounded apply/identity/terminal/fingerprint rules, then
// check the resulting complete view. No whole scan holds STORE_LOCK; concurrent
// local publications invalidate the captured generation, including with None.
pub(super) fn validate_cached(slot: &Slot, database: &Database, deadline: Instant) -> Result<()> {
	let fence = ColdFence::capture(slot, deadline)?;
	let transaction = database.begin_read()?;
	let rows = transaction.open_table(ROWS)?;
	let mut changes = Vec::with_capacity(BUILD_CHUNK);
	slot.archive.walk(|directory, filename, _| {
		live(deadline)?;
		let key = original_name(filename)?;
		let actual = read_original(&slot.archive, directory, filename, deadline)?;
		let prior = rows
			.get(key.as_slice())?
			.map(|raw| codec::decode(raw.value()))
			.transpose()?;
		if prior.is_none_or(|old| old.record != actual.record || old.stamp != actual.stamp) {
			changes.push(actual);
		}
		if changes.len() == BUILD_CHUNK {
			fence.check(slot, deadline)?;
			apply(database, std::mem::take(&mut changes), None, false)?;
			fence.check(slot, deadline)?;
		}
		Ok(())
	})?;
	drop(rows);
	drop(transaction);
	fence.check(slot, deadline)?;
	apply(database, changes, None, false)?;
	fence.check(slot, deadline)?;
	verify_members(database, &slot.archive, &PendingView::default(), deadline)?;
	fence.check(slot, deadline)
}

#[cfg(test)]
#[path = "request_archive_content_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "request_archive_content_parallel_tests.rs"]
mod parallel_tests;
