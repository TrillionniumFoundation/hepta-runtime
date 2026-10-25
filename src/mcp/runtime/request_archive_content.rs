// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Complete bounded Record observations; no cleanup, digest rebase or content lease.
use super::*;
use std::collections::BTreeSet;
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread::{Scope, ScopedJoinHandle};

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
	live(deadline)?;
	let raw_id = filename
		.strip_suffix(".json")
		.filter(|value| valid_id(value))
		.ok_or_else(|| anyhow!("invalid request metadata filename"))?;
	archive.fence_record(filename, directory)?;
	let before = stamp_at(directory, filename)?;
	let mut file = open_at(directory, filename, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	descriptor_matches(&file, before)?;
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
	let record: Record = serde_json::from_slice(&bytes[..length])?;
	if !valid_id(&record.request_id)
		|| !valid_id(&record.owner)
		|| !valid_tool(&record.tool_name)
		|| record.request_id != raw_id
	{
		bail!("request audit metadata identity refused");
	}
	descriptor_matches(&file, before)?;
	if stamp_at(directory, filename)? != before {
		bail!("archive content member changed");
	}
	archive.fence_record(filename, directory)?;
	live(deadline)?;
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

// Only the usage snapshot calls this entry, while it owns the actual global
// store guard and state. Cold validation and page reads retain the serial gate.
pub(super) fn verify_usage_members(
	database: &Database,
	archive: &Archive,
	view: &PendingView,
	deadline: Instant,
	guard: &AuditStoreGuard<'_>,
) -> Result<()> {
	verify_members_in_mode(database, archive, view, deadline, Some(guard))
}

fn verify_members_in_mode(
	database: &Database,
	archive: &Archive,
	view: &PendingView,
	deadline: Instant,
	usage_guard: Option<&AuditStoreGuard<'_>>,
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
	if let Some(guard) = usage_guard.filter(|_| base_count > LARGE_ARCHIVE_ROWS) {
		return verify_members_parallel(
			archive,
			(&rows, &order),
			view,
			expected_count,
			deadline,
			guard,
		);
	}
	let mut seen_pending = BTreeSet::new();
	let mut observed = 0u64;
	archive.walk(|directory, filename, _| {
		live(deadline)?;
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
				entry
			}
			None => base
				.as_ref()
				.ok_or_else(|| anyhow!("archive namespace changed"))?,
		};
		let actual = read_original(archive, directory, filename, deadline)?;
		if actual.record != expected.record || actual.stamp != expected.stamp {
			bail!("archive full record content changed");
		}
		observed = observed
			.checked_add(1)
			.ok_or_else(|| anyhow!("archive index count overflow"))?;
		Ok(())
	})?;
	if observed != expected_count || seen_pending.len() != view.entries.len() {
		bail!("archive content view coverage changed");
	}
	live(deadline)
}

const ORIGINAL_READ_WORKERS: usize = 2;

struct OriginalTask<'a> {
	number: u64,
	archive: &'a Archive,
	directory: &'a File,
	filename: String,
	expected: Entry,
	deadline: Instant,
}

struct OriginalReply {
	number: u64,
	result: Result<()>,
}

struct OriginalLane<'scope, 'env> {
	send: Option<SyncSender<OriginalTask<'env>>>,
	receive: Option<Receiver<OriginalReply>>,
	thread: Option<ScopedJoinHandle<'scope, u64>>,
	outstanding: Option<u64>,
	verified: u64,
}

// A lane includes both a queued/running job and its unconsumed result. Its next
// job cannot be submitted until that one result has been consumed successfully.
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
			let (send_job, receive_job) = std::sync::mpsc::sync_channel::<OriginalTask<'env>>(1);
			let (send_result, receive_result) = std::sync::mpsc::sync_channel(1);
			self.lanes[lane].send = Some(send_job);
			self.lanes[lane].receive = Some(receive_result);
			let cancelled = self.cancelled;
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
						while let Ok(task) = receive_job.recv() {
							if cancelled.load(Ordering::Acquire) {
								break;
							}
							let number = task.number;
							let result = perform(task);
							let failed = result.is_err();
							if send_result.send(OriginalReply { number, result }).is_err() {
								break;
							}
							// Each reply belongs to a checked, non-wrapping submitted
							// number; neither lane can report more than that bound.
							reported += 1;
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
		let Some(number) = self.lanes[lane].outstanding.take() else {
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
		if reply.number != number {
			bail!("archive original worker task identity changed");
		}
		// Preserve the actual original-read error, including its source chain;
		// subsequent cancellation/disconnect/join bookkeeping cannot replace it.
		reply.result?;
		live(self.deadline)?;
		self.lanes[lane].verified = self.lanes[lane]
			.verified
			.checked_add(1)
			.ok_or_else(|| anyhow!("archive original worker count overflow"))?;
		self.verified = self
			.verified
			.checked_add(1)
			.ok_or_else(|| anyhow!("archive original worker count overflow"))?;
		Ok(())
	}

	fn submit(
		&mut self,
		archive: &'env Archive,
		directory: &'env File,
		filename: &str,
		expected: Entry,
	) -> Result<()> {
		let lane = (self.submitted % ORIGINAL_READ_WORKERS as u64) as usize;
		self.receive(lane)?;
		live(self.deadline)?;
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
		let sender = self.lanes[lane]
			.send
			.as_ref()
			.ok_or_else(|| anyhow!("archive original worker input unavailable"))?;
		// The previous result was consumed, so this lane's capacity-one input
		// must have room. Never add an unbounded send wait to the caller budget.
		if sender.try_send(task).is_err() {
			bail!("archive original worker input unavailable");
		}
		self.lanes[lane].outstanding = Some(self.submitted);
		self.submitted = next;
		Ok(())
	}

	fn finish(&mut self, expected_count: u64) -> Result<()> {
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
		self.cancelled.store(true, Ordering::Release);
		for lane in &mut self.lanes {
			drop(lane.send.take());
			drop(lane.receive.take());
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
	std::thread::scope(|scope| {
		let mut state = (OriginalWorkers::new(&cancelled, deadline), BTreeSet::new());
		state.0.start(scope, &verify_original_task)?;
		archive.walk_with_finish(
			&mut state,
			|(workers, seen_pending), directory, filename, _| {
				live(deadline)?;
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
