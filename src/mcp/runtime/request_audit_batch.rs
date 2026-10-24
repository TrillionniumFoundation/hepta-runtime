// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Optional bounded audit cohorts. Every file still syncs; archive directory
//! barriers precede hot publication, and every acknowledgement follows both.
use super::*;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{mpsc, Condvar};
use std::thread::JoinHandle;

const MAX_BATCH: usize = 32;
const MAX_QUEUED: usize = 128;
static COORDINATOR: OnceLock<Coordinator> = OnceLock::new();

struct Begin {
	root: PathBuf,
	owner: String,
	tool: String,
	target: Option<String>,
}
enum Work {
	Begin(Begin),
	Finish(PathBuf, RequestTicket, AuditCompletion),
}
impl Work {
	fn key(&self) -> (&Path, bool) {
		match self {
			Self::Begin(spec) => (&spec.root, true),
			Self::Finish(root, ..) => (root, false),
		}
	}
}
enum Outcome {
	Begun(RequestTicket),
	Finished,
}
struct Job {
	work: Work,
	reply: mpsc::Sender<Result<Outcome>>,
}
#[derive(Default)]
struct Pending {
	jobs: VecDeque<Job>,
	closed: bool,
	running: bool,
}
#[derive(Default)]
struct Queue {
	pending: Mutex<Pending>,
	ready: Condvar,
}
type Processor = Arc<dyn Fn(Vec<Work>) -> Vec<Result<Outcome>> + Send + Sync>;
pub(super) struct Coordinator {
	queue: Arc<Queue>,
	processor: Processor,
	worker: Option<JoinHandle<()>>,
}

pub(super) fn coordinator() -> Option<&'static Coordinator> {
	COORDINATOR.get()
}
pub(super) fn enable() -> Result<()> {
	let worker = Coordinator::new()?;
	COORDINATOR
		.set(worker)
		.map_err(|_| anyhow!("audit group coordinator already initialized"))
}
fn failures(count: usize) -> Vec<Result<Outcome>> {
	(0..count)
		.map(|_| Err(anyhow!("audit cohort durability unavailable; never replay")))
		.collect()
}
impl Queue {
	fn completed(&self) {
		let mut pending = match self.pending.lock() {
			Ok(value) => value,
			Err(poisoned) => {
				drop(poisoned.into_inner());
				self.close();
				return;
			}
		};
		pending.running = false;
		let wake = !pending.jobs.is_empty();
		drop(pending);
		if wake {
			self.ready.notify_one();
		}
	}
	fn close(&self) {
		let mut pending = match self.pending.lock() {
			Ok(value) => value,
			Err(poisoned) => poisoned.into_inner(),
		};
		pending.closed = true;
		for job in pending.jobs.drain(..) {
			let _ = job
				.reply
				.send(Err(anyhow!("audit coordinator closed; never replay")));
		}
		drop(pending);
		self.ready.notify_all();
	}
	fn take(&self) -> Result<Option<Vec<Job>>> {
		let mut pending = self
			.pending
			.lock()
			.map_err(|_| anyhow!("audit queue unavailable"))?;
		while (pending.running || pending.jobs.is_empty()) && !pending.closed {
			pending = self
				.ready
				.wait(pending)
				.map_err(|_| anyhow!("audit queue unavailable"))?;
		}
		if pending.closed || pending.jobs.is_empty() {
			return Ok(None);
		}
		// File synchronization naturally accumulates backlog. Process the
		// oldest same-root prefix immediately. Interleaved admissions and
		// completions share the same two barriers without changing FIFO order.
		let Some(first) = pending.jobs.front() else {
			return Ok(None);
		};
		let (root, _) = first.work.key();
		let root = root.to_owned();
		let mut cohort = Vec::with_capacity(MAX_BATCH);
		while cohort.len() < MAX_BATCH
			&& pending
				.jobs
				.front()
				.is_some_and(|job| job.work.key().0 == root)
		{
			if let Some(job) = pending.jobs.pop_front() {
				cohort.push(job);
			}
		}
		pending.running = true;
		Ok(Some(cohort))
	}
}
impl Coordinator {
	pub(super) fn is_ready(&self) -> bool {
		stage::is_ready()
			&& self
				.queue
				.pending
				.lock()
				.is_ok_and(|pending| !pending.closed)
	}
	fn new() -> Result<Self> {
		Self::with_processor(Arc::new(|works| {
			let count = works.len();
			trace::measure("cohort_execute", count, None, || {
				execute(works, &mut |directory, _| {
					directory.sync_all()?;
					Ok(())
				})
			})
			.unwrap_or_else(|_| failures(count))
		}))
	}
	fn with_processor(processor: Processor) -> Result<Self> {
		let queue = Arc::new(Queue::default());
		let state = queue.clone();
		let background = processor.clone();
		let worker = std::thread::Builder::new()
			.name("audit-group-commit".into())
			.spawn(move || {
				// A worker panic closes queued waiters instead of stranding them. A
				// dropped in-progress reply also refuses; it never authorizes replay.
				let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
					while let Some(cohort) = state.take()? {
						let (works, senders): (Vec<_>, Vec<_>) =
							cohort.into_iter().map(|job| (job.work, job.reply)).unzip();
						let mut outcomes = process(&state, &background, works).into_iter();
						for sender in senders {
							let value = outcomes
								.next()
								.unwrap_or_else(|| Err(anyhow!("audit cohort result unavailable")));
							let _ = sender.send(value);
						}
						state.completed();
					}
					Ok(())
				}));
				state.close();
			})?;
		Ok(Self {
			queue,
			processor,
			worker: Some(worker),
		})
	}
	fn submit(&self, work: Work) -> Result<Outcome> {
		let total = trace::Span::new("coordinator_submit", 1, Some(0));
		let mut pending = trace::measure("coordinator_queue_lock", 1, Some(0), || {
			self.queue
				.pending
				.lock()
				.map_err(|_| anyhow!("audit queue unavailable"))
		})?;
		if pending.closed || pending.jobs.len() >= MAX_QUEUED {
			bail!("audit queue closed or full; no automatic replay");
		}
		// The caller already runs on a blocking pool. Claim the same serial
		// processor when idle, avoiding a second thread handoff for C1. Backlog
		// always goes through the FIFO worker; it cannot be overtaken here.
		if !pending.running && pending.jobs.is_empty() {
			pending.running = true;
			drop(pending);
			let result = process(&self.queue, &self.processor, vec![work])
				.into_iter()
				.next()
				.unwrap_or_else(|| Err(anyhow!("audit cohort result unavailable")));
			self.queue.completed();
			return total.finish(result);
		}
		let (reply, receive) = mpsc::channel();
		pending.jobs.push_back(Job { work, reply });
		drop(pending);
		self.queue.ready.notify_one();
		let result = trace::measure("coordinator_reply_wait", 1, Some(0), || {
			receive
				.recv()
				.map_err(|_| anyhow!("audit acknowledgement unavailable; never replay"))?
		});
		total.finish(result)
	}
	pub(super) fn begin(
		&self,
		root: PathBuf,
		owner: String,
		tool: String,
		target: Option<String>,
	) -> Result<RequestTicket> {
		if !valid_id(&owner)
			|| !valid_tool(&tool)
			|| target.as_deref().is_some_and(|id| !valid_id(id))
		{
			bail!("invalid bounded audit admission");
		}
		match self.submit(Work::Begin(Begin {
			root,
			owner,
			tool,
			target,
		}))? {
			Outcome::Begun(ticket) => Ok(ticket),
			Outcome::Finished => bail!("audit acknowledgement type mismatch"),
		}
	}
	pub(super) fn finish(
		&self,
		root: PathBuf,
		ticket: RequestTicket,
		completion: AuditCompletion,
	) -> Result<()> {
		match self.submit(Work::Finish(root, ticket, completion))? {
			Outcome::Finished => Ok(()),
			Outcome::Begun(_) => bail!("audit acknowledgement type mismatch"),
		}
	}
}

fn process(queue: &Queue, processor: &Processor, works: Vec<Work>) -> Vec<Result<Outcome>> {
	let count = works.len();
	match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| processor(works))) {
		Ok(values) if values.len() == count => values,
		Ok(_) => {
			trace::Span::new("cohort_processor_result_count", count, None).record(Some(&anyhow!(
				"audit cohort durability unavailable; never replay"
			)));
			queue.close();
			failures(count)
		}
		Err(_) => {
			trace::Span::new("cohort_processor_panic", count, None).record(Some(&anyhow!(
				"audit cohort durability unavailable; never replay"
			)));
			queue.close();
			failures(count)
		}
	}
}
impl Drop for Coordinator {
	fn drop(&mut self) {
		self.queue.close();
		if let Some(worker) = self.worker.take() {
			let _ = worker.join();
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Barrier {
	Archive,
	Hot,
}

fn directory_identity(directory: &File) -> Result<(u64, u64)> {
	use std::os::unix::fs::MetadataExt;
	let metadata = private_directory_metadata(directory)?;
	Ok((metadata.dev(), metadata.ino()))
}

fn same_directory(left: &File, right: &File) -> Result<()> {
	// Identity fences need ownership and inode checks, not a namespace-cache
	// epoch. Reading that epoch here needlessly drains watches several times.
	if directory_identity(left)? != directory_identity(right)? {
		bail!("audit cohort directory identity changed");
	}
	Ok(())
}

/// A replacement root or archive never inherits the old cohort's acknowledgements.
fn fence(root: &Path, directory: &File, archive: &Archive) -> Result<()> {
	let base = audit_root(root)?;
	fence_at(&base, directory, archive)
}

fn fence_at(base: &File, directory: &File, archive: &Archive) -> Result<()> {
	let named_hot = open_at(base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	same_directory(directory, &named_hot)?;
	archive.fence_at(base)
}

fn prepare_begin(
	spec: Begin,
	directory: &File,
	archive: &Archive,
	records: &mut Vec<Record>,
	pending: &mut HashSet<String>,
	cohort: usize,
	slot: usize,
) -> Result<RequestTicket> {
	if !valid_id(&spec.owner) || !valid_tool(&spec.tool) {
		bail!("invalid audit cohort admission");
	}
	let read_pin = if let Some(id) = spec.target {
		if !matches!(spec.tool.as_str(), "request_status" | "request_result")
			|| !valid_id(&id)
			|| retained_record(directory, archive, &id)?.is_none_or(|r| r.owner != spec.owner)
		{
			bail!("request unavailable to this scope");
		}
		let pin = Arc::new(());
		read_pins()?
			.entry(id)
			.or_default()
			.push(Arc::downgrade(&pin));
		Some(pin)
	} else {
		None
	};
	let hot_present = trace::measure("begin_retention", cohort, Some(slot), || {
		retain_for_batch(directory, archive, &spec.owner, records, pending, false)
	})?;
	let record = Record {
		request_id: trace::measure("begin_identity", cohort, Some(slot), new_id)?,
		owner: spec.owner,
		tool_name: spec.tool,
		state: DurableState::Unknown,
		accepted_unix_ms: SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_millis(),
		elapsed_ms: None,
	};
	// Clone descriptors before any new publication can consume their budget.
	let ticket = RequestTicket {
		directory: trace::measure("begin_clone_hot", cohort, Some(slot), || {
			Ok(directory.try_clone()?)
		})?,
		archive: trace::measure("begin_clone_archive", cohort, Some(slot), || {
			archive.try_clone()
		})?,
		hot_present,
		record,
		started: Instant::now(),
		active: Arc::new(AtomicBool::new(true)),
		_read_pin: read_pin,
	};
	if hot_present {
		pending.insert(ticket.record.request_id.clone());
		records.push(ticket.record.clone());
	}
	Ok(ticket)
}

fn save_archives<'a>(
	archive: &'a Archive,
	tickets: &[(usize, bool, RequestTicket)],
	staging: &mut impl FnMut(&[(&File, &Record, bool)]) -> Vec<Result<()>>,
) -> (Vec<Result<()>>, Vec<&'a File>) {
	let mut directories = Vec::new();
	let mut remember = |directory: &'a File| {
		if !directories
			.iter()
			.any(|value: &&File| value.as_raw_fd() == directory.as_raw_fd())
		{
			directories.push(directory);
		}
	};
	let mut ids = HashSet::new();
	if tickets
		.iter()
		.any(|(_, _, ticket)| !ids.insert(&ticket.record.request_id))
	{
		// Preserve serial terminal-identity checks even for duplicate internal
		// tickets. Distinct native IDs can synchronize without changing FIFO.
		let results = tickets
			.iter()
			.map(|(_, begin, ticket)| {
				let filename = format!("{}.json", ticket.record.request_id);
				let directory = match archive.existing_directory(&filename)? {
					Some(directory) => directory,
					None => archive.directory_for_write(&filename, false)?,
				};
				remember(directory);
				if *begin {
					save_archive_with_sync(archive, &ticket.record, false, false)
				} else {
					archive_record_with_sync(archive, &ticket.record, false)
				}
			})
			.collect();
		return (results, directories);
	}
	let mut writes = Vec::with_capacity(tickets.len());
	let mut prepared = Vec::with_capacity(tickets.len());
	for (slot, (_, begin, ticket)) in tickets.iter().enumerate() {
		let replacing = if *begin {
			Ok(Some(false))
		} else {
			trace::measure("archive_replacement", tickets.len(), Some(slot), || {
				archive_replacement(archive, &ticket.record)
			})
		};
		match replacing {
			Ok(Some(replacing)) => {
				match trace::measure("archive_write_target", tickets.len(), Some(slot), || {
					archive.directory_for_write(
						&format!("{}.json", ticket.record.request_id),
						replacing,
					)
				}) {
					Ok(directory) => {
						remember(directory);
						writes.push((directory, &ticket.record, replacing));
						prepared.push(None);
					}
					Err(error) => prepared.push(Some(Err(error))),
				}
			}
			Ok(None) => {
				let result =
					trace::measure("archive_existing_target", tickets.len(), Some(slot), || {
						archive
							.directory_for_existing(&format!("{}.json", ticket.record.request_id))
					})
					.map(&mut remember);
				prepared.push(Some(result));
			}
			Err(error) => prepared.push(Some(Err(error))),
		}
	}
	let records: Vec<_> = writes.iter().map(|(_, record, _)| *record).collect();
	let mut results = index::publication_batch(archive, &records, || staging(&writes))
		.into_iter()
		.zip(&writes)
		.enumerate()
		.map(|(slot, (result, (directory, record, _)))| {
			result?;
			trace::measure("archive_record_fence", tickets.len(), Some(slot), || {
				archive.fence_record(&format!("{}.json", record.request_id), directory)
			})
		});
	let results = prepared
		.into_iter()
		.map(|value| {
			value.unwrap_or_else(|| {
				results
					.next()
					.unwrap_or_else(|| Err(anyhow!("audit file barrier unavailable; never replay")))
			})
		})
		.collect();
	(results, directories)
}

fn synchronize_archives(
	archive: &Archive,
	directories: &[&File],
	barrier: &mut impl FnMut(&File, Barrier) -> Result<()>,
) -> Result<()> {
	let mut failed = None;
	// Attempt every affected directory even after one barrier fails. No hot
	// publication or acknowledgement follows any uncertain archive directory.
	for directory in directories {
		if let Err(error) = barrier(directory, Barrier::Archive) {
			if failed.is_none() {
				failed = Some(error);
			}
		}
	}
	if let Some(error) = failed {
		return Err(error);
	}
	archive.fence_at(archive.root())?;
	for directory in directories {
		archive.fence_target(directory)?;
	}
	Ok(())
}

fn finish_outputs(values: Vec<Option<Result<Outcome>>>) -> Vec<Result<Outcome>> {
	values
		.into_iter()
		.map(|value| {
			value.unwrap_or_else(|| Err(anyhow!("audit cohort acknowledgement unavailable")))
		})
		.collect()
}

fn finish_single(
	root: &Path,
	mut ticket: RequestTicket,
	completion: AuditCompletion,
	barrier: &mut impl FnMut(&File, Barrier) -> Result<()>,
) -> Result<Outcome> {
	let _guard = store_lock()?;
	trace::measure("finish_single_initial_fence", 1, Some(0), || {
		fence(root, &ticket.directory, &ticket.archive)
	})?;
	let before = trace::measure("finish_single_hot_stamp", 1, Some(0), || {
		archive_stamp(&ticket.directory)
	})?;
	ticket.record.state = match completion {
		AuditCompletion::Completed => DurableState::Completed,
		AuditCompletion::Failed => DurableState::Failed,
		AuditCompletion::Unknown => DurableState::Unknown,
	};
	ticket.record.elapsed_ms =
		Some(ticket.started.elapsed().as_millis().min(u64::MAX as u128) as u64);
	let filename = format!("{}.json", ticket.record.request_id);
	let target = match ticket.archive.existing_directory(&filename)? {
		Some(directory) => directory,
		None => ticket.archive.directory_for_write(&filename, false)?,
	};
	let archived = trace::measure("finish_single_archive_write", 1, Some(0), || {
		archive_record_with_sync(&ticket.archive, &ticket.record, false)
	});
	trace::measure("finish_single_archive_barrier", 1, Some(0), || {
		synchronize_archives(&ticket.archive, &[target], barrier)
	})?;
	archived?;
	if ticket.hot_present {
		let published = trace::measure("finish_single_hot_write", 1, Some(0), || {
			save_with_sync(&ticket.directory, &ticket.record, true, false)
		});
		trace::measure("finish_single_hot_barrier", 1, Some(0), || {
			barrier(&ticket.directory, Barrier::Hot)
		})?;
		published?;
	}
	trace::measure("finish_single_final_fence", 1, Some(0), || {
		fence(root, &ticket.directory, &ticket.archive)
	})?;
	if ticket.hot_present {
		// A pinned single completion only changes its existing member. Reuse
		// the original completion cache update instead of cloning and sorting
		// every retained record or scanning unrelated payloads.
		trace::measure("finish_single_cache_update", 1, Some(0), || {
			update_cached_completion(&ticket.directory, &ticket.record, before)
		})?;
	}
	ticket.active.store(false, Ordering::Release);
	Ok(Outcome::Finished)
}

fn execute(
	works: Vec<Work>,
	barrier: &mut impl FnMut(&File, Barrier) -> Result<()>,
) -> Result<Vec<Result<Outcome>>> {
	execute_with_staging(works, barrier, &mut stage::save_many)
}

// The production staging operation is unchanged. Tests inject an exact file
// barrier outcome here without bypassing archive publication, fences or ACKs.
fn execute_with_staging(
	mut works: Vec<Work>,
	barrier: &mut impl FnMut(&File, Barrier) -> Result<()>,
	staging: &mut impl FnMut(&[(&File, &Record, bool)]) -> Vec<Result<()>>,
) -> Result<Vec<Result<Outcome>>> {
	if works.len() == 1 && matches!(works.first(), Some(Work::Finish(..))) {
		let Some(Work::Finish(root, ticket, completion)) = works.pop() else {
			bail!("single audit completion unavailable");
		};
		return Ok(vec![trace::measure(
			"cohort_single_finish",
			1,
			Some(0),
			|| finish_single(&root, ticket, completion, barrier),
		)]);
	}
	let count = works.len();
	let Some(first) = works.first() else {
		bail!("empty audit cohort");
	};
	let (root, _) = first.key();
	let root = root.to_owned();
	if count > MAX_BATCH || works.iter().any(|work| work.key().0 != root.as_path()) {
		bail!("mixed or oversized audit cohort");
	}
	let _guard = store_lock()?;
	// Preparation shares one pinned root. The final fence resolves the named
	// path again before any acknowledgement, preserving replacement detection.
	let base = trace::measure("cohort_open_root", count, None, || audit_root(&root))?;
	let directory = trace::measure("cohort_open_hot", count, None, || {
		open_named_store_at(&base, STORE_NAME)
	})?;
	let archive = trace::measure("cohort_open_archive", count, None, || {
		open_archive_at(&base)
	})?;
	let mut records = trace::measure("cohort_hot_snapshot", count, None, || {
		hot_snapshot_at(&directory, &archive, true)
	})?;
	trace::measure("cohort_initial_fence", count, None, || {
		fence_at(&base, &directory, &archive)
	})?;
	let before = trace::measure("cohort_hot_stamp", count, None, || {
		archive_stamp(&directory)
	})?;
	let mut values: Vec<Option<Result<Outcome>>> =
		std::iter::repeat_with(|| None).take(count).collect();
	let mut staged = Vec::with_capacity(count);
	let mut pending = HashSet::new();
	for (index, work) in works.into_iter().enumerate() {
		let is_begin = matches!(&work, Work::Begin(_));
		let prepared = trace::measure("cohort_prepare", count, Some(index), || match work {
			Work::Begin(spec) => prepare_begin(
				spec,
				&directory,
				&archive,
				&mut records,
				&mut pending,
				count,
				index,
			),
			Work::Finish(_, mut ticket, completion) => (|| -> Result<RequestTicket> {
				same_directory(&ticket.directory, &directory)?;
				same_directory(ticket.archive.legacy(), archive.legacy())?;
				ticket.archive.fence_at(&base)?;
				ticket.record.state = match completion {
					AuditCompletion::Completed => DurableState::Completed,
					AuditCompletion::Failed => DurableState::Failed,
					AuditCompletion::Unknown => DurableState::Unknown,
				};
				ticket.record.elapsed_ms =
					Some(ticket.started.elapsed().as_millis().min(u64::MAX as u128) as u64);
				Ok(ticket)
			})(),
		});
		match prepared {
			Ok(ticket) => staged.push((index, is_begin, ticket)),
			Err(error) => values[index] = Some(Err(error)),
		}
	}
	let archive_span = trace::Span::new("cohort_archive_write", count, None);
	let (archived, archive_directories) = save_archives(&archive, &staged, staging);
	archive_span.record(archived.iter().find_map(|result| result.as_ref().err()));
	// Even a failed publication may have changed a name. A failed barrier
	// refuses every waiter, and no new hot publication or active marker follows.
	trace::measure("cohort_archive_barrier", count, None, || {
		synchronize_archives(&archive, &archive_directories, barrier)
	})?;
	let mut ready = Vec::with_capacity(staged.len());
	let mut hot_attempted = false;
	let mut archived_ok = Vec::with_capacity(staged.len());
	for ((index, is_begin, ticket), archived) in staged.into_iter().zip(archived) {
		trace::Span::new("cohort_archive_result", count, Some(index))
			.record(archived.as_ref().err());
		match archived {
			Ok(()) => archived_ok.push((index, is_begin, ticket)),
			Err(error) => {
				if is_begin {
					records.retain(|record| record.request_id != ticket.record.request_id);
				}
				values[index] = Some(Err(error));
			}
		}
	}
	let hot_records: Vec<_> = archived_ok
		.iter()
		.filter(|(_, _, ticket)| ticket.hot_present)
		.map(|(_, begin, ticket)| (&directory, &ticket.record, !*begin))
		.collect();
	let hot_span = trace::Span::new("cohort_hot_write", count, None);
	let hot_results = staging(&hot_records);
	hot_span.record(hot_results.iter().find_map(|result| result.as_ref().err()));
	let mut hot_results = hot_results.into_iter();
	for (index, is_begin, ticket) in archived_ok {
		let published = if ticket.hot_present {
			hot_attempted = true;
			hot_results
				.next()
				.unwrap_or_else(|| Err(anyhow!("audit hot file barrier unavailable; never replay")))
		} else {
			Ok(())
		};
		trace::Span::new("cohort_hot_result", count, Some(index)).record(published.as_ref().err());
		match published {
			Ok(()) => {
				if !is_begin && ticket.hot_present {
					if let Some(old) = records
						.iter_mut()
						.find(|r| r.request_id == ticket.record.request_id)
					{
						*old = ticket.record.clone();
					}
				}
				ready.push((index, is_begin, ticket));
			}
			Err(error) => {
				if is_begin {
					records.retain(|r| r.request_id != ticket.record.request_id);
				}
				values[index] = Some(Err(error));
			}
		}
	}
	if hot_attempted || archive_stamp(&directory)? != before {
		trace::measure("cohort_hot_barrier", count, None, || {
			barrier(&directory, Barrier::Hot)
		})?;
	}
	trace::measure("cohort_final_fence", count, None, || {
		fence(&root, &directory, &archive)?;
		for target in &archive_directories {
			archive.fence_target(target)?;
		}
		Ok(())
	})?;
	records.sort_by(|a, b| {
		(a.accepted_unix_ms, &a.request_id).cmp(&(b.accepted_unix_ms, &b.request_id))
	});
	trace::measure("cohort_cache_hot", count, None, || {
		cache_hot_owned(&directory, records)
	})?;
	let mut active = if ready.iter().any(|(_, is_begin, _)| *is_begin) {
		Some(trace::measure(
			"cohort_active_registry",
			count,
			None,
			active_registry,
		)?)
	} else {
		None
	};
	for (index, is_begin, mut ticket) in ready {
		if is_begin {
			ticket.started = Instant::now();
			active
				.as_mut()
				.ok_or_else(|| anyhow!("audit cohort active registry unavailable"))?
				.insert(
					ticket.record.request_id.clone(),
					Arc::downgrade(&ticket.active),
				);
			values[index] = Some(Ok(Outcome::Begun(ticket)));
		} else {
			ticket.active.store(false, Ordering::Release);
			values[index] = Some(Ok(Outcome::Finished));
		}
	}
	Ok(finish_outputs(values))
}

#[cfg(all(test, unix))]
#[path = "request_audit_batch_tests.rs"]
mod tests;
