// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Directory-local metadata windows and complete identity joins in bounded RAM.
use super::*;

pub(super) const NAME_BATCH: usize = 1_048_576;
pub(super) const JOIN_WORKERS: usize = 2;
pub(super) const JOIN_READER_BOUND: usize = JOIN_WORKERS * (FAN_IN + 1);

/// ROW ranges already have strict identity order. Preserve one complete run
/// without sorting or writing another disposable merge generation.
pub(in super::super) struct RowExpected(Writer);
impl RowExpected {
	pub(in super::super) fn new(root: &File) -> Result<Self> {
		let mut writer = Writer::new(root)?;
		writer.begin()?;
		Ok(Self(writer))
	}
	pub(in super::super) fn push(&mut self, image: Image) -> Result<()> {
		self.0.push(image)
	}
	pub(in super::super) fn finish(self) -> Result<Spool> {
		self.0.finish()
	}
}

struct NameHint {
	identity: Id,
	inode: u64,
}
#[derive(Default)]
struct Observation {
	tracing: bool,
	rows: u64,
	cohorts: u64,
	batches: u64,
	maximum_batch: usize,
	stat_elapsed: Duration,
}
/// Owns only bounded-in-RAM disk streams, never a snapshot-sized record vector.
pub(super) struct Observed {
	sources: Vec<(usize, Spool)>,
	stats: Observation,
	started: Instant,
}
fn partition_of(identity: &Id) -> usize {
	identity[0] as usize * COLD_ROW_WORKERS / 256
}
fn flush_names(
	directory: &File,
	names: &mut Vec<NameHint>,
	sorters: &mut [Sorter],
	pool: &rayon::ThreadPool,
	deadline: Instant,
	cancelled: &AtomicBool,
	stats: &mut Observation,
) -> Result<()> {
	if names.is_empty() {
		return Ok(());
	}
	if names.len() > NAME_BATCH || sorters.len() != COLD_ROW_WORKERS {
		bail!("archive directory window exceeds its bound");
	}
	// Directory entries supply locality hints, never trusted metadata. The
	// subsequent named fstatat checks every field, including inode and type.
	live(cancelled, deadline)?;
	let sort_started = stats.tracing.then(Instant::now);
	// Sorting is synchronous; cancellation is checked before and after it.
	names.sort_unstable_by_key(|entry| (entry.inode, entry.identity));
	if let Some(started) = sort_started {
		let hint_bytes = std::mem::size_of::<NameHint>();
		let window_bytes = names
			.len()
			.checked_mul(hint_bytes)
			.ok_or_else(|| anyhow!("archive directory window byte count overflow"))?;
		eprintln!("archive_index cold_stage=name_window_sort_complete rows={} elapsed_ms={} name_hint_bytes={hint_bytes} logical_window_bytes={window_bytes}", names.len(), started.elapsed().as_millis());
	}
	live(cancelled, deadline)?;
	stats.batches += 1;
	stats.maximum_batch = stats.maximum_batch.max(names.len());
	for cohort in names.chunks(BUILD_CHUNK) {
		live(cancelled, deadline)?;
		let started = stats.tracing.then(Instant::now);
		let images = pool.install(|| {
			cohort
				.par_iter()
				.map(|entry| -> Result<Image> {
					live(cancelled, deadline)?;
					let filename = filename(&entry.identity)?;
					Ok(order_image(
						&entry.identity,
						stamp_at(directory, &filename)?,
					))
				})
				.collect::<Result<Vec<_>>>()
		})?;
		if let Some(started) = started {
			stats.stat_elapsed += started.elapsed();
		}
		stats.cohorts += 1;
		stats.rows = stats
			.rows
			.checked_add(images.len() as u64)
			.ok_or_else(|| anyhow!("archive observed count overflow"))?;
		for image in images {
			let identity: Id = image[..32].try_into()?;
			sorters[partition_of(&identity)].push(image)?;
		}
	}
	names.clear();
	Ok(())
}
pub(super) fn observe(
	slot: &Slot,
	pool: &rayon::ThreadPool,
	deadline: Instant,
	cancelled: &AtomicBool,
) -> Result<Observed> {
	#[cfg(test)]
	parallel_event(slot, ParallelEvent::ObservationStarted);
	let started = Instant::now();
	let tracing = tracing_enabled();
	let mut last_report = Instant::now();
	let mut stats = Observation {
		tracing,
		..Observation::default()
	};
	let mut sorters = (0..COLD_ROW_WORKERS)
		.map(|_| Sorter::new(&slot.root))
		.collect::<Result<Vec<_>>>()?;
	// A bounded producer enumerates filenames while the consumer validates
	// all original fstatat metadata. Keeping those I/O phases concurrent
	// avoids summing two full multi-million-row passes at cold startup.
	std::thread::scope(|scope| -> Result<()> {
		// One pinned physical directory belongs to each bounded name window.
		// Keep the 40-byte per-name representation and avoid repeating canonical
		// probes of both namespaces for every one of the legacy originals.
		let (sender, receiver) = std::sync::mpsc::sync_channel::<(&File, Vec<NameHint>)>(1);
		let producer = scope.spawn(move || -> Result<()> {
			let mut names = Vec::with_capacity(NAME_BATCH);
			let mut physical: Option<&File> = None;
			// Preserve both physical copies of a duplicate. The complete sorted
			// stream rejects equal IDs before this observation can certify a cache.
			slot.archive
				.walk_for_complete_identity_join(|directory, filename, inode| {
					live(cancelled, deadline)?;
					if staging(filename)? {
						return Ok(());
					}
					if !names.is_empty()
						&& physical.is_some_and(|prior| !std::ptr::eq(prior, directory))
					{
						let previous = physical
							.ok_or_else(|| anyhow!("archive directory window scope unavailable"))?;
						let full = std::mem::replace(&mut names, Vec::with_capacity(NAME_BATCH));
						sender
							.send((previous, full))
							.map_err(|_| anyhow!("archive directory observer receiver closed"))?;
					}
					physical = Some(directory);
					let identity = filename
						.strip_suffix(".json")
						.filter(|raw| valid_id(raw))
						.ok_or_else(|| anyhow!("invalid archive member"))?;
					names.push(NameHint {
						identity: id(identity)?,
						inode,
					});
					if names.len() == NAME_BATCH {
						let full = std::mem::replace(&mut names, Vec::with_capacity(NAME_BATCH));
						sender
							.send((directory, full))
							.map_err(|_| anyhow!("archive directory observer receiver closed"))?;
					}
					Ok(())
				})?;
			if !names.is_empty() {
				let directory = physical
					.ok_or_else(|| anyhow!("archive directory window scope unavailable"))?;
				sender
					.send((directory, names))
					.map_err(|_| anyhow!("archive directory observer receiver closed"))?;
			}
			Ok(())
		});
		let consumed = (|| -> Result<()> {
			while let Ok((directory, mut names)) = receiver.recv() {
				flush_names(
					directory,
					&mut names,
					&mut sorters,
					pool,
					deadline,
					cancelled,
					&mut stats,
				)?;
				if tracing && last_report.elapsed() >= Duration::from_secs(5) {
					eprintln!("archive_index cold_stage=directory_stat_stream_progress checked_rows={} cohorts={} name_batches={} maximum_name_batch={} stat_elapsed_ms={} elapsed_ms={}", stats.rows, stats.cohorts, stats.batches, stats.maximum_batch, stats.stat_elapsed.as_millis(), started.elapsed().as_millis());
					last_report = Instant::now();
				}
			}
			Ok(())
		})();
		// A failing consumer must wake a producer blocked on the bounded queue.
		drop(receiver);
		let produced = producer
			.join()
			.map_err(|_| anyhow!("archive directory walker panicked"))?;
		consumed?;
		produced
	})?;
	let sources = sorters
		.into_iter()
		.enumerate()
		.map(|(part, sorter)| Ok((part, sorter.finish()?)))
		.collect::<Result<Vec<_>>>()?;
	let written = sources.iter().try_fold(0u64, |total, (_, source)| {
		total
			.checked_add(source.rows)
			.ok_or_else(|| anyhow!("archive observed count overflow"))
	})?;
	if written != stats.rows {
		bail!("archive observed stream coverage changed");
	}
	if tracing {
		eprintln!("archive_index cold_stage=directory_stat_stream_complete status=passed checked_rows={} cohorts={} name_batches={} maximum_name_batch={} name_batch_bound={NAME_BATCH} maximum_stat_cohort={BUILD_CHUNK} stat_elapsed_ms={} elapsed_ms={} global_inode_order=false inode_hint_trusted=false", stats.rows, stats.cohorts, stats.batches, stats.maximum_batch, stats.stat_elapsed.as_millis(), started.elapsed().as_millis());
	}
	#[cfg(test)]
	parallel_event(slot, ParallelEvent::ObservationComplete);
	Ok(Observed {
		sources,
		stats,
		started,
	})
}

#[derive(Default)]
struct Joined {
	matched: u64,
	changed: u64,
	extra: u64,
	ids: Fingerprint,
}
fn join_readers(
	slot: &Slot,
	mut next_expected: impl FnMut() -> Result<Option<Image>>,
	mut next_actual: impl FnMut() -> Result<Option<Image>>,
	deadline: Instant,
	cancelled: &AtomicBool,
	output: &Sender,
) -> Result<Joined> {
	let mut old = next_expected()?;
	let mut seen = next_actual()?;
	let mut changes = Vec::with_capacity(BUILD_CHUNK);
	let mut changed = Vec::with_capacity(BUILD_CHUNK);
	let mut joined = Joined::default();
	loop {
		live(cancelled, deadline)?;
		match (old.as_ref(), seen.as_ref()) {
			(None, None) => break,
			(Some(a), Some(b)) if a[..32] == b[..32] => {
				joined.ids.add(b"id", &b[..32], 1);
				joined.matched += 1;
				if a != b {
					joined.changed += 1;
					changed.push((filename(&a[..32])?, decode_stamp(&a[32..])?));
				}
				old = next_expected()?;
				seen = next_actual()?;
			}
			(Some(a), Some(b)) if a[..32] < b[..32] => {
				bail!("archive original identity coverage changed")
			}
			(Some(_), None) => bail!("archive original identity coverage changed"),
			(_, Some(b)) => {
				joined.ids.add(b"id", &b[..32], 1);
				joined.extra += 1;
				changes.push(checked_original(slot, &filename(&b[..32])?)?);
				seen = next_actual()?;
			}
		}
		if changed.len() == BUILD_CHUNK {
			original_cohort(
				slot,
				&mut changed,
				&mut changes,
				deadline,
				cancelled,
				output,
			)?;
		}
		if changes.len() == BUILD_CHUNK {
			output
				.send(Message::Changes(std::mem::take(&mut changes)))
				.map_err(|_| anyhow!("archive writer unavailable"))?;
		}
	}
	original_cohort(
		slot,
		&mut changed,
		&mut changes,
		deadline,
		cancelled,
		output,
	)?;
	if !changes.is_empty() {
		output
			.send(Message::Changes(changes))
			.map_err(|_| anyhow!("archive writer unavailable"))?;
	}
	Ok(joined)
}
fn join_partition(
	slot: &Slot,
	expected: &Spool,
	actual: &Spool,
	part: usize,
	deadline: Instant,
	cancelled: &AtomicBool,
	output: &Sender,
) -> Result<Joined> {
	if expected.order != SortOrder::Identity || actual.order != SortOrder::Identity {
		bail!("archive identity comparison order changed");
	}
	let mut left = expected.one()?;
	let mut right = TerminalMerge::with_order(
		std::slice::from_ref(actual),
		deadline,
		cancelled,
		SortOrder::Identity,
	)?;
	let readers = right.readers.len() + 1;
	if readers > FAN_IN + 1 || readers > TERMINAL_READERS {
		bail!("archive identity comparison reader bound changed");
	}
	let in_partition = |image: Option<Image>| -> Result<Option<Image>> {
		if image
			.as_ref()
			.is_some_and(|raw| raw[0] as usize * COLD_ROW_WORKERS / 256 != part)
		{
			bail!("archive identity partition membership changed");
		}
		Ok(image)
	};
	let result = join_readers(
		slot,
		|| in_partition(left.next()?),
		|| in_partition(right.next(deadline, cancelled)?),
		deadline,
		cancelled,
		output,
	)?;
	if result.matched != expected.rows
		|| result.matched.checked_add(result.extra) != Some(actual.rows)
		|| !right.complete
	{
		bail!("archive identity comparison coverage changed");
	}
	if tracing_enabled() {
		let bytes = result
			.matched
			.checked_mul(72)
			.ok_or_else(|| anyhow!("archive comparison byte count overflow"))?;
		eprintln!("archive_index cold_stage=directory_identity_join_partition_complete partition={part} expected_rows={} observed_rows={} matched_rows={} changed_rows={} extra_rows={} missing_rows=0 compared_stamp_bytes={bytes} readers={readers} complete_stream_hashes=true payload_eof_verified=true single_expected_run=true", expected.rows, actual.rows, result.matched, result.changed, result.extra);
	}
	Ok(result)
}
pub(super) fn verify_sources(
	slot: &Slot,
	expected: Vec<(usize, Spool)>,
	pool: &rayon::ThreadPool,
	deadline: Instant,
	cancelled: &AtomicBool,
	output: &Sender,
) -> Result<OriginalCoverage> {
	validate_expected(&expected)?;
	let observed = observe(slot, pool, deadline, cancelled)?;
	join_observed(slot, expected, observed, deadline, cancelled, output)
}
fn validate_expected(expected: &[(usize, Spool)]) -> Result<()> {
	if expected.len() != COLD_ROW_WORKERS
		|| expected.iter().enumerate().any(|(part, (found, source))| {
			*found != part || source.order != SortOrder::Identity || source.runs != 1
		}) {
		bail!("archive expected identity partition coverage changed");
	}
	Ok(())
}
fn join_partitions(
	expected: &[(usize, Spool)],
	observed: &[Spool],
	deadline: Instant,
	cancelled: &AtomicBool,
	work: impl Fn(usize, &Spool, &Spool) -> Result<Joined> + Sync,
) -> Result<Joined> {
	validate_expected(expected)?;
	if observed.len() != expected.len() {
		bail!("archive observed identity partition coverage changed");
	}
	let readers = observed.iter().try_fold(0usize, |maximum, source| {
		if source.order != SortOrder::Identity || source.runs == 0 || source.runs > FAN_IN as u64 {
			bail!("archive terminal sort incomplete");
		}
		Ok(maximum.max(usize::try_from(source.runs)? + 1))
	})?;
	if readers
		.checked_mul(JOIN_WORKERS)
		.is_none_or(|maximum| maximum > TERMINAL_READERS)
	{
		bail!("archive identity comparison reader bound changed");
	}
	std::thread::scope(|scope| {
		// Each worker sends exactly one small result. This queue can hold every
		// result while we join all workers; original Changes retain their own
		// capacity-one queue and are consumed by the existing outer coordinator.
		let (finished, results) =
			std::sync::mpsc::sync_channel::<Result<Vec<(usize, Joined)>>>(JOIN_WORKERS);
		let mut handles = Vec::with_capacity(JOIN_WORKERS);
		for worker in 0..JOIN_WORKERS {
			let finished = finished.clone();
			let work = &work;
			handles.push(scope.spawn(move || {
				let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
					let mut parts = Vec::with_capacity(COLD_ROW_WORKERS.div_ceil(JOIN_WORKERS));
					for (part, ((_, left), right)) in expected
						.iter()
						.zip(observed)
						.enumerate()
						.skip(worker)
						.step_by(JOIN_WORKERS)
					{
						live(cancelled, deadline)?;
						parts.push((part, work(part, left, right)?));
					}
					Ok(parts)
				}))
				.unwrap_or_else(|_| Err(anyhow!("archive identity join worker panicked")));
				let failed = result.is_err();
				// Publish the triggering failure before cancellation can make a peer
				// report a secondary cancellation error. Receive order preserves it.
				let sent = finished.send(result);
				if failed || sent.is_err() {
					cancelled.store(true, Ordering::Relaxed);
				}
			}));
		}
		drop(finished);
		let mut join_failure = None;
		for handle in handles {
			if handle.join().is_err() {
				cancelled.store(true, Ordering::Relaxed);
				join_failure
					.get_or_insert_with(|| anyhow!("archive identity join worker panicked"));
			}
		}
		let mut failure = None;
		let mut parts: Vec<Option<Joined>> = (0..expected.len()).map(|_| None).collect();
		for result in results {
			match result {
				Ok(joined) => {
					for (part, value) in joined {
						let target = parts
							.get_mut(part)
							.ok_or_else(|| anyhow!("archive joined partition coverage changed"))?;
						if target.replace(value).is_some() {
							bail!("archive joined partition coverage changed");
						}
					}
				}
				Err(error) => {
					if failure.is_none() {
						failure = Some(error);
					}
				}
			}
		}
		if let Some(error) = failure.or(join_failure) {
			return Err(error);
		}
		live(cancelled, deadline)?;
		let mut total = Joined::default();
		for part in parts {
			let joined =
				part.ok_or_else(|| anyhow!("archive joined partition coverage changed"))?;
			total.matched = total
				.matched
				.checked_add(joined.matched)
				.ok_or_else(|| anyhow!("archive joined count overflow"))?;
			total.changed = total
				.changed
				.checked_add(joined.changed)
				.ok_or_else(|| anyhow!("archive joined count overflow"))?;
			total.extra = total
				.extra
				.checked_add(joined.extra)
				.ok_or_else(|| anyhow!("archive joined count overflow"))?;
			total.ids.merge(joined.ids);
		}
		Ok(total)
	})
}
pub(super) fn join_observed(
	slot: &Slot,
	expected: Vec<(usize, Spool)>,
	observed: Observed,
	deadline: Instant,
	cancelled: &AtomicBool,
	output: &Sender,
) -> Result<OriginalCoverage> {
	validate_expected(&expected)?;
	let Observed {
		sources,
		stats,
		started,
	} = observed;
	let observed = reduce_sources(slot, sources, deadline, cancelled)?;
	let total = join_partitions(
		&expected,
		&observed,
		deadline,
		cancelled,
		|part, left, right| join_partition(slot, left, right, part, deadline, cancelled, output),
	)?;
	if total.matched.checked_add(total.extra) != Some(stats.rows) {
		bail!("archive original identity coverage changed");
	}
	if tracing_enabled() {
		eprintln!("archive_index cold_stage=directory_identity_join_complete status=passed matched_rows={} changed_rows={} extra_rows={} missing_rows=0 observed_rows={} partitions={COLD_ROW_WORKERS} maximum_join_readers={JOIN_READER_BOUND} maximum_merge_readers={TERMINAL_READERS} elapsed_ms={} global_inode_order=false join_workers={JOIN_WORKERS} maximum_partition_join_readers={}", total.matched, total.changed, total.extra, stats.rows, started.elapsed().as_millis(), FAN_IN + 1);
	}
	Ok(OriginalCoverage {
		ids: total.ids,
		rows: stats.rows,
		matched: total.matched,
		changed: total.changed,
		extra: total.extra,
	})
}

#[cfg(test)]
#[path = "request_archive_directory_tests.rs"]
mod tests;
