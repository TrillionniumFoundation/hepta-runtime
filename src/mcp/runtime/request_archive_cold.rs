// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Complete range validation with bounded original checks streamed from ordered stamps.
use super::*;
use rayon::prelude::*;

const FORMAT_KEY: &str = "owner_time_identity";
const FORMAT: &[u8] = b"v1";
const VALUE_BYTES: usize = 104;
const ORDER_WORKERS: usize = 8;
const ORDER_BOUND_SAMPLES: usize = 256;

#[path = "request_archive_runs.rs"]
mod runs;

pub(super) fn order_value(entry: &Entry) -> Result<Id> {
	id(&entry.record.request_id)
}
fn order_image(identity: &Id, stamp: FileStamp) -> [u8; VALUE_BYTES] {
	let mut value = [0; VALUE_BYTES];
	value[..32].copy_from_slice(identity);
	value[32..].copy_from_slice(&stamp_value(stamp));
	value
}
/// The ROW codec and comparison streams always retain every original stamp byte,
/// independently of the smaller owner/time lookup value.
pub(super) fn stamp_value(s: FileStamp) -> [u8; 72] {
	let mut value = [0; 72];
	value[..8].copy_from_slice(&s.device.to_be_bytes());
	value[8..16].copy_from_slice(&s.inode.to_be_bytes());
	value[16..20].copy_from_slice(&s.mode.to_be_bytes());
	value[20..24].copy_from_slice(&s.uid.to_be_bytes());
	for (part, word) in value[24..].chunks_exact_mut(8).zip([
		s.links,
		s.length,
		s.modified.0 as u64,
		s.modified.1 as u64,
		s.changed.0 as u64,
		s.changed.1 as u64,
	]) {
		part.copy_from_slice(&word.to_be_bytes());
	}
	value
}

pub(super) fn order_identity(value: &[u8]) -> Result<&[u8]> {
	if value.len() != 32 {
		bail!("invalid ordered archive identity");
	}
	Ok(value)
}
fn decode(key: &[u8], value: &[u8]) -> Result<(String, FileStamp)> {
	if value.len() != VALUE_BYTES {
		bail!("invalid temporary archive stamp image");
	}
	let identity = &value[..32];
	if key.len() != 80 || &key[48..] != identity {
		bail!("archive order index changed");
	}
	let mut filename = String::with_capacity(69);
	const HEX: &[u8; 16] = b"0123456789abcdef";
	for byte in identity {
		filename.push(HEX[(byte >> 4) as usize] as char);
		filename.push(HEX[(byte & 15) as usize] as char);
	}
	filename.push_str(".json");
	let stamp = decode_stamp(&value[32..])?;
	Ok((filename, stamp))
}
pub(super) fn decode_stamp(raw: &[u8]) -> Result<FileStamp> {
	if raw.len() != 72 {
		bail!("invalid ordered archive stamp");
	}
	let word = |start| -> Result<u64> { Ok(u64::from_be_bytes(raw[start..start + 8].try_into()?)) };
	Ok(FileStamp {
		device: word(0)?,
		inode: word(8)?,
		mode: u32::from_be_bytes(raw[16..20].try_into()?),
		uid: u32::from_be_bytes(raw[20..24].try_into()?),
		links: word(24)?,
		length: word(32)?,
		modified: (word(40)? as i64, word(48)? as i64),
		changed: (word(56)? as i64, word(64)? as i64),
	})
}

fn order_fingerprint(sum: &mut Fingerprint, key: &[u8], value: &[u8]) -> Result<()> {
	if key.len() != 80 || value.len() != 32 || &key[48..] != value {
		bail!("archive order index changed");
	}
	let mut image = [0u8; 80 + 32];
	image[..80].copy_from_slice(key);
	image[80..].copy_from_slice(value);
	sum.add(b"owner-time-identity-v1", &image, 1);
	Ok(())
}
pub(super) fn mark_new(meta: &mut redb::Table<&str, &[u8]>) -> Result<()> {
	meta.insert(FORMAT_KEY, FORMAT)?;
	Ok(())
}
/// Only the disposable ordered projection changes. No original is rewritten.
/// Drop each read snapshot before writing so old COW generations stay bounded.
pub(super) fn upgrade(database: &Database, slot: &Slot, deadline: Instant) -> Result<()> {
	{
		let read = database.begin_read()?;
		if read
			.open_table(META)?
			.get(FORMAT_KEY)?
			.is_some_and(|v| v.value() == FORMAT)
		{
			return Ok(());
		}
	}
	let mut cursor: Option<Id> = None;
	loop {
		if Instant::now() >= deadline {
			bail!("archive index preparation deadline");
		}
		let keys = {
			let read = database.begin_read()?;
			let rows = read.open_table(ROWS)?;
			let low = cursor.as_ref().map_or(std::ops::Bound::Unbounded, |key| {
				std::ops::Bound::Excluded(key.as_slice())
			});
			let mut keys = Vec::with_capacity(BUILD_CHUNK);
			for pair in rows
				.range::<&[u8]>((low, std::ops::Bound::Unbounded))?
				.take(BUILD_CHUNK)
			{
				let (key, _) = pair?;
				keys.push(<Id>::try_from(key.value())?);
			}
			keys
		};
		if keys.is_empty() {
			break;
		}
		cursor = keys.last().copied();
		let mut write = database.begin_write()?;
		write.set_durability(Durability::None)?;
		{
			let rows = write.open_table(ROWS)?;
			let mut order = write.open_table(ORDER)?;
			for key in keys {
				let raw = rows
					.get(key.as_slice())?
					.ok_or_else(|| anyhow!("archive row missing"))?;
				let entry = codec::decode(raw.value())?;
				if id(&entry.record.request_id)? != key {
					bail!("archive index identity changed");
				}
				order.insert(
					order_key(&entry.record)?.as_slice(),
					order_value(&entry)?.as_slice(),
				)?;
			}
		}
		write.commit()?;
		fold_cache_changes(database, slot, &mut Vec::new())?;
	}
	let mut write = database.begin_write()?;
	write.set_durability(Durability::Immediate)?;
	write.set_quick_repair(true);
	mark_new(&mut write.open_table(META)?)?;
	write.commit()?;
	Ok(())
}

#[derive(Default)]
pub(super) struct ColdTotals {
	pub(super) rows: u64,
	pub(super) row_sum: Fingerprint,
	pub(super) ids: Fingerprint,
	pub(super) order: Fingerprint,
	pub(super) counts: Fingerprint,
	pub(super) actual_ids: Option<Fingerprint>,
	pub(super) actual_order: Option<Fingerprint>,
	pub(super) namespace: Option<(Fingerprint, u64)>,
	pub(super) originals: Option<OriginalCoverage>,
	sources: Vec<(usize, runs::Spool)>,
}

/// Produced only after the exact expected/observed ID join consumes every
/// checked stream. It describes the originals, including changes already
/// folded by the receiving coordinator, rather than its old read snapshot.
#[derive(Debug)]
pub(super) struct OriginalCoverage {
	pub(super) ids: Fingerprint,
	pub(super) rows: u64,
	pub(super) matched: u64,
	pub(super) changed: u64,
	pub(super) extra: u64,
}
impl OriginalCoverage {
	pub(super) fn matches_namespace(&self, ids: &Fingerprint, rows: u64) -> bool {
		self.matched.checked_add(self.extra) == Some(self.rows)
			&& self.changed <= self.matched
			&& self.rows == rows
			&& self.ids == *ids
	}
}
impl ColdTotals {
	fn merge(&mut self, other: Self) -> Result<()> {
		self.rows = self
			.rows
			.checked_add(other.rows)
			.ok_or_else(|| anyhow!("archive row count overflow"))?;
		self.row_sum.merge(other.row_sum);
		self.ids.merge(other.ids);
		self.order.merge(other.order);
		self.counts.merge(other.counts);
		self.sources.extend(other.sources);
		Ok(())
	}
}
enum Message {
	Changes(Vec<Entry>),
	Rows(Box<ColdTotals>, Duration),
	Ids(Fingerprint, Duration),
	Order(Fingerprint, Duration),
	OriginalDone(Option<OriginalCoverage>),
	Observed(Box<runs::Observed>, Duration, Duration),
	Namespace(Fingerprint, u64, Duration, Duration),
	Failed(anyhow::Error),
}
type Sender = std::sync::mpsc::SyncSender<Message>;
fn report_worker(work: impl FnOnce() -> Result<Message>, output: &Sender, cancelled: &AtomicBool) {
	let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
		.unwrap_or_else(|_| Err(anyhow!("archive validation producer panicked")));
	let message = match result {
		Ok(message) => message,
		Err(error) => {
			cancelled.store(true, Ordering::Relaxed);
			Message::Failed(error)
		}
	};
	let _ = output.send(message);
}

#[derive(Clone, Copy)]
pub(super) struct ScanPlan<'a> {
	deadline: Instant,
	cache_file: Option<&'a File>,
	epoch: Option<&'a ParallelEpoch>,
}
impl<'a> ScanPlan<'a> {
	pub(super) fn new(
		deadline: Instant,
		cache_file: Option<&'a File>,
		epoch: Option<&'a ParallelEpoch>,
	) -> Self {
		Self {
			deadline,
			cache_file,
			epoch,
		}
	}
}
struct ScanResources {
	started: Instant,
	budget: Option<runs::OriginalBudget>,
}
fn live(cancelled: &AtomicBool, deadline: Instant) -> Result<()> {
	if cancelled.load(Ordering::Relaxed) {
		bail!("archive parallel validation cancelled");
	}
	if Instant::now() >= deadline {
		bail!("archive index preparation deadline");
	}
	Ok(())
}
#[cfg(test)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdRecord<'a> {
	#[serde(borrow)]
	request_id: std::borrow::Cow<'a, str>,
	#[serde(borrow)]
	owner: std::borrow::Cow<'a, str>,
	#[serde(borrow)]
	tool_name: std::borrow::Cow<'a, str>,
	state: DurableState,
	accepted_unix_ms: u128,
	#[serde(rename = "elapsed_ms")]
	_elapsed_ms: Option<u64>,
}
#[cfg(test)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdEntry<'a> {
	#[serde(borrow)]
	record: ColdRecord<'a>,
	stamp: FileStamp,
}
fn count_key(counters: &mut BTreeMap<Vec<u8>, u64>, key: &[u8]) {
	if let Some(count) = counters.get_mut(key) {
		*count += 1;
	} else {
		counters.insert(key.to_vec(), 1);
	}
}
#[cfg(test)]
fn project(
	entry: &ColdEntry<'_>,
	identity: &Id,
	owner: &Id,
	total: &mut ColdTotals,
	counters: &mut BTreeMap<Vec<u8>, u64>,
) -> Result<()> {
	project_view(
		&codec::View {
			identity: *identity,
			owner: *owner,
			accepted: entry.record.accepted_unix_ms,
			elapsed: entry.record._elapsed_ms,
			state: entry.record.state,
			stamp: entry.stamp,
			tool: &entry.record.tool_name,
		},
		total,
		counters,
	)
}
fn project_view(
	entry: &codec::View<'_>,
	total: &mut ColdTotals,
	counters: &mut BTreeMap<Vec<u8>, u64>,
) -> Result<()> {
	let mut key = [0u8; 80];
	key[..32].copy_from_slice(&entry.owner);
	key[32..48].copy_from_slice(&entry.accepted.to_be_bytes());
	key[48..].copy_from_slice(&entry.identity);
	order_fingerprint(&mut total.order, &key, &entry.identity)?;
	let mut state = [0u8; 34];
	state[..32].copy_from_slice(&entry.owner);
	state[32] = b's';
	state[33] = match entry.state {
		DurableState::Unknown => 0,
		DurableState::Completed => 1,
		DurableState::Failed => 2,
	};
	count_key(counters, &state);
	if !valid_tool(entry.tool) {
		bail!("invalid archive index tool");
	}
	let mut tool = [0u8; 97];
	tool[..32].copy_from_slice(&entry.owner);
	tool[32] = b't';
	let end = 33 + entry.tool.len();
	tool[33..end].copy_from_slice(entry.tool.as_bytes());
	count_key(counters, &tool[..end]);
	Ok(())
}
fn partition(
	slot: &Slot,
	rows: &impl ReadableTable<&'static [u8], &'static [u8]>,
	number: usize,
	deadline: Instant,
	cancelled: &AtomicBool,
) -> Result<ColdTotals> {
	let start = [(number * 256 / COLD_ROW_WORKERS) as u8];
	let end = [((number + 1) * 256 / COLD_ROW_WORKERS) as u8];
	let upper = if number + 1 == COLD_ROW_WORKERS {
		std::ops::Bound::Unbounded
	} else {
		std::ops::Bound::Excluded(end.as_slice())
	};
	let mut total = ColdTotals::default();
	let mut originals = runs::RowExpected::new(&slot.root)?;
	let mut counters: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
	for pair in rows.range::<&[u8]>((std::ops::Bound::Included(start.as_slice()), upper))? {
		live(cancelled, deadline)?;
		let (key, raw) = pair?;
		total.row_sum.row(key.value(), raw.value(), true)?;
		let entry = codec::view(raw.value())?;
		if key.value() != entry.identity {
			bail!("archive index identity changed");
		}
		originals.push(order_image(&entry.identity, entry.stamp))?;
		total.ids.add(b"id", key.value(), 1);
		project_view(&entry, &mut total, &mut counters)?;
		total.rows += 1;
		if total.rows.is_multiple_of(BUILD_CHUNK as u64) {
			for (key, copies) in std::mem::take(&mut counters) {
				total.counts.add(b"count", &key, copies);
			}
		}
	}
	for (key, copies) in counters {
		total.counts.add(b"count", &key, copies);
	}
	let original_stream = originals.finish()?;
	if std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref() == Some(std::ffi::OsStr::new("1")) {
		eprintln!("archive_index cold_stage=row_expected_identity_stream_complete partition={number} rows={} bytes={} runs={} full_stamp_bytes=72 identity_bytes=32 naturally_ordered=true", total.rows, original_stream.byte_length(), original_stream.run_count());
	}
	total.sources.push((number, original_stream));
	Ok(total)
}
fn identities(
	ids: &impl ReadableTable<&'static [u8], u8>,
	deadline: Instant,
	cancelled: &AtomicBool,
) -> Result<(Fingerprint, u64)> {
	let mut total = Fingerprint::default();
	let mut checked = 0u64;
	for pair in ids.iter()? {
		live(cancelled, deadline)?;
		let (key, value) = pair?;
		if key.value().len() != 32 || value.value() != 1 {
			bail!("archive identity index changed");
		}
		total.add(b"id", key.value(), 1);
		checked += 1;
	}
	Ok((total, checked))
}
fn original_cohort(
	slot: &Slot,
	cohort: &mut Vec<(String, FileStamp)>,
	changes: &mut Vec<Entry>,
	deadline: Instant,
	cancelled: &AtomicBool,
	output: &Sender,
) -> Result<()> {
	// Disk inode locality may differ from owner/time ordering, especially when
	// writers created originals concurrently. Sort only this bounded cohort.
	cohort.sort_unstable_by_key(|(_, stamp)| (stamp.device, stamp.inode));
	for (filename, expected) in cohort.drain(..) {
		live(cancelled, deadline)?;
		let actual = stamp(&slot.archive, &filename).map_err(|error| {
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
			{
				anyhow!("archive original identity coverage changed: {error}")
			} else {
				error
			}
		})?;
		if actual != expected {
			changes.push(checked_original(slot, &filename)?);
		}
		if changes.len() == BUILD_CHUNK {
			output
				.send(Message::Changes(std::mem::take(changes)))
				.map_err(|_| anyhow!("archive writer unavailable"))?;
		}
	}
	Ok(())
}

fn ordered(
	order: &impl ReadableTable<&'static [u8], &'static [u8]>,
	bounds: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>),
	deadline: Instant,
	cancelled: &AtomicBool,
) -> Result<(Fingerprint, u64)> {
	let mut total = Fingerprint::default();
	let mut checked = 0u64;
	for pair in order.range::<&[u8]>(bounds)? {
		live(cancelled, deadline)?;
		let (key, value) = pair?;
		order_fingerprint(&mut total, key.value(), value.value())?;
		checked += 1;
	}
	Ok((total, checked))
}

fn order_boundaries(
	rows: &impl ReadableTable<&'static [u8], &'static [u8]>,
	deadline: Instant,
) -> Result<Vec<[u8; 80]>> {
	// Samples choose only load-balancing boundaries. The scans below cover the
	// entire key space, including malformed keys outside all sampled bounds.
	let mut samples = Vec::with_capacity(ORDER_BOUND_SAMPLES);
	for pair in rows.iter()?.take(ORDER_BOUND_SAMPLES) {
		if Instant::now() >= deadline {
			bail!("archive index preparation deadline");
		}
		let (identity, raw) = pair?;
		let entry = codec::view(raw.value())?;
		if identity.value() != entry.identity {
			bail!("archive index identity changed");
		}
		let mut key = [0u8; 80];
		key[..32].copy_from_slice(&entry.owner);
		key[32..48].copy_from_slice(&entry.accepted.to_be_bytes());
		key[48..].copy_from_slice(&entry.identity);
		samples.push(key);
	}
	samples.sort_unstable();
	let mut boundaries = Vec::with_capacity(ORDER_WORKERS - 1);
	for part in 1..ORDER_WORKERS {
		let position = part * samples.len() / ORDER_WORKERS;
		if position > 0 && position < samples.len() {
			boundaries.push(samples[position]);
		}
	}
	boundaries.dedup();
	Ok(boundaries)
}

// All tables belong to the caller's same immutable read snapshot.
fn table_rows(
	database: &Database,
	slot: &Slot,
	rows: &(impl ReadableTable<&'static [u8], &'static [u8]> + Sync),
	order: &(impl ReadableTable<&'static [u8], &'static [u8]> + Sync),
	ids: &(impl ReadableTable<&'static [u8], u8> + Sync),
	plan: ScanPlan<'_>,
	validate: impl FnOnce(&ColdTotals) -> Result<bool>,
) -> Result<ColdTotals> {
	let ScanPlan {
		deadline,
		cache_file,
		epoch,
	} = plan;
	let started = Instant::now();
	let trace =
		std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref() == Some(std::ffi::OsStr::new("1"));
	let mut resources = ScanResources {
		started,
		budget: epoch.map(|_| runs::OriginalBudget::new(trace, started)),
	};
	let result = (|| {
		let (mut total, observed) =
			table_phase(database, slot, rows, order, ids, plan, &mut resources)?;
		if epoch.is_none() {
			if let Some(file) = cache_file {
				CacheReadHint::release_clean_pages(file);
			}
			if trace {
				eprintln!(
					"archive_index cold_stage=index_tables_complete elapsed_ms={}",
					started.elapsed().as_millis()
				);
			}
		}
		match (observed, resources.budget.as_mut()) {
			(Some(observed), Some(budget)) => {
				if !validate(&total)? {
					bail!("archive table fingerprints changed");
				}
				if trace {
					eprintln!("archive_index cold_stage=table_fingerprints_verified elapsed_ms={} overlapped_observation=true", started.elapsed().as_millis());
				}
				if let Some(epoch) = epoch {
					epoch.check(slot)?;
					epoch.trace("parallel_epoch_handoff_verified");
				}
				#[cfg(test)]
				parallel_event(slot, ParallelEvent::BeforeJoin);
				total.originals = runs::verify_observed(
					database,
					slot,
					std::mem::take(&mut total.sources),
					Some(observed),
					deadline,
					budget,
				)?;
			}
			(None, None) => {
				// No content watch: retain the original serial scan/join/fingerprint order.
				total.originals =
					runs::verify(database, slot, std::mem::take(&mut total.sources), deadline)?;
				if !validate(&total)? {
					bail!("archive table fingerprints changed");
				}
				if trace {
					eprintln!("archive_index cold_stage=table_fingerprints_verified elapsed_ms={} overlapped_observation=false", started.elapsed().as_millis());
				}
			}
			_ => bail!("archive observation scheduling coverage changed"),
		}
		if let Some(epoch) = epoch {
			epoch.check(slot)?;
		}
		Ok(total)
	})();
	// A fold can notice the changed watcher before its next explicit epoch probe.
	let result = match epoch {
		Some(epoch) => epoch.check(slot).and(result),
		None => result,
	};
	if let Some(budget) = &resources.budget {
		budget.trace();
	}
	result
}

// All tables belong to the caller's same immutable read snapshot.
fn table_phase(
	database: &Database,
	slot: &Slot,
	rows: &(impl ReadableTable<&'static [u8], &'static [u8]> + Sync),
	order: &(impl ReadableTable<&'static [u8], &'static [u8]> + Sync),
	ids: &(impl ReadableTable<&'static [u8], u8> + Sync),
	plan: ScanPlan<'_>,
	resources: &mut ScanResources,
) -> Result<(ColdTotals, Option<runs::Observed>)> {
	let ScanPlan {
		deadline,
		cache_file,
		epoch,
	} = plan;
	let started = resources.started;
	let budget = &mut resources.budget;
	let table_started = started.elapsed();
	let trace =
		std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref() == Some(std::ffi::OsStr::new("1"));
	let boundaries = order_boundaries(rows, deadline)?;
	let order_parts = boundaries.len() + 1;
	if trace {
		eprintln!(
			"archive_index cold_stage=table_order_boundaries_complete partitions={order_parts} sample_limit={ORDER_BOUND_SAMPLES} table_elapsed_ms={}",
			started.elapsed().as_millis()
		);
	}
	let table_parts = COLD_ROW_WORKERS + 1 + order_parts;
	let expected_parts = table_parts + 2 * usize::from(epoch.is_some());
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(COLD_ROW_WORKERS)
		.build()?;
	let cancelled = AtomicBool::new(false);
	std::thread::scope(|scope| {
		let (send, receive) = std::sync::mpsc::sync_channel::<Message>(1);
		let cancellation = &cancelled;
		if epoch.is_some() {
			let namespace_send = send.clone();
			scope.spawn(move || {
				let begin = started.elapsed();
				report_worker(
					|| {
						let (sum, names) = namespace_observation(slot, deadline, cancellation)?;
						Ok(Message::Namespace(sum, names, begin, started.elapsed()))
					},
					&namespace_send,
					cancellation,
				);
			});
			let original_send = send.clone();
			scope.spawn(move || {
				let begin = started.elapsed();
				report_worker(
					|| {
						let observed = runs::observe(slot, deadline, cancellation)?;
						Ok(Message::Observed(
							Box::new(observed),
							begin,
							started.elapsed(),
						))
					},
					&original_send,
					cancellation,
				);
			});
		}
		{
			let row_send = send.clone();
			let pool_failure = send.clone();
			scope.spawn(move || {
				let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pool.install(|| {
					(0..COLD_ROW_WORKERS).into_par_iter().for_each_with(
						row_send,
						|sender, number| {
							report_worker(|| {
							let part_started = trace.then(Instant::now);
								#[cfg(test)]
								if number == 0 { parallel_event(slot, ParallelEvent::TableStarted); }
							let result = partition(slot, rows, number, deadline, cancellation);
							let complete = started.elapsed();
							if let Some(part_started) = part_started {
								eprintln!(
									"archive_index cold_stage=table_row_partition_complete partition={number} rows={} success={} elapsed_ms={} table_elapsed_ms={}",
									result.as_ref().map_or(0, |part| part.rows),
									result.is_ok(),
									part_started.elapsed().as_millis(),
									started.elapsed().as_millis()
								);
							}
							result.map(|part| Message::Rows(Box::new(part), complete))
							}, sender, cancellation);
						},
					)
				})));
				if result.is_err() {
					report_worker(|| Err(anyhow!("archive ROW pool panicked")), &pool_failure, cancellation);
				}
			});
			let id_send = send.clone();
			scope.spawn(move || {
				report_worker(|| {
				let part_started = trace.then(Instant::now);
				let result = identities(ids, deadline, cancellation);
				let complete = started.elapsed();
				if let Some(part_started) = part_started {
					eprintln!(
						"archive_index cold_stage=table_ids_complete rows={} success={} elapsed_ms={} table_elapsed_ms={}",
						result.as_ref().map_or(0, |(_, checked)| *checked),
						result.is_ok(),
						part_started.elapsed().as_millis(),
						started.elapsed().as_millis()
					);
				}
				result.map(|(sum, _)| Message::Ids(sum, complete))
				}, &id_send, cancellation);
			});
		}
		for part in 0..order_parts {
			let low = if part == 0 {
				std::ops::Bound::Unbounded
			} else {
				std::ops::Bound::Included(boundaries[part - 1].as_slice())
			};
			let high = if part == boundaries.len() {
				std::ops::Bound::Unbounded
			} else {
				std::ops::Bound::Excluded(boundaries[part].as_slice())
			};
			let order_send = send.clone();
			scope.spawn(move || {
				report_worker(|| {
				let part_started = trace.then(Instant::now);
				let result = ordered(order, (low, high), deadline, cancellation);
				let complete = started.elapsed();
				if let Some(part_started) = part_started {
					eprintln!(
						"archive_index cold_stage=table_order_partition_complete partition={part} rows={} success={} elapsed_ms={} table_elapsed_ms={}",
						result.as_ref().map_or(0, |(_, checked)| *checked),
						result.is_ok(),
						part_started.elapsed().as_millis(),
						started.elapsed().as_millis()
					);
				}
				result.map(|(sum, _)| Message::Order(sum, complete))
				}, &order_send, cancellation);
			});
		}
		drop(send);
		let result = (|| {
			let mut total = ColdTotals::default();
			let mut finished = 0;
			let mut table_finished = 0;
			let mut table_complete = None;
			let mut table_reported = false;
			let mut observed = None;
			let mut observed_times = None;
			let mut changes = Vec::new();
			let mut fold_calls = 0u64;
			let mut fold_elapsed = Duration::ZERO;
			let mut fold_max = Duration::ZERO;
			// Count only advice inside this coordinator. Periodic release is
			// disabled here; table_rows and cold_rows retain their final release.
			let cache_advice_calls = 0u64;
			let cache_advice_elapsed = Duration::ZERO;
			let cache_advice_max = Duration::ZERO;
			while finished < expected_parts {
				if let Some(epoch) = epoch {
					epoch.check(slot)?;
				}
				match receive.recv_timeout(MAINTENANCE_INTERVAL) {
					Ok(Message::Changes(entries)) => changes = entries,
					Ok(Message::Rows(part, complete)) => {
						table_complete = Some(
							table_complete.map_or(complete, |last: Duration| last.max(complete)),
						);
						total.merge(*part)?;
						finished += 1;
						table_finished += 1;
					}
					Ok(Message::Ids(value, complete)) => {
						table_complete = Some(
							table_complete.map_or(complete, |last: Duration| last.max(complete)),
						);
						total.actual_ids = Some(value);
						finished += 1;
						table_finished += 1;
					}
					Ok(Message::Order(value, complete)) => {
						table_complete = Some(
							table_complete.map_or(complete, |last: Duration| last.max(complete)),
						);
						total
							.actual_order
							.get_or_insert_with(Fingerprint::default)
							.merge(value);
						finished += 1;
						table_finished += 1;
					}
					Ok(Message::Namespace(sum, names, begin, end)) => {
						if epoch.is_none() || total.namespace.is_some() {
							bail!("duplicate archive namespace observation result");
						}
						total.namespace = Some((sum, names));
						finished += 1;
						if trace {
							eprintln!("archive_index cold_stage=parallel_namespace_complete rows={names} start_us={} complete_us={} elapsed_ms={} complete_namespace_rescan=true namespace_workers=1", begin.as_micros(), end.as_micros(), end.saturating_sub(begin).as_millis());
						}
					}
					Ok(Message::Observed(value, begin, end)) => {
						if epoch.is_none() || observed.is_some() {
							bail!("duplicate archive observation result");
						}
						observed = Some(*value);
						observed_times = Some((begin, end));
						finished += 1;
					}
					Ok(Message::OriginalDone(_)) => {
						bail!("unexpected archive original checker result")
					}
					Ok(Message::Failed(error)) => return Err(error),
					Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
					Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
						bail!("archive checker unavailable")
					}
				}
				if table_finished == table_parts && !table_reported {
					table_reported = true;
					let complete = table_complete
						.ok_or_else(|| anyhow!("archive table completion clock unavailable"))?;
					#[cfg(test)]
					parallel_event(slot, ParallelEvent::TablesComplete);
					if epoch.is_some() {
						if let Some(file) = cache_file {
							CacheReadHint::release_clean_pages(file);
						}
						if trace {
							eprintln!(
								"archive_index cold_stage=index_tables_complete elapsed_ms={}",
								complete.as_millis()
							);
						}
					}
				}
				let fold_started = trace.then(Instant::now);
				#[cfg(test)]
				if epoch.is_some() {
					parallel_event(slot, ParallelEvent::BeforeFold);
				}
				fold_cache_changes(database, slot, &mut changes)?;
				if let Some(fold_started) = fold_started {
					let elapsed = fold_started.elapsed();
					fold_calls += 1;
					fold_elapsed += elapsed;
					fold_max = fold_max.max(elapsed);
				}
				if let Some(budget) = budget.as_mut() {
					budget.maintain();
				}
			}
			if total.rows != rows.len()? {
				bail!("archive row range coverage changed");
			}
			if table_finished != table_parts
				|| observed.is_some() != epoch.is_some()
				|| total.namespace.is_some() != epoch.is_some()
			{
				bail!("archive parallel scan coverage changed");
			}
			if let Some(epoch) = epoch {
				epoch.check(slot)?;
			}
			if trace {
				if let (Some(table_end), Some((observed_start, observed_end))) =
					(table_complete, observed_times)
				{
					let overlap = table_end
						.min(observed_end)
						.saturating_sub(table_started.max(observed_start));
					eprintln!("archive_index cold_stage=parallel_scan_complete table_start_us={} table_complete_us={} observation_start_us={} observation_complete_us={} overlap_us={} coordinator_complete_us={} observation_results=1", table_started.as_micros(), table_end.as_micros(), observed_start.as_micros(), observed_end.as_micros(), overlap.as_micros(), started.elapsed().as_micros());
				}
			}
			if trace {
				eprintln!(
					"archive_index cold_stage=table_coordinator_complete rows={} parts={finished} elapsed_ms={} fold_calls={fold_calls} fold_elapsed_us={} fold_max_us={} cache_advice_calls={cache_advice_calls} cache_advice_elapsed_us={} cache_advice_max_us={}",
					total.rows,
					started.elapsed().as_millis(),
					fold_elapsed.as_micros(),
					fold_max.as_micros(),
					cache_advice_elapsed.as_micros(),
					cache_advice_max.as_micros()
				);
			}
			Ok((total, observed))
		})();
		cancelled.store(true, Ordering::Relaxed);
		drop(receive);
		result
	})
}

// All tables belong to the caller's same immutable read snapshot.
pub(super) fn cold_rows(
	database: &Database,
	slot: &Slot,
	rows: &(impl ReadableTable<&'static [u8], &'static [u8]> + Sync),
	order: &(impl ReadableTable<&'static [u8], &'static [u8]> + Sync),
	ids: &(impl ReadableTable<&'static [u8], u8> + Sync),
	plan: ScanPlan<'_>,
	validate: impl FnOnce(&ColdTotals) -> Result<bool>,
) -> Result<ColdTotals> {
	let started = Instant::now();
	let trace =
		std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref() == Some(std::ffi::OsStr::new("1"));
	let total = table_rows(database, slot, rows, order, ids, plan, validate)?;
	if trace {
		eprintln!(
			"archive_index cold_stage=tables_complete elapsed_ms={}",
			started.elapsed().as_millis()
		);
	}
	// Complete ROW and observed streams were joined by identity, comparing
	// every stamp byte. Directory windows only schedule the metadata reads.
	// Reclaim only disposable cache pages before complete directory coverage.
	if let Some(file) = plan.cache_file {
		CacheReadHint::release_clean_pages(file);
	}
	if trace {
		let original_workers = runs::STAT_WORKERS;
		eprintln!("archive_index row_partitions={COLD_ROW_WORKERS} order_partitions={ORDER_WORKERS} original_stat_workers={original_workers} maximum_changed_original_cohort={BUILD_CHUNK} complete_order_ranges=true random_original_row_lookups=false");

		runs::trace();
		let (namespace_workers, namespace_cohort, namespace_schedule) = if plan.epoch.is_some() {
			(1, 1, "parallel_content_watch")
		} else {
			(COLD_ROW_WORKERS, 4096, "serial_after_stamps")
		};
		eprintln!("archive_index owner_order_identity_bytes=32 namespace_workers={namespace_workers} namespace_name_cohort={namespace_cohort} complete_namespace_rescan=true namespace_schedule={namespace_schedule}");
	}
	Ok(total)
}

#[cfg(test)]
#[path = "request_archive_cold_tests.rs"]
mod tests;

/// Re-enumerate every namespace member; only hash computation is parallel.
/// Bounded batches keep publication catch-up outside the workers' read work.
pub(super) fn directory_coverage(
	database: &Database,
	slot: &Slot,
	changes: &mut Vec<Entry>,
	deadline: Instant,
) -> Result<(Fingerprint, u64)> {
	const NAMES: usize = 4096;
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(COLD_ROW_WORKERS)
		.build()?;
	let mut names = Vec::with_capacity(NAMES);
	let mut total = Fingerprint::default();
	let mut count = 0u64;
	let mut fold = |names: &mut Vec<String>| -> Result<()> {
		if names.is_empty() {
			return Ok(());
		}
		let part = pool.install(|| {
			names
				.par_iter()
				.try_fold(
					Fingerprint::default,
					|mut sum, filename| -> Result<Fingerprint> {
						if Instant::now() >= deadline {
							bail!("archive index preparation deadline");
						}
						let identity = filename
							.strip_suffix(".json")
							.filter(|raw| valid_id(raw))
							.ok_or_else(|| anyhow!("invalid archive member"))?;
						sum.add(b"id", &id(identity)?, 1);
						Ok(sum)
					},
				)
				.try_reduce(
					Fingerprint::default,
					|mut left, right| -> Result<Fingerprint> {
						left.merge(right);
						Ok(left)
					},
				)
		})?;
		total.merge(part);
		count = count
			.checked_add(names.len() as u64)
			.ok_or_else(|| anyhow!("archive directory count overflow"))?;
		names.clear();
		fold_cache_changes(database, slot, changes)
	};
	slot.archive.walk(|_, filename, _| {
		if Instant::now() >= deadline {
			bail!("archive index preparation deadline");
		}
		if staging(filename)? {
			return Ok(());
		}
		names.push(filename.to_owned());
		if names.len() == NAMES {
			fold(&mut names)?;
		}
		Ok(())
	})?;
	fold(&mut names)?;
	Ok((total, count))
}

/// A second complete namespace enumeration may overlap the immutable table and
/// original-stamp scans only inside a stable content-watch/publication epoch.
/// This worker is read-only; the coordinator alone folds pending publications.
fn namespace_observation(
	slot: &Slot,
	deadline: Instant,
	cancelled: &AtomicBool,
) -> Result<(Fingerprint, u64)> {
	#[cfg(test)]
	parallel_event(slot, ParallelEvent::NamespaceStarted);
	let mut sum = Fingerprint::default();
	let mut names = 0u64;
	// This independent physical coverage is accepted only together with the
	// complete observed stream's strict identity merge in the same epoch.
	slot.archive
		.walk_for_complete_identity_join(|_, filename, _| {
			live(cancelled, deadline)?;
			if staging(filename)? {
				return Ok(());
			}
			let identity = filename
				.strip_suffix(".json")
				.filter(|raw| valid_id(raw))
				.ok_or_else(|| anyhow!("invalid archive member"))?;
			sum.add(b"id", &id(identity)?, 1);
			names = names
				.checked_add(1)
				.ok_or_else(|| anyhow!("archive directory count overflow"))?;
			Ok(())
		})?;
	live(cancelled, deadline)?;
	#[cfg(test)]
	parallel_event(slot, ParallelEvent::NamespaceComplete);
	Ok((sum, names))
}
