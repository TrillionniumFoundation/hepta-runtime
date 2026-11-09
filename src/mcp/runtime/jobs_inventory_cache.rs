// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded process-local pages over one fully checked inventory observation.
use super::inventory_source::{self, SourceProof};
use super::*;
use ring::rand::SecureRandom;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

#[path = "jobs_inventory_pending.rs"]
mod pending;
use pending::Pending;

const IDLE_SNAPSHOT_TARGET: usize = 4;
const MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const SNAPSHOT_TTL: Duration = Duration::from_secs(300);
static SNAPSHOTS: OnceLock<Arc<Mutex<SnapshotCache>>> = OnceLock::new();

#[derive(Clone, Copy, Serialize)]
struct ObservationInterval {
	started_unix_ms: u64,
	completed_unix_ms: u64,
	elapsed_ms: u64,
}

impl ObservationInterval {
	fn finish(started_unix_ms: u64, started: Instant) -> Result<Self> {
		Ok(Self {
			started_unix_ms,
			completed_unix_ms: now_ms()
				.try_into()
				.context("inventory clock exceeds JSON range")?,
			elapsed_ms: started
				.elapsed()
				.as_millis()
				.try_into()
				.context("inventory duration exceeds JSON range")?,
		})
	}
}

struct Snapshot {
	root: PathBuf,
	host: Option<String>,
	rows: Vec<InventoryRow>,
	source: SourceProof,
	fingerprint: String,
	token: String,
	created: Instant,
	observation: ObservationInterval,
	retained_bytes: usize,
	invalidated: AtomicBool,
}

impl Snapshot {
	fn expired(&self, now: Instant) -> bool {
		now.saturating_duration_since(self.created) >= SNAPSHOT_TTL
			|| self.invalidated.load(Ordering::Acquire)
	}

	fn bytes(&self) -> usize {
		// All retained payloads have concrete capacities. No private arguments,
		// original JSON buffers or unbounded Value trees survive the observation.
		std::mem::size_of::<Self>()
			+ self.root.capacity()
			+ self.host.as_ref().map_or(0, String::capacity)
			+ self.token.capacity()
			+ self.fingerprint.capacity()
			+ self.rows.capacity() * std::mem::size_of::<InventoryRow>()
			+ self
				.rows
				.iter()
				.map(|row| row.id.capacity() + row.host.capacity() + row.launch_state.capacity())
				.sum::<usize>()
			+ self.source.retained_bytes()
	}
}

#[derive(Default)]
struct SnapshotCache {
	entries: VecDeque<Arc<Snapshot>>,
	pending: VecDeque<Arc<Pending>>,
	bytes: usize,
}

impl SnapshotCache {
	fn prune(&mut self, now: Instant) {
		// In-flight pages keep their allocation charged until their final Arc
		// drops. Expiry cannot turn a slow reader into unaccounted cache memory.
		self.entries
			.retain(|entry| !entry.expired(now) || Arc::strong_count(entry) > 1);
		self.pending.retain(|entry| {
			!entry.expired(now) || Arc::strong_count(entry) > 1 || !entry.finished()
		});
		self.bytes = self
			.entries
			.iter()
			.map(|entry| entry.retained_bytes)
			.sum::<usize>()
			+ self
				.pending
				.iter()
				.map(|entry| entry.reserved_bytes())
				.sum::<usize>();
	}

	fn lookup(
		&mut self,
		root: &Path,
		host: Option<&str>,
		token: &str,
		now: Instant,
	) -> Result<Arc<Snapshot>> {
		self.prune(now);
		self.entries
			.iter()
			.find(|entry| {
				entry.root == root
					&& entry.host.as_deref() == host
					&& entry.token == token
					&& !entry.expired(now)
			})
			.cloned()
			.ok_or_else(|| {
				anyhow::anyhow!(
			"inventory snapshot unavailable, expired or invalidated; restart from the first page"
		)
			})
	}

	fn insert(&mut self, snapshot: Snapshot, now: Instant) -> Result<()> {
		if snapshot.retained_bytes > MAX_SNAPSHOT_BYTES {
			bail!("durable inventory snapshot cache byte bound exceeded; no partial inventory returned");
		}
		self.prune(now);
		if self
			.entries
			.iter()
			.any(|entry| entry.token == snapshot.token)
		{
			bail!("durable inventory snapshot identity collision");
		}
		while self.entries.len() + self.pending.len() >= IDLE_SNAPSHOT_TARGET
			|| self.bytes + snapshot.retained_bytes > MAX_SNAPSHOT_BYTES
		{
			if !pending::remove_idle_entry(self) {
				if self.bytes + snapshot.retained_bytes > MAX_SNAPSHOT_BYTES {
					bail!(
						"durable inventory snapshot byte budget in use; retry a fresh first page"
					);
				}
				// The count target prunes idle cache only; active readers keep their
				// complete allocation and never become an implicit admission cap.
				break;
			}
		}
		self.bytes += snapshot.retained_bytes;
		self.entries.push_back(Arc::new(snapshot));
		Ok(())
	}
}

#[derive(Clone, Copy)]
enum Cursor<'a> {
	Page(&'a str, &'a str),
	Pending(&'a str, u64),
}

fn valid_token(token: &str) -> bool {
	token.len() == 64
		&& token
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn checked_cursor(params: &ProcessListPageParams) -> Result<Option<Cursor<'_>>> {
	if !(1..=128).contains(&params.limit.unwrap_or(128)) {
		bail!("invalid durable job inventory page");
	}
	let Some(cursor) = params.cursor.as_deref() else {
		return Ok(None);
	};
	if cursor.len() > 256 {
		bail!("invalid durable job inventory page");
	}
	if let Some(progress) = cursor.strip_prefix("pending:") {
		let (token, step) = progress
			.split_once(':')
			.context("invalid inventory cursor")?;
		if !valid_token(token) || step.is_empty() || !step.bytes().all(|byte| byte.is_ascii_digit())
		{
			bail!("invalid durable job inventory page");
		}
		return Ok(Some(Cursor::Pending(
			token,
			step.parse().context("invalid inventory step")?,
		)));
	}
	let (token, id) = cursor.split_once(':').context("invalid inventory cursor")?;
	if !valid_token(token) || !valid_name(id) {
		bail!("invalid inventory cursor");
	}
	Ok(Some(Cursor::Page(token, id)))
}

#[cfg(test)]
fn observe(root: &Path, host: Option<&str>, limits: InventoryLimits) -> Result<Snapshot> {
	let started = Instant::now();
	let started_unix_ms = now_ms()
		.try_into()
		.context("inventory clock exceeds JSON range")?;
	let (rows, source) = inventory_source::observe(root, limits, |record| InventoryRow {
		id: record.id,
		host: record.host,
		created_unix_ms: record.created_unix_ms,
		execution_mode: record.execution_mode,
		launch_state: record.launch_state,
	})?;
	snapshot_from_rows(
		root,
		host,
		rows,
		source,
		ObservationInterval::finish(started_unix_ms, started)?,
	)
}

fn snapshot_from_rows(
	root: &Path,
	host: Option<&str>,
	mut rows: Vec<InventoryRow>,
	source: SourceProof,
	observation: ObservationInterval,
) -> Result<Snapshot> {
	// Filtering follows the complete original checks, including private fields
	// on other hosts. Numeric JSON projection is also deferred to preserve that
	// refusal ordering without allowing serde_json::json! to panic on a wide u128.
	rows.retain(|row| host.is_none_or(|host| row.host == host));
	if rows
		.iter()
		.any(|row| row.created_unix_ms > u128::from(u64::MAX))
	{
		bail!("durable inventory selected timestamp exceeds the JSON response range");
	}
	rows.sort_by(|left, right| left.id.cmp(&right.id));
	let fingerprint = inventory_snapshot_digest(&rows, host, &root.to_string_lossy())?;
	let token = random_token()?;
	let mut snapshot = Snapshot {
		root: root.to_path_buf(),
		host: host.map(str::to_owned),
		rows,
		source,
		fingerprint,
		token,
		created: Instant::now(),
		observation,
		retained_bytes: 0,
		invalidated: AtomicBool::new(false),
	};
	snapshot.retained_bytes = snapshot.bytes();
	Ok(snapshot)
}

fn random_token() -> Result<String> {
	let mut random = [0u8; 32];
	ring::rand::SystemRandom::new()
		.fill(&mut random)
		.map_err(|_| anyhow::anyhow!("durable inventory snapshot identity unavailable"))?;
	Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn render(
	snapshot: &Snapshot,
	params: &ProcessListPageParams,
	after: Option<&str>,
	validation: Option<ObservationInterval>,
) -> Result<(String, bool)> {
	let start = match after {
		None => 0,
		Some(id) => {
			snapshot
				.rows
				.binary_search_by(|row| row.id.as_str().cmp(id))
				.map_err(|_| anyhow::anyhow!("inventory cursor unavailable"))?
				+ 1
		}
	};
	let mut end = (start + usize::from(params.limit.unwrap_or(128))).min(snapshot.rows.len());
	loop {
		let more = end < snapshot.rows.len();
		let next = if more {
			Some(format!("{}:{}", snapshot.token, snapshot.rows[end - 1].id))
		} else {
			None
		};
		let value = json!({"jobs":&snapshot.rows[start..end],"total":snapshot.rows.len(),
			"next_cursor":next,"has_more":more,"inventory_complete":!more,"validation_pending":false,
			"snapshot_sha256":snapshot.fingerprint,"status_authoritative":false,
			"snapshot_observation":snapshot.observation,
			"source_validation":validation.unwrap_or(snapshot.observation),"observation_atomic":false,
			"snapshot_semantics":"registry_metadata_at_observation"});
		let text = serde_json::to_string(&value)?;
		let wire = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(
			text.clone(),
		)]);
		if serde_json::to_vec(&wire)?.len() <= 64 * 1024 {
			return Ok((text, more));
		}
		if end <= start + 1 {
			bail!("one durable job identity exceeds the inventory page budget");
		}
		end -= 1;
	}
}

fn request_at(
	root: &Path,
	params: &ProcessListPageParams,
	limits: InventoryLimits,
	cache: &Arc<Mutex<SnapshotCache>>,
) -> Result<String> {
	let cursor = checked_cursor(params)?;
	if let Some(Cursor::Pending(token, step)) = cursor {
		return pending::resume(root, params, cache, token, step);
	}
	if let Some(Cursor::Page(token, id)) = cursor {
		let snapshot = cache
			.lock()
			.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?
			.lookup(root, params.host.as_deref(), token, Instant::now())?;
		return pending::start_validation(root, params, limits, cache, snapshot, id);
	}
	// Every first page starts a fresh full observation. Pending responses expose
	// no rows; bounded steps must finish every original before any page is visible.
	pending::start_observation(root, params, limits, cache)
}

pub(super) fn list(root: &Path, params: &ProcessListPageParams) -> Result<String> {
	// Pending polls never restart work. Background workers own their retained
	// payload reservation independently of the caller's lifetime.
	request_at(
		root,
		params,
		InventoryLimits::default(),
		SNAPSHOTS.get_or_init(|| Arc::new(Mutex::new(SnapshotCache::default()))),
	)
}

#[cfg(test)]
fn page_at(
	root: &Path,
	params: &ProcessListPageParams,
	limits: InventoryLimits,
	cache: &Arc<Mutex<SnapshotCache>>,
) -> Result<String> {
	let mut request = params.clone();
	let started = Instant::now();
	loop {
		let text = request_at(root, &request, limits, cache)?;
		let value: Value = serde_json::from_str(&text)?;
		if value["validation_pending"] != true {
			return Ok(text);
		}
		if started.elapsed() > Duration::from_secs(35) {
			bail!("inventory test wait exceeded observation deadline");
		}
		request.cursor = value["next_cursor"].as_str().map(str::to_owned);
		std::thread::sleep(Duration::from_millis(1));
	}
}

#[cfg(test)]
#[path = "jobs_inventory_cache_tests.rs"]
mod tests;
