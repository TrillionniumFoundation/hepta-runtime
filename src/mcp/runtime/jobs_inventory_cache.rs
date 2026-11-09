// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded process-local pages over one fully checked inventory observation.
use super::inventory_source::{self, SourceProof};
use super::*;
use ring::rand::SecureRandom;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

const IDLE_SNAPSHOT_TARGET: usize = 4;
const MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const SNAPSHOT_TTL: Duration = Duration::from_secs(300);
static SNAPSHOTS: OnceLock<Mutex<SnapshotCache>> = OnceLock::new();

struct Snapshot {
	root: PathBuf,
	host: Option<String>,
	rows: Vec<InventoryRow>,
	source: SourceProof,
	fingerprint: String,
	token: String,
	created: Instant,
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
	bytes: usize,
}

impl SnapshotCache {
	fn prune(&mut self, now: Instant) {
		// In-flight pages keep their allocation charged until their final Arc
		// drops. Expiry cannot turn a slow reader into unaccounted cache memory.
		self.entries
			.retain(|entry| !entry.expired(now) || Arc::strong_count(entry) > 1);
		self.bytes = self.entries.iter().map(|entry| entry.retained_bytes).sum();
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
			bail!(
				"durable inventory snapshot cache byte bound exceeded; no partial inventory returned"
			);
		}
		self.prune(now);
		if self
			.entries
			.iter()
			.any(|entry| entry.token == snapshot.token)
		{
			bail!("durable inventory snapshot identity collision");
		}
		while self.entries.len() >= IDLE_SNAPSHOT_TARGET
			|| self.bytes + snapshot.retained_bytes > MAX_SNAPSHOT_BYTES
		{
			let position = self
				.entries
				.iter()
				.position(|entry| Arc::strong_count(entry) == 1);
			let Some(position) = position else {
				if self.bytes + snapshot.retained_bytes > MAX_SNAPSHOT_BYTES {
					bail!(
						"durable inventory snapshot byte budget in use; retry a fresh first page"
					);
				}
				// The entry-count target prunes idle cache only, never active readers.
				break;
			};
			if let Some(old) = self.entries.remove(position) {
				self.bytes -= old.retained_bytes;
			}
		}
		self.bytes += snapshot.retained_bytes;
		self.entries.push_back(Arc::new(snapshot));
		Ok(())
	}
}

fn checked_cursor(params: &ProcessListPageParams) -> Result<Option<(&str, &str)>> {
	if !(1..=128).contains(&params.limit.unwrap_or(128)) {
		bail!("invalid durable job inventory page");
	}
	let Some(cursor) = params.cursor.as_deref() else {
		return Ok(None);
	};
	if cursor.len() > 256 {
		bail!("invalid durable job inventory page");
	}
	let (token, id) = cursor.split_once(':').context("invalid inventory cursor")?;
	if token.len() != 64
		|| !token
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
		|| !valid_name(id)
	{
		bail!("invalid inventory cursor");
	}
	Ok(Some((token, id)))
}

fn observe(root: &Path, host: Option<&str>, limits: InventoryLimits) -> Result<Snapshot> {
	let (mut rows, source) = inventory_source::observe(root, limits, |record| InventoryRow {
		id: record.id,
		host: record.host,
		created_unix_ms: record.created_unix_ms,
		execution_mode: record.execution_mode,
		launch_state: record.launch_state,
	})?;
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
	let mut random = [0u8; 32];
	ring::rand::SystemRandom::new()
		.fill(&mut random)
		.map_err(|_| anyhow::anyhow!("durable inventory snapshot identity unavailable"))?;
	let token = random.iter().map(|byte| format!("{byte:02x}")).collect();
	let mut snapshot = Snapshot {
		root: root.to_path_buf(),
		host: host.map(str::to_owned),
		rows,
		source,
		fingerprint,
		token,
		created: Instant::now(),
		retained_bytes: 0,
		invalidated: AtomicBool::new(false),
	};
	snapshot.retained_bytes = snapshot.bytes();
	Ok(snapshot)
}

fn render(
	snapshot: &Snapshot,
	params: &ProcessListPageParams,
	after: Option<&str>,
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
			"next_cursor":next,"has_more":more,"inventory_complete":!more,
			"snapshot_sha256":snapshot.fingerprint,"status_authoritative":false,
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

fn page_at(
	root: &Path,
	params: &ProcessListPageParams,
	limits: InventoryLimits,
	cache: &Mutex<SnapshotCache>,
) -> Result<String> {
	let cursor = checked_cursor(params)?;
	if let Some((token, id)) = cursor {
		let snapshot = cache
			.lock()
			.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?
			.lookup(root, params.host.as_deref(), token, Instant::now())?;
		// No cache lock is held over original I/O. On failure this handle is
		// permanently invalidated, including same-content restoration after it.
		if let Err(error) = inventory_source::validate(root, limits, &snapshot.source) {
			snapshot.invalidated.store(true, Ordering::Release);
			return Err(error);
		}
		if snapshot.expired(Instant::now()) {
			bail!("inventory snapshot expired or invalidated; restart from the first page");
		}
		return render(&snapshot, params, Some(id)).map(|(text, _)| text);
	}
	// Every first page observes the originals afresh. Failed or incomplete
	// observations publish no snapshot and cannot be completed by later calls.
	cache
		.lock()
		.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?
		.prune(Instant::now());
	let snapshot = observe(root, params.host.as_deref(), limits)?;
	let (text, more) = render(&snapshot, params, None)?;
	if more {
		cache
			.lock()
			.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?
			.insert(snapshot, Instant::now())?;
	}
	Ok(text)
}

pub(super) fn list(root: &Path, params: &ProcessListPageParams) -> Result<String> {
	// Scan admission has no worker-count gate. Snapshot retention keeps its
	// independent cache bounds after each caller owns a complete observation.
	page_at(
		root,
		params,
		InventoryLimits::default(),
		SNAPSHOTS.get_or_init(|| Mutex::new(SnapshotCache::default())),
	)
}

#[cfg(test)]
#[path = "jobs_inventory_cache_tests.rs"]
mod tests;
