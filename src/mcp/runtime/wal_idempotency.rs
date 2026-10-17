// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-only candidate: fail-closed SQLite WAL job identity ledger.
//! No production effect path imports this module or changes the active owner.
use anyhow::{bail, Context, Result};
use rusqlite::{
	params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

const VERSION: &str = "hepta-idempotency-ledger-v3";
const MAX_JOB_BYTES: u64 = 1024 * 1024;
const DB_NAME: &str = "idempotency-v3.sqlite3";

#[derive(Debug, Deserialize)]
struct LegacyJob {
	id: String,
	host: String,
	idempotency_key: Option<String>,
	request_digest: Option<String>,
	#[serde(default)]
	launch_state: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Reserve {
	Fresh(String),
	Existing { job_id: String, phase: String },
}

/// A single, persistently fenced remote attempt. The caller must submit only
/// when this ticket was freshly issued; UNKNOWN is never a retry permit.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
struct SubmitOnce {
	job_id: String,
}

#[derive(Clone, Copy)]
struct ReservationRequest<'a> {
	host: &'a str,
	key: &'a str,
	digest: &'a str,
	proposed_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WriterBinding {
	owner: String,
	epoch: i64,
}

struct Ledger {
	connection: Connection,
	db_path: PathBuf,
	jobs: PathBuf,
	writer: Option<WriterBinding>,
}

fn safe_id(s: &str) -> bool {
	!s.is_empty()
		&& s.len() <= 256
		&& s.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn safe_digest(digest: &str) -> bool {
	digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(unix)]
fn validate_dir(path: &Path) -> Result<()> {
	use std::os::unix::fs::{MetadataExt, PermissionsExt};
	let meta = fs::symlink_metadata(path)?;
	if !meta.is_dir()
		|| meta.file_type().is_symlink()
		|| meta.uid() != unsafe { libc::geteuid() }
		|| meta.permissions().mode() & 0o777 != 0o700
	{
		bail!("ledger requires current-UID private 0700 real directory");
	}
	Ok(())
}

#[cfg(unix)]
fn directory_epoch(path: &Path) -> Result<(u64, u64, i64, i64, i64, i64)> {
	use std::os::unix::fs::MetadataExt;
	validate_dir(path)?;
	let m = fs::symlink_metadata(path)?;
	Ok((
		m.dev(),
		m.ino(),
		m.mtime(),
		m.mtime_nsec(),
		m.ctime(),
		m.ctime_nsec(),
	))
}

#[cfg(unix)]
fn read_original(path: &Path) -> Result<LegacyJob> {
	use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
	let before = fs::symlink_metadata(path)?;
	let valid = |m: &fs::Metadata| {
		m.is_file()
			&& !m.file_type().is_symlink()
			&& m.uid() == unsafe { libc::geteuid() }
			&& m.nlink() == 1
			&& m.permissions().mode() & 0o777 == 0o600
			&& (1..=MAX_JOB_BYTES).contains(&m.len())
	};
	let identity = |m: &fs::Metadata| {
		(
			m.dev(),
			m.ino(),
			m.len(),
			m.mtime(),
			m.mtime_nsec(),
			m.ctime(),
			m.ctime_nsec(),
		)
	};
	if !valid(&before) {
		bail!("legacy record must be current-owner single-link 0600 file");
	}
	let mut handle = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
		.open(path)?;
	let opened = handle.metadata()?;
	if !valid(&opened) || identity(&opened) != identity(&before) {
		bail!("legacy record identity changed before read");
	}
	let mut bytes = Vec::with_capacity(before.len() as usize);
	(&mut handle)
		.take(MAX_JOB_BYTES + 1)
		.read_to_end(&mut bytes)?;
	if bytes.len() as u64 != before.len() {
		bail!("legacy record size changed while reading");
	}
	let after = handle.metadata()?;
	let path_after = fs::symlink_metadata(path)?;
	if identity(&opened) != identity(&after)
		|| identity(&opened) != identity(&path_after)
		|| !valid(&path_after)
	{
		bail!("legacy record changed during read");
	}
	let value: LegacyJob = serde_json::from_slice(&bytes)
		.context("corrupt original job identity refuses entire bootstrap")?;
	if !safe_id(&value.id)
		|| path.file_name().and_then(|p| p.to_str()) != Some(format!("{}.json", value.id).as_str())
	{
		bail!("legacy job id does not match filename");
	}
	if !safe_id(&value.host)
		|| value
			.idempotency_key
			.as_ref()
			.is_some_and(|k| k.is_empty() || k.len() > 256)
		|| value
			.request_digest
			.as_deref()
			.is_some_and(|d| !safe_digest(d))
	{
		bail!("invalid legacy host/key/digest");
	}
	Ok(value)
}

// DB-transaction epoch check is only an admission model. Production
// submission still needs an external cross-controller owner lock held until
// the actual remote effect has been handed off and reconciled.
fn require_current_writer(txn: &Transaction<'_>, proof: Option<&WriterBinding>) -> Result<()> {
	let row: Option<(String, i64, String)> = txn
		.query_row(
			"SELECT owner, epoch, phase FROM writer_authority WHERE slot=1",
			[],
			|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
		)
		.optional()?;
	match (row, proof) {
		// Existing unfenced tests may use an isolated ledger only before a
		// writer has been established. No configured controller may bypass it.
		(None, None) => Ok(()),
		(Some((owner, epoch, phase)), Some(proof))
			if owner == proof.owner && epoch == proof.epoch && phase == "admitting" =>
		{
			Ok(())
		}
		_ => bail!("current writer/epoch is frozen, absent or superseded"),
	}
}

// SQLite may open a preexisting -wal or -shm inode during connect. A
// substituted link or wide-mode sidecar must not be trusted as WAL state.
#[cfg(unix)]
fn validate_existing_sidecars(path: &Path) -> Result<()> {
	use std::os::unix::fs::{MetadataExt, PermissionsExt};
	for suffix in ["-wal", "-shm"] {
		let mut name = path.as_os_str().to_os_string();
		name.push(suffix);
		let sidecar = PathBuf::from(name);
		match fs::symlink_metadata(&sidecar) {
			Ok(meta) => {
				if !meta.is_file()
					|| meta.file_type().is_symlink()
					|| meta.uid() != unsafe { libc::geteuid() }
					|| meta.nlink() != 1
					|| meta.permissions().mode() & 0o7777 != 0o600
				{
					bail!("WAL sidecar inode or permissions unsafe");
				}
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error).context("WAL sidecar metadata unavailable"),
		}
	}
	Ok(())
}

impl Ledger {
	fn connect(path: &Path, creating: bool) -> Result<Connection> {
		#[cfg(unix)]
		validate_existing_sidecars(path)?;
		let connection = Connection::open_with_flags(
			path,
			OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
		)?;
		#[cfg(unix)]
		validate_existing_sidecars(path)?;
		connection.busy_timeout(Duration::from_secs(20))?;
		// Reopen must not reassert WAL mode under concurrent admissions.
		let pragma = if creating {
			"PRAGMA journal_mode=WAL"
		} else {
			"PRAGMA journal_mode"
		};
		let mode: String = connection.query_row(pragma, [], |r| r.get(0))?;
		if mode != "wal" {
			bail!("WAL admission required");
		}
		connection.execute_batch(
			"PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;",
		)?;
		Ok(connection)
	}

	fn create_private(root: &Path, jobs: &Path) -> Result<Self> {
		validate_dir(root)?;
		validate_dir(jobs)?;
		let db = root.join(DB_NAME);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			OpenOptions::new()
				.write(true)
				.create_new(true)
				.mode(0o600)
				.custom_flags(libc::O_NOFOLLOW)
				.open(&db)?;
		}
		let connection = Self::connect(&db, true)?;
		connection.execute_batch(
			"CREATE TABLE metadata (
                slot INTEGER PRIMARY KEY CHECK (slot = 1),
                version TEXT NOT NULL, root TEXT NOT NULL,
                jobs_root TEXT NOT NULL, jobs_dev TEXT NOT NULL,
                jobs_inode TEXT NOT NULL, sealed INTEGER NOT NULL CHECK (sealed IN (0,1)),
                scanned INTEGER NOT NULL);
             CREATE TABLE identities (
                host TEXT NOT NULL, idem_key TEXT NOT NULL,
                job_id TEXT NOT NULL UNIQUE, digest TEXT,
                phase TEXT NOT NULL CHECK (phase IN
                  ('legacy','reserved','record_saved','submission_unknown')),
                admitted_owner TEXT, admitted_epoch INTEGER,
                CHECK ((admitted_owner IS NULL AND admitted_epoch IS NULL)
                    OR (admitted_owner IN ('v4','v11') AND admitted_epoch>0)),
                PRIMARY KEY (host, idem_key)
             ) WITHOUT ROWID;
             CREATE TABLE original_job_ids (
                job_id TEXT PRIMARY KEY,
                host TEXT NOT NULL, idem_key TEXT
             ) WITHOUT ROWID;
             CREATE TABLE writer_authority (
                slot INTEGER PRIMARY KEY CHECK(slot=1),
                owner TEXT NOT NULL CHECK(owner IN ('v4','v11')),
                epoch INTEGER NOT NULL CHECK(epoch>0),
                phase TEXT NOT NULL CHECK(phase IN ('admitting','frozen'))
             );",
		)?;
		let root_path = fs::canonicalize(root)?;
		let jobs_path = fs::canonicalize(jobs)?;
		let epoch = directory_epoch(jobs)?;
		connection.execute(
			"INSERT INTO metadata VALUES (1,?1,?2,?3,?4,?5,0,0)",
			params![
				VERSION,
				root_path.to_string_lossy(),
				jobs_path.to_string_lossy(),
				epoch.0.to_string(),
				epoch.1.to_string()
			],
		)?;
		Ok(Self {
			connection,
			db_path: db,
			jobs: jobs_path,
			writer: None,
		})
	}

	fn reopen(root: &Path, jobs: &Path) -> Result<Self> {
		validate_dir(root)?;
		validate_dir(jobs)?;
		let db = root.join(DB_NAME);
		let m = fs::symlink_metadata(&db)?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::{MetadataExt, PermissionsExt};
			if !m.is_file()
				|| m.file_type().is_symlink()
				|| m.nlink() != 1
				|| m.uid() != unsafe { libc::geteuid() }
				|| m.permissions().mode() & 0o777 != 0o600
			{
				bail!("ledger DB inode/permissions unsafe");
			}
		}
		let connection = Self::connect(&db, false)?;
		let check: String = connection.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
		if check != "ok" {
			bail!("ledger DB integrity check refused");
		}
		let meta: (String, String, String, String, String, i64) = connection.query_row(
			"SELECT version,root,jobs_root,jobs_dev,jobs_inode,sealed
                   FROM metadata WHERE slot = 1",
			[],
			|r| {
				Ok((
					r.get(0)?,
					r.get(1)?,
					r.get(2)?,
					r.get(3)?,
					r.get(4)?,
					r.get(5)?,
				))
			},
		)?;
		let root_path = fs::canonicalize(root)?;
		let jobs_path = fs::canonicalize(jobs)?;
		let epoch = directory_epoch(jobs)?;
		if meta.0 != VERSION
			|| meta.1 != root_path.to_string_lossy()
			|| meta.2 != jobs_path.to_string_lossy()
			|| meta.3 != epoch.0.to_string()
			|| meta.4 != epoch.1.to_string()
			|| meta.5 != 1
		{
			bail!("unsealed, rebound or stale ledger refused; no new effects");
		}
		Ok(Self {
			connection,
			db_path: db,
			jobs: jobs_path,
			writer: None,
		})
	}

	/// Test-only initial handoff after a frozen, complete historical import.
	/// This is NOT administrator authentication or a production owner switch.
	fn establish_first_writer(&mut self, owner: &str) -> Result<i64> {
		if !matches!(owner, "v4" | "v11") || self.writer.is_some() {
			bail!("initial writer must be a fresh configured controller");
		}
		let txn = self
			.connection
			.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let sealed: i64 =
			txn.query_row("SELECT sealed FROM metadata WHERE slot=1", [], |r| r.get(0))?;
		let unsettled: i64 = txn.query_row(
			"SELECT COUNT(*) FROM identities WHERE phase != 'legacy'",
			[],
			|r| r.get(0),
		)?;
		if sealed != 1 || unsettled != 0 {
			bail!("initial writer requires sealed unchanged legacy history");
		}
		txn.execute(
			"INSERT INTO writer_authority(slot,owner,epoch,phase)
             VALUES (1,?1,1,'admitting')",
			params![owner],
		)?;
		txn.commit()?;
		self.writer = Some(WriterBinding {
			owner: owner.to_owned(),
			epoch: 1,
		});
		Ok(1)
	}

	/// A restarted controller can name its owner and epoch, but each later
	/// transaction must check the actual database writer row again.
	fn bind_writer(&mut self, owner: &str, epoch: i64) -> Result<()> {
		if !matches!(owner, "v4" | "v11") || epoch < 1 {
			bail!("invalid writer proof");
		}
		let candidate = WriterBinding {
			owner: owner.to_owned(),
			epoch,
		};
		let txn = self
			.connection
			.transaction_with_behavior(TransactionBehavior::Immediate)?;
		require_current_writer(&txn, Some(&candidate))?;
		txn.commit()?;
		self.writer = Some(candidate);
		Ok(())
	}

	/// SQLite serializes this transition with WAL writes. Remote submissions
	/// that already left the DB transaction are NOT drained by this operation.
	fn freeze_writer(&mut self) -> Result<()> {
		let current = self.writer.as_ref().context("writer identity required")?;
		let txn = self
			.connection
			.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let updated = txn.execute(
			"UPDATE writer_authority SET phase='frozen'
             WHERE slot=1 AND owner=?1 AND epoch=?2 AND phase='admitting'",
			params![current.owner, current.epoch],
		)?;
		if updated != 1 {
			bail!("writer already frozen or no longer authoritative");
		}
		txn.commit()?;
		Ok(())
	}

	/// Model a privileged transfer after a completed external drain.
	/// No public MCP entrypoint or real transfer capability invokes this.
	fn promote_frozen_writer(&mut self, successor: &str) -> Result<i64> {
		let current = self
			.writer
			.as_ref()
			.context("frozen owner identity required")?;
		if !matches!(successor, "v4" | "v11")
			|| current.owner == successor
			|| current.epoch == i64::MAX
		{
			bail!("invalid successor owner or epoch");
		}
		let txn = self
			.connection
			.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let updated = txn.execute(
			"UPDATE writer_authority
             SET owner=?1, epoch=epoch+1, phase='admitting'
             WHERE slot=1 AND owner=?2 AND epoch=?3 AND phase='frozen'",
			params![successor, current.owner, current.epoch],
		)?;
		if updated != 1 {
			bail!("owner transfer requires exact previous frozen epoch");
		}
		txn.commit()?;
		let epoch = current.epoch + 1;
		self.writer = None;
		Ok(epoch)
	}

	// Caller must freeze all effect writers and verify this is disposable
	// state before invocation. No production caller currently exists.
	fn bootstrap_frozen(&mut self) -> Result<usize> {
		let before = directory_epoch(&self.jobs)?;
		let txn = self
			.connection
			.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let sealed: i64 = txn.query_row("SELECT sealed FROM metadata WHERE slot = 1", [], |r| {
			r.get(0)
		})?;
		if sealed != 0 {
			bail!("ledger already sealed");
		}
		let mut scanned = 0usize;
		for item in fs::read_dir(&self.jobs)? {
			let entry = item?;
			if entry.path().extension().and_then(|s| s.to_str()) != Some("json") {
				continue;
			}
			let original = read_original(&entry.path())?;
			scanned += 1;
			// Preserve every historical ID, including unkeyed jobs. Otherwise
			// a new keyed reservation could reuse an old unkeyed remote ID.
			txn.execute(
				"INSERT INTO original_job_ids(job_id,host,idem_key) VALUES (?1,?2,?3)",
				params![
					original.id.as_str(),
					original.host.as_str(),
					original.idempotency_key.as_deref()
				],
			)
			.context("duplicate original job ID; bootstrap refused")?;
			if let Some(key) = original.idempotency_key {
				txn.execute(
					"INSERT INTO identities(host,idem_key,job_id,digest,phase)
                        VALUES (?1,?2,?3,?4,'legacy')",
					params![original.host, key, original.id, original.request_digest],
				)
				.context("duplicate original job ID or host/key; bootstrap refused")?;
			}
		}
		if directory_epoch(&self.jobs)? != before {
			bail!("legacy directory changed during bootstrap; no publication");
		}
		txn.execute(
			"UPDATE metadata SET sealed=1, scanned=?1 WHERE slot=1",
			params![i64::try_from(scanned)?],
		)?;
		txn.commit()?;
		Ok(scanned)
	}

	fn reserve(
		&mut self,
		host: &str,
		key: &str,
		digest: &str,
		proposed_id: &str,
	) -> Result<Reserve> {
		let one = ReservationRequest {
			host,
			key,
			digest,
			proposed_id,
		};
		self.reserve_batch(&[one])?
			.into_iter()
			.next()
			.context("empty admission response")
	}

	// One durable FULL-sync WAL commit for a bounded group of independent
	// decisions. All bindings succeed atomically, or none become visible.
	// No remote effects are started while the transaction is held.
	fn reserve_batch(&mut self, entries: &[ReservationRequest<'_>]) -> Result<Vec<Reserve>> {
		if entries.is_empty() || entries.len() > 128 {
			bail!("batch admission requires between 1 and 128 identities");
		}
		for request in entries {
			if !safe_id(request.host)
				|| request.key.is_empty()
				|| request.key.len() > 256
				|| !safe_id(request.proposed_id)
				|| !safe_digest(request.digest)
			{
				bail!("invalid admission host/key/digest/job_id");
			}
		}
		let txn = self
			.connection
			.transaction_with_behavior(TransactionBehavior::Immediate)?;
		require_current_writer(&txn, self.writer.as_ref())?;
		let sealed: i64 =
			txn.query_row("SELECT sealed FROM metadata WHERE slot=1", [], |r| r.get(0))?;
		if sealed != 1 {
			bail!("unsealed ledger refuses new effects");
		}
		let mut results = Vec::with_capacity(entries.len());
		for request in entries {
			let fresh = txn.execute(
				"INSERT INTO identities(host,idem_key,job_id,digest,phase,
                    admitted_owner,admitted_epoch)
                VALUES (?1,?2,?3,?4,'reserved',?5,?6)
                ON CONFLICT(host,idem_key) DO NOTHING",
				params![
					request.host,
					request.key,
					request.proposed_id,
					request.digest,
					self.writer.as_ref().map(|w| w.owner.as_str()),
					self.writer.as_ref().map(|w| w.epoch),
				],
			)?;
			let (id, bound, phase): (String, Option<String>, String) = txn.query_row(
				"SELECT job_id,digest,phase FROM identities
                WHERE host=?1 AND idem_key=?2",
				params![request.host, request.key],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?;
			if bound.as_deref() != Some(request.digest) {
				bail!("idempotency key already bound to another or unknown digest");
			}
			if fresh == 1 {
				// The original-ID registry includes historical UNKEYED jobs.
				// Collisions roll back this entire batch, not just this row.
				txn.execute(
					"INSERT INTO original_job_ids(job_id,host,idem_key) VALUES (?1,?2,?3)",
					params![&id, request.host, request.key],
				)
				.context("job ID already reserved by an existing original identity")?;
			}
			let (owner_host, owner_key): (String, Option<String>) = txn
				.query_row(
					"SELECT host, idem_key FROM original_job_ids WHERE job_id=?1",
					params![&id],
					|row| Ok((row.get(0)?, row.get(1)?)),
				)
				.context("original job-ID registry binding unavailable")?;
			if owner_host != request.host || owner_key.as_deref() != Some(request.key) {
				bail!("job ID owner differs from the exact host/key binding");
			}
			results.push(if fresh == 1 {
				Reserve::Fresh(id)
			} else {
				Reserve::Existing { job_id: id, phase }
			});
		}
		txn.commit()?;
		Ok(results)
	}

	fn mark_saved(&mut self, host: &str, key: &str, job_id: &str, digest: &str) -> Result<()> {
		let path = self.jobs.join(format!("{job_id}.json"));
		let job = read_original(&path)?;
		if job.id != job_id
			|| job.host != host
			|| job.idempotency_key.as_deref() != Some(key)
			|| job.request_digest.as_deref() != Some(digest)
			|| job.launch_state.as_deref() != Some("pending")
		{
			bail!("saved original record not bound to a pending reserved identity");
		}
		let txn = self
			.connection
			.transaction_with_behavior(TransactionBehavior::Immediate)?;
		require_current_writer(&txn, self.writer.as_ref())?;
		let changed = txn.execute(
			"UPDATE identities SET phase='record_saved'
             WHERE host=?1 AND idem_key=?2 AND job_id=?3 AND digest=?4
                   AND phase='reserved'
                   AND admitted_owner IS ?5 AND admitted_epoch IS ?6
                   AND EXISTS (
                       SELECT 1 FROM original_job_ids AS j
                       WHERE j.job_id=?3 AND j.host=?1 AND j.idem_key=?2
                   )",
			params![
				host,
				key,
				job_id,
				digest,
				self.writer.as_ref().map(|w| w.owner.as_str()),
				self.writer.as_ref().map(|w| w.epoch)
			],
		)?;
		if changed != 1 {
			bail!("original identity cannot transition to saved");
		}
		txn.commit()?;
		Ok(())
	}

	/// Persist intent BEFORE any remote submission. A crash, timeout or
	/// transport failure after this transaction must retain the original ID
	/// as UNKNOWN; no caller may obtain another submit ticket by retrying.
	/// An external single-effect-owner permit must span this call and the
	/// actual remote submission before this becomes an effectful API.
	fn begin_remote_submission(
		&mut self,
		host: &str,
		key: &str,
		job_id: &str,
		digest: &str,
	) -> Result<SubmitOnce> {
		if !safe_id(job_id) || !safe_id(host) || key.is_empty() || !safe_digest(digest) {
			bail!("invalid remote submission identity");
		}
		let saved = read_original(&self.jobs.join(format!("{job_id}.json")))?;
		if saved.id != job_id
			|| saved.host != host
			|| saved.idempotency_key.as_deref() != Some(key)
			|| saved.request_digest.as_deref() != Some(digest)
			|| saved.launch_state.as_deref() != Some("pending")
		{
			bail!("remote submission requires exact saved pending original identity");
		}
		let txn = self
			.connection
			.transaction_with_behavior(TransactionBehavior::Immediate)?;
		require_current_writer(&txn, self.writer.as_ref())?;
		let changed = txn.execute(
			"UPDATE identities SET phase='submission_unknown'
             WHERE host=?1 AND idem_key=?2 AND job_id=?3 AND digest=?4
                   AND phase='record_saved'
                   AND admitted_owner IS ?5 AND admitted_epoch IS ?6
                   AND EXISTS (
                       SELECT 1 FROM original_job_ids AS j
                       WHERE j.job_id=?3 AND j.host=?1 AND j.idem_key=?2
                   )",
			params![
				host,
				key,
				job_id,
				digest,
				self.writer.as_ref().map(|w| w.owner.as_str()),
				self.writer.as_ref().map(|w| w.epoch)
			],
		)?;
		if changed != 1 {
			bail!("remote submission was already attempted or not durably saved");
		}
		txn.commit()?;
		Ok(SubmitOnce {
			job_id: job_id.to_owned(),
		})
	}

	fn index_file(&self) -> &Path {
		&self.db_path
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::{Arc, Barrier};
	use std::thread;
	use std::time::Instant;

	const HOSTS: [&str; 6] = ["main", "pocket4", "rog", "mac", "x230", "ai395"];

	struct Fixture {
		temporary: tempfile::TempDir,
		jobs: PathBuf,
	}

	impl Fixture {
		fn new() -> Self {
			use std::os::unix::fs::PermissionsExt;
			let temporary = tempfile::tempdir().unwrap();
			let jobs = temporary.path().join("jobs");
			fs::create_dir(&jobs).unwrap();
			fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();
			Self { temporary, jobs }
		}

		fn root(&self) -> &Path {
			self.temporary.path()
		}

		fn original(&self, id: &str, host: &str, key: Option<&str>, digest: Option<&str>) {
			use std::os::unix::fs::OpenOptionsExt;
			let path = self.jobs.join(format!("{id}.json"));
			let text = serde_json::json!({
				"id": id, "host": host, "idempotency_key": key,
				"request_digest": digest, "launch_state": "pending",
			});
			let mut file = OpenOptions::new()
				.create_new(true)
				.write(true)
				.mode(0o600)
				.open(path)
				.unwrap();
			use std::io::Write;
			file.write_all(text.to_string().as_bytes()).unwrap();
			file.sync_all().unwrap();
		}

		fn seeded(&self, n: usize) {
			for i in 0..n {
				self.original(
					&format!("seed-{i:07}"),
					HOSTS[i % 6],
					Some(&format!("historical-{i:07}")),
					Some(&"a".repeat(64)),
				);
			}
		}

		fn bootstrap(&self) -> Ledger {
			let mut ledger = Ledger::create_private(self.root(), &self.jobs).unwrap();
			ledger.bootstrap_frozen().unwrap();
			ledger
		}
	}

	#[test]
	fn imported_legacy_survives_restart_and_digest_conflict_is_denied() {
		let f = Fixture::new();
		f.original("old-job", "pocket4", Some("old-key"), Some(&"a".repeat(64)));
		let mut ledger = Ledger::create_private(f.root(), &f.jobs).unwrap();
		assert!(Ledger::reopen(f.root(), &f.jobs).is_err());
		assert_eq!(ledger.bootstrap_frozen().unwrap(), 1);
		drop(ledger);
		let mut recovered = Ledger::reopen(f.root(), &f.jobs).unwrap();
		assert_eq!(
			recovered
				.reserve("pocket4", "old-key", &"a".repeat(64), "replay-attempt")
				.unwrap(),
			Reserve::Existing {
				job_id: "old-job".into(),
				phase: "legacy".into()
			}
		);
		assert!(recovered
			.reserve("pocket4", "old-key", &"b".repeat(64), "illicit-replay")
			.is_err());
	}

	#[test]
	fn crash_after_reservation_preserves_original_id_without_relaunch() {
		let f = Fixture::new();
		let mut ledger = f.bootstrap();
		let digest = "a".repeat(64);
		assert_eq!(
			ledger.reserve("main", "same", &digest, "once-id").unwrap(),
			Reserve::Fresh("once-id".into())
		);
		drop(ledger);
		let mut recovered = Ledger::reopen(f.root(), &f.jobs).unwrap();
		assert_eq!(
			recovered
				.reserve("main", "same", &digest, "second-id")
				.unwrap(),
			Reserve::Existing {
				job_id: "once-id".into(),
				phase: "reserved".into()
			}
		);
		// The record was intentionally never written: crash leaves a
		// reservation fence, not proof a remote effect failed or succeeded.
		assert!(!f.jobs.join("once-id.json").exists());
		assert!(recovered
			.mark_saved("main", "same", "once-id", &digest)
			.is_err());
		f.original("once-id", "main", Some("same"), Some(&digest));
		recovered
			.mark_saved("main", "same", "once-id", &digest)
			.unwrap();
		assert_eq!(
			recovered
				.reserve("main", "same", &digest, "third-id")
				.unwrap(),
			Reserve::Existing {
				job_id: "once-id".into(),
				phase: "record_saved".into()
			}
		);
		assert!(recovered
			.mark_saved("main", "same", "once-id", &digest)
			.is_err());
	}

	#[test]

	fn unique_job_id_cannot_bind_to_different_host_or_key() {
		let f = Fixture::new();
		let mut ledger = f.bootstrap();
		assert_eq!(
			ledger
				.reserve("main", "one", &"a".repeat(64), "same-id")
				.unwrap(),
			Reserve::Fresh("same-id".into())
		);
		assert!(ledger
			.reserve("rog", "different", &"a".repeat(64), "same-id")
			.is_err());
		assert_eq!(
			ledger
				.reserve("rog", "different", &"a".repeat(64), "separate-id")
				.unwrap(),
			Reserve::Fresh("separate-id".into())
		);
	}

	#[test]
	fn failed_duplicate_import_rolls_back_entire_legacy_set() {
		let f = Fixture::new();
		f.original("one", "main", Some("legacy-key"), Some(&"a".repeat(64)));
		f.original("two", "main", Some("legacy-key"), Some(&"a".repeat(64)));
		let mut ledger = Ledger::create_private(f.root(), &f.jobs).unwrap();
		assert!(ledger.bootstrap_frozen().is_err());
		let indexed: i64 = ledger
			.connection
			.query_row("SELECT count(*) FROM identities", [], |r| r.get(0))
			.unwrap();
		assert_eq!(indexed, 0);
		assert!(Ledger::reopen(f.root(), &f.jobs).is_err());
		assert!(ledger
			.reserve("main", "legacy-key", &"a".repeat(64), "new-id")
			.is_err());
	}

	#[test]
	fn missing_old_digest_remains_bound_and_cannot_silently_replay() {
		let f = Fixture::new();
		f.original("legacy-id", "mac", Some("legacy-key"), None);
		let mut ledger = f.bootstrap();
		assert!(ledger
			.reserve("mac", "legacy-key", &"a".repeat(64), "attempt-new-id")
			.is_err());
	}

	#[test]
	fn imports_unkeyed_jobs_without_inventing_idempotency_keys() {
		let f = Fixture::new();
		f.original("anon-one", "main", None, None);
		f.original("keyed-two", "main", Some("keyed"), Some(&"a".repeat(64)));
		let mut ledger = Ledger::create_private(f.root(), &f.jobs).unwrap();
		assert_eq!(ledger.bootstrap_frozen().unwrap(), 2);
		let keyed: i64 = ledger
			.connection
			.query_row("SELECT count(*) FROM identities", [], |r| r.get(0))
			.unwrap();
		assert_eq!(keyed, 1);
		let original_ids: i64 = ledger
			.connection
			.query_row("SELECT COUNT(*) FROM original_job_ids", [], |r| r.get(0))
			.unwrap();
		assert_eq!(
			original_ids, 2,
			"unkeyed original IDs remain globally reserved"
		);
	}

	#[test]
	fn imported_unkeyed_job_id_must_not_be_reissued_for_a_new_key() {
		let f = Fixture::new();
		f.original("anonymous-id", "main", None, None);
		let mut ledger = f.bootstrap();
		assert!(
			ledger
				.reserve("rog", "new-key", &"a".repeat(64), "anonymous-id")
				.is_err(),
			"an original unkeyed job identity must remain globally reserved"
		);
	}

	#[test]
	fn collision_with_an_unkeyed_legacy_id_rolls_back_entire_batch() {
		let f = Fixture::new();
		f.original("anonymous-id", "pocket4", None, None);
		let mut ledger = f.bootstrap();
		let digest = "a".repeat(64);
		let requests = [
			ReservationRequest {
				host: "mac",
				key: "new-1",
				digest: &digest,
				proposed_id: "new-id",
			},
			ReservationRequest {
				host: "rog",
				key: "new-2",
				digest: &digest,
				proposed_id: "anonymous-id",
			},
		];
		assert!(ledger.reserve_batch(&requests).is_err());
		let count: i64 = ledger
			.connection
			.query_row("SELECT COUNT(*) FROM identities", [], |row| row.get(0))
			.unwrap();
		assert_eq!(count, 0, "failed batch must not persist the first new key");
	}

	#[test]
	fn symbolic_and_hard_links_and_overpermissive_records_fail_bootstrap() {
		use std::os::unix::fs::{symlink, PermissionsExt};
		for case in ["symlink", "hardlink", "wide"] {
			let f = Fixture::new();
			f.original("original", "main", Some("key"), Some(&"a".repeat(64)));
			let file = f.jobs.join("original.json");
			if case == "symlink" {
				fs::rename(&file, f.root().join("elsewhere.json")).unwrap();
				symlink(f.root().join("elsewhere.json"), &file).unwrap();
			} else if case == "hardlink" {
				fs::hard_link(&file, f.root().join("linked-copy")).unwrap();
			} else {
				fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
			}
			let mut ledger = Ledger::create_private(f.root(), &f.jobs).unwrap();
			assert!(
				ledger.bootstrap_frozen().is_err(),
				"{case} should fail closed"
			);
		}
	}

	#[test]
	fn sealed_index_refuses_wrong_state_root_or_invalid_schema() {
		let one = Fixture::new();
		let two = Fixture::new();
		let ledger = one.bootstrap();

		let db = ledger.index_file().to_path_buf();
		drop(ledger);
		fs::copy(db, two.root().join(DB_NAME)).unwrap();
		use std::os::unix::fs::PermissionsExt;
		fs::set_permissions(two.root().join(DB_NAME), fs::Permissions::from_mode(0o600)).unwrap();
		assert!(Ledger::reopen(two.root(), &two.jobs).is_err());
	}

	#[test]
	fn process_concurrency_same_key_writes_exactly_one_reservation() {
		let f = Fixture::new();
		let ledger = f.bootstrap();
		drop(ledger);
		const N: usize = 32;
		let gate = Arc::new(Barrier::new(N));
		let mut outcomes = thread::scope(|scope| {
			let handles: Vec<_> = (0..N)
				.map(|i| {
					let gate = Arc::clone(&gate);
					let root = f.root();
					let jobs = f.jobs.as_path();
					scope.spawn(move || {
						let mut ledger = Ledger::reopen(root, jobs).unwrap();
						gate.wait();

						ledger
							.reserve(
								"main",
								"shared-key",
								&"a".repeat(64),
								&format!("proposed-{i:03}"),
							)
							.unwrap()
					})
				})
				.collect();
			handles
				.into_iter()
				.map(|h| h.join().unwrap())
				.collect::<Vec<_>>()
		});
		let fresh = outcomes
			.iter()
			.filter(|x| matches!(x, Reserve::Fresh(_)))
			.count();
		assert_eq!(
			fresh, 1,
			"SQLite UNIQUE(host,key) admits exactly one identity"
		);
		let first_id = outcomes
			.iter()
			.find_map(|x| {
				if let Reserve::Fresh(id) = x {
					Some(id.clone())
				} else {
					None
				}
			})
			.unwrap();
		assert!(outcomes.drain(..).all(|x| match x {
			Reserve::Fresh(id) => id == first_id,
			Reserve::Existing { job_id, phase } => job_id == first_id && phase == "reserved",
		}));
		let ledger = Ledger::reopen(f.root(), &f.jobs).unwrap();
		let total: i64 = ledger
			.connection
			.query_row(
				"SELECT count(*) FROM identities WHERE host='main' AND idem_key='shared-key'",
				[],
				|r| r.get(0),
			)
			.unwrap();
		assert_eq!(total, 1);
	}

	#[test]
	fn distinct_six_host_concurrency_reserves_without_shared_python_scan() {
		let f = Fixture::new();
		let ledger = f.bootstrap();
		drop(ledger);
		const N: usize = 32;
		// Main thread releases all workers after they have reopened the DB.
		let gate = Arc::new(Barrier::new(N + 1));
		let begin = Instant::now();
		let (outcomes, reservation_ms) = thread::scope(|scope| {
			let handles: Vec<_> = (0..N)
				.map(|i| {
					let gate = Arc::clone(&gate);
					let root = f.root();
					let jobs = f.jobs.as_path();
					scope.spawn(move || {
						let mut ledger = Ledger::reopen(root, jobs).unwrap();
						gate.wait();
						ledger
							.reserve(
								HOSTS[i % 6],
								&format!("key-{i}"),
								&"a".repeat(64),
								&format!("fresh-{i}"),
							)
							.unwrap()
					})
				})
				.collect();
			gate.wait();
			let transaction_begin = Instant::now();
			let complete = handles
				.into_iter()
				.map(|h| h.join().unwrap())
				.collect::<Vec<_>>();
			(complete, transaction_begin.elapsed().as_secs_f64() * 1000.0)
		});
		assert_eq!(outcomes.len(), N);
		assert!(outcomes.iter().all(|x| matches!(x, Reserve::Fresh(_))));
		println!(
			"sqlite_disposable_unique_key_workers={N} all_reserved={} setup_plus_txn_ms={:.2} txn_only_ms={reservation_ms:.2}",
			outcomes.len(),
			begin.elapsed().as_secs_f64() * 1000.0
		);
	}

	#[test]
	fn bounded_wal_batches_preserve_six_host_uniqueness() {
		let f = Fixture::new();
		let mut ledger = f.bootstrap();
		let digest = "a".repeat(64);
		for n in [1usize, 4, 8, 16, 32] {
			let keys: Vec<_> = (0..n).map(|i| format!("batch-{n}-key-{i}")).collect();
			let ids: Vec<_> = (0..n).map(|i| format!("batch-{n}-id-{i}")).collect();
			let requests: Vec<_> = (0..n)
				.map(|i| ReservationRequest {
					host: HOSTS[i % HOSTS.len()],
					key: &keys[i],
					digest: &digest,
					proposed_id: &ids[i],
				})
				.collect();
			let t = Instant::now();
			let first = ledger.reserve_batch(&requests).unwrap();
			let commit_ms = t.elapsed().as_secs_f64() * 1000.0;
			assert_eq!(first.len(), n);
			assert!(first.iter().all(|r| matches!(r, Reserve::Fresh(_))));
			let second = ledger.reserve_batch(&requests).unwrap();
			assert_eq!(second.len(), n);
			for (i, result) in second.into_iter().enumerate() {
				assert_eq!(
					result,
					Reserve::Existing {
						job_id: ids[i].clone(),
						phase: "reserved".to_owned()
					}
				);
			}
			println!("isolated_wal_batch_size={n} committed={n} durable_commit_ms={commit_ms:.3}");
		}
	}

	#[test]
	fn mismatched_digest_or_duplicate_id_rolls_back_entire_batch() {
		let f = Fixture::new();
		let mut ledger = f.bootstrap();
		let a = "a".repeat(64);
		let b = "b".repeat(64);
		let first = [
			ReservationRequest {
				host: "main",
				key: "same",
				digest: &a,
				proposed_id: "first",
			},
			ReservationRequest {
				host: "main",
				key: "same",
				digest: &b,
				proposed_id: "second",
			},
		];
		assert!(ledger.reserve_batch(&first).is_err());
		let count: i64 = ledger
			.connection
			.query_row("SELECT COUNT(*) FROM identities", [], |r| r.get(0))
			.unwrap();
		assert_eq!(count, 0, "an error must roll back earlier inserts");

		let reused_id = [
			ReservationRequest {
				host: "main",
				key: "a-key",
				digest: &a,
				proposed_id: "same-id",
			},
			ReservationRequest {
				host: "rog",
				key: "b-key",
				digest: &a,
				proposed_id: "same-id",
			},
		];
		assert!(ledger.reserve_batch(&reused_id).is_err());
		let count: i64 = ledger
			.connection
			.query_row("SELECT COUNT(*) FROM identities", [], |r| r.get(0))
			.unwrap();
		assert_eq!(count, 0);
	}

	#[test]
	fn committed_batch_survives_restart_without_issuing_new_ids() {
		let f = Fixture::new();
		let mut ledger = f.bootstrap();
		let digest = "c".repeat(64);
		let items = [
			ReservationRequest {
				host: "main",
				key: "a",
				digest: &digest,
				proposed_id: "id-0",
			},
			ReservationRequest {
				host: "mac",
				key: "b",
				digest: &digest,
				proposed_id: "id-1",
			},
		];
		assert_eq!(
			ledger.reserve_batch(&items).unwrap(),
			vec![Reserve::Fresh("id-0".into()), Reserve::Fresh("id-1".into())]
		);
		drop(ledger);
		let mut recovery = Ledger::reopen(f.root(), &f.jobs).unwrap();
		assert_eq!(
			recovery.reserve_batch(&items).unwrap(),
			vec![
				Reserve::Existing {
					job_id: "id-0".into(),
					phase: "reserved".into()
				},
				Reserve::Existing {
					job_id: "id-1".into(),
					phase: "reserved".into()
				},
			]
		);
	}

	#[test]
	#[ignore = "manual isolated 23347-row SQLite migration+query benchmark, no remote work"]
	fn realistic_history_23347_rows_and_indexed_query_benchmark() {
		let f = Fixture::new();
		f.seeded(23_347);
		let start = Instant::now();
		let mut ledger = f.bootstrap();
		let seed_ms = start.elapsed().as_secs_f64() * 1000.0;
		let key = "historical-0023346";
		let mut samples = vec![];
		for _ in 0..100 {
			let t = Instant::now();
			let old = ledger
				.reserve("main", key, &"a".repeat(64), "must-not-new-id")
				.unwrap();
			assert_eq!(
				old,
				Reserve::Existing {
					job_id: "seed-0023346".into(),
					phase: "legacy".into()
				}
			);
			samples.push(t.elapsed().as_secs_f64() * 1000.0);
		}
		samples.sort_by(f64::total_cmp);
		println!(
			"sqlite_wal_seed_rows=23347 bootstrap_ms={seed_ms:.3} \
                  lookup_p50_ms={:.4} lookup_p95_ms={:.4} no_remote_effects=true",
			samples[50], samples[95]
		);
	}

	#[test]
	fn submission_intent_is_durable_single_use_after_saved_record() {
		let f = Fixture::new();
		let mut writer = f.bootstrap();
		let digest = "a".repeat(64);
		let reserved = writer
			.reserve("main", "once-key", &digest, "job-once")
			.unwrap();
		assert_eq!(reserved, Reserve::Fresh("job-once".into()));
		assert!(writer
			.begin_remote_submission("main", "once-key", "job-once", &digest)
			.is_err());
		f.original("job-once", "main", Some("once-key"), Some(&digest));
		writer
			.mark_saved("main", "once-key", "job-once", &digest)
			.unwrap();
		let ticket = writer
			.begin_remote_submission("main", "once-key", "job-once", &digest)
			.unwrap();
		assert_eq!(
			ticket,
			SubmitOnce {
				job_id: "job-once".into()
			}
		);
		assert!(writer
			.begin_remote_submission("main", "once-key", "job-once", &digest)
			.is_err());
		drop(writer);
		let mut reopened = Ledger::reopen(f.root(), &f.jobs).unwrap();
		assert_eq!(
			reopened
				.reserve("main", "once-key", &digest, "new-job")
				.unwrap(),
			Reserve::Existing {
				job_id: "job-once".into(),
				phase: "submission_unknown".into()
			}
		);
		assert!(!f.jobs.join("new-job.json").exists());
		assert!(reopened
			.begin_remote_submission("main", "once-key", "job-once", &digest)
			.is_err());
	}

	#[test]
	fn submission_intent_rejects_tampered_identity_and_invalid_state() {
		let f = Fixture::new();
		let mut ledger = f.bootstrap();
		let digest = "a".repeat(64);
		assert_eq!(
			ledger.reserve("rog", "key", &digest, "original").unwrap(),
			Reserve::Fresh("original".into())
		);
		f.original("original", "rog", Some("key"), Some(&digest));
		ledger
			.mark_saved("rog", "key", "original", &digest)
			.unwrap();
		let wrong_digest = "b".repeat(64);
		for (host, key, id, hash) in [
			("mac", "key", "original", digest.as_str()),
			("rog", "changed", "original", digest.as_str()),
			("rog", "key", "wrong-id", digest.as_str()),
			("rog", "key", "original", wrong_digest.as_str()),
		] {
			assert!(ledger.begin_remote_submission(host, key, id, hash).is_err());
		}
		// Even with an intact DB reservation, a changed original launch state
		// is not a valid new remote-submission authorization.
		let path = f.jobs.join("original.json");
		let bytes = fs::read(&path).unwrap();
		let mut saved: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
		saved["launch_state"] = serde_json::json!("launched");
		fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();

		assert!(ledger
			.begin_remote_submission("rog", "key", "original", &digest)
			.is_err());
		saved["launch_state"] = serde_json::json!("pending");
		fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
		assert!(ledger
			.begin_remote_submission("rog", "key", "original", &digest)
			.is_ok());
	}

	#[test]
	fn batch_six_hosts_stages_six_independent_single_use_remote_tickets() {
		let f = Fixture::new();
		let mut writer = f.bootstrap();
		let digest = "a".repeat(64);
		let keys: Vec<String> = (0..6).map(|i| format!("task-{i}")).collect();
		let ids: Vec<String> = (0..6).map(|i| format!("batch-original-{i}")).collect();
		let entries: Vec<_> = (0..6)
			.map(|i| ReservationRequest {
				host: HOSTS[i],
				key: &keys[i],
				digest: &digest,
				proposed_id: &ids[i],
			})
			.collect();
		let reserved = writer.reserve_batch(&entries).unwrap();
		assert_eq!(reserved.len(), 6);
		assert!(reserved.iter().all(|x| matches!(x, Reserve::Fresh(_))));
		for i in 0..6 {
			f.original(&ids[i], HOSTS[i], Some(&keys[i]), Some(&digest));
			writer
				.mark_saved(HOSTS[i], &keys[i], &ids[i], &digest)
				.unwrap();
			assert_eq!(
				writer
					.begin_remote_submission(HOSTS[i], &keys[i], &ids[i], &digest)
					.unwrap()
					.job_id,
				ids[i]
			);
		}
		drop(writer);
		let mut rebooted = Ledger::reopen(f.root(), &f.jobs).unwrap();
		for (i, result) in rebooted.reserve_batch(&entries).unwrap().iter().enumerate() {
			assert_eq!(
				result,
				&Reserve::Existing {
					job_id: ids[i].clone(),
					phase: "submission_unknown".into()
				}
			);
			assert!(rebooted
				.begin_remote_submission(HOSTS[i], &keys[i], &ids[i], &digest)
				.is_err());
		}
	}

	#[test]
	fn single_writer_epoch_freeze_transfer_and_rollback_preserves_all_ids() {
		let f = Fixture::new();
		let digest = "a".repeat(64);
		f.original("legacy-job", "main", Some("legacy-key"), Some(&digest));
		let mut v4 = f.bootstrap();
		assert_eq!(v4.establish_first_writer("v4").unwrap(), 1);
		let mut v4_second = Ledger::reopen(f.root(), &f.jobs).unwrap();
		v4_second.bind_writer("v4", 1).unwrap();
		let mut v11 = Ledger::reopen(f.root(), &f.jobs).unwrap();
		assert!(v11.bind_writer("v11", 1).is_err());
		assert!(v11
			.reserve("mac", "unauthorized", &digest, "bad-id")
			.is_err());
		assert_eq!(
			v4.reserve("main", "legacy-key", &digest, "replay-id")
				.unwrap(),
			Reserve::Existing {
				job_id: "legacy-job".into(),
				phase: "legacy".into()
			}
		);
		v4.freeze_writer().unwrap();
		assert!(v4.reserve("mac", "frozen", &digest, "bad-id").is_err());
		assert!(v4_second
			.reserve("rog", "also-frozen", &digest, "bad-id")
			.is_err());
		assert!(v11.bind_writer("v11", 1).is_err());
		let epoch_two = v4.promote_frozen_writer("v11").unwrap();
		assert_eq!(epoch_two, 2);
		assert!(v4_second
			.reserve("mac", "stale-owner", &digest, "bad-id")
			.is_err());
		v11.bind_writer("v11", epoch_two).unwrap();
		assert_eq!(
			v11.reserve("mac", "new-era", &digest, "successor-id")
				.unwrap(),
			Reserve::Fresh("successor-id".into())
		);
		assert_eq!(
			v11.reserve("main", "legacy-key", &digest, "replay-id")
				.unwrap(),
			Reserve::Existing {
				job_id: "legacy-job".into(),
				phase: "legacy".into()
			}
		);
		v11.freeze_writer().unwrap();

		let epoch_three = v11.promote_frozen_writer("v4").unwrap();
		assert_eq!(epoch_three, 3);
		assert!(v11.reserve("main", "stale-v11", &digest, "bad-id").is_err());
		v4_second.bind_writer("v4", epoch_three).unwrap();
		assert_eq!(
			v4_second
				.reserve("rog", "rollback-new", &digest, "rollback-id")
				.unwrap(),
			Reserve::Fresh("rollback-id".into())
		);
		assert_eq!(
			v4_second
				.reserve("mac", "new-era", &digest, "bad-replay")
				.unwrap(),
			Reserve::Existing {
				job_id: "successor-id".into(),
				phase: "reserved".into()
			}
		);
	}

	#[test]
	fn submission_intent_cannot_cross_owner_epoch_or_bypass_frozen_state() {
		let f = Fixture::new();
		let mut v4 = f.bootstrap();
		let digest = "b".repeat(64);
		v4.establish_first_writer("v4").unwrap();
		assert_eq!(
			v4.reserve("main", "command", &digest, "original-id")
				.unwrap(),
			Reserve::Fresh("original-id".into())
		);
		f.original("original-id", "main", Some("command"), Some(&digest));
		let mut unbound = Ledger::reopen(f.root(), &f.jobs).unwrap();
		assert!(unbound
			.mark_saved("main", "command", "original-id", &digest)
			.is_err());
		assert!(unbound
			.begin_remote_submission("main", "command", "original-id", &digest)
			.is_err());
		v4.mark_saved("main", "command", "original-id", &digest)
			.unwrap();
		v4.freeze_writer().unwrap();
		assert!(v4
			.begin_remote_submission("main", "command", "original-id", &digest)
			.is_err());
		assert_eq!(v4.promote_frozen_writer("v11").unwrap(), 2);
		let mut v11 = Ledger::reopen(f.root(), &f.jobs).unwrap();
		v11.bind_writer("v11", 2).unwrap();
		assert_eq!(
			v11.reserve("main", "command", &digest, "new-id").unwrap(),
			Reserve::Existing {
				job_id: "original-id".into(),
				phase: "record_saved".into()
			}
		);
		assert!(
			v11.begin_remote_submission("main", "command", "original-id", &digest)
				.is_err(),
			"new owner cannot submit an old epoch's staged remote command"
		);
		assert!(!f.jobs.join("new-id.json").exists());
	}

	#[test]
	fn stale_writer_batch_fails_atomically_across_epoch_transfer() {
		let f = Fixture::new();
		let mut old = f.bootstrap();
		let digest = "d".repeat(64);
		old.establish_first_writer("v4").unwrap();
		let mut stale = Ledger::reopen(f.root(), &f.jobs).unwrap();
		stale.bind_writer("v4", 1).unwrap();
		old.freeze_writer().unwrap();
		assert_eq!(old.promote_frozen_writer("v11").unwrap(), 2);
		let old_batch = [
			ReservationRequest {
				host: "rog",
				key: "blocked-rog",
				digest: &digest,
				proposed_id: "blocked-rog-id",
			},
			ReservationRequest {
				host: "mac",
				key: "blocked-mac",
				digest: &digest,
				proposed_id: "blocked-mac-id",
			},
		];
		assert!(stale.reserve_batch(&old_batch).is_err());
		let mut successor = Ledger::reopen(f.root(), &f.jobs).unwrap();
		successor.bind_writer("v11", 2).unwrap();
		let new_batch = [
			ReservationRequest {
				host: "rog",
				key: "new-rog",
				digest: &digest,
				proposed_id: "new-rog-id",
			},
			ReservationRequest {
				host: "mac",
				key: "new-mac",
				digest: &digest,
				proposed_id: "new-mac-id",
			},
		];
		assert_eq!(successor.reserve_batch(&new_batch).unwrap().len(), 2);
		assert!(stale.reserve_batch(&old_batch).is_err());
		successor.freeze_writer().unwrap();
		assert!(successor.reserve_batch(&new_batch).is_err());
		assert_eq!(successor.promote_frozen_writer("v4").unwrap(), 3);
		let mut restored = Ledger::reopen(f.root(), &f.jobs).unwrap();
		restored.bind_writer("v4", 3).unwrap();
		assert_eq!(
			restored
				.reserve("rog", "new-rog", &digest, "replayed-id")
				.unwrap(),
			Reserve::Existing {
				job_id: "new-rog-id".into(),
				phase: "reserved".into()
			}
		);
		assert_eq!(
			restored
				.reserve("mac", "new-mac", &digest, "replayed-id")
				.unwrap(),
			Reserve::Existing {
				job_id: "new-mac-id".into(),
				phase: "reserved".into()
			}
		);
		assert!(stale.reserve_batch(&old_batch).is_err());
		assert!(!f.jobs.join("blocked-rog-id.json").exists());
	}

	#[test]
	fn successor_batch_reuses_old_epoch_ids_after_restart_without_relaunch() {
		let f = Fixture::new();
		let digest = "e".repeat(64);
		let mut first = f.bootstrap();
		first.establish_first_writer("v4").unwrap();
		let ids = ["job-a", "job-b", "job-c"];
		let keys = ["key-a", "key-b", "key-c"];
		let hosts = ["main", "pocket4", "mac"];
		let requests: Vec<_> = (0..ids.len())
			.map(|i| ReservationRequest {
				host: hosts[i],
				key: keys[i],
				digest: &digest,
				proposed_id: ids[i],
			})
			.collect();
		assert!(first
			.reserve_batch(&requests)
			.unwrap()
			.iter()
			.all(|x| matches!(x, Reserve::Fresh(_))));
		first.freeze_writer().unwrap();
		assert_eq!(first.promote_frozen_writer("v11").unwrap(), 2);
		drop(first);
		let mut second = Ledger::reopen(f.root(), &f.jobs).unwrap();
		assert!(
			second.reserve_batch(&requests).is_err(),
			"unbound new controller must be denied"
		);
		second.bind_writer("v11", 2).unwrap();
		let results = second.reserve_batch(&requests).unwrap();
		for (i, result) in results.into_iter().enumerate() {
			assert_eq!(
				result,
				Reserve::Existing {
					job_id: ids[i].into(),
					phase: "reserved".into()
				}
			);
		}
		second.freeze_writer().unwrap();
		assert!(second.reserve_batch(&requests).is_err());
		assert_eq!(second.promote_frozen_writer("v4").unwrap(), 3);
		let mut restored = Ledger::reopen(f.root(), &f.jobs).unwrap();
		restored.bind_writer("v4", 3).unwrap();
		assert!(restored
			.reserve_batch(&requests)
			.unwrap()
			.iter()
			.all(|x| matches!(x, Reserve::Existing { phase, .. } if phase == "reserved")));
	}

	#[test]
	fn rollback_cannot_reuse_unkeyed_legacy_id_or_change_reserved_batch_identity() {
		let f = Fixture::new();
		let digest = "f".repeat(64);
		f.original("unkeyed-original", "x230", None, None);
		let mut first = f.bootstrap();
		first.establish_first_writer("v4").unwrap();
		let initial = [
			ReservationRequest {
				host: "rog",
				key: "same-rog",
				digest: &digest,
				proposed_id: "original-rog-id",
			},
			ReservationRequest {
				host: "mac",
				key: "same-mac",
				digest: &digest,
				proposed_id: "original-mac-id",
			},
		];
		assert!(first
			.reserve_batch(&initial)
			.unwrap()
			.iter()
			.all(|r| matches!(r, Reserve::Fresh(_))));
		first.freeze_writer().unwrap();
		assert_eq!(first.promote_frozen_writer("v11").unwrap(), 2);
		let mut successor = Ledger::reopen(f.root(), &f.jobs).unwrap();
		successor.bind_writer("v11", 2).unwrap();
		let wrong = [
			ReservationRequest {
				host: "rog",
				key: "same-rog",
				digest: &digest,
				proposed_id: "unkeyed-original",
			},
			ReservationRequest {
				host: "main",
				key: "new-main",
				digest: &digest,
				proposed_id: "unkeyed-original",
			},
		];
		assert!(successor.reserve_batch(&wrong).is_err());
		let replayed = successor.reserve_batch(&initial).unwrap();
		assert_eq!(
			replayed[0],
			Reserve::Existing {
				job_id: "original-rog-id".into(),
				phase: "reserved".into()
			}
		);
		assert_eq!(
			replayed[1],
			Reserve::Existing {
				job_id: "original-mac-id".into(),
				phase: "reserved".into()
			}
		);
		successor.freeze_writer().unwrap();
		assert_eq!(successor.promote_frozen_writer("v4").unwrap(), 3);
		let mut restored = Ledger::reopen(f.root(), &f.jobs).unwrap();
		restored.bind_writer("v4", 3).unwrap();
		assert!(restored.reserve_batch(&wrong).is_err());
		assert!(restored
			.reserve_batch(&initial)
			.unwrap()
			.iter()
			.all(|r| matches!(r, Reserve::Existing { .. })));
	}

	#[test]
	fn frozen_authority_remains_closed_after_controller_restart() {
		let f = Fixture::new();
		let mut v4 = f.bootstrap();
		let digest = "c".repeat(64);
		v4.establish_first_writer("v4").unwrap();
		v4.freeze_writer().unwrap();
		drop(v4);
		let mut new_v4 = Ledger::reopen(f.root(), &f.jobs).unwrap();
		assert!(new_v4.bind_writer("v4", 1).is_err());
		assert!(new_v4
			.reserve("main", "crash-retry", &digest, "bad-id")
			.is_err());
		let mut new_v11 = Ledger::reopen(f.root(), &f.jobs).unwrap();
		assert!(new_v11.bind_writer("v11", 2).is_err());
		assert!(new_v11
			.reserve("rog", "crash-new", &digest, "bad-id")
			.is_err());
	}
}

#[cfg(all(test, unix))]
mod sidecar_identity_tests {
	use super::*;
	use std::os::unix::fs::{symlink, PermissionsExt};

	fn new_fixture() -> (tempfile::TempDir, PathBuf) {
		let root = tempfile::tempdir().unwrap();
		let jobs = root.path().join("jobs");
		fs::create_dir(&jobs).unwrap();
		fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();
		let mut ledger = Ledger::create_private(root.path(), &jobs).unwrap();
		assert_eq!(ledger.bootstrap_frozen().unwrap(), 0);
		drop(ledger);
		(root, jobs)
	}

	fn sidecar(db: &Path, suffix: &str) -> PathBuf {
		let mut path = db.as_os_str().to_os_string();
		path.push(suffix);
		PathBuf::from(path)
	}

	#[test]
	fn refuses_linked_or_wide_wal_and_shm_before_reopen() {
		let (root, jobs) = new_fixture();
		let db = root.path().join(DB_NAME);
		let sentinel = root.path().join("unrelated-private-file");
		fs::write(&sentinel, b"DO_NOT_CHANGE").unwrap();
		fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
		for suffix in ["-wal", "-shm"] {
			let path = sidecar(&db, suffix);
			assert!(!path.exists(), "closed WAL must checkpoint test fixture");
			symlink(&sentinel, &path).unwrap();
			assert!(Ledger::reopen(root.path(), &jobs).is_err());
			fs::remove_file(&path).unwrap();

			fs::hard_link(&sentinel, &path).unwrap();
			assert!(Ledger::reopen(root.path(), &jobs).is_err());
			fs::remove_file(&path).unwrap();

			fs::write(&path, b"untrusted-sidecar").unwrap();
			fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
			assert!(Ledger::reopen(root.path(), &jobs).is_err());
			fs::remove_file(&path).unwrap();
		}
		assert_eq!(fs::read(&sentinel).unwrap(), b"DO_NOT_CHANGE");
		assert!(Ledger::reopen(root.path(), &jobs).is_ok());
	}

	#[test]
	fn sqlite_connection_no_follow_rejects_main_db_symlink() {
		let (root, jobs) = new_fixture();
		let db = root.path().join(DB_NAME);
		let copy = root.path().join("private-db-copy");
		fs::copy(&db, &copy).unwrap();
		fs::set_permissions(&copy, fs::Permissions::from_mode(0o600)).unwrap();
		fs::remove_file(&db).unwrap();
		symlink(&copy, &db).unwrap();
		assert!(Ledger::connect(&db, false).is_err());
		assert!(Ledger::reopen(root.path(), &jobs).is_err());
	}
}
