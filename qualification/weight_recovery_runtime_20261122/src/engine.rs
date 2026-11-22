// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Journaled research transactions. This module owns no model files or active pointer.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_RECORDS: usize = 24;
const MAX_PENDING: usize = 24;
static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn digest(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}

fn valid_hash(s: &str) -> bool {
	s.len() == 64
		&& s.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
	pub schema: String,
	pub source_sha256: String,
	pub candidate_sha256: String,
	pub law_sha256: String,
	pub task_sha256: String,
	pub evaluator_sha256: String,
	pub owner_request_sha256: String,
	pub owner_request: Value,
}

impl Intent {
	pub fn validate(&self) -> Result<()> {
		if self.schema != "hepta.weight.recovery-intent.v1"
			|| [
				&self.source_sha256,
				&self.candidate_sha256,
				&self.law_sha256,
				&self.task_sha256,
				&self.evaluator_sha256,
				&self.owner_request_sha256,
			]
			.iter()
			.any(|s| !valid_hash(s))
			|| digest(&serde_json::to_vec(&self.owner_request)?) != self.owner_request_sha256
			|| serde_json::to_vec(self)?.len() > MAX_RECORD_BYTES as usize / 2
		{
			bail!("invalid or unbound recovery intent");
		}
		Ok(())
	}
	pub fn id(&self) -> Result<String> {
		self.validate()?;
		Ok(format!("wtx1_{}", digest(&serde_json::to_vec(self)?)))
	}
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerReceipt {
	pub artifact_id: String,
	pub source_sha256: String,
	pub content_sha256: String,
	pub kind: String,
}

impl OwnerReceipt {
	fn validate(&self, intent: &Intent, restore: bool) -> Result<()> {
		let id_ok = self
			.artifact_id
			.strip_prefix("wa1_")
			.is_some_and(valid_hash);
		let (source, target, kind) = if restore {
			(&intent.candidate_sha256, &intent.source_sha256, "restore")
		} else {
			(&intent.source_sha256, &intent.candidate_sha256, "patch")
		};
		if !id_ok
			|| &self.source_sha256 != source
			|| &self.content_sha256 != target
			|| self.kind != kind
		{
			bail!("owner receipt does not bind the declared source and candidate");
		}
		Ok(())
	}
}

/// The caller supplies the existing canonical owner. Publication and inverse
/// restoration must reconcile identical requests to the same immutable artifact.
pub trait ArtifactOwner {
	fn publish(&mut self, intent: &Intent) -> Result<OwnerReceipt>;
	fn inspect(&mut self, receipt: &OwnerReceipt) -> Result<()>;
	fn restore(&mut self, intent: &Intent, candidate: &OwnerReceipt) -> Result<OwnerReceipt>;
	fn verify_original(&mut self, intent: &Intent) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
	pub candidate_sha256: String,
	pub task_sha256: String,
	pub law_sha256: String,
	pub evaluator_sha256: String,
	pub passed: bool,
	pub result_sha256: String,
}

pub trait Evaluator {
	fn evaluate(&mut self, intent: &Intent, candidate: &OwnerReceipt) -> Result<Evaluation>;
}

pub trait Checkpoint {
	fn reached(&mut self, name: &str) -> Result<()>;
}

pub struct NoCheckpoint;
impl Checkpoint for NoCheckpoint {
	fn reached(&mut self, _: &str) -> Result<()> {
		Ok(())
	}
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Stage {
	Prepared,
	PublishIntent,
	Published,
	VerifyIntent,
	Verified,
	Accepted,
	RestoreIntent,
	Restored,
	Complete,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
	ResearchAcceptedRestored,
	ResearchRejectedRestored,
	InterruptedRestored,
	KeptOriginal,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
	pub schema: String,
	pub sequence: u64,
	pub previous_sha256: Option<String>,
	pub intent: Intent,
	pub stage: Stage,
	pub publication: Option<OwnerReceipt>,
	pub evaluation: Option<Evaluation>,
	pub acceptance_sha256: Option<String>,
	pub restoration: Option<OwnerReceipt>,
	pub decision: Option<Decision>,
	pub recovery: bool,
	pub failure: Option<String>,
}

impl Record {
	fn validate(&self) -> Result<()> {
		self.intent.validate()?;
		if self.schema != "hepta.weight.recovery-record.v1" || self.sequence >= MAX_RECORDS as u64 {
			bail!("unsupported journal schema or record limit");
		}
		if self.sequence == 0 && (self.stage != Stage::Prepared || self.previous_sha256.is_some()) {
			bail!("journal must begin with the durable original intent");
		}
		if self.sequence > 0 && !self.previous_sha256.as_deref().is_some_and(valid_hash) {
			bail!("journal chain digest missing");
		}
		if let Some(p) = &self.publication {
			p.validate(&self.intent, false)?;
		}
		if let Some(r) = &self.restoration {
			r.validate(&self.intent, true)?;
		}
		if let Some(e) = &self.evaluation {
			if e.candidate_sha256 != self.intent.candidate_sha256
				|| e.task_sha256 != self.intent.task_sha256
				|| e.law_sha256 != self.intent.law_sha256
				|| e.evaluator_sha256 != self.intent.evaluator_sha256
				|| !valid_hash(&e.result_sha256)
			{
				bail!("evaluation identity differs from fixed intent");
			}
		}
		if let Some(acceptance) = &self.acceptance_sha256 {
			let e = self
				.evaluation
				.as_ref()
				.ok_or_else(|| anyhow!("acceptance without evaluation"))?;
			if !e.passed || *acceptance != digest(&serde_json::to_vec(e)?) {
				bail!("acceptance is not bound to a passing evaluation");
			}
		}
		if matches!(self.stage, Stage::Prepared | Stage::PublishIntent)
			&& (self.publication.is_some()
				|| self.evaluation.is_some()
				|| self.acceptance_sha256.is_some()
				|| self.restoration.is_some())
		{
			bail!("unpublished stage contains later effects");
		}
		if matches!(self.stage, Stage::Published | Stage::VerifyIntent)
			&& (self.evaluation.is_some()
				|| self.acceptance_sha256.is_some()
				|| self.restoration.is_some())
		{
			bail!("unevaluated stage contains later evidence");
		}
		if matches!(self.stage, Stage::Verified)
			&& (self.acceptance_sha256.is_some() || self.restoration.is_some())
		{
			bail!("verified stage contains later effects");
		}
		if matches!(self.stage, Stage::Accepted | Stage::RestoreIntent)
			&& self.restoration.is_some()
		{
			bail!("unrestored stage contains restore receipt");
		}
		let published_stage = !(matches!(self.stage, Stage::Prepared | Stage::PublishIntent)
			|| self.stage == Stage::Complete && self.decision == Some(Decision::KeptOriginal));
		if published_stage && self.publication.is_none() {
			bail!("publication receipt missing");
		}
		if matches!(self.stage, Stage::Verified | Stage::Accepted) && self.evaluation.is_none() {
			bail!("evaluated stage lacks evaluation");
		}
		if self.stage == Stage::Accepted && self.acceptance_sha256.is_none() {
			bail!("acceptance missing");
		}
		if matches!(self.stage, Stage::Restored | Stage::Complete)
			&& self.decision != Some(Decision::KeptOriginal)
			&& self.restoration.is_none()
		{
			bail!("restore receipt missing");
		}
		if (self.stage == Stage::Complete) != self.decision.is_some() {
			bail!("decision/stage mismatch");
		}
		if self.decision == Some(Decision::ResearchAcceptedRestored)
			&& self.acceptance_sha256.is_none()
		{
			bail!("completed acceptance has no evidence");
		}
		if self.decision == Some(Decision::ResearchRejectedRestored)
			&& (self.evaluation.as_ref().is_none_or(|e| e.passed)
				|| self.acceptance_sha256.is_some())
		{
			bail!("research rejection requires an actual rejected evaluation");
		}
		if self.decision == Some(Decision::InterruptedRestored) && !self.recovery {
			bail!("interrupted outcome lacks recovery provenance");
		}
		if matches!(
			self.decision,
			Some(Decision::ResearchAcceptedRestored | Decision::ResearchRejectedRestored)
		) && self.recovery
		{
			bail!("recovery cannot manufacture normal research completion");
		}
		if self.decision == Some(Decision::KeptOriginal)
			&& (self.publication.is_some()
				|| self.evaluation.is_some()
				|| self.restoration.is_some())
		{
			bail!("kept original may not conceal artifact effects");
		}
		Ok(())
	}
}

fn transition(previous: &Record, next: &Record) -> Result<()> {
	let legal = matches!(
		(previous.stage, next.stage),
		(Stage::Prepared, Stage::PublishIntent | Stage::Complete)
			| (Stage::PublishIntent, Stage::Published)
			| (Stage::Published, Stage::VerifyIntent | Stage::RestoreIntent)
			| (Stage::VerifyIntent, Stage::Verified | Stage::RestoreIntent)
			| (Stage::Verified, Stage::Accepted | Stage::RestoreIntent)
			| (Stage::Accepted, Stage::RestoreIntent)
			| (Stage::RestoreIntent, Stage::Restored)
			| (Stage::Restored, Stage::Complete)
	);
	if !legal
		|| next.sequence != previous.sequence + 1
		|| next.intent != previous.intent
		|| previous.publication.is_some() && previous.publication != next.publication
		|| previous.evaluation.is_some() && previous.evaluation != next.evaluation
		|| previous.acceptance_sha256.is_some()
			&& previous.acceptance_sha256 != next.acceptance_sha256
		|| previous.restoration.is_some() && previous.restoration != next.restoration
		|| previous.recovery && !next.recovery
	{
		bail!("illegal journal transition or changed retained evidence");
	}
	next.validate()
}

struct Journal {
	path: PathBuf,
	_lock: File,
}

fn private_directory(path: &Path) -> Result<()> {
	let mut builder = std::fs::DirBuilder::new();
	builder.mode(0o700);
	match builder.create(path) {
		Ok(()) => (),
		Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
		Err(e) => return Err(e.into()),
	}
	let m = std::fs::symlink_metadata(path)?;
	if !m.is_dir()
		|| m.file_type().is_symlink()
		|| m.mode() & 0o077 != 0
		|| m.uid() != unsafe { libc::geteuid() }
	{
		bail!("journal directory must be private, owned and nonsymlink");
	}
	Ok(())
}

impl Journal {
	fn open(root: &Path, intent: &Intent) -> Result<Self> {
		intent.validate()?;
		if !root.is_absolute() || root.components().any(|c| matches!(c, Component::ParentDir)) {
			bail!("absolute confined journal root required");
		}
		private_directory(root)?;
		if std::fs::canonicalize(root)? != root {
			bail!("journal root cannot traverse symbolic links");
		}
		let path = root.join(intent.id()?);
		private_directory(&path)?;
		File::open(root)?.sync_all()?;
		let lock = OpenOptions::new()
			.read(true)
			.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
			.open(&path)?;
		if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("transaction busy; retry the same intent");
		}
		Ok(Self { path, _lock: lock })
	}
	fn read(&self, intent: &Intent) -> Result<Option<(Record, String)>> {
		let mut paths = Vec::new();
		let mut pending = 0;
		for entry in std::fs::read_dir(&self.path)? {
			let entry = entry?;
			let name = entry
				.file_name()
				.into_string()
				.map_err(|_| anyhow!("journal filename invalid"))?;
			let m = std::fs::symlink_metadata(entry.path())?;
			if !m.is_file()
				|| m.file_type().is_symlink()
				|| m.nlink() != 1
				|| m.mode() & 0o777 != 0o600
				|| m.uid() != unsafe { libc::geteuid() }
				|| m.len() > MAX_RECORD_BYTES
			{
				bail!("journal file type, ownership, length or links invalid");
			}
			if name.starts_with(".pending-") {
				pending += 1;
			} else {
				paths.push(entry.path());
			}
		}
		if paths.len() > MAX_RECORDS || pending > MAX_PENDING {
			bail!("journal entry quota exceeded");
		}
		paths.sort();
		let mut previous: Option<(Record, String)> = None;
		for (i, path) in paths.iter().enumerate() {
			if path.file_name().and_then(|s| s.to_str())
				!= Some(format!("record-{i:04}.json").as_str())
			{
				bail!("journal chain has a gap or unexpected entry");
			}
			let mut f = OpenOptions::new()
				.read(true)
				.custom_flags(libc::O_NOFOLLOW)
				.open(path)?;
			let before = f.metadata()?;
			let mut raw = Vec::new();
			std::io::Read::by_ref(&mut f)
				.take(MAX_RECORD_BYTES + 1)
				.read_to_end(&mut raw)?;
			let after = f.metadata()?;
			if raw.len() as u64 > MAX_RECORD_BYTES
				|| before.ino() != after.ino()
				|| before.len() != after.len()
				|| before.ctime_nsec() != after.ctime_nsec()
				|| before.ctime() != after.ctime()
			{
				bail!("journal changed during read");
			}
			let record: Record = serde_json::from_slice(&raw)?;
			record.validate()?;
			if record.intent != *intent || record.sequence != i as u64 {
				bail!("journal identity mismatch");
			}
			if let Some((p, h)) = &previous {
				if record.previous_sha256.as_ref() != Some(h) {
					bail!("journal chain digest mismatch");
				}
				transition(p, &record)?;
			}
			previous = Some((record, digest(&raw)));
		}
		Ok(previous)
	}
	fn append(&self, record: &mut Record, previous: Option<(&Record, &str)>) -> Result<String> {
		if let Some((p, h)) = previous {
			record.sequence = p.sequence + 1;
			record.previous_sha256 = Some(h.to_owned());
			transition(p, record)?;
		} else {
			record.validate()?;
		}
		let bytes = serde_json::to_vec(record)?;
		if bytes.len() as u64 > MAX_RECORD_BYTES {
			bail!("journal record too large");
		}
		// A failed sync/rename can leave a complete record. Reuse it only if its
		// bytes are exactly the record this transition would write now. Never
		// promote an uncommitted acceptance merely because it parses correctly.
		let mut matching = None;
		let mut pending = 0usize;
		for entry in std::fs::read_dir(&self.path)? {
			let entry = entry?;
			if !entry.file_name().to_string_lossy().starts_with(".pending-") {
				continue;
			}
			pending += 1;
			if pending > MAX_PENDING {
				bail!("pending journal quota exceeded");
			}
			let mut file = OpenOptions::new()
				.read(true)
				.custom_flags(libc::O_NOFOLLOW)
				.open(entry.path())?;
			let metadata = file.metadata()?;
			if !metadata.is_file()
				|| metadata.nlink() != 1
				|| metadata.mode() & 0o777 != 0o600
				|| metadata.uid() != unsafe { libc::geteuid() }
				|| metadata.len() > MAX_RECORD_BYTES
			{
				bail!("pending journal type, ownership or byte budget differs");
			}
			if metadata.len() == bytes.len() as u64 {
				let mut retained = Vec::new();
				std::io::Read::by_ref(&mut file)
					.take(MAX_RECORD_BYTES + 1)
					.read_to_end(&mut retained)?;
				let after = file.metadata()?;
				if metadata.ino() != after.ino()
					|| metadata.len() != after.len()
					|| metadata.ctime() != after.ctime()
					|| metadata.ctime_nsec() != after.ctime_nsec()
				{
					bail!("pending journal changed while read");
				}
				if retained == bytes {
					file.sync_all()?;
					matching = Some(entry.path());
				}
			}
		}
		let tmp = if let Some(path) = matching {
			path
		} else {
			if pending >= MAX_PENDING {
				bail!("incomplete journal evidence reached its bounded quota");
			}
			let nonce = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)?
				.as_nanos();
			let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
			let path = self.path.join(format!(
				".pending-{}-{}-{nonce}-{sequence}",
				std::process::id(),
				record.sequence
			));
			let mut f = OpenOptions::new()
				.write(true)
				.create_new(true)
				.mode(0o600)
				.custom_flags(libc::O_NOFOLLOW)
				.open(&path)?;
			f.write_all(&bytes)?;
			f.sync_all()?;
			drop(f);
			path
		};
		let dst = self
			.path
			.join(format!("record-{:04}.json", record.sequence));
		use std::os::unix::ffi::OsStrExt;
		let from = std::ffi::CString::new(tmp.as_os_str().as_bytes())?;
		let to = std::ffi::CString::new(dst.as_os_str().as_bytes())?;
		if unsafe {
			libc::renameat2(
				libc::AT_FDCWD,
				from.as_ptr(),
				libc::AT_FDCWD,
				to.as_ptr(),
				libc::RENAME_NOREPLACE,
			)
		} != 0
		{
			return Err(std::io::Error::last_os_error())
				.context("publish immutable journal record");
		}
		File::open(&self.path)?.sync_all()?;
		Ok(digest(&bytes))
	}
}

fn advance(
	journal: &Journal,
	current: &mut Record,
	hash: &mut String,
	stage: Stage,
	change: impl FnOnce(&mut Record),
) -> Result<()> {
	let previous = current.clone();
	current.stage = stage;
	change(current);
	*hash = journal.append(current, Some((&previous, hash)))?;
	Ok(())
}

fn finish_restore<O: ArtifactOwner, C: Checkpoint>(
	journal: &Journal,
	current: &mut Record,
	hash: &mut String,
	owner: &mut O,
	check: &mut C,
	recovery: bool,
) -> Result<()> {
	if current.stage == Stage::Complete {
		owner.verify_original(&current.intent)?;
		if let Some(p) = &current.publication {
			owner.inspect(p)?;
		}
		if let Some(r) = &current.restoration {
			owner.inspect(r)?;
		}
		return Ok(());
	}
	if current.stage == Stage::Prepared {
		owner.verify_original(&current.intent)?;
		advance(journal, current, hash, Stage::Complete, |r| {
			r.recovery = true;
			r.decision = Some(Decision::KeptOriginal);
		})?;
		check.reached("complete")?;
		return Ok(());
	}
	if current.stage == Stage::PublishIntent {
		let p = owner.publish(&current.intent)?;
		p.validate(&current.intent, false)?;
		check.reached("publish_effect")?;
		advance(journal, current, hash, Stage::Published, |r| {
			r.publication = Some(p);
			r.recovery = true;
		})?;
	}
	let candidate = current
		.publication
		.clone()
		.ok_or_else(|| anyhow!("recovery has no candidate"))?;
	owner.inspect(&candidate)?;
	if current.stage != Stage::Restored {
		if current.stage != Stage::RestoreIntent {
			advance(journal, current, hash, Stage::RestoreIntent, |r| {
				r.recovery |= recovery
			})?;
		}
		check.reached("restore_intent")?;
		let restored = owner.restore(&current.intent, &candidate)?;
		restored.validate(&current.intent, true)?;
		owner.inspect(&restored)?;
		check.reached("restore_effect")?;
		advance(journal, current, hash, Stage::Restored, |r| {
			r.restoration = Some(restored)
		})?;
		check.reached("restored")?;
	}
	owner.verify_original(&current.intent)?;
	owner.inspect(&candidate)?;
	owner.inspect(
		current
			.restoration
			.as_ref()
			.ok_or_else(|| anyhow!("durable restoration receipt missing"))?,
	)?;
	let decision = if current.recovery || recovery {
		Decision::InterruptedRestored
	} else if current.acceptance_sha256.is_some() {
		Decision::ResearchAcceptedRestored
	} else {
		Decision::ResearchRejectedRestored
	};
	advance(journal, current, hash, Stage::Complete, |r| {
		r.recovery |= recovery;
		r.decision = Some(decision);
	})?;
	check.reached("complete")?;
	Ok(())
}

/// Start exactly one research lifecycle. On ordinary errors the same function
/// attempts conservative inverse recovery; a process death is reconciled by recover.
pub fn execute<O: ArtifactOwner, E: Evaluator, C: Checkpoint>(
	root: &Path,
	intent: Intent,
	owner: &mut O,
	evaluator: &mut E,
	check: &mut C,
) -> Result<Record> {
	let journal = Journal::open(root, &intent)?;
	if journal.read(&intent)?.is_some() {
		bail!("transaction exists; recover the same intent");
	}
	owner.verify_original(&intent)?;
	let mut current = Record {
		schema: "hepta.weight.recovery-record.v1".into(),
		sequence: 0,
		previous_sha256: None,
		intent,
		stage: Stage::Prepared,
		publication: None,
		evaluation: None,
		acceptance_sha256: None,
		restoration: None,
		decision: None,
		recovery: false,
		failure: None,
	};
	let mut hash = journal.append(&mut current, None)?;
	let result = (|| -> Result<()> {
		check.reached("prepared")?;
		advance(
			&journal,
			&mut current,
			&mut hash,
			Stage::PublishIntent,
			|_| {},
		)?;
		check.reached("publish_intent")?;
		let p = owner.publish(&current.intent)?;
		p.validate(&current.intent, false)?;
		check.reached("publish_effect")?;
		advance(&journal, &mut current, &mut hash, Stage::Published, |r| {
			r.publication = Some(p)
		})?;
		check.reached("published")?;
		owner.inspect(
			current
				.publication
				.as_ref()
				.ok_or_else(|| anyhow!("publication missing"))?,
		)?;
		advance(
			&journal,
			&mut current,
			&mut hash,
			Stage::VerifyIntent,
			|_| {},
		)?;
		check.reached("verify_intent")?;
		let e = evaluator.evaluate(
			&current.intent,
			current
				.publication
				.as_ref()
				.ok_or_else(|| anyhow!("publication missing"))?,
		)?;
		check.reached("verify_effect")?;
		advance(&journal, &mut current, &mut hash, Stage::Verified, |r| {
			r.evaluation = Some(e)
		})?;
		check.reached("verified")?;
		if current.evaluation.as_ref().is_some_and(|e| e.passed) {
			let sha = digest(&serde_json::to_vec(&current.evaluation)?);
			advance(&journal, &mut current, &mut hash, Stage::Accepted, |r| {
				r.acceptance_sha256 = Some(sha)
			})?;
			check.reached("accepted")?;
		}
		finish_restore(&journal, &mut current, &mut hash, owner, check, false)
	})();
	if let Err(error) = result {
		let (mut retained, mut h) = journal
			.read(&current.intent)?
			.ok_or_else(|| anyhow!("journal disappeared"))?;
		retained.failure = Some(error.to_string());
		finish_restore(
			&journal,
			&mut retained,
			&mut h,
			owner,
			&mut NoCheckpoint,
			true,
		)
		.with_context(|| format!("original failure: {error}; inverse recovery incomplete"))?;
		return Ok(retained);
	}
	Ok(current)
}

/// Restart never repeats evaluation or manufactures a fresh acceptance. It
/// reconciles a possibly published artifact and explicitly restores its source.
pub fn recover<O: ArtifactOwner, C: Checkpoint>(
	root: &Path,
	intent: &Intent,
	owner: &mut O,
	check: &mut C,
) -> Result<Record> {
	let journal = Journal::open(root, intent)?;
	let (mut current, mut hash) = journal
		.read(intent)?
		.ok_or_else(|| anyhow!("no durable intent to recover"))?;
	finish_restore(&journal, &mut current, &mut hash, owner, check, true)?;
	Ok(current)
}
