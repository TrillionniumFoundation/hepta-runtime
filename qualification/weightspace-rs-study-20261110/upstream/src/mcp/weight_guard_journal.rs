// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Durable fixed-request guard receipts and explicit same-request reconciliation.
//! No live pointer is changed. Interrupted requests always reject, even if their
//! fresh guard replay would pass. Retained acceptance is never an auth cache.

use anyhow::{bail, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

use super::weight_guard::GuardedPatchParams;

pub(super) async fn evaluate_with_roots(
	params: GuardedPatchParams,
	roots: &[PathBuf],
	state: &Path,
) -> Result<Value> {
	#[cfg(target_os = "linux")]
	{
		linux::evaluate(params, roots, state).await
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (params, roots, state);
		bail!("durable guarded weight requests require Linux");
	}
}

#[cfg(target_os = "linux")]
mod linux {
	use super::*;
	use anyhow::{anyhow, Context};
	use serde::Serialize;
	use serde_json::json;
	use sha2::{Digest, Sha256};
	use std::collections::BTreeMap;
	use std::ffi::{CStr, CString, OsStr};
	use std::fs::{File, Metadata};
	use std::io::{Read, Write};
	use std::os::fd::{AsRawFd, FromRawFd};
	use std::os::unix::ffi::OsStrExt;
	use std::os::unix::fs::MetadataExt;
	use std::path::Component;
	use std::sync::atomic::{AtomicU64, Ordering};
	use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
	use tokio::io::AsyncReadExt;

	pub(super) const ROOT_NAME: &str = "weight-guard-journal-v1";
	pub(super) const MAX_REQUEST_BYTES: usize = 1024 * 1024;
	pub(super) const MAX_ENTRIES: usize = 128;
	const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
	const MAX_RECORD_BYTES: usize = 1024 * 1024;
	const MAX_CANDIDATE_BYTES: usize = 64 * 1024;
	const MAX_FAILURE_BYTES: usize = 64 * 1024;
	const MAX_MEMBERS: usize = 12;
	const VERSION: &str = "hepta.guard.f32-linear.exact-l2.v2.journal.v1";
	static SEQUENCE: AtomicU64 = AtomicU64::new(0);

	struct Bounded(Vec<u8>);
	impl Write for Bounded {
		fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
			if bytes.len() > MAX_REQUEST_BYTES.saturating_sub(self.0.len()) {
				return Err(std::io::Error::other(
					"canonical guard request exceeds 1 MiB",
				));
			}
			self.0.extend_from_slice(bytes);
			Ok(bytes.len())
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}

	pub(super) fn digest(bytes: &[u8]) -> String {
		Sha256::digest(bytes)
			.iter()
			.map(|b| format!("{b:02x}"))
			.collect()
	}

	/// Named source binding, not a claim of a complete execution closure.
	fn source_fingerprint() -> BTreeMap<&'static str, String> {
		[
			("guard", include_bytes!("weight_guard.rs").as_slice()),
			("norm", include_bytes!("weight_norm.rs").as_slice()),
			("forward", include_bytes!("weight_forward.rs").as_slice()),
			("tensor", include_bytes!("weight_tensor.rs").as_slice()),
			("artifact", include_bytes!("weight_artifact.rs").as_slice()),
			("config", include_bytes!("weight_config.rs").as_slice()),
			("rea_files", include_bytes!("rea_files.rs").as_slice()),
			("rea_model", include_bytes!("rea_model.rs").as_slice()),
			("rea_evidence", include_bytes!("rea_evidence.rs").as_slice()),
			(
				"journal",
				include_bytes!("weight_guard_journal.rs").as_slice(),
			),
			(
				"cargo_manifest",
				include_bytes!("../../Cargo.toml").as_slice(),
			),
			("cargo_lock", include_bytes!("../../Cargo.lock").as_slice()),
		]
		.into_iter()
		.map(|(name, bytes)| (name, digest(bytes)))
		.collect()
	}

	#[derive(Serialize)]
	struct Intent<'a> {
		schema: &'static str,
		guard_semantics: &'static str,
		named_source_sha256: BTreeMap<&'static str, String>,
		source_fingerprint_is_complete_execution_closure: bool,
		state_dir: &'a Path,
		workspace_roots: &'a [PathBuf],
		request: &'a GuardedPatchParams,
	}

	pub(super) fn canonical_request(
		params: &GuardedPatchParams,
		roots: &[PathBuf],
		state: &Path,
	) -> Result<Vec<u8>> {
		// Round-trip also rejects nonfinite numbers serialized as JSON null.
		let mut request = Bounded(Vec::new());
		serde_json::to_writer(&mut request, params)?;
		let decoded: GuardedPatchParams = serde_json::from_slice(&request.0)?;
		let mut roundtrip = Bounded(Vec::new());
		serde_json::to_writer(&mut roundtrip, &decoded)?;
		if request.0 != roundtrip.0 {
			bail!("guard request is not an exact finite JSON round-trip");
		}
		let intent = Intent {
			schema: "hepta.weight.guard-intent.v1",
			guard_semantics: VERSION,
			named_source_sha256: source_fingerprint(),
			source_fingerprint_is_complete_execution_closure: false,
			state_dir: state,
			workspace_roots: roots,
			request: params,
		};
		let mut encoded = Bounded(Vec::new());
		serde_json::to_writer(&mut encoded, &intent)?;
		Ok(encoded.0)
	}

	fn cstr(value: &OsStr) -> Result<CString> {
		Ok(CString::new(value.as_bytes())?)
	}

	fn open_at(dir: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
		let name = CString::new(name)?;
		let fd = unsafe {
			libc::openat(
				dir.as_raw_fd(),
				name.as_ptr(),
				flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
				mode,
			)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(unsafe { File::from_raw_fd(fd) })
	}

	fn owned_directory(file: &File) -> Result<()> {
		let m = file.metadata()?;
		if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o700 {
			bail!("guard journal directory must be owned mode 0700");
		}
		Ok(())
	}

	fn owned_file(meta: &Metadata) -> Result<()> {
		if !meta.is_file()
			|| meta.uid() != unsafe { libc::geteuid() }
			|| meta.mode() & 0o777 != 0o600
			|| meta.nlink() != 1
		{
			bail!("guard journal file must be owned, regular, single-linked mode 0600");
		}
		Ok(())
	}

	fn absolute_directory(path: &Path, private: bool) -> Result<(PathBuf, File)> {
		if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4096 {
			bail!("guard journal requires bounded absolute directory paths");
		}
		let mut current = File::open("/")?;
		let mut components = 0usize;
		for component in path.components() {
			match component {
				Component::RootDir => {}
				Component::Normal(name) => {
					components += 1;
					if components > 128 {
						bail!("too many guard journal path components");
					}
					let name = cstr(name)?;
					let fd = unsafe {
						libc::openat(
							current.as_raw_fd(),
							name.as_ptr(),
							libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
						)
					};
					if fd < 0 {
						return Err(std::io::Error::last_os_error())
							.context("unsafe or missing guard directory component");
					}
					current = unsafe { File::from_raw_fd(fd) };
				}
				_ => bail!("guard journal disallows special directory components"),
			}
		}
		if private {
			owned_directory(&current)?;
		}
		let canonical = std::fs::canonicalize(path)?;
		let checked = File::open(&canonical)?;
		if !same_inode(&current.metadata()?, &checked.metadata()?) {
			bail!("guard directory identity changed during canonical binding");
		}
		Ok((canonical, current))
	}

	fn same_inode(a: &Metadata, b: &Metadata) -> bool {
		a.dev() == b.dev() && a.ino() == b.ino()
	}

	fn mkdir_at(parent: &File, name: &str) -> Result<()> {
		let part = CString::new(name)?;
		if unsafe { libc::mkdirat(parent.as_raw_fd(), part.as_ptr(), 0o700) } != 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(())
	}

	fn rename_exclusive(from_dir: &File, from: &str, to_dir: &File, to: &str) -> Result<()> {
		let from = CString::new(from)?;
		let to = CString::new(to)?;
		if unsafe {
			libc::renameat2(
				from_dir.as_raw_fd(),
				from.as_ptr(),
				to_dir.as_raw_fd(),
				to.as_ptr(),
				libc::RENAME_NOREPLACE,
			)
		} != 0
		{
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(())
	}

	fn nonce() -> Result<String> {
		Ok(format!(
			"{}-{}-{}",
			std::process::id(),
			SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
			SEQUENCE.fetch_add(1, Ordering::Relaxed)
		))
	}

	fn names(dir: &File, limit: usize) -> Result<Vec<String>> {
		struct Stream(*mut libc::DIR);
		impl Drop for Stream {
			fn drop(&mut self) {
				unsafe {
					libc::closedir(self.0);
				}
			}
		}
		// Open a new file description so directory enumeration offsets cannot leak
		// into the pinned root/lock descriptor or another scan.
		let copy = open_at(dir, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
		let fd = std::os::fd::IntoRawFd::into_raw_fd(copy);
		let raw = unsafe { libc::fdopendir(fd) };
		if raw.is_null() {
			let error = std::io::Error::last_os_error();
			unsafe {
				libc::close(fd);
			}
			return Err(error.into());
		}
		let stream = Stream(raw);
		let mut result = Vec::new();
		loop {
			unsafe {
				*libc::__errno_location() = 0;
			}
			let entry = unsafe { libc::readdir(stream.0) };
			if entry.is_null() {
				let error = std::io::Error::last_os_error();
				if error.raw_os_error() != Some(0) {
					return Err(error.into());
				}
				break;
			}
			let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
				.to_str()?
				.to_owned();
			if name == "." || name == ".." {
				continue;
			}
			result.push(name);
			if result.len() > limit {
				bail!("guard journal bounded directory count exceeded");
			}
		}
		Ok(result)
	}

	fn read_optional(dir: &File, name: &str, max: usize) -> Result<Option<Vec<u8>>> {
		let mut file = match open_at(dir, name, libc::O_RDONLY, 0) {
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
		let before = file.metadata()?;
		owned_file(&before)?;
		if before.len() > max as u64 {
			bail!("guard journal record byte cap exceeded");
		}
		let mut bytes = Vec::new();
		(&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
		if bytes.len() > max {
			bail!("guard journal record grew past its byte cap");
		}
		super::super::rea_files::ensure_unchanged(&before, &file.metadata()?)?;
		let again = open_at(dir, name, libc::O_RDONLY, 0)?;
		super::super::rea_files::ensure_unchanged(&before, &again.metadata()?)?;
		Ok(Some(bytes))
	}

	fn publish_file(dir: &File, name: &str, bytes: &[u8]) -> Result<()> {
		let temporary = format!(".pending-{name}-{}", nonce()?);
		let mut file = open_at(
			dir,
			&temporary,
			libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
			0o600,
		)?;
		owned_file(&file.metadata()?)?;
		file.write_all(bytes)?;
		file.sync_all()?;
		drop(file);
		rename_exclusive(dir, &temporary, dir, name)?;
		dir.sync_all()?;
		if read_optional(dir, name, bytes.len())?.as_deref() != Some(bytes) {
			bail!("guard journal published record verification failed");
		}
		Ok(())
	}

	pub(super) struct Journal {
		state_path: PathBuf,
		state: File,
		root: File,
	}

	impl Journal {
		pub(super) async fn open(state: &Path) -> Result<Self> {
			let (state_path, state) = absolute_directory(state, true)?;
			match mkdir_at(&state, ROOT_NAME) {
				Ok(()) => state.sync_all()?,
				Err(error)
					if error
						.downcast_ref::<std::io::Error>()
						.is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) => {}
				Err(error) => return Err(error),
			}
			let root = open_at(&state, ROOT_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			owned_directory(&root)?;
			let deadline = Instant::now() + Duration::from_secs(10);
			loop {
				if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
					break;
				}
				let error = std::io::Error::last_os_error();
				if error.kind() != std::io::ErrorKind::WouldBlock {
					return Err(error.into());
				}
				if Instant::now() >= deadline {
					bail!("guard journal busy; retry the identical request");
				}
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
			let journal = Self {
				state_path,
				state,
				root,
			};
			journal.check_root()?;
			Ok(journal)
		}

		fn check_root(&self) -> Result<()> {
			let (_, state) = absolute_directory(&self.state_path, true)?;
			let root = open_at(
				&self.state,
				ROOT_NAME,
				libc::O_RDONLY | libc::O_DIRECTORY,
				0,
			)?;
			owned_directory(&self.root)?;
			owned_directory(&root)?;
			if !same_inode(&state.metadata()?, &self.state.metadata()?)
				|| !same_inode(&root.metadata()?, &self.root.metadata()?)
			{
				bail!("guard journal state or root pathname was rebound");
			}
			Ok(())
		}

		fn quota(&self, incoming: u64, new_entry: bool) -> Result<()> {
			let entries = names(&self.root, MAX_ENTRIES)?;
			if new_entry && entries.len() >= MAX_ENTRIES {
				bail!("guard journal entry quota exhausted");
			}
			let mut total = 0u64;
			for name in entries {
				if !name.starts_with(".pending-entry-")
					&& !name
						.strip_prefix("wgj1_")
						.is_some_and(super::super::weight_config::valid_sha256)
				{
					bail!("unexpected guard journal entry");
				}
				let dir = open_at(&self.root, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
				owned_directory(&dir)?;
				for member in names(&dir, MAX_MEMBERS)? {
					if !matches!(
						member.as_str(),
						"intent.json" | "candidate.json" | "completion.json" | "first_failure.json"
					) && !member.starts_with(".pending-")
					{
						bail!("unexpected guard journal member");
					}
					let file = open_at(&dir, &member, libc::O_RDONLY, 0)?;
					let meta = file.metadata()?;
					owned_file(&meta)?;
					if meta.len() > MAX_RECORD_BYTES as u64 {
						bail!("guard journal member exceeds byte cap");
					}
					total = total
						.checked_add(meta.len())
						.ok_or_else(|| anyhow!("guard journal quota overflow"))?;
				}
			}
			if total
				.checked_add(incoming)
				.is_none_or(|n| n > MAX_TOTAL_BYTES)
			{
				bail!("guard journal total-byte quota exhausted");
			}
			Ok(())
		}

		fn entry(&self, id: &str, intent: &[u8]) -> Result<(File, bool)> {
			self.check_root()?;
			match open_at(&self.root, id, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
				Ok(dir) => {
					owned_directory(&dir)?;
					if read_optional(&dir, "intent.json", MAX_REQUEST_BYTES)?.as_deref()
						!= Some(intent)
					{
						bail!("guard journal intent is missing, altered or belongs to different semantics");
					}
					self.quota(0, false)?;
					Ok((dir, false))
				}
				Err(error)
					if error
						.downcast_ref::<std::io::Error>()
						.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
				{
					// Reserve worst-case completion/candidate/failure accounting while
					// holding the global lock; physical disk exhaustion still can fail.
					self.quota(
						(intent.len() + MAX_RECORD_BYTES + MAX_CANDIDATE_BYTES + MAX_FAILURE_BYTES)
							as u64,
						true,
					)?;
					let stage_name = format!(".pending-entry-{}", nonce()?);
					mkdir_at(&self.root, &stage_name)?;
					let stage = open_at(
						&self.root,
						&stage_name,
						libc::O_RDONLY | libc::O_DIRECTORY,
						0,
					)?;
					owned_directory(&stage)?;
					publish_file(&stage, "intent.json", intent)?;
					stage.sync_all()?;
					rename_exclusive(&self.root, &stage_name, &self.root, id)?;
					self.root.sync_all()?;
					self.check_entry(id, &stage, intent)?;
					Ok((stage, true))
				}
				Err(error) => Err(error),
			}
		}

		fn check_entry(&self, id: &str, dir: &File, intent: &[u8]) -> Result<()> {
			self.check_root()?;
			let current = open_at(&self.root, id, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			owned_directory(&current)?;
			owned_directory(dir)?;
			if !same_inode(&current.metadata()?, &dir.metadata()?)
				|| read_optional(dir, "intent.json", MAX_REQUEST_BYTES)?.as_deref() != Some(intent)
			{
				bail!("guard journal entry or canonical intent changed");
			}
			Ok(())
		}

		fn write_record(
			&self,
			dir: &File,
			name: &str,
			value: &Value,
			max: usize,
		) -> Result<Vec<u8>> {
			let bytes = serde_json::to_vec(value)?;
			if bytes.len() > max {
				bail!("guard journal durable record exceeds byte cap");
			}
			self.quota(bytes.len() as u64, false)?;
			publish_file(dir, name, &bytes)?;
			Ok(bytes)
		}
	}

	fn parse_record(bytes: &[u8]) -> Result<Value> {
		super::super::rea_evidence::parse_unique_json(bytes)
	}

	fn semantic_guard(report: &Value) -> Result<Value> {
		let mut result = report.clone();
		result
			.as_object_mut()
			.ok_or_else(|| anyhow!("guard result must be an object"))?
			.remove("native_operation_wall_seconds");
		for key in ["candidate", "restoration"] {
			if let Some(map) = result[key].as_object_mut() {
				map.remove("reused");
			}
		}
		Ok(result)
	}

	fn semantic_restore(report: &Value) -> Value {
		let mut result = report.clone();
		if let Some(map) = result.as_object_mut() {
			map.remove("reused");
		}
		result
	}

	fn semantic_result(mode: &str, guard: &Value, restoration: &Value) -> Result<Value> {
		Ok(
			json!({"mode":mode,"guard":semantic_guard(guard)?,"forced_restoration":semantic_restore(restoration)}),
		)
	}

	async fn force_restore(guard: &Value, state: &Path, expected: &str) -> Result<Value> {
		let id = guard["candidate"]["artifact_id"]
			.as_str()
			.ok_or_else(|| anyhow!("guard did not identify its candidate"))?;
		let restored = tokio::time::timeout(Duration::from_secs(360), async {
			let receipt = super::super::weight_artifact::restore_with_state(id, state).await?;
			let restored_id = receipt["artifact_id"]
				.as_str()
				.ok_or_else(|| anyhow!("restore identity missing"))?;
			let (mut file, before, committed) =
				super::super::weight_artifact::open_pinned_artifact(restored_id, state).await?;
			if before.len() > 2 * 1024 * 1024 * 1024u64 {
				bail!("restored artifact exceeds byte cap");
			}
			let mut hash = Sha256::new();
			let mut remaining = before.len();
			let mut buffer = vec![0u8; 1024 * 1024];
			while remaining > 0 {
				let count = remaining.min(buffer.len() as u64) as usize;
				file.read_exact(&mut buffer[..count]).await?;
				hash.update(&buffer[..count]);
				remaining -= count as u64;
			}
			super::super::rea_files::ensure_unchanged(&before, &file.metadata().await?)?;
			let actual: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
			if actual != expected || committed != expected || receipt["sha256"] != expected {
				bail!("forced restore did not authenticate the exact requested parent hash");
			}
			Ok::<_, anyhow::Error>(receipt)
		})
		.await
		.context("forced restoration deadline expired; recovery unverified")??;
		Ok(restored)
	}

	fn candidate_record(id: &str, intent_hash: &str, guard: &Value) -> Result<Value> {
		let candidate = semantic_restore(&guard["candidate"]);
		if candidate["artifact_id"].as_str().is_none() || candidate["sha256"].as_str().is_none() {
			bail!("guard candidate receipt is incomplete");
		}
		Ok(
			json!({"schema":"hepta.weight.guard-candidate.v1","journal_id":id,
            "intent_sha256":intent_hash,"guard_semantics":VERSION,"candidate":candidate}),
		)
	}

	fn write_or_check_candidate(j: &Journal, dir: &File, record: &Value) -> Result<()> {
		if let Some(bytes) = read_optional(dir, "candidate.json", MAX_CANDIDATE_BYTES)? {
			if parse_record(&bytes)? != *record {
				bail!("guard candidate record differs from authenticated replay");
			}
		} else {
			j.write_record(dir, "candidate.json", record, MAX_CANDIDATE_BYTES)?;
		}
		Ok(())
	}

	fn retain_first_failure(
		j: &Journal,
		dir: &File,
		id: &str,
		intent_hash: &str,
		report: &Value,
	) -> Result<bool> {
		if let Some(bytes) = read_optional(dir, "first_failure.json", MAX_FAILURE_BYTES)? {
			let existing = parse_record(&bytes)?;
			if existing["schema"] != "hepta.weight.guard-first-failure.v1"
				|| existing["journal_id"] != id
				|| existing["intent_sha256"] != intent_hash
			{
				bail!("first failure journal record is inconsistent");
			}
			return Ok(false);
		}
		j.write_record(
			dir,
			"first_failure.json",
			&json!({"schema":"hepta.weight.guard-first-failure.v1",
            "journal_id":id,"intent_sha256":intent_hash,"report":report}),
			MAX_FAILURE_BYTES,
		)?;
		Ok(true)
	}

	fn failure(
		id: &str,
		phase: &str,
		error: &anyhow::Error,
		started: Instant,
		recovery: bool,
	) -> Value {
		json!({"schema":"hepta.weight.guard-journal-result.v1","journal_id":id,
            "accepted":false,"outcome":if recovery {"rejected_recovery_unverified"} else {"rejected_revalidation_or_evaluation_unverified"},
            "error":error.to_string().chars().take(1024).collect::<String>(),"phase":phase,
            "current_durable_completion":false,"interruption_recovery_verified":false,
            "native_journal_call_wall_seconds":started.elapsed().as_secs_f64(),
            "prior_interrupted_call_cost_known":false,"end_to_end_cost_known":false,
            "source_modified":false,"production_eligible":false,
            "explicit_same_request_reconcile":recovery,"background_recovery":false})
	}

	struct Timings {
		started: Instant,
		guard_seconds: f64,
		restore_seconds: f64,
	}

	fn result(
		id: &str,
		mode: &str,
		guard: Value,
		restoration: Value,
		completion_hash: &str,
		replay: bool,
		timings: Timings,
	) -> Value {
		let original_accepted = guard["accepted"].as_bool().unwrap_or(false);
		let interrupted = mode == "interrupted_recovery";
		let mut output = guard;
		output["journal_id"] = json!(id);
		output["guard_semantics"] = json!(VERSION);
		output["named_source_fingerprint_is_complete_execution_closure"] = json!(false);
		output["durable_evaluation_receipt"] = json!(true);
		output["current_durable_completion"] = json!(true);
		output["completion_sha256"] = json!(completion_hash);
		output["completed_receipt_reauthenticated_by_full_guard_replay"] = json!(replay);
		output["explicit_same_request_reconcile"] = json!(interrupted);
		output["background_recovery"] = json!(false);
		output["replay_guard_internal_accepted"] = json!(original_accepted);
		if interrupted {
			output["accepted"] = json!(false);
			output["outcome"] = json!("interrupted_rejected_and_restored");
			output["restoration"] = restoration;
			output["interruption_recovery_verified"] = json!(true);
		}
		output["native_journal_call_wall_seconds"] = json!(timings.started.elapsed().as_secs_f64());
		output["this_call_guard_wall_seconds"] = json!(timings.guard_seconds);
		output["this_call_forced_restore_wall_seconds"] = json!(timings.restore_seconds);
		output["component_times_are_nested_in_journal_wall"] = json!(true);
		output["prior_interrupted_call_cost_known"] = json!(false);
		output["receipt_reuse_skips_model_authentication"] = json!(false);
		output["recovery_may_publish_previously_absent_isolated_candidate"] = json!(interrupted);
		output
	}

	#[cfg(test)]
	async fn failpoint(name: &str) -> Result<()> {
		if std::env::var("HEPTA_TEST_JOURNAL_PHASE").as_deref() == Ok(name) {
			let marker = PathBuf::from(std::env::var("HEPTA_TEST_JOURNAL_MARKER")?);
			let mut options = std::fs::OpenOptions::new();
			use std::os::unix::fs::OpenOptionsExt;
			options
				.write(true)
				.create_new(true)
				.mode(0o600)
				.custom_flags(libc::O_NOFOLLOW);
			let mut file = options.open(marker)?;
			file.write_all(name.as_bytes())?;
			file.sync_all()?;
			loop {
				tokio::time::sleep(Duration::from_secs(1)).await;
			}
		}
		Ok(())
	}

	#[cfg(not(test))]
	async fn failpoint(_: &str) -> Result<()> {
		Ok(())
	}

	pub(super) async fn evaluate(
		params: GuardedPatchParams,
		roots: &[PathBuf],
		state: &Path,
	) -> Result<Value> {
		let started = Instant::now();
		if roots.is_empty() || roots.len() > 64 {
			bail!("guard journal requires 1..=64 workspace roots");
		}
		let (state, _) = absolute_directory(state, true)?;
		let roots = roots
			.iter()
			.map(|root| absolute_directory(root, false).map(|x| x.0))
			.collect::<Result<Vec<_>>>()?;
		let intent = canonical_request(&params, &roots, &state)?;
		let intent_hash = digest(&intent);
		let id = format!("wgj1_{intent_hash}");
		let journal = Journal::open(&state).await?;
		let (dir, new) = journal.entry(&id, &intent)?;
		let prior_completion = read_optional(&dir, "completion.json", MAX_RECORD_BYTES)?;
		let prior = prior_completion
			.as_ref()
			.map(|bytes| parse_record(bytes))
			.transpose()?;
		let mode = if let Some(prior) = &prior {
			if prior["schema"] != "hepta.weight.guard-completion.v1"
				|| prior["journal_id"] != id
				|| prior["intent_sha256"] != intent_hash
				|| prior["guard_semantics"] != VERSION
				|| !matches!(
					prior["mode"].as_str(),
					Some("evaluation" | "interrupted_recovery")
				) {
				bail!("guard journal completion binding or version mismatch");
			}
			prior["mode"].as_str().unwrap()
		} else if new {
			"evaluation"
		} else {
			"interrupted_recovery"
		};
		failpoint("after_intent").await?;
		let guard_start = Instant::now();
		let evaluated =
			super::super::weight_guard::evaluate_with_roots(params.clone(), &roots, &state).await;
		let guard_seconds = guard_start.elapsed().as_secs_f64();
		let guard = match evaluated {
			Ok(guard) => guard,
			Err(error) => {
				let mut report = failure(
					&id,
					"full_guard_replay",
					&error,
					started,
					!new || mode == "interrupted_recovery",
				);
				report["this_call_guard_wall_seconds"] = json!(guard_seconds);
				let retained = retain_first_failure(&journal, &dir, &id, &intent_hash, &report);
				report["this_failure_durably_retained"] =
					json!(retained.as_ref().is_ok_and(|v| *v));
				if let Err(error) = retained {
					report["failure_retention_error"] = json!(error.to_string());
				}
				report["native_journal_call_wall_seconds"] = json!(started.elapsed().as_secs_f64());
				if new {
					// Preserve the original tool-error contract for a fresh invalid
					// request. Only an existing intent is a reconciliation response.
					bail!(
						"guard journal {id}: fresh guarded request rejected: {error}; first failure retained={}",
						report["this_failure_durably_retained"]
					);
				}
				return Ok(report);
			}
		};
		failpoint("after_guard_before_candidate").await?;
		let recovery_start = Instant::now();
		let forced = if mode == "interrupted_recovery" {
			force_restore(&guard, &state, &params.patch.expected_sha256).await
		} else {
			Ok(Value::Null)
		};
		let restore_seconds = if mode == "interrupted_recovery" {
			recovery_start.elapsed().as_secs_f64()
		} else {
			0.0
		};
		let restoration = match forced {
			Ok(restored) => restored,
			Err(error) => {
				let mut report = failure(&id, "forced_restore", &error, started, true);
				report["this_call_guard_wall_seconds"] = json!(guard_seconds);
				report["this_call_forced_restore_wall_seconds"] = json!(restore_seconds);
				report["candidate"] = guard["candidate"].clone();
				report["replay_guard_internal_accepted"] = guard["accepted"].clone();
				let retained = retain_first_failure(&journal, &dir, &id, &intent_hash, &report);
				report["this_failure_durably_retained"] =
					json!(retained.as_ref().is_ok_and(|v| *v));
				if let Err(error) = retained {
					report["failure_retention_error"] = json!(error.to_string());
				}
				report["native_journal_call_wall_seconds"] = json!(started.elapsed().as_secs_f64());
				return Ok(report);
			}
		};
		let recorded: Result<String> = async {
            journal.check_entry(&id, &dir, &intent)?;
            write_or_check_candidate(&journal, &dir, &candidate_record(&id, &intent_hash, &guard)?)?;
            failpoint("after_candidate_before_completion").await?;
            let semantic = semantic_result(mode, &guard, &restoration)?;
            let semantic_hash = digest(&serde_json::to_vec(&semantic)?);
            if let Some(prior) = &prior {
                if prior["semantic_sha256"] != semantic_hash || prior["semantic_result"] != semantic {
                    bail!("completed guard receipt differs from freshly authenticated semantics");
                }
                if read_optional(&dir, "completion.json", MAX_RECORD_BYTES)? != prior_completion {
                    bail!("completed guard record changed during revalidation");
                }
                dir.sync_all()?;
                return Ok(digest(prior_completion.as_ref().unwrap()));
            }
            let complete = json!({"schema":"hepta.weight.guard-completion.v1","journal_id":id,
                "intent_sha256":intent_hash,"guard_semantics":VERSION,"mode":mode,
                "semantic_sha256":semantic_hash,"semantic_result":semantic,
                "this_call_guard_wall_seconds":guard_seconds,"this_call_forced_restore_wall_seconds":restore_seconds,
                "wall_before_completion_publication_seconds":started.elapsed().as_secs_f64(),
                "prior_interrupted_call_cost_known":false,"end_to_end_cost_known":false});
            let bytes = journal.write_record(&dir, "completion.json", &complete, MAX_RECORD_BYTES)?;
            journal.check_entry(&id, &dir, &intent)?;
            failpoint("after_completion").await?;
            Ok(digest(&bytes))
        }.await;
		match recorded {
			Ok(completion_hash) => Ok(result(
				&id,
				mode,
				guard,
				restoration,
				&completion_hash,
				prior.is_some(),
				Timings {
					started,
					guard_seconds,
					restore_seconds,
				},
			)),
			Err(error) => {
				// Publication, semantics and revalidation failures never leak acceptance.
				let restore_start = Instant::now();
				let recovered = force_restore(&guard, &state, &params.patch.expected_sha256).await;
				let mut report = failure(
					&id,
					"journal_completion_or_revalidation",
					&error,
					started,
					true,
				);
				report["this_call_guard_wall_seconds"] = json!(guard_seconds);
				report["this_call_forced_restore_wall_seconds"] =
					json!(restore_seconds + restore_start.elapsed().as_secs_f64());
				report["candidate"] = guard["candidate"].clone();
				match recovered {
					Ok(receipt) => {
						report["outcome"] = json!("rejected_and_restored_journal_incomplete");
						report["restoration"] = receipt;
						report["interruption_recovery_verified"] = json!(true);
					}
					Err(error) => report["restoration_error"] = json!(error.to_string()),
				}
				let retained = retain_first_failure(&journal, &dir, &id, &intent_hash, &report);
				report["this_failure_durably_retained"] =
					json!(retained.as_ref().is_ok_and(|v| *v));
				if let Err(error) = retained {
					report["failure_retention_error"] = json!(error.to_string());
				}
				report["native_journal_call_wall_seconds"] = json!(started.elapsed().as_secs_f64());
				Ok(report)
			}
		}
	}
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_guard_journal_tests.rs"]
mod tests;
