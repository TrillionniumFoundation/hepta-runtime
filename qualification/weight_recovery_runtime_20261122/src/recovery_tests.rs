// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fast coordination controls; canonical owner process checks live in the root bridge.

use super::*;
use anyhow::{bail, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Fixture {
	path: PathBuf,
	intent: Intent,
}
impl Fixture {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!(
			"hepta-recovery-unit-{}-{}",
			std::process::id(),
			SERIAL.fetch_add(1, Ordering::Relaxed)
		));
		let req = json!({"tensor":"synthetic","old":[1,2],"new":[3,4]});
		let intent = Intent {
			schema: "hepta.weight.recovery-intent.v1".into(),
			source_sha256: digest(&[1, 2]),
			candidate_sha256: digest(&[3, 4]),
			law_sha256: digest(b"law"),
			task_sha256: digest(b"task"),
			evaluator_sha256: digest(b"evaluator"),
			owner_request_sha256: digest(&serde_json::to_vec(&req).unwrap()),
			owner_request: req,
		};
		Self { path, intent }
	}
}
impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.path);
	}
}
#[derive(Default)]
struct MockOwner {
	entries: BTreeMap<String, OwnerReceipt>,
	publish_calls: usize,
	restore_calls: usize,
	source_changed: bool,
}
impl ArtifactOwner for MockOwner {
	fn publish(&mut self, i: &Intent) -> Result<OwnerReceipt> {
		self.publish_calls += 1;
		let r = OwnerReceipt {
			artifact_id: format!("wa1_{}", digest(b"patch")),
			source_sha256: i.source_sha256.clone(),
			content_sha256: i.candidate_sha256.clone(),
			kind: "patch".into(),
		};
		self.entries.insert(r.artifact_id.clone(), r.clone());
		Ok(r)
	}
	fn inspect(&mut self, r: &OwnerReceipt) -> Result<()> {
		if self.entries.get(&r.artifact_id) != Some(r) {
			bail!("mock missing")
		}
		Ok(())
	}
	fn restore(&mut self, i: &Intent, _: &OwnerReceipt) -> Result<OwnerReceipt> {
		self.restore_calls += 1;
		let r = OwnerReceipt {
			artifact_id: format!("wa1_{}", digest(b"restore")),
			source_sha256: i.candidate_sha256.clone(),
			content_sha256: i.source_sha256.clone(),
			kind: "restore".into(),
		};
		self.entries.insert(r.artifact_id.clone(), r.clone());
		Ok(r)
	}
	fn verify_original(&mut self, _: &Intent) -> Result<()> {
		if self.source_changed {
			bail!("source changed")
		}
		Ok(())
	}
}
struct Score {
	pass: bool,
	broken: bool,
	calls: usize,
}
impl Evaluator for Score {
	fn evaluate(&mut self, i: &Intent, _: &OwnerReceipt) -> Result<Evaluation> {
		self.calls += 1;
		Ok(Evaluation {
			candidate_sha256: i.candidate_sha256.clone(),
			task_sha256: if self.broken {
				digest(b"wrong-task")
			} else {
				i.task_sha256.clone()
			},
			law_sha256: i.law_sha256.clone(),
			evaluator_sha256: i.evaluator_sha256.clone(),
			passed: self.pass,
			result_sha256: digest(b"finite toy result"),
		})
	}
}
struct FailAt(&'static str);
impl Checkpoint for FailAt {
	fn reached(&mut self, name: &str) -> Result<()> {
		if name == self.0 {
			bail!("injected return-path error")
		}
		Ok(())
	}
}

#[test]
fn normal_accept_and_idempotent_recovery() -> Result<()> {
	let f = Fixture::new();
	let mut o = MockOwner::default();
	let mut e = Score {
		pass: true,
		broken: false,
		calls: 0,
	};
	let r = execute(&f.path, f.intent.clone(), &mut o, &mut e, &mut NoCheckpoint)?;
	assert_eq!(r.decision, Some(Decision::ResearchAcceptedRestored));
	assert_eq!(e.calls, 1);
	assert_eq!(o.entries.len(), 2);
	let again = recover(&f.path, &f.intent, &mut o, &mut NoCheckpoint)?;
	assert_eq!(r, again);
	assert_eq!(o.publish_calls, 1);
	assert_eq!(o.restore_calls, 1);
	assert!(execute(&f.path, f.intent.clone(), &mut o, &mut e, &mut NoCheckpoint).is_err());
	Ok(())
}

#[test]
fn rejected_evaluation_has_no_acceptance() -> Result<()> {
	let f = Fixture::new();
	let mut o = MockOwner::default();
	let mut e = Score {
		pass: false,
		broken: false,
		calls: 0,
	};
	let r = execute(&f.path, f.intent.clone(), &mut o, &mut e, &mut NoCheckpoint)?;
	assert_eq!(r.decision, Some(Decision::ResearchRejectedRestored));
	assert!(r.acceptance_sha256.is_none());
	assert_eq!(o.restore_calls, 1);
	Ok(())
}

#[test]
fn wrong_evaluator_identity_recovers_without_acceptance() -> Result<()> {
	let f = Fixture::new();
	let mut o = MockOwner::default();
	let mut e = Score {
		pass: true,
		broken: true,
		calls: 0,
	};
	let r = execute(&f.path, f.intent.clone(), &mut o, &mut e, &mut NoCheckpoint)?;
	assert_eq!(r.decision, Some(Decision::InterruptedRestored));
	assert!(r.evaluation.is_none());
	assert!(r.acceptance_sha256.is_none());
	assert!(r.failure.is_some());
	Ok(())
}

#[test]
fn ordinary_errors_restore_at_each_boundary() -> Result<()> {
	for cut in [
		"prepared",
		"publish_intent",
		"publish_effect",
		"published",
		"verify_intent",
		"verify_effect",
		"verified",
		"accepted",
		"restore_intent",
		"restore_effect",
		"restored",
	] {
		let f = Fixture::new();
		let mut o = MockOwner::default();
		let mut e = Score {
			pass: true,
			broken: false,
			calls: 0,
		};
		let r = execute(&f.path, f.intent.clone(), &mut o, &mut e, &mut FailAt(cut))?;
		assert_eq!(
			r.decision,
			Some(if cut == "prepared" {
				Decision::KeptOriginal
			} else {
				Decision::InterruptedRestored
			}),
			"{cut}"
		);
		let publication_calls = o.publish_calls;
		let restore_calls = o.restore_calls;
		let again = recover(&f.path, &f.intent, &mut o, &mut NoCheckpoint)?;
		assert_eq!(r, again, "{cut}");
		assert_eq!(
			(publication_calls, restore_calls),
			(o.publish_calls, o.restore_calls)
		);
	}
	Ok(())
}

#[test]
fn invalid_request_binding_rejected_before_journal() -> Result<()> {
	let f = Fixture::new();
	let mut i = f.intent.clone();
	i.owner_request = json!({"new":"tampered"});
	assert!(i.id().is_err());
	assert!(!Path::new(&f.path).exists());
	Ok(())
}

#[test]
fn missing_or_tampered_record_is_fail_closed() -> Result<()> {
	let f = Fixture::new();
	let mut o = MockOwner::default();
	let mut e = Score {
		pass: true,
		broken: false,
		calls: 0,
	};
	execute(&f.path, f.intent.clone(), &mut o, &mut e, &mut NoCheckpoint)?;
	let p = f.path.join(f.intent.id()?).join("record-0001.json");
	std::fs::remove_file(p)?;
	assert!(recover(&f.path, &f.intent, &mut o, &mut NoCheckpoint).is_err());
	Ok(())
}

#[test]
fn changed_original_is_not_reported_recovered() -> Result<()> {
	let f = Fixture::new();
	let mut o = MockOwner::default();
	let mut e = Score {
		pass: true,
		broken: false,
		calls: 0,
	};
	execute(&f.path, f.intent.clone(), &mut o, &mut e, &mut NoCheckpoint)?;
	o.source_changed = true;
	assert!(recover(&f.path, &f.intent, &mut o, &mut NoCheckpoint).is_err());
	Ok(())
}

#[test]
fn durable_restored_rechecks_missing_and_damaged_artifact_before_complete() -> Result<()> {
	for damaged in [false, true] {
		let f = Fixture::new();
		let mut o = MockOwner::default();
		let mut e = Score {
			pass: true,
			broken: false,
			calls: 0,
		};
		let r = execute(&f.path, f.intent.clone(), &mut o, &mut e, &mut NoCheckpoint)?;
		let transaction = f.path.join(f.intent.id()?);
		let completed = transaction.join(format!("record-{:04}.json", r.sequence));
		std::fs::remove_file(&completed)?;
		let restore_id = &r.restoration.as_ref().unwrap().artifact_id;
		if damaged {
			o.entries.get_mut(restore_id).unwrap().content_sha256 = digest(b"corrupt");
		} else {
			o.entries.remove(restore_id);
		}
		assert!(recover(&f.path, &f.intent, &mut o, &mut NoCheckpoint).is_err());
		assert!(!completed.exists());
		assert_eq!(e.calls, 1);
	}
	Ok(())
}

#[test]
fn same_process_partial_stage_does_not_block_and_exact_complete_stage_reuses() -> Result<()> {
	for complete in [false, true] {
		let f = Fixture::new();
		std::fs::DirBuilder::new().mode(0o700).create(&f.path)?;
		let transaction = f.path.join(f.intent.id()?);
		std::fs::DirBuilder::new()
			.mode(0o700)
			.create(&transaction)?;
		let partial = transaction.join(format!(".pending-{}-0", std::process::id()));
		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&partial)?;
		file.write_all(b"{partial")?;
		file.sync_all()?;
		let matching = transaction.join(".pending-exact-complete");
		if complete {
			let record = Record {
				schema: "hepta.weight.recovery-record.v1".into(),
				sequence: 0,
				previous_sha256: None,
				intent: f.intent.clone(),
				stage: Stage::Prepared,
				publication: None,
				evaluation: None,
				acceptance_sha256: None,
				restoration: None,
				decision: None,
				recovery: false,
				failure: None,
			};
			let mut file = std::fs::OpenOptions::new()
				.write(true)
				.create_new(true)
				.mode(0o600)
				.open(&matching)?;
			file.write_all(&serde_json::to_vec(&record)?)?;
			file.sync_all()?;
		}
		let mut o = MockOwner::default();
		let mut e = Score {
			pass: true,
			broken: false,
			calls: 0,
		};
		let r = execute(&f.path, f.intent.clone(), &mut o, &mut e, &mut NoCheckpoint)?;
		assert_eq!(r.decision, Some(Decision::ResearchAcceptedRestored));
		assert_eq!(std::fs::read(partial)?, b"{partial");
		assert!(!matching.exists());
		assert_eq!(recover(&f.path, &f.intent, &mut o, &mut NoCheckpoint)?, r);
	}
	Ok(())
}
