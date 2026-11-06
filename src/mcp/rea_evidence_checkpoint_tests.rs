// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Real private-store, authenticated-history and commit-lifetime regressions.

use super::*;
use crate::mcp::rea_evidence_source;
use crate::mcp::rea_response_encoding::ObjectOrder as ResponseObjectOrder;
use crate::mcp::rea_response_order::{RecordOrder, RecordOrigin};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const IMPORT: &[u8] =
	include_bytes!("../../tests/fixtures/rea_evidence_checkpoint/unknown-verified.json");

fn environment() -> (tempfile::TempDir, Scope) {
	let temp = tempfile::tempdir().unwrap();
	let scope = Scope {
		state_dir: temp.path().join("state"),
		owner: "a".repeat(64),
		policy: "b".repeat(64),
	};
	(temp, scope)
}

fn imported(bytes: &[u8]) -> Arc<EvidenceSession> {
	let (bundle, order) =
		rea_evidence_file::parse_checkpoint_json(bytes, &CancellationToken::new()).unwrap();
	let resolver = |path: &[Value]| order.keys(path);
	let candidate =
		rea_evidence_source::authenticate_import_with_order(bundle, Some(&resolver)).unwrap();
	let session = Arc::new(EvidenceSession::default());
	session
		.import_if_active(
			candidate,
			order.into_record_orders().unwrap(),
			&CancellationToken::new(),
		)
		.unwrap();
	session
}

fn bundle(session: &EvidenceSession) -> String {
	let reply = session.get_bundle(json!({}));
	assert!(reply.is_error.is_none(), "{reply:?}");
	serde_json::to_string(&reply).unwrap()
}

fn save(scope: &Scope, session: &EvidenceSession) -> Value {
	serde_json::from_str(
		&checkpoint_at(scope, session, &CancellationToken::new(), &|_| Ok(())).unwrap(),
	)
	.unwrap()
}

fn restore(scope: &Scope, id: &str, session: &EvidenceSession) -> Result<String> {
	resume_at(
		scope,
		&ResumeParams {
			checkpoint_id: id.into(),
		},
		session,
		&CancellationToken::new(),
	)
}

fn listing(scope: &Scope, offset: usize, limit: usize, expected: Option<String>) -> Result<Value> {
	Ok(serde_json::from_str(&list_at(
		scope,
		&ListParams {
			offset,
			limit,
			expected_catalog_sha256: expected,
		},
		&CancellationToken::new(),
	)?)?)
}

fn directory(scope: &Scope, id: &str) -> PathBuf {
	scope.state_dir.join(ROOT_NAME).join(id)
}

#[test]
fn original_unknown_fixture_is_bound_to_real_node_production() {
	let provenance: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_checkpoint/provenance.json"
	))
	.unwrap();
	let raw = include_bytes!("../../tests/fixtures/rea_evidence_checkpoint/producer-run.stdout");
	let producer: Value = serde_json::from_slice(raw).unwrap();
	assert_eq!(hash(IMPORT), provenance["fixture_sha256"]);
	assert_eq!(
		IMPORT.len(),
		provenance["fixture_bytes"].as_u64().unwrap() as usize
	);
	assert_eq!(producer, provenance["original_producer"]);
	assert_eq!(producer["selected_fixture"]["sha256"], hash(IMPORT));
	assert_eq!(
		producer["node"]["sha256"],
		"94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90"
	);
	assert_eq!(
		producer["tarball"]["sha256"],
		"8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb"
	);
	let terminal = &provenance["controller_terminal"];
	assert_eq!(terminal["state"], "succeeded");
	assert_eq!(terminal["exit_code"], 0);
	assert_eq!(terminal["output_complete"], true);
	assert_eq!(terminal["output_durable"], true);
	assert_eq!(terminal["automatic_retry"], false);
	assert_eq!(terminal["terminal_publication_confirmed"], true);
	assert_eq!(terminal["log_bytes"]["stdout"]["stored"], raw.len());
	assert_eq!(terminal["log_truncated"]["stdout"], false);
}

#[test]
fn complete_unknown_history_and_imported_physical_keys_survive_cold_state_reconstruction() {
	let (_temp, scope) = environment();
	let source = String::from_utf8(IMPORT.to_vec()).unwrap();
	let old = r#""normalized_result":{"2":"two","3":"three","z":1,"#;
	assert_eq!(source.matches(old).count(), 1);
	let physical = source.replacen(
		old,
		r#""normalized_result":{"3":"three","2":"two","z":0,"z":1,"#,
		1,
	);
	let session = imported(physical.as_bytes());
	let before = bundle(&session);
	let receipt = save(&scope, &session);
	assert_eq!(receipt["records"], 3);
	assert_eq!(receipt["unknown_revisions"], 3);
	assert_eq!(receipt["reused"], false);
	let repeated = save(&scope, &session);
	assert_eq!(repeated["checkpoint_id"], receipt["checkpoint_id"]);
	assert_eq!(repeated["reused"], true);
	drop(session);
	let reconstructed = Scope {
		state_dir: scope.state_dir.clone(),
		owner: scope.owner.clone(),
		policy: scope.policy.clone(),
	};
	let cold = EvidenceSession::default();
	assert_eq!(cold.snapshot().unwrap().record_count(), 0);
	restore(
		&reconstructed,
		receipt["checkpoint_id"].as_str().unwrap(),
		&cold,
	)
	.unwrap();
	assert_eq!(bundle(&cold), before);
	assert_eq!(cold.snapshot().unwrap().unknown_count(), 3);
	let unchanged = bundle(&cold);
	assert!(restore(
		&reconstructed,
		receipt["checkpoint_id"].as_str().unwrap(),
		&cold
	)
	.is_err());
	assert_eq!(bundle(&cold), unchanged);
}

#[test]
fn first_origin_changes_checkpoint_identity_and_round_trips_both_wire_orders() {
	let (_temp, scope) = environment();
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/service-reference-r1.json"
	))
	.unwrap();
	let record = fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.find(|case| case["name"] == "rotation-signers-default")
		.unwrap()["expected"]
		.clone();
	let mut ids = Vec::new();
	let mut wires = Vec::new();
	for (first, later) in [
		(
			RecordOrigin::ApkToolDerived,
			RecordOrigin::AnalysisViewToolDerived,
		),
		(
			RecordOrigin::AnalysisViewToolDerived,
			RecordOrigin::ApkToolDerived,
		),
	] {
		let session = EvidenceSession::default();
		session.record_with_origin(record.clone(), first).unwrap();
		session.record_with_origin(record.clone(), later).unwrap();
		let wire = bundle(&session);
		let saved = save(&scope, &session);
		let id = saved["checkpoint_id"].as_str().unwrap().to_owned();
		let cold = EvidenceSession::default();
		restore(&scope, &id, &cold).unwrap();
		assert_eq!(bundle(&cold), wire);
		ids.push(id);
		wires.push(wire);
	}
	assert_ne!(
		ids[0], ids[1],
		"retention sidecar must participate in immutable identity"
	);
	assert_ne!(
		wires[0], wires[1],
		"the independent frozen origins have observably different key order"
	);
}

#[test]
fn owner_policy_and_current_session_are_rechecked_without_cross_session_loading() {
	let (_temp, scope) = environment();
	let source = imported(IMPORT);
	let id = save(&scope, &source)["checkpoint_id"]
		.as_str()
		.unwrap()
		.to_owned();
	for different in [
		Scope {
			owner: "c".repeat(64),
			..scope.clone()
		},
		Scope {
			policy: "d".repeat(64),
			..scope.clone()
		},
	] {
		let cold = EvidenceSession::default();
		assert!(restore(&different, &id, &cold).is_err());
		assert_eq!(cold.snapshot().unwrap().record_count(), 0);
		assert_eq!(listing(&different, 0, 16, None).unwrap()["total"], 0);
	}
	let before = bundle(&source);
	assert!(restore(&scope, &id, &source).is_err());
	assert_eq!(bundle(&source), before);
	let other_empty = EvidenceSession::default();
	assert_eq!(other_empty.snapshot().unwrap().record_count(), 0);
}

fn mutate_rebind(scope: &Scope, id: &str, edit: impl FnOnce(&mut Value, &mut Value)) -> String {
	let old = directory(scope, id);
	let mut manifest: Manifest =
		serde_json::from_slice(&fs::read(old.join("manifest.json")).unwrap()).unwrap();
	let mut body: Value =
		serde_json::from_slice(&fs::read(old.join("bundle.json")).unwrap()).unwrap();
	let mut sidecar: Value =
		serde_json::from_slice(&fs::read(old.join("retention.json")).unwrap()).unwrap();
	edit(&mut body, &mut sidecar);
	let token = CancellationToken::new();
	let body_bytes = encode(&body, MAX_BUNDLE_BYTES, &token).unwrap();
	let sidecar_bytes = encode(&sidecar, MAX_SIDECAR_BYTES, &token).unwrap();
	manifest.bundle_sha256 = hash(&body_bytes);
	manifest.bundle_bytes = body_bytes.len();
	manifest.retention_sha256 = hash(&sidecar_bytes);
	manifest.retention_bytes = sidecar_bytes.len();
	manifest.records = body["records"].as_array().unwrap().len();
	manifest.unknown_revisions = body["unknowns"].as_array().unwrap().len();
	fs::write(old.join("bundle.json"), body_bytes).unwrap();
	fs::write(old.join("retention.json"), sidecar_bytes).unwrap();
	fs::write(old.join("manifest.json"), manifest.bytes(&token).unwrap()).unwrap();
	let new_id = manifest.id(&token).unwrap();
	if new_id != id {
		fs::rename(old, directory(scope, &new_id)).unwrap();
	}
	new_id
}

#[test]
fn recomputed_file_hashes_do_not_bypass_complete_sidecar_or_unknown_authentication() {
	for defect in 0..4 {
		let (_temp, scope) = environment();
		let id = save(&scope, &imported(IMPORT))["checkpoint_id"]
			.as_str()
			.unwrap()
			.to_owned();
		let changed = mutate_rebind(&scope, &id, |body, sidecar| match defect {
			0 => {
				sidecar["records"][0]["imported_order"][0]["keys"] = json!([]);
			}
			1 => {
				sidecar["records"][0]
					.as_object_mut()
					.unwrap()
					.remove("has_imported_order");
			}
			2 => {
				sidecar["records"][0]["ignored"] = json!(true);
			}
			_ => {
				body["unknowns"].as_array_mut().unwrap().remove(0);
			}
		});
		assert_ne!(changed, id);
		let cold = EvidenceSession::default();
		assert!(restore(&scope, &changed, &cold).is_err(), "defect {defect}");
		assert_eq!(cold.snapshot().unwrap().record_count(), 0);
		assert_eq!(cold.snapshot().unwrap().unknown_count(), 0);
		assert!(listing(&scope, 0, 1, None).is_err());
	}
}

#[test]
fn sidecar_and_recomputed_manifest_cannot_keep_the_old_checkpoint_id() {
	let (_temp, scope) = environment();
	let id = save(&scope, &imported(IMPORT))["checkpoint_id"]
		.as_str()
		.unwrap()
		.to_owned();
	let changed = mutate_rebind(&scope, &id, |_body, sidecar| {
		sidecar["records"][0]["imported_order"][0]["keys"] = json!([]);
	});
	fs::rename(directory(&scope, &changed), directory(&scope, &id)).unwrap();
	let cold = EvidenceSession::default();
	let error = restore(&scope, &id, &cold).unwrap_err().to_string();
	assert!(error.contains("identity"), "{error}");
}

#[test]
fn native_origin_requires_nested_producer_order_after_complete_rehashing() {
	let (_temp, scope) = environment();
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/service-reference-r1.json"
	))
	.unwrap();
	let mut record = fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.find(|case| case["name"] == "rotation-signers-default")
		.unwrap()["expected"]
		.clone();
	// The public Evidence parameter schema accepts free JSON. The native
	// producer has no authoritative order for this additional nested member.
	record["parameters"]["opaque_extension"] = json!({"z":1,"a":{"nested":true}});
	let semantic = rea_evidence::semantic_record_content(&record).unwrap();
	record["evidence_id"] = json!(format!(
		"ev_{}",
		hash(&encode(&semantic, MAX_BUNDLE_BYTES, &CancellationToken::new()).unwrap())
	));
	assert!(
		RecordOrder::new(&record, RecordOrigin::ApkToolDerived)
			.keys(&[], record.as_object().unwrap())
			.is_ok(),
		"root-only validation must accept this regression's record"
	);
	let session = EvidenceSession::default();
	session
		.record_with_origin(record, RecordOrigin::Unknown)
		.unwrap();
	let id = save(&scope, &session)["checkpoint_id"]
		.as_str()
		.unwrap()
		.to_owned();
	let changed = mutate_rebind(&scope, &id, |_body, sidecar| {
		sidecar["records"][0]["origin"] = json!("apk-tool-derived");
	});
	assert_ne!(id, changed);
	let cold = EvidenceSession::default();
	let error = restore(&scope, &changed, &cold).unwrap_err();
	assert!(
		format!("{error:#}").contains("native producer order is incomplete"),
		"{error:#}"
	);
	assert_eq!(cold.snapshot().unwrap().record_count(), 0);
	assert!(listing(&scope, 0, 1, None).is_err());
}

#[test]
fn snapshot_enforces_record_and_unknown_revision_budgets_before_capture() {
	let session = imported(IMPORT);
	let token = CancellationToken::new();
	assert!(session
		.checkpoint_snapshot(2, MAX_UNKNOWN_REVISIONS, &token)
		.is_err());
	assert!(session.checkpoint_snapshot(MAX_RECORDS, 2, &token).is_err());
	assert_eq!(
		session.checkpoint_snapshot(3, 3, &token).unwrap().counts(),
		(3, 3)
	);
	assert_eq!(session.snapshot().unwrap().record_count(), 3);
	assert_eq!(session.snapshot().unwrap().unknown_count(), 3);
	token.cancel();
	assert!(session
		.checkpoint_snapshot(MAX_RECORDS, MAX_UNKNOWN_REVISIONS, &token)
		.is_err());
}

#[test]
fn catalog_pagination_detects_growth_damage_and_changed_scope() {
	let (_temp, scope) = environment();
	let source = imported(IMPORT);
	let id = save(&scope, &source)["checkpoint_id"]
		.as_str()
		.unwrap()
		.to_owned();
	let first = listing(&scope, 0, 1, None).unwrap();
	assert_eq!(first["total"], 1);
	assert!(listing(&scope, 1, 1, None).is_err());
	save(&scope, &EvidenceSession::default());
	assert!(listing(
		&scope,
		1,
		1,
		Some(first["catalog_sha256"].as_str().unwrap().into())
	)
	.is_err());
	let fresh = listing(&scope, 0, 1, None).unwrap();
	assert_eq!(fresh["total"], 2);
	let expected = fresh["catalog_sha256"].as_str().unwrap().to_owned();
	let second = listing(&scope, 1, 1, Some(expected.clone())).unwrap();
	assert_eq!(second["catalog_sha256"], expected);
	assert_eq!(second["returned"], 1);
	assert_eq!(second["exhausted"], true);
	assert_ne!(
		second["checkpoints"][0]["checkpoint_id"],
		fresh["checkpoints"][0]["checkpoint_id"]
	);
	assert!(listing(
		&Scope {
			policy: "c".repeat(64),
			..scope.clone()
		},
		1,
		1,
		Some(expected.clone())
	)
	.is_err());
	fs::write(directory(&scope, &id).join("retention.json"), b"{}").unwrap();
	assert!(listing(&scope, 1, 1, Some(expected)).is_err());
}

#[test]
fn recovered_private_inode_rules_and_incomplete_staging_are_enforced() {
	for defect in 0..3 {
		let (_temp, scope) = environment();
		let id = save(&scope, &imported(IMPORT))["checkpoint_id"]
			.as_str()
			.unwrap()
			.to_owned();
		let path = directory(&scope, &id).join("retention.json");
		match defect {
			0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap(),
			1 => fs::hard_link(&path, scope.state_dir.join("linked-sidecar")).unwrap(),
			_ => {
				let bytes = fs::read(&path).unwrap();
				let other = scope.state_dir.join("other-sidecar");
				fs::write(&other, bytes).unwrap();
				fs::remove_file(&path).unwrap();
				symlink(other, &path).unwrap();
			}
		}
		assert!(restore(&scope, &id, &EvidenceSession::default()).is_err());
	}
	let (_temp, scope) = environment();
	let token = CancellationToken::new();
	let store = store::Store::open(&scope, true, true, &token)
		.unwrap()
		.unwrap();
	for index in 0..MAX_CHECKPOINTS {
		let path = scope
			.state_dir
			.join(ROOT_NAME)
			.join(format!(".stage-orphan-{index}"));
		fs::create_dir(&path).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
	}
	assert!(store.admit_quota(1).is_err());
	drop(store);
	assert_eq!(listing(&scope, 0, 16, None).unwrap()["total"], 0);
	assert!(checkpoint_at(&scope, &EvidenceSession::default(), &token, &|_| Ok(())).is_err());
}

#[test]
fn recovered_staging_bytes_consume_quota_before_any_payload_read() {
	let (_temp, scope) = environment();
	drop(
		store::Store::open(&scope, true, true, &CancellationToken::new())
			.unwrap()
			.unwrap(),
	);
	let stage = scope.state_dir.join(ROOT_NAME).join(".stage-over-budget");
	private_dir(&stage);
	let path = stage.join("bundle.json");
	private_bytes(&path, b"");
	fs::OpenOptions::new()
		.write(true)
		.open(path)
		.unwrap()
		.set_len(MAX_STORE_BYTES + 1)
		.unwrap();
	let error = listing(&scope, 0, 1, None).unwrap_err();
	assert!(
		error.to_string().contains("store byte budget exhausted"),
		"{error:#}"
	);
	assert!(checkpoint_at(
		&scope,
		&EvidenceSession::default(),
		&CancellationToken::new(),
		&|_| Ok(())
	)
	.is_err());
}

#[test]
fn after_rename_failure_is_reconciled_by_identical_create_only_request() {
	let (_temp, scope) = environment();
	let session = imported(IMPORT);
	assert!(
		checkpoint_at(&scope, &session, &CancellationToken::new(), &|phase| {
			if phase == store::CommitPhase::BeforeParentSync {
				anyhow::bail!("injected loss before parent sync");
			}
			Ok(())
		})
		.is_err()
	);
	let entries: Vec<_> = fs::read_dir(scope.state_dir.join(ROOT_NAME))
		.unwrap()
		.map(|entry| entry.unwrap().file_name())
		.collect();
	assert_eq!(entries.len(), 1);
	let receipt = save(&scope, &session);
	assert_eq!(receipt["reused"], true);
	assert_eq!(receipt["checkpoint_id"], entries[0].to_str().unwrap());
	assert_eq!(receipt["durability"], "file_and_directory_sync_confirmed");
}

fn private_dir(path: &Path) {
	fs::create_dir(path).unwrap();
	fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_bytes(path: &Path, bytes: &[u8]) {
	fs::write(path, bytes).unwrap();
	fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn state_directory_ancestor_sync_failure_cannot_be_skipped_on_retry() {
	for failed_ancestor in [0, 1] {
		let (temp, mut scope) = environment();
		scope.state_dir = temp
			.path()
			.join("new-parent")
			.join("new-child")
			.join("state");
		let parents: Vec<PathBuf> = scope
			.state_dir
			.ancestors()
			.skip(1)
			.map(Path::to_path_buf)
			.collect();
		let token = CancellationToken::new();
		for attempt in 0..2 {
			let observed = Mutex::new(Vec::new());
			let error =
				store::Store::open_with_parent_sync_hook(&scope, true, true, &token, &|parent| {
					observed.lock().unwrap().push(parent.to_path_buf());
					if parent == parents[failed_ancestor].as_path() {
						anyhow::bail!("injected state ancestor durability failure");
					}
					Ok(())
				})
				.err()
				.expect("an unconfirmed state ancestor must refuse store admission");
			assert!(
				format!("{error:#}").contains("injected state ancestor durability failure"),
				"attempt {attempt}: {error:#}"
			);
			assert_eq!(
				observed.lock().unwrap().as_slice(),
				&parents[..=failed_ancestor],
				"retry must not skip directories left by the failed initialization"
			);
			assert!(scope.state_dir.is_dir());
			assert!(!scope.state_dir.join(ROOT_NAME).exists());
		}
		let observed = Mutex::new(Vec::new());
		let store =
			store::Store::open_with_parent_sync_hook(&scope, true, true, &token, &|parent| {
				observed.lock().unwrap().push(parent.to_path_buf());
				Ok(())
			})
			.unwrap()
			.unwrap();
		assert_eq!(*observed.lock().unwrap(), parents);
		assert!(store.names().unwrap().is_empty());
		drop(store);
		let receipt = save(&scope, &imported(IMPORT));
		assert_eq!(receipt["durability"], "file_and_directory_sync_confirmed");
		assert_eq!(listing(&scope, 0, 1, None).unwrap()["total"], 1);
	}
}

#[test]
fn configured_state_replacement_refuses_each_commit_phase_and_preserves_both_namespaces() {
	for selected_phase in [
		store::CommitPhase::BeforeRename,
		store::CommitPhase::BeforeParentSync,
		store::CommitPhase::AfterParentSync,
	] {
		let (temp, scope) = environment();
		let detached = temp.path().join("detached-state");
		let error = checkpoint_at(
			&scope,
			&imported(IMPORT),
			&CancellationToken::new(),
			&|phase| {
				if phase == selected_phase {
					fs::rename(&scope.state_dir, &detached).unwrap();
					private_dir(&scope.state_dir);
					private_bytes(
						&scope.state_dir.join("foreign"),
						b"keep configured replacement",
					);
				}
				Ok(())
			},
		)
		.unwrap_err();
		assert!(
			format!("{error:#}").contains("configured state directory identity changed"),
			"{selected_phase:?}: {error:#}"
		);
		assert_eq!(
			fs::read(scope.state_dir.join("foreign")).unwrap(),
			b"keep configured replacement"
		);
		assert!(!scope.state_dir.join(ROOT_NAME).exists());
		let committed: Vec<_> = fs::read_dir(detached.join(ROOT_NAME))
			.unwrap()
			.map(|entry| entry.unwrap().path())
			.filter(|path| valid_id(path.file_name().unwrap().to_str().unwrap()))
			.collect();
		assert_eq!(
			committed.len(),
			if selected_phase == store::CommitPhase::BeforeRename {
				0
			} else {
				1
			}
		);
		for path in committed {
			assert_eq!(fs::read_dir(&path).unwrap().count(), 3);
			for member in ["bundle.json", "manifest.json", "retention.json"] {
				assert!(path.join(member).is_file(), "{selected_phase:?}: {member}");
			}
		}
		assert_eq!(listing(&scope, 0, 1, None).unwrap()["total"], 0);
		assert!(!scope.state_dir.join(ROOT_NAME).exists());
	}
}

#[test]
fn complete_reads_and_reconciliation_reject_replaced_configured_state() {
	let (temp, scope) = environment();
	let id = save(&scope, &imported(IMPORT))["checkpoint_id"]
		.as_str()
		.unwrap()
		.to_owned();
	let token = CancellationToken::new();
	let store = store::Store::open(&scope, false, false, &token)
		.unwrap()
		.unwrap();
	let mut observed = store.checkpoint(&id).unwrap().unwrap();
	let manifest = read_manifest(&mut observed, &id, &token).unwrap();
	drop(read_payloads(&mut observed, &manifest, &token).unwrap());
	observed.confirm_read().unwrap();
	let detached = temp.path().join("detached-state");
	fs::rename(&scope.state_dir, &detached).unwrap();
	private_dir(&scope.state_dir);
	private_bytes(&scope.state_dir.join("foreign"), b"keep read replacement");
	let error = observed.confirm_read().unwrap_err();
	assert!(
		format!("{error:#}").contains("configured state directory identity changed"),
		"{error:#}"
	);
	assert!(store.confirm_existing().is_err());
	assert!(store.names().is_err());
	assert!(store.checkpoint(&id).is_err());
	assert_eq!(
		fs::read(scope.state_dir.join("foreign")).unwrap(),
		b"keep read replacement"
	);
	assert!(!scope.state_dir.join(ROOT_NAME).exists());
	assert_eq!(
		fs::read_dir(detached.join(ROOT_NAME).join(&id))
			.unwrap()
			.count(),
		3
	);
}

#[test]
fn complete_reads_remain_bound_to_named_directory_and_all_three_member_inodes() {
	for defect in 0..3 {
		let (_temp, scope) = environment();
		let id = save(&scope, &imported(IMPORT))["checkpoint_id"]
			.as_str()
			.unwrap()
			.to_owned();
		let token = CancellationToken::new();
		let store = store::Store::open(&scope, false, false, &token)
			.unwrap()
			.unwrap();
		let mut observed = store.checkpoint(&id).unwrap().unwrap();
		let manifest = read_manifest(&mut observed, &id, &token).unwrap();
		if defect != 2 {
			drop(read_payloads(&mut observed, &manifest, &token).unwrap());
		}
		let path = directory(&scope, &id);
		if defect == 0 {
			fs::rename(&path, scope.state_dir.join("detached-checkpoint")).unwrap();
			private_dir(&path);
			private_bytes(&path.join("foreign"), b"retained");
		} else {
			let member = if defect == 1 {
				"retention.json"
			} else {
				"manifest.json"
			};
			let bytes = fs::read(path.join(member)).unwrap();
			fs::rename(path.join(member), scope.state_dir.join("detached-member")).unwrap();
			private_bytes(&path.join(member), &bytes);
		}
		if defect == 2 {
			assert!(
				read_payloads(&mut observed, &manifest, &token).is_err(),
				"replacing an already read manifest must invalidate the combined observation"
			);
		} else {
			assert!(observed.confirm_read().is_err(), "defect {defect}");
		}
	}
}

#[test]
fn staging_directory_or_member_swap_refuses_commit_and_retains_foreign_inodes() {
	for directory_swap in [true, false] {
		let (_temp, scope) = environment();
		let selected = Mutex::new(None::<PathBuf>);
		let error = checkpoint_at(
			&scope,
			&imported(IMPORT),
			&CancellationToken::new(),
			&|phase| {
				if phase == store::CommitPhase::BeforeRename {
					let path = fs::read_dir(scope.state_dir.join(ROOT_NAME))
						.unwrap()
						.map(|entry| entry.unwrap().path())
						.find(|path| {
							path.file_name()
								.unwrap()
								.to_str()
								.unwrap()
								.starts_with(".stage-")
						})
						.unwrap();
					if directory_swap {
						fs::rename(&path, scope.state_dir.join("detached-stage")).unwrap();
						private_dir(&path);
						private_bytes(&path.join("foreign"), b"do not unlink");
					} else {
						let bytes = fs::read(path.join("retention.json")).unwrap();
						fs::rename(
							path.join("retention.json"),
							scope.state_dir.join("detached-sidecar"),
						)
						.unwrap();
						private_bytes(&path.join("retention.json"), &bytes);
					}
					*selected.lock().unwrap() = Some(path);
				}
				Ok(())
			},
		)
		.unwrap_err();
		assert!(
			format!("{error:#}").contains("cleanup is incomplete"),
			"{error:#}"
		);
		let path = selected.lock().unwrap().clone().unwrap();
		if directory_swap {
			assert_eq!(fs::read(path.join("foreign")).unwrap(), b"do not unlink");
			assert_eq!(
				fs::read_dir(scope.state_dir.join("detached-stage"))
					.unwrap()
					.count(),
				3
			);
		} else {
			assert!(path.join("retention.json").is_file());
			assert!(path.join("bundle.json").is_file());
			assert!(path.join("manifest.json").is_file());
			assert!(scope.state_dir.join("detached-sidecar").is_file());
		}
		assert!(fs::read_dir(scope.state_dir.join(ROOT_NAME))
			.unwrap()
			.all(|entry| !valid_id(entry.unwrap().file_name().to_str().unwrap())));
		assert_eq!(listing(&scope, 0, 1, None).unwrap()["total"], 0);
	}
}

#[test]
fn published_directory_replacement_never_gets_a_confirmed_durable_receipt() {
	for selected_phase in [
		store::CommitPhase::BeforeParentSync,
		store::CommitPhase::AfterParentSync,
	] {
		let (_temp, scope) = environment();
		let selected = Mutex::new(None::<PathBuf>);
		assert!(checkpoint_at(
			&scope,
			&imported(IMPORT),
			&CancellationToken::new(),
			&|phase| {
				if phase == selected_phase {
					let path = fs::read_dir(scope.state_dir.join(ROOT_NAME))
						.unwrap()
						.map(|entry| entry.unwrap().path())
						.find(|path| valid_id(path.file_name().unwrap().to_str().unwrap()))
						.unwrap();
					fs::rename(&path, scope.state_dir.join("detached-published")).unwrap();
					private_dir(&path);
					private_bytes(&path.join("foreign"), b"retain this foreign directory");
					*selected.lock().unwrap() = Some(path);
				}
				Ok(())
			}
		)
		.is_err());
		let path = selected.lock().unwrap().clone().unwrap();
		assert_eq!(
			fs::read(path.join("foreign")).unwrap(),
			b"retain this foreign directory"
		);
		assert_eq!(
			fs::read_dir(scope.state_dir.join("detached-published"))
				.unwrap()
				.count(),
			3
		);
	}
}

#[test]
fn unresumable_native_token_budget_is_refused_before_store_creation() {
	let (_temp, scope) = environment();
	let original: Value = serde_json::from_slice(IMPORT).unwrap();
	let mut record = original["records"][0].clone();
	record["normalized_result"] = json!({"large":"x".repeat(16 * 1024 * 1024 + 1)});
	let semantic = rea_evidence::semantic_record_content(&record).unwrap();
	let encoded = encode(&semantic, MAX_BUNDLE_BYTES, &CancellationToken::new()).unwrap();
	record["evidence_id"] = json!(format!("ev_{}", hash(&encoded)));
	let session = EvidenceSession::default();
	session
		.record_with_origin(record, RecordOrigin::Unknown)
		.unwrap();
	assert!(checkpoint_at(&scope, &session, &CancellationToken::new(), &|_| Ok(())).is_err());
	assert_eq!(session.snapshot().unwrap().record_count(), 1);
	assert!(!scope.state_dir.join(ROOT_NAME).exists());
}

#[test]
fn canonical_bundle_depth_overrun_is_refused_before_store_creation() {
	let (_temp, scope) = environment();
	let original: Value = serde_json::from_slice(IMPORT).unwrap();
	let mut record = original["records"][0].clone();
	let mut nested = json!(0);
	for _ in 0..120 {
		nested = Value::Array(vec![nested]);
	}
	record["normalized_result"] = nested;
	let semantic = rea_evidence::semantic_record_content(&record).unwrap();
	record["evidence_id"] = json!(format!(
		"ev_{}",
		hash(&encode(&semantic, MAX_BUNDLE_BYTES, &CancellationToken::new()).unwrap())
	));
	let session = EvidenceSession::default();
	session
		.record_with_origin(record, RecordOrigin::Unknown)
		.unwrap();
	assert!(checkpoint_at(&scope, &session, &CancellationToken::new(), &|_| Ok(())).is_err());
	assert_eq!(session.snapshot().unwrap().record_count(), 1);
	assert!(!scope.state_dir.join(ROOT_NAME).exists());
}

struct DropProbe(Arc<AtomicBool>);
impl Drop for DropProbe {
	fn drop(&mut self) {
		self.0.store(true, Ordering::SeqCst);
	}
}

fn lock_available(path: &Path) -> bool {
	let file = fs::File::open(path).unwrap();
	let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
	if result == 0 {
		unsafe {
			libc::flock(file.as_raw_fd(), libc::LOCK_UN);
		}
	}
	result == 0
}

#[tokio::test]
async fn aborted_waiter_keeps_admission_and_real_store_lock_through_commit() {
	for phase in [
		store::CommitPhase::BeforeRename,
		store::CommitPhase::BeforeParentSync,
	] {
		let (_temp, scope) = environment();
		let session = imported(IMPORT);
		let released = Arc::new(AtomicBool::new(false));
		let probe = DropProbe(Arc::clone(&released));
		let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
		let entered_tx = Mutex::new(Some(entered_tx));
		let (release_tx, release_rx) = std::sync::mpsc::channel();
		let release_rx = Mutex::new(release_rx);
		let owned_scope = scope.clone();
		let task = tokio::spawn(owned(CancellationToken::new(), probe, move |stop| {
			checkpoint_at(&owned_scope, &session, stop, &|current| {
				if current == phase {
					if let Some(tx) = entered_tx.lock().unwrap().take() {
						let _ = tx.send(());
					}
					release_rx
						.lock()
						.unwrap()
						.recv_timeout(Duration::from_secs(5))
						.context("test commit gate was not released")?;
				}
				Ok(())
			})
		}));
		tokio::time::timeout(Duration::from_secs(5), entered_rx)
			.await
			.unwrap()
			.unwrap();
		task.abort();
		assert!(task.await.unwrap_err().is_cancelled());
		assert!(!released.load(Ordering::SeqCst));
		assert!(!lock_available(&scope.state_dir.join(ROOT_NAME)));
		release_tx.send(()).unwrap();
		tokio::time::timeout(Duration::from_secs(5), async {
			while !released.load(Ordering::SeqCst) {
				tokio::time::sleep(Duration::from_millis(5)).await;
			}
		})
		.await
		.unwrap();
		assert!(lock_available(&scope.state_dir.join(ROOT_NAME)));
		assert_eq!(
			listing(&scope, 0, 16, None).unwrap()["total"],
			if phase == store::CommitPhase::BeforeRename {
				0
			} else {
				1
			}
		);
	}
}
