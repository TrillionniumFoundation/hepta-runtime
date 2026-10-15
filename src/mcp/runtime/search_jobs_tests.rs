// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Adversarial validation and durable receipt tests for the search lifecycle.
use super::*;

fn params() -> SearchStartParams {
	serde_json::from_value(
		json!({"host":"main","root":"/tmp/workspace","query":"needle","kind":"content"}),
	)
	.unwrap()
}

fn record() -> SearchRecord {
	SearchRecord {
		id: "1".repeat(64),
		owner: "2".repeat(64),
		instance: "3".repeat(64),
		host: "main".into(),
		ssh_target: "localhost".into(),
		remote_state_dir: "/tmp/state".into(),
		created_unix_ms: 1,
		state: "running".into(),
		reason: None,
		request: params(),
	}
}

#[test]
fn identities_are_opaque_unique_and_caller_cannot_supply_owner() {
	let one = new_owner_id().unwrap();
	let two = new_owner_id().unwrap();
	assert!(valid_id(&one));
	assert_ne!(one, two);
	assert!(!valid_id("../owner"));
	assert!(!valid_id(&"A".repeat(64)));
	assert!(
		serde_json::from_value::<SearchRefParams>(json!({"search_id":one,"owner":two})).is_err()
	);
	assert!(serde_json::from_value::<SearchStartParams>(
		json!({"host":"main","root":"/tmp","query":"x","kind":"content","owner":"spoof"})
	)
	.is_err());
}

#[test]
fn validation_bounds_every_caller_resource() {
	let base = params();
	assert!(validate_start(&base).is_ok());
	let mut p = base.clone();
	p.query = "x".repeat(513);
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.query = "bad\nquery".into();
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.root = "/tmp/../outside".into();
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.root = "relative".into();
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.max_results = Some(1001);
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.max_entries = Some(10001);
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.max_bytes = Some(64 * 1024 * 1024 + 1);
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.timeout_seconds = Some(31);
	assert!(validate_start(&p).is_err());
	p = base;
	p.max_results = Some(0);
	assert!(validate_start(&p).is_err());
	assert!(page_limit(Some(0)).is_err());
	assert!(page_limit(Some(33)).is_err());
}

#[test]
fn unfinished_restart_receipt_is_interrupted_without_pid_reattachment() {
	let mut r = record();
	let old = r.instance.clone();
	assert!(!reconcile(&mut r, &old));
	assert!(reconcile(&mut r, &"4".repeat(64)));
	assert_eq!(r.state, "interrupted");
	assert_eq!(
		r.reason.as_deref(),
		Some("controller_restarted_no_session_resume")
	);
	assert!(!reconcile(&mut r, &"5".repeat(64)));
	let mut terminal = record();
	terminal.state = "completed".into();
	assert!(!reconcile(&mut terminal, &"4".repeat(64)));
	assert_eq!(terminal.state, "completed");
}

#[test]
fn abandoned_native_completed_receipt_frees_active_quota_without_exposing_its_owner() {
	let mut r = record();
	assert!(!apply_native_terminal(&mut r, &json!({"state":"running"})));
	assert!(!apply_native_terminal(
		&mut r,
		&json!({"state":"untrusted"})
	));
	assert!(apply_native_terminal(
		&mut r,
		&json!({"state":"completed","reason":null})
	));
	assert!(TERMINAL.contains(&r.state.as_str()));
	assert_eq!(r.owner, "2".repeat(64));
	assert!(!apply_native_terminal(
		&mut r,
		&json!({"state":"interrupted"})
	));
	assert_eq!(r.state, "completed");
}

#[test]
fn outer_mcp_string_escaping_counts_against_fixed_wire_budget() {
	let payload = "\\\"".repeat(MAX_PAGE_BYTES / 5);
	let value = json!({"payload":payload});
	let raw = serde_json::to_string(&value).unwrap();
	assert!(raw.len() < MAX_PAGE_BYTES);
	assert!(wire_size(&raw).unwrap() > MAX_PAGE_BYTES);
	assert!(response(value).is_err());
}

#[tokio::test]
async fn private_receipt_denies_other_session_without_path_details() {
	let temporary = tempfile::tempdir().unwrap();
	let r = record();
	save(temporary.path(), &r).await.unwrap();
	let error = owned(temporary.path(), &"9".repeat(64), &r.id)
		.await
		.unwrap_err()
		.to_string();
	assert_eq!(error, "search unavailable to this session");
	assert!(!error.contains("workspace"));
	assert!(!error.contains("localhost"));
	let error = owned(temporary.path(), &r.owner, &"9".repeat(64))
		.await
		.unwrap_err()
		.to_string();
	assert_eq!(error, "search unavailable to this session");
}

#[tokio::test]
async fn receipts_refuse_symlink_special_files_and_unbounded_serialized_responses() {
	let temporary = tempfile::tempdir().unwrap();
	let r = record();
	save(temporary.path(), &r).await.unwrap();
	let path = temporary.path().join(format!("{}.json", r.id));
	let got = read_record(&path).await.unwrap();
	assert_eq!(got.id, r.id);
	#[cfg(unix)]
	{
		use std::os::unix::fs::symlink;
		let link = temporary.path().join("link.json");
		symlink(&path, &link).unwrap();
		assert!(read_record(&link).await.is_err());
	}
	assert!(response(json!({"payload":"x".repeat(MAX_PAGE_BYTES)})).is_err());
	let empty = serde_json::to_string(&json!({"payload":""})).unwrap();
	let exact_payload = MAX_PAGE_BYTES - wire_size(&empty).unwrap();
	let boundary = json!({"payload":"x".repeat(exact_payload)});
	assert_eq!(
		wire_size(&serde_json::to_string(&boundary).unwrap()).unwrap(),
		MAX_PAGE_BYTES
	);
	assert!(response(boundary).is_ok());
	assert!(response(json!({"payload":"x".repeat(exact_payload + 1)})).is_err());
}

fn effect_ack(record: &SearchRecord, action: &str, state: &str) -> Value {
	let mut value = json!({"search_id":record.id,"action":action,"backend":"native_search_worker","state":state});
	if action == "start" {
		value["snapshot_ready"] = json!(false);
	} else {
		value["stop_requested"] = json!(!TERMINAL.contains(&state));
	}
	value
}

#[tokio::test]
async fn failed_search_intent_never_polls_start_or_stop_dispatch() {
	use std::sync::atomic::{AtomicUsize, Ordering};
	let root = tempfile::tempdir().unwrap();
	let blocked = root.path().join("not-a-directory");
	tokio::fs::write(&blocked, b"must remain untouched")
		.await
		.unwrap();
	let calls = AtomicUsize::new(0);
	let r = record();
	let start = dispatch_search_start(&blocked, r.clone(), async {
		calls.fetch_add(1, Ordering::SeqCst);
		Ok(effect_ack(&r, "start", "running"))
	})
	.await
	.unwrap_err()
	.to_string();
	assert!(start.contains("no start request dispatched"));
	let stop = dispatch_search_stop(&blocked, r.clone(), async {
		calls.fetch_add(1, Ordering::SeqCst);
		Ok(effect_ack(&r, "stop", "running"))
	})
	.await
	.unwrap_err()
	.to_string();
	assert!(stop.contains("no stop request dispatched"));
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	assert_eq!(
		tokio::fs::read(&blocked).await.unwrap(),
		b"must remain untouched"
	);
}

#[tokio::test]
async fn acknowledged_start_save_failure_returns_existing_identity_and_real_observation() {
	let root = tempfile::tempdir().unwrap();
	let directory = root.path().join("state");
	tokio::fs::create_dir(&directory).await.unwrap();
	let retained = root.path().join("retained-intent");
	let marker = root.path().join("accepted-start");
	let mut r = record();
	r.state = "launching".into();
	let ack = effect_ack(&r, "start", "running");
	let result = dispatch_search_start(&directory, r.clone(), async {
		tokio::fs::write(&marker, b"one start accepted")
			.await
			.unwrap();
		tokio::fs::rename(&directory, &retained).await.unwrap();
		tokio::fs::write(&directory, b"publication blocked after effect")
			.await
			.unwrap();
		Ok(ack)
	})
	.await
	.unwrap();
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["search"]["state"], "running");
	assert_eq!(value["observed_state"], "running");
	assert_eq!(value["effect_outcome"], "start_acknowledged");
	assert_eq!(value["automatic_retry"], false);
	assert_eq!(value["metadata_durability_confirmed"], false);
	assert_eq!(
		read_record(&retained.join(format!("{}.json", r.id)))
			.await
			.unwrap()
			.state,
		"launching"
	);
	assert_eq!(
		tokio::fs::read(marker).await.unwrap(),
		b"one start accepted"
	);
}

#[tokio::test]
async fn lost_start_ack_is_structured_unknown_without_relaunch() {
	use std::sync::atomic::{AtomicUsize, Ordering};
	let root = tempfile::tempdir().unwrap();
	let mut r = record();
	r.state = "launching".into();
	let calls = AtomicUsize::new(0);
	let result = dispatch_search_start(root.path(), r.clone(), async {
		calls.fetch_add(1, Ordering::SeqCst);
		Err(anyhow!("SECRET lost start ACK"))
	})
	.await
	.unwrap();
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(calls.load(Ordering::SeqCst), 1);
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["effect_outcome"], "start_unknown");
	assert_eq!(value["outcome"], "unknown");
	assert_eq!(value["automatic_retry"], false);
	assert_eq!(value["metadata_durability_confirmed"], true);
	assert!(!result.contains("SECRET"));
	assert_eq!(
		read_record(&root.path().join(format!("{}.json", r.id)))
			.await
			.unwrap()
			.state,
		"launch_uncertain"
	);
}

#[tokio::test]
async fn delivered_cancel_with_lost_ack_retains_same_identity_and_unconfirmed_outcome() {
	let root = tempfile::tempdir().unwrap();
	let r = record();
	let marker = root.path().join("delivered-cancel");
	let result = dispatch_search_stop(root.path(), r.clone(), async {
		tokio::fs::write(&marker, b"one cancellation marker accepted")
			.await
			.unwrap();
		Err(anyhow!("SECRET acknowledgement lost after cancel"))
	})
	.await
	.unwrap();
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["effect_outcome"], "cancel_unknown");
	assert_eq!(value["outcome"], "unknown");
	assert_eq!(value["observed_state"], "running");
	assert_eq!(value["termination_confirmed"], false);
	assert_eq!(value["automatic_retry"], false);
	assert!(value.get("stop_requested").is_none());
	assert!(!result.contains("SECRET"));
	assert_eq!(
		tokio::fs::read(marker).await.unwrap(),
		b"one cancellation marker accepted"
	);
}

#[tokio::test]
async fn terminal_stop_ack_survives_save_failure_without_becoming_termination_proof() {
	let root = tempfile::tempdir().unwrap();
	let directory = root.path().join("state");
	tokio::fs::create_dir(&directory).await.unwrap();
	let retained = root.path().join("retained-intent");
	let r = record();
	let ack = effect_ack(&r, "stop", "cancelled");
	let result = dispatch_search_stop(&directory, r.clone(), async {
		tokio::fs::rename(&directory, &retained).await.unwrap();
		tokio::fs::write(&directory, b"publication blocked after ACK")
			.await
			.unwrap();
		Ok(ack)
	})
	.await
	.unwrap();
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["search"]["state"], "cancelled");
	assert_eq!(value["observed_state"], "cancelled");
	assert_eq!(value["stop_requested"], false);
	assert_eq!(value["metadata_durability_confirmed"], false);
	assert_eq!(value["termination_confirmed"], false);
	assert_eq!(value["automatic_retry"], false);
	assert_eq!(
		read_record(&retained.join(format!("{}.json", r.id)))
			.await
			.unwrap()
			.state,
		"running"
	);
}

#[tokio::test]
async fn post_rename_directory_sync_failure_preserves_observation_and_unconfirmed_durability() {
	let root = tempfile::tempdir().unwrap();
	let mut r = record();
	let ack = effect_ack(&r, "start", "running");
	let observed = retain_start_effect(&mut r, Ok(ack));
	let persistence = save_with_directory_sync(root.path(), &r, async {
		Err(anyhow!("SECRET directory fsync failed"))
	})
	.await;
	assert!(persistence.is_err());
	assert_eq!(
		read_record(&root.path().join(format!("{}.json", r.id)))
			.await
			.unwrap()
			.state,
		"running"
	);
	let result = retain_search_effect_result(&r, observed, persistence);
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["observed_state"], "running");
	assert_eq!(value["metadata_durability_confirmed"], false);
	assert_eq!(value["automatic_retry"], false);
	assert!(!result.contains("SECRET"));
}

#[test]
fn effect_ack_identity_backend_action_and_flags_must_match() {
	let r = record();
	let mut invalid_starts = vec![
		Value::Null,
		json!([]),
		json!({"state":"running","snapshot_ready":false}),
	];
	let mut invalid_stops = vec![
		Value::Null,
		json!({"state":"cancelled","stop_requested":false}),
	];
	for key in ["search_id", "action", "backend"] {
		let mut a = effect_ack(&r, "start", "running");
		a[key] = json!("mismatched");
		invalid_starts.push(a);
		let mut a = effect_ack(&r, "stop", "running");
		a[key] = json!("mismatched");
		invalid_stops.push(a);
	}
	let mut a = effect_ack(&r, "start", "running");
	a["error"] = json!("SECRET contradictory acknowledgement");
	invalid_starts.push(a);
	let mut a = effect_ack(&r, "stop", "running");
	a["error"] = json!("SECRET contradictory acknowledgement");
	invalid_stops.push(a);
	let mut a = effect_ack(&r, "start", "running");
	a["snapshot_ready"] = json!(true);
	invalid_starts.push(a);
	let mut a = effect_ack(&r, "stop", "running");
	a["stop_requested"] = json!(false);
	invalid_stops.push(a);
	let mut a = effect_ack(&r, "stop", "cancelled");
	a["stop_requested"] = json!(true);
	invalid_stops.push(a);
	for native in invalid_starts {
		let mut r = r.clone();
		let value = retain_start_effect(&mut r, Ok(native));
		assert_eq!(value["effect_outcome"], "start_unknown");
		assert_eq!(r.state, "launch_uncertain");
	}
	for native in invalid_stops {
		let mut r = r.clone();
		let value = retain_stop_effect(&mut r, Ok(native));
		assert_eq!(value["effect_outcome"], "cancel_unknown");
		assert_eq!(value["termination_confirmed"], false);
		assert_eq!(r.state, "running");
	}
}

#[test]
fn oversized_effect_response_retains_identity_under_actual_mcp_envelope_cap() {
	let r = record();
	let observed = json!({"effect_outcome":"cancel_requested","observed_state":"running","stop_requested":true,"termination_confirmed":false,"excess":"\\\"".repeat(64*1024)});
	let result =
		retain_search_effect_result(&r, observed, Err(anyhow!("SECRET persistence failure")));
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["effect_outcome"], "cancel_requested");
	assert_eq!(value["stop_requested"], true);
	assert_eq!(value["metadata_durability_confirmed"], false);
	assert_eq!(value["automatic_retry"], false);
	assert!(wire_size(&result).unwrap() < 64 * 1024);
	assert!(!result.contains("SECRET"));
}
