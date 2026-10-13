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
