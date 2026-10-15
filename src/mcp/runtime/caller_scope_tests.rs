// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Trusted extension, reconnect, authority-change and private credential file regressions.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn parts(token: Option<&[u8]>) -> axum::http::request::Parts {
	let (mut parts, _) = axum::http::Request::new(()).into_parts();
	if let Some(token) = token {
		parts
			.extensions
			.insert(AuthenticatedOperatorScope::from_verified_token(token));
	}
	parts
}
#[test]
fn same_verified_credential_has_stable_private_scope_across_native_sessions() {
	let a = parts(Some(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
	let b = parts(Some(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
	let old = SessionOwnerBinding::default()
		.resolve_parts(Some(&a), None)
		.unwrap();
	let new = SessionOwnerBinding::default()
		.resolve_parts(Some(&b), Some(&"b".repeat(64)))
		.unwrap();
	assert_eq!(old, new);
	assert!(old.authenticated);
	let response = old
		.annotate(
			r#"{"requests":[],"retention":{"per_session":128}}"#.into(),
			false,
		)
		.unwrap();
	let value: Value = serde_json::from_str(&response).unwrap();
	assert_eq!(
		value["ownership_scope"],
		"authenticated_private_operator_credential"
	);
	assert_eq!(value["cross_session_resume"], true);
	assert_eq!(value["authenticated_chatgpt_caller_isolation"], false);
	assert_eq!(value["retention"]["per_owner"], 128);
	assert!(!response.contains(old.owner()));
	assert!(!format!("{old:?}").contains(old.owner()));
	assert!(
		!format!("{:?}", a.extensions.get::<AuthenticatedOperatorScope>()).contains(old.owner())
	);
}
#[test]
fn session_binding_refuses_different_credential_without_mutating_its_owner() {
	let binding = SessionOwnerBinding::default();
	let a = parts(Some(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
	let b = parts(Some(b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
	let owner = binding.resolve_parts(Some(&a), None).unwrap();
	assert!(binding.resolve_parts(Some(&b), None).is_err());
	assert_eq!(binding.resolve_parts(Some(&a), None).unwrap(), owner);
	assert_ne!(
		SessionOwnerBinding::default()
			.resolve_parts(Some(&b), None)
			.unwrap(),
		owner
	);
}
#[test]
fn http_headers_without_trusted_extension_cannot_spoof_or_use_stdio_fallback() {
	let mut forged = parts(None);
	for name in ["x-hepta-runtime-token", "x-hepta-caller", "mcp-session-id"] {
		forged
			.headers
			.insert(name, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap());
	}
	assert!(SessionOwnerBinding::default()
		.resolve_parts(Some(&forged), Some(&"a".repeat(64)))
		.is_err());
}
#[test]
fn stdio_retains_random_native_session_ownership_and_no_secure_resume_claim() {
	let a = SessionOwnerBinding::default()
		.resolve_parts(None, Some(&"a".repeat(64)))
		.unwrap();
	let b = SessionOwnerBinding::default()
		.resolve_parts(None, Some(&"b".repeat(64)))
		.unwrap();
	assert_ne!(a, b);
	let value: Value =
		serde_json::from_str(&a.annotate(r#"{"searches":[]}"#.into(), true).unwrap()).unwrap();
	assert_eq!(value["ownership_scope"], "native_mcp_session_only");
	assert_eq!(value["credential_metadata_resume"], false);
	assert_eq!(value["session_resume_after_restart"], false);
	assert!(SessionOwnerBinding::default()
		.resolve_parts(None, None)
		.is_err());
}
#[test]
fn token_descriptor_requires_private_owned_single_link_regular_file() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("token");
	std::fs::write(&path, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n").unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	assert_eq!(
		read_private_token(&path).unwrap(),
		b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	);
	for mode in [0o640, 0o604, 0o700, 0o400, 0o660] {
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
		assert!(read_private_token(&path).is_err(), "{mode:o}");
	}
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let alias = root.path().join("alias");
	symlink(&path, &alias).unwrap();
	assert!(read_private_token(&alias).is_err());
	std::fs::remove_file(&alias).unwrap();
	std::fs::hard_link(&path, &alias).unwrap();
	assert!(read_private_token(&path).is_err());
	assert!(read_private_token(root.path()).is_err());
}
#[test]
fn token_length_and_ascii_header_contract_are_checked_before_service_start() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("token");
	for token in [
		vec![b'a'; 31],
		vec![b'a'; 4097],
		vec![0xff; 32],
		vec![b' '; 32],
		vec![b'\n'; 32],
	] {
		std::fs::write(&path, token).unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
		assert!(read_private_token(&path).is_err());
	}
}

#[test]
fn exact_wire_cap_refuses_oversized_reads_but_retains_post_effect_identity() {
	let owner = SessionOwnerBinding::default()
		.resolve_parts(
			Some(&parts(Some(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))),
			None,
		)
		.unwrap();
	let id = "c".repeat(64);
	let original = serde_json::to_string(
		&json!({"search":{"search_id":id,"host":"main","state":"running"},
		"stop_requested":true,"excess": "x".repeat(65536)}),
	)
	.unwrap();
	let error = owner
		.annotate(original.clone(), true)
		.unwrap_err()
		.to_string();
	assert!(error.contains("64 KiB") && error.contains("reduce result page limit"));
	let retained = owner.annotate_search_effect(original);
	let value: Value = serde_json::from_str(&retained).unwrap();
	assert_eq!(value["search"]["search_id"], id);
	assert_eq!(value["search"]["state"], "running");
	assert_eq!(value["stop_requested"], true);
	assert_eq!(value["automatic_retry"], false);
	assert_eq!(
		value["scope_annotation_status"],
		"unavailable_after_effect_identity_retained"
	);
	let wire =
		rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(&retained)]);
	assert!(serde_json::to_vec(&wire).unwrap().len() < 65536);
}
