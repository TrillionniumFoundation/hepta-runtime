// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use super::*;
use serde_json::json;

#[test]
fn session_identity_is_deterministic_and_bound() {
	let first = session_id("fixture-key").unwrap();
	let second = session_id("fixture-key").unwrap();
	assert_eq!(first, second);
	assert!(valid_session(&first));
	assert_ne!(first, session_id("another-key").unwrap());
}

#[test]
fn session_identity_rejects_empty_and_oversized_keys() {
	assert!(session_id("").is_err());
	assert!(session_id(&"x".repeat(257)).is_err());
	assert!(!valid_session("stream-deadbeef"));
}

#[test]
fn prepare_schema_rejects_authority_injection() {
	assert!(serde_json::from_value::<StreamPrepareParams>(json!({
		"idempotency_key":"fixture",
		"application_pids":[123],
		"sudo":true
	}))
	.is_err());
	assert!(serde_json::from_value::<StreamPrepareParams>(json!({
		"idempotency_key":"fixture",
		"application_pids":[123],
		"socket_path":"/tmp/attacker"
	}))
	.is_err());
}

#[test]
fn write_schema_requires_explicit_retry_identity() {
	assert!(serde_json::from_value::<StreamWriteParams>(json!({
		"session_id":format!("stream-{}", "a".repeat(64)),
		"data_base64":"AA=="
	}))
	.is_err());
	assert!(serde_json::from_value::<StreamWriteParams>(json!({
		"session_id":format!("stream-{}", "a".repeat(64)),
		"request_id":"fixture-01",
		"data_base64":"AA=="
	}))
	.is_ok());
}

#[test]
fn read_stream_is_typed() {
	assert!(serde_json::from_value::<StreamReadParams>(json!({
		"session_id":format!("stream-{}", "a".repeat(64)),
		"stream":"stdout"
	}))
	.is_ok());
	assert!(serde_json::from_value::<StreamReadParams>(json!({
		"session_id":format!("stream-{}", "a".repeat(64)),
		"stream":"socket"
	}))
	.is_err());
}
