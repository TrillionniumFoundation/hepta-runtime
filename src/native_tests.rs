// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use super::*;

fn request(key: Option<&str>) -> ProcessStartParams {
	serde_json::from_value(serde_json::json!({
		"host": "fixture", "executable": "/usr/bin/true", "idempotency_key": key,
	}))
	.unwrap()
}

#[tokio::test]
async fn missing_or_empty_key_fails_before_runtime_initialization() {
	for key in [None, Some(""), Some(" \t")] {
		let error = execute_or_observe(request(key)).await.unwrap_err();
		assert!(error
			.to_string()
			.contains("original nonempty idempotency key"));
		let error = observe_request(request(key)).await.unwrap_err();
		assert!(error
			.to_string()
			.contains("original nonempty idempotency key"));
	}
}

#[test]
fn key_bound_uses_bytes_and_retains_original_request() {
	let oversized = "a".repeat(257);
	assert!(require_key(&request(Some(&oversized))).is_err());
	let multibyte = "界".repeat(86);
	assert!(require_key(&request(Some(&multibyte))).is_err());
	let original = request(Some("turn-1-op-1"));
	let before = serde_json::to_vec(&original).unwrap();
	require_key(&original).unwrap();
	assert_eq!(serde_json::to_vec(&original).unwrap(), before);
}
