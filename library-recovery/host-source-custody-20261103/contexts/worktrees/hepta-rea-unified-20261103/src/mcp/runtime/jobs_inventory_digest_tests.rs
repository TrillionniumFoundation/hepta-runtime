// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Preserve existing inventory snapshots, wire responses and restart cursors.

use super::*;

fn original_digest(rows: &[Value], host: Option<&str>, namespace: &str) -> String {
	// This is the pre-streaming binding. Keep it independent of the borrowed
	// serializer so a field-order, escaping or null-handling change is visible.
	let bytes = serde_json::to_vec(&json!({
		"namespace": namespace, "host": host, "rows": rows,
	}))
	.unwrap();
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn rows(count: usize) -> Vec<Value> {
	(0..count)
		.map(|index| {
			json!({
				"launch_state": format!("line\n\t\"\\控制-{}", "é".repeat(index % 97)),
				"id": format!("1a20-{index:06x}-1"),
				"host": if index % 2 == 0 { "main" } else { "mac" },
				"execution_mode": if index % 3 == 0 { "isolated" } else { "operator" },
				"created_unix_ms": u64::MAX - index as u64,
			})
		})
		.collect()
}

#[test]
fn streamed_binding_matches_original_for_empty_large_and_escaped_inventories() {
	for count in [0, 1, 128, 4096] {
		let rows = rows(count);
		for host in [None, Some("main"), Some("escaped-\"\\\n-主机")] {
			for namespace in ["", "private-state", "/tmp/控制\n\"\\/state"] {
				assert_eq!(
					inventory_snapshot_digest(&rows, host, namespace).unwrap(),
					original_digest(&rows, host, namespace),
					"count={count}, host={host:?}, namespace={namespace:?}",
				);
			}
		}
	}
}

#[test]
fn original_cursor_resumes_with_identical_page_bytes_and_binding_checks() {
	let rows = rows(257);
	let namespace = "/tmp/old-controller-state";
	let digest = original_digest(&rows, Some("main"), namespace);
	let mut params = ProcessListPageParams {
		host: Some("main".into()),
		cursor: Some(format!("{digest}:{}", rows[127]["id"].as_str().unwrap())),
		limit: Some(17),
	};
	let expected = serde_json::to_string(&json!({
		"jobs": &rows[128..145], "total": 257,
		"next_cursor": format!("{digest}:{}", rows[144]["id"].as_str().unwrap()),
		"has_more": true, "inventory_complete": false, "snapshot_sha256": digest,
		"status_authoritative": false, "snapshot_semantics": "registry_metadata_at_observation",
	}))
	.unwrap();
	assert_eq!(page_job_rows(&rows, &params, namespace).unwrap(), expected);
	assert!(page_job_rows(&rows, &params, "/tmp/different-state").is_err());
	params.host = None;
	assert!(page_job_rows(&rows, &params, namespace).is_err());
	params.host = Some("main".into());
	let mut changed = rows.clone();
	changed[256]["launch_state"] = json!("pending");
	assert!(page_job_rows(&changed, &params, namespace).is_err());
}

#[test]
fn original_digest_is_preserved_when_wire_budget_reduces_the_page() {
	let mut rows = rows(3);
	for row in &mut rows {
		row["launch_state"] = json!("x".repeat(24 * 1024));
	}
	let namespace = "wire-budget-source";
	let digest = original_digest(&rows, None, namespace);
	let params = ProcessListPageParams {
		limit: Some(3),
		..Default::default()
	};
	let text = page_job_rows(&rows, &params, namespace).unwrap();
	let expected = serde_json::to_string(&json!({
		"jobs": &rows[..2], "total": 3,
		"next_cursor": format!("{digest}:{}", rows[1]["id"].as_str().unwrap()),
		"has_more": true, "inventory_complete": false, "snapshot_sha256": digest,
		"status_authoritative": false, "snapshot_semantics": "registry_metadata_at_observation",
	}))
	.unwrap();
	assert_eq!(text, expected);
	let wire = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(text)]);
	assert!(serde_json::to_vec(&wire).unwrap().len() <= 64 * 1024);
}
