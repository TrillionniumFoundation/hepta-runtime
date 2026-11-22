// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Batch-limit regression and retained single-document defenses.

use serde_json::{json, Value};

#[test]
fn collection_larger_than_single_document_limit_keeps_per_item_guards() {
	let mut input = b"[{\"a\":1},".to_vec();
	input.extend(vec![b' '; 9 * 1024 * 1024]);
	input.extend(b"{\"b\":2}]");
	let values: Vec<Value> = super::batch::parse(&input).unwrap();
	assert_eq!(values, vec![json!({"a":1}), json!({"b":2})]);
	assert!(super::batch::parse::<Value>(br#"[{"a":1,"a":2}]"#).is_err());
	assert!(super::batch::parse::<Value>(br#"[{"a":{"b":1,"b":2}}]"#).is_err());
}

#[test]
fn oversized_items_collections_counts_and_trailing_values_are_rejected() {
	let mut oversized_item = b"[\"".to_vec();
	oversized_item.extend(vec![b'x'; 8 * 1024 * 1024]);
	oversized_item.extend(b"\"]");
	assert!(super::batch::parse::<Value>(&oversized_item).is_err());
	assert!(super::batch::parse::<Value>(&vec![b' '; 32 * 1024 * 1024 + 1]).is_err());
	let excessive = format!("[{}]", vec!["null"; 2049].join(","));
	assert!(super::batch::parse::<Value>(excessive.as_bytes()).is_err());
	assert!(super::batch::parse::<Value>(b"[]").is_err());
	assert!(super::batch::parse::<Value>(b"[null] null").is_err());
	assert!(super::batch::parse::<Value>(b"{}").is_err());
}
