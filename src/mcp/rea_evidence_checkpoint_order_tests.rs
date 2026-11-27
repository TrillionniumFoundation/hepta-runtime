// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Portable object-order checks and Linux parser round trips with duplicate/index keys.

use super::*;
#[cfg(target_os = "linux")]
use crate::mcp::rea_evidence_file::parse_checkpoint_json;
use serde_json::json;
#[cfg(target_os = "linux")]
use tokio_util::sync::CancellationToken;

#[test]
fn numeric_key_checkpoint_round_trip_is_platform_independent() {
	let value = json!({"0":0,"2":2,"4294967294":3,"01":4,"4294967295":5});
	let keys: Vec<String> = ["0", "2", "4294967294", "01", "4294967295"]
		.into_iter()
		.map(str::to_owned)
		.collect();
	let stored = StoredObjectOrder {
		path: Vec::new(),
		keys: keys.clone(),
	};
	let original = ObjectOrder::from_checkpoint_order(&value, vec![stored.clone()]).unwrap();
	assert_eq!(original.keys(&[]), Some(keys));
	let round_trip = original.checkpoint_order(&value, &mut 4096).unwrap();
	let restored = ObjectOrder::from_checkpoint_order(&value, round_trip).unwrap();
	assert_eq!(restored.keys(&[]), original.keys(&[]));
	for (left, right) in [(0, 1), (2, 3)] {
		let mut invalid = stored.clone();
		invalid.keys.swap(left, right);
		assert!(ObjectOrder::from_checkpoint_order(&value, vec![invalid]).is_err());
	}
}

#[cfg(target_os = "linux")]
#[test]
fn physical_numeric_order_and_duplicate_replacement_round_trip() {
	let bytes = br#"{"2":{"discarded":0},"1":1,"z":0,"2":{"b":2,"a":1},"01":3,"4294967295":4}"#;
	let (value, original) = parse_checkpoint_json(bytes, &CancellationToken::new()).unwrap();
	assert_eq!(
		original.keys(&[]).unwrap(),
		["1", "2", "z", "01", "4294967295"]
	);
	assert_eq!(value["2"], json!({"b":2,"a":1}));
	let stored = original
		.checkpoint_order(&value, &mut (1024 * 1024))
		.unwrap();
	let encoded = serde_json::to_vec(&stored).unwrap();
	let restored =
		ObjectOrder::from_checkpoint_order(&value, serde_json::from_slice(&encoded).unwrap())
			.unwrap();
	assert_eq!(restored.keys(&[]), original.keys(&[]));
	assert_eq!(
		restored.keys(&[json!("2")]),
		Some(vec!["b".into(), "a".into()])
	);
}

#[cfg(target_os = "linux")]
#[test]
fn schema_stripped_proto_does_not_invalidate_retained_order() {
	let (mut value, order) = parse_checkpoint_json(
		br#"{"__proto__":{"unused":1},"z":{"b":2,"a":1}}"#,
		&CancellationToken::new(),
	)
	.unwrap();
	value.as_object_mut().unwrap().remove("__proto__");
	let stored = order.checkpoint_order(&value, &mut 4096).unwrap();
	let restored = ObjectOrder::from_checkpoint_order(&value, stored).unwrap();
	assert_eq!(restored.keys(&[]), Some(vec!["z".into()]));
	assert_eq!(
		restored.keys(&[json!("z")]),
		Some(vec!["b".into(), "a".into()])
	);
}

#[cfg(target_os = "linux")]
#[test]
fn every_actual_object_requires_one_complete_unambiguous_sidecar_entry() {
	let (value, order) = parse_checkpoint_json(
		br#"{"1":1,"2":2,"nested":[{"b":2,"a":1}]}"#,
		&CancellationToken::new(),
	)
	.unwrap();
	let stored = order.checkpoint_order(&value, &mut 8192).unwrap();
	let mut missing = stored.clone();
	missing.pop();
	assert!(ObjectOrder::from_checkpoint_order(&value, missing).is_err());
	let mut partial = stored.clone();
	partial[0].keys.pop();
	assert!(ObjectOrder::from_checkpoint_order(&value, partial).is_err());
	let mut duplicate = stored.clone();
	duplicate.push(duplicate[0].clone());
	assert!(ObjectOrder::from_checkpoint_order(&value, duplicate).is_err());
	let mut impossible = stored.clone();
	impossible[0].keys.swap(0, 1);
	assert!(ObjectOrder::from_checkpoint_order(&value, impossible).is_err());
	let mut extra = stored;
	extra.push(StoredObjectOrder {
		path: vec![Part::Key("absent".into())],
		keys: Vec::new(),
	});
	assert!(ObjectOrder::from_checkpoint_order(&value, extra).is_err());
	assert!(serde_json::from_value::<StoredObjectOrder>(
		json!({"path":[],"keys":[],"ignored":true})
	)
	.is_err());
	assert!(order.checkpoint_order(&value, &mut 0).is_err());
}
