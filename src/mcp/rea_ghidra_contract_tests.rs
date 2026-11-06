// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed Ghidra selector, retained identity and bounded observation regressions.

use super::*;

fn request(operation: StaticOperation, address: Option<&str>) -> ReaStaticRequest {
	ReaStaticRequest {
		profile: "owned_ghidra".into(),
		profile_sha256: "1".repeat(64),
		idempotency_key: "owned-analysis".into(),
		operation,
		artifact_path: "/work/owned".into(),
		artifact_sha256: "2".repeat(64),
		function_address: address.map(str::to_owned),
	}
}

#[test]
fn address_is_an_exact_canonical_entry_not_a_name_range_or_expression() {
	for good in ["0x0", "0x1", "0x401100", "0xffffffffffffffff"] {
		assert!(valid_address(good), "{good}");
	}
	for bad in [
		"",
		"main",
		"401100",
		"0X401100",
		"0x",
		"0x00",
		"0x0401100",
		"0xAB",
		"0x10000000000000000",
		"-0x1",
		"0x1+1",
		"0x1..0x2",
		"0x1\n",
		"ram:0x1",
		"0x1;exec",
	] {
		assert!(!valid_address(bad), "{bad:?}");
	}
}

#[test]
fn only_selected_ghidra_operations_admit_one_address() {
	for operation in [
		StaticOperation::Function,
		StaticOperation::Decompile,
		StaticOperation::Xrefs,
	] {
		validate_selection(
			StaticProvider::Ghidra,
			&request(operation, Some("0x401000")),
		)
		.unwrap();
		assert!(validate_selection(StaticProvider::Ghidra, &request(operation, None)).is_err());
		assert!(validate_selection(
			StaticProvider::GnuReadelf,
			&request(operation, Some("0x401000"))
		)
		.is_err());
	}
	for operation in [
		StaticOperation::Inventory,
		StaticOperation::Functions,
		StaticOperation::Headers,
	] {
		validate_selection(StaticProvider::Ghidra, &request(operation, None)).unwrap();
		assert!(validate_selection(
			StaticProvider::Ghidra,
			&request(operation, Some("0x401000"))
		)
		.is_err());
	}
}

#[test]
fn old_request_serialization_and_inventory_bridge_are_unchanged() {
	let mut original = request(StaticOperation::Inventory, None);
	let encoded = serde_json::to_value(&original).unwrap();
	assert!(encoded.get("function_address").is_none());
	let decoded: ReaStaticRequest = serde_json::from_value(encoded.clone()).unwrap();
	assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
	assert_eq!(
		bridge(StaticOperation::Inventory, None).unwrap(),
		include_str!("rea_ghidra_bridge.java")
	);
	// Pin the historical bytes independently of the selected source file.
	assert_eq!(
		sha256(bridge(StaticOperation::Inventory, None).unwrap().as_bytes()),
		"47de6f614c94983f6042adff41bb188a545599ca5ca4ac249480171ffaedc127"
	);
	original.operation = StaticOperation::Decompile;
	original.function_address = Some("0x401000".into());
	assert_ne!(serde_json::to_value(original).unwrap(), encoded);
	assert_ne!(
		bridge(StaticOperation::Decompile, Some(2)).unwrap(),
		bridge(StaticOperation::Inventory, None).unwrap()
	);
	assert_eq!(
		sha256(
			bridge(StaticOperation::Inventory, Some(2))
				.unwrap()
				.as_bytes()
		),
		"a4d166231a4eade27ae1e403b85718da9729c4d752822e9bf9a7ff7fe37878f4"
	);
	assert_eq!(
		sha256(
			bridge(StaticOperation::Decompile, Some(2))
				.unwrap()
				.as_bytes()
		),
		"1b20b872258f26ba75ac463afd1c35a544f76efd3f0bcc05e29515eb940fdf21"
	);
}

#[test]
fn revision_three_has_separate_fixed_engine_bridges_without_legacy_rebinding() {
	for operation in [
		StaticOperation::Inventory,
		StaticOperation::Functions,
		StaticOperation::Function,
		StaticOperation::Decompile,
		StaticOperation::Xrefs,
	] {
		let source = bridge(operation, Some(3)).unwrap();
		assert!(source.contains("equals(\"12.1.4\")"));
		assert!(source.contains("report.put(\"bridge_revision\",3)"));
		assert!(!source.contains("equals(\"12.2\")"));
		assert_ne!(source, bridge(operation, Some(2)).unwrap());
		assert!(bridge(operation, Some(5)).is_err());
	}
	assert!(bridge(StaticOperation::Sources, Some(3)).is_err());
}

#[test]
fn revision_four_has_new_identity_and_preserves_revision_three_bytes() {
	for (operation, digest) in [
		(
			StaticOperation::Inventory,
			"2d5ee6195f3e080e8645e22da6f100c498809fe93eb6766ad10487d8dd326701",
		),
		(
			StaticOperation::Decompile,
			"c795e179be454b950db6f0ac60e221ed327d646e703aff46e9376d93661a5f4c",
		),
	] {
		let old = bridge(operation, Some(3)).unwrap();
		assert_eq!(sha256(old.as_bytes()), digest);
		let current = bridge(operation, Some(4)).unwrap();
		assert_ne!(current, old);
		assert!(current.contains("report.put(\"bridge_revision\",4)"));
		assert!(current.contains("equals(\"12.1.4\")"));
	}
	let current = bridge(StaticOperation::Decompile, Some(4)).unwrap();
	assert!(current.contains("hepta.rea.ghidra-analysis.v2"));
	assert!(current.contains("getFunctionContaining(requested)"));
	assert!(current.contains("getAddressRanges(true)"));
	assert!(bridge(StaticOperation::Sources, Some(4)).is_err());
}

#[test]
fn bounded_function_rows_require_internal_selected_entry() {
	let row = json!({"entry_address":"0x401000","name":"owned","name_sha256":"3".repeat(64),"external":false});
	function_row(&row, Some("0x401000")).unwrap();
	assert!(function_row(&row, Some("0x401001")).is_err());
	let mut external = row.clone();
	external["external"] = json!(true);
	assert!(function_row(&external, None).is_err());
	let mut bad = row;
	bad["entry_address"] = json!("0x0401000");
	assert!(function_row(&bad, None).is_err());
}
