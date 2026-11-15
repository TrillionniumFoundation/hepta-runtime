// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Refuse shared/unbounded groups and arbitrary filesystem control targets.
use super::*;

#[test]
fn metadata_pressure_requests_only_a_bounded_fraction_of_existing_limit() {
	assert_eq!(
		amount(2048 * MIB, 2000 * MIB, 1800 * MIB, 100 * MIB),
		Some(256 * MIB)
	);
	assert_eq!(
		amount(512 * MIB, 500 * MIB, 450 * MIB, 10 * MIB),
		Some(64 * MIB)
	);
	assert_eq!(
		amount(16 * 1024 * MIB, 16 * 1024 * MIB, 15 * 1024 * MIB, 10 * MIB),
		Some(256 * MIB)
	);
}
#[test]
fn ordinary_file_cache_or_low_pressure_never_requests_reclaim() {
	assert_eq!(amount(128 * MIB, 128 * MIB, 120 * MIB, 0), None);
	assert_eq!(amount(2048 * MIB, 1000 * MIB, 900 * MIB, 0), None);
	assert_eq!(amount(2048 * MIB, 2000 * MIB, 500 * MIB, 100 * MIB), None);
	assert_eq!(amount(2048 * MIB, 2000 * MIB, 1500 * MIB, 600 * MIB), None);
}
#[test]
fn unified_group_path_requires_one_canonical_nonroot_path() {
	assert_eq!(
		group_path("0::/user.slice/service\n"),
		Some("/user.slice/service".into())
	);
	for text in [
		"0::/",
		"0::relative",
		"0::/../x",
		"0::/x/./y",
		"0::/x//y",
		"0::/x\n0::/y",
		"1:memory:/x",
	] {
		assert!(group_path(text).is_none(), "{text}");
	}
}
#[test]
fn dedicated_group_accepts_only_self_and_optional_parent() {
	assert!(dedicated("42\n", 42, 7));
	assert!(dedicated("7\n42\n", 42, 7));
	assert!(dedicated("42\n42\n7\n", 42, 7));
}
#[test]
fn shared_invalid_or_unrelated_membership_is_never_accepted() {
	for procs in ["", "7\n", "42\n8\n", "42\n0\n", "42\n-1\n", "42\nno\n"] {
		assert!(!dedicated(procs, 42, 7), "{procs}");
	}
}
#[test]
fn ordinary_filesystem_descriptor_cannot_be_a_reclaim_controller() {
	let root = tempfile::tempdir().unwrap();
	let file = File::open(root.path()).unwrap();
	assert!(cgroup_filesystem(&file).is_err());
	assert!(open_group("/").is_err());
}
#[test]
fn control_reads_refuse_oversized_values_without_writing_files() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("control");
	let bytes = vec![b'x'; CONTROL_BYTES as usize + 1];
	std::fs::write(&path, &bytes).unwrap();
	assert!(bounded(File::open(&path).unwrap()).is_err());
	assert_eq!(std::fs::read(path).unwrap(), bytes);
}
#[test]
fn required_statistics_never_infer_zero_from_missing_or_invalid_input() {
	assert_eq!(
		statistic("file 12\nslab_reclaimable 42\n", "slab_reclaimable"),
		Some(42)
	);
	for text in [
		"",
		"slab 42",
		"slab_reclaimable bad",
		"slab_reclaimable 42 extra",
	] {
		assert_eq!(statistic(text, "slab_reclaimable"), None);
	}
}
