// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact GPL inventory, symlink refusal and unchanged classpath admission.

use super::*;

#[tokio::test]
async fn revision_four_inventories_gpl_and_detects_added_or_linked_members() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path();
	tokio::fs::create_dir(path.join("Ghidra")).await.unwrap();
	tokio::fs::write(path.join("Ghidra/core.dat"), b"core")
		.await
		.unwrap();
	let name = path.to_str().unwrap();
	let legacy = file_inventory(name, installation_subtrees(Some(3)))
		.await
		.unwrap();
	assert_eq!(legacy, BTreeSet::from(["Ghidra/core.dat".to_owned()]));
	assert!(file_inventory(name, installation_subtrees(Some(4)))
		.await
		.is_err());
	tokio::fs::create_dir(path.join("GPL")).await.unwrap();
	tokio::fs::write(path.join("GPL/helper"), b"owned")
		.await
		.unwrap();
	let before = file_inventory(name, installation_subtrees(Some(4)))
		.await
		.unwrap();
	assert_eq!(
		before,
		BTreeSet::from(["Ghidra/core.dat".to_owned(), "GPL/helper".to_owned()])
	);
	tokio::fs::write(path.join("GPL/extra"), b"extra")
		.await
		.unwrap();
	assert_ne!(
		file_inventory(name, installation_subtrees(Some(4)))
			.await
			.unwrap(),
		before
	);
	assert_eq!(
		file_inventory(name, installation_subtrees(Some(3)))
			.await
			.unwrap(),
		legacy
	);
	tokio::fs::symlink(path.join("Ghidra/core.dat"), path.join("GPL/linked"))
		.await
		.unwrap();
	assert!(file_inventory(name, installation_subtrees(Some(4)))
		.await
		.is_err());
}

#[tokio::test]
async fn gpl_subtree_root_cannot_be_replaced_by_a_symlink() {
	let root = tempfile::tempdir().unwrap();
	let outside = tempfile::tempdir().unwrap();
	tokio::fs::create_dir(root.path().join("Ghidra"))
		.await
		.unwrap();
	tokio::fs::write(root.path().join("Ghidra/core.dat"), b"core")
		.await
		.unwrap();
	tokio::fs::symlink(outside.path(), root.path().join("GPL"))
		.await
		.unwrap();
	assert!(file_inventory(
		root.path().to_str().unwrap(),
		installation_subtrees(Some(4))
	)
	.await
	.is_err());
}

#[test]
fn admitting_gpl_inventory_does_not_admit_its_jars_to_the_java_classpath() {
	assert_eq!(classpath_priority("GPL/DMG/data/lib/DMG.jar"), None);
	assert_eq!(
		classpath_priority("GPL/Features/custom/lib/extra.jar"),
		None
	);
	assert_eq!(
		classpath_priority("Ghidra/Framework/Utility/lib/Utility.jar"),
		Some(0)
	);
}
