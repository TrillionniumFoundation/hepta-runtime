// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn installed_runtime_pin_detects_name_replacement_even_with_identical_bytes() {
	let dir = tempfile::tempdir().unwrap();
	let root = tokio::fs::canonicalize(dir.path()).await.unwrap();
	let path = root.join("component");
	tokio::fs::write(&path, b"owned-runtime-component")
		.await
		.unwrap();
	let pinned = pin(
		path.to_str().unwrap(),
		&sha256(b"owned-runtime-component"),
		vec![root.to_str().unwrap().into()],
		Instant::now() + Duration::from_secs(10),
	)
	.await
	.unwrap();
	verify_pin(&pinned).await.unwrap();
	tokio::fs::rename(&path, root.join("original-component"))
		.await
		.unwrap();
	tokio::fs::write(&path, b"owned-runtime-component")
		.await
		.unwrap();
	assert!(verify_pin(&pinned).await.is_err());
}

#[tokio::test]
async fn private_engine_scratch_is_created_with_owner_only_permissions() {
	let root = tempfile::tempdir().unwrap();
	let work = scratch(root.path().to_str().unwrap(), "jadx")
		.await
		.unwrap();
	assert_eq!(
		tokio::fs::metadata(&*work)
			.await
			.unwrap()
			.permissions()
			.mode() & 0o777,
		0o700
	);
	assert_eq!(disk_usage(&work).await.unwrap(), 0);
	assert!(work.finish().await.unwrap());
}
