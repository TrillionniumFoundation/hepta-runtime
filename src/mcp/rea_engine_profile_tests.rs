// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Revision-bound installation coverage and fixed GNU native helper identity.

use super::*;

fn engine(revision: Option<u32>) -> GhidraEngineProfile {
	let (version, release) = release_identity(revision).unwrap();
	GhidraEngineProfile {
		bridge_revision: revision,
		java_home: "/opt/jdk25".into(),
		installation_root: "/opt/ghidra".into(),
		manifest_path: "/work/manifest.json".into(),
		manifest_sha256: "1".repeat(64),
		engine_version: version.into(),
		release_archive_sha256: release.into(),
		runtime_files: BTreeMap::new(),
	}
}

fn manifest(engine: &GhidraEngineProfile) -> InstallationManifest {
	InstallationManifest {
		schema: "hepta.rea.ghidra-installation.v1".into(),
		engine_version: engine.engine_version.clone(),
		release_archive_sha256: engine.release_archive_sha256.clone(),
		files: [
			"Ghidra/application.properties",
			"Ghidra/Framework/Utility/lib/Utility.jar",
			"Ghidra/Features/Base/lib/Base.jar",
		]
		.into_iter()
		.map(|name| (name.into(), "1".repeat(64)))
		.collect(),
	}
}

#[test]
fn revision_four_requires_fixed_gpl_members_without_rebinding_old_manifests() {
	for revision in [None, Some(2), Some(3)] {
		let selected = engine(revision);
		let value = manifest(&selected);
		validate_manifest(&value, &selected).unwrap();
		assert_eq!(installation_subtrees(revision), &["Ghidra"]);
	}
	let selected = engine(Some(4));
	let mut value = manifest(&selected);
	assert!(validate_manifest(&value, &selected).is_err());
	for (path, digest) in GHIDRA_V4_GPL_REQUIRED {
		value.files.insert(path.into(), digest.into());
	}
	validate_manifest(&value, &selected).unwrap();
	assert_eq!(installation_subtrees(Some(4)), &["Ghidra", "GPL"]);
	for (path, _) in GHIDRA_V4_GPL_REQUIRED {
		let mut missing = value.clone();
		missing.files.remove(path);
		assert!(validate_manifest(&missing, &selected).is_err());
		let mut substituted = value.clone();
		substituted.files.insert(path.into(), "0".repeat(64));
		assert!(validate_manifest(&substituted, &selected).is_err());
	}
	let old = engine(Some(3));
	assert!(validate_manifest(&value, &old).is_err());
}

#[test]
fn revision_four_gpl_paths_stay_inside_the_two_explicit_subtrees() {
	let selected = engine(Some(4));
	let mut value = manifest(&selected);
	for (path, digest) in GHIDRA_V4_GPL_REQUIRED {
		value.files.insert(path.into(), digest.into());
	}
	for path in [
		"GPL/../escape",
		"GPL//file",
		"GPL/file:stream",
		"GPL/foo\\bar",
		"support/helper",
		"GPL",
	] {
		let mut bad = value.clone();
		bad.files.insert(path.into(), "1".repeat(64));
		assert!(validate_manifest(&bad, &selected).is_err(), "{path}");
	}
	value
		.files
		.insert("GPL/other/module.dat".into(), "1".repeat(64));
	validate_manifest(&value, &selected).unwrap();
}
