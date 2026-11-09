// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Focused private startup provenance and publication regressions.

use super::super::{
	claim_controller_state_dir, init_runtime_at, init_runtime_with_private_receipt_at,
	prepare_controller_state_dir,
};
use super::*;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::sync::OnceLock;

fn fixture_bytes(state: &Path) -> Vec<u8> {
	serde_json::to_vec(&serde_json::json!({
		"state_dir": state,
		"controller_workspace_roots": ["/synthetic/private-workspace"],
		"hosts": {"fixture": {
			"ssh_target": "private-fixture-alias",
			"remote_state_dir": "/synthetic/private-remote"
		}}
	}))
	.unwrap()
}

fn loaded_at(root: &Path, state: &Path) -> (PathBuf, Vec<u8>, LoadedRuntimeConfig) {
	let path = root.join("runtime.json");
	let bytes = fixture_bytes(state);
	fs::write(&path, &bytes).unwrap();
	let loaded = LoadedRuntimeConfig::load(&path).unwrap();
	(path, bytes, loaded)
}

fn installed_at(root: &Path) -> (OnceLock<InstalledRuntimeConfig>, OnceLock<ControllerLocks>) {
	let (_, _, loaded) = loaded_at(root, &root.join("state"));
	let (config, provenance) = loaded.into_parts();
	let runtime = OnceLock::new();
	let owner = OnceLock::new();
	init_runtime_at(config, Some(provenance), &runtime, &owner).unwrap();
	(runtime, owner)
}

fn receipt_json(path: &Path) -> serde_json::Value {
	serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn receipt_binds_original_buffer_after_path_replacement_and_normalization() {
	let root = tempfile::tempdir().unwrap();
	let state = root.path().join("intermediate/../state");
	let (path, original, loaded) = loaded_at(root.path(), &state);
	let replacement = root.path().join("replacement.json");
	fs::write(&replacement, fixture_bytes(&root.path().join("other-state"))).unwrap();
	fs::rename(replacement, &path).unwrap();
	assert_ne!(fs::read(&path).unwrap(), original);
	let runtime = OnceLock::new();
	let owner = OnceLock::new();
	let receipt_path = init_runtime_with_private_receipt_at(loaded, &runtime, &owner).unwrap();
	let installed = runtime.get().unwrap();
	let receipt = receipt_json(&receipt_path);
	assert_eq!(receipt["raw_input"]["sha256"], sha256_hex(&original));
	assert_eq!(receipt["raw_input"]["byte_len"], original.len());
	assert_eq!(
		installed.config.state_dir,
		fs::canonicalize(root.path().join("state")).unwrap()
	);
	let installed_bytes = serde_json::to_vec(&installed.config).unwrap();
	assert_eq!(
		receipt["installed_config_sha256"],
		sha256_hex(&installed_bytes)
	);
	assert_ne!(
		receipt["raw_input"]["sha256"],
		receipt["installed_config_sha256"]
	);
	assert_eq!(receipt["stage"], "configuration_initialized");
	assert_eq!(receipt["process"]["pid"], std::process::id());
	assert_eq!(receipt["process"]["euid"], unsafe { libc::geteuid() });
	assert_eq!(
		receipt["controller_owner_file"]["inode"],
		owner.get().unwrap()._owner.metadata().unwrap().ino()
	);
	assert_eq!(
		receipt["controller_legacy_owner_file"]["inode"],
		owner.get().unwrap()._legacy.metadata().unwrap().ino()
	);
	let receipt_bytes = fs::read(&receipt_path).unwrap();
	assert!(receipt_bytes.len() <= 4096);
	assert!(receipt_bytes.ends_with(b"\n"));
	let text = String::from_utf8(receipt_bytes).unwrap();
	for hidden in [
		"private-fixture-alias",
		"/synthetic/private-workspace",
		"/synthetic/private-remote",
		root.path().to_str().unwrap(),
	] {
		assert!(!text.contains(hidden));
	}
	for forbidden in ["ready", "binary_sha256", "service_label", "verified"] {
		assert!(receipt.get(forbidden).is_none());
	}
	assert_eq!(fs::metadata(&receipt_path).unwrap().mode() & 0o7777, 0o600);
	let parent = receipt_path.parent().unwrap();
	assert_eq!(fs::metadata(parent).unwrap().mode() & 0o7777, 0o700);
	assert_eq!(fs::read_dir(parent).unwrap().count(), 1);
}

#[test]
fn input_whitespace_changes_raw_identity_without_changing_existing_policy_identity() {
	let root = tempfile::tempdir().unwrap();
	let (path, compact, first) = loaded_at(root.path(), &root.path().join("state"));
	let value: serde_json::Value = serde_json::from_slice(&compact).unwrap();
	fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
	let second = LoadedRuntimeConfig::load(&path).unwrap();
	let (first_config, first_origin) = first.into_parts();
	let (second_config, second_origin) = second.into_parts();
	assert_ne!(first_origin.sha256, second_origin.sha256);
	let before = serde_json::to_vec(&first_config).unwrap();
	assert_eq!(before, serde_json::to_vec(&second_config).unwrap());
	let plain = InstalledRuntimeConfig::new(first_config.clone());
	let mut qualified = InstalledRuntimeConfig::new(first_config);
	qualified.load_provenance = Some(first_origin);
	assert_eq!(
		plain.policy_digest().unwrap(),
		qualified.policy_digest().unwrap()
	);
	assert_eq!(before, serde_json::to_vec(&qualified.config).unwrap());
	assert!(!String::from_utf8(compact).unwrap().contains("allow_execute"));
	assert!(String::from_utf8(before).unwrap().contains("\"allow_execute\":false"));
}

#[test]
fn invalid_input_has_no_provenance_or_state_effect() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("runtime.json");
	for bytes in [
		b"{".to_vec(),
		br#"{"state_dir":"/synthetic/state","hosts":{}}"#.to_vec(),
		fixture_bytes(Path::new("relative-state")),
	] {
		fs::write(&path, bytes).unwrap();
		assert!(LoadedRuntimeConfig::load(&path).is_err());
	}
	assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn ordinary_in_memory_installation_does_not_gain_file_origin_or_a_receipt() {
	let root = tempfile::tempdir().unwrap();
	let config: RuntimeConfig =
		serde_json::from_slice(&fixture_bytes(&root.path().join("state"))).unwrap();
	let runtime = OnceLock::new();
	let owner = OnceLock::new();
	init_runtime_at(config, None, &runtime, &owner).unwrap();
	let installed = runtime.get().unwrap();
	assert!(installed.load_provenance.is_none());
	assert!(installed.policy_digest.get().is_none());
	assert!(publish_private_receipt(installed, owner.get().unwrap()).is_err());
	assert!(installed.policy_digest.get().is_none());
	assert!(!installed.config.state_dir.join("startup-receipts").exists());
}

#[test]
fn rejected_reinstallation_preserves_original_subject_and_receipt() {
	let root = tempfile::tempdir().unwrap();
	let (_, original, loaded) = loaded_at(root.path(), &root.path().join("state"));
	let runtime = OnceLock::new();
	let owner = OnceLock::new();
	let receipt_path = init_runtime_with_private_receipt_at(loaded, &runtime, &owner).unwrap();
	let receipt_bytes = fs::read(&receipt_path).unwrap();
	let installed = runtime.get().unwrap();
	let original_owner = owner.get().unwrap()._owner.metadata().unwrap().ino();
	let (_, _, rejected) = loaded_at(root.path(), &root.path().join("rejected-state"));
	assert!(init_runtime_with_private_receipt_at(rejected, &runtime, &owner).is_err());
	assert!(std::ptr::eq(installed, runtime.get().unwrap()));
	assert_eq!(
		installed.load_provenance.as_ref().unwrap().sha256,
		sha256_hex(&original)
	);
	assert_eq!(
		owner.get().unwrap()._owner.metadata().unwrap().ino(),
		original_owner
	);
	assert_eq!(fs::read(&receipt_path).unwrap(), receipt_bytes);
	assert_eq!(fs::read_dir(receipt_path.parent().unwrap()).unwrap().count(), 1);
	assert!(!root.path().join("rejected-state/startup-receipts").exists());
}

#[test]
fn failed_owner_acquisition_never_installs_or_publishes() {
	let root = tempfile::tempdir().unwrap();
	let state = prepare_controller_state_dir(&root.path().join("state")).unwrap();
	let _held = claim_controller_state_dir(&state).unwrap();
	let (_, _, loaded) = loaded_at(root.path(), &state);
	let runtime = OnceLock::new();
	let owner = OnceLock::new();
	assert!(init_runtime_with_private_receipt_at(loaded, &runtime, &owner).is_err());
	assert!(runtime.get().is_none());
	assert!(owner.get().is_none());
	assert!(!state.join("startup-receipts").exists());
}

#[test]
fn installation_revalidates_before_publishing() {
	let root = tempfile::tempdir().unwrap();
	let (_, _, mut loaded) = loaded_at(root.path(), &root.path().join("state"));
	// Only this descendant test can mutate the otherwise private wrapper.
	loaded.config.hosts.clear();
	let runtime = OnceLock::new();
	let owner = OnceLock::new();
	assert!(init_runtime_with_private_receipt_at(loaded, &runtime, &owner).is_err());
	assert!(runtime.get().is_none());
	assert!(owner.get().is_none());
	assert!(!root.path().join("state").exists());
}

#[test]
fn failed_second_installation_set_never_publishes_partial_initialization() {
	let root = tempfile::tempdir().unwrap();
	let old_state = prepare_controller_state_dir(&root.path().join("old-owner")).unwrap();
	let owner = OnceLock::new();
	assert!(owner.set(claim_controller_state_dir(&old_state).unwrap()).is_ok());
	let (_, _, loaded) = loaded_at(root.path(), &root.path().join("state"));
	let runtime = OnceLock::new();
	assert!(init_runtime_with_private_receipt_at(loaded, &runtime, &owner).is_err());
	assert!(runtime.get().is_some());
	assert!(!root.path().join("state/startup-receipts").exists());
}

#[test]
fn unsafe_receipt_directories_are_not_repaired_or_followed() {
	for kind in ["symlink", "public-directory", "regular-file"] {
		let root = tempfile::tempdir().unwrap();
		let (runtime, owner) = installed_at(root.path());
		let state = &runtime.get().unwrap().config.state_dir;
		let namespace = state.join("startup-receipts");
		let outside = root.path().join("outside");
		fs::create_dir(&outside).unwrap();
		match kind {
			"symlink" => symlink(&outside, &namespace).unwrap(),
			"public-directory" => {
				fs::create_dir(&namespace).unwrap();
				fs::set_permissions(&namespace, fs::Permissions::from_mode(0o755)).unwrap();
			}
			_ => fs::write(&namespace, b"retain original").unwrap(),
		}
		assert!(publish_private_receipt(runtime.get().unwrap(), owner.get().unwrap()).is_err());
		assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
		if kind == "public-directory" {
			assert_eq!(fs::metadata(&namespace).unwrap().mode() & 0o7777, 0o755);
			assert_eq!(fs::read_dir(&namespace).unwrap().count(), 0);
		}
		if kind == "regular-file" {
			assert_eq!(fs::read(&namespace).unwrap(), b"retain original");
		}
	}
}

#[test]
fn final_name_collision_retains_original_and_failed_pending_bytes() {
	let root = tempfile::tempdir().unwrap();
	let (runtime, owner) = installed_at(root.path());
	let id = "a".repeat(32);
	let path =
		unix::publish_instance(runtime.get().unwrap(), owner.get().unwrap(), id.clone()).unwrap();
	let bytes = fs::read(&path).unwrap();
	let inode = fs::metadata(&path).unwrap().ino();
	assert!(unix::publish_instance(runtime.get().unwrap(), owner.get().unwrap(), id).is_err());
	assert_eq!(fs::read(&path).unwrap(), bytes);
	assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
	assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
	let pending = path.with_extension("pending");
	assert!(pending.is_file());
	assert_eq!(fs::metadata(&pending).unwrap().nlink(), 1);
	assert_eq!(receipt_json(&pending)["stage"], "configuration_initialized");
}

#[test]
fn existing_pending_entries_cannot_replace_or_write_through_an_alias() {
	for kind in ["file", "symlink", "hardlink"] {
		let root = tempfile::tempdir().unwrap();
		let (runtime, owner) = installed_at(root.path());
		let namespace = runtime.get().unwrap().config.state_dir.join("startup-receipts");
		fs::create_dir(&namespace).unwrap();
		fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
		let id = "b".repeat(32);
		let stem = format!("config-{}-{id}", std::process::id());
		let pending = namespace.join(format!("{stem}.pending"));
		let protected = root.path().join("protected");
		fs::write(&protected, b"preserve").unwrap();
		match kind {
			"symlink" => symlink(&protected, &pending).unwrap(),
			"hardlink" => fs::hard_link(&protected, &pending).unwrap(),
			_ => fs::write(&pending, b"prior pending").unwrap(),
		}
		assert!(unix::publish_instance(runtime.get().unwrap(), owner.get().unwrap(), id).is_err());
		assert_eq!(fs::read(&protected).unwrap(), b"preserve");
		assert!(!namespace.join(format!("{stem}.json")).exists());
	}
}

#[test]
fn invalid_instance_name_cannot_create_a_receipt_namespace() {
	let root = tempfile::tempdir().unwrap();
	let (runtime, owner) = installed_at(root.path());
	for id in ["../outside".to_owned(), "X".repeat(32), "a".repeat(33)] {
		assert!(unix::publish_instance(runtime.get().unwrap(), owner.get().unwrap(), id).is_err());
	}
	assert!(!runtime.get().unwrap().config.state_dir.join("startup-receipts").exists());
}

#[test]
fn normalized_non_utf8_config_fails_opt_in_receipt_without_changing_default_semantics() {
	let root = tempfile::tempdir().unwrap();
	let non_utf8 = root
		.path()
		.join(std::ffi::OsString::from_vec(b"state-\xff".to_vec()));
	fs::create_dir(&non_utf8).unwrap();
	fs::set_permissions(&non_utf8, fs::Permissions::from_mode(0o700)).unwrap();
	let link = root.path().join("state-link");
	symlink(&non_utf8, &link).unwrap();
	let (_, _, loaded) = loaded_at(root.path(), &link);
	let runtime = OnceLock::new();
	let owner = OnceLock::new();
	assert!(init_runtime_with_private_receipt_at(loaded, &runtime, &owner).is_err());
	assert_eq!(runtime.get().unwrap().config.state_dir, non_utf8);
	assert!(owner.get().is_some());
	assert!(!non_utf8.join("startup-receipts").exists());
}

#[test]
fn private_file_guard_rejects_foreign_owner_permissions_and_multiple_links() {
	let root = tempfile::tempdir().unwrap();
	let file = root.path().join("receipt");
	fs::write(&file, b"private").unwrap();
	fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
	let uid = unsafe { libc::geteuid() };
	assert!(unix::validate_private_file(&fs::metadata(&file).unwrap(), uid).is_ok());
	assert!(
		unix::validate_private_file(&fs::metadata(&file).unwrap(), uid.wrapping_add(1)).is_err()
	);
	fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
	assert!(unix::validate_private_file(&fs::metadata(&file).unwrap(), uid).is_err());
	fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
	fs::hard_link(&file, root.path().join("alias")).unwrap();
	assert!(unix::validate_private_file(&fs::metadata(&file).unwrap(), uid).is_err());
}
