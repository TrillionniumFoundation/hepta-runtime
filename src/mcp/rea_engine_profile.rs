// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded installation identity for the fixed Ghidra import-only provider.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use super::{absolute_normal_path, is_sha256, ReaStaticProfile};

pub(crate) const GHIDRA_RELEASE_SHA256: &str =
	"2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67";
pub(crate) const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_INSTALLATION_FILES: usize = 20_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GhidraEngineProfile {
	pub java_home: String,
	pub installation_root: String,
	pub manifest_path: String,
	pub manifest_sha256: String,
	pub engine_version: String,
	pub release_archive_sha256: String,
	pub runtime_files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallationManifest {
	pub schema: String,
	pub engine_version: String,
	pub release_archive_sha256: String,
	pub files: BTreeMap<String, String>,
}

pub(crate) fn policy_paths(engine: &GhidraEngineProfile) -> Vec<String> {
	let mut paths = vec![
		engine.java_home.clone(),
		engine.installation_root.clone(),
		engine.manifest_path.clone(),
	];
	paths.extend(
		engine
			.runtime_files
			.keys()
			.map(|relative| format!("{}/{relative}", engine.java_home)),
	);
	paths
}

pub(crate) fn validate_ghidra(profile: &ReaStaticProfile) -> Result<()> {
	let engine = profile
		.ghidra_engine
		.as_ref()
		.context("Ghidra profile requires its installation manifest")?;
	if profile.java_engine.is_some()
		|| !absolute_normal_path(&engine.java_home)
		|| !absolute_normal_path(&engine.installation_root)
		|| engine.installation_root.contains(':')
		|| !absolute_normal_path(&engine.manifest_path)
		|| !is_sha256(&engine.manifest_sha256)
		|| engine.engine_version != "12.2"
		|| engine.release_archive_sha256 != GHIDRA_RELEASE_SHA256
		|| profile.backend_executable != format!("{}/bin/java", engine.java_home)
		|| profile.max_artifact_bytes > 8 * 1024 * 1024
		|| profile.max_output_bytes < 2048
		|| profile.memory_max_bytes < 1024 * 1024 * 1024
		|| engine.runtime_files.len() > 16
	{
		bail!("Ghidra profile requires the fixed 12.2 distribution, Java 25 and bounded import resources");
	}
	for name in [
		"release",
		"lib/modules",
		"lib/server/libjvm.so",
		"lib/libjava.so",
		"lib/libzip.so",
		"lib/libnio.so",
		"lib/libjli.so",
	] {
		if !engine.runtime_files.contains_key(name) {
			bail!("Ghidra runtime manifest is missing {name}");
		}
	}
	for (relative, digest) in &engine.runtime_files {
		if relative.is_empty()
			|| Path::new(relative).is_absolute()
			|| !absolute_normal_path(&format!("{}/{relative}", engine.java_home))
			|| !is_sha256(digest)
		{
			bail!("Ghidra runtime manifest has an invalid path or digest");
		}
	}
	Ok(())
}

pub(crate) fn validate_manifest(
	manifest: &InstallationManifest,
	engine: &GhidraEngineProfile,
) -> Result<()> {
	if manifest.schema != "hepta.rea.ghidra-installation.v1"
		|| manifest.engine_version != engine.engine_version
		|| manifest.release_archive_sha256 != engine.release_archive_sha256
		|| manifest.files.is_empty()
		|| manifest.files.len() > MAX_INSTALLATION_FILES
	{
		bail!("Ghidra installation manifest identity or file budget is invalid");
	}
	for required in [
		"Ghidra/application.properties",
		"Ghidra/Framework/Utility/lib/Utility.jar",
		"Ghidra/Features/Base/lib/Base.jar",
	] {
		if !manifest.files.contains_key(required) {
			bail!("Ghidra installation manifest is missing {required}");
		}
	}
	for (relative, digest) in &manifest.files {
		if !relative.starts_with("Ghidra/")
			|| relative.contains(':')
			|| relative.contains('\\')
			|| !absolute_normal_path(&format!("{}/{relative}", engine.installation_root))
			|| !is_sha256(digest)
		{
			bail!("Ghidra installation manifest has an invalid path or digest");
		}
	}
	Ok(())
}
