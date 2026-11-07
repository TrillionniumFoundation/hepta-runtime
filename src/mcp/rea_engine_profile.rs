// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded installation and explicit bridge identity for the fixed Ghidra provider.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use super::{absolute_normal_path, is_sha256, ReaStaticProfile};

pub(crate) const GHIDRA_RELEASE_SHA256: &str =
	"2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67";
pub(crate) const GHIDRA_1214_RELEASE_SHA256: &str =
	"ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db";
#[cfg(target_os = "linux")]
pub(crate) const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(any(target_os = "linux", test))]
pub(crate) const MAX_INSTALLATION_FILES: usize = 20_000;

#[cfg(any(target_os = "linux", test))]
pub(crate) const GHIDRA_V4_GPL_REQUIRED: [(&str, &str); 2] = [
	(
		"GPL/DemanglerGnu/Module.manifest",
		"ca76258f330d1096cb616df83a4213593a574c907d02eb47b0926ccc5359bd7b",
	),
	(
		"GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_41",
		"0dfec5481a933e9cb2a7ef025040dd3a817d0085bc3bee166ce69ce7de759ad9",
	),
];

#[cfg(any(target_os = "linux", test))]
pub(crate) fn installation_subtrees(revision: Option<u32>) -> &'static [&'static str] {
	if revision == Some(4) {
		&["Ghidra", "GPL"]
	} else {
		&["Ghidra"]
	}
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GhidraEngineProfile {
	/// Absent and revision 2 retain Ghidra 12.2; revisions 3 and 4 select fixed 12.1.4.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub bridge_revision: Option<u32>,
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
#[cfg(any(target_os = "linux", test))]
pub(crate) struct InstallationManifest {
	pub schema: String,
	pub engine_version: String,
	pub release_archive_sha256: String,
	pub files: BTreeMap<String, String>,
}

pub(crate) fn release_identity(revision: Option<u32>) -> Result<(&'static str, &'static str)> {
	match revision {
		None | Some(2) => Ok(("12.2", GHIDRA_RELEASE_SHA256)),
		Some(3 | 4) => Ok(("12.1.4", GHIDRA_1214_RELEASE_SHA256)),
		_ => bail!("Ghidra bridge revision does not select a fixed release"),
	}
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
	let (version, release_sha256) = release_identity(engine.bridge_revision)?;
	if (engine.bridge_revision.is_none()
		&& profile
			.allowed_operations
			.iter()
			.any(|operation| *operation != super::StaticOperation::Inventory))
		|| profile.java_engine.is_some()
		|| !absolute_normal_path(&engine.java_home)
		|| !absolute_normal_path(&engine.installation_root)
		|| engine.installation_root.contains(':')
		|| !absolute_normal_path(&engine.manifest_path)
		|| !is_sha256(&engine.manifest_sha256)
		|| engine.engine_version != version
		|| engine.release_archive_sha256 != release_sha256
		|| profile.backend_executable != format!("{}/bin/java", engine.java_home)
		|| profile.max_artifact_bytes > 8 * 1024 * 1024
		|| profile.max_output_bytes < 2048
		|| profile.memory_max_bytes < 1024 * 1024 * 1024
		|| engine.runtime_files.len() > 16
	{
		bail!("Ghidra profile requires its revision-bound fixed distribution, Java 25 and bounded engine resources and an explicit analysis bridge revision");
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

#[cfg(any(target_os = "linux", test))]
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
	if engine.bridge_revision == Some(4) {
		for (required, expected) in GHIDRA_V4_GPL_REQUIRED {
			if manifest.files.get(required).map(String::as_str) != Some(expected) {
				bail!(
					"Ghidra revision 4 manifest is missing or changes fixed GNU helper {required}"
				);
			}
		}
	}
	for (relative, digest) in &manifest.files {
		if !(relative.starts_with("Ghidra/")
			|| (engine.bridge_revision == Some(4) && relative.starts_with("GPL/")))
			|| (engine.bridge_revision == Some(4)
				&& relative
					.split('/')
					.any(|part| matches!(part, "" | "." | "..")))
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

#[cfg(test)]
#[path = "rea_engine_profile_tests.rs"]
mod tests;
