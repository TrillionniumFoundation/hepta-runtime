// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Qualification projection of the original retained-result owner.
use super::runtime::config::{valid_name, Platform, RuntimeConfig};
use anyhow::{bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
#[path = "rea_engine_profile.rs"]
pub mod engine_profile;
pub use engine_profile::GhidraEngineProfile;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StaticProvider {
	GnuReadelf,
	GnuObjdump,
	Jadx,
	Ghidra,
}

#[derive(
	Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StaticOperation {
	Headers,
	Sections,
	Symbols,
	Notes,
	Relocations,
	Classes,
	Sources,
	Inventory,
	Functions,
	Function,
	Decompile,
	Xrefs,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JavaEngineProfile {
	pub java_home: String,
	pub jar_path: String,
	pub jar_sha256: String,
	pub engine_version: String,
	/// Distribution provenance, independently verified when the admin installs it.
	pub release_archive_sha256: String,
	/// Exact relative JRE files and their pins; system shared libraries remain outside this set.
	pub runtime_files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReaStaticProfile {
	pub host: String,
	pub runtime_executable: String,
	pub runtime_sha256: String,
	pub provider: StaticProvider,
	pub backend_executable: String,
	pub backend_sha256: String,
	/// Exact first line of the admitted backend's `--version` output under LC_ALL=C.
	pub backend_version: String,
	pub working_directory: String,
	pub input_roots: Vec<String>,
	pub allowed_operations: Vec<StaticOperation>,
	#[serde(default = "default_artifact_bytes")]
	pub max_artifact_bytes: u64,
	#[serde(default = "default_output_bytes")]
	pub max_output_bytes: usize,
	#[serde(default = "default_timeout")]
	pub timeout_seconds: u64,
	#[serde(default = "default_memory")]
	pub memory_max_bytes: u64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub java_engine: Option<JavaEngineProfile>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ghidra_engine: Option<GhidraEngineProfile>,
}

fn default_artifact_bytes() -> u64 {
	64 * 1024 * 1024
}
fn default_output_bytes() -> usize {
	32 * 1024
}
fn default_timeout() -> u64 {
	30
}
fn default_memory() -> u64 {
	512 * 1024 * 1024
}

impl StaticProvider {
	pub(crate) fn supports(self, operation: StaticOperation) -> bool {
		match self {
			Self::GnuReadelf => matches!(
				operation,
				StaticOperation::Headers
					| StaticOperation::Sections
					| StaticOperation::Symbols
					| StaticOperation::Notes
					| StaticOperation::Relocations
			),
			Self::GnuObjdump => matches!(
				operation,
				StaticOperation::Headers
					| StaticOperation::Sections
					| StaticOperation::Symbols
					| StaticOperation::Relocations
			),
			Self::Jadx => matches!(
				operation,
				StaticOperation::Classes | StaticOperation::Sources
			),
			Self::Ghidra => matches!(
				operation,
				StaticOperation::Inventory
					| StaticOperation::Functions
					| StaticOperation::Function
					| StaticOperation::Decompile
					| StaticOperation::Xrefs
			),
		}
	}
}
pub(crate) fn is_sha256(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn absolute_normal_path(value: &str) -> bool {
	Path::new(value).is_absolute()
		&& value.len() <= 4096
		&& !value.contains(['\0', '\n', '\r'])
		&& !value.split('/').any(|part| part == "." || part == "..")
		&& !Path::new(value)
			.components()
			.any(|p| matches!(p, Component::ParentDir | Component::CurDir))
}
fn inside(path: &str, roots: &[String]) -> bool {
	roots.iter().any(|root| Path::new(path).starts_with(root))
}
pub(crate) fn validate_profile(profile: &ReaStaticProfile) -> Result<()> {
	if !valid_name(&profile.host) {
		bail!("static profile requires a configured host name");
	}
	for path in [
		&profile.runtime_executable,
		&profile.backend_executable,
		&profile.working_directory,
	]
	.into_iter()
	.chain(&profile.input_roots)
	{
		if !absolute_normal_path(path) {
			bail!("static profile paths must be absolute and normalized");
		}
	}
	if !is_sha256(&profile.runtime_sha256) || !is_sha256(&profile.backend_sha256) {
		bail!("static profile requires runtime and backend SHA-256 pins");
	}
	let expected_prefix = match profile.provider {
		StaticProvider::GnuReadelf => "GNU readelf ",
		StaticProvider::GnuObjdump => "GNU objdump ",
		StaticProvider::Jadx => "openjdk 21.",
		StaticProvider::Ghidra => "openjdk 25.",
	};
	if !profile.backend_version.starts_with(expected_prefix)
		|| profile.backend_version.len() > 512
		|| profile.backend_version.contains(['\0', '\n', '\r'])
	{
		bail!("static profile requires its exact admitted backend version line");
	}
	match (&profile.java_engine, profile.provider) {
		(Some(engine), StaticProvider::Jadx) => {
			if !absolute_normal_path(&engine.java_home)
				|| !absolute_normal_path(&engine.jar_path)
				|| profile.backend_executable != format!("{}/bin/java", engine.java_home)
				|| !is_sha256(&engine.jar_sha256)
				|| !is_sha256(&engine.release_archive_sha256)
				|| engine.engine_version != "1.5.6"
				|| engine.runtime_files.len() > 16
				|| profile.max_artifact_bytes > 32 * 1024 * 1024
				|| profile.memory_max_bytes < 768 * 1024 * 1024
			{
				bail!("JADX profile requires the pinned 1.5.6 jar, Java 21 installation and bounded resources");
			}
			for required in [
				"release",
				"lib/modules",
				"lib/server/libjvm.so",
				"lib/libjava.so",
				"lib/libzip.so",
				"lib/libnio.so",
				"lib/libjli.so",
			] {
				if !engine.runtime_files.contains_key(required) {
					bail!("JADX runtime manifest is missing {required}");
				}
			}
			for (relative, digest) in &engine.runtime_files {
				if relative.is_empty()
					|| Path::new(relative).is_absolute()
					|| !absolute_normal_path(&format!("{}/{relative}", engine.java_home))
					|| !is_sha256(digest)
				{
					bail!("JADX runtime manifest has an invalid path or digest");
				}
			}
		}
		(None, StaticProvider::GnuReadelf | StaticProvider::GnuObjdump) => {}
		(None, StaticProvider::Ghidra) => engine_profile::validate_ghidra(profile)?,
		_ => bail!("Java engine settings must match an admitted Java provider"),
	}
	if profile.provider != StaticProvider::Ghidra && profile.ghidra_engine.is_some() {
		bail!("Ghidra installation settings require the fixed Ghidra provider");
	}
	if profile.input_roots.is_empty()
		|| profile.input_roots.len() > 16
		|| profile.allowed_operations.is_empty()
		|| profile
			.allowed_operations
			.iter()
			.any(|op| !profile.provider.supports(*op))
		|| profile
			.allowed_operations
			.iter()
			.collect::<BTreeSet<_>>()
			.len() != profile.allowed_operations.len()
	{
		bail!("static profile requires bounded roots and distinct supported operations");
	}
	if !(1..=512 * 1024 * 1024).contains(&profile.max_artifact_bytes)
		|| !(1024..=64 * 1024).contains(&profile.max_output_bytes)
		|| !(1..=120).contains(&profile.timeout_seconds)
		|| !(256 * 1024 * 1024..=2 * 1024 * 1024 * 1024).contains(&profile.memory_max_bytes)
		|| profile.memory_max_bytes < profile.max_artifact_bytes + 128 * 1024 * 1024
	{
		bail!("static profile resource limits are outside the admitted bounds");
	}
	Ok(())
}
pub fn validate_profiles(config: &RuntimeConfig) -> Result<()> {
	if !config.rea_static_profiles.is_empty() && !cfg!(target_os = "linux") {
		bail!("static backend profiles currently require a Linux controller");
	}
	if config.rea_static_profiles.len() > 16 {
		bail!("at most 16 static backend profiles are supported");
	}
	for (name, profile) in &config.rea_static_profiles {
		if !valid_name(name) {
			bail!("invalid static profile name");
		}
		validate_profile(profile)?;
		let host = config.host(&profile.host)?;
		if host.platform != Platform::Linux || !host.allow_execute {
			bail!("static profiles require an executing configured Linux host");
		}
		if !host.allowed_cwd_prefixes.is_empty()
			&& !inside(&profile.working_directory, &host.allowed_cwd_prefixes)
		{
			bail!("static profile cwd exceeds its host policy");
		}
		if let Some(engine) = &profile.java_engine {
			let runtime_paths: Vec<_> = engine
				.runtime_files
				.keys()
				.map(|relative| format!("{}/{relative}", engine.java_home))
				.collect();
			for path in [&engine.java_home, &engine.jar_path]
				.into_iter()
				.chain(&runtime_paths)
			{
				if !inside(path, &host.allowed_read_path_prefixes)
					|| inside(path, &host.protected_path_prefixes)
				{
					bail!("Java engine profile exceeds its host read policy");
				}
			}
		}
		if let Some(engine) = &profile.ghidra_engine {
			for path in engine_profile::policy_paths(engine) {
				if !inside(&path, &host.allowed_read_path_prefixes)
					|| inside(&path, &host.protected_path_prefixes)
				{
					bail!("Ghidra engine profile exceeds its host read policy");
				}
			}
		}
		for path in [&profile.runtime_executable, &profile.backend_executable]
			.into_iter()
			.chain(&profile.input_roots)
		{
			if !inside(path, &host.allowed_read_path_prefixes)
				|| inside(path, &host.protected_path_prefixes)
			{
				bail!("static profile exceeds its host read policy");
			}
		}
	}
	Ok(())
}
