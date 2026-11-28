use anyhow::{bail,Result};
use serde::{Deserialize,Serialize};
use std::path::Path;
use super::runtime::config::{RuntimeConfig,Platform,valid_name};
use super::hia_contract;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HiaWorkerProfile {
	pub host: String,
	pub python_executable: String,
	/// Trusted installed Hepta source root. No caller-controlled PYTHONPATH is accepted.
	pub working_directory: String,
	/// Private store shared by this configured operator authority across sessions.
	pub state_root: String,
	#[serde(default)]
	pub artifact_roots: Vec<String>,
	/// Exact sorted source inventory returned by the installed worker's manifest command.
	pub worker_sha256: String,
	pub backend_sha256: String,
	pub catalog_sha256: String,
	/// Optional administrator-selected manifest for pinned native helper images.
	/// Omitted legacy fields must not change durable profile/request identities.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub native_helpers_manifest: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub native_helpers_sha256: Option<String>,
	#[serde(default = "default_timeout")]
	pub timeout_seconds: u64,
	#[serde(default = "default_memory")]
	pub memory_max_bytes: u64,
}

fn default_timeout() -> u64 {
	120
}
fn default_memory() -> u64 {
	1024 * 1024 * 1024
}


fn inside(path: &str, roots: &[String]) -> bool {
	roots.iter().any(|root| Path::new(path).starts_with(root))
}
pub(super) fn validate_profile(config: &RuntimeConfig) -> Result<()> {
	let Some(profile) = &config.hia_worker else {
		return Ok(());
	};
	if !valid_name(&profile.host) {
		bail!("invalid HIA worker host alias");
	}
	let host = config.host(&profile.host)?;
	if host.platform != Platform::Linux || !host.allow_execute || !host.allow_write {
		bail!("HIA worker requires an executing, writable configured Linux host");
	}
	if ![
		&profile.worker_sha256,
		&profile.backend_sha256,
		&profile.catalog_sha256,
	]
	.into_iter()
	.all(|digest| super::rea_provider::is_sha256(digest))
	{
		bail!("HIA worker requires exact lowercase SHA256 installation pins");
	}
	if profile.catalog_sha256 != hia_contract::catalog_sha256() {
		bail!("HIA worker catalog differs from the runtime's registered tool contract");
	}
	match (
		&profile.native_helpers_manifest,
		&profile.native_helpers_sha256,
	) {
		(None, None) => {}
		(Some(path), Some(digest)) => {
			if !super::rea_provider::is_sha256(digest)
				|| !super::rea_provider::absolute_normal_path(path)
				|| !inside(path, &host.allowed_read_path_prefixes)
				|| inside(path, &host.protected_path_prefixes)
				|| Path::new(path).starts_with(&profile.state_root)
			{
				bail!("HIA native helpers require an exact digest and permitted installation path outside mutable state");
			}
		}
		_ => bail!("HIA native helper manifest and digest must be configured together"),
	}
	if !(1..=3600).contains(&profile.timeout_seconds)
		|| !(64 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&profile.memory_max_bytes)
		|| profile.artifact_roots.len() > 32
	{
		bail!("HIA worker resource limits exceed the admitted profile bounds");
	}
	for path in [
		&profile.python_executable,
		&profile.working_directory,
		&profile.state_root,
	]
	.into_iter()
	.chain(&profile.artifact_roots)
	{
		if !super::rea_provider::absolute_normal_path(path)
			|| !inside(path, &host.allowed_read_path_prefixes)
			|| inside(path, &host.protected_path_prefixes)
		{
			bail!("HIA profile path exceeds the configured host read policy");
		}
	}
	if profile.state_root == "/"
		|| !inside(&profile.state_root, &host.allowed_write_path_prefixes)
		|| Path::new(&profile.working_directory).starts_with(&profile.state_root)
		|| Path::new(&profile.state_root).starts_with(&profile.working_directory)
	{
		bail!("HIA state requires a writable private root disjoint from the installed source");
	}
	if !host.allowed_cwd_prefixes.is_empty()
		&& !inside(&profile.working_directory, &host.allowed_cwd_prefixes)
	{
		bail!("HIA installation exceeds its host execution roots");
	}
	Ok(())
}