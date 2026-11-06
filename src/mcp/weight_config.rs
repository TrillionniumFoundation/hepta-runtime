// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Administrator-owned weight-worker profiles. Callers never choose executables.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

use super::runtime::config::{valid_name, RuntimeConfig};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WeightWorkerProfile {
	pub host: String,
	pub python_executable: String,
	pub worker_path: String,
	pub worker_sha256: String,
	/// Whole package identity in addition to the mandatory entry-point identity.
	#[serde(default)]
	pub worker_package_sha256: Option<String>,
	/// Explicit installation on the worker host; never infer the controller path.
	/// Omission preserves the historical profile serialization and Python client.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub native_client: Option<WeightNativeClientProfile>,
	pub session_root: String,
	pub input_roots: Vec<String>,
	pub allowed_providers: Vec<String>,
	#[serde(default = "default_memory")]
	pub max_memory_bytes: u64,
	#[serde(default = "default_threads")]
	pub max_cpu_threads: u8,
	#[serde(default = "default_lifetime")]
	pub max_lifetime_seconds: u64,
	#[serde(default = "default_request")]
	pub max_request_ms: u64,
	#[serde(default = "default_sessions")]
	pub max_active_sessions: usize,
	#[serde(default = "default_calls")]
	pub max_requests_per_session: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WeightNativeClientProfile {
	pub executable: String,
	pub sha256: String,
}

pub(super) fn valid_sha256(digest: &str) -> bool {
	digest.len() == 64
		&& digest
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn default_memory() -> u64 {
	4 * 1024 * 1024 * 1024
}
fn default_threads() -> u8 {
	2
}
fn default_lifetime() -> u64 {
	1800
}
fn default_request() -> u64 {
	120_000
}
fn default_sessions() -> usize {
	1
}
fn default_calls() -> usize {
	128
}

pub(crate) fn absolute_normal_path(path: &str) -> bool {
	Path::new(path).is_absolute()
		&& !path.contains(['\0', '\n', '\r'])
		&& !Path::new(path)
			.components()
			.any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}

fn inside(path: &str, roots: &[String]) -> bool {
	roots.iter().any(|root| Path::new(path).starts_with(root))
}

pub fn validate_profiles(config: &RuntimeConfig) -> Result<()> {
	if !config.weight_workers.is_empty() && !cfg!(target_os = "linux") {
		bail!("weight workers currently require a qualified Linux controller");
	}
	if config.weight_workers.len() > 16 {
		bail!("at most 16 weight worker profiles are supported");
	}
	for (name, profile) in &config.weight_workers {
		if !valid_name(name) {
			bail!("invalid weight worker profile name");
		}
		let host = config.host(&profile.host)?;
		if !host.allow_execute || !host.allow_write {
			bail!("weight profile {name} requires an executing, writable configured host");
		}
		for path in [
			&profile.python_executable,
			&profile.worker_path,
			&profile.session_root,
		]
		.into_iter()
		.chain(&profile.input_roots)
		{
			if !absolute_normal_path(path) {
				bail!("weight profile {name} paths must be absolute and normalized");
			}
		}
		if !valid_sha256(&profile.worker_sha256) {
			bail!("weight profile {name} requires a lowercase SHA-256 worker pin");
		}
		if profile
			.worker_package_sha256
			.as_ref()
			.is_some_and(|digest| !valid_sha256(digest))
		{
			bail!("weight profile {name} has an invalid package SHA-256 pin");
		}
		if let Some(client) = &profile.native_client {
			if !absolute_normal_path(&client.executable) || !valid_sha256(&client.sha256) {
				bail!("weight profile {name} native client needs an absolute executable and SHA-256 pin");
			}
			if !inside(&client.executable, &host.allowed_read_path_prefixes)
				|| host
					.protected_path_prefixes
					.iter()
					.any(|root| Path::new(&client.executable).starts_with(root))
			{
				bail!("weight profile {name} native client exceeds its host path policy");
			}
		}
		if !inside(&profile.session_root, &host.allowed_write_path_prefixes)
			|| (!host.allowed_cwd_prefixes.is_empty()
				&& !inside(&profile.session_root, &host.allowed_cwd_prefixes))
			|| !inside(&profile.worker_path, &host.allowed_read_path_prefixes)
			|| profile.input_roots.is_empty()
			|| profile
				.input_roots
				.iter()
				.any(|root| !inside(root, &host.allowed_read_path_prefixes))
		{
			bail!("weight profile {name} exceeds its host path policy");
		}
		if host.protected_path_prefixes.iter().any(|root| {
			Path::new(&profile.session_root).starts_with(root)
				|| Path::new(root).starts_with(&profile.session_root)
		}) {
			bail!("weight profile {name} session root intersects a protected path");
		}
		if profile.session_root.len() + 40 > 103 {
			bail!("weight profile {name} Unix socket path would exceed 103 bytes");
		}
		if profile.allowed_providers.is_empty()
			|| profile.allowed_providers.iter().any(|p| !valid_name(p))
		{
			bail!("weight profile {name} needs explicit provider names");
		}
		if !(256 * 1024 * 1024..=64 * 1024 * 1024 * 1024).contains(&profile.max_memory_bytes)
			|| !(1..=8).contains(&profile.max_cpu_threads)
			|| !(30..=7200).contains(&profile.max_lifetime_seconds)
			|| !(1000..=600_000).contains(&profile.max_request_ms)
			|| !(1..=8).contains(&profile.max_active_sessions)
			|| !(1..=512).contains(&profile.max_requests_per_session)
		{
			bail!("weight profile {name} has an unsupported resource budget");
		}
	}
	Ok(())
}
