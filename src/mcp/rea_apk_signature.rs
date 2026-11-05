// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Confined APK capture and native signature verification. The isolated worker
//! receives bounded captured bytes, never the source path or runtime secrets.

use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

#[path = "rea_apk_signature_observation.rs"]
mod observation;
#[path = "rea_apk_signature_parser.rs"]
mod parser;
#[path = "rea_apk_signature_worker.rs"]
mod worker;

pub use observation::{
	ApkErrorTag, ApkInspectionError, ApkResource, ApkSignatureReport, ApkStaticInspection,
	StaticLimits,
};

/// Bounded declared facts from already captured bytes; no filesystem or engine access.
pub fn inspect_static(
	bytes: &[u8],
) -> std::result::Result<ApkStaticInspection, ApkInspectionError> {
	observation::inspect_with_limits(bytes, StaticLimits::REA_6_8_0)
}

/// Select an established bounded profile without changing the legacy endpoint.
pub fn inspect_static_with_limits(
	bytes: &[u8],
	limits: StaticLimits,
) -> std::result::Result<ApkStaticInspection, ApkInspectionError> {
	observation::inspect_with_limits(bytes, limits)
}

/// Preserve declarations when the additional cryptographic verifier cannot complete.
pub fn inspect_captured_with_observations(bytes: &[u8]) -> Result<serde_json::Value> {
	parser::inspect_with_observations(bytes)
}

pub(super) const MAX_APK_BYTES: usize = 128 * 1024 * 1024;
pub(super) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectApkSignatureParams {
	/// Absolute APK file inside configured controller workspace roots, at most 128 MiB.
	pub path: String,
	/// Optional exact lowercase full-file SHA-256; mismatch fails before the parser starts.
	pub expected_sha256: Option<String>,
}

fn validate(params: &InspectApkSignatureParams) -> Result<()> {
	if params.expected_sha256.as_ref().is_some_and(|digest| {
		digest.len() != 64
			|| !digest
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	}) {
		bail!("APK signature identity must be a lowercase complete SHA-256");
	}
	Ok(())
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
	if cancellation.is_cancelled() {
		bail!("APK signature inspection cancelled");
	}
	Ok(())
}

async fn inspect_with_roots(
	params: InspectApkSignatureParams,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
) -> Result<String> {
	ensure_not_cancelled(cancellation)?;
	validate(&params)?;
	static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
	let _permit = Arc::clone(SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2))))
		.try_acquire_owned()
		.context("APK signature parser busy; retry when another inspection finishes")?;
	let (mut file, before) =
		super::rea_files::open_confined(Path::new(&params.path), roots).await?;
	ensure_not_cancelled(cancellation)?;
	if before.len() == 0 || before.len() > MAX_APK_BYTES as u64 {
		bail!("APK signature archive must contain 1 byte through 128 MiB");
	}
	let deadline = Instant::now() + Duration::from_secs(30);
	let mut captured = Vec::with_capacity(usize::try_from(before.len())?);
	let mut hash = Sha256::new();
	let mut buffer = vec![0_u8; 64 * 1024];
	loop {
		ensure_not_cancelled(cancellation)?;
		if Instant::now() > deadline {
			bail!("APK capture exceeded 30 second deadline");
		}
		// Finish each regular-file read before cancellation. Dropping a Tokio
		// read future does not itself stop its underlying blocking file read.
		let count = file
			.read(&mut buffer)
			.await
			.context("cannot capture admitted APK")?;
		if count == 0 {
			break;
		}
		if count > MAX_APK_BYTES - captured.len() {
			bail!("APK grew beyond the 128 MiB capture budget");
		}
		hash.update(&buffer[..count]);
		captured.extend_from_slice(&buffer[..count]);
	}
	let after = file.metadata().await?;
	#[cfg(unix)]
	super::rea_files::ensure_unchanged(&before, &after)?;
	if captured.len() as u64 != before.len() {
		bail!("APK length changed during capture");
	}
	let digest = parser::hex(&hash.finalize());
	if params
		.expected_sha256
		.as_deref()
		.is_some_and(|expected| expected != digest)
	{
		bail!("APK full-file SHA-256 differs from the requested identity");
	}
	ensure_not_cancelled(cancellation)?;
	#[cfg(not(test))]
	let mut result = worker::inspect_isolated(captured, cancellation).await?;
	#[cfg(test)]
	let mut result = parser::inspect(&captured)?;
	ensure_not_cancelled(cancellation)?;
	if result["record_format"] != "hepta.rea-apk-signature.v1"
		|| result["rea_evidence_compatible"] != false
		|| result["source"]["sha256"] != digest
		|| result["source"]["byte_length"] != before.len()
		|| result["verification"]["complete_android_verification"] != false
	{
		bail!("APK worker report is not bound to controller-admitted bytes and coverage");
	}
	result["source"]["local_path"] = json!(params.path);
	result["source"]["descriptor_scope"] = json!("one policy-admitted descriptor; before/after metadata checked; worker sees captured bytes only");
	result["limitations"].as_array_mut().context("APK worker omitted limitations")?
		.push(json!("Descriptor checks detect ordinary concurrent writes, not privileged races that restore metadata. File identity describes the complete captured byte sequence."));
	let encoded = serde_json::to_string(&result)?;
	if encoded.len() > MAX_RESPONSE_BYTES {
		bail!("APK signature response exceeds 1 MiB");
	}
	Ok(encoded)
}

pub async fn inspect_apk_signature(
	params: InspectApkSignatureParams,
	cancellation: CancellationToken,
) -> Result<String> {
	ensure_not_cancelled(&cancellation)?;
	validate(&params)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	inspect_with_roots(params, roots, &cancellation).await
}

pub fn serve_once() -> Result<()> {
	worker::serve_once()
}

#[cfg(test)]
#[path = "rea_apk_signature_tests.rs"]
mod tests;
