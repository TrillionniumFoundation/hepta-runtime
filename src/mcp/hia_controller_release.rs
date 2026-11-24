// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Admit the installed HIA controller as one release, before serving traffic.

use std::{
	collections::BTreeMap,
	env,
	fs::{File, OpenOptions},
	io::Read,
	os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
	path::Path,
	sync::{Arc, OnceLock},
};

use anyhow::{ensure, Context, Result};
use serde::Deserialize;

use super::{hia_contract, hia_wire_candidate::sealed};

const CATALOG: &str = "HIA_AGENT_NATIVE_TOOL_CATALOG.json";
const SCHEMA: &str = "hepta.hia.mcp.controller.v1";
const RECEIPT_SCHEMA: &str = "hepta.hia.mcp.controller.v2";
const WITNESS_SCHEMA: &str = "hepta.hia.mcp.controller.v3";
const TERMINAL_RECEIPT_SCHEMA: &str = "hepta.hia.mcp.controller.v4";
const LIFECYCLE_OWNER_SCHEMA: &str = "hepta.hia.mcp.controller.v5";
const WITNESS_PUBLISHER_SCHEMA: &str = "hepta.hia.mcp.controller.v6";
const SUPERVISOR_OUTCOME_SCHEMA: &str = "hepta.hia.mcp.controller.v7";
const SUPERVISOR_PUBLICATION_SCHEMA: &str = "hepta.hia.mcp.controller.v8";
const WORKDIR_AUTHORITY_SCHEMA: &str = "hepta.hia.mcp.controller.v9";
const CANCEL_AUTHORITY_SCHEMA: &str = "hepta.hia.mcp.controller.v10";
const SUPERVISION_LOOP_SCHEMA: &str = "hepta.hia.mcp.controller.v11";
const CANCEL_WRITER_SCHEMA: &str = "hepta.hia.mcp.controller.v12";
const RESOURCE_INGRESS_SCHEMA: &str = "hepta.hia.mcp.controller.v13";
const GROUP_SIGNAL_SCHEMA: &str = "hepta.hia.mcp.controller.v14";
const CHILD_PUBLICATION_SCHEMA: &str = "hepta.hia.mcp.controller.v15";
const ORIGINAL_CHILD_WAIT_SCHEMA: &str = "hepta.hia.mcp.controller.v16";
const OUTPUT_CAPTURE_SCHEMA: &str = "hepta.hia.mcp.controller.v17";
const WORKLOAD_SPAWN_SCHEMA: &str = "hepta.hia.mcp.controller.v18";
const SUPERVISOR_IDENTITY_SCHEMA: &str = "hepta.hia.mcp.controller.v19";
const OWNER_LOCK_SCHEMA: &str = "hepta.hia.mcp.controller.v20";
const OWNER_RECORD_SCHEMA: &str = "hepta.hia.mcp.controller.v21";
const OWNER_FILE_LOCK_SCHEMA: &str = "hepta.hia.mcp.controller.v22";
const OWNER_MARKER_SCHEMA: &str = "hepta.hia.mcp.controller.v23";
const OWNER_CUSTODY_SCHEMA: &str = "hepta.hia.mcp.controller.v24";
const NATIVE_JOB_OWNER_SCHEMA: &str = "hepta.hia.mcp.controller.v25";
const NATIVE_JOB_TRANSPORT_SCHEMA: &str = "hepta.hia.mcp.controller.v26";
const JOB_SUPERVISOR: &str = "hia-job-supervisor";
const WITNESS_ROLE: &str = "JOB_WITNESS";
const WITNESS_PATH: &str = "HIA_LOCAL_MCP_JOB_WITNESS_IMAGE";
const RECEIPT_ROLE: &str = "JOB_RECEIPT";
const JOB_RECEIPT: &str = "hia-job-receipt";
const TERMINAL_RECEIPT_ROLE: &str = "JOB_TERMINAL_RECEIPT";
const JOB_TERMINAL_RECEIPT: &str = "hia-agent-job-terminal-receipt";
const WORKER_PREPARE: &str = "hia-worker-prepare";
const NATIVE_JOB_ROLES: [(&str, &str, usize); 5] = [
	("JOB_ENTRY", "hia-job-entry", 2 << 20),
	("JOB_SUBMIT", "hia-job-submit", 4 << 20),
	("JOB_OBSERVATION", "hia-job-observation", 2 << 20),
	("JOB_CANCEL", "hia-job-cancel", 1 << 20),
	("JOB_LAUNCH", "hia-job-launch", 1 << 20),
];
const NATIVE_JOB_HELPERS: [&str; 3] = [WORKER_PREPARE, JOB_RECEIPT, JOB_SUPERVISOR];
const FILTERS: [(&str, &str); 9] = [
	("WIRE", "hia-agent-mcp-request"),
	("REPLY", "hia-agent-mcp-reply"),
	("TERMINAL", "hia-agent-mcp-terminal"),
	("NEGOTIATION", "hia-agent-mcp-negotiation"),
	("CATALOG", "hia-agent-mcp-catalog"),
	("URI", "hia-agent-mcp-uri"),
	("INPUT_SCHEMA", "hia-agent-mcp-input-schema"),
	("RESPONSE_SCHEMA", "hia-agent-mcp-response-schema"),
	("PROOF_SCHEMA", "hia-agent-mcp-proof-schema"),
];
const WORKER_ROLES: [&str; 12] = [
	"PREPARE",
	"JOB_IDENTITY",
	"SESSION_SCOPE",
	"HTTP_AUTH",
	"JOB_TRANSITION",
	"JOB_LAUNCH_ACK",
	"JOB_POLL",
	"JOB_TERMINAL",
	"CAPTURE_POLICY",
	"JOB_LIFECYCLE",
	"JOB_OPERATION",
	"JOB_PENDING",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
	schema: String,
	files: BTreeMap<String, String>,
}

struct Release {
	witness: bool,
	lifecycle_owner: bool,
	supervisor_protocol: u8,
	terminal_artifacts: Option<serde_json::Value>,
	images: BTreeMap<&'static str, File>,
	native_artifacts: BTreeMap<&'static str, NativeJobArtifact>,
	catalog: Vec<u8>,
}

struct NativeJobArtifact {
	sha256: String,
	bytes: OnceLock<Arc<[u8]>>,
}

static RELEASE: OnceLock<Release> = OnceLock::new();

fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
	let file = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
		.open(path)
		.with_context(|| {
			format!(
				"cannot open installed HIA controller file {}",
				path.display()
			)
		})?;
	let info = file.metadata()?;
	ensure!(
		info.is_file()
			&& info.mode() & 0o022 == 0
			&& (info.uid() == 0 || info.uid() == unsafe { libc::geteuid() })
			&& info.len() > 0
			&& info.len() <= limit as u64,
		"invalid installed HIA controller file extent or custody"
	);
	let mut bytes = Vec::new();
	file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
	ensure!(
		bytes.len() as u64 == info.len(),
		"HIA controller file changed while read"
	);
	Ok(bytes)
}

impl Release {
	fn load(manifest: &Path, pin: &str) -> Result<Self> {
		let directory = manifest
			.parent()
			.context("missing HIA controller release directory")?;
		ensure!(
			manifest.is_absolute() && directory.canonicalize()? == directory,
			"HIA controller release directory must be canonical and absolute"
		);
		let payload = read(manifest, 16 * 1024)?;
		ensure!(
			hia_contract::sha256(&payload) == pin,
			"invalid HIA controller manifest identity"
		);
		let admitted: Manifest = serde_json::from_slice(&payload)?;
		let with_receipt = match admitted.schema.as_str() {
			SCHEMA => false,
			RECEIPT_SCHEMA
			| WITNESS_SCHEMA
			| TERMINAL_RECEIPT_SCHEMA
			| LIFECYCLE_OWNER_SCHEMA
			| WITNESS_PUBLISHER_SCHEMA
			| SUPERVISOR_OUTCOME_SCHEMA
			| SUPERVISOR_PUBLICATION_SCHEMA
			| WORKDIR_AUTHORITY_SCHEMA
			| CANCEL_AUTHORITY_SCHEMA
			| SUPERVISION_LOOP_SCHEMA
			| CANCEL_WRITER_SCHEMA
			| RESOURCE_INGRESS_SCHEMA
			| GROUP_SIGNAL_SCHEMA
			| CHILD_PUBLICATION_SCHEMA
			| ORIGINAL_CHILD_WAIT_SCHEMA
			| OUTPUT_CAPTURE_SCHEMA
			| WORKLOAD_SPAWN_SCHEMA
			| SUPERVISOR_IDENTITY_SCHEMA
			| OWNER_LOCK_SCHEMA
			| OWNER_RECORD_SCHEMA
			| OWNER_FILE_LOCK_SCHEMA
			| OWNER_MARKER_SCHEMA
			| OWNER_CUSTODY_SCHEMA
			| NATIVE_JOB_OWNER_SCHEMA
			| NATIVE_JOB_TRANSPORT_SCHEMA => true,
			_ => anyhow::bail!("invalid installed HIA controller schema"),
		};
		let supervisor_protocol = match admitted.schema.as_str() {
			NATIVE_JOB_TRANSPORT_SCHEMA => 26,
			NATIVE_JOB_OWNER_SCHEMA => 25,
			OWNER_CUSTODY_SCHEMA => 24,
			OWNER_MARKER_SCHEMA => 23,
			OWNER_FILE_LOCK_SCHEMA => 22,
			OWNER_RECORD_SCHEMA => 21,
			OWNER_LOCK_SCHEMA => 20,
			SUPERVISOR_IDENTITY_SCHEMA => 19,
			WORKLOAD_SPAWN_SCHEMA => 18,
			OUTPUT_CAPTURE_SCHEMA => 17,
			ORIGINAL_CHILD_WAIT_SCHEMA => 16,
			CHILD_PUBLICATION_SCHEMA => 15,
			GROUP_SIGNAL_SCHEMA => 14,
			RESOURCE_INGRESS_SCHEMA => 13,
			CANCEL_WRITER_SCHEMA => 12,
			SUPERVISION_LOOP_SCHEMA => 11,
			CANCEL_AUTHORITY_SCHEMA => 10,
			WORKDIR_AUTHORITY_SCHEMA => 9,
			SUPERVISOR_PUBLICATION_SCHEMA => 8,
			SUPERVISOR_OUTCOME_SCHEMA => 7,
			WITNESS_PUBLISHER_SCHEMA => 6,
			_ => 0,
		};
		let native_job_owner = supervisor_protocol >= 25;
		let native_job_transport = supervisor_protocol == 26;
		let witness_publisher = supervisor_protocol >= 6;
		let lifecycle_owner = admitted.schema == LIFECYCLE_OWNER_SCHEMA || witness_publisher;
		let with_terminal_receipt = admitted.schema == TERMINAL_RECEIPT_SCHEMA || lifecycle_owner;
		let witness = admitted.schema == WITNESS_SCHEMA || with_terminal_receipt;
		ensure!(
			admitted.files.len()
				== FILTERS.len()
					+ 2 + usize::from(with_receipt)
					+ usize::from(with_terminal_receipt)
					+ usize::from(native_job_owner)
					+ usize::from(native_job_transport) * NATIVE_JOB_ROLES.len(),
			"invalid installed HIA controller role inventory"
		);
		let load = |name: &str, limit: usize| -> Result<Vec<u8>> {
			let expected = admitted
				.files
				.get(name)
				.context("missing installed HIA controller role")?;
			let bytes = read(&directory.join(name), limit)?;
			ensure!(
				hia_contract::sha256(&bytes) == *expected,
				"invalid HIA controller role {name}"
			);
			Ok(bytes)
		};
		let catalog = load(CATALOG, hia_contract::CATALOG_BYTES.len())?;
		ensure!(
			catalog == hia_contract::CATALOG_BYTES,
			"installed HIA controller catalog differs from this runtime"
		);
		let mut images = BTreeMap::new();
		let mut native_artifacts = BTreeMap::new();
		let mut terminal_artifacts = witness_publisher.then(serde_json::Map::new);
		for name in FILTERS
			.map(|(_, name)| name)
			.into_iter()
			.chain([WORKER_PREPARE])
			.chain(with_receipt.then_some(JOB_RECEIPT))
			.chain(with_terminal_receipt.then_some(JOB_TERMINAL_RECEIPT))
			.chain(native_job_owner.then_some(JOB_SUPERVISOR))
			.chain(
				NATIVE_JOB_ROLES
					.iter()
					.filter(|_| native_job_transport)
					.map(|(_, name, _)| *name),
			) {
			let bytes = load(name, native_job_limit(name).unwrap_or(1 << 20))?;
			ensure!(
				bytes.starts_with(b"\x7fELF\x02\x01\x01")
					&& bytes.get(16..20) == Some(&[2, 0, 62, 0]),
				"invalid installed HIA controller executable {name}"
			);
			if let (Some(artifacts), Some(role)) = (
				terminal_artifacts.as_mut(),
				match name {
					WORKER_PREPARE => Some("encoder"),
					JOB_RECEIPT => Some("writer"),
					JOB_SUPERVISOR => Some("supervisor"),
					_ => None,
				},
			) {
				const HEX: &[u8; 16] = b"0123456789abcdef";
				let mut encoded = String::with_capacity(bytes.len() * 2);
				for &byte in &bytes {
					encoded.push(HEX[(byte >> 4) as usize] as char);
					encoded.push(HEX[(byte & 15) as usize] as char);
				}
				artifacts.insert(
					role.into(),
					serde_json::json!({
						"sha256": admitted.files.get(name).context("missing terminal image pin")?,
						"hex": encoded,
					}),
				);
			}
			if native_job_transport && native_job_limit(name).is_some() {
				native_artifacts.insert(
					name,
					NativeJobArtifact {
						sha256: admitted
							.files
							.get(name)
							.context("missing native job image pin")?
							.clone(),
						bytes: OnceLock::new(),
					},
				);
			}
			images.insert(name, sealed(c"hia-controller-release", &bytes, true)?);
		}
		Ok(Self {
			witness,
			lifecycle_owner,
			supervisor_protocol,
			terminal_artifacts: terminal_artifacts.map(serde_json::Value::Object),
			images,
			native_artifacts,
			catalog,
		})
	}

	fn native_job_pin(&self, name: &str) -> Result<&NativeJobArtifact> {
		ensure!(
			self.supervisor_protocol == 26,
			"native job transport requires a complete v26 HIA controller release"
		);
		self.native_artifacts
			.get(name)
			.context("unlisted native job artifact role")
	}

	fn native_job_artifact(&self, name: &str, expected_sha: &str) -> Result<Arc<[u8]>> {
		let artifact = self.native_job_pin(name)?;
		ensure!(
			expected_sha == artifact.sha256,
			"native job artifact {name} differs from the configured identity"
		);
		if let Some(bytes) = artifact.bytes.get() {
			return Ok(Arc::clone(bytes));
		}
		let image = self
			.images
			.get(name)
			.context("missing sealed native job image")?;
		verify_native_image_seals(image)?;
		let limit = native_job_limit(name).context("unlisted native job image extent")?;
		let length = usize::try_from(image.metadata()?.len())?;
		ensure!(
			length > 0 && length <= limit,
			"invalid sealed native job image extent"
		);
		let mut bytes = vec![0; length];
		image
			.read_exact_at(&mut bytes, 0)
			.context("cannot capture sealed native job image")?;
		ensure!(
			hia_contract::sha256(&bytes) == expected_sha,
			"sealed native job image identity changed"
		);
		// Every caller shares the same immutable bytes even when the first reads
		// race. Queued observations retain an Arc, not another image allocation.
		let _ = artifact.bytes.set(Arc::from(bytes));
		artifact
			.bytes
			.get()
			.map(Arc::clone)
			.context("native job image cache was not initialized")
	}
}

fn native_job_limit(name: &str) -> Option<usize> {
	if NATIVE_JOB_HELPERS.contains(&name) {
		return Some(1 << 20);
	}
	NATIVE_JOB_ROLES
		.iter()
		.find(|(_, known, _)| *known == name)
		.map(|(_, _, limit)| *limit)
}

#[cfg(target_os = "linux")]
fn verify_native_image_seals(image: &File) -> Result<()> {
	use std::os::fd::AsRawFd;
	let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
	let observed = unsafe { libc::fcntl(image.as_raw_fd(), libc::F_GET_SEALS) };
	ensure!(
		observed >= 0 && observed & required == required,
		"native job image has not retained all immutability seals"
	);
	Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_native_image_seals(_image: &File) -> Result<()> {
	anyhow::bail!("native job transport requires Linux sealed descriptors")
}

pub(super) fn has_native_job_transport() -> bool {
	RELEASE
		.get()
		.is_some_and(|release| release.supervisor_protocol == 26)
}

pub(super) fn native_job_artifact(name: &str, expected_sha: &str) -> Result<Arc<[u8]>> {
	RELEASE
		.get()
		.context("native job transport requires an installed HIA controller release")?
		.native_job_artifact(name, expected_sha)
}

pub(super) fn native_job_artifact_sha256(name: &str) -> Result<String> {
	let release = RELEASE
		.get()
		.context("native job transport requires an installed HIA controller release")?;
	Ok(release.native_job_pin(name)?.sha256.clone())
}

pub(super) fn lifecycle_owner_selected() -> bool {
	RELEASE.get().is_some_and(|release| release.lifecycle_owner)
}

pub(super) fn resource_ingress_selected() -> bool {
	RELEASE
		.get()
		.is_some_and(|release| release.supervisor_protocol >= 13)
}

pub(super) fn terminal_publication_artifacts() -> Option<(&'static serde_json::Value, u8)> {
	let release = RELEASE.get()?;
	Some((
		release.terminal_artifacts.as_ref()?,
		release.supervisor_protocol,
	))
}

/// Startup calls this once. No admitted role can silently fall back to an
/// environment image, and an invalid release is never published partially.
pub fn install(manifest: &Path, pin: &str) -> Result<()> {
	ensure!(
		!FILTERS
			.iter()
			.map(|(role, _)| *role)
			.chain(WORKER_ROLES)
			.chain([RECEIPT_ROLE, WITNESS_ROLE, TERMINAL_RECEIPT_ROLE])
			.chain(NATIVE_JOB_ROLES.map(|(role, _, _)| role))
			.any(|role| {
				env::var_os(format!("HIA_LOCAL_MCP_{role}_IMAGE")).is_some()
					|| env::var_os(format!("HIA_LOCAL_MCP_{role}_SHA256")).is_some()
			}) && env::var_os("HIA_LOCAL_MCP_CATALOG_DATA").is_none(),
		"HIA controller release cannot be combined with per-role environment selectors"
	);
	RELEASE
		.set(Release::load(manifest, pin)?)
		.map_err(|_| anyhow::anyhow!("HIA controller release is already installed"))
}

fn release_name(path_key: &str) -> Option<&'static str> {
	let role = path_key
		.strip_prefix("HIA_LOCAL_MCP_")?
		.strip_suffix("_IMAGE")?;
	if role == RECEIPT_ROLE {
		return Some(JOB_RECEIPT);
	}
	if role == TERMINAL_RECEIPT_ROLE {
		return Some(JOB_TERMINAL_RECEIPT);
	}
	if role == WITNESS_ROLE || WORKER_ROLES.contains(&role) {
		return Some(WORKER_PREPARE);
	}
	if let Some((_, name, _)) = NATIVE_JOB_ROLES.iter().find(|(known, _, _)| *known == role) {
		return Some(*name);
	}
	FILTERS
		.iter()
		.find(|(known, _)| *known == role)
		.map(|(_, name)| *name)
}

#[cfg(test)]
#[path = "hia_controller_native_jobs_tests.rs"]
mod native_jobs_tests;

fn admitted_image<'a>(release: &'a Release, path_key: &str) -> Option<&'a File> {
	if path_key == WITNESS_PATH && !release.witness {
		return None;
	}
	release.images.get(release_name(path_key)?)
}

pub(super) fn selected(path_key: &str) -> bool {
	RELEASE
		.get()
		.and_then(|release| admitted_image(release, path_key))
		.is_some()
}

pub(super) fn image(path_key: &str) -> Option<std::io::Result<File>> {
	Some(admitted_image(RELEASE.get()?, path_key)?.try_clone())
}

pub(super) fn catalog() -> Option<&'static [u8]> {
	Some(&RELEASE.get()?.catalog)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::os::unix::fs::FileExt;

	#[test]
	fn installed_roles_are_exact_and_sealed_before_any_selection() {
		let folder = tempfile::tempdir().unwrap();
		let directory = folder.path().canonicalize().unwrap();
		let mut pins = BTreeMap::new();
		let mut image = vec![0; 80];
		image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
		image[16..20].copy_from_slice(&[2, 0, 62, 0]);
		for role in FILTERS
			.map(|(_, name)| name)
			.into_iter()
			.chain([WORKER_PREPARE, CATALOG])
		{
			let data = if role == CATALOG {
				hia_contract::CATALOG_BYTES
			} else {
				&image
			};
			std::fs::write(directory.join(role), data).unwrap();
			pins.insert(role, hia_contract::sha256(data));
		}
		let manifest = directory.join("hia-controller.json");
		let data = serde_json::to_vec(&serde_json::json!({"schema":SCHEMA,"files":pins})).unwrap();
		std::fs::write(&manifest, &data).unwrap();
		let pin = hia_contract::sha256(&data);
		assert!(Release::load(&manifest, &"0".repeat(64)).is_err());
		let release = Release::load(&manifest, &pin).unwrap();
		assert_eq!(release.images.len(), 10);
		assert_eq!(release.catalog, hia_contract::CATALOG_BYTES);
		assert!(!release.images.contains_key(JOB_RECEIPT));
		assert!(admitted_image(&release, WITNESS_PATH).is_none());
		let incomplete =
			serde_json::to_vec(&serde_json::json!({"schema":RECEIPT_SCHEMA,"files":pins})).unwrap();
		std::fs::write(&manifest, &incomplete).unwrap();
		assert!(Release::load(&manifest, &hia_contract::sha256(&incomplete)).is_err());
		std::fs::write(directory.join(JOB_RECEIPT), &image).unwrap();
		pins.insert(JOB_RECEIPT, hia_contract::sha256(&image));
		let complete =
			serde_json::to_vec(&serde_json::json!({"schema":RECEIPT_SCHEMA,"files":pins})).unwrap();
		std::fs::write(&manifest, &complete).unwrap();
		let complete_pin = hia_contract::sha256(&complete);
		assert!(Release::load(&manifest, &complete_pin)
			.unwrap()
			.images
			.contains_key(JOB_RECEIPT));
		let v3 =
			serde_json::to_vec(&serde_json::json!({"schema":WITNESS_SCHEMA,"files":pins})).unwrap();
		std::fs::write(&manifest, &v3).unwrap();
		let release_v3 = Release::load(&manifest, &hia_contract::sha256(&v3)).unwrap();
		assert!(admitted_image(&release_v3, WITNESS_PATH).is_some());
		assert!(!release_v3.images.contains_key(JOB_TERMINAL_RECEIPT));
		let incomplete_v4 =
			serde_json::to_vec(&serde_json::json!({"schema":TERMINAL_RECEIPT_SCHEMA,"files":pins}))
				.unwrap();
		std::fs::write(&manifest, &incomplete_v4).unwrap();
		assert!(Release::load(&manifest, &hia_contract::sha256(&incomplete_v4)).is_err());
		std::fs::write(directory.join(JOB_TERMINAL_RECEIPT), &image).unwrap();
		pins.insert(JOB_TERMINAL_RECEIPT, hia_contract::sha256(&image));
		let v4 =
			serde_json::to_vec(&serde_json::json!({"schema":TERMINAL_RECEIPT_SCHEMA,"files":pins}))
				.unwrap();
		std::fs::write(&manifest, &v4).unwrap();
		let release_v4 = Release::load(&manifest, &hia_contract::sha256(&v4)).unwrap();
		assert!(release_v4.images.contains_key(JOB_TERMINAL_RECEIPT));
		assert!(admitted_image(&release_v4, WITNESS_PATH).is_some());
		assert!(!release_v4.lifecycle_owner);
		let v5 =
			serde_json::to_vec(&serde_json::json!({"schema":LIFECYCLE_OWNER_SCHEMA,"files":pins}))
				.unwrap();
		std::fs::write(&manifest, &v5).unwrap();
		assert!(
			Release::load(&manifest, &hia_contract::sha256(&v5))
				.unwrap()
				.lifecycle_owner
		);
		let incomplete_v25 =
			serde_json::to_vec(&serde_json::json!({"schema":NATIVE_JOB_OWNER_SCHEMA,"files":pins}))
				.unwrap();
		std::fs::write(&manifest, &incomplete_v25).unwrap();
		assert!(Release::load(&manifest, &hia_contract::sha256(&incomplete_v25)).is_err());
		std::fs::write(directory.join(JOB_SUPERVISOR), &image).unwrap();
		pins.insert(JOB_SUPERVISOR, hia_contract::sha256(&image));
		let complete_v25 =
			serde_json::to_vec(&serde_json::json!({"schema":NATIVE_JOB_OWNER_SCHEMA,"files":pins}))
				.unwrap();
		std::fs::write(&manifest, &complete_v25).unwrap();
		let v25_pin = hia_contract::sha256(&complete_v25);
		let release_v25 = Release::load(&manifest, &v25_pin).unwrap();
		assert_eq!(release_v25.images.len(), 13);
		assert_eq!(release_v25.supervisor_protocol, 25);
		assert!(release_v25.lifecycle_owner);
		let supervisor = release_v25.terminal_artifacts.as_ref().unwrap();
		assert_eq!(
			supervisor["supervisor"]["sha256"],
			serde_json::Value::String(hia_contract::sha256(&image))
		);
		assert_eq!(
			supervisor["supervisor"]["hex"].as_str().unwrap().len(),
			image.len() * 2
		);
		let extra_v24 =
			serde_json::to_vec(&serde_json::json!({"schema":OWNER_CUSTODY_SCHEMA,"files":pins}))
				.unwrap();
		std::fs::write(&manifest, &extra_v24).unwrap();
		assert!(Release::load(&manifest, &hia_contract::sha256(&extra_v24)).is_err());
		std::fs::write(&manifest, &complete_v25).unwrap();
		std::fs::write(directory.join(JOB_SUPERVISOR), b"different").unwrap();
		assert!(Release::load(&manifest, &v25_pin).is_err());
		let sealed_supervisor = release_v25.images.get(JOB_SUPERVISOR).unwrap();
		let mut retained_supervisor = vec![0; image.len()];
		assert_eq!(
			sealed_supervisor
				.read_at(&mut retained_supervisor, 0)
				.unwrap(),
			image.len()
		);
		assert_eq!(retained_supervisor, image);
		std::fs::write(directory.join(JOB_TERMINAL_RECEIPT), b"different").unwrap();
		assert!(Release::load(&manifest, &hia_contract::sha256(&v5)).is_err());
		std::fs::write(&manifest, &v4).unwrap();
		assert!(Release::load(&manifest, &hia_contract::sha256(&v4)).is_err());
		std::fs::write(&manifest, &complete).unwrap();
		std::fs::write(directory.join(JOB_RECEIPT), b"different").unwrap();
		assert!(Release::load(&manifest, &complete_pin).is_err());
		std::fs::write(&manifest, &data).unwrap();
		let original = release.images.get(WORKER_PREPARE).unwrap();
		std::fs::write(directory.join(WORKER_PREPARE), b"different").unwrap();
		assert!(Release::load(&manifest, &pin).is_err());
		let mut stored = vec![0; image.len()];
		assert_eq!(original.read_at(&mut stored, 0).unwrap(), image.len());
		assert_eq!(stored, image);
		assert_eq!(
			release_name("HIA_LOCAL_MCP_JOB_PENDING_IMAGE"),
			Some(WORKER_PREPARE)
		);
		assert_eq!(
			release_name("HIA_LOCAL_MCP_PROOF_SCHEMA_IMAGE"),
			Some("hia-agent-mcp-proof-schema")
		);
		assert_eq!(release_name("HIA_LOCAL_MCP_USER_UNLISTED_IMAGE"), None);
	}
}
