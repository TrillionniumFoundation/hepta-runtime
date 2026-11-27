// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Installed controller role custody and sealed-byte regression tests.

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
	let v5 = serde_json::to_vec(&serde_json::json!({"schema":LIFECYCLE_OWNER_SCHEMA,"files":pins}))
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
