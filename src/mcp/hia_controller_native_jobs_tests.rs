// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Verify complete v26 admission and immutable shared native job images.

use super::*;
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;

struct Fixture {
	_directory: tempfile::TempDir,
	directory: PathBuf,
	image: Vec<u8>,
	pins: BTreeMap<&'static str, String>,
}

impl Fixture {
	fn new(native: bool) -> Self {
		let temporary = tempfile::tempdir().unwrap();
		let directory = temporary.path().canonicalize().unwrap();
		let mut image = vec![0; 80];
		image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
		image[16..20].copy_from_slice(&[2, 0, 62, 0]);
		let mut pins = BTreeMap::new();
		for name in FILTERS
			.map(|(_, name)| name)
			.into_iter()
			.chain([
				WORKER_PREPARE,
				CATALOG,
				JOB_RECEIPT,
				JOB_TERMINAL_RECEIPT,
				JOB_SUPERVISOR,
			])
			.chain(
				NATIVE_JOB_ROLES
					.iter()
					.filter(|_| native)
					.map(|(_, name, _)| *name),
			) {
			let data = if name == CATALOG {
				hia_contract::CATALOG_BYTES
			} else {
				&image
			};
			std::fs::write(directory.join(name), data).unwrap();
			pins.insert(name, hia_contract::sha256(data));
		}
		Self {
			_directory: temporary,
			directory,
			image,
			pins,
		}
	}

	fn manifest(&self, schema: &str, pins: &BTreeMap<&str, String>) -> (PathBuf, String) {
		let bytes = serde_json::to_vec(&serde_json::json!({"schema":schema,"files":pins})).unwrap();
		let path = self.directory.join("hia-controller.json");
		std::fs::write(&path, &bytes).unwrap();
		(path, hia_contract::sha256(&bytes))
	}

	fn load(&self) -> Release {
		let (path, pin) = self.manifest(NATIVE_JOB_TRANSPORT_SCHEMA, &self.pins);
		Release::load(&path, &pin).unwrap()
	}

	fn replace_image(&mut self, name: &'static str, length: usize) {
		let mut bytes = vec![0; length];
		bytes[..self.image.len()].copy_from_slice(&self.image);
		std::fs::write(self.directory.join(name), &bytes).unwrap();
		self.pins.insert(name, hia_contract::sha256(&bytes));
	}
}

#[test]
fn v26_requires_every_role_and_rejects_unknown_replacements() {
	let fixture = Fixture::new(true);
	assert_eq!(fixture.pins.len(), 19);
	let release = fixture.load();
	assert_eq!(release.images.len(), 18);
	assert_eq!(release.native_artifacts.len(), 8);
	assert_eq!(release.supervisor_protocol, 26);
	assert!(release.lifecycle_owner);
	for name in fixture.pins.keys() {
		let mut incomplete = fixture.pins.clone();
		incomplete.remove(name);
		let (path, pin) = fixture.manifest(NATIVE_JOB_TRANSPORT_SCHEMA, &incomplete);
		assert!(Release::load(&path, &pin).is_err(), "missing {name}");
		incomplete.insert("unlisted-role", fixture.pins[name].clone());
		let (path, pin) = fixture.manifest(NATIVE_JOB_TRANSPORT_SCHEMA, &incomplete);
		assert!(Release::load(&path, &pin).is_err(), "substituted {name}");
	}
	let mut extra = fixture.pins.clone();
	extra.insert("unlisted-role", "a".repeat(64));
	let (path, pin) = fixture.manifest(NATIVE_JOB_TRANSPORT_SCHEMA, &extra);
	assert!(Release::load(&path, &pin).is_err());
	let (path, pin) = fixture.manifest("hepta.hia.mcp.controller.v27", &fixture.pins);
	assert!(Release::load(&path, &pin).is_err());
}

#[test]
fn native_images_are_pinned_shared_and_independent_of_replaced_paths() {
	let fixture = Fixture::new(true);
	let release = fixture.load();
	for name in NATIVE_JOB_ROLES
		.iter()
		.map(|(_, name, _)| *name)
		.chain(NATIVE_JOB_HELPERS)
	{
		let pin = &fixture.pins[name];
		let first = release.native_job_artifact(name, pin).unwrap();
		assert_eq!(first.as_ref(), fixture.image.as_slice());
		assert_eq!(&release.native_job_pin(name).unwrap().sha256, pin);
		let second = release.native_job_artifact(name, pin).unwrap();
		assert!(Arc::ptr_eq(&first, &second));
		assert!(release.native_job_artifact(name, &"0".repeat(64)).is_err());
		std::fs::write(fixture.directory.join(name), b"replacement bytes").unwrap();
		let retained = release.native_job_artifact(name, pin).unwrap();
		assert!(Arc::ptr_eq(&first, &retained));
		assert_eq!(retained.as_ref(), fixture.image.as_slice());
	}
	let (path, pin) = fixture.manifest(NATIVE_JOB_TRANSPORT_SCHEMA, &fixture.pins);
	assert!(Release::load(&path, &pin).is_err());
	for name in [
		CATALOG,
		"hia-agent-mcp-request",
		"../hia-job-submit",
		"unknown",
	] {
		assert!(release.native_job_pin(name).is_err());
		assert!(release.native_job_artifact(name, &"a".repeat(64)).is_err());
	}
}

#[test]
fn first_native_reads_share_one_arc_and_never_move_the_descriptor_cursor() {
	let fixture = Fixture::new(true);
	let release = fixture.load();
	let name = "hia-job-observation";
	let pin = &fixture.pins[name];
	let mut descriptor = release.images[name].try_clone().unwrap();
	descriptor.seek(SeekFrom::Start(17)).unwrap();
	let observed = std::thread::scope(|scope| {
		let readers: Vec<_> = (0..8)
			.map(|_| scope.spawn(|| release.native_job_artifact(name, pin).unwrap()))
			.collect();
		readers
			.into_iter()
			.map(|reader| reader.join().unwrap())
			.collect::<Vec<_>>()
	});
	assert!(observed
		.iter()
		.all(|bytes| Arc::ptr_eq(&observed[0], bytes)));
	assert_eq!(descriptor.stream_position().unwrap(), 17);
	assert_eq!(observed[0].as_ref(), fixture.image.as_slice());
}

#[test]
fn native_cache_refuses_an_unsealed_descriptor_even_with_correct_bytes() {
	let fixture = Fixture::new(true);
	let mut release = fixture.load();
	let name = "hia-job-submit";
	release
		.images
		.insert(name, File::open(fixture.directory.join(name)).unwrap());
	assert!(release
		.native_job_artifact(name, &fixture.pins[name])
		.is_err());
	assert!(release.native_artifacts[name].bytes.get().is_none());
}

#[test]
fn native_roles_keep_individual_extent_caps_and_legacy_helper_caps() {
	for (name, limit) in NATIVE_JOB_ROLES
		.iter()
		.map(|(_, name, limit)| (*name, *limit))
		.chain(NATIVE_JOB_HELPERS.map(|name| (name, 1 << 20)))
	{
		let mut fixture = Fixture::new(true);
		fixture.replace_image(name, limit);
		let release = fixture.load();
		let retained = release
			.native_job_artifact(name, &fixture.pins[name])
			.unwrap();
		assert_eq!(retained.len(), limit, "exact cap for {name}");
		fixture.replace_image(name, limit + 1);
		let (path, pin) = fixture.manifest(NATIVE_JOB_TRANSPORT_SCHEMA, &fixture.pins);
		assert!(
			Release::load(&path, &pin).is_err(),
			"excess extent for {name}"
		);
	}
}

#[test]
fn legacy_controller_cannot_supply_native_transport_artifacts() {
	let fixture = Fixture::new(false);
	let (path, pin) = fixture.manifest(NATIVE_JOB_OWNER_SCHEMA, &fixture.pins);
	let release = Release::load(&path, &pin).unwrap();
	assert_eq!(release.supervisor_protocol, 25);
	assert!(release.native_artifacts.is_empty());
	for name in NATIVE_JOB_ROLES
		.iter()
		.map(|(_, name, _)| *name)
		.chain(NATIVE_JOB_HELPERS)
	{
		assert!(release.native_job_artifact(name, &"a".repeat(64)).is_err());
	}
	assert!(admitted_image(&release, "HIA_LOCAL_MCP_JOB_SUBMIT_IMAGE").is_none());
	assert!(admitted_image(&release, "HIA_LOCAL_MCP_JOB_PENDING_IMAGE").is_some());
}
