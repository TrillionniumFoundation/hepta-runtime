// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Compare real Python observations with the complete general-purpose helper.

use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

fn run_source(source: &str, input: &Value, directory: &Path) -> (bool, Vec<u8>, Vec<u8>) {
	// An empty fixture cwd and isolated Python prevent omitted dependencies from
	// being silently loaded from a neighboring checkout. Only fixed source is code.
	let mut stdout = tempfile::tempfile().unwrap();
	let mut stderr = tempfile::tempfile().unwrap();
	let mut child = Command::new("python3")
		.args(["-I", "-S", "-c", source])
		.current_dir(directory)
		.stdin(Stdio::piped())
		.stdout(Stdio::from(stdout.try_clone().unwrap()))
		.stderr(Stdio::from(stderr.try_clone().unwrap()))
		.spawn()
		.unwrap();
	child
		.stdin
		.take()
		.unwrap()
		.write_all(&serde_json::to_vec(input).unwrap())
		.unwrap();
	let deadline = Instant::now() + Duration::from_secs(10);
	let status = loop {
		if let Some(status) = child.try_wait().unwrap() {
			break status;
		}
		if Instant::now() >= deadline {
			child.kill().unwrap();
			child.wait().unwrap();
			panic!("binary observation source fixture deadline");
		}
		std::thread::sleep(Duration::from_millis(5));
	};
	stdout.seek(SeekFrom::Start(0)).unwrap();
	stderr.seek(SeekFrom::Start(0)).unwrap();
	let mut out = Vec::new();
	let mut err = Vec::new();
	stdout.take(128 * 1024 + 1).read_to_end(&mut out).unwrap();
	stderr.take(4097).read_to_end(&mut err).unwrap();
	assert!(out.len() <= 128 * 1024 && err.len() <= 4096);
	(status.success(), out, err)
}

fn compare(input: &Value, directory: &Path, success: bool) -> Vec<u8> {
	let original = run_source(SOURCE, input, directory);
	let observed = run_source(observation_source(), input, directory);
	assert_eq!(observed, original, "input: {input}");
	assert_eq!(
		observed.0,
		success,
		"stderr: {}",
		String::from_utf8_lossy(&observed.2)
	);
	if success {
		assert!(observed.2.is_empty());
	} else {
		assert!(observed.1.is_empty());
		assert!(!observed.2.is_empty());
	}
	observed.1
}

fn digest(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

#[test]
fn observation_source_omits_only_unused_inode_patch_code() {
	assert_eq!(
		SOURCE,
		concat!(
			include_str!("file_metadata.py"),
			"\n",
			include_str!("inode_patch.py"),
			"\n",
			include_str!("binary_file.py")
		)
	);
	assert_eq!(
		SOURCE.len() - observation_source().len(),
		include_str!("inode_patch.py").len() + 1
	);
	assert!(SOURCE.contains("def inode_patch("));
	assert!(!observation_source().contains("def inode_patch("));
}

#[test]
fn shorter_observation_source_preserves_real_info_and_bounded_read_bytes() {
	let fixture = tempfile::tempdir().unwrap();
	let root = fixture.path().canonicalize().unwrap();
	let path = root.join("payload-中文'\".bin");
	let bytes: Vec<u8> = (0..70_001).map(|index| (index % 251) as u8).collect();
	std::fs::write(&path, &bytes).unwrap();
	let info: Value = serde_json::from_slice(&compare(
		&json!({"op":"info","root":root,"path":path}),
		&root,
		true,
	))
	.unwrap();
	assert_eq!(info["size"], bytes.len());
	assert_eq!(info["sha256"], digest(&bytes));
	assert!(info["metadata"].is_object());
	assert!(info["metadata"]["acl_sha256"].is_string());
	let version = info["version"].as_str().unwrap();
	for (offset, limit) in [
		(0usize, 32768usize),
		(13, 65536),
		(70_000, 65536),
		(70_001, 1),
	] {
		let value: Value = serde_json::from_slice(&compare(
			&json!({"op":"read","root":root,"path":path,"offset":offset,
				"limit":limit,"expected_version":version}),
			&root,
			true,
		))
		.unwrap();
		let end = (offset + limit).min(bytes.len());
		assert_eq!(value["version"], version);
		assert_eq!(value["offset"], offset);
		assert_eq!(value["next_offset"], end);
		assert_eq!(value["eof"], end == bytes.len());
		assert_eq!(value["chunk_sha256"], digest(&bytes[offset..end]));
		assert_eq!(
			value["data_base64"].as_str().unwrap().len(),
			4 * (end - offset).div_ceil(3)
		);
	}
	assert_eq!(std::fs::read(&path).unwrap(), bytes);
	assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
}

#[test]
fn shorter_observation_source_preserves_version_cursor_and_path_refusals() {
	let fixture = tempfile::tempdir().unwrap();
	let base = fixture.path().canonicalize().unwrap();
	let root = base.join("allowed");
	std::fs::create_dir(&root).unwrap();
	let path = root.join("payload.bin");
	std::fs::write(&path, b"abc").unwrap();
	let link = root.join("link.bin");
	std::os::unix::fs::symlink(&path, &link).unwrap();
	let directory = root.join("directory");
	std::fs::create_dir(&directory).unwrap();
	for input in [
		json!({"op":"read","root":root,"path":path,"expected_version":"stale"}),
		json!({"op":"read","root":root,"path":path,"offset":4}),
		json!({"op":"read","root":root,"path":link}),
		json!({"op":"info","root":root,"path":directory}),
		json!({"op":"info","root":root,"path":root.join("missing")}),
		json!({"op":"read","root":root,"path":base.join("outside")}),
		json!({"op":"info","root":root,"path":root}),
		json!({"op":"read","root":root,"path":root.join(".hepta-private")}),
	] {
		compare(&input, &base, false);
	}
	assert_eq!(std::fs::read(&path).unwrap(), b"abc");
	assert_eq!(std::fs::read_dir(&root).unwrap().count(), 3);
}
