// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Library builds without remote-fs must reject remote I/O and preserve local I/O.

use super::*;

#[tokio::test]
async fn remote_operations_reject_both_schemes_without_touching_local_files() {
	const CHILD: &str = "HEPTA_REMOTE_FS_UNAVAILABLE_TEST_CHILD";
	if std::env::var_os(CHILD).is_none() {
		let output = tokio::process::Command::new(std::env::current_exe().unwrap())
			.args([
				concat!(
					"mcp::fs::remote::remote_unavailable_tests::",
					"remote_operations_reject_both_schemes_without_touching_local_files"
				),
				"--exact",
				"--test-threads=1",
			])
			.env(CHILD, "1")
			.output()
			.await
			.unwrap();
		assert!(
			output.status.success(),
			"{}\n{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
		return;
	}

	let directory = tempfile::tempdir().unwrap();
	// Own the real configuration only in this single-test child; never reset
	// the production OnceLock or mutate the parent test process's environment.
	#[cfg(unix)]
	{
		use crate::mcp::runtime::config::{check_remote_write, init_runtime, RuntimeConfig};
		let config: RuntimeConfig = serde_json::from_value(serde_json::json!({
			"state_dir": directory.path(),
			"hosts": {"registered": {
				"ssh_target": "configured-peer.invalid",
				"remote_state_dir": "/remote-unavailable-fixture"
			}}
		}))
		.unwrap();
		init_runtime(config).unwrap();
		assert!(
			check_remote_write("not-configured.invalid", "/sentinel.txt")
				.unwrap_err()
				.to_string()
				.contains("unregistered SSH host")
		);
	}
	let file = directory.path().join("sentinel.txt");
	let untouched = b"original local contents";
	tokio::fs::write(&file, untouched).await.unwrap();

	for scheme in ["ssh", "sftp"] {
		let source = parse_path_source(&format!(
			"{scheme}://not-configured.invalid/{}",
			file.to_string_lossy()
				.replace('\\', "/")
				.trim_start_matches('/')
		));
		assert!(source.is_remote());
		let direct = [
			("read", remote_read(&source).await.map(|_| ())),
			(
				"read text",
				remote_read_to_string(&source).await.map(|_| ()),
			),
			("write", remote_write(&source, b"must not be written").await),
			("exists", remote_exists(&source).await.map(|_| ())),
			("metadata", remote_metadata(&source).await.map(|_| ())),
			("mkdir", remote_create_dir_all(&source).await),
			("remove", remote_remove_file(&source).await),
			("list", remote_list_dir(&source).await.map(|_| ())),
			(
				"canonicalize",
				remote_canonicalize(&source).await.map(|_| ()),
			),
		];
		for (operation, result) in direct {
			assert_eq!(
				result.unwrap_err().to_string(),
				"remote filesystem support requires the remote-fs feature",
				"{scheme} direct {operation}"
			);
		}

		let unified = [
			("read", io_read(&source).await.map(|_| ())),
			("read text", io_read_to_string(&source).await.map(|_| ())),
			("write", io_write(&source, b"must not be written").await),
			("exists", io_exists(&source).await.map(|_| ())),
			("is directory", io_is_dir(&source).await.map(|_| ())),
			("is file", io_is_file(&source).await.map(|_| ())),
			("metadata", io_metadata(&source).await.map(|_| ())),
			("mkdir", io_create_dir_all(&source).await),
			("remove", io_remove_file(&source).await),
			("list", io_list_dir(&source).await.map(|_| ())),
			("canonicalize", io_canonicalize(&source).await.map(|_| ())),
		];
		for (operation, result) in unified {
			assert_eq!(
				result.unwrap_err().to_string(),
				"remote filesystem support requires the remote-fs feature",
				"{scheme} unified {operation}"
			);
		}
		assert_eq!(tokio::fs::read(&file).await.unwrap(), untouched);
	}
}

#[tokio::test]
async fn local_io_remains_available_without_remote_filesystem_support() {
	let directory = tempfile::tempdir().unwrap();
	let nested = PathSource::Local(directory.path().join("nested"));
	io_create_dir_all(&nested).await.unwrap();
	assert!(io_is_dir(&nested).await.unwrap());
	let file = PathSource::Local(directory.path().join("nested/value.txt"));
	assert!(!io_exists(&file).await.unwrap());
	io_write(&file, b"local value").await.unwrap();
	assert_eq!(io_read(&file).await.unwrap(), b"local value");
	assert_eq!(io_read_to_string(&file).await.unwrap(), "local value");
	assert!(io_exists(&file).await.unwrap());
	assert!(io_is_file(&file).await.unwrap());
	assert!(!io_is_dir(&file).await.unwrap());
	let metadata = io_metadata(&file).await.unwrap();
	assert_eq!(metadata.size, 11);
	assert!(metadata.is_file);
	assert!(!metadata.is_dir);
	assert_eq!(
		io_canonicalize(&file).await.unwrap(),
		tokio::fs::canonicalize(directory.path().join("nested/value.txt"))
			.await
			.unwrap()
	);
	io_remove_file(&file).await.unwrap();
	assert!(!io_exists(&file).await.unwrap());
}
