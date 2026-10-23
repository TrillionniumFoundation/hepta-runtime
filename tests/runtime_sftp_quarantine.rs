// Copyright 2026 Muvon Un Limited
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

//! Runtime-mode SFTP containment regression tests. These do not contact an SSH host.

use hepta_runtime::mcp::fs::remote::{self, parse_path_source, SftpPool, SshConfig};
use hepta_runtime::mcp::runtime::{config, init_runtime, RuntimeConfig};
use serde_json::json;

const DENIAL: &str = "remote SFTP file I/O is quarantined in runtime mode";

#[tokio::test]
async fn configured_remote_file_roots_never_authorize_unconfined_sftp() {
	let state = tempfile::tempdir().expect("isolated controller state");
	let policy: RuntimeConfig = serde_json::from_value(json!({
		"state_dir": state.path().join("state"),
		"hosts": {
			"locked": {
				"ssh_target": "locked",
				"allowed_read_path_prefixes": ["/srv/allowed"],
				"allowed_write_path_prefixes": ["/srv/allowed"],
				"allow_write": true
			}
		}
	}))
	.expect("runtime policy fixture");
	init_runtime(policy).expect("isolated test executable initializes runtime once");
	remote::init_sftp_pool(SshConfig::default());

	let source = parse_path_source("ssh://locked/srv/allowed/linked/secret.txt");
	for write in [false, true] {
		let error = config::check_remote_path(
			"locked",
			"/srv/allowed/linked/secret.txt",
			false,
			false,
			write,
		)
		.expect_err("lexical allowlist alone cannot qualify a remote SFTP effect");
		assert!(error.to_string().contains(DENIAL), "{error:#}");
	}

	// The pool must deny *before* any host resolution, authentication,
	// cached-session reuse or actual SFTP operation.
	let pool = SftpPool::new(SshConfig::default());
	let error = match pool
		.get_or_connect("locked", 22, "never-authenticate", false, false)
		.await
	{
		Ok(_) => panic!("raw pool access must not bypass runtime policy"),
		Err(error) => error,
	};
	assert!(error.to_string().contains(DENIAL), "{error:#}");

	// Exercise every public unified I/O path, including the mutation
	// surfaces used by editors, copy/move and directory tools.
	let errors = [
		remote::io_read_to_string(&source).await.unwrap_err().to_string(),
		remote::io_read(&source).await.unwrap_err().to_string(),
		remote::io_write(&source, b"must-not-be-written")
			.await
			.unwrap_err()
			.to_string(),
		remote::io_exists(&source).await.unwrap_err().to_string(),
		remote::io_is_dir(&source).await.unwrap_err().to_string(),
		remote::io_is_file(&source).await.unwrap_err().to_string(),
		remote::io_metadata(&source).await.unwrap_err().to_string(),
		remote::io_create_dir_all(&source)
			.await
			.unwrap_err()
			.to_string(),
		remote::io_remove_file(&source).await.unwrap_err().to_string(),
		remote::io_canonicalize(&source).await.unwrap_err().to_string(),
		remote::io_list_dir(&source).await.unwrap_err().to_string(),
	];
	for error in errors {
		assert!(error.contains(DENIAL), "unexpected SFTP denial: {error}");
	}
}

#[cfg(unix)]
#[test]
fn lexical_remote_root_does_not_imply_physical_containment() {
	use std::os::unix::fs::symlink;
	let tree = tempfile::tempdir().expect("filesystem fixture");
	let allowed = tree.path().join("allowed");
	let outside = tree.path().join("outside");
	std::fs::create_dir(&allowed).expect("allowed");
	std::fs::create_dir(&outside).expect("outside");
	symlink(&outside, allowed.join("linked")).expect("intermediate symlink");
	let path = allowed.join("linked/secret.txt");

	assert!(path.starts_with(&allowed), "lexical path appears inside root");
	std::fs::write(&path, b"fixture").expect("POSIX follows intermediate symlink");
	assert!(
		!path
			.canonicalize()
			.expect("actual target")
			.starts_with(allowed.canonicalize().expect("actual root")),
		"remote SFTP prefix matching cannot prove destination isolation"
	);
	assert_eq!(
		std::fs::read(outside.join("secret.txt")).expect("outside marker"),
		b"fixture"
	);
}
