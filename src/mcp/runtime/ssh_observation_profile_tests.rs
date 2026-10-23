// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn exact_supported_config_has_no_dynamic_or_undeclared_inputs() {
	let known = Path::new("/private/known_hosts");
	let accepted = b"Host hepta-main\n HostName 127.0.0.1\n User test\n Port 22\n HostKeyAlias pinned-main\n UserKnownHostsFile /private/known_hosts\n GlobalKnownHostsFile /dev/null\n BatchMode yes\n ConnectTimeout 8\n ControlMaster no\n ForwardAgent no\n StrictHostKeyChecking yes\n";
	validate_config(accepted, known).unwrap();
	for line in [
		"Include /private/more",
		"Match exec /usr/bin/true",
		"ProxyJump main",
		"ProxyCommand /bin/true",
		"IdentityFile /private/key",
		"LocalCommand /bin/true",
		"UserKnownHostsFile /other/known_hosts",
		"GlobalKnownHostsFile /etc/ssh/ssh_known_hosts",
		"ForwardAgent yes",
		"StrictHostKeyChecking no",
		"Host !main",
		"Host hepta-*",
		"User ${USER}",
		"Hostname `command`",
		"User \"quoted\"",
	] {
		assert!(
			validate_config(
				format!("{}\n{line}\n", std::str::from_utf8(accepted).unwrap()).as_bytes(),
				known
			)
			.is_err(),
			"accepted {line}"
		);
	}
}

#[test]
fn exact_file_pins_reject_inplace_changes_symlinks_hardlinks_and_permissions() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("config");
	std::fs::write(&path, b"one").unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let (pin, _) = PinnedFile::load(&path, None, 1024, true, false).unwrap();
	pin.verify().unwrap();
	std::fs::write(&path, b"two").unwrap();
	assert!(pin.verify().is_err());
	let link = root.path().join("link");
	symlink(&path, &link).unwrap();
	assert!(PinnedFile::load(&link, None, 1024, true, false).is_err());
	std::fs::remove_file(&link).unwrap();
	std::fs::hard_link(&path, &link).unwrap();
	assert!(PinnedFile::load(&path, None, 1024, true, false).is_err());
	std::fs::remove_file(link).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(PinnedFile::load(&path, None, 1024, true, false).is_err());
}

#[test]
fn directory_identity_survives_owned_membership_but_detects_replacement() {
	let root = tempfile::tempdir().unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let before = private_directory(root.path()).unwrap();
	std::fs::write(root.path().join("owned"), b"bounded").unwrap();
	let after = private_directory(root.path()).unwrap();
	assert!(before.same_directory(&after));
	let other = tempfile::tempdir().unwrap();
	std::fs::set_permissions(other.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	assert!(!before.same_directory(&private_directory(other.path()).unwrap()));
}

#[test]
fn only_the_fixed_system_shell_alias_has_a_pinned_symlink_exception() {
	let (target, components) = fixed_shell_resolution().unwrap();
	assert_eq!(target, std::fs::canonicalize("/bin/sh").unwrap());
	assert!(components.iter().all(|node| node.stamp.uid == 0));
	let hash = digest(&std::fs::read(&target).unwrap())
		.iter()
		.map(|v| format!("{v:02x}"))
		.collect::<String>();
	let shell = PinnedShell::load(&hash).unwrap();
	shell.verify().unwrap();
	assert!(PinnedShell::load(&"0".repeat(64)).is_err());
	assert!(
		open_absolute(Path::new("/bin/sh"), false).is_err()
			|| std::fs::symlink_metadata("/bin/sh").unwrap().is_file()
	);
}

fn identities(key: &[u8]) -> Vec<u8> {
	let mut bytes = vec![12, 0, 0, 0, 1];
	bytes.extend_from_slice(&(key.len() as u32).to_be_bytes());
	bytes.extend_from_slice(key);
	bytes.extend_from_slice(&0u32.to_be_bytes());
	bytes
}

#[test]
fn agent_frames_are_bounded_exact_and_key_changes_are_not_socket_identity() {
	let first = identities(b"public-test-key-one");
	let second = identities(b"public-test-key-two");
	assert_ne!(
		agent_identities(&first).unwrap(),
		agent_identities(&second).unwrap()
	);
	for bad in [
		vec![],
		vec![5],
		vec![12, 0, 0, 0, 0],
		vec![12, 0, 0, 0, 65],
		first[..first.len() - 1].to_vec(),
	] {
		assert!(agent_identities(&bad).is_err());
	}
	let mut extra = first;
	extra.push(0);
	assert!(agent_identities(&extra).is_err());
	for path in [
		"relative",
		"/private/../socket",
		"/private/./socket",
		"/private/%h",
		"/private/a b",
		"/private/${UNDECLARED}/socket",
		"/private/`command`",
		"/private/\"quoted\"",
		"/private/back\\slash",
	] {
		assert!(absolute(Path::new(path)).is_err());
	}
}

#[tokio::test]
async fn direct_agent_identity_includes_response_bytes_and_rejects_replaced_socket() {
	let root = tempfile::tempdir().unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let path = root.path().join("agent");
	let listener = tokio::net::UnixListener::bind(&path).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775)).unwrap();
	let server = tokio::spawn(async move {
		for key in [b"key-one".as_slice(), b"key-two".as_slice()] {
			let (mut stream, _) = listener.accept().await.unwrap();
			let mut request = [0; 5];
			stream.read_exact(&mut request).await.unwrap();
			assert_eq!(request, [0, 0, 0, 1, 11]);
			let response = identities(key);
			stream
				.write_all(&(response.len() as u32).to_be_bytes())
				.await
				.unwrap();
			stream.write_all(&response).await.unwrap();
		}
	});
	let first = agent_snapshot(&path, Instant::now() + std::time::Duration::from_secs(2))
		.await
		.unwrap();
	let second = agent_snapshot(&path, Instant::now() + std::time::Duration::from_secs(2))
		.await
		.unwrap();
	assert_eq!(first.stamp, second.stamp);
	assert_ne!(first, second);
	server.await.unwrap();
	std::fs::remove_file(&path).unwrap();
	std::fs::write(&path, b"not a socket").unwrap();
	assert!(
		agent_snapshot(&path, Instant::now() + std::time::Duration::from_secs(1))
			.await
			.is_err()
	);
}
