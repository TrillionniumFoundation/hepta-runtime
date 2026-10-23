// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
use super::*;
use sha2::Digest;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn profile_hashes_keep_standard_sha256_bytes() {
	for (bytes, expected) in [
		(
			b"".as_slice(),
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		),
		(
			b"abc".as_slice(),
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		),
	] {
		assert_eq!(digest(bytes), hex_digest(expected).unwrap());
	}
	for length in [
		1, 55, 56, 63, 64, 65, 4095, 4096, 16383, 16384, 16385, 262151,
	] {
		let bytes: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
		let reference: [u8; 32] = sha2::Sha256::digest(&bytes).into();
		assert_eq!(digest(&bytes), reference);
	}
}

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
fn streamed_pins_check_every_chunk_and_the_partial_tail() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("large-pin");
	let mut bytes: Vec<u8> = (0..VERIFY_BUFFER_BYTES * 13 + 7)
		.map(|index| (index % 251) as u8)
		.collect();
	std::fs::write(&path, &bytes).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let (mut pin, _) = PinnedFile::load(&path, None, bytes.len(), true, false).unwrap();
	pin.verify().unwrap();
	for position in [
		0,
		VERIFY_BUFFER_BYTES - 1,
		VERIFY_BUFFER_BYTES * 7,
		bytes.len() - 1,
	] {
		bytes[position] ^= 1;
		std::fs::write(&path, &bytes).unwrap();
		// Isolate byte verification from the independent metadata fence.
		pin.stamp = Stamp::of(&std::fs::metadata(&path).unwrap());
		assert!(pin.verify().is_err(), "missed changed byte {position}");
		bytes[position] ^= 1;
		std::fs::write(&path, &bytes).unwrap();
		pin.stamp = Stamp::of(&std::fs::metadata(&path).unwrap());
		pin.verify().unwrap();
	}
}

#[test]
fn streamed_pins_keep_length_and_path_identity_fences() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("pin");
	let bytes = vec![7; VERIFY_BUFFER_BYTES + 3];
	std::fs::write(&path, &bytes).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let (pin, _) = PinnedFile::load(&path, None, bytes.len(), true, false).unwrap();
	for length in [bytes.len() - 1, bytes.len() + 1] {
		std::fs::OpenOptions::new()
			.write(true)
			.open(&path)
			.unwrap()
			.set_len(length as u64)
			.unwrap();
		assert!(pin.verify().is_err());
	}
	std::fs::rename(&path, root.path().join("original")).unwrap();
	std::fs::write(&path, &bytes).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	assert!(pin.verify().is_err());
	let target = root.path().join("target");
	std::fs::rename(&path, &target).unwrap();
	symlink(&target, &path).unwrap();
	assert!(pin.verify().is_err());
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
