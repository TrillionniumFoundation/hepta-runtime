// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Deterministic initial control-socket publication and ownership regressions.
use super::*;

fn listener_fixture() -> (
	tempfile::TempDir,
	PathBuf,
	PathBuf,
	tokio::net::UnixListener,
) {
	let root = tempfile::tempdir().unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let temporary = root.path().join("control.temporary");
	let socket = root.path().join("control");
	let listener = tokio::net::UnixListener::bind(&temporary).unwrap();
	std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
	std::fs::hard_link(&temporary, &socket).unwrap();
	(root, temporary, socket, listener)
}

#[tokio::test(flavor = "current_thread")]
async fn initial_socket_waits_for_temporary_link_removal_before_exact_proof() {
	let (_root, temporary, socket, _listener) = listener_fixture();
	let before = profile::socket_stamp(&socket).unwrap();
	assert_eq!(before.link_count(), 2);
	assert!(master_socket_readiness(&socket, std::process::id())
		.await
		.unwrap()
		.is_none());
	let probe = UnixStream::connect(&socket).await.unwrap();
	let original_peer = profile::peer(&probe).unwrap();
	assert_eq!(original_peer.0, std::process::id() as i32);
	assert_eq!(original_peer.1, unsafe { libc::geteuid() });
	std::fs::remove_file(&temporary).unwrap();
	let after = profile::socket_stamp(&socket).unwrap();
	assert_eq!(after.link_count(), 1);
	assert_eq!((before.dev, before.ino), (after.dev, after.ino));
	assert_eq!(profile::peer(&probe).unwrap(), original_peer);
	assert_ne!(
		before, after,
		"the original full-stamp check rejects this publication"
	);
	let ready = master_socket_readiness(&socket, std::process::id())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(ready, after);
	assert_eq!(profile::socket_stamp(&socket).unwrap(), ready);
}

#[tokio::test(flavor = "current_thread")]
async fn initial_socket_rejects_extra_links_and_wrong_owned_peer() {
	let (root, temporary, socket, _listener) = listener_fixture();
	let third = root.path().join("third");
	std::fs::hard_link(&socket, &third).unwrap();
	assert!(master_socket_readiness(&socket, std::process::id())
		.await
		.unwrap_err()
		.to_string()
		.contains("unexpected link count"));
	std::fs::remove_file(&third).unwrap();
	std::fs::remove_file(&temporary).unwrap();
	assert!(
		master_socket_readiness(&socket, std::process::id().wrapping_add(1))
			.await
			.unwrap_err()
			.to_string()
			.contains("not the owned master")
	);
	assert!(master_socket_readiness(&socket, std::process::id())
		.await
		.unwrap()
		.is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn initial_two_link_socket_stays_unadmitted_until_original_deadline() {
	let (_root, _temporary, socket, listener) = listener_fixture();
	let original = profile::socket_stamp(&socket).unwrap();
	let deadline = Instant::now() + Duration::from_millis(60);
	let result = timeout_at(deadline, async {
		loop {
			if master_socket_readiness(&socket, std::process::id())
				.await?
				.is_some()
			{
				return Ok::<(), anyhow::Error>(());
			}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	})
	.await;
	assert!(result.is_err());
	assert_eq!(profile::socket_stamp(&socket).unwrap(), original);
	assert!(timeout(Duration::from_millis(10), listener.accept())
		.await
		.is_err());
}
