// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Protocol bounds, exact byte/identity preservation and no resend after doubt.

use super::*;

fn options(socket: PathBuf) -> WeightClientArgs {
	WeightClientArgs {
		socket,
		session_id: "ws_012345678901234567890123".into(),
		worker_path: PathBuf::from("/tmp/weight/worker.py"),
		expected_worker_sha256: "a".repeat(64),
		expected_package_sha256: Some("b".repeat(64)),
		expected_client_sha256: "c".repeat(64),
		timeout_ms: 1000,
		connect_timeout_ms: 1000,
	}
}

fn request(session: &str) -> Vec<u8> {
	format!("{{\"id\":\"probe-1\",\"op\":\"probe\",\"session_id\":\"{session}\",\"params\":{{\"x\":[-0.0,1e-9],\"label\":\"中文\"}}}}\n").into_bytes()
}

#[test]
fn options_and_request_identity_do_not_expand_the_owner_contract() {
	let args = options(PathBuf::from("/tmp/weight/socket"));
	validate_options(&args).unwrap();
	assert_eq!(
		request_identity(&request(&args.session_id), &args.session_id).unwrap(),
		"probe-1"
	);
	assert!(request_identity(&request("other"), &args.session_id).is_err());
	let duplicate = format!("{{\"id\":\"probe-1\",\"op\":\"probe\",\"session_id\":\"{}\",\"params\":{{\"x\":1,\"x\":2}}}}\n",args.session_id);
	assert!(request_identity(duplicate.as_bytes(), &args.session_id).is_err());
	for wrong in ["../outside", "bad\nrequest", ""] {
		assert!(!valid_id(wrong));
	}
	let mut invalid = args.clone();
	invalid.socket = PathBuf::from("relative.sock");
	assert!(validate_options(&invalid).is_err());
	invalid = args.clone();
	invalid.expected_client_sha256 = "unpinned".into();
	assert!(validate_options(&invalid).is_err());
	invalid = args;
	invalid.connect_timeout_ms = 30_001;
	assert!(validate_options(&invalid).is_err());
}

#[tokio::test]
async fn framing_requires_one_bounded_newline_terminated_frame() {
	for bytes in [b"".as_slice(), b"{}", b"{}\n{}\n", b"{}\n ", b"12345678\n"] {
		let mut reader = bytes;
		assert!(read_frame(&mut reader, 8).await.is_err(), "{bytes:?}");
	}
	assert_eq!(
		read_frame(&mut b"{}\n".as_slice(), 3).await.unwrap(),
		b"{}\n"
	);
}

#[test]
fn response_requires_exact_id_unique_json_and_a_complete_envelope() {
	assert!(response_ok(b"{\"id\":\"r\",\"ok\":true,\"result\":{}}\n", "r").unwrap());
	assert!(!response_ok(b"{\"id\":\"r\",\"ok\":false,\"error\":{\"code\":\"X\",\"message\":\"m\",\"details\":{}}}\n", "r").unwrap());
	for bytes in [
		b"{\"id\":null,\"ok\":true,\"result\":{}}\n".as_slice(),
		b"{\"id\":\"other\",\"ok\":true,\"result\":{}}\n",
		b"{\"id\":\"r\",\"ok\":true}\n",
		b"{\"id\":\"r\",\"ok\":true,\"result\":{},\"error\":{}}\n",
		b"{\"id\":\"r\",\"ok\":true,\"result\":{\"x\":1,\"x\":2}}\n",
		b"{\"id\":\"r\",\"ok\":true,\"result\":{\"x\":1e999}}\n",
	] {
		assert!(response_ok(bytes, "r").is_err(), "{bytes:?}");
	}
	let error = ClientFailure::new("REQUEST_TIMEOUT_UNKNOWN", "deadline", true);
	let frame: serde_json::Value =
		serde_json::from_slice(&error.frame(Some("original")).unwrap()).unwrap();
	assert_eq!(frame["id"], "original");
	assert_eq!(frame["error"]["details"]["operation_state"], "unknown");
	assert_eq!(frame["error"]["details"]["automatic_retry"], false);
}

#[tokio::test]
async fn package_pin_matches_python_ascii_sorted_string_dictionary() {
	let temp = tempfile::tempdir().unwrap();
	let entry = temp.path().join("worker.py");
	tokio::fs::create_dir(temp.path().join("weight_runtime"))
		.await
		.unwrap();
	tokio::fs::write(&entry, b"worker\n").await.unwrap();
	tokio::fs::write(temp.path().join("weight_runtime/__init__.py"), b"init\n")
		.await
		.unwrap();
	tokio::fs::write(temp.path().join("weight_runtime/z.py"), b"z\n")
		.await
		.unwrap();
	tokio::fs::write(
		temp.path().join("weight_runtime/ignored.txt"),
		b"not source",
	)
	.await
	.unwrap();
	let (entry_sha, size) = hash_file(&entry, MAX_PACKAGE_BYTES).await.unwrap();
	let expected = format!("{{\"weight_runtime/__init__.py\":\"{}\",\"weight_runtime/z.py\":\"{}\",\"worker.py\":\"{entry_sha}\"}}",digest_hex(&Sha256::digest(b"init\n")),digest_hex(&Sha256::digest(b"z\n")));
	let actual = package_digest(&entry, &entry_sha, size).await.unwrap();
	assert_eq!(actual, digest_hex(&Sha256::digest(expected.as_bytes())));
	assert_eq!(
		ascii_json_string("a中😀\n\"").unwrap(),
		"\"a\\u4e2d\\ud83d\\ude00\\n\\\"\""
	);
	assert_eq!(ascii_json_string("\u{7f}").unwrap(), "\"\\u007f\"");
	assert!(hash_file(&entry, 2).await.is_err());
	tokio::fs::write(temp.path().join("weight_runtime/z.py"), b"changed\n")
		.await
		.unwrap();
	assert_ne!(
		package_digest(&entry, &entry_sha, size).await.unwrap(),
		actual
	);
}

#[cfg(unix)]
async fn socket() -> (
	tempfile::TempDir,
	WeightClientArgs,
	tokio::net::UnixListener,
) {
	use std::os::unix::fs::PermissionsExt;
	let temp = tempfile::Builder::new().prefix("hwn-").tempdir().unwrap();
	let args = options(temp.path().join("worker.sock"));
	let server = tokio::net::UnixListener::bind(&args.socket).unwrap();
	tokio::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o600))
		.await
		.unwrap();
	(temp, args, server)
}

#[cfg(unix)]
#[tokio::test]
async fn socket_exchange_preserves_request_and_response_bytes() {
	let (_temp, args, server) = socket().await;
	let frame = request(&args.session_id);
	let expected = frame.clone();
	let response = b"{\"id\":\"probe-1\",\"ok\":true,\"result\":{\"x\":[-0.0,1e-9],\"patch\":\"untouched\"}}\n";
	let task = tokio::spawn(async move {
		let (mut stream, _) = server.accept().await.unwrap();
		assert_eq!(
			read_frame(&mut stream, MAX_REQUEST_BYTES).await.unwrap(),
			expected
		);
		for part in response.chunks(7) {
			stream.write_all(part).await.unwrap();
		}
		stream.shutdown().await.unwrap();
	});
	let result = exchange(&args, &frame, "probe-1").await.unwrap();
	assert_eq!(result, response);
	task.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn socket_timeout_does_not_reconnect_or_resend_after_a_possible_effect() {
	let (_temp, mut args, server) = socket().await;
	args.timeout_ms = 35;
	let frame = request(&args.session_id);
	let task = tokio::spawn(async move {
		let (mut stream, _) = server.accept().await.unwrap();
		let seen = read_frame(&mut stream, MAX_REQUEST_BYTES).await.unwrap();
		assert!(!seen.is_empty());
		tokio::time::sleep(Duration::from_millis(90)).await;
		assert!(
			tokio::time::timeout(Duration::from_millis(80), server.accept())
				.await
				.is_err(),
			"client resent an uncertain operation"
		);
	});
	let error = exchange(&args, &frame, "probe-1").await.unwrap_err();
	assert_eq!(error.code, "REQUEST_TIMEOUT_UNKNOWN");
	assert!(error.uncertain);
	task.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn socket_protocol_failures_are_unknown_and_preserve_the_original_id() {
	for response in [
		b"{\"id\":\"wrong\",\"ok\":true,\"result\":{}}\n".to_vec(),
		b"{\"id\":\"probe-1\",\"ok\":true,\"result\":{}}\n{}\n".to_vec(),
		vec![b'x'; MAX_RESPONSE_BYTES + 1],
	] {
		let (_temp, args, server) = socket().await;
		let frame = request(&args.session_id);
		let task = tokio::spawn(async move {
			let (mut stream, _) = server.accept().await.unwrap();
			read_frame(&mut stream, MAX_REQUEST_BYTES).await.unwrap();
			let _ = stream.write_all(&response).await;
		});
		let error = exchange(&args, &frame, "probe-1").await.unwrap_err();
		assert_eq!(error.code, "PROTOCOL_ERROR");
		assert!(error.uncertain);
		let error: serde_json::Value =
			serde_json::from_slice(&error.frame(Some("probe-1")).unwrap()).unwrap();
		assert_eq!(error["id"], "probe-1");
		task.await.unwrap();
	}
}

#[cfg(unix)]
#[tokio::test]
async fn missing_or_nonprivate_socket_is_refused_before_sending() {
	use std::os::unix::fs::PermissionsExt;
	let (_temp, mut args, server) = socket().await;
	tokio::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o666))
		.await
		.unwrap();
	let error = connect(&args).await.unwrap_err();
	assert_eq!(error.code, "PEER_DENIED");
	assert!(!error.uncertain);
	drop(server);
	tokio::fs::remove_file(&args.socket).await.unwrap();
	args.connect_timeout_ms = 20;
	let error = connect(&args).await.unwrap_err();
	assert_eq!(error.code, "CONNECT_TIMEOUT");
	assert!(!error.uncertain);
}
