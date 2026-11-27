// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! HTTP authority must not depend on enabling the remote runtime tool set.

use super::{load_http_auth, parse_loopback_http_bind};

#[test]
fn http_mcp_denies_missing_auth_on_every_platform() {
	assert!(load_http_auth(None).is_err());
}

#[test]
fn http_mcp_accepts_only_loopback_ip_listeners() {
	for addr in ["127.0.0.1:12345", "127.0.0.2:12345", "[::1]:12345"] {
		assert!(parse_loopback_http_bind(addr).is_ok(), "{addr}");
	}
	for addr in [
		"0.0.0.0:12345",
		"[::]:12345",
		"192.168.1.2:12345",
		"10.0.0.42:12345",
		"invalid:12345",
	] {
		assert!(parse_loopback_http_bind(addr).is_err(), "{addr}");
	}
}

#[cfg(unix)]
fn private_token(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
	use std::os::unix::fs::PermissionsExt;
	std::fs::write(path, bytes)?;
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
	Ok(())
}

#[cfg(unix)]
#[test]
fn http_auth_accepts_private_regular_token_and_one_trailing_newline() -> anyhow::Result<()> {
	let temp = tempfile::tempdir()?;
	let path = temp.path().join("auth.token");
	private_token(&path, b"0123456789abcdef0123456789abcdef\n")?;
	assert!(load_http_auth(Some(&path)).is_ok());
	Ok(())
}

#[cfg(unix)]
#[test]
fn http_auth_rejects_nonprivate_and_linked_tokens() -> anyhow::Result<()> {
	use std::os::unix::fs::PermissionsExt;
	let temp = tempfile::tempdir()?;
	let path = temp.path().join("auth.token");
	private_token(&path, b"0123456789abcdef0123456789abcdef")?;
	for mode in [0o640, 0o604, 0o666] {
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
		assert!(load_http_auth(Some(&path)).is_err(), "mode {mode:o}");
	}
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
	let alias = temp.path().join("alias");
	std::os::unix::fs::symlink(&path, &alias)?;
	assert!(load_http_auth(Some(&alias)).is_err());
	std::fs::remove_file(&alias)?;
	std::fs::hard_link(&path, &alias)?;
	assert!(load_http_auth(Some(&path)).is_err());
	assert!(load_http_auth(Some(&alias)).is_err());
	Ok(())
}

#[cfg(unix)]
#[test]
fn http_auth_bounds_token_file_reads_and_rejects_nonfiles() -> anyhow::Result<()> {
	let temp = tempfile::tempdir()?;
	let path = temp.path().join("auth.token");
	private_token(&path, &[b'x'; 4096])?;
	assert!(load_http_auth(Some(&path)).is_ok());
	private_token(&path, &[b'x'; 4098])?;
	assert!(load_http_auth(Some(&path)).is_err());
	private_token(&path, b"short")?;
	assert!(load_http_auth(Some(&path)).is_err());
	assert!(load_http_auth(Some(temp.path())).is_err());
	Ok(())
}

#[tokio::test]
async fn http_startup_without_runtime_config_still_requires_auth() {
	let result = super::run_http_server("127.0.0.1:0", None).await;
	assert!(result.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn http_startup_without_runtime_config_denies_public_listener() -> anyhow::Result<()> {
	let temp = tempfile::tempdir()?;
	let path = temp.path().join("auth.token");
	private_token(&path, b"0123456789abcdef0123456789abcdef")?;
	assert!(super::run_http_server("0.0.0.0:0", Some(&path))
		.await
		.is_err());
	Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn http_middleware_requires_token_denies_origin_and_preserves_scope() -> anyhow::Result<()> {
	use axum::{http::StatusCode, routing::get, Extension, Router};
	use hepta_runtime::mcp::runtime::caller_scope::AuthenticatedOperatorScope;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	let temp = tempfile::tempdir()?;
	let token_path = temp.path().join("auth.token");
	private_token(&token_path, b"0123456789abcdef0123456789abcdef")?;
	let router = Router::new()
		.route(
			"/mcp",
			get(
				|Extension(_): Extension<AuthenticatedOperatorScope>| async {
					StatusCode::NO_CONTENT
				},
			),
		)
		.layer(axum::middleware::from_fn_with_state(
			load_http_auth(Some(&token_path))?,
			super::require_http_auth,
		));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let address = listener.local_addr()?;
	let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
	let owner = tokio::spawn(async move {
		axum::serve(listener, router)
			.with_graceful_shutdown(async {
				let _ = stop_rx.await;
			})
			.await
	});
	for (headers, status) in [
		("", "401"),
		("X-Hepta-Runtime-Token: incorrect\r\n", "401"),
		("X-Hepta-Runtime-Token: 0123456789abcdef0123456789abcdef\r\n", "204"),
		(
			"X-Hepta-Runtime-Token: 0123456789abcdef0123456789abcdef\r\nOrigin: https://example.invalid\r\n",
			"403",
		),
	] {
		let response = tokio::time::timeout(std::time::Duration::from_secs(5), async {
			let mut stream = tokio::net::TcpStream::connect(address).await?;
			stream
				.write_all(
					format!("GET /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\r\n")
						.as_bytes(),
				)
				.await?;
			let mut response = String::new();
			stream.read_to_string(&mut response).await?;
			Ok::<_, std::io::Error>(response)
		})
		.await??;
		assert!(response.starts_with(&format!("HTTP/1.1 {status} ")));
	}
	let _ = stop_tx.send(());
	tokio::time::timeout(std::time::Duration::from_secs(5), owner).await???;
	Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct NativeWireFixture {
	_directory: tempfile::TempDir,
	token: std::path::PathBuf,
	original: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl NativeWireFixture {
	fn new(raw: &str) -> anyhow::Result<Self> {
		use sha2::{Digest, Sha256};
		use std::os::unix::fs::PermissionsExt;
		let directory = tempfile::tempdir()?;
		let token = directory.path().join("auth.token");
		private_token(&token, b"0123456789abcdef0123456789abcdef")?;
		// This executable emits one fixed descriptor, not a parser. The original
		// whitespace fixes its offsets, so reserializing the HTTP request fails.
		let mut descriptor = vec![0_u8; 96];
		for (offset, value) in [
			(0, 88),
			(16, 5),
			(32, (raw.find("\"id\": 7").unwrap() + 6) as u64),
			(40, 1),
			(64, 1), // hia_describe is the first native tool ordinal.
			(72, raw.rfind("{}").unwrap() as u64),
			(80, 2),
		] {
			descriptor[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
		}
		descriptor[8..16].copy_from_slice(b"HIAMCP01");
		let mut image = vec![0_u8; 120];
		image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
		for (offset, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
			image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
		}
		for (offset, value) in [(20, 1_u32), (64, 1), (68, 5)] {
			image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
		}
		for (offset, value) in [
			(24, 0x400000_u64 + 120),
			(32, 64),
			(80, 0x400000),
			(88, 0x400000),
			(96, 252),
			(104, 252),
			(112, 4096),
		] {
			image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
		}
		image.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x48, 0xbe]);
		image.extend_from_slice(&(0x400000_u64 + 156).to_le_bytes());
		image.extend_from_slice(&[
			0xba, 96, 0, 0, 0, 0x0f, 0x05, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05,
		]);
		image.extend_from_slice(&descriptor);
		assert_eq!(image.len(), 252);
		let executable = directory.path().join("wire-descriptor-fixture");
		std::fs::write(&executable, &image)?;
		std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500))?;
		let settings = [
			("HIA_LOCAL_MCP_WIRE_IMAGE", executable.into_os_string()),
			(
				"HIA_LOCAL_MCP_WIRE_SHA256",
				std::ffi::OsString::from(format!("{:x}", Sha256::digest(&image))),
			),
		];
		let original = settings
			.iter()
			.map(|(key, _)| (*key, std::env::var_os(key)))
			.collect();
		for (key, value) in settings {
			std::env::set_var(key, value);
		}
		Ok(Self {
			_directory: directory,
			token,
			original,
		})
	}
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for NativeWireFixture {
	fn drop(&mut self) {
		for (key, value) in &self.original {
			if let Some(value) = value {
				std::env::set_var(key, value);
			} else {
				std::env::remove_var(key);
			}
		}
	}
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
async fn post_native_http(
	address: std::net::SocketAddr,
	body: &str,
	session: Option<&str>,
) -> anyhow::Result<String> {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let session_header = session.map_or_else(String::new, |id| format!("Mcp-Session-Id: {id}\r\n"));
	let header = format!(
		"POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
		X-Hepta-Runtime-Token: 0123456789abcdef0123456789abcdef\r\n\
		Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
		MCP-Protocol-Version: 2025-11-25\r\n{session_header}Content-Length: {}\r\n\r\n",
		body.len()
	);
	let response = tokio::time::timeout(std::time::Duration::from_secs(10), async {
		let mut stream = tokio::net::TcpStream::connect(address).await?;
		stream.write_all(header.as_bytes()).await?;
		stream.write_all(body.as_bytes()).await?;
		let mut response = String::new();
		stream.read_to_string(&mut response).await?;
		Ok::<_, std::io::Error>(response)
	})
	.await??;
	Ok(response)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
async fn authenticated_http_hia_tools_admit_original_wire_and_reject_mismatches(
) -> anyhow::Result<()> {
	use rmcp::transport::streamable_http_server::{
		session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
	};
	let raw = "{\"jsonrpc\":\"2.0\", \"id\": 7,\"method\":\"tools/call\", \"params\":{\"name\":\"hia_describe\", \"arguments\":{}}}";
	let fixture = NativeWireFixture::new(raw)?;
	let cancel = tokio_util::sync::CancellationToken::new();
	let service = StreamableHttpService::new(
		|| Ok(hepta_runtime::mcp::server::OctofsServer::new()),
		LocalSessionManager::default().into(),
		StreamableHttpServerConfig::default().with_cancellation_token(cancel.child_token()),
	);
	let router = axum::Router::new().nest_service("/mcp", service).layer(
		axum::middleware::from_fn_with_state(
			load_http_auth(Some(&fixture.token))?,
			super::require_http_auth,
		),
	);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let address = listener.local_addr()?;
	let stopped = cancel.clone();
	let owner = tokio::spawn(async move {
		axum::serve(listener, router)
			.with_graceful_shutdown(stopped.cancelled_owned())
			.await
	});
	let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"native-http-fixture","version":"1"}}}"#;
	let response = post_native_http(address, initialize, None).await?;
	assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
	let session = response
		.lines()
		.find_map(|line| {
			let (name, value) = line.split_once(':')?;
			name.eq_ignore_ascii_case("mcp-session-id")
				.then(|| value.trim().to_owned())
		})
		.expect("the real stateful HTTP service returns a session");
	let response = post_native_http(
		address,
		r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
		Some(&session),
	)
	.await?;
	assert!(response.starts_with("HTTP/1.1 202 "), "{response}");
	let admitted = post_native_http(address, raw, Some(&session)).await?;
	// No Worker is installed in this fixture: reaching the ordinary visibility
	// refusal proves the wire gate admitted the actual authenticated HTTP call.
	assert!(
		admitted.contains("tool not found in this runtime mode"),
		"{admitted}"
	);
	assert!(
		!admitted.contains("HIA native wire admission refused"),
		"{admitted}"
	);
	for changed in [
		raw.replace("hia_describe", "hia_verify"),
		raw.replace("\"id\": 7", "\"id\": 71"),
		raw.replace("\"arguments\":{}", "\"arguments\":{\"changed\":true}"),
	] {
		let refused = post_native_http(address, &changed, Some(&session)).await?;
		assert!(
			refused.contains("HIA native wire admission refused"),
			"{refused}"
		);
	}
	cancel.cancel();
	tokio::time::timeout(std::time::Duration::from_secs(5), owner).await???;
	Ok(())
}
