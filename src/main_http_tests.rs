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
