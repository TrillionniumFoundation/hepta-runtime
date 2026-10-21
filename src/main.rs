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

use anyhow::Result;
use clap::Parser;
use tracing::Level;
use std::io::Read;

mod cli;
pub mod mcp;
pub mod utils;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();

	match cli.command {
		Commands::Mcp {
			path,
			bind,
			ssh_key,
			ssh_timeout,
			runtime_config,
			auth_token_file,
		} => {
			let runtime_enabled = runtime_config.is_some();
			if let Some(config_path) = runtime_config.as_ref() {
				let config = mcp::runtime::RuntimeConfig::load(config_path)?;
				mcp::runtime::init_runtime(config)?;
			}

			// Resolve working directory
			let working_directory = if let Some(p) = path {
				p.canonicalize().unwrap_or(p)
			} else {
				std::env::current_dir()?
			};

			// Stderr-only logging — no stdout (would corrupt stdio MCP protocol)
			init_mcp_logging();

			// Initialize SFTP pool for remote filesystem support.
			let config = mcp::fs::remote::SshConfig {
				key_path: ssh_key,
				timeout: std::time::Duration::from_secs(ssh_timeout.unwrap_or(30)),
			};
			mcp::fs::remote::init_sftp_pool(config);

			// Set the session root directory for all tool calls
			mcp::set_session_root_directory(working_directory.clone());

			match bind {
				Some(addr) => {
					// HTTP mode with Streamable HTTP transport.
					run_http_server(&addr, auth_token_file.as_deref(), runtime_enabled).await?;
				}
				None => {
					// STDIO mode (default)
					run_stdio_server(mcp::server::OctofsServer::new()).await?;
				}
			}
		}
	}

	Ok(())
}

/// Run the MCP server over STDIO (default mode).
///
/// Exits cleanly on: EOF on stdin (parent closed pipe), or SIGTERM
/// (parent requests graceful shutdown). Both paths call kill_all_shell_children()
/// to ensure no orphan processes survive after we exit.
async fn run_stdio_server(server: mcp::server::OctofsServer) -> Result<()> {
	use rmcp::{transport::stdio, ServiceExt};

	tracing::info!("Starting MCP server (STDIO mode)");

	let service = server.serve(stdio()).await.inspect_err(|e| {
		tracing::error!("serving error: {:?}", e);
	})?;

	// `waiting()` blocks until the transport closes naturally (EOF on stdin).
	// For SIGTERM we cancel via the service's cancellation token so the task
	// exits cleanly without dropping the handle mid-flight.
	#[cfg(unix)]
	{
		use tokio::signal::unix::{signal, SignalKind};
		let ct = service.cancellation_token();
		let mut sigterm =
			signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
		tokio::select! {
			_ = service.waiting() => {
				// EOF on stdin — clean shutdown
			}
			_ = sigterm.recv() => {
				tracing::debug!("SIGTERM received, shutting down gracefully");
				ct.cancel();
			}
		}
	}
	#[cfg(not(unix))]
	{
		service.waiting().await.ok();
	}

	// Kill request-scoped shell trees and interactive SSH PTYs. Durable runtime jobs
	// are deliberately independent and remain queryable after this process restarts.
	mcp::fs::shell::kill_all_shell_children();
	mcp::runtime::pty::close_all_ptys();

	Ok(())
}

#[derive(Clone)]
struct HttpAuth {
	token_hash: [u8; 32],
}

fn load_http_auth(path: Option<&std::path::Path>, required: bool) -> Result<Option<HttpAuth>> {
	use sha2::{Digest, Sha256};
	let Some(path) = path else {
		if required {
			anyhow::bail!("runtime HTTP mode requires --auth-token-file");
		}
		return Ok(None);
	};

	// Check the opened file, not a separate metadata(path) followed by read(path).
	// A symlink swap between those operations could substitute the auth secret.
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW);
	}
	let mut file = options.open(path)?;
	let metadata = file.metadata()?;
	if !metadata.is_file() {
		anyhow::bail!(
			"HTTP auth token path is not a regular file: {}",
			path.display()
		);
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::{MetadataExt, PermissionsExt};
		if metadata.permissions().mode() & 0o077 != 0 {
			anyhow::bail!("HTTP auth token file must be private to its owner");
		}
		if metadata.nlink() != 1 {
			anyhow::bail!("HTTP auth token file must not have multiple hard links");
		}
		// The pathname must still designate the inode opened without following
		// a final-component symlink. The token bytes always come from that fd.
		let current = std::fs::symlink_metadata(path)?;
		if !current.is_file()
			|| current.dev() != metadata.dev()
			|| current.ino() != metadata.ino()
		{
			anyhow::bail!("HTTP auth token file identity changed during open");
		}
	}
	if metadata.len() > 4_097 {
		anyhow::bail!("HTTP auth token file exceeds the 4096-byte limit");
	}
	// Bound the read as well: the file may grow after the fstat.
	let mut token = Vec::new();
	file.take(4_098).read_to_end(&mut token)?;
	if token.len() > 4_097 {
		token.fill(0);
		anyhow::bail!("HTTP auth token file exceeds the 4096-byte limit");
	}
	let bytes = token.strip_suffix(b"\n").unwrap_or(&token);
	if bytes.len() < 32 || bytes.len() > 4096 {
		token.fill(0);
		anyhow::bail!("HTTP auth token must contain 32..4096 bytes");
	}
	let token_hash = Sha256::digest(bytes).into();
	token.fill(0);
	Ok(Some(HttpAuth { token_hash }))
}

async fn require_http_auth(
	axum::extract::State(auth): axum::extract::State<HttpAuth>,
	request: axum::extract::Request,
	next: axum::middleware::Next,
) -> axum::response::Response {
	use axum::response::IntoResponse;
	use sha2::{Digest, Sha256};
	use subtle::ConstantTimeEq;
	let valid = request
		.headers()
		.get("x-hepta-runtime-token")
		.is_some_and(|value| {
			let candidate: [u8; 32] = Sha256::digest(value.as_bytes()).into();
			bool::from(candidate.ct_eq(&auth.token_hash))
		});
	if !valid {
		return axum::http::StatusCode::UNAUTHORIZED.into_response();
	}
	next.run(request).await
}

/// Run the MCP server over HTTP with Streamable HTTP transport.
async fn run_http_server(
	bind_addr: &str,
	auth_token_file: Option<&std::path::Path>,
	auth_required: bool,
) -> Result<()> {
	use rmcp::transport::streamable_http_server::{
		session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
	};

	let ct = tokio_util::sync::CancellationToken::new();

	// Each HTTP session gets a fresh server instance with isolated workdir state.
	// The factory closure creates a new OctofsServer for each session.
	let service = StreamableHttpService::new(
		|| Ok(mcp::server::OctofsServer::new()),
		LocalSessionManager::default().into(),
		StreamableHttpServerConfig::default().with_cancellation_token(ct.child_token()),
	);

	let auth = load_http_auth(auth_token_file, auth_required)?;
	let mut protected = axum::Router::new().nest_service("/mcp", service);
	if let Some(auth) = auth {
		protected = protected.layer(axum::middleware::from_fn_with_state(
			auth,
			require_http_auth,
		));
	}
	let router = axum::Router::new()
		.route("/healthz", axum::routing::get(|| async { "ok\n" }))
		.route("/readyz", axum::routing::get(|| async { "ready\n" }))
		.merge(protected);
	let addr = bind_addr
		.parse::<std::net::SocketAddr>()
		.map_err(|e| anyhow::anyhow!("Invalid bind address '{}': {}", bind_addr, e))?;

	let tcp_listener = tokio::net::TcpListener::bind(&addr)
		.await
		.map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", addr, e))?;

	tracing::info!("MCP HTTP server listening on {}", addr);

	let _ = axum::serve(tcp_listener, router)
		.with_graceful_shutdown(async move {
			#[cfg(unix)]
			{
				use tokio::signal::unix::{signal, SignalKind};
				let mut sigterm =
					signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
				tokio::select! {
					_ = tokio::signal::ctrl_c() => {},
					_ = sigterm.recv() => {},
				}
			}
			#[cfg(not(unix))]
			tokio::signal::ctrl_c().await.unwrap();
			ct.cancel();
		})
		.await;

	// Same orphan cleanup as STDIO shutdown. Durable runtime jobs are unaffected.
	mcp::fs::shell::kill_all_shell_children();
	mcp::runtime::pty::close_all_ptys();

	Ok(())
}

fn init_mcp_logging() {
	// Parse RUST_LOG for a level override; default to WARN so debug! is a no-op.
	let level = std::env::var("RUST_LOG")
		.ok()
		.and_then(|v| v.parse::<Level>().ok())
		.unwrap_or(Level::WARN);

	tracing::subscriber::set_global_default(StderrSubscriber { level })
		.expect("failed to set tracing subscriber");
}

/// Minimal tracing subscriber — writes level + message to stderr.
/// Avoids the heavy tracing-subscriber crate (regex-automata, sharded-slab, etc.).
struct StderrSubscriber {
	level: Level,
}

impl tracing::Subscriber for StderrSubscriber {
	fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
		metadata.level() <= &self.level
	}

	fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
		tracing::span::Id::from_u64(1)
	}

	fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

	fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

	fn event(&self, event: &tracing::Event<'_>) {
		use std::fmt::Write;
		let mut msg = String::new();
		let _ = write!(msg, "[{}] ", event.metadata().level());
		event.record(&mut MessageVisitor(&mut msg));
		eprintln!("{}", msg);
	}

	fn enter(&self, _span: &tracing::span::Id) {}
	fn exit(&self, _span: &tracing::span::Id) {}
}

struct MessageVisitor<'a>(&'a mut String);

impl tracing::field::Visit for MessageVisitor<'_> {
	fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
		if field.name() == "message" {
			let _ = std::fmt::write(self.0, format_args!("{:?}", value));
		}
	}

	fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
		if field.name() == "message" {
			self.0.push_str(value);
		}
	}
}

#[cfg(all(test, unix))]
mod http_auth_file_tests {
	use super::load_http_auth;
	use std::os::unix::fs::PermissionsExt;

	fn private_token(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
		std::fs::write(path, bytes)?;
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
		Ok(())
	}

	#[test]
	fn http_auth_accepts_private_regular_token_and_one_trailing_newline() -> anyhow::Result<()> {
		let temp = tempfile::tempdir()?;
		let path = temp.path().join("auth.token");
		private_token(&path, b"0123456789abcdef0123456789abcdef\n")?;
		assert!(load_http_auth(Some(&path), true)?.is_some());
		assert!(load_http_auth(None, false)?.is_none());
		assert!(load_http_auth(None, true).is_err());
		Ok(())
	}

	#[test]
	fn http_auth_rejects_group_or_world_permissions() -> anyhow::Result<()> {
		let temp = tempfile::tempdir()?;
		let path = temp.path().join("auth.token");
		private_token(&path, b"0123456789abcdef0123456789abcdef")?;
		for mode in [0o640, 0o604, 0o666] {
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
			assert!(load_http_auth(Some(&path), true).is_err(), "mode {mode:o}");
		}
		Ok(())
	}

	#[test]
	fn http_auth_rejects_symlink_and_hardlinks() -> anyhow::Result<()> {
		let temp = tempfile::tempdir()?;
		let path = temp.path().join("auth.token");
		private_token(&path, b"0123456789abcdef0123456789abcdef")?;
		let alias = temp.path().join("alias");
		std::os::unix::fs::symlink(&path, &alias)?;
		assert!(load_http_auth(Some(&alias), true).is_err());
		std::fs::remove_file(&alias)?;
		std::fs::hard_link(&path, &alias)?;
		assert!(load_http_auth(Some(&path), true).is_err());
		assert!(load_http_auth(Some(&alias), true).is_err());
		Ok(())
	}

	#[test]
	fn http_auth_bounds_token_file_reads_and_rejects_nonfiles() -> anyhow::Result<()> {
		let temp = tempfile::tempdir()?;
		let path = temp.path().join("auth.token");
		private_token(&path, &vec![b'x'; 4096])?;
		assert!(load_http_auth(Some(&path), true)?.is_some());
		private_token(&path, &vec![b'x'; 4098])?;
		assert!(load_http_auth(Some(&path), true).is_err());
		private_token(&path, b"short")?;
		assert!(load_http_auth(Some(&path), true).is_err());
		assert!(load_http_auth(Some(temp.path()), true).is_err());
		Ok(())
	}
}
