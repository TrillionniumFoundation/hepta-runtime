// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact production items; verified by the source extraction manifest.
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub enum PathSource {
	/// A local filesystem path (already resolved against the workdir).
	Local(PathBuf),
	/// A remote path accessed via SFTP over SSH.
	Remote {
		host: String,
		port: u16,
		user: String,
		path: String,
		user_explicit: bool,
		port_explicit: bool,
	},
}


impl PathSource {
	/// Returns the path component as a string slice.
	pub fn path_str(&self) -> &str {
		match self {
			PathSource::Local(p) => p.to_str().unwrap_or(""),
			PathSource::Remote { path, .. } => path,
		}
	}

	/// True if this is a remote path.
	pub fn is_remote(&self) -> bool {
		matches!(self, PathSource::Remote { .. })
	}

	/// Path as sent over SFTP. `/~` (URL form `ssh://host/~/x`) is the login
	/// home: SFTP resolves relative paths against it, so `/~` becomes `.` and
	/// `/~/x` becomes `x`. Absolute paths pass through unchanged.
	pub fn sftp_path(&self) -> &str {
		let path = self.path_str();
		let tilde = path.strip_prefix('/').unwrap_or(path);
		match tilde {
			"~" | "~/" => ".",
			_ => tilde.strip_prefix("~/").unwrap_or(path),
		}
	}

	/// Returns a lock key unique per host+path to avoid cross-host collisions.
	pub fn lock_key(&self) -> String {
		match self {
			PathSource::Local(p) => p.to_string_lossy().to_string(),
			PathSource::Remote {
				host, port, path, ..
			} => {
				format!("{host}:{port}{path}")
			}
		}
	}

	/// Human-readable path for error messages.
	pub fn display(&self) -> String {
		match self {
			PathSource::Local(p) => p.display().to_string(),
			PathSource::Remote {
				host,
				port,
				user,
				path,
				user_explicit,
				port_explicit,
			} => {
				let user = user_explicit
					.then(|| format!("{user}@"))
					.unwrap_or_default();
				let host = if host.contains(':') {
					format!("[{host}]")
				} else {
					host.clone()
				};
				let port = port_explicit
					.then(|| format!(":{port}"))
					.unwrap_or_default();
				format!("ssh://{user}{host}{port}{path}")
			}
		}
	}

	/// Returns the local Path if this is a local source.
	pub fn as_local_path(&self) -> Option<&Path> {
		match self {
			PathSource::Local(p) => Some(p),
			PathSource::Remote { .. } => None,
		}
	}

	/// Returns the parent directory as a PathSource, if any.
	pub fn parent(&self) -> Option<PathSource> {
		match self {
			PathSource::Local(p) => p.parent().map(|pp| PathSource::Local(pp.to_path_buf())),
			PathSource::Remote {
				host,
				port,
				user,
				path,
				user_explicit,
				port_explicit,
			} => {
				let parent = Path::new(path).parent()?;
				Some(PathSource::Remote {
					host: host.clone(),
					port: *port,
					user: user.clone(),
					path: parent.to_string_lossy().to_string(),
					user_explicit: *user_explicit,
					port_explicit: *port_explicit,
				})
			}
		}
	}
}


#[derive(Debug, Clone)]
pub struct RemoteMetadata {
	pub size: u64,
	pub is_dir: bool,
	pub is_file: bool,
	pub modified: Option<SystemTime>,
}


#[derive(Debug, Clone)]
pub struct IoMetadata {
	pub size: u64,
	pub is_dir: bool,
	pub is_file: bool,
	pub modified: Option<SystemTime>,
}


pub async fn io_read_to_string(source: &PathSource) -> Result<String> {
	match source {
		PathSource::Local(p) => tokio::fs::read_to_string(p)
			.await
			.map_err(|e| anyhow!("Failed to read '{}': {}", source.display(), e)),
		PathSource::Remote { .. } => sftp::remote_read_to_string(source).await,
	}
}


pub async fn io_write(source: &PathSource, content: &[u8]) -> Result<()> {
	match source {
		PathSource::Local(p) => tokio::fs::write(p, content)
			.await
			.map_err(|e| anyhow!("Failed to write '{}': {}", source.display(), e)),
		#[cfg(feature = "remote-fs")]
		PathSource::Remote { host, path, .. } => {
			crate::mcp::runtime::config::check_remote_write(host, path)?;
			sftp::remote_write(source, content).await
		}
		#[cfg(not(feature = "remote-fs"))]
		PathSource::Remote { .. } => sftp::remote_write(source, content).await,
	}
}


pub async fn io_exists(source: &PathSource) -> Result<bool> {
	match source {
		PathSource::Local(p) => Ok(p.exists()),
		PathSource::Remote { .. } => sftp::remote_exists(source).await,
	}
}


pub async fn io_metadata(source: &PathSource) -> Result<IoMetadata> {
	match source {
		PathSource::Local(p) => {
			let meta = tokio::fs::metadata(p)
				.await
				.map_err(|e| anyhow!("Failed to stat '{}': {}", source.display(), e))?;
			Ok(IoMetadata {
				size: meta.len(),
				is_dir: meta.is_dir(),
				is_file: meta.is_file(),
				modified: meta.modified().ok(),
			})
		}
		PathSource::Remote { .. } => {
			let m = sftp::remote_metadata(source).await?;
			Ok(IoMetadata {
				size: m.size,
				is_dir: m.is_dir,
				is_file: m.is_file,
				modified: m.modified,
			})
		}
	}
}


pub async fn io_remove_file(source: &PathSource) -> Result<()> {
	match source {
		PathSource::Local(p) => tokio::fs::remove_file(p)
			.await
			.map_err(|e| anyhow!("Failed to remove '{}': {}", source.display(), e)),
		#[cfg(feature = "remote-fs")]
		PathSource::Remote { host, path, .. } => {
			crate::mcp::runtime::config::check_remote_write(host, path)?;
			sftp::remote_remove_file(source).await
		}
		#[cfg(not(feature = "remote-fs"))]
		PathSource::Remote { .. } => sftp::remote_remove_file(source).await,
	}
}


mod sftp { include!("original_sftp_unavailable.rs"); }

pub async fn io_create_dir_all(source: &PathSource) -> Result<()> {
	match source {
		PathSource::Local(p) => tokio::fs::create_dir_all(p)
			.await
			.map_err(|e| anyhow!("Failed to create dirs for '{}': {}", source.display(), e)),
		#[cfg(feature = "remote-fs")]
		PathSource::Remote { host, path, .. } => {
			crate::mcp::runtime::config::check_remote_write(host, path)?;
			sftp::remote_create_dir_all(source).await
		}
		#[cfg(not(feature = "remote-fs"))]
		PathSource::Remote { .. } => sftp::remote_create_dir_all(source).await,
	}
}


pub fn parse_path_source(path: &str) -> PathSource {
	let rest = path
		.strip_prefix("ssh://")
		.or_else(|| path.strip_prefix("sftp://"));

	let Some(rest) = rest else {
		return PathSource::Local(PathBuf::from(path));
	};

	// Split user from host part
	let (user, host_part, user_explicit) = match rest.find('@') {
		Some(idx) => (rest[..idx].to_string(), &rest[idx + 1..], true),
		None => (
			std::env::var("USER").unwrap_or_else(|_| "root".to_string()),
			rest,
			false,
		),
	};

	// Split host:port from path (first '/' separates)
	let (host_port, remote_path) = match host_part.find('/') {
		Some(idx) => (&host_part[..idx], &host_part[idx..]),
		None => (host_part, "/~"),
	};

	// Split host from port — handle IPv6 brackets
	let (host, port, port_explicit) = if let Some(inner) = host_port.strip_prefix('[') {
		match inner.find(']') {
			Some(idx) => {
				let addr = &inner[..idx];
				let explicit = inner[idx + 1..].strip_prefix(':');
				let port = explicit.and_then(|s| s.parse::<u16>().ok()).unwrap_or(22);
				(addr.to_string(), port, explicit.is_some())
			}
			None => (host_port.to_string(), 22, false),
		}
	} else {
		match host_port.rfind(':') {
			Some(idx) => {
				let port = host_port[idx + 1..].parse::<u16>().unwrap_or(22);
				(host_port[..idx].to_string(), port, true)
			}
			None => (host_port.to_string(), 22, false),
		}
	};

	PathSource::Remote {
		host,
		port,
		user,
		path: remote_path.to_string(),
		user_explicit,
		port_explicit,
	}
}


pub fn resolve_path_source(path_str: &str, workdir: &Path) -> PathSource {
	match parse_path_source(path_str) {
		PathSource::Local(p) if p.is_absolute() => PathSource::Local(p),
		PathSource::Local(p) => match parse_path_source(&workdir.to_string_lossy()) {
			PathSource::Remote {
				host,
				port,
				user,
				path,
				user_explicit,
				port_explicit,
			} => {
				let rel = path_str.replace('\\', "/");
				let joined = if path.ends_with('/') {
					format!("{path}{rel}")
				} else {
					format!("{path}/{rel}")
				};
				PathSource::Remote {
					host,
					port,
					user,
					path: joined,
					user_explicit,
					port_explicit,
				}
			}
			_ => PathSource::Local(workdir.join(p)),
		},
		remote => remote,
	}
}

