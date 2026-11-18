// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original path parsing/display/resolution with unreachable remote-effect fences.
use std::path::{Path, PathBuf};
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

impl From<&Path> for PathSource {
	fn from(p: &Path) -> Self {
		PathSource::Local(p.to_path_buf())
	}
}

impl From<&PathBuf> for PathSource {
	fn from(p: &PathBuf) -> Self {
		PathSource::Local(p.clone())
	}
}

/// Parse a path string into a [`PathSource`].
///
/// Recognized remote schemes:
/// - `ssh://user@host:port/path`
/// - `sftp://user@host:port/path`
///
/// `host` may be an OpenSSH config alias. A path of `/~` or `/~/x` is relative
/// to the login home (see [`PathSource::sftp_path`]); no path at all means `/~`,
/// matching `ssh host` / `scp host:`.
///
/// If no scheme is present, the path is treated as local and returned as-is
/// (the caller is responsible for resolving it against the workdir).
///
/// Defaults: port 22, user from `$USER` (or "root" if unset); both are
/// overridden by `~/.ssh/config` when not explicit in the URL.
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

/// Resolve a path string into a PathSource, resolving local paths against workdir.
/// Remote paths (ssh://, sftp://) are returned as-is; local relative paths are
/// resolved against the workdir (same as `core::resolve_path`).
///
/// The workdir itself may be a remote URL (`--path ssh://...`), carried as a
/// PathBuf — relative paths under a remote workdir are joined with '/' manually
/// (PathBuf::join would insert '\' on Windows and corrupt the URL) and resolve
/// to Remote sources. Absolute local paths stay local; use a
/// full ssh:// URL to address a remote absolute path explicitly.
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

pub async fn io_canonicalize(_source: &PathSource) -> anyhow::Result<PathBuf> {
    panic!("qualification fixture reached an unqualified remote canonicalize effect")
}
pub async fn io_is_dir(_source: &PathSource) -> anyhow::Result<bool> {
    panic!("qualification fixture reached an unqualified remote is_dir effect")
}
