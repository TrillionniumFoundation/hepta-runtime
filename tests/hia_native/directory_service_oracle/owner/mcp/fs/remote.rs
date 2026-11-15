// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
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
//! Unchanged PathSource enum and two path functions.
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
