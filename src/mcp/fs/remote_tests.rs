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

use super::sftp::{
	apply_ssh_host_config, encode_file_bytes, parse_jump_target, parse_ssh_host_config,
	ConnectionSlots, SshHostConfig,
};
use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Waker};

fn assert_pending<F: Future>(future: Pin<&mut F>) {
	assert!(future
		.poll(&mut Context::from_waker(Waker::noop()))
		.is_pending());
}

#[tokio::test]
async fn connection_slots_share_one_setup_and_leave_other_hosts_available() {
	let pool = ConnectionSlots::new();
	let attempts = AtomicUsize::new(0);
	let (release, connected) = tokio::sync::oneshot::channel();
	let mut slow = Box::pin(
		pool.get_or_connect("slow".into(), |_| true, |value| *value, async {
			attempts.fetch_add(1, Ordering::Relaxed);
			Ok(connected.await.unwrap())
		}),
	);
	assert_pending(slow.as_mut());
	let mut same = Box::pin(
		pool.get_or_connect("slow".into(), |_| true, |value| *value, async {
			attempts.fetch_add(1, Ordering::Relaxed);
			Ok(99)
		}),
	);
	assert_pending(same.as_mut());
	assert_eq!(attempts.load(Ordering::Relaxed), 1);
	assert_eq!(
		pool.get_or_connect("other".into(), |_| true, |value| *value, async { Ok(23) })
			.await
			.unwrap(),
		23
	);
	// A warm target must also bypass a different target's pending setup.
	assert_eq!(
		pool.get_or_connect("other".into(), |_| true, |value| *value, async {
			panic!("cached host must not reconnect")
		},)
			.await
			.unwrap(),
		23
	);
	release.send(17).unwrap();
	assert_eq!(slow.await.unwrap(), 17);
	assert_eq!(same.await.unwrap(), 17);
	assert_eq!(attempts.load(Ordering::Relaxed), 1);
	assert_eq!(pool.slot_count(), 2);
}

#[tokio::test]
async fn connection_slots_retry_after_failure_without_caching_errors() {
	let pool = ConnectionSlots::<usize>::new();
	let attempts = AtomicUsize::new(0);
	let (release, failed) = tokio::sync::oneshot::channel();
	let mut first = Box::pin(
		pool.get_or_connect("host".into(), |_| true, |value| *value, async {
			attempts.fetch_add(1, Ordering::Relaxed);
			failed.await.unwrap();
			Err(anyhow!("first setup failed"))
		}),
	);
	assert_pending(first.as_mut());
	let mut waiter =
		Box::pin(
			pool.get_or_connect("host".into(), |_| true, |value| *value, async {
				attempts.fetch_add(1, Ordering::Relaxed);
				Ok(31)
			}),
		);
	assert_pending(waiter.as_mut());
	release.send(()).unwrap();
	assert!(first.await.is_err());
	assert_eq!(pool.slot_count(), 1);
	assert_eq!(waiter.await.unwrap(), 31);
	assert_eq!(attempts.load(Ordering::Relaxed), 2);
	for index in 0..128 {
		assert!(pool
			.get_or_connect(format!("failed-{index}"), |_| true, |value| *value, async {
				Err(anyhow!("unavailable"))
			},)
			.await
			.is_err());
	}
	assert_eq!(pool.slot_count(), 1);
}

struct CountDrop(Arc<AtomicUsize>);

impl Drop for CountDrop {
	fn drop(&mut self) {
		self.0.fetch_add(1, Ordering::Relaxed);
	}
}

#[tokio::test]
async fn connection_slots_cancel_setup_and_allow_the_same_waiter_to_connect() {
	let pool = ConnectionSlots::<usize>::new();
	let drops = Arc::new(AtomicUsize::new(0));
	let mut first = Box::pin(
		pool.get_or_connect("host".into(), |_| true, |value| *value, async {
			let _setup = CountDrop(drops.clone());
			std::future::pending().await
		}),
	);
	assert_pending(first.as_mut());
	let mut waiter =
		Box::pin(pool.get_or_connect("host".into(), |_| true, |value| *value, async { Ok(41) }));
	assert_pending(waiter.as_mut());
	drop(first);
	assert_eq!(drops.load(Ordering::Relaxed), 1);
	assert_eq!(pool.slot_count(), 1);
	// A new caller must queue on the same slot as the existing waiter.
	let mut newcomer = Box::pin(pool.get_or_connect(
		"host".into(),
		|_| true,
		|value| *value,
		async { panic!("a queued caller must reuse the waiter's connection") },
	));
	assert_pending(newcomer.as_mut());
	assert_eq!(waiter.await.unwrap(), 41);
	assert_eq!(newcomer.await.unwrap(), 41);
	assert_eq!(pool.slot_count(), 1);
}

#[tokio::test]
async fn connection_slots_remove_empty_slots_after_every_caller_is_cancelled() {
	let pool = ConnectionSlots::<usize>::new();
	for index in 0..128 {
		let key = format!("cancelled-{index}");
		let mut connecting = Box::pin(pool.get_or_connect(
			key.clone(),
			|_| true,
			|value| *value,
			std::future::pending(),
		));
		assert_pending(connecting.as_mut());
		let mut waiting =
			Box::pin(pool.get_or_connect(key, |_| true, |value| *value, std::future::pending()));
		assert_pending(waiting.as_mut());
		if index % 2 == 0 {
			drop(connecting);
			assert_eq!(pool.slot_count(), 1);
			drop(waiting);
		} else {
			drop(waiting);
			assert_eq!(pool.slot_count(), 1);
			drop(connecting);
		}
		assert_eq!(pool.slot_count(), 0);
	}
}

#[tokio::test]
async fn connection_slots_replace_dead_sessions_and_remove_failed_replacements() {
	let pool = ConnectionSlots::new();
	assert_eq!(
		pool.get_or_connect("host".into(), |_| true, |value| *value, async { Ok(1) })
			.await
			.unwrap(),
		1
	);
	assert!(pool
		.get_or_connect("host".into(), |_| false, |value| *value, async {
			Err(anyhow!("replacement failed"))
		},)
		.await
		.is_err());
	assert_eq!(pool.slot_count(), 0);
	assert_eq!(
		pool.get_or_connect("host".into(), |_| true, |value| *value, async { Ok(2) })
			.await
			.unwrap(),
		2
	);
}

#[test]
fn file_hex_encoding_preserves_empty_zero_high_and_all_byte_values() {
	assert_eq!(encode_file_bytes(&[]), "");
	assert_eq!(
		encode_file_bytes(&[0, 1, 15, 16, 127, 128, 255]),
		"00010f107f80ff"
	);
	let every: Vec<u8> = (0..=255).collect();
	let encoded = encode_file_bytes(&every);
	assert_eq!(encoded.len(), every.len() * 2);
	assert!(encoded
		.bytes()
		.all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
	let decoded: Vec<u8> = encoded
		.as_bytes()
		.chunks_exact(2)
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect();
	assert_eq!(decoded, every);
	let full: Vec<u8> = (0..1024 * 1024).map(|index| index as u8).collect();
	let full_encoded = encode_file_bytes(&full);
	assert_eq!(full_encoded.len(), 2 * 1024 * 1024);
	assert!(full_encoded
		.as_bytes()
		.chunks_exact(encoded.len())
		.all(|chunk| chunk == encoded.as_bytes()));
}

#[test]
#[ignore = "manual old/new file hex encoding microbenchmark; no remote access"]
fn benchmark_file_hex_encoding() {
	use std::hint::black_box;
	use std::time::Instant;
	for (size, rounds) in [(64, 4096), (4096, 256), (1024 * 1024, 4)] {
		let input: Vec<u8> = (0..size).map(|index| index as u8).collect();
		let old = Instant::now();
		for _ in 0..rounds {
			let encoded: String = black_box(&input)
				.iter()
				.map(|byte| format!("{byte:02x}"))
				.collect();
			black_box(encoded);
		}
		let old = old.elapsed();
		let new = Instant::now();
		for _ in 0..rounds {
			black_box(encode_file_bytes(black_box(&input)));
		}
		let new = new.elapsed();
		eprintln!(
			"file_hex bytes={size} rounds={rounds} old_ns={} new_ns={} ratio={:.3}",
			old.as_nanos(),
			new.as_nanos(),
			old.as_secs_f64() / new.as_secs_f64()
		);
	}
}

#[test]
fn parses_connection_and_authentication_options() {
	let home = std::path::Path::new("/home/me");
	let text = r#"
Host *
  IdentityAgent ~/.ssh/agent.sock
  Port 2200
Host dev
  HostName 192.0.2.10
  User box
  Port 2222
  ProxyJump jump
  IdentityFile ~/.ssh/dev_ed25519
"#;
	let config = parse_ssh_host_config(text, "dev", home);
	let expected_agent = home.join(".ssh/agent.sock").to_string_lossy().into_owned();
	let expected_identity = home.join(".ssh/dev_ed25519").to_string_lossy().into_owned();

	assert_eq!(config.host_name.as_deref(), Some("192.0.2.10"));
	assert_eq!(config.user.as_deref(), Some("box"));
	// OpenSSH uses the first value obtained, so Host * wins here.
	assert_eq!(config.port, Some(2200));
	assert_eq!(config.proxy_jump.as_deref(), Some("jump"));
	assert_eq!(
		config.identity_agent.as_deref(),
		Some(expected_agent.as_str())
	);
	assert_eq!(config.identity_files, vec![expected_identity]);
}

#[test]
fn explicit_url_user_and_port_override_ssh_config() {
	let config = SshHostConfig {
		host_name: Some("192.0.2.10".to_string()),
		user: Some("configured-user".to_string()),
		port: Some(2200),
		..Default::default()
	};
	let target = apply_ssh_host_config("dev", 2222, "url-user", true, true, config);

	assert_eq!(target.host, "192.0.2.10");
	assert_eq!(target.user, "url-user");
	assert_eq!(target.port, 2222);
}

#[test]
fn parses_proxy_jump_forms() {
	assert_eq!(
		parse_jump_target("jump").unwrap(),
		("jump", 22, "", false, false)
	);
	assert_eq!(
		parse_jump_target("user@jump:2222").unwrap(),
		("jump", 2222, "user", true, true)
	);
	assert_eq!(
		parse_jump_target("user@[2001:db8::1]:2222").unwrap(),
		("2001:db8::1", 2222, "user", true, true)
	);
	assert!(parse_jump_target("one,two").is_err());
}

#[test]
fn test_local_absolute_path() {
	let result = parse_path_source("/home/user/file.txt");
	assert!(matches!(result, PathSource::Local(_)));
	assert_eq!(result.path_str(), "/home/user/file.txt");
}

#[test]
fn test_local_relative_path() {
	let result = parse_path_source("src/main.rs");
	assert!(matches!(result, PathSource::Local(_)));
	assert_eq!(result.path_str(), "src/main.rs");
}

#[test]
fn test_ssh_full_url() {
	let result = parse_path_source("ssh://user@host:2222/path/to/file.txt");
	match result {
		PathSource::Remote {
			host,
			port,
			user,
			path,
			..
		} => {
			assert_eq!(host, "host");
			assert_eq!(port, 2222);
			assert_eq!(user, "user");
			assert_eq!(path, "/path/to/file.txt");
		}
		_ => panic!("expected Remote"),
	}
}

#[test]
fn test_sftp_scheme() {
	let result = parse_path_source("sftp://admin@example.com/var/log/syslog");
	match result {
		PathSource::Remote {
			host,
			port,
			user,
			path,
			..
		} => {
			assert_eq!(host, "example.com");
			assert_eq!(port, 22);
			assert_eq!(user, "admin");
			assert_eq!(path, "/var/log/syslog");
		}
		_ => panic!("expected Remote"),
	}
}

#[test]
fn test_ssh_no_port() {
	let result = parse_path_source("ssh://user@host/path");
	match result {
		PathSource::Remote {
			host,
			port,
			user,
			path,
			..
		} => {
			assert_eq!(host, "host");
			assert_eq!(port, 22);
			assert_eq!(user, "user");
			assert_eq!(path, "/path");
		}
		_ => panic!("expected Remote"),
	}
}

#[test]
fn test_ssh_no_user() {
	let result = parse_path_source("ssh://host:2222/path");
	match result {
		PathSource::Remote {
			host,
			port,
			user,
			path,
			..
		} => {
			assert_eq!(host, "host");
			assert_eq!(port, 2222);
			// user defaults to $USER or "root"
			assert!(!user.is_empty());
			assert_eq!(path, "/path");
		}
		_ => panic!("expected Remote"),
	}
}

#[test]
fn test_ssh_no_path() {
	let result = parse_path_source("ssh://user@host:2222");
	match result {
		PathSource::Remote {
			host,
			port,
			user,
			path,
			..
		} => {
			assert_eq!(host, "host");
			assert_eq!(port, 2222);
			assert_eq!(user, "user");
			assert_eq!(path, "/~");
		}
		_ => panic!("expected Remote"),
	}
	assert_eq!(parse_path_source("ssh://dev").display(), "ssh://dev/~");
}

#[test]
fn test_sftp_path_home_relative() {
	let sftp = |url: &str| parse_path_source(url).sftp_path().to_string();
	assert_eq!(sftp("ssh://dev"), ".");
	assert_eq!(sftp("ssh://dev/~"), ".");
	assert_eq!(sftp("ssh://dev/~/"), ".");
	assert_eq!(sftp("ssh://dev/~/src/main.rs"), "src/main.rs");
	assert_eq!(sftp("ssh://dev/"), "/");
	assert_eq!(sftp("ssh://dev/etc/hosts"), "/etc/hosts");
	assert_eq!(sftp("ssh://dev/~box/x"), "/~box/x");
	let workdir = PathBuf::from("ssh://dev");
	assert_eq!(
		resolve_path_source("src/main.rs", &workdir).sftp_path(),
		"src/main.rs"
	);
}

#[test]
fn test_ssh_ipv6_with_port() {
	let result = parse_path_source("ssh://user@[::1]:2222/path");
	match result {
		PathSource::Remote {
			host,
			port,
			user,
			path,
			..
		} => {
			assert_eq!(host, "::1");
			assert_eq!(port, 2222);
			assert_eq!(user, "user");
			assert_eq!(path, "/path");
		}
		_ => panic!("expected Remote"),
	}
}

#[test]
fn test_ssh_ipv6_no_port() {
	let result = parse_path_source("ssh://user@[::1]/path");
	match result {
		PathSource::Remote {
			host,
			port,
			user,
			path,
			..
		} => {
			assert_eq!(host, "::1");
			assert_eq!(port, 22);
			assert_eq!(user, "user");
			assert_eq!(path, "/path");
		}
		_ => panic!("expected Remote"),
	}
}

#[test]
fn test_remote_display_preserves_explicit_authority_parts() {
	assert_eq!(
		parse_path_source("ssh://dev/path").display(),
		"ssh://dev/path"
	);
	assert_eq!(
		parse_path_source("ssh://box@dev/path").display(),
		"ssh://box@dev/path"
	);
	assert_eq!(
		parse_path_source("ssh://box@dev:2222/path").display(),
		"ssh://box@dev:2222/path"
	);
	assert_eq!(
		parse_path_source("ssh://[2001:db8::1]/path").display(),
		"ssh://[2001:db8::1]/path"
	);
}

#[test]
fn test_is_remote() {
	assert!(!parse_path_source("/local/path").is_remote());
	assert!(parse_path_source("ssh://host/path").is_remote());
	assert!(parse_path_source("sftp://host/path").is_remote());
}

#[test]
fn test_lock_key_local() {
	let source = parse_path_source("/local/path");
	assert_eq!(source.lock_key(), "/local/path");
}

#[test]
fn test_lock_key_remote() {
	let source = parse_path_source("ssh://user@host:2222/path");
	assert_eq!(source.lock_key(), "host:2222/path");
}

#[test]
fn test_resolve_relative_under_remote_workdir() {
	let workdir = PathBuf::from("ssh://user@host:2222/root");
	match resolve_path_source("src/main.rs", &workdir) {
		PathSource::Remote {
			host,
			port,
			user,
			path,
			..
		} => {
			assert_eq!(host, "host");
			assert_eq!(port, 2222);
			assert_eq!(user, "user");
			assert_eq!(path, "/root/src/main.rs");
		}
		_ => panic!("expected Remote"),
	}
	// A local workdir keeps relative paths local.
	assert!(!resolve_path_source("src/main.rs", Path::new("/tmp/w")).is_remote());
}
