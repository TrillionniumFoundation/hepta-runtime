// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original jobs audit append reference, isolated from runtime installation.
#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{fs::{File, OpenOptions}, io::Write, path::{Path, PathBuf},
          sync::{Mutex, OnceLock}, time::{SystemTime, UNIX_EPOCH}};
static AUDIT_LOCK: OnceLock<Mutex<Option<AuditReadiness>>> = OnceLock::new();
struct AuditConfig { state_dir: PathBuf }
fn runtime_config() -> Result<AuditConfig> {
    bail!("configuration installation is outside this isolated original reference")
}
fn now_ms() -> u128 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis()
}
struct PreparedAudit {
	path: PathBuf,
	line: Vec<u8>,
}

// One positive publication proof, never an event/history or absence cache.
// Held descriptors prevent inode reuse from manufacturing an identity match.
struct AuditReadiness {
	#[cfg(unix)]
	binding: AuditBinding,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuditDirectoryStamp {
	device: u64,
	inode: u64,
	modified: (i64, i64),
	changed: (i64, i64),
	namespace: super::namespace_version::Version,
}

#[cfg(unix)]
fn audit_directory_stamp(directory: &std::fs::File) -> Result<AuditDirectoryStamp> {
	use std::os::unix::fs::MetadataExt;
	let metadata = directory.metadata()?;
	if !metadata.is_dir() {
		bail!("audit publication parent is not a directory");
	}
	Ok(AuditDirectoryStamp {
		device: metadata.dev(),
		inode: metadata.ino(),
		modified: (metadata.mtime(), metadata.mtime_nsec()),
		changed: (metadata.ctime(), metadata.ctime_nsec()),
		namespace: super::namespace_version::version(directory)?,
	})
}

#[cfg(unix)]
fn audit_inode(metadata: &std::fs::Metadata) -> (u64, u64) {
	use std::os::unix::fs::MetadataExt;
	(metadata.dev(), metadata.ino())
}

#[cfg(unix)]
fn open_audit_directory(path: &Path) -> Result<std::fs::File> {
	use std::os::unix::fs::OpenOptionsExt;
	// Follow the same configured symlinks as before, while refusing a FIFO or
	// regular-file substitution before a newly added read open could block.
	Ok(OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
		.open(path)?)
}

#[cfg(unix)]
fn audit_reliable_generation(stamps: &[AuditDirectoryStamp; 3]) -> bool {
	#[cfg(target_os = "linux")]
	{
		stamps.iter().all(|stamp| {
			matches!(
				stamp.namespace,
				super::namespace_version::Version::Watch(_, _)
			)
		})
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = stamps;
		false
	}
}

#[cfg(unix)]
struct AuditBinding {
	path: PathBuf,
	audit_path: PathBuf,
	state_path: PathBuf,
	target_path: PathBuf,
	file: std::fs::File,
	audit_directory: std::fs::File,
	state_directory: std::fs::File,
	target_directory: std::fs::File,
	stamps: [AuditDirectoryStamp; 3],
}

#[cfg(unix)]
impl AuditBinding {
	fn open(path: PathBuf, file: std::fs::File) -> Result<Self> {
		let path = if path.is_absolute() {
			path
		} else {
			std::env::current_dir()?.join(path)
		};
		let audit_path = path
			.parent()
			.context("audit path has no parent")?
			.to_path_buf();
		let state_path = audit_path.parent().unwrap_or(Path::new("/")).to_path_buf();
		// The file was opened no-follow and owner-private. Keep the complete
		// path and parent publication fences in addition to that inode check.
		let target_path = std::fs::canonicalize(&path)?;
		let target_parent = target_path.parent().context("audit target has no parent")?;
		let audit_directory = open_audit_directory(&audit_path)?;
		let state_directory = open_audit_directory(&state_path)?;
		let target_directory = open_audit_directory(target_parent)?;
		let stamps = [
			audit_directory_stamp(&audit_directory)?,
			audit_directory_stamp(&state_directory)?,
			audit_directory_stamp(&target_directory)?,
		];
		let binding = Self {
			path,
			audit_path,
			state_path,
			target_path,
			file,
			audit_directory,
			state_directory,
			target_directory,
			stamps,
		};
		binding.validate()?;
		Ok(binding)
	}

	fn validate(&self) -> Result<()> {
		let file_identity = audit_inode(&self.file.metadata()?);
		if audit_inode(&std::fs::metadata(&self.path)?) != file_identity
			|| std::fs::canonicalize(&self.path)? != self.target_path
			|| audit_inode(&std::fs::metadata(&self.target_path)?) != file_identity
		{
			bail!("audit file binding changed");
		}
		let paths: [&Path; 3] = [
			self.audit_path.as_path(),
			self.state_path.as_path(),
			self.target_path.parent().expect("target parent"),
		];
		let directories = [
			&self.audit_directory,
			&self.state_directory,
			&self.target_directory,
		];
		for ((path, directory), expected) in paths.into_iter().zip(directories).zip(&self.stamps) {
			if audit_inode(&std::fs::metadata(path)?) != (expected.device, expected.inode)
				|| audit_directory_stamp(directory)? != *expected
			{
				bail!("audit directory publication binding changed");
			}
		}
		Ok(())
	}

	fn can_reuse_parents(&self, path: &Path, file: &std::fs::File) -> Result<bool> {
		// A names/inodes fingerprint can return to the same value after an
		// unlink/relink ABA, especially on a filesystem with coarse timestamps.
		// It remains a final fence, but never authorizes omitting a later barrier.
		if !path.is_absolute()
			|| path.as_os_str() != self.path.as_os_str()
			|| !audit_reliable_generation(&self.stamps)
			|| audit_inode(&file.metadata()?) != audit_inode(&self.file.metadata()?)
		{
			return Ok(false);
		}
		// Resolve all original names and symlink targets again, and validate all
		// held directory descriptors and reliable namespace generations.
		self.validate()?;
		Ok(true)
	}

	fn synchronize_directories(
		&self,
		synchronize: &mut impl FnMut(&std::fs::File) -> Result<()>,
	) -> Result<()> {
		// Normal layout performs exactly audit → state. A symlink target outside
		// that pair adds one bounded target-parent barrier before alias parents.
		let target = (self.stamps[2].device, self.stamps[2].inode);
		let audit = (self.stamps[0].device, self.stamps[0].inode);
		let state = (self.stamps[1].device, self.stamps[1].inode);
		if target != audit && target != state {
			synchronize(&self.target_directory)?;
		}
		synchronize(&self.audit_directory)?;
		if state != audit {
			synchronize(&self.state_directory)?;
		}
		Ok(())
	}
}

fn prepare_audit_at(
	path: PathBuf,
	action: &str,
	host: &str,
	subject: &str,
	outcome: &Value,
) -> Result<PreparedAudit> {
	let event = json!({
		"at_unix_ms": now_ms(),
		"action": action,
		"host": host,
		"subject": subject,
		"outcome": outcome,
	});
	let mut line = serde_json::to_vec(&event)?;
	line.push(b'\n');
	Ok(PreparedAudit { path, line })
}

fn prepare_audit(
	action: &str,
	host: &str,
	subject: &str,
	outcome: &Value,
) -> Result<PreparedAudit> {
	prepare_audit_at(
		runtime_config()?.state_dir.join("audit/events.jsonl"),
		action,
		host,
		subject,
		outcome,
	)
}

fn append_audit_with(
	prepared: PreparedAudit,
	synchronize: impl FnOnce(&std::fs::File) -> Result<()>,
) -> Result<()> {
	let preparation = prepared.path.parent().map_or(Ok(()), |parent| {
		std::fs::create_dir_all(parent).map_err(anyhow::Error::from)
	});
	let mut readiness = AUDIT_LOCK
		.get_or_init(|| Mutex::new(None))
		.lock()
		.map_err(|_| anyhow::anyhow!("audit lock poisoned"))?;
	append_audit_prepared_with(
		prepared,
		&mut readiness,
		preparation,
		synchronize,
		|directory| Ok(directory.sync_all()?),
	)
}

fn append_audit_prepared_with(
	prepared: PreparedAudit,
	readiness: &mut Option<AuditReadiness>,
	preparation: Result<()>,
	synchronize_file: impl FnOnce(&std::fs::File) -> Result<()>,
	synchronize_directory: impl FnMut(&std::fs::File) -> Result<()>,
) -> Result<()> {
	if let Err(error) = preparation {
		*readiness = None;
		return Err(error);
	}
	append_audit_at_with(prepared, readiness, synchronize_file, synchronize_directory)
}

fn open_audit_append(path: &Path) -> Result<File> {
	let mut options = OpenOptions::new();
	options.create(true).append(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options
			.mode(0o600)
			.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
	}
	let file = options.open(path)?;
	let metadata = file.metadata()?;
	if !metadata.is_file() {
		bail!("audit sink is not a regular file: {}", path.display());
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::{MetadataExt, PermissionsExt};
		if metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() } {
			bail!("audit sink must not be hard-linked: {}", path.display());
		}
		// The prior release created audit files using the caller's umask.
		// Tighten a regular, independently opened file descriptor during upgrade
		// rather than breaking every audit operation on legacy mode 0644.
		if metadata.permissions().mode() & 0o077 != 0 {
			file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
			if file.metadata()?.permissions().mode() & 0o077 != 0 {
				bail!("audit sink must be owner-private: {}", path.display());
			}
		}
	}
	Ok(file)
}

#[cfg(unix)]
fn append_audit_at_with(
	prepared: PreparedAudit,
	readiness: &mut Option<AuditReadiness>,
	synchronize_file: impl FnOnce(&std::fs::File) -> Result<()>,
	mut synchronize_directory: impl FnMut(&std::fs::File) -> Result<()>,
) -> Result<()> {
	let previous = readiness.take();
	let file = open_audit_append(&prepared.path)?;
	let warm = previous.as_ref().is_some_and(|previous| {
		previous
			.binding
			.can_reuse_parents(&prepared.path, &file)
			.unwrap_or(false)
	});
	let mut binding = if warm {
		let mut binding = previous.expect("qualified audit readiness").binding;
		binding.file = file;
		binding
	} else {
		// Any missing/mismatched/failed prior proof is irreversibly cold. A
		// freshly opened matching binding cannot restore warm authorization.
		AuditBinding::open(prepared.path, file)?
	};
	binding.file.write_all(&prepared.line)?;
	// The existing per-event fdatasync remains mandatory on both paths.
	synchronize_file(&binding.file)?;
	if !warm {
		binding.synchronize_directories(&mut synchronize_directory)?;
	}
	binding.validate()?;
	*readiness = Some(AuditReadiness { binding });
	Ok(())
}

#[cfg(not(unix))]
fn append_audit_at_with(
	prepared: PreparedAudit,
	readiness: &mut Option<AuditReadiness>,
	synchronize_file: impl FnOnce(&std::fs::File) -> Result<()>,
	_synchronize_directory: impl FnMut(&std::fs::File) -> Result<()>,
) -> Result<()> {
	// Keep the previous platform guarantee and path behavior. This candidate's
	// directory publication proof applies only to the Unix implementation.
	*readiness = None;
	let mut file = open_audit_append(&prepared.path)?;
	file.write_all(&prepared.line)?;
	synchronize_file(&file)
}

fn append_audit(prepared: PreparedAudit) -> Result<()> {
	append_audit_with(prepared, |file| {
		file.sync_data()?;
		Ok(())
	})
}

pub(crate) fn audit(action: &str, host: &str, subject: &str, outcome: &Value) -> Result<()> {
	append_audit(prepare_audit(action, host, subject, outcome)?)
}


pub fn capture(root: &Path, host: &str, subject: &str, fail_sync: &str) -> Value {
    let prepared = prepare_audit_at(root.join("audit/events.jsonl"),
        "native_binary_write", host, subject, &json!({"op":"write"}));
    let prepared = match prepared {
        Ok(value) => value,
        Err(error) => return json!({"error":error.to_string()}),
    };
    let event = String::from_utf8(prepared.line.clone()).unwrap();
    let preparation = prepared.path.parent().map_or(Ok(()), |parent| {
        std::fs::create_dir_all(parent).map_err(anyhow::Error::from)
    });
    let mut readiness = AUDIT_LOCK.get_or_init(|| Mutex::new(None)).lock().unwrap();
    let mut file_syncs = 0;
    let mut directories = Vec::new();
    let result = append_audit_prepared_with(prepared, &mut readiness, preparation,
        |file| {
            file_syncs += 1;
            if fail_sync == "file" { return Err(std::io::Error::from_raw_os_error(5).into()); }
            file.sync_data()?;
            Ok(())
        },
        |directory| {
            use std::os::unix::fs::MetadataExt;
            let metadata = directory.metadata()?;
            directories.push((metadata.dev(), metadata.ino()));
            if fail_sync == format!("directory:{}", directories.len()-1) {
                return Err(std::io::Error::from_raw_os_error(5).into());
            }
            directory.sync_all()?;
            Ok(())
        });
    json!({"ok":result.is_ok(), "error":result.err().map(|e|e.to_string()),
           "event":event,"file_syncs":file_syncs,"directories":directories,
           "ready":readiness.is_some()})
}
pub fn reset() { *AUDIT_LOCK.get_or_init(|| Mutex::new(None)).lock().unwrap() = None; }
