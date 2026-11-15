// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Frozen R23 public reference-buffer mechanism screen; no production service use.
#![allow(dead_code, unused_imports)]
#[cfg(not(target_os = "linux"))]
compile_error!("this screen requires Linux");
mod guard {
use anyhow::{bail, Result};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
struct Completion { stop: CancellationToken }
pub(super) struct OwnerTicket { completion: Completion, deadline: Instant }
impl OwnerTicket {
	pub(super) fn check_current(&self) -> Result<()> {
		if self.completion.stop.is_cancelled() || Instant::now() >= self.deadline {
			bail!("observation validation cancelled or expired before authority acceptance");
		}
		Ok(())
	}

}
pub(super) fn new() -> OwnerTicket {
    OwnerTicket { completion: Completion { stop: CancellationToken::new() },
        deadline: Instant::now() + std::time::Duration::from_secs(120) }
}
pub(super) fn cancel(ticket: &OwnerTicket) { ticket.completion.stop.cancel(); }
pub(super) fn expire(ticket: &mut OwnerTicket) {
    ticket.deadline = Instant::now() - std::time::Duration::from_secs(1);
}
pub(super) fn keep_alive(ticket: &OwnerTicket) -> CancellationToken {
    ticket.completion.stop.clone()
}
}

mod arm16 {
use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
const MAX_EXECUTABLE_REFERENCE_BYTES: usize = 2 * 1024 * 1024;
const VERIFY_BUFFER_BYTES: usize = 16 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Stamp {
	pub dev: u64,
	pub ino: u64,
	pub uid: u32,
	pub mode: u32,
	nlink: u64,
	len: u64,
	mtime: (i64, i64),
	ctime: (i64, i64),
}

impl Stamp {
	pub(super) fn of(value: &Metadata) -> Self {
		Self {
			dev: value.dev(),
			ino: value.ino(),
			uid: value.uid(),
			mode: value.mode(),
			nlink: value.nlink(),
			len: value.len(),
			mtime: (value.mtime(), value.mtime_nsec()),
			ctime: (value.ctime(), value.ctime_nsec()),
		}
	}
	pub(super) fn link_count(&self) -> u64 {
		self.nlink
	}
	pub(super) fn same_directory(&self, other: &Self) -> bool {
		(self.dev, self.ino, self.uid, self.mode) == (other.dev, other.ino, other.uid, other.mode)
	}
}

#[derive(Clone)]
struct PinnedFile {
	path: PathBuf,
	stamp: Stamp,
	digest: [u8; 32],
	reference: Option<Arc<[u8]>>,
	maximum: usize,
	private: bool,
	executable: bool,
}

pub(super) fn absolute(path: &Path) -> Result<()> {
	let text = path
		.to_str()
		.context("observation profile path is not UTF-8")?;
	if !path.is_absolute()
		|| text.len() > 4096
		|| text.chars().any(|v| {
			v.is_control()
				|| v.is_whitespace()
				|| matches!(v, '%' | '~' | '$' | '`' | '\'' | '"' | '\\')
		}) || text.split('/').any(|v| matches!(v, "." | ".."))
	{
		bail!("unsupported observation profile path");
	}
	Ok(())
}

/// Every component is resolved relative to the preceding pinned descriptor.
pub(super) fn open_absolute(path: &Path, directory: bool) -> Result<File> {
	absolute(path)?;
	let mut current = File::open("/")?;
	let parts: Vec<_> = path
		.components()
		.filter_map(|v| match v {
			Component::Normal(v) => Some(v),
			_ => None,
		})
		.collect();
	for (index, part) in parts.iter().enumerate() {
		let name = std::ffi::CString::new(part.as_encoded_bytes())?;
		let flags = libc::O_RDONLY
			| libc::O_NOFOLLOW
			| libc::O_NONBLOCK
			| libc::O_CLOEXEC
			| if index + 1 < parts.len() || directory {
				libc::O_DIRECTORY
			} else {
				0
			};
		let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		current = unsafe { File::from_raw_fd(fd) };
	}
	Ok(current)
}

pub(super) fn private_directory(path: &Path) -> Result<Stamp> {
	let opened = open_absolute(path, true)?;
	let info = opened.metadata()?;
	if !info.is_dir() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o7777 != 0o700 {
		bail!("observation socket directory must be private and account-owned");
	}
	Ok(Stamp::of(&info))
}

fn checked_file(
	path: &Path,
	maximum: usize,
	private: bool,
	executable: bool,
) -> Result<(File, Stamp)> {
	let file = open_absolute(path, false)?;
	let before = file.metadata()?;
	if !before.is_file()
		|| before.nlink() != 1
		|| before.len() as u128 > maximum as u128
		|| if private {
			before.uid() != unsafe { libc::geteuid() } || before.mode() & 0o7777 != 0o600
		} else {
			before.uid() != 0 || before.mode() & 0o6022 != 0
		} {
		bail!("unsupported observation profile inode or byte bound");
	}
	if executable {
		if before.mode() & 0o111 == 0 {
			bail!("observation executable is not executable");
		}
		let name = c"security.capability";
		let result =
			unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
		if result >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
			bail!("observation executable capabilities are unsupported");
		}
	}
	Ok((file, Stamp::of(&before)))
}

fn verify_read(
	path: &Path,
	file: &File,
	stamp: &Stamp,
	length: usize,
	maximum: usize,
) -> Result<()> {
	if length as u64 != stamp.len
		|| length > maximum
		|| *stamp != Stamp::of(&file.metadata()?)
		|| *stamp != Stamp::of(&open_absolute(path, false)?.metadata()?)
	{
		bail!("observation profile input changed");
	}
	Ok(())
}

fn read_file(
	path: &Path,
	maximum: usize,
	private: bool,
	executable: bool,
) -> Result<(Stamp, Vec<u8>)> {
	let (mut file, stamp) = checked_file(path, maximum, private, executable)?;
	let mut bytes = Vec::with_capacity(stamp.len as usize);
	Read::by_ref(&mut file)
		.take(maximum as u64 + 1)
		.read_to_end(&mut bytes)?;
	verify_read(path, &file, &stamp, bytes.len(), maximum)?;
	Ok((stamp, bytes))
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
	let mut result = [0; 32];
	result.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
	result
}

fn hex_digest(value: &str) -> Result<[u8; 32]> {
	if value.len() != 64
		|| !value
			.bytes()
			.all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
	{
		bail!("observation profile needs exact lowercase SHA256 pins");
	}
	let mut result = [0; 32];
	for (index, item) in result.iter_mut().enumerate() {
		*item = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
	}
	Ok(result)
}

fn bounded_executable_reference(bytes: Vec<u8>, remaining: &mut usize) -> Option<Arc<[u8]>> {
	let next = (*remaining).checked_sub(bytes.len())?;
	*remaining = next;
	Some(bytes.into())
}

impl PinnedFile {
	fn load(
		path: &Path,
		expected: Option<&str>,
		maximum: usize,
		private: bool,
		executable: bool,
	) -> Result<(Self, Vec<u8>)> {
		let (stamp, bytes) = read_file(path, maximum, private, executable)?;
		let digest = digest(&bytes);
		if expected.is_some_and(|pin| hex_digest(pin).ok() != Some(digest)) {
			bail!("observation profile byte pin mismatch");
		}
		Ok((
			Self {
				path: path.to_owned(),
				stamp,
				digest,
				reference: None,
				maximum,
				private,
				executable,
			},
			bytes,
		))
	}
	fn verify_identity(&self) -> Result<()> {
		let (_, stamp) = checked_file(&self.path, self.maximum, self.private, self.executable)?;
		if stamp != self.stamp {
			bail!("observation profile changed after complete validation");
		}
		Ok(())
	}
	fn verify(&self) -> Result<()> {
		self.verify_checked(&|| Ok(()))
	}
	fn verify_checked(&self, check_current: &impl Fn() -> Result<()>) -> Result<()> {
		check_current()?;
		let (mut file, stamp) =
			checked_file(&self.path, self.maximum, self.private, self.executable)?;
		check_current()?;
		if stamp != self.stamp {
			bail!("observation profile changed");
		}
		// Every check still reads every byte. Only the fixed public executables can
		// use a bounded startup-pin-verified reference instead of rehashing.
		// The same descriptor and path stamps still fence the complete read.
		let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
		let mut matches_reference = true;
		let mut buffer = [0; VERIFY_BUFFER_BYTES];
		let mut length = 0usize;
		let mut reader = Read::by_ref(&mut file).take(self.maximum as u64 + 1);
		loop {
			check_current()?;
			let count = match Read::read(&mut reader, &mut buffer) {
				Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
					check_current()?;
					continue;
				}
				result => result?,
			};
			check_current()?;
			if count == 0 {
				break;
			}
			length += count;
			if let Some(reference) = &self.reference {
				// Do not stop on a mismatch: later reads, cancellation and the
				// original final descriptor/path checks still have to run.
				matches_reference &=
					reference.get(length - count..length) == Some(&buffer[..count]);
			} else {
				hash.update(&buffer[..count]);
			}
			check_current()?;
		}
		check_current()?;
		verify_read(&self.path, &file, &stamp, length, self.maximum)?;
		check_current()?;
		let content_matches = match &self.reference {
			Some(reference) => matches_reference && length == reference.len(),
			None => hash.finish().as_ref() == self.digest,
		};
		if !content_matches {
			bail!("observation profile changed");
		}
		check_current()?;
		Ok(())
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SystemComponent {
	path: PathBuf,
	stamp: Stamp,
	link: Option<PathBuf>,
}

/// This is the only symlink exception. OpenSSH's fixed ProxyCommand invokes
/// /bin/sh when SHELL is absent. No profile-supplied path enters this resolver.
fn fixed_shell_resolution() -> Result<(PathBuf, Vec<SystemComponent>)> {
	let mut directory = File::open("/")?;
	let mut current = PathBuf::from("/");
	let mut remaining: VecDeque<std::ffi::OsString> = VecDeque::from(["bin".into(), "sh".into()]);
	let mut components = Vec::new();
	let mut links = 0usize;
	for _ in 0..64 {
		let info = directory.metadata()?;
		if !info.is_dir() || info.uid() != 0 || info.mode() & 0o6022 != 0 {
			bail!("unsupported observation system shell directory");
		}
		components.push(SystemComponent {
			path: current.clone(),
			stamp: Stamp::of(&info),
			link: None,
		});
		let part: std::ffi::OsString = remaining
			.pop_front()
			.context("observation system shell target missing")?;
		if part == "." {
			continue;
		}
		if part == ".." {
			if !current.pop() {
				bail!("observation system shell escapes root");
			}
			directory = open_absolute(&current, true)?;
			continue;
		}
		let name = std::ffi::CString::new(part.as_encoded_bytes())?;
		let fd = unsafe {
			libc::openat(
				directory.as_raw_fd(),
				name.as_ptr(),
				libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		let node = unsafe { File::from_raw_fd(fd) };
		let info = node.metadata()?;
		let path = current.join(&part);
		if info.file_type().is_symlink() {
			links += 1;
			if links > 8 || info.uid() != 0 || info.nlink() != 1 {
				bail!("unsupported observation system shell alias");
			}
			let mut target = vec![0u8; 4097];
			let count = unsafe {
				libc::readlinkat(
					node.as_raw_fd(),
					c"".as_ptr(),
					target.as_mut_ptr().cast(),
					target.len(),
				)
			};
			if count <= 0 || count as usize > 4096 {
				bail!("unsupported observation system shell alias target");
			}
			target.truncate(count as usize);
			let target = PathBuf::from(std::ffi::OsString::from_vec(target));
			let reopened = unsafe {
				libc::openat(
					directory.as_raw_fd(),
					name.as_ptr(),
					libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
				)
			};
			if reopened < 0 {
				return Err(std::io::Error::last_os_error().into());
			}
			let reopened = unsafe { File::from_raw_fd(reopened) };
			let stamp = Stamp::of(&info);
			if Stamp::of(&node.metadata()?) != stamp || Stamp::of(&reopened.metadata()?) != stamp {
				bail!("observation system shell alias changed");
			}
			components.push(SystemComponent {
				path,
				stamp,
				link: Some(target.clone()),
			});
			if target.is_absolute() {
				current = PathBuf::from("/");
				directory = File::open("/")?;
			}
			for part in target.components().rev() {
				match part {
					Component::Normal(value) => remaining.push_front(value.to_owned()),
					Component::ParentDir => remaining.push_front("..".into()),
					Component::CurDir => remaining.push_front(".".into()),
					Component::RootDir => {}
					_ => bail!("unsupported observation system shell alias target"),
				}
			}
		} else if info.is_dir() && !remaining.is_empty() {
			current = path;
			directory = node;
		} else if info.is_file() && remaining.is_empty() {
			return Ok((path, components));
		} else {
			bail!("unsupported observation system shell resolution");
		}
	}
	bail!("observation system shell resolution bound")
}

struct PinnedShell {
	components: Vec<SystemComponent>,
	target: PinnedFile,
}
impl PinnedShell {
	fn load(expected: &str, reference_budget: &mut usize) -> Result<Self> {
		let (path, components) = fixed_shell_resolution()?;
		let (mut target, bytes) =
			PinnedFile::load(&path, Some(expected), 16 * 1024 * 1024, false, true)?;
		target.reference = bounded_executable_reference(bytes, reference_budget);
		let result = Self { components, target };
		result.verify()?;
		Ok(result)
	}
	fn verify_resolution(&self) -> Result<()> {
		let (path, components) = fixed_shell_resolution()?;
		if path != self.target.path
			|| components.len() != self.components.len()
			|| components
				.iter()
				.zip(&self.components)
				.any(|(now, expected)| {
					now.path != expected.path
						|| now.link != expected.link
						|| if now.link.is_some() {
							now.stamp != expected.stamp
						} else {
							!now.stamp.same_directory(&expected.stamp)
						}
				}) {
			bail!("observation fixed system shell resolution changed");
		}
		Ok(())
	}
	fn verify(&self) -> Result<()> {
		self.verify_resolution()?;
		self.target.verify()
	}
}

pub(super) struct ComponentPins {
    ssh: PinnedFile, false_program: PinnedFile, shell: PinnedShell,
}
pub(super) fn load(spec: &crate::PublicPins) -> Result<ComponentPins> {
		let mut reference_budget = MAX_EXECUTABLE_REFERENCE_BYTES;
		let (mut ssh, ssh_bytes) = PinnedFile::load(
			Path::new("/usr/bin/ssh"),
			Some(&spec.ssh_sha256),
			16 * 1024 * 1024,
			false,
			true,
		)?;
		// Only fixed public executables share this profile's reference byte budget.
		// Files that do not fit keep SHA and leave the remaining budget unchanged.
		ssh.reference = bounded_executable_reference(ssh_bytes, &mut reference_budget);
		let (mut false_program, false_bytes) = PinnedFile::load(
			Path::new("/usr/bin/false"),
			Some(&spec.false_sha256),
			1024 * 1024,
			false,
			true,
		)?;
		false_program.reference = bounded_executable_reference(false_bytes, &mut reference_budget);
		let shell = PinnedShell::load(&spec.shell_sha256, &mut reference_budget)?;
    if ssh.reference.is_none() || false_program.reference.is_none()
        || shell.target.reference.is_none() {
        bail!("screen requires all three public files to fit the R23 reference budget");
    }
    Ok(ComponentPins { ssh, false_program, shell })
}
impl ComponentPins {
    fn pin(&self, index: usize) -> &PinnedFile {
        match index { 0 => &self.ssh, 1 => &self.false_program, 2 => &self.shell.target,
            _ => unreachable!("fixed three-file screen") }
    }
}
impl crate::ScreenArm for ComponentPins {
    fn verify(&self, scenario: usize, ticket: &crate::guard::OwnerTicket) -> Result<()> {
        let range = if scenario == 3 { 0..3 } else { scenario..scenario + 1 };
        for index in range {
            ticket.check_current()?;
            if index == 2 {
                self.shell.verify_resolution()?;
                ticket.check_current()?;
            }
            self.pin(index).verify_checked(&|| ticket.check_current())?;
            ticket.check_current()?;
        }
        Ok(())
    }
    fn preflight(&self) -> Result<serde_json::Value> {
        use std::cell::Cell;
        self.shell.verify_resolution()?;
        let mut rows = Vec::new();
        for index in 0..3 {
            let pin = self.pin(index);
            let good = crate::guard::new();
            let complete = Cell::new(0usize);
            pin.verify_checked(&|| {
                complete.set(complete.get() + 1);
                good.check_current()
            })?;
            let mut bad = pin.clone();
            let mut bytes = pin.reference.as_ref().context("reference missing")?.to_vec();
            if bytes.is_empty() { bail!("fixed executable unexpectedly empty"); }
            bytes[0] ^= 1;
            bad.reference = Some(bytes.into());
            let count = Cell::new(0usize);
            let failure = bad.verify_checked(&|| {
                count.set(count.get() + 1);
                good.check_current()
            }).err().context("reference mismatch was accepted")?;
            if failure.to_string() != "observation profile changed"
                || count.get() + 1 != complete.get() {
                bail!("complete-read mismatch preflight failed");
            }
            let late = crate::guard::new();
            let count_late = Cell::new(0usize);
            let failure = bad.verify_checked(&|| {
                count_late.set(count_late.get() + 1);
                if count_late.get() == complete.get() - 2 { crate::guard::cancel(&late); }
                late.check_current()
            }).err().context("late cancellation was accepted")?;
            if failure.to_string() != crate::CANCEL_ERROR {
                bail!("late cancellation did not retain precedence over content mismatch");
            }
            let stopped = crate::guard::new();
            crate::guard::cancel(&stopped);
            let failure = pin.verify_checked(&|| stopped.check_current())
                .err().context("cancelled validation was accepted")?;
            if failure.to_string() != crate::CANCEL_ERROR { bail!("cancel result differs"); }
            let mut expired = crate::guard::new();
            crate::guard::expire(&mut expired);
            let failure = pin.verify_checked(&|| expired.check_current())
                .err().context("expired validation was accepted")?;
            if failure.to_string() != crate::CANCEL_ERROR { bail!("expiry result differs"); }
            rows.push(serde_json::json!({"index": index, "bytes": pin.stamp.len,
                "complete_checkpoints": complete.get(), "mismatch_checkpoints": count.get(),
                "late_cancel_preempts_mismatch": true, "cancel_and_expiry_rejected": true}));
        }
        self.shell.verify_resolution()?;
        Ok(serde_json::json!({"buffer_bytes": VERIFY_BUFFER_BYTES, "files": rows}))
    }
}
pub(super) fn discover_public_pins() -> Result<(crate::PublicPins, serde_json::Value)> {
    let (shell_path, _) = fixed_shell_resolution()?;
    let paths = [PathBuf::from("/usr/bin/ssh"), PathBuf::from("/usr/bin/false"), shell_path];
    let maxima = [16 * 1024 * 1024, 1024 * 1024, 16 * 1024 * 1024];
    let mut hexes = Vec::new();
    let mut rows = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let (pin, _) = PinnedFile::load(path, None, maxima[index], false, true)?;
        let hex = pin.digest.iter().map(|v| format!("{v:02x}")).collect::<String>();
        rows.push(serde_json::json!({"role": crate::SCENARIOS[index],
            "path": path.to_str().context("public path is not UTF-8")?,
            "bytes": pin.stamp.len, "sha256": hex}));
        hexes.push(hex);
    }
    Ok((crate::PublicPins { ssh_sha256: hexes[0].clone(),
        false_sha256: hexes[1].clone(), shell_sha256: hexes[2].clone() },
        serde_json::json!(rows)))
}

}
mod arm64 {
use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
const MAX_EXECUTABLE_REFERENCE_BYTES: usize = 2 * 1024 * 1024;
const VERIFY_BUFFER_BYTES: usize = 64 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Stamp {
	pub dev: u64,
	pub ino: u64,
	pub uid: u32,
	pub mode: u32,
	nlink: u64,
	len: u64,
	mtime: (i64, i64),
	ctime: (i64, i64),
}

impl Stamp {
	pub(super) fn of(value: &Metadata) -> Self {
		Self {
			dev: value.dev(),
			ino: value.ino(),
			uid: value.uid(),
			mode: value.mode(),
			nlink: value.nlink(),
			len: value.len(),
			mtime: (value.mtime(), value.mtime_nsec()),
			ctime: (value.ctime(), value.ctime_nsec()),
		}
	}
	pub(super) fn link_count(&self) -> u64 {
		self.nlink
	}
	pub(super) fn same_directory(&self, other: &Self) -> bool {
		(self.dev, self.ino, self.uid, self.mode) == (other.dev, other.ino, other.uid, other.mode)
	}
}

#[derive(Clone)]
struct PinnedFile {
	path: PathBuf,
	stamp: Stamp,
	digest: [u8; 32],
	reference: Option<Arc<[u8]>>,
	maximum: usize,
	private: bool,
	executable: bool,
}

pub(super) fn absolute(path: &Path) -> Result<()> {
	let text = path
		.to_str()
		.context("observation profile path is not UTF-8")?;
	if !path.is_absolute()
		|| text.len() > 4096
		|| text.chars().any(|v| {
			v.is_control()
				|| v.is_whitespace()
				|| matches!(v, '%' | '~' | '$' | '`' | '\'' | '"' | '\\')
		}) || text.split('/').any(|v| matches!(v, "." | ".."))
	{
		bail!("unsupported observation profile path");
	}
	Ok(())
}

/// Every component is resolved relative to the preceding pinned descriptor.
pub(super) fn open_absolute(path: &Path, directory: bool) -> Result<File> {
	absolute(path)?;
	let mut current = File::open("/")?;
	let parts: Vec<_> = path
		.components()
		.filter_map(|v| match v {
			Component::Normal(v) => Some(v),
			_ => None,
		})
		.collect();
	for (index, part) in parts.iter().enumerate() {
		let name = std::ffi::CString::new(part.as_encoded_bytes())?;
		let flags = libc::O_RDONLY
			| libc::O_NOFOLLOW
			| libc::O_NONBLOCK
			| libc::O_CLOEXEC
			| if index + 1 < parts.len() || directory {
				libc::O_DIRECTORY
			} else {
				0
			};
		let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		current = unsafe { File::from_raw_fd(fd) };
	}
	Ok(current)
}

pub(super) fn private_directory(path: &Path) -> Result<Stamp> {
	let opened = open_absolute(path, true)?;
	let info = opened.metadata()?;
	if !info.is_dir() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o7777 != 0o700 {
		bail!("observation socket directory must be private and account-owned");
	}
	Ok(Stamp::of(&info))
}

fn checked_file(
	path: &Path,
	maximum: usize,
	private: bool,
	executable: bool,
) -> Result<(File, Stamp)> {
	let file = open_absolute(path, false)?;
	let before = file.metadata()?;
	if !before.is_file()
		|| before.nlink() != 1
		|| before.len() as u128 > maximum as u128
		|| if private {
			before.uid() != unsafe { libc::geteuid() } || before.mode() & 0o7777 != 0o600
		} else {
			before.uid() != 0 || before.mode() & 0o6022 != 0
		} {
		bail!("unsupported observation profile inode or byte bound");
	}
	if executable {
		if before.mode() & 0o111 == 0 {
			bail!("observation executable is not executable");
		}
		let name = c"security.capability";
		let result =
			unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
		if result >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
			bail!("observation executable capabilities are unsupported");
		}
	}
	Ok((file, Stamp::of(&before)))
}

fn verify_read(
	path: &Path,
	file: &File,
	stamp: &Stamp,
	length: usize,
	maximum: usize,
) -> Result<()> {
	if length as u64 != stamp.len
		|| length > maximum
		|| *stamp != Stamp::of(&file.metadata()?)
		|| *stamp != Stamp::of(&open_absolute(path, false)?.metadata()?)
	{
		bail!("observation profile input changed");
	}
	Ok(())
}

fn read_file(
	path: &Path,
	maximum: usize,
	private: bool,
	executable: bool,
) -> Result<(Stamp, Vec<u8>)> {
	let (mut file, stamp) = checked_file(path, maximum, private, executable)?;
	let mut bytes = Vec::with_capacity(stamp.len as usize);
	Read::by_ref(&mut file)
		.take(maximum as u64 + 1)
		.read_to_end(&mut bytes)?;
	verify_read(path, &file, &stamp, bytes.len(), maximum)?;
	Ok((stamp, bytes))
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
	let mut result = [0; 32];
	result.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
	result
}

fn hex_digest(value: &str) -> Result<[u8; 32]> {
	if value.len() != 64
		|| !value
			.bytes()
			.all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
	{
		bail!("observation profile needs exact lowercase SHA256 pins");
	}
	let mut result = [0; 32];
	for (index, item) in result.iter_mut().enumerate() {
		*item = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
	}
	Ok(result)
}

fn bounded_executable_reference(bytes: Vec<u8>, remaining: &mut usize) -> Option<Arc<[u8]>> {
	let next = (*remaining).checked_sub(bytes.len())?;
	*remaining = next;
	Some(bytes.into())
}

impl PinnedFile {
	fn load(
		path: &Path,
		expected: Option<&str>,
		maximum: usize,
		private: bool,
		executable: bool,
	) -> Result<(Self, Vec<u8>)> {
		let (stamp, bytes) = read_file(path, maximum, private, executable)?;
		let digest = digest(&bytes);
		if expected.is_some_and(|pin| hex_digest(pin).ok() != Some(digest)) {
			bail!("observation profile byte pin mismatch");
		}
		Ok((
			Self {
				path: path.to_owned(),
				stamp,
				digest,
				reference: None,
				maximum,
				private,
				executable,
			},
			bytes,
		))
	}
	fn verify_identity(&self) -> Result<()> {
		let (_, stamp) = checked_file(&self.path, self.maximum, self.private, self.executable)?;
		if stamp != self.stamp {
			bail!("observation profile changed after complete validation");
		}
		Ok(())
	}
	fn verify(&self) -> Result<()> {
		self.verify_checked(&|| Ok(()))
	}
	fn verify_checked(&self, check_current: &impl Fn() -> Result<()>) -> Result<()> {
		check_current()?;
		let (mut file, stamp) =
			checked_file(&self.path, self.maximum, self.private, self.executable)?;
		check_current()?;
		if stamp != self.stamp {
			bail!("observation profile changed");
		}
		// Every check still reads every byte. Only the fixed public executables can
		// use a bounded startup-pin-verified reference instead of rehashing.
		// The same descriptor and path stamps still fence the complete read.
		let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
		let mut matches_reference = true;
		let mut buffer = [0; VERIFY_BUFFER_BYTES];
		let mut length = 0usize;
		let mut reader = Read::by_ref(&mut file).take(self.maximum as u64 + 1);
		loop {
			check_current()?;
			let count = match Read::read(&mut reader, &mut buffer) {
				Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
					check_current()?;
					continue;
				}
				result => result?,
			};
			check_current()?;
			if count == 0 {
				break;
			}
			length += count;
			if let Some(reference) = &self.reference {
				// Do not stop on a mismatch: later reads, cancellation and the
				// original final descriptor/path checks still have to run.
				matches_reference &=
					reference.get(length - count..length) == Some(&buffer[..count]);
			} else {
				hash.update(&buffer[..count]);
			}
			check_current()?;
		}
		check_current()?;
		verify_read(&self.path, &file, &stamp, length, self.maximum)?;
		check_current()?;
		let content_matches = match &self.reference {
			Some(reference) => matches_reference && length == reference.len(),
			None => hash.finish().as_ref() == self.digest,
		};
		if !content_matches {
			bail!("observation profile changed");
		}
		check_current()?;
		Ok(())
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SystemComponent {
	path: PathBuf,
	stamp: Stamp,
	link: Option<PathBuf>,
}

/// This is the only symlink exception. OpenSSH's fixed ProxyCommand invokes
/// /bin/sh when SHELL is absent. No profile-supplied path enters this resolver.
fn fixed_shell_resolution() -> Result<(PathBuf, Vec<SystemComponent>)> {
	let mut directory = File::open("/")?;
	let mut current = PathBuf::from("/");
	let mut remaining: VecDeque<std::ffi::OsString> = VecDeque::from(["bin".into(), "sh".into()]);
	let mut components = Vec::new();
	let mut links = 0usize;
	for _ in 0..64 {
		let info = directory.metadata()?;
		if !info.is_dir() || info.uid() != 0 || info.mode() & 0o6022 != 0 {
			bail!("unsupported observation system shell directory");
		}
		components.push(SystemComponent {
			path: current.clone(),
			stamp: Stamp::of(&info),
			link: None,
		});
		let part: std::ffi::OsString = remaining
			.pop_front()
			.context("observation system shell target missing")?;
		if part == "." {
			continue;
		}
		if part == ".." {
			if !current.pop() {
				bail!("observation system shell escapes root");
			}
			directory = open_absolute(&current, true)?;
			continue;
		}
		let name = std::ffi::CString::new(part.as_encoded_bytes())?;
		let fd = unsafe {
			libc::openat(
				directory.as_raw_fd(),
				name.as_ptr(),
				libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		let node = unsafe { File::from_raw_fd(fd) };
		let info = node.metadata()?;
		let path = current.join(&part);
		if info.file_type().is_symlink() {
			links += 1;
			if links > 8 || info.uid() != 0 || info.nlink() != 1 {
				bail!("unsupported observation system shell alias");
			}
			let mut target = vec![0u8; 4097];
			let count = unsafe {
				libc::readlinkat(
					node.as_raw_fd(),
					c"".as_ptr(),
					target.as_mut_ptr().cast(),
					target.len(),
				)
			};
			if count <= 0 || count as usize > 4096 {
				bail!("unsupported observation system shell alias target");
			}
			target.truncate(count as usize);
			let target = PathBuf::from(std::ffi::OsString::from_vec(target));
			let reopened = unsafe {
				libc::openat(
					directory.as_raw_fd(),
					name.as_ptr(),
					libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
				)
			};
			if reopened < 0 {
				return Err(std::io::Error::last_os_error().into());
			}
			let reopened = unsafe { File::from_raw_fd(reopened) };
			let stamp = Stamp::of(&info);
			if Stamp::of(&node.metadata()?) != stamp || Stamp::of(&reopened.metadata()?) != stamp {
				bail!("observation system shell alias changed");
			}
			components.push(SystemComponent {
				path,
				stamp,
				link: Some(target.clone()),
			});
			if target.is_absolute() {
				current = PathBuf::from("/");
				directory = File::open("/")?;
			}
			for part in target.components().rev() {
				match part {
					Component::Normal(value) => remaining.push_front(value.to_owned()),
					Component::ParentDir => remaining.push_front("..".into()),
					Component::CurDir => remaining.push_front(".".into()),
					Component::RootDir => {}
					_ => bail!("unsupported observation system shell alias target"),
				}
			}
		} else if info.is_dir() && !remaining.is_empty() {
			current = path;
			directory = node;
		} else if info.is_file() && remaining.is_empty() {
			return Ok((path, components));
		} else {
			bail!("unsupported observation system shell resolution");
		}
	}
	bail!("observation system shell resolution bound")
}

struct PinnedShell {
	components: Vec<SystemComponent>,
	target: PinnedFile,
}
impl PinnedShell {
	fn load(expected: &str, reference_budget: &mut usize) -> Result<Self> {
		let (path, components) = fixed_shell_resolution()?;
		let (mut target, bytes) =
			PinnedFile::load(&path, Some(expected), 16 * 1024 * 1024, false, true)?;
		target.reference = bounded_executable_reference(bytes, reference_budget);
		let result = Self { components, target };
		result.verify()?;
		Ok(result)
	}
	fn verify_resolution(&self) -> Result<()> {
		let (path, components) = fixed_shell_resolution()?;
		if path != self.target.path
			|| components.len() != self.components.len()
			|| components
				.iter()
				.zip(&self.components)
				.any(|(now, expected)| {
					now.path != expected.path
						|| now.link != expected.link
						|| if now.link.is_some() {
							now.stamp != expected.stamp
						} else {
							!now.stamp.same_directory(&expected.stamp)
						}
				}) {
			bail!("observation fixed system shell resolution changed");
		}
		Ok(())
	}
	fn verify(&self) -> Result<()> {
		self.verify_resolution()?;
		self.target.verify()
	}
}

pub(super) struct ComponentPins {
    ssh: PinnedFile, false_program: PinnedFile, shell: PinnedShell,
}
pub(super) fn load(spec: &crate::PublicPins) -> Result<ComponentPins> {
		let mut reference_budget = MAX_EXECUTABLE_REFERENCE_BYTES;
		let (mut ssh, ssh_bytes) = PinnedFile::load(
			Path::new("/usr/bin/ssh"),
			Some(&spec.ssh_sha256),
			16 * 1024 * 1024,
			false,
			true,
		)?;
		// Only fixed public executables share this profile's reference byte budget.
		// Files that do not fit keep SHA and leave the remaining budget unchanged.
		ssh.reference = bounded_executable_reference(ssh_bytes, &mut reference_budget);
		let (mut false_program, false_bytes) = PinnedFile::load(
			Path::new("/usr/bin/false"),
			Some(&spec.false_sha256),
			1024 * 1024,
			false,
			true,
		)?;
		false_program.reference = bounded_executable_reference(false_bytes, &mut reference_budget);
		let shell = PinnedShell::load(&spec.shell_sha256, &mut reference_budget)?;
    if ssh.reference.is_none() || false_program.reference.is_none()
        || shell.target.reference.is_none() {
        bail!("screen requires all three public files to fit the R23 reference budget");
    }
    Ok(ComponentPins { ssh, false_program, shell })
}
impl ComponentPins {
    fn pin(&self, index: usize) -> &PinnedFile {
        match index { 0 => &self.ssh, 1 => &self.false_program, 2 => &self.shell.target,
            _ => unreachable!("fixed three-file screen") }
    }
}
impl crate::ScreenArm for ComponentPins {
    fn verify(&self, scenario: usize, ticket: &crate::guard::OwnerTicket) -> Result<()> {
        let range = if scenario == 3 { 0..3 } else { scenario..scenario + 1 };
        for index in range {
            ticket.check_current()?;
            if index == 2 {
                self.shell.verify_resolution()?;
                ticket.check_current()?;
            }
            self.pin(index).verify_checked(&|| ticket.check_current())?;
            ticket.check_current()?;
        }
        Ok(())
    }
    fn preflight(&self) -> Result<serde_json::Value> {
        use std::cell::Cell;
        self.shell.verify_resolution()?;
        let mut rows = Vec::new();
        for index in 0..3 {
            let pin = self.pin(index);
            let good = crate::guard::new();
            let complete = Cell::new(0usize);
            pin.verify_checked(&|| {
                complete.set(complete.get() + 1);
                good.check_current()
            })?;
            let mut bad = pin.clone();
            let mut bytes = pin.reference.as_ref().context("reference missing")?.to_vec();
            if bytes.is_empty() { bail!("fixed executable unexpectedly empty"); }
            bytes[0] ^= 1;
            bad.reference = Some(bytes.into());
            let count = Cell::new(0usize);
            let failure = bad.verify_checked(&|| {
                count.set(count.get() + 1);
                good.check_current()
            }).err().context("reference mismatch was accepted")?;
            if failure.to_string() != "observation profile changed"
                || count.get() + 1 != complete.get() {
                bail!("complete-read mismatch preflight failed");
            }
            let late = crate::guard::new();
            let count_late = Cell::new(0usize);
            let failure = bad.verify_checked(&|| {
                count_late.set(count_late.get() + 1);
                if count_late.get() == complete.get() - 2 { crate::guard::cancel(&late); }
                late.check_current()
            }).err().context("late cancellation was accepted")?;
            if failure.to_string() != crate::CANCEL_ERROR {
                bail!("late cancellation did not retain precedence over content mismatch");
            }
            let stopped = crate::guard::new();
            crate::guard::cancel(&stopped);
            let failure = pin.verify_checked(&|| stopped.check_current())
                .err().context("cancelled validation was accepted")?;
            if failure.to_string() != crate::CANCEL_ERROR { bail!("cancel result differs"); }
            let mut expired = crate::guard::new();
            crate::guard::expire(&mut expired);
            let failure = pin.verify_checked(&|| expired.check_current())
                .err().context("expired validation was accepted")?;
            if failure.to_string() != crate::CANCEL_ERROR { bail!("expiry result differs"); }
            rows.push(serde_json::json!({"index": index, "bytes": pin.stamp.len,
                "complete_checkpoints": complete.get(), "mismatch_checkpoints": count.get(),
                "late_cancel_preempts_mismatch": true, "cancel_and_expiry_rejected": true}));
        }
        self.shell.verify_resolution()?;
        Ok(serde_json::json!({"buffer_bytes": VERIFY_BUFFER_BYTES, "files": rows}))
    }
}
pub(super) fn discover_public_pins() -> Result<(crate::PublicPins, serde_json::Value)> {
    let (shell_path, _) = fixed_shell_resolution()?;
    let paths = [PathBuf::from("/usr/bin/ssh"), PathBuf::from("/usr/bin/false"), shell_path];
    let maxima = [16 * 1024 * 1024, 1024 * 1024, 16 * 1024 * 1024];
    let mut hexes = Vec::new();
    let mut rows = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let (pin, _) = PinnedFile::load(path, None, maxima[index], false, true)?;
        let hex = pin.digest.iter().map(|v| format!("{v:02x}")).collect::<String>();
        rows.push(serde_json::json!({"role": crate::SCENARIOS[index],
            "path": path.to_str().context("public path is not UTF-8")?,
            "bytes": pin.stamp.len, "sha256": hex}));
        hexes.push(hex);
    }
    Ok((crate::PublicPins { ssh_sha256: hexes[0].clone(),
        false_sha256: hexes[1].clone(), shell_sha256: hexes[2].clone() },
        serde_json::json!(rows)))
}

}

use anyhow::{bail, Context, Result};
const SCENARIOS: [&str; 4] = ["ssh", "false", "shell", "public_triplet"];
const CANCEL_ERROR: &str = "observation validation cancelled or expired before authority acceptance";
struct PublicPins { ssh_sha256: String, false_sha256: String, shell_sha256: String }
trait ScreenArm {
    fn verify(&self, scenario: usize, ticket: &guard::OwnerTicket) -> Result<()>;
    fn preflight(&self) -> Result<serde_json::Value>;
}
fn clock_ns(clock: libc::clockid_t) -> u64 {
	let mut value = libc::timespec {
		tv_sec: 0,
		tv_nsec: 0,
	};
	assert_eq!(unsafe { libc::clock_gettime(clock, &mut value) }, 0);
	value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
}

fn main() -> Result<()> {
    if std::env::args().len() != 1 { bail!("the frozen screen takes no runtime parameters"); }
    let (pins, public) = arm16::discover_public_pins()?;
    let a = arm16::load(&pins)?;
    let b = arm64::load(&pins)?;
    let arms: [&dyn ScreenArm; 2] = [&a, &b];
    let preflight = [a.preflight()?, b.preflight()?];
    println!("{}", serde_json::json!({"kind": "setup",
        "profile_sha256": "a62169343c2a08c38d69925f33fdc7551cf4be7b4b7f50cf89683f652a8f853a", "validation_sha256": "65fb35aaf7cafc8f561bf7cce5fcd0ffb3ad98b2328245ed88d5dfce45b3a056",
        "blocks": 3, "iterations": 256, "warmup_per_scenario_arm": 8,
        "buffers": [16384, 65536], "scenarios": SCENARIOS,
        "public_inputs": public, "preflight": preflight,
        "scope": "public-file component only; no worker/owner lifecycle or RPC workload",
        "private_profile_read": false, "rss_comparable": false,
        "pins_source": "fixed public-file fingerprints; no private profile pin extraction"}));
    for scenario in 0..4 {
        for arm in &arms {
            let ticket = guard::new();
            for _ in 0..8 { arm.verify(scenario, &ticket)?; }
        }
        for block in 0..3 {
            for (position, index) in [0usize, 1, 1, 0].into_iter().enumerate() {
                let ticket = guard::new();
                let escape = guard::keep_alive(&ticket);
                std::hint::black_box(&escape);
                let wall_start = clock_ns(libc::CLOCK_MONOTONIC);
                let thread_start = clock_ns(libc::CLOCK_THREAD_CPUTIME_ID);
                let process_start = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID);
                for _ in 0..256 { arms[index].verify(scenario, &ticket)?; }
                let process_end = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID);
                let thread_end = clock_ns(libc::CLOCK_THREAD_CPUTIME_ID);
                let wall_end = clock_ns(libc::CLOCK_MONOTONIC);
                std::hint::black_box(&escape);
                println!("{}", serde_json::json!({"kind": "sample",
                    "scenario": SCENARIOS[scenario], "block": block, "position": position,
                    "buffer_bytes": ([16384, 65536][index]), "iterations": 256,
                    "wall_start_ns": wall_start, "wall_end_ns": wall_end,
                    "thread_cpu_start_ns": thread_start, "thread_cpu_end_ns": thread_end,
                    "process_cpu_start_ns": process_start, "process_cpu_end_ns": process_end}));
            }
        }
    }
    a.preflight()?;
    b.preflight()?;
    println!("{}", serde_json::json!({"kind": "complete", "sample_cells": 48,
        "automatic_retries": 0, "final_public_checks_passed": true}));
    Ok(())
}
