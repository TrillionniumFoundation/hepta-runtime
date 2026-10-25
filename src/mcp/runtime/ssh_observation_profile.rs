// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! Explicitly supported, immutable inputs for the opt-in observation transport.
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{timeout_at, Instant};

const MAX_PROFILE_BYTES: usize = 256 * 1024;
const MAX_AGENT_BYTES: usize = 64 * 1024;
const VERIFY_BUFFER_BYTES: usize = 16 * 1024;
const DIRECTIVES: &[&str] = &[
	"batchmode",
	"connecttimeout",
	"controlmaster",
	"forwardagent",
	"globalknownhostsfile",
	"host",
	"hostkeyalias",
	"hostname",
	"port",
	"stricthostkeychecking",
	"user",
	"userknownhostsfile",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Specification {
	schema: String,
	allow_bounded_cached_authentication: bool,
	ssh_config: PathBuf,
	ssh_config_sha256: String,
	known_hosts: PathBuf,
	known_hosts_sha256: String,
	ssh_sha256: String,
	false_sha256: String,
	shell_sha256: String,
	agent_socket: PathBuf,
	socket_parent: PathBuf,
}

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
		// Rehash every byte on every check without allocating a whole executable.
		// The same descriptor and path stamps still fence the complete read.
		let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
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
			hash.update(&buffer[..count]);
			check_current()?;
		}
		check_current()?;
		verify_read(&self.path, &file, &stamp, length, self.maximum)?;
		check_current()?;
		if hash.finish().as_ref() != self.digest {
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
	fn load(expected: &str) -> Result<Self> {
		let (path, components) = fixed_shell_resolution()?;
		let (target, _) = PinnedFile::load(&path, Some(expected), 16 * 1024 * 1024, false, true)?;
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

fn validate_config(bytes: &[u8], known_hosts: &Path) -> Result<()> {
	let raw = std::str::from_utf8(bytes)?;
	for original in raw.lines() {
		let line = original.split('#').next().unwrap_or_default().trim();
		if line.is_empty() {
			continue;
		}
		// The first scope deliberately has no quoted/multi-source/dynamic syntax.
		if line
			.chars()
			.any(|v| matches!(v, '\'' | '"' | '\\' | '%' | '$' | '`'))
		{
			bail!("unsupported observation SSH config syntax");
		}
		let split = line
			.find(|v: char| v.is_ascii_whitespace() || v == '=')
			.context("unsupported observation SSH config line")?;
		let key = line[..split].to_ascii_lowercase();
		let value = line[split..].trim_start_matches(|v: char| v.is_ascii_whitespace() || v == '=');
		if !DIRECTIVES.contains(&key.as_str()) || value.is_empty() {
			bail!("unsupported observation SSH config directive");
		}
		let values: Vec<_> = value.split_ascii_whitespace().collect();
		if key == "host" {
			if values
				.iter()
				.any(|v| *v != "*" && !crate::mcp::runtime::config::valid_name(v))
			{
				bail!("unsupported observation SSH host pattern");
			}
		} else if values.len() != 1 {
			bail!("unsupported observation SSH config value");
		}
		match key.as_str() {
			"userknownhostsfile" if value != known_hosts.to_str().unwrap_or_default() => {
				bail!("undeclared observation known-hosts input")
			}
			"globalknownhostsfile" if value != "/dev/null" => {
				bail!("unsupported observation global known-hosts input")
			}
			"stricthostkeychecking" | "batchmode" if value != "yes" => {
				bail!("unsupported observation authentication policy")
			}
			"forwardagent" if value != "no" => bail!("observation agent forwarding is unsupported"),
			"port" if value.parse::<u16>().ok().is_none_or(|v| v == 0) => {
				bail!("unsupported observation SSH port")
			}
			"connecttimeout" if value.parse::<u16>().ok().is_none_or(|v| v == 0 || v > 60) => {
				bail!("unsupported observation SSH timeout")
			}
			"controlmaster" if !matches!(value, "no" | "yes" | "auto") => {
				bail!("unsupported observation master setting")
			}
			_ => {}
		}
	}
	Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AgentIdentity {
	stamp: Stamp,
	peer: (i32, u32, u32),
	keys: [u8; 32],
}

pub(super) fn peer(stream: &UnixStream) -> Result<(i32, u32, u32)> {
	let mut value: libc::ucred = unsafe { std::mem::zeroed() };
	let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
	if unsafe {
		libc::getsockopt(
			stream.as_raw_fd(),
			libc::SOL_SOCKET,
			libc::SO_PEERCRED,
			(&mut value as *mut libc::ucred).cast(),
			&mut len,
		)
	} != 0 || len as usize != std::mem::size_of::<libc::ucred>()
	{
		bail!("observation Unix peer identity unavailable");
	}
	Ok((value.pid, value.uid, value.gid))
}

pub(super) fn socket_stamp(path: &Path) -> Result<Stamp> {
	socket_stamp_inner(path, true)
}

fn socket_stamp_inner(path: &Path, strict_mode: bool) -> Result<Stamp> {
	absolute(path)?;
	let parent = path.parent().context("observation socket has no parent")?;
	let opened = open_absolute(parent, true)?;
	let parent_before = Stamp::of(&opened.metadata()?);
	if !parent_before.same_directory(&private_directory(parent)?) {
		bail!("observation socket parent changed");
	}
	let name = std::ffi::CString::new(
		path.file_name()
			.context("observation socket name missing")?
			.as_encoded_bytes(),
	)?;
	let mut value: libc::stat = unsafe { std::mem::zeroed() };
	if unsafe {
		libc::fstatat(
			opened.as_raw_fd(),
			name.as_ptr(),
			&mut value,
			libc::AT_SYMLINK_NOFOLLOW,
		)
	} != 0
	{
		return Err(std::io::Error::last_os_error().into());
	}
	if value.st_mode & libc::S_IFMT != libc::S_IFSOCK
		|| value.st_uid != unsafe { libc::geteuid() }
		|| (strict_mode && value.st_mode & 0o077 != 0)
		|| value.st_mode & 0o7000 != 0
	{
		bail!("observation socket is not private and account-owned");
	}
	if !parent_before.same_directory(&private_directory(parent)?) {
		bail!("observation socket parent changed");
	}
	Ok(Stamp {
		dev: value.st_dev,
		ino: value.st_ino,
		uid: value.st_uid,
		mode: value.st_mode,
		nlink: value.st_nlink,
		len: value.st_size.try_into()?,
		mtime: (value.st_mtime, value.st_mtime_nsec),
		ctime: (value.st_ctime, value.st_ctime_nsec),
	})
}

fn agent_identities(bytes: &[u8]) -> Result<[u8; 32]> {
	if bytes.len() < 5 || bytes[0] != 12 {
		bail!("unsupported observation SSH agent response");
	}
	let number = u32::from_be_bytes(bytes[1..5].try_into()?) as usize;
	if number == 0 || number > 64 {
		bail!("observation SSH agent identities bound");
	}
	let mut position = 5usize;
	for _ in 0..number * 2 {
		let end = position.checked_add(4).context("agent frame overflow")?;
		let length = u32::from_be_bytes(
			bytes
				.get(position..end)
				.context("truncated agent frame")?
				.try_into()?,
		) as usize;
		position = end.checked_add(length).context("agent frame overflow")?;
		if position > bytes.len() {
			bail!("truncated agent identity");
		}
	}
	if position != bytes.len() {
		bail!("extra agent identity bytes");
	}
	Ok(digest(bytes))
}

// Only this exact lookup timer creates the typed error. I/O timeouts, malformed
// frames and failed socket/peer checks remain ordinary authority failures.
// Expiry can reflect the RPC budget or owner scheduling; it supplies no
// credential result and does not identify which part of the lookup was delayed.
#[derive(Debug)]
pub(super) struct AgentLookupDeadline(tokio::time::error::Elapsed);

impl std::fmt::Display for AgentLookupDeadline {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("observation SSH agent deadline")
	}
}

impl std::error::Error for AgentLookupDeadline {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		Some(&self.0)
	}
}

pub(super) async fn agent_snapshot(path: &Path, deadline: Instant) -> Result<AgentIdentity> {
	// Forwarded agent sockets may be0775; their descriptor-checked0700
	// account-owned parent is the confidentiality boundary. Control sockets
	// still use the stricter individual socket mode check above.
	let before = socket_stamp_inner(path, false)?;
	timeout_at(deadline, async {
		let mut stream = UnixStream::connect(path).await?;
		let peer = peer(&stream)?;
		if peer.1 != unsafe { libc::geteuid() } {
			bail!("observation SSH agent peer is not account-owned");
		}
		stream.write_all(&[0, 0, 0, 1, 11]).await?;
		let mut length = [0; 4];
		stream.read_exact(&mut length).await?;
		let length = u32::from_be_bytes(length) as usize;
		if !(5..=MAX_AGENT_BYTES).contains(&length) {
			bail!("observation SSH agent frame bound");
		}
		let mut bytes = vec![0; length];
		stream.read_exact(&mut bytes).await?;
		let keys = agent_identities(&bytes)?;
		if socket_stamp_inner(path, false)? != before {
			bail!("observation SSH agent socket changed");
		}
		Ok(AgentIdentity {
			stamp: before,
			peer,
			keys,
		})
	})
	.await
	.map_err(AgentLookupDeadline)?
}

pub(super) struct Profile {
	files: Vec<PinnedFile>,
	shell: PinnedShell,
	pub config: PathBuf,
	pub known_hosts: PathBuf,
	pub agent: PathBuf,
	pub socket_parent: PathBuf,
	pub parent_stamp: Stamp,
	pub hosts: BTreeMap<String, String>,
	policy: [u8; 32],
	pub ssh_inode: (u64, u64),
}

impl Profile {
	pub(super) fn load(path: &Path) -> Result<Self> {
		let (profile, bytes) = PinnedFile::load(path, None, MAX_PROFILE_BYTES, true, false)?;
		let spec: Specification = serde_json::from_slice(&bytes)?;
		if spec.schema != "hepta-observation-ssh-pool/v1"
			|| !spec.allow_bounded_cached_authentication
		{
			bail!("observation profile must explicitly authorize bounded cached authentication");
		}
		for item in [
			&spec.ssh_config,
			&spec.known_hosts,
			&spec.agent_socket,
			&spec.socket_parent,
		] {
			absolute(item)?;
		}
		if std::env::var_os("SSH_AUTH_SOCK").as_deref() != Some(spec.agent_socket.as_os_str()) {
			bail!("observation profile requires its direct current SSH agent");
		}
		let (config, raw) = PinnedFile::load(
			&spec.ssh_config,
			Some(&spec.ssh_config_sha256),
			MAX_PROFILE_BYTES,
			true,
			false,
		)?;
		let (known, _) = PinnedFile::load(
			&spec.known_hosts,
			Some(&spec.known_hosts_sha256),
			MAX_PROFILE_BYTES,
			true,
			false,
		)?;
		validate_config(&raw, &spec.known_hosts)?;
		let (ssh, _) = PinnedFile::load(
			Path::new("/usr/bin/ssh"),
			Some(&spec.ssh_sha256),
			16 * 1024 * 1024,
			false,
			true,
		)?;
		let (false_program, _) = PinnedFile::load(
			Path::new("/usr/bin/false"),
			Some(&spec.false_sha256),
			1024 * 1024,
			false,
			true,
		)?;
		let shell = PinnedShell::load(&spec.shell_sha256)?;
		let runtime = crate::mcp::runtime::config::runtime_config()?;
		let hosts: BTreeMap<_, _> = runtime
			.hosts
			.iter()
			.map(|(name, host)| (name.clone(), host.ssh_target.clone()))
			.collect();
		if hosts.len() > 8
			|| hosts
				.values()
				.any(|target| !crate::mcp::runtime::config::valid_name(target))
		{
			bail!("observation profile supports at most eight literal SSH aliases");
		}
		Ok(Self {
			ssh_inode: (ssh.stamp.dev, ssh.stamp.ino),
			files: vec![profile, config, known, ssh, false_program],
			shell,
			config: spec.ssh_config,
			known_hosts: spec.known_hosts,
			agent: spec.agent_socket,
			parent_stamp: private_directory(&spec.socket_parent)?,
			socket_parent: spec.socket_parent,
			hosts,
			policy: digest(&serde_json::to_vec(runtime)?),
		})
	}
	pub(super) fn verify_files(&self) -> Result<()> {
		for file in &self.files {
			file.verify()?;
		}
		self.shell.verify()?;
		self.verify_policy()
	}
	pub(super) fn verify_files_checked(
		&self,
		check_current: &impl Fn() -> Result<()>,
	) -> Result<()> {
		for file in &self.files {
			check_current()?;
			file.verify_checked(check_current)?;
			check_current()?;
		}
		check_current()?;
		self.shell.verify_resolution()?;
		check_current()?;
		self.shell.target.verify_checked(check_current)?;
		check_current()?;
		self.verify_policy()?;
		check_current()
	}
	pub(super) fn verify_boundaries(&self, check_current: &impl Fn() -> Result<()>) -> Result<()> {
		for file in &self.files {
			check_current()?;
			file.verify_identity()?;
			check_current()?;
		}
		check_current()?;
		self.shell.verify_resolution()?;
		check_current()?;
		self.shell.target.verify_identity()?;
		check_current()?;
		self.verify_policy()?;
		check_current()
	}
	fn verify_policy(&self) -> Result<()> {
		if !private_directory(&self.socket_parent)?.same_directory(&self.parent_stamp)
			|| digest(&serde_json::to_vec(
				crate::mcp::runtime::config::runtime_config()?,
			)?) != self.policy
			|| std::env::var_os("SSH_AUTH_SOCK").as_deref() != Some(self.agent.as_os_str())
		{
			bail!("observation policy or credential profile changed");
		}
		Ok(())
	}
}

#[cfg(test)]
#[path = "ssh_observation_profile_tests.rs"]
mod tests;
