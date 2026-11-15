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
//! Descriptor-confined admission and create-only durable capture publication.

use anyhow::{bail, Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) const SCHEMA: &str = "hepta.rea.local-browser-capture.v1";
pub(super) const ENTRY: &str = "/__hepta_fixture__";
pub(super) const PROBE: &str = "/__hepta_blocked__";
pub(super) const CONTROL: &str = "/__hepta_control__";
pub(super) const MAX_BODY: usize = 64 * 1024;
pub(super) const MAX_TOTAL_BODY: usize = 2 * 1024 * 1024;
pub(super) const MAX_HAR: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
	pub file: String,
	pub sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Resource {
	pub url_path: String,
	pub mime_type: String,
	pub before: Source,
	pub after: Option<Source>,
	#[serde(default = "delivery")]
	pub delivery: String,
	#[serde(default)]
	pub delay_ms: u64,
}

fn delivery() -> String {
	"complete".into()
}

fn timeout() -> u64 {
	30
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
	pub schema: String,
	pub resources: Vec<Resource>,
	pub requests: Vec<String>,
	#[serde(default = "timeout")]
	pub timeout_seconds: u64,
}

#[derive(Clone)]
pub(super) struct Snapshot {
	pub resource: Resource,
	pub before: Arc<[u8]>,
	pub after: Arc<[u8]>,
}

pub(super) struct Admission {
	pub parent: Directory,
	pub manifest: Manifest,
	pub manifest_sha256: String,
	pub snapshots: Vec<Snapshot>,
	pub output_name: String,
}

pub(super) struct Directory {
	pub file: File,
	pub path: PathBuf,
}

pub(super) fn sha256(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

pub(super) fn validate_sha256(value: &str) -> Result<()> {
	if value.len() != 64
		|| !value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
	{
		bail!("SHA-256 must contain exactly 64 lowercase hexadecimal characters");
	}
	Ok(())
}

pub(super) fn relative_parts(path: &str) -> Result<Vec<&str>> {
	if path.is_empty() || path.len() > 512 || path.contains(['\\', '\0']) {
		bail!("resource path is empty, too long, or contains forbidden characters");
	}
	let parts: Vec<_> = path.split('/').collect();
	if parts.len() > 16
		|| parts
			.iter()
			.any(|p| p.is_empty() || *p == "." || *p == "..")
	{
		bail!("resource path must contain 1..16 normalized relative components");
	}
	Ok(parts)
}

fn absolute_parts(path: &str) -> Result<Vec<&str>> {
	if !path.starts_with('/') || path.len() > 4096 {
		bail!("capture path must be absolute and at most 4096 bytes");
	}
	if path == "/" {
		return Ok(Vec::new());
	}
	let parts: Vec<_> = path[1..].split('/').collect();
	if parts
		.iter()
		.any(|p| p.is_empty() || *p == "." || *p == ".." || p.contains(['\\', '\0']))
	{
		bail!("capture path must be normalized, without dot, empty, or symlink components");
	}
	Ok(parts)
}

pub(super) fn open_at(parent: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
	let name = CString::new(name)?;
	// SAFETY: borrowed descriptor and terminated name remain valid throughout openat.
	let fd = unsafe {
		libc::openat(
			parent.as_raw_fd(),
			name.as_ptr(),
			flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
			mode,
		)
	};
	if fd < 0 {
		return Err(std::io::Error::last_os_error()).context("descriptor-relative open refused");
	}
	// SAFETY: openat returned one newly owned descriptor.
	Ok(unsafe { File::from_raw_fd(fd) })
}

impl Directory {
	pub fn open_absolute(path: &str) -> Result<Self> {
		let parts = absolute_parts(path)?;
		let mut file = File::open("/")?;
		for part in parts {
			file = open_at(&file, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
		}
		Ok(Self {
			file,
			path: PathBuf::from(path),
		})
	}

	/// Rebind a reported path to the retained descriptor. Same-UID hostile racing
	/// remains outside this helper's isolation guarantee; detected renames refuse.
	pub fn verify_location(&self) -> Result<()> {
		use std::os::unix::fs::MetadataExt;
		let path = self
			.path
			.to_str()
			.context("non-UTF8 capture directory path")?;
		let current =
			Self::open_absolute(path).context("capture directory path identity unconfirmed")?;
		let expected = self.file.metadata()?;
		let actual = current.file.metadata()?;
		if expected.dev() != actual.dev() || expected.ino() != actual.ino() || expected.nlink() == 0
		{
			bail!("capture directory path no longer names the retained descriptor; outcome unconfirmed");
		}
		Ok(())
	}

	pub fn create_child(&self, name: &str) -> Result<Self> {
		self.verify_location()?;
		if relative_parts(name)?.len() != 1 {
			bail!("output must be one direct child name");
		}
		let name_c = CString::new(name)?;
		// SAFETY: parent descriptor and C string are valid; mkdirat is create-only.
		if unsafe { libc::mkdirat(self.file.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("new capture directory refused; never overwrite or retry automatically");
		}
		self.file
			.sync_all()
			.context("capture directory publication durability unconfirmed")?;
		let file = open_at(&self.file, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
		let child = Self {
			file,
			path: self.path.join(name),
		};
		self.verify_location()?;
		child.verify_location()?;
		Ok(child)
	}

	pub fn read_snapshot(&self, relative: &str, maximum: usize) -> Result<Vec<u8>> {
		self.verify_location()?;
		let parts = relative_parts(relative)?;
		let mut parent = self.file.try_clone()?;
		for part in &parts[..parts.len() - 1] {
			parent = open_at(&parent, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
		}
		let mut file = open_at(
			&parent,
			parts[parts.len() - 1],
			libc::O_RDONLY | libc::O_NONBLOCK,
			0,
		)?;
		let before = file.metadata()?;
		if !before.is_file() || before.len() > maximum as u64 {
			bail!("capture input must be a bounded regular file");
		}
		let mut bytes = Vec::with_capacity(before.len() as usize);
		Read::by_ref(&mut file)
			.take(maximum as u64 + 1)
			.read_to_end(&mut bytes)?;
		if bytes.len() > maximum || bytes.len() as u64 != before.len() {
			bail!("capture input changed or exceeded its read budget");
		}
		crate::mcp::rea_files::ensure_unchanged(&before, &file.metadata()?)?;
		self.verify_location()?;
		Ok(bytes)
	}

	pub fn publish(&self, name: &str, bytes: &[u8], maximum: usize) -> Result<()> {
		self.verify_location()?;
		if bytes.len() > maximum || relative_parts(name)?.len() != 1 {
			bail!("capture publication exceeds its fixed budget or name contract");
		}
		let stage = format!(".stage-{}", random_name()?);
		let mut file = open_at(
			&self.file,
			&stage,
			libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
			0o600,
		)?;
		let stage_c = CString::new(stage)?;
		let name_c = CString::new(name)?;
		let mut linked = false;
		let result = (|| {
			file.write_all(bytes)?;
			file.sync_all()?;
			// SAFETY: both directory descriptors remain owned; linkat never replaces a name.
			if unsafe {
				libc::linkat(
					self.file.as_raw_fd(),
					stage_c.as_ptr(),
					self.file.as_raw_fd(),
					name_c.as_ptr(),
					0,
				)
			} != 0
			{
				return Err(std::io::Error::last_os_error())
					.context("create-only capture publication refused");
			}
			linked = true;
			self.file.sync_all()?;
			self.verify_location()?;
			Ok(())
		})();
		// SAFETY: stage is a private, freshly created direct child name.
		let removed = unsafe { libc::unlinkat(self.file.as_raw_fd(), stage_c.as_ptr(), 0) } == 0;
		let durable = self.file.sync_all();
		if linked && (result.is_err() || !removed || durable.is_err()) {
			bail!("capture publication unconfirmed after linking; inspect the original job and output, do not retry automatically");
		}
		result?;
		if !removed {
			bail!("capture staging cleanup unconfirmed");
		}
		durable?;
		self.verify_location()
			.context("capture publication path identity unconfirmed")?;
		Ok(())
	}
}

pub(super) fn random_name() -> Result<String> {
	let mut bytes = [0u8; 16];
	SystemRandom::new()
		.fill(&mut bytes)
		.map_err(|_| anyhow::anyhow!("private capture randomness unavailable"))?;
	Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub(super) fn admit(args: &super::BrowserCaptureArgs) -> Result<Admission> {
	absolute_parts(&args.manifest)?;
	absolute_parts(&args.output_directory)?;
	validate_sha256(&args.expected_sha256)?;
	let path = Path::new(&args.manifest);
	let parent_path = path.parent().context("manifest has no parent")?;
	let output = Path::new(&args.output_directory);
	if output.parent() != Some(parent_path) {
		bail!("output directory must be a new direct child of the manifest parent");
	}
	let parent =
		Directory::open_absolute(parent_path.to_str().context("non-UTF8 manifest parent")?)?;
	let manifest_name = path
		.file_name()
		.and_then(|p| p.to_str())
		.context("invalid manifest filename")?;
	let bytes = parent.read_snapshot(manifest_name, 64 * 1024)?;
	let digest = sha256(&bytes);
	if digest != args.expected_sha256 {
		bail!("manifest SHA-256 mismatch");
	}
	let manifest: Manifest =
		serde_json::from_slice(&bytes).context("invalid fixed capture manifest")?;
	if manifest.schema != SCHEMA
		|| !(1..=16).contains(&manifest.resources.len())
		|| !(1..=32).contains(&manifest.requests.len())
		|| !(1..=60).contains(&manifest.timeout_seconds)
	{
		bail!("capture schema or resource/request/timeout bound refused");
	}
	let mut urls = BTreeSet::new();
	let mut cache: BTreeMap<(String, String), Arc<[u8]>> = BTreeMap::new();
	let mut total = 0usize;
	let mut snapshots = Vec::new();
	for resource in &manifest.resources {
		let url = &resource.url_path;
		if !url.starts_with('/')
			|| url.starts_with("/__hepta_")
			|| url.len() > 128
			|| !url
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
			|| relative_parts(&url[1..]).is_err()
			|| !urls.insert(url.clone())
		{
			bail!("resource URL path must be unique, normalized, bounded and non-reserved");
		}
		if resource.mime_type.is_empty()
			|| resource.mime_type.len() > 128
			|| !resource.mime_type.bytes().all(|b| (32..=126).contains(&b))
			|| !matches!(resource.delivery.as_str(), "complete" | "truncated")
			|| resource.delay_ms > 2000
		{
			bail!("resource MIME, delivery, or delay refused");
		}
		let mut read_source = |source: &Source| -> Result<Arc<[u8]>> {
			validate_sha256(&source.sha256)?;
			relative_parts(&source.file)?;
			let key = (source.file.clone(), source.sha256.clone());
			let bytes = if let Some(bytes) = cache.get(&key) {
				bytes.clone()
			} else {
				let bytes: Arc<[u8]> = parent.read_snapshot(&source.file, MAX_BODY)?.into();
				if sha256(&bytes) != source.sha256 {
					bail!("resource SHA-256 mismatch for {}", source.file);
				}
				cache.insert(key, bytes.clone());
				bytes
			};
			total += bytes.len();
			if total > MAX_TOTAL_BODY {
				bail!("source snapshots exceed the combined two-phase budget");
			}
			Ok(bytes)
		};
		let before = read_source(&resource.before)?;
		let after = read_source(resource.after.as_ref().unwrap_or(&resource.before))?;
		snapshots.push(Snapshot {
			resource: resource.clone(),
			before,
			after,
		});
	}
	if manifest.requests.iter().any(|path| !urls.contains(path)) {
		bail!("requests must select declared resource URLs");
	}
	let output_name = output
		.file_name()
		.and_then(|p| p.to_str())
		.context("invalid output directory name")?
		.to_owned();
	if relative_parts(&output_name)?.len() != 1 {
		bail!("invalid output directory name");
	}
	Ok(Admission {
		parent,
		manifest,
		manifest_sha256: digest,
		snapshots,
		output_name,
	})
}
