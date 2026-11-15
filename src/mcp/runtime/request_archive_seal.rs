// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded, interruptible integrity seals for disposable, durable cache images.
use super::*;
use std::os::unix::fs::FileExt;

const SEAL_NAME: &str = ".request-archive-index-seal-v1.json";
const LEGACY_FORMAT: &str = "hepta-redb-4.4.0-recovery-bit-sha256-v1";
const FORMAT: &str = "hepta-redb-4.4.0-recovery-bit-two-part-sha256-v2";
const DOMAIN: &[u8] = b"hepta-redb4.4.0-two-part-seal-v2\0";
const MAX_SEAL_BYTES: u64 = 4096;
const HASH_CHUNK: usize = 1024 * 1024;
const MAGIC: [u8; 9] = [b'r', b'e', b'd', b'b', 0x1a, 0x0a, 0xa9, 0x0d, 0x0a];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Seal {
	format: String,
	binding: Vec<u8>,
	device: u64,
	inode: u64,
	length: u64,
	sha256: String,
}

fn unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
	before.dev() == after.dev()
		&& before.ino() == after.ino()
		&& before.mode() == after.mode()
		&& before.uid() == after.uid()
		&& before.nlink() == after.nlink()
		&& before.len() == after.len()
		&& (before.mtime(), before.mtime_nsec()) == (after.mtime(), after.mtime_nsec())
		&& (before.ctime(), before.ctime_nsec()) == (after.ctime(), after.ctime_nsec())
}

fn legacy_digest(
	file: &File,
	deadline: Instant,
	cancelled: impl Fn() -> Result<bool>,
) -> Result<Option<String>> {
	private_cache(file)?;
	let _cache_read_hint = CacheReadHint::new(file, false);
	let before = file.metadata()?;
	if before.len() < 320 {
		return Ok(None);
	}
	let mut buffer = vec![0u8; HASH_CHUNK];
	let mut hash = ArchiveHash::new();
	let mut offset = 0u64;
	while offset < before.len() {
		if Instant::now() >= deadline {
			bail!("archive cache seal deadline");
		}
		if cancelled()? {
			return Ok(None);
		}
		let count = (before.len() - offset).min(HASH_CHUNK as u64) as usize;
		file.read_exact_at(&mut buffer[..count], offset)?;
		if offset == 0 {
			if buffer[..9] != MAGIC {
				return Ok(None);
			}
			// Pinned redb 4.4.0 header.rs: only byte 9, bit 1 is the open/close
			// recovery marker. Hash every other bit, both commit slots and all data.
			// Review this format-specific normalization before upgrading redb.
			buffer[9] &= !2;
		}
		hash.update(&buffer[..count]);
		offset += count as u64;
	}
	if !unchanged(&before, &file.metadata()?) {
		bail!("archive cache changed during seal");
	}
	const HEX: &[u8; 16] = b"0123456789abcdef";
	let mut result = String::with_capacity(64);
	for byte in hash.finalize() {
		result.push(HEX[(byte >> 4) as usize] as char);
		result.push(HEX[(byte & 15) as usize] as char);
	}
	Ok(Some(result))
}

// Keep exactly two disjoint byte ranges, including every sparse zero byte.
// The ordered root binds both range hashes and their precise split/length.
fn part_digest(
	file: &File,
	start: u64,
	end: u64,
	deadline: Instant,
	cancelled: &AtomicBool,
) -> Result<Option<[u8; 32]>> {
	let mut buffer = vec![0u8; HASH_CHUNK];
	let mut hash = ArchiveHash::new();
	let mut offset = start;
	while offset < end {
		if cancelled.load(Ordering::Relaxed) {
			return Ok(None);
		}
		if Instant::now() >= deadline {
			bail!("archive cache seal deadline");
		}
		let count = (end - offset).min(HASH_CHUNK as u64) as usize;
		file.read_exact_at(&mut buffer[..count], offset)?;
		if offset == 0 {
			if buffer[..9] != MAGIC {
				return Ok(None);
			}
			// The pinned redb recovery marker is the sole normalized bit.
			buffer[9] &= !2;
		}
		hash.update(&buffer[..count]);
		offset += count as u64;
	}
	Ok(Some(hash.finalize()))
}
fn digest(
	file: &File,
	deadline: Instant,
	cancelled: impl Fn() -> Result<bool>,
) -> Result<Option<String>> {
	private_cache(file)?;
	let _cache_read_hint = CacheReadHint::new(file, false);
	let before = file.metadata()?;
	if before.len() < 320 {
		return Ok(None);
	}
	let split = before.len() / 2;
	let stop = AtomicBool::new(false);
	let result = std::thread::scope(|scope| -> Result<Option<[[u8; 32]; 2]>> {
		let (send, receive) = std::sync::mpsc::sync_channel(1);
		for (number, start, end) in [(0, 0, split), (1, split, before.len())] {
			let sender = send.clone();
			let stop = &stop;
			scope.spawn(move || {
				let _ = sender.send((number, part_digest(file, start, end, deadline, stop)));
			});
		}
		drop(send);
		let result = (|| {
			let mut hashes = [[0u8; 32]; 2];
			let mut received = [false; 2];
			while !received.iter().all(|done| *done) {
				if Instant::now() >= deadline {
					bail!("archive cache seal deadline");
				}
				if cancelled()? {
					return Ok(None);
				}
				match receive.recv_timeout(Duration::from_millis(5)) {
					Ok((number, value)) => {
						let Some(value) = value? else { return Ok(None) };
						if received[number] {
							bail!("duplicate cache seal partition");
						}
						hashes[number] = value;
						received[number] = true;
					}
					Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
					Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
						bail!("archive cache seal checker unavailable");
					}
				}
			}
			Ok(Some(hashes))
		})();
		// Join both readers on every error/cancellation path; the receiver must
		// be dropped first so a completed second worker cannot block on send.
		stop.store(true, Ordering::Relaxed);
		drop(receive);
		result
	})?;
	let Some(hashes) = result else {
		return Ok(None);
	};
	if !unchanged(&before, &file.metadata()?) {
		bail!("archive cache changed during seal");
	}
	let mut root = ArchiveHash::new();
	root.update(DOMAIN);
	root.update(before.len().to_be_bytes());
	root.update(split.to_be_bytes());
	root.update(hashes[0]);
	root.update(hashes[1]);
	const HEX: &[u8; 16] = b"0123456789abcdef";
	let mut result = String::with_capacity(64);
	for byte in root.finalize() {
		result.push(HEX[(byte >> 4) as usize] as char);
		result.push(HEX[(byte & 15) as usize] as char);
	}
	Ok(Some(result))
}

fn existing(slot: &Slot) -> Result<Option<File>> {
	match open_at(&slot.root, SEAL_NAME, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
		Ok(file) => {
			private_cache(&file)?;
			if file.metadata()?.len() > MAX_SEAL_BYTES {
				bail!("oversized archive cache seal");
			}
			Ok(Some(file))
		}
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
		{
			Ok(None)
		}
		Err(error) => Err(error),
	}
}

pub(super) fn verified(slot: &Slot, cache: &File, deadline: Instant) -> Result<bool> {
	let Some(mut file) = existing(slot)? else {
		return Ok(false);
	};
	let mut bytes = Vec::new();
	Read::by_ref(&mut file)
		.take(MAX_SEAL_BYTES + 1)
		.read_to_end(&mut bytes)?;
	if bytes.len() as u64 > MAX_SEAL_BYTES {
		return Ok(false);
	}
	let Ok(seal) = serde_json::from_slice::<Seal>(&bytes) else {
		return Ok(false);
	};
	let info = cache.metadata()?;
	if !matches!(seal.format.as_str(), FORMAT | LEGACY_FORMAT)
		|| seal.binding != binding(slot)?
		|| (seal.device, seal.inode, seal.length) != (info.dev(), info.ino(), info.len())
		|| !valid_id(&seal.sha256)
	{
		return Ok(false);
	}
	let observed = if seal.format == LEGACY_FORMAT {
		legacy_digest(cache, deadline, || Ok(false))?
	} else {
		digest(cache, deadline, || Ok(false))?
	};
	Ok(observed.as_deref() == Some(seal.sha256.as_str()))
}

fn interrupted(slot: &Slot, generation: u64, metadata_epoch: u64) -> Result<bool> {
	// A foreground reader holds state while checking original receipts. Never
	// wait behind it here while both digest workers continue issuing reads.
	if slot.metadata_activity.quiet_epoch() != Some(metadata_epoch) {
		return Ok(true);
	}
	let state = match slot.state.try_lock() {
		Ok(state) => state,
		Err(std::sync::TryLockError::WouldBlock) => return Ok(true),
		Err(std::sync::TryLockError::Poisoned(_)) => {
			bail!("archive cache seal unavailable");
		}
	};
	Ok(state.failed
		|| state.retired
		|| state.requested
		|| state.generation != generation
		|| !state.pending.is_empty()
		|| slot.metadata_activity.quiet_epoch() != Some(metadata_epoch))
}

pub(super) fn persist(slot: &Slot, deadline: Instant) -> Result<bool> {
	let Some(metadata_epoch) = slot.metadata_activity.quiet_epoch() else {
		return Ok(false);
	};
	let generation = {
		let state = match slot.state.try_lock() {
			Ok(state) => state,
			Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
			Err(std::sync::TryLockError::Poisoned(_)) => {
				bail!("archive cache seal unavailable");
			}
		};
		if state.failed
			|| state.retired
			|| state.requested
			|| !state.pending.is_empty()
			|| state.last_publication.elapsed() < IDLE_SYNC_QUIET
			|| slot.metadata_activity.quiet_epoch() != Some(metadata_epoch)
		{
			return Ok(false);
		}
		state.generation
	};
	let file = open_at(&slot.root, CACHE_NAME, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	private_cache(&file)?;
	let info = file.metadata()?;
	let Some(sha256) = digest(&file, deadline, || {
		#[cfg(test)]
		seal_event(slot, SealEvent::Hashing);
		interrupted(slot, generation, metadata_epoch)
	})?
	else {
		return Ok(false);
	};
	#[cfg(test)]
	seal_event(slot, SealEvent::Hashed);
	// A short query can begin and end between the last poll and hash completion.
	// Check its epoch before creating any temporary seal or replacing the old one.
	if interrupted(slot, generation, metadata_epoch)? {
		return Ok(false);
	}
	if !unchanged(&info, &file.metadata()?) {
		bail!("archive cache changed during seal");
	}
	let seal = Seal {
		format: FORMAT.into(),
		binding: binding(slot)?,
		device: info.dev(),
		inode: info.ino(),
		length: info.len(),
		sha256,
	};
	let temporary = format!(".disk-index-{}.tmp", new_id()?);
	let mut output = open_at(
		&slot.root,
		&temporary,
		libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	let result = (|| -> Result<()> {
		output.write_all(&serde_json::to_vec(&seal)?)?;
		output.sync_all()?;
		// Reject unsafe reserved targets; never chmod or overwrite a linked inode.
		drop(existing(slot)?);
		if unsafe {
			libc::renameat(
				slot.root.as_raw_fd(),
				name(&temporary)?.as_ptr(),
				slot.root.as_raw_fd(),
				name(SEAL_NAME)?.as_ptr(),
			)
		} < 0
		{
			return Err(std::io::Error::last_os_error().into());
		}
		slot.root.sync_all()?;
		Ok(())
	})();
	if let Err(error) = result {
		unsafe {
			libc::unlinkat(slot.root.as_raw_fd(), name(&temporary)?.as_ptr(), 0);
		}
		return Err(error);
	}
	Ok(true)
}

#[cfg(test)]
#[path = "request_archive_seal_tests.rs"]
mod tests;
