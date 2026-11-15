// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification projection of the original retained-result owner.
include!("original_store.rs");
use std::os::unix::fs::OpenOptionsExt;

struct State {
	root: PathBuf,
	_root_guard: File,
	legacy: File,
	archive: Option<ArchiveStore>,
	shard: Option<File>,
	archive_lease: u64,
	next_archive: u64,
	shard_lease: u64,
	next_shard: u64,
}
fn word(raw: &[u8], at: usize) -> Option<u64> {
	Some(u64::from_le_bytes(raw.get(at..at + 8)?.try_into().ok()?))
}
fn classify(error: anyhow::Error) -> (u64, u64) {
	if let Some(io) = error.downcast_ref::<std::io::Error>() {
		if let Some(errno) = io.raw_os_error() {
			return (23, errno as u64);
		}
		return match io.kind() {
			std::io::ErrorKind::UnexpectedEof => (27, 0),
			std::io::ErrorKind::WriteZero => (28, 0),
			_ => (255, 0),
		};
	}
	if error.downcast_ref::<serde_json::Error>().is_some() {
		return (21, 0);
	}
	let diagnostic = match error.to_string().as_str() {
		"private request audit inode refused" => 16,
		"result archive anchor schema refused" => 17,
		"result archive anchor changed during read" => 18,
		"result anchor cache unavailable" => 19,
		"result archive anchor bytes changed; history never repaired automatically" => 20,
		"result archive anchor size refused" => 22,
		"result archive marker size refused" => 24,
		"result archive marker schema refused" => 25,
		"result archive marker binding changed" => 29,
		"result state unavailable" => 30,
		"result archive anchor missing; history never recreated automatically" => 31,
		"unanchored result archive refused; history never recreated automatically" => 32,
		"result archive directory binding changed; history never recreated automatically" => 33,
		"private request audit directory refused" => 34,
		"invalid result archive identity" => 35,
		"result archive shard binding changed; history never recreated automatically" => 36,
		_ => 255,
	};
	(diagnostic, 0)
}
fn operation(state: &mut State, op: u64, create: bool, payload: &[u8]) -> Result<(u64, u64)> {
	match op {
		1 => {
			let opened = open_archive_store(&state.root, &state.legacy, create)?;
			let identity = opened.as_ref().map_or((0, 0), |archive| {
				let identity = &archive.anchor.anchor.archive;
				(identity.device, identity.inode)
			});
			if opened.is_some() {
				state.next_archive += 1;
				state.archive_lease = state.next_archive;
			}
			state.archive = opened;
			Ok(identity)
		}
		2 => {
			let id = std::str::from_utf8(payload)
				.map_err(|_| anyhow!("invalid result archive identity"))?;
			let archive = state.archive.as_ref().unwrap();
			let opened = shard(archive, id)?;
			let index = u8::from_str_radix(&id[..2], 16)? as usize;
			let identity = &archive.anchor.anchor.shards[index];
			let identity = (identity.device, identity.inode);
			state.shard = Some(opened);
			state.next_shard += 1;
			state.shard_lease = state.next_shard;
			Ok(identity)
		}
		3 => {
			for index in 0..256 {
				let id = format!("{index:02x}{}", "0".repeat(62));
				shard(state.archive.as_ref().unwrap(), &id)?;
			}
			Ok((0, 0))
		}
		4 => {
			state.shard.take();
			state.shard_lease = 0;
			Ok((0, 0))
		}
		5 => {
			state.archive.take();
			state.archive_lease = 0;
			Ok((0, 0))
		}
		6 => {
			let identity = directory_identity(state.shard.as_ref().unwrap(), true)?;
			Ok((identity.device, identity.inode))
		}
		_ => unreachable!(),
	}
}
fn response(state: &mut State, raw: &[u8]) -> Option<Vec<u8>> {
	if raw.len() < 48
		|| raw.len() > 1072
		|| raw.get(..8)? != b"HRASQ001"
		|| word(raw, 32)? != (raw.len() - 48) as u64
		|| word(raw, 40)? != 0
	{
		return None;
	}
	let op = word(raw, 8)?;
	let create = word(raw, 16)?;
	let lease = word(raw, 24)?;
	if !(1..=6).contains(&op)
		|| create > 1
		|| (op != 1 && create != 0)
		|| (op != 2 && raw.len() != 48)
		|| (op == 1 && lease != 0)
	{
		return None;
	}
	match op {
		1 if state.archive.is_some() || state.shard.is_some() || state.next_archive == u64::MAX => {
			return None;
		}
		2 | 3 | 5 => {
			if state.archive.is_none()
				|| lease != state.archive_lease
				|| (op != 5 && state.shard.is_some())
				|| (op == 2 && state.next_shard == u64::MAX)
			{
				return None;
			}
		}
		4 | 6 if state.shard.is_none() || lease != state.shard_lease => return None,
		_ => {}
	}
	let (diagnostic, errno, device, inode) = match operation(state, op, create != 0, &raw[48..]) {
		Ok((device, inode)) => (0, 0, device, inode),
		Err(error) => {
			let (diagnostic, errno) = classify(error);
			(diagnostic, errno, 0, 0)
		}
	};
	let mut bytes = b"HRASR001".to_vec();
	for value in [
		diagnostic,
		errno,
		u64::from(state.archive.is_some() || state.shard.is_some()),
		state.archive_lease,
		state.shard_lease,
		device,
		inode,
	] {
		bytes.extend(value.to_le_bytes());
	}
	Some(bytes)
}
fn run() -> Result<()> {
	let mut arguments = std::env::args_os().skip(1);
	let root = PathBuf::from(arguments.next().ok_or_else(|| anyhow!("root required"))?);
	let legacy = PathBuf::from(arguments.next().ok_or_else(|| anyhow!("legacy required"))?);
	let open = |path: &Path| -> Result<File> {
		Ok(std::fs::OpenOptions::new()
			.read(true)
			.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
			.open(path)?)
	};
	let mut state = State {
		_root_guard: open(&root)?,
		legacy: open(&legacy)?,
		root,
		archive: None,
		shard: None,
		archive_lease: 0,
		next_archive: 0,
		shard_lease: 0,
		next_shard: 0,
	};
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	loop {
		let mut header = [0u8; 8];
		loop {
			match input.read(&mut header[..1]) {
				Ok(0) => return Ok(()),
				Ok(_) => break,
				Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
				Err(error) => return Err(error.into()),
			}
		}
		input.read_exact(&mut header[1..])?;
		let length = u64::from_le_bytes(header);
		if length > 1048576 {
			bail!("private frame too large");
		}
		let mut raw = vec![0; length as usize];
		input.read_exact(&mut raw)?;
		if let Some(bytes) = response(&mut state, &raw) {
			output.write_all(&(bytes.len() as u32).to_le_bytes())?;
			output.write_all(&bytes)?;
		} else {
			output.write_all(&u32::MAX.to_le_bytes())?;
		}
		output.flush()?;
	}
}
fn main() {
	if run().is_err() {
		std::process::exit(74);
	}
}
