// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Execute the exact current-target local create function through Tokio.
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use tokio::io::AsyncWriteExt;
async fn create_local_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
	let mut file = tokio::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(path)
		.await?;
	file.write_all(content).await?;
	file.flush().await
}

fn word(raw: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
}
fn main() -> io::Result<()> {
	let mut wire = Vec::new();
	io::stdin().lock().read_to_end(&mut wire)?;
	if wire.len() < 64
		|| &wire[..8] != b"HLCREQ01"
		|| word(&wire, 8) != 1
		|| wire[32..64].iter().any(|byte| *byte != 0)
	{
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"invalid private fixture frame",
		));
	}
	let path_len = word(&wire, 16) as usize;
	let content_len = word(&wire, 24) as usize;
	if path_len > wire.len() - 64 || content_len != wire.len() - 64 - path_len {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"invalid private fixture lengths",
		));
	}
	let path = Path::new(OsStr::from_bytes(&wire[64..64 + path_len]));
	let content = &wire[64 + path_len..];
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?;
	io::stderr().write_all(b"HLCREATE-REFERENCE-BEGIN\n")?;
	let actual = runtime.block_on(create_local_file(path, content));
	io::stderr().write_all(b"HLCREATE-REFERENCE-END\n")?;
	let (kind, error, written) = match actual {
		Ok(()) => (0u64, 0u64, content.len() as u64),
		Err(error) => match error.raw_os_error() {
			Some(number) if number > 0 => (1, number as u64, 0),
			None if error.kind() == io::ErrorKind::InvalidInput
				&& wire[64..64 + path_len].contains(&0) =>
			{
				(2, 0, 0)
			}
			None if error.kind() == io::ErrorKind::WriteZero => (3, 0, 0),
			_ => return Err(error),
		},
	};
	let mut response = b"HLCRER01".to_vec();
	for value in [48, kind, error, written, 0] {
		response.extend_from_slice(&value.to_le_bytes());
	}
	io::stdout().lock().write_all(&response)?;
	Ok(())
}
