// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Persistent private observer; exact target I/O bodies live in the sibling module.
use anyhow::{anyhow, bail, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

mod mcp {
	pub mod runtime {
		pub mod storage;
	}
}

fn main() -> Result<()> {
	let root = PathBuf::from(std::env::args_os().nth(1).ok_or_else(|| anyhow!("fixture root required"))?);
	let input = std::io::stdin();
	let output = std::io::stdout();
	let mut input = input.lock();
	let mut output = output.lock();
	let mut current: Option<(u64, File)> = None;
	loop {
		let mut header = [0_u8; 16];
		let first = input.read(&mut header[..1])?;
		if first == 0 {
			break;
		}
		input.read_exact(&mut header[1..])?;
		let case = u64::from_le_bytes(header[..8].try_into()?);
		let size = u64::from_le_bytes(header[8..].try_into()?);
		if case >= 10000 || !(128..=8192).contains(&size) {
			bail!("fixture case/extent");
		}
		let mut frame = vec![0_u8; size as usize];
		input.read_exact(&mut frame)?;
		if current.as_ref().map(|pair| pair.0) != Some(case) {
			current = None;
			current = Some((case, File::open(root.join(format!("case-{case:04}")))?));
		}
		let file = &current.as_ref().ok_or_else(|| anyhow!("fixture directory"))?.1;
		let generation = u64::from_le_bytes(frame[16..24].try_into()?);
		eprintln!("AUDIT_ORIGINAL_BEGIN {case} {generation}");
		let result = mcp::runtime::storage::run(file, &frame)?;
		eprintln!("AUDIT_ORIGINAL_END {case} {generation}");
		output.write_all(&(result.len() as u64).to_le_bytes())?;
		output.write_all(&result)?;
		output.flush()?;
	}
	drop(current);
	Ok(())
}
