// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-only persistent transport around the complete original SystemEntropy.
use std::io::{Read, Write};
use zeroize::Zeroizing;
include!(concat!(env!("OUT_DIR"), "/original_operation_reference.rs"));

fn main() -> Result<(), Box<dyn std::error::Error>> {
	if std::env::args_os().count() != 1 {
		std::process::exit(64);
	}
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	let mut frame = [0u8; 24];
	let mut bytes = Zeroizing::new([0u8; 128]);
	let mut calls = 0usize;
	loop {
		let mut used = 0;
		while used != frame.len() {
			match input.read(&mut frame[used..]) {
				Ok(0) if used == 0 => break,
				Ok(0) => std::process::exit(2),
				Ok(count) => used += count,
				Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
				Err(error) => return Err(error.into()),
			}
		}
		if used == 0 {
			break;
		}
		let wanted = u64::from_le_bytes(frame[8..16].try_into().unwrap());
		let valid = &frame[..8] == b"HRENT001" && frame[16..] == [0; 8] && wanted <= 128;
		let code = if !valid {
			0xffff_ffffu32
		} else {
			calls += 1;
			if original::original_system_entropy(&mut bytes[..wanted as usize]) {
				wanted as u32
			} else {
				0xffff_fffdu32
			}
		};
		output.write_all(&code.to_le_bytes())?;
		if code <= 128 {
			output.write_all(&bytes[..code as usize])?;
		}
		output.flush()?;
		bytes.fill(0);
	}
	let counts = std::env::var_os("HIA_ENTROPY_ORACLE_COUNTS").ok_or("test count path required")?;
	std::fs::write(
		counts,
		serde_json::to_vec(&serde_json::json!({"original_owner_calls": calls}))?,
	)?;
	Ok(())
}
