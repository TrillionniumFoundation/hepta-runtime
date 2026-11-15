// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Locked SDK serialization reference for the complete qualified corpus.
use std::io::{Read, Write};

fn main() {
	let mut input = Vec::new();
	std::io::stdin().lock().read_to_end(&mut input).unwrap();
	assert_eq!(input.len() % 4, 0);
	let mut output = std::io::BufWriter::new(std::io::stdout().lock());
	for bytes in input.chunks_exact(4) {
		let bits = u32::from_le_bytes(bytes.try_into().unwrap());
		serde_json::to_writer(&mut output, &f32::from_bits(bits)).unwrap();
		output.write_all(b"\n").unwrap();
	}
	output.flush().unwrap();
}
