// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Write};

#[derive(Default)]
struct ByteCounter {
	bytes: usize,
}

impl Write for ByteCounter {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.bytes = self
			.bytes
			.checked_add(buf.len())
			.ok_or_else(|| io::Error::other("serialized JSON size exceeds usize"))?;
		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

/// Count the complete compact JSON representation without retaining its bytes.
pub(crate) fn serialized_json_size<T: serde::Serialize + ?Sized>(
	value: &T,
) -> serde_json::Result<usize> {
	let mut counter = ByteCounter::default();
	serde_json::to_writer(&mut counter, value)?;
	Ok(counter.bytes)
}

#[cfg(test)]
#[path = "json_size_tests.rs"]
mod tests;
