// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit-file example adapter; pure model parsing and computation live in the library.
use anyhow::{ensure, Context, Result};
use hepta_runtime::mcp::weight_smallhcsn::Deadline;
pub(super) use hepta_runtime::mcp::weight_smallhcsn::{bind, inputs, sha};
use std::path::Path;
use tokio::{fs::File, io::AsyncReadExt};

pub(super) async fn capture(
	path: &Path,
	expected: &str,
	cap: u64,
	deadline: &Deadline,
) -> Result<Vec<u8>> {
	deadline.check()?;
	ensure!(path.is_absolute(), "explicit absolute input path required");
	let file = tokio::time::timeout(deadline.remaining()?, File::open(path))
		.await
		.context("file open deadline")?
		.context("open explicit file")?;
	let metadata = tokio::time::timeout(deadline.remaining()?, file.metadata())
		.await
		.context("metadata deadline")?
		.context("read file metadata")?;
	ensure!(
		metadata.is_file() && metadata.len() <= cap,
		"input is not a bounded regular file"
	);
	let mut raw = Vec::new();
	tokio::time::timeout(
		deadline.remaining()?,
		file.take(cap + 1).read_to_end(&mut raw),
	)
	.await
	.context("file read deadline")?
	.context("read bounded file")?;
	deadline.check()?;
	ensure!(
		raw.len() as u64 == metadata.len() && sha(&raw) == expected,
		"whole input identity mismatch"
	);
	Ok(raw)
}
