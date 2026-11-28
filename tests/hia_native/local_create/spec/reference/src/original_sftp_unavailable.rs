// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact target items; verified by the source extraction manifest.
use super::PathSource;
use anyhow::{anyhow, Result};

fn unavailable() -> anyhow::Error {
	anyhow!("remote filesystem support requires the remote-fs feature")
}


pub async fn remote_exists(_source: &PathSource) -> Result<bool> {
	Err(unavailable())
}


pub async fn remote_create_dir_all(_source: &PathSource) -> Result<()> {
	Err(unavailable())
}


pub async fn remote_write(_source: &PathSource, _content: &[u8]) -> Result<()> {
	Err(unavailable())
}


