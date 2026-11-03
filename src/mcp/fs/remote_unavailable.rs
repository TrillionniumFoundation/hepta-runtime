// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Reject remote filesystem requests when the embedding build omits that backend.
//!
//! URL parsing and local I/O remain shared with the default build. No remote
//! request reaches the SFTP pool or the runtime's system-SSH file helper here.

use super::{PathSource, RemoteMetadata};
use anyhow::{anyhow, Result};

fn unavailable() -> anyhow::Error {
	anyhow!("remote filesystem support requires the remote-fs feature")
}

pub async fn remote_read(_source: &PathSource) -> Result<Vec<u8>> {
	Err(unavailable())
}

pub async fn remote_read_to_string(_source: &PathSource) -> Result<String> {
	Err(unavailable())
}

pub async fn remote_write(_source: &PathSource, _content: &[u8]) -> Result<()> {
	Err(unavailable())
}

pub async fn remote_exists(_source: &PathSource) -> Result<bool> {
	Err(unavailable())
}

pub async fn remote_metadata(_source: &PathSource) -> Result<RemoteMetadata> {
	Err(unavailable())
}

pub async fn remote_create_dir_all(_source: &PathSource) -> Result<()> {
	Err(unavailable())
}

pub async fn remote_remove_file(_source: &PathSource) -> Result<()> {
	Err(unavailable())
}

pub async fn remote_list_dir(_source: &PathSource) -> Result<Vec<(String, RemoteMetadata)>> {
	Err(unavailable())
}

pub async fn remote_canonicalize(_source: &PathSource) -> Result<String> {
	Err(unavailable())
}
