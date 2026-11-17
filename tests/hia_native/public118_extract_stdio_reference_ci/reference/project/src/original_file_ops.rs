// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact target items; verified by the source extraction manifest.
use super::remote::{io_create_dir_all, io_exists, io_write, PathSource};
use anyhow::{anyhow, bail, Result};
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


pub async fn create_file_spec(source: &PathSource, content: &str) -> Result<String> {
	// Check if file already exists — guide the AI toward the right edit tool instead of retrying create
	if io_exists(source).await? {
		bail!(
			"File already exists: {}. Edit it with str_replace or batch_edit instead of create.",
			source.display()
		);
	}

	// Create parent directories if they don't exist
	if let Some(parent_source) = source.parent() {
		if !io_exists(&parent_source).await? {
			io_create_dir_all(&parent_source)
				.await
				.map_err(|e| anyhow!("Permission denied. Cannot create directories: {}", e))?;
		}
	}

	// Write the content to the file
	match source {
		PathSource::Local(path) => create_local_file(path, content.as_bytes())
			.await
			.map_err(|e| anyhow!("Permission denied. Cannot write to file: {}", e))?,
		PathSource::Remote { .. } => io_write(source, content.as_bytes())
			.await
			.map_err(|e| anyhow!("Permission denied. Cannot write to file: {}", e))?,
	}
	super::delta::note_create(source, content);

	Ok(format!(
		"File created successfully with {} bytes",
		content.len()
	))
}


