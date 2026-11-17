pub async fn io_metadata(source: &PathSource) -> Result<IoMetadata> {
	match source {
		PathSource::Local(p) => {
			let meta = tokio::fs::metadata(p)
				.await
				.map_err(|e| anyhow!("Failed to stat '{}': {}", source.display(), e))?;
			Ok(IoMetadata {
				size: meta.len(),
				is_dir: meta.is_dir(),
				is_file: meta.is_file(),
				modified: meta.modified().ok(),
			})
		}
		PathSource::Remote { .. } => {
			let m = sftp::remote_metadata(source).await?;
			Ok(IoMetadata {
				size: m.size,
				is_dir: m.is_dir,
				is_file: m.is_file,
				modified: m.modified,
			})
		}
	}
}
