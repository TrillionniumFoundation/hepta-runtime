pub async fn io_create_dir_all(source: &PathSource) -> Result<()> {
	match source {
		PathSource::Local(p) => tokio::fs::create_dir_all(p)
			.await
			.map_err(|e| anyhow!("Failed to create dirs for '{}': {}", source.display(), e)),
		#[cfg(feature = "remote-fs")]
		PathSource::Remote { host, path, .. } => {
			crate::mcp::runtime::config::check_remote_write(host, path)?;
			sftp::remote_create_dir_all(source).await
		}
		#[cfg(not(feature = "remote-fs"))]
		PathSource::Remote { .. } => sftp::remote_create_dir_all(source).await,
	}
}
