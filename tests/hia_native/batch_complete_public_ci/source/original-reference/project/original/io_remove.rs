pub async fn io_remove_file(source: &PathSource) -> Result<()> {
	match source {
		PathSource::Local(p) => tokio::fs::remove_file(p)
			.await
			.map_err(|e| anyhow!("Failed to remove '{}': {}", source.display(), e)),
		#[cfg(feature = "remote-fs")]
		PathSource::Remote { host, path, .. } => {
			crate::mcp::runtime::config::check_remote_write(host, path)?;
			sftp::remote_remove_file(source).await
		}
		#[cfg(not(feature = "remote-fs"))]
		PathSource::Remote { .. } => sftp::remote_remove_file(source).await,
	}
}
