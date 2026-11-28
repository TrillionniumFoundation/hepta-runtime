pub async fn io_write(source: &PathSource, content: &[u8]) -> Result<()> {
	match source {
		PathSource::Local(p) => tokio::fs::write(p, content)
			.await
			.map_err(|e| anyhow!("Failed to write '{}': {}", source.display(), e)),
		#[cfg(feature = "remote-fs")]
		PathSource::Remote { host, path, .. } => {
			crate::mcp::runtime::config::check_remote_write(host, path)?;
			sftp::remote_write(source, content).await
		}
		#[cfg(not(feature = "remote-fs"))]
		PathSource::Remote { .. } => sftp::remote_write(source, content).await,
	}
}
