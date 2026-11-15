// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact current-target create_local_file; verified before every reference build.
async fn create_local_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
	let mut file = tokio::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(path)
		.await?;
	file.write_all(content).await?;
	file.flush().await
}

