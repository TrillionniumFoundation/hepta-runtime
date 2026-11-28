// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use std::io::Write;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    anyhow::ensure!(args.len() <= 1, "expected at most one configuration fixture");
    if let Some(path) = args.first() {
        let config = hepta_runtime::mcp::runtime::config::RuntimeConfig::load(
            std::path::Path::new(path),
        )?;
        hepta_runtime::mcp::runtime::config::init_runtime(config)?;
    }
    let result = hepta_runtime::mcp::server::__hia_current_catalog_observe().await?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &result)?;
    output.write_all(b"\n")?;
    Ok(())
}
