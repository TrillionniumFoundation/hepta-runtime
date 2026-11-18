// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification-only framed access to unchanged Async read methods.
pub mod mcp;
pub mod utils;
use std::{io::{Read, Write}, path::PathBuf};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input { op: u8, owner: String, request_id: String }

fn run() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    anyhow::ensure!(args.len() == 3 && args[1] == "--runtime-config", "fixed qualification argv");
    mcp::runtime::config::RuntimeConfig::load(&PathBuf::from(&args[2]))
        .and_then(mcp::runtime::config::init_runtime)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut calls = 0u64;
    loop {
        let mut length = [0u8; 4];
        let n = stdin.read(&mut length[..1])?;
        if n == 0 { break; }
        stdin.read_exact(&mut length[1..])?;
        let n = u32::from_le_bytes(length) as usize;
        anyhow::ensure!(n <= 8 * 1024 * 1024, "qualification frame capacity");
        let mut input = vec![0; n];
        stdin.read_exact(&mut input)?;
        let input: Input = serde_json::from_slice(&input)?;
        let result = runtime.block_on(async {
            match input.op {
                1 => mcp::runtime::request_async::observation(&input.owner, &input.request_id)
                    .await.map(|v| serde_json::json!({"value": v})),
                2 => mcp::runtime::request_async::audit_read_target(&input.owner, &input.request_id)
                    .await.map(|v| serde_json::json!({"value": v})),
                _ => anyhow::bail!("unknown qualification operation"),
            }
        });
        calls += 1;
        let value = match result {
            Ok(value) => serde_json::json!({"ok": value}),
            Err(error) => serde_json::json!({"error": error.to_string()}),
        };
        let output = serde_json::to_vec(&value)?;
        stdout.write_all(&(output.len() as u32).to_le_bytes())?;
        stdout.write_all(&output)?;
        stdout.flush()?;
    }
    eprintln!("{}", serde_json::json!({"original_read_calls": calls}));
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("qualification carrier error: {error}");
        std::process::exit(1);
    }
}
