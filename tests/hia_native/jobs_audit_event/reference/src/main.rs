// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Locked original jobs audit event serializer, isolated from runtime installation.
use std::io::{self, BufRead};
use serde_json::{json, Value};

mod original;

fn main() -> anyhow::Result<()> {
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line?)?;
        let host = value["host"].as_str().ok_or_else(|| anyhow::anyhow!("host"))?;
        let subject = value["subject"].as_str().ok_or_else(|| anyhow::anyhow!("subject"))?;
        let outcome = json!({"op": "write"});
        let result = if let Some(timestamp) = value["timestamp"].as_str() {
            let timestamp: u128 = timestamp.parse()?;
            match serde_json::to_value(timestamp) {
                Ok(timestamp) => {
                    let event = json!({"at_unix_ms": timestamp,
                        "action": "native_binary_write", "host": host,
                        "subject": subject, "outcome": outcome});
                    let mut line = serde_json::to_string(&event)?;
                    line.push('\n');
                    json!({"line": line})
                }
                Err(error) => json!({"timestamp_error": error.to_string()}),
            }
        } else {
            json!({"line": original::capture(host, subject, &outcome)?})
        };
        println!("{}", serde_json::to_string(&result)?);
    }
    Ok(())
}
