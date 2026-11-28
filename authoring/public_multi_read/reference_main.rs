// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-only byte observer of the unchanged original MultiReadParams and handlers.
use anyhow::{bail, Result};
use rmcp::{model::{CallToolResult, ContentBlock}, schemars};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::{self, BufRead, Write};
include!("original.rs");

fn word(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for byte in raw {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn typed_frame(params: &MultiReadParams) -> Vec<u8> {
    let mut out = vec![0; 256];
    out[..8].copy_from_slice(b"HMRPR001");
    word(&mut out, 16, 1);
    word(&mut out, 24, u64::from(params.max_file_bytes.is_some())
        | (u64::from(params.max_response_bytes.is_some()) << 1));
    word(&mut out, 32, params.max_file_bytes.unwrap_or(0));
    word(&mut out, 40, params.max_response_bytes.unwrap_or(0));
    word(&mut out, 48, params.paths.len() as u64);
    word(&mut out, 56, params.host.len() as u64);
    word(&mut out, 64, params.paths.iter().map(|p| 8 + p.len() as u64).sum());
    out.extend_from_slice(params.host.as_bytes());
    for path in &params.paths {
        out.extend_from_slice(&(path.len() as u64).to_le_bytes());
        out.extend_from_slice(path.as_bytes());
    }
    out
}

fn typed_error(message: &str) -> Vec<u8> {
    let mut out = vec![0; 256];
    out[..8].copy_from_slice(b"HMRPR001");
    word(&mut out, 8, 1);
    word(&mut out, 16, 1);
    word(&mut out, 72, message.len() as u64);
    out.extend_from_slice(message.as_bytes());
    out
}

fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let raw = row["raw_json"].as_str().unwrap();
        let result = match serde_json::from_str::<Map<String, Value>>(raw) {
            Err(error) => json!({"value_admitted": false, "value_error": error.to_string()}),
            Ok(map) => {
                let value = Value::Object(map);
                let canonical = serde_json::to_string(&value).unwrap();
                match serde_json::from_value::<MultiReadParams>(value) {
                    Err(error) => json!({"value_admitted": true, "canonical": canonical,
                        "typed_ok": false, "error": error.to_string(),
                        "typed_frame_hex": hex(&typed_error(&error.to_string()))}),
                    Ok(params) => {
                        let validation = match validate(&params) {
                            Ok((file, response)) => json!({"ok": true,
                                "max_file_bytes": file, "max_response_bytes": response}),
                            Err(error) => json!({"ok": false, "error": error.to_string()}),
                        };
                        json!({"value_admitted": true, "canonical": canonical, "typed_ok": true,
                            "normalized": params, "validation": validation,
                            "typed_frame_hex": hex(&typed_frame(&params))})
                    }
                }
            }
        };
        serde_json::to_writer(&mut out, &json!({"case_id": row["case_id"], "result": result})).unwrap();
        out.write_all(b"\n").unwrap();
    }
    out.flush().unwrap();
}

#[cfg(test)]
#[path = "original_tests.rs"]
mod original_tests;
