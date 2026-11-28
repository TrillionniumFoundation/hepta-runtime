// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-owned byte observer of the five unchanged original typed declarations.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::{self, BufRead, Write};
include!("original.rs");

fn word(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(raw.len() * 2);
    for byte in raw {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}
fn result_frame(kind: u64, params: &Value) -> Vec<u8> {
    let mut out = vec![0; 256];
    out[..8].copy_from_slice(b"HBPRR001");
    word(&mut out, 16, kind);
    let action = match (kind, params["action"].as_str()) {
        (4, Some("chunk")) | (5, Some("apply")) => 1,
        (4, Some("commit")) | (5, Some("status")) => 2,
        (4, Some("abort")) | (5, Some("recover")) => 3,
        (_, None) => 0,
        _ => panic!("typed action is not one of the unchanged enum variants"),
    };
    word(&mut out, 24, action);
    let options: &[(u64, &str)] = match kind {
        1 | 3 => &[],
        2 => &[(9, "offset"), (10, "limit"), (4, "expected_version")],
        4 => &[(9, "offset"), (3, "data_base64"), (4, "expected_version"), (11, "size"), (6, "sha256")],
        5 => &[(9, "offset"), (4, "expected_version"), (8, "expected_sha256"), (3, "data_base64")],
        _ => panic!("private kind"),
    };
    let present = options.iter().fold(0u64, |bits, (id, key)| {
        if params[*key].is_null() { bits } else { bits | (1u64 << *id) }
    });
    word(&mut out, 32, present);
    let flags = u64::from(params["acknowledge_non_atomic"].as_bool().unwrap_or(false))
        | (u64::from(params["preserve_special_bits"].as_bool().unwrap_or(false)) << 1);
    word(&mut out, 40, flags);
    for (at, key) in [(48, "offset"), (56, "limit"), (64, "size")] {
        word(&mut out, at, params[key].as_u64().unwrap_or(0));
    }
    for (index, key) in ["host", "path", "data_base64", "expected_version", "upload_id",
                         "sha256", "transaction_id", "expected_sha256"].iter().enumerate() {
        let bytes = params[*key].as_str().unwrap_or("").as_bytes();
        word(&mut out, 88 + index * 8, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }
    out
}
fn error_frame(kind: u64, message: &str) -> Vec<u8> {
    let mut out = vec![0; 256];
    out[..8].copy_from_slice(b"HBPRR001");
    word(&mut out, 8, 1);
    word(&mut out, 16, kind);
    word(&mut out, 72, message.len() as u64);
    out.extend_from_slice(message.as_bytes());
    out
}
fn project<T: DeserializeOwned + Serialize>(value: Value) -> Result<Value, serde_json::Error> {
    serde_json::from_value::<T>(value).map(|params| serde_json::to_value(params).unwrap())
}
fn main() {
    let input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let raw = row["raw_json"].as_str().unwrap();
        let kind = row["kind"].as_u64().unwrap();
        let result = match serde_json::from_str::<Map<String, Value>>(raw) {
            Err(error) => json!({"value_admitted":false,"value_error":error.to_string()}),
            Ok(map) => {
                let value = Value::Object(map);
                let canonical = serde_json::to_string(&value).unwrap();
                let typed = match kind {
                    1 => project::<FileInfoParams>(value),
                    2 => project::<BinaryReadParams>(value),
                    3 => project::<BinaryWriteParams>(value),
                    4 => project::<BinaryUploadParams>(value),
                    5 => project::<InodePatchParams>(value),
                    _ => panic!("private fixture kind"),
                };
                match typed {
                    Ok(params) => {
                        let frame = result_frame(kind, &params);
                        json!({"value_admitted":true,"canonical":canonical,"ok":true,
                            "normalized":params,"frame_hex":hex(&frame)})
                    },
                    Err(error) => json!({"value_admitted":true,"canonical":canonical,"ok":false,
                        "error":error.to_string(),"frame_hex":hex(&error_frame(kind,&error.to_string()))}),
                }
            }
        };
        serde_json::to_writer(&mut output,
            &json!({"case_id":row["case_id"],"kind":kind,"name":row["name"],"result":result})).unwrap();
        output.write_all(b"\n").unwrap();
    }
    output.flush().unwrap();
}
#[cfg(test)]
#[path = "original_tests.rs"]
mod original_tests;
