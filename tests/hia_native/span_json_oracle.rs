// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Direct locked-serde Value/Map reference for the full-span carrier.
use std::io::{self, BufRead, Write};
fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 { return None; }
    text.as_bytes().chunks_exact(2).map(|p| {
        Some((((p[0] as char).to_digit(16)? << 4) | (p[1] as char).to_digit(16)?) as u8)
    }).collect()
}
fn word(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}
fn evaluate(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < 24 || word(input, 8)? != 1 || word(input, 16)? != (input.len() - 24) as u64 { return None; }
    match &input[..8] {
        b"HJSVS002" => {
            let value: serde_json::Value = serde_json::from_slice(&input[24..]).ok()?;
            serde_json::to_vec(&value).ok()
        }
        b"HJSMS002" => {
            let value: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&input[24..]).ok()?;
            serde_json::to_vec(&value).ok()
        }
        _ => None,
    }
}
fn main() -> io::Result<()> {
    let input = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lock().lines() {
        let request = unhex(&line?).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "exact hexadecimal frame required"))?;
        match evaluate(&request) {
            Some(bytes) => {
                write!(output, "{:08x}:", bytes.len())?;
                for byte in bytes { write!(output, "{byte:02x}")?; }
                writeln!(output)?;
            }
            None => writeln!(output, "ffffffff:")?,
        }
    }
    output.flush()
}
