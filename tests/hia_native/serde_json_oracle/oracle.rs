// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Independent locked-serde parse, number classification and serializer oracle.

use std::io::{self, BufRead, Write};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDocument {
	schema: String,
	owner: String,
	epoch: u64,
	phase: String,
	state_root: String,
	/// Frozen V4 state used to reject an already-accepted legacy idempotency
	/// binding before V11 can allocate a new job identity.
	#[serde(default)]
	predecessor_state_root: Option<String>,
}

#[derive(Deserialize)]
struct LegacyJobKey {
	id: String,
	host: String,
	idempotency_key: Option<String>,
	request_digest: Option<String>,
}


fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let a = (pair[0] as char).to_digit(16)?;
            let b = (pair[1] as char).to_digit(16)?;
            Some(((a << 4) | b) as u8)
        })
        .collect()
}

fn word(bytes: &[u8], start: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(start..start + 8)?.try_into().ok()?,
    ))
}

fn evaluate(input: &[u8]) -> Option<Vec<u8>> {
    if input.get(..8) == Some(&b"HFEJSON1"[..]) { return evaluate_fence(input); }
    if input.len() < 24 || input.len() > 8 * 1024 * 1024 + 24 || &input[..8] != b"HSJVAL01" {
        return None;
    }
    let operation = word(input, 8)?;
    if word(input, 16)? != (input.len() - 24) as u64 {
        return None;
    }
    match operation {
        1 => {
            let value: serde_json::Value = serde_json::from_slice(&input[24..]).ok()?;
            serde_json::to_vec(&value).ok()
        }
        2 => {
            let value: serde_json::Value = serde_json::from_slice(&input[24..]).ok()?;
            let number = value.as_number()?;
            let (kind, bits) = if number.is_f64() {
                (5_u64, number.as_f64()?.to_bits())
            } else if let Some(unsigned) = number.as_u64() {
                (3, unsigned)
            } else {
                (4, number.as_i64()? as u64)
            };
            Some([kind.to_le_bytes(), bits.to_le_bytes()].concat())
        }
        3 if input.len() == 32 => {
            let value = f64::from_bits(word(input, 24)?);
            if value.is_finite() {
                serde_json::to_vec(&value).ok()
            } else {
                None
            }
        }
        _ => None,
    }
}


fn project(kind: u64, flags: u64, epoch: u64, fields: &[Option<&str>]) -> Vec<u8> {
    let mut output = vec![0_u8; 128];
    output[..8].copy_from_slice(b"HFEJRS01");
    output[8..16].copy_from_slice(&kind.to_le_bytes());
    output[16..24].copy_from_slice(&flags.to_le_bytes());
    output[24..32].copy_from_slice(&epoch.to_le_bytes());
    for (i, field) in fields.iter().enumerate() {
        if let Some(value) = field {
            let offset = output.len() as u64;
            let length = value.len() as u64;
            output[32 + i * 16..40 + i * 16].copy_from_slice(&offset.to_le_bytes());
            output[40 + i * 16..48 + i * 16].copy_from_slice(&length.to_le_bytes());
            output.extend_from_slice(value.as_bytes());
        }
    }
    output
}

fn evaluate_fence(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < 24 { return None; }
    let kind = word(input, 8)?;
    if word(input, 16)? != (input.len() - 24) as u64 { return None; }
    match kind {
        1 if input.len() <= 4096 + 24 => {
            let v: OwnerDocument = serde_json::from_slice(&input[24..]).ok()?;
            Some(project(kind, u64::from(v.predecessor_state_root.is_some()), v.epoch,
                &[Some(&v.schema), Some(&v.owner), Some(&v.phase), Some(&v.state_root), v.predecessor_state_root.as_deref()]))
        }
        2 if input.len() <= 1024 * 1024 + 24 => {
            let v: LegacyJobKey = serde_json::from_slice(&input[24..]).ok()?;
            let flags = u64::from(v.idempotency_key.is_some()) | (u64::from(v.request_digest.is_some()) << 1);
            Some(project(kind, flags, 0,
                &[Some(&v.id), Some(&v.host), v.idempotency_key.as_deref(), v.request_digest.as_deref()]))
        }
        _ => None,
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let input =
            decode_hex(&line?).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "oracle corpus must contain exact hexadecimal frames"))?;
        match evaluate(&input) {
            Some(bytes) => {
                write!(out, "{:08x}:", bytes.len())?;
                for b in bytes {
                    write!(out, "{b:02x}")?;
                }
                writeln!(out)?;
            }
            None => writeln!(out, "ffffffff:")?,
        }
    }
    out.flush()
}
