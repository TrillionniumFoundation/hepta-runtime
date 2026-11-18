// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
use std::io::{self, BufRead, Write};

fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn decode_length(raw: &[u8], at: &mut usize) -> usize {
    let mut result = 0usize;
    let mut shift = 0u32;
    loop {
        let part = raw[*at];
        *at += 1;
        result |= ((part & 127) as usize) << shift;
        if part < 128 {
            return result;
        }
        shift += 7;
    }
}

fn apply(raw: &[u8]) -> Vec<u8> {
    assert!(raw.len() >= 64 && &raw[..8] == b"HLINE001");
    let operation = word(raw, 8);
    let bits = word(raw, 16);
    let count = word(raw, 24) as usize;
    let hash_size = word(raw, 32) as usize;
    assert_eq!(word(raw, 40) as usize, raw.len() - 64);
    assert_eq!(word(raw, 48), 0);
    assert_eq!(word(raw, 56), 0);
    let result = match operation {
        1 => {
            let expected = std::str::from_utf8(&raw[64..64 + hash_size]).unwrap();
            let mut at = 64 + hash_size;
            let mut lines = Vec::with_capacity(count);
            for _ in 0..count {
                let size = decode_length(raw, &mut at);
                lines.push(std::str::from_utf8(&raw[at..at + size]).unwrap());
                at += size;
            }
            assert_eq!(at, raw.len());
            verify_line_id(bits as usize, expected, &lines).map(|value| (value, false))
        }
        2 => resolve_line_index(bits as i64, count).map(|value| (value, false)),
        3 => resolve_line_index_clamped(bits as i64, count),
        _ => panic!("unsupported typed original operation"),
    };
    let mut out = b"HLINER01".to_vec();
    match result {
        Ok((value, clamped)) => {
            for word in [0, value as u64, u64::from(clamped), 0] {
                out.extend(word.to_le_bytes());
            }
        }
        Err(error) => {
            for word in [1, 0, 0, error.len() as u64] {
                out.extend(word.to_le_bytes());
            }
            out.extend(error.as_bytes());
        }
    }
    out
}

fn main() {
    assert_eq!(usize::BITS, 64);
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let raw: Vec<u8> = (0..line.len()).step_by(2)
            .map(|at| u8::from_str_radix(&line[at..at + 2], 16).unwrap()).collect();
        let result = apply(&raw);
        out.write_all(b"OK ").unwrap();
        for byte in result {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out.write_all(b"\n").unwrap();
        out.flush().unwrap();
    }
}
