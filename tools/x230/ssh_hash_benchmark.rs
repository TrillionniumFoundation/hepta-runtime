// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
// Isolated diagnostic: compare already-linked SHA-256 implementations.
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::Instant;

fn portable(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn dispatched(bytes: &[u8]) -> [u8; 32] {
    let result = ring::digest::digest(&ring::digest::SHA256, bytes);
    result.as_ref().try_into().unwrap()
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let bytes = std::fs::read(&args[1]).unwrap();
    let iterations: usize = args.get(2).map(|v| v.parse().unwrap()).unwrap_or(128);
    assert_eq!(portable(&bytes), dispatched(&bytes));
    for length in [0, 1, 55, 56, 63, 64, 65, 4095, 4096, 16385] {
        let input = &bytes[..length.min(bytes.len())];
        assert_eq!(portable(input), dispatched(input));
        let mut streamed = ring::digest::Context::new(&ring::digest::SHA256);
        for chunk in input.chunks(17) { streamed.update(chunk); }
        assert_eq!(portable(input).as_slice(), streamed.finish().as_ref());
    }
    for name in ["sha2", "ring", "ring", "sha2"] {
        let start = Instant::now();
        let calculate: fn(&[u8]) -> [u8; 32] = if name == "ring" { dispatched } else { portable };
        for _ in 0..iterations { black_box(calculate(black_box(&bytes))); }
        let seconds = start.elapsed().as_secs_f64();
        println!("{{\"implementation\":\"{name}\",\"iterations\":{iterations},\"bytes\":{},\"seconds\":{seconds},\"mib_per_second\":{}}}", bytes.len(), bytes.len() as f64 * iterations as f64 / 1048576.0 / seconds);
    }
}
