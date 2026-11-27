// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Preserve native filter input bytes, read position and immutable seals.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

#[tokio::test]
async fn native_filter_input_is_rewound_and_immutable_after_blocking_preparation() {
	let frame = b"native\0filter\xffframe\n";
	let input = prepare_filter_input(frame).await.unwrap();
	let mut input = tokio::fs::File::from_std(input);
	let mut retained = Vec::new();
	input.read_to_end(&mut retained).await.unwrap();
	assert_eq!(&retained[..], &frame[..]);
	let write = input.write_all(b"changed").await;
	let flush = input.flush().await;
	assert!(write.is_err() || flush.is_err());
}
