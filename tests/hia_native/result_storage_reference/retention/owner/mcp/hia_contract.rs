// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Qualification projection of the original retained-result owner.
use sha2::{Digest, Sha256};
const CATALOG_BYTES: &[u8] = include_bytes!("hia_tool_catalog.json");
pub(super) fn sha256(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}
pub(super) fn catalog_sha256() -> String {
	sha256(CATALOG_BYTES)
}
