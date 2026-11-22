// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded research executor; canonical owner plan is compiled without invoking a service.

extern crate self as rmcp;
pub use schemars;
pub mod codec;
pub mod compare;
pub mod dag;
pub mod forward;
pub mod lifecycle;

/// Compile harness for the unchanged owner SHA syntax dependency only.
pub mod weight_config {
	pub fn valid_sha256(value: &str) -> bool {
		value.len() == 64
			&& value
				.bytes()
				.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
	}
}

#[path = "../../../src/mcp/weight_tensor.rs"]
pub(crate) mod canonical_weight_tensor;

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
