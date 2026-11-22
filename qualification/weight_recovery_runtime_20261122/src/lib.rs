// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Durable coordination around the existing immutable weight artifact owner.

mod engine;
pub use engine::*;

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod recovery_tests;
