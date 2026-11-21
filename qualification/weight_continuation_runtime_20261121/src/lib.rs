// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated, source-authenticated finite continuation policy research executor.
//! No deployed runtime registration, checkpoint write or production transaction owner.

pub mod gate;
pub mod policy;
pub mod session;
pub mod source;
pub mod task;

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod runtime_tests;
