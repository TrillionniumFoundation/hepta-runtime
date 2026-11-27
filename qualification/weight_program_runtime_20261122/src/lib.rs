// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Source-bound readout programs and a finite, resource-aware edit decision model.

// The shared finite planner keeps the qualification crate's original digest.
use hepta_semantic_source_adapter_study::digest;

pub mod causal;
pub mod edit;
pub mod planner;
pub mod snapshot;

#[cfg(test)]
#[path = "program_tests.rs"]
mod program_tests;

#[cfg(test)]
mod test_support;

pub mod coordinator;

pub mod batch;
#[cfg(test)]
mod batch_tests;
