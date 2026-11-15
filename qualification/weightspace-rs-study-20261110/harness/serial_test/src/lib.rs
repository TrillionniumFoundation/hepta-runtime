// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-only shim. All tests MUST run with --test-threads=1.
//! No original serial_test behavior is claimed as qualified by this harness.
extern crate proc_macro;
use proc_macro::TokenStream;
#[proc_macro_attribute]
pub fn serial(_attr: TokenStream, item: TokenStream) -> TokenStream { item }
