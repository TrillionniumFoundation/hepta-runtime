// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated research harness; it does not activate a checkpoint or register an MCP server.
//! Upstream numerical source and tests are unmodified; the transport/schema shim is explicit.
extern crate self as rmcp;
pub use schemars;
pub mod mcp;
