// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Namespace adapter for the original source. Full MCP, file, process and journal owners are excluded.
pub mod weight_tensor;
#[path = "../upstream/src/mcp/weight_norm.rs"]
pub mod weight_norm;
#[path = "../upstream/src/mcp/weight_ridge.rs"]
pub mod weight_ridge;
#[path = "../upstream/src/mcp/weight_bellman.rs"]
pub mod weight_bellman;
#[path = "../upstream/src/mcp/weight_certificate.rs"]
pub mod weight_certificate;
pub mod projection;
pub mod confirmation;
