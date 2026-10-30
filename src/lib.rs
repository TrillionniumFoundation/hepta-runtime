// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Share the existing policy-enforced runtime between the CLI/MCP server and
//! explicitly trusted in-process Rust adapters. This is one implementation,
//! not a second execution spine.
//!
//! Importing this library does not grant Hepta cell, model, or tool authority.
//! An embedding host must independently validate final-use authorization,
//! generation, and exact-payload binding before calling an effectful endpoint.

pub mod mcp;
pub mod utils;

/// Trusted native process facade; authorization remains with the embedding host.
pub mod native;
