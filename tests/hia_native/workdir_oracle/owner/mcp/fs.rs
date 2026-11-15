// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact workdir owner; remote effects deliberately outside this fixture.
pub mod remote;
pub mod workdir;
pub use remote::PathSource;
pub use workdir::{execute_workdir_command, WorkdirResult};
