// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Actual original concurrency cases driving the HIA controller and kernel boundary.
#![allow(dead_code)]

#[path = "controller_host.rs"]
mod controller_host;
use controller_host::{AuditStoreLock, StoreLockFailure};
use std::sync::Arc;
use std::time::Instant;

include!("audit_store_tests.rs.txt");
include!("controller_extra_tests.rs.txt");

fn extra_observation(kind: &str, fields: &str) {
	controller_host::test_observation(kind, fields);
}

#[test]
fn deadline_mapping_is_exact_on_the_pinned_linux_toolchain() {
	controller_host::clock_mapping_domain();
}
