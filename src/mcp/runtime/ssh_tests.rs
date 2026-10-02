// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for ssh.
use super::*;
use std::collections::BTreeMap;

#[test]
fn quotes_shell_data() {
	assert_eq!(shell_quote("a b"), "'a b'");
	assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
}

#[test]
fn builds_argv_without_model_side_quoting() {
	let cmd = build_exec_command(
		"/bin/printf",
		&["%s".into(), "a b'c".into()],
		Some("/tmp/a b"),
		&BTreeMap::new(),
		24,
		80,
	)
	.unwrap();
	assert!(cmd.contains("'/tmp/a b'"));
	assert!(cmd.contains("'a b'\"'\"'c'"));
}
