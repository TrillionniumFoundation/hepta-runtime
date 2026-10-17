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

#[test]
fn python_interpreter_is_fixed_or_absolute_safe_and_shell_quoted() {
	assert_eq!(
		python_json_command("python3", "print('ok')").unwrap(),
		"'python3' -c 'print('\"'\"'ok'\"'\"')'"
	);
	let interpreter = "/opt/venv's python/bin/python3";
	assert_eq!(
		python_json_command(interpreter, "print(1)").unwrap(),
		format!("{} -c 'print(1)'", shell_quote(interpreter))
	);
	for invalid in [
		"",
		"python",
		"venv/bin/python3",
		"/opt/../bin/python3",
		"/opt/python\n3",
		"/opt/python\t3",
		"/opt/python\0",
	] {
		assert!(
			python_json_command(invalid, "print(1)").is_err(),
			"{invalid:?}"
		);
	}
	assert!(python_json_command(&format!("/{}", "x".repeat(4096)), "").is_err());
}
