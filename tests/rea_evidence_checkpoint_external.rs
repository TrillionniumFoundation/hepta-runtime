// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! The shipping binary must recover an explicitly selected complete checkpoint
//! after a real HTTP process kill, and refuse changed authority and corruption.

#![cfg(all(target_os = "linux", feature = "remote-fs"))]

#[test]
fn real_http_evidence_checkpoint_survives_restart_with_owner_policy_and_order() {
	let output = std::process::Command::new("python3")
		.arg("-B")
		.arg("-c")
		.arg(include_str!("rea_evidence_checkpoint_http.py"))
		.arg(env!("CARGO_BIN_EXE_hepta-runtime"))
		.arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"))
		.output()
		.expect("Python standard-library HTTP checkpoint driver");
	assert!(
		output.status.success(),
		"stdout: {}\nstderr: {}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
	let stdout = String::from_utf8(output.stdout).expect("UTF-8 checkpoint qualification");
	assert!(stdout.contains("REA_EVIDENCE_CHECKPOINT_HTTP_QUALIFICATION"));
	print!("{stdout}");
}
