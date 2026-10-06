// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Operator argument contracts; no production process is signalled.
use super::*;

#[test]
fn signal_rejects_process_groups_and_wildcards() {
	for pid in [0, u32::MAX, (i32::MAX as u32) + 1] {
		let p: HostSignalParams = serde_json::from_value(json!({"host":"test","pid":pid})).unwrap();
		assert!(validate_signal(&p).is_err());
	}
	let p: HostSignalParams = serde_json::from_value(json!({"host":"test","pid":1234})).unwrap();
	assert_eq!(validate_signal(&p).unwrap(), 15);
}

#[test]
fn signal_keeps_real_pid_scope_and_probe() {
	for number in [0, 9, 15, 19] {
		let p: HostSignalParams = serde_json::from_value(
			json!({"host":"test","pid":1234,"signal":number,"expected_identity":"boot:ticks"}),
		)
		.unwrap();
		assert_eq!(validate_signal(&p).unwrap(), number);
	}
	let p: HostSignalParams =
		serde_json::from_value(json!({"host":"test","pid":1234,"signal":-1})).unwrap();
	assert!(validate_signal(&p).is_err());
}

#[test]
fn sudo_preserves_argv_and_defaults_to_fresh_auth() {
	let p: SudoStartParams = serde_json::from_value(
		json!({"host":"test","executable":"/bin/sh","args":["-c","printf '%s' \"a; b 中文\""]}),
	)
	.unwrap();
	assert!(p.fresh_auth);
	assert_eq!(
		sudo_argv(&p).unwrap(),
		[
			"-k",
			"-u",
			"root",
			"--",
			"/bin/sh",
			"-c",
			"printf '%s' \"a; b 中文\""
		]
	);
}

#[test]
fn sudo_rejects_option_injection_and_supports_noninteractive() {
	let mut p: SudoStartParams = serde_json::from_value(
		json!({"host":"test","executable":"/usr/bin/id","non_interactive":true,"fresh_auth":false}),
	)
	.unwrap();
	assert_eq!(
		sudo_argv(&p).unwrap(),
		["-n", "-u", "root", "--", "/usr/bin/id"]
	);
	p.run_as = Some("-n".into());
	assert!(sudo_argv(&p).is_err());
}

#[test]
fn operator_schemas_reject_hidden_authority_fields() {
	assert!(serde_json::from_value::<HostSignalParams>(
		json!({"host":"test","pid":1234,"execution_mode":"operator"})
	)
	.is_err());
	assert!(serde_json::from_value::<SudoStartParams>(
		json!({"host":"test","executable":"/usr/bin/id","password":"never"})
	)
	.is_err());
}
