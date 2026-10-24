// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pure configuration checks and isolated process-level environment validation.
use super::*;

#[test]
fn absent_capacity_environment_preserves_compatible_defaults() {
	assert_eq!(
		parse_limits(None, None).unwrap(),
		RetentionLimits {
			owner_keys: 128,
			global_keys: 512
		}
	);
}

#[test]
fn administrator_can_raise_lifetime_capacity_without_adding_expiry() {
	assert_eq!(
		parse_limits(Some("8192"), Some("32768")).unwrap(),
		RetentionLimits {
			owner_keys: 8192,
			global_keys: 32768
		}
	);
	assert!(parse_limits(Some("1"), Some("1")).is_ok());
	assert!(parse_limits(Some("65536"), Some("65536")).is_ok());
}

#[test]
fn capacities_refuse_zero_negative_overflow_nondecimal_and_inconsistent_ranges() {
	for invalid in [
		"",
		"0",
		"-1",
		"+1",
		" 128",
		"128 ",
		"1.0",
		"1e3",
		"1_024",
		"65537",
		"999999999999999999999999999999999999999999",
		"１２８",
		"NaN",
		"1\n",
	] {
		assert!(
			parse_limits(Some(invalid), Some("65536")).is_err(),
			"{invalid:?}"
		);
		assert!(
			parse_limits(Some("1"), Some(invalid)).is_err(),
			"{invalid:?}"
		);
	}
	assert!(parse_limits(Some("513"), None).is_err());
	assert!(parse_limits(None, Some("127")).is_err());
	assert!(parse_limits(Some("8192"), Some("4096")).is_err());
}

#[test]
fn environment_is_validated_once_before_journal_access() {
	const CHILD: &str = "HEPTA_RETENTION_LIMITS_TEST_CHILD";
	if let Ok(case) = std::env::var(CHILD) {
		if case == "invalid" {
			assert!(init_retention_limits().is_err());
			std::env::set_var(OWNER_KEYS_ENV, "128");
			assert!(init_retention_limits().is_err());
		} else {
			init_retention_limits().unwrap();
			let original = *retention_limits().unwrap();
			assert_eq!(original.owner_keys, 8192);
			assert_eq!(original.global_keys, 32768);
			std::env::set_var(OWNER_KEYS_ENV, "1");
			std::env::set_var(GLOBAL_KEYS_ENV, "1");
			assert_eq!(*retention_limits().unwrap(), original);
		}
		return;
	}
	for case in ["valid", "invalid"] {
		let status = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"--exact",
				"mcp::runtime::retention_limits::tests::environment_is_validated_once_before_journal_access",
				"--test-threads=1",
			])
			.env(CHILD, case)
			.env(OWNER_KEYS_ENV, if case == "valid" { "8192" } else { "0" })
			.env(GLOBAL_KEYS_ENV, "32768")
			.status()
			.unwrap();
		assert!(status.success());
	}
}
