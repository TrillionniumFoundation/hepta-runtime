// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for config.
use super::*;

#[test]
fn names_are_strict() {
	assert!(valid_name("rog-1.example"));
	assert!(!valid_name("rog/1"));
	assert!(!valid_name(&"-".repeat(129)));
}

#[test]
fn basename_is_stable() {
	assert_eq!(executable_basename("/usr/bin/systemctl"), "systemctl");
	assert_eq!(executable_basename("python3"), "python3");
}

#[test]
fn privileged_regexes_are_full_match_capable() {
	let regex = Regex::new(r"\A(?:[a-z0-9_-]+)\z").unwrap();
	assert!(regex.is_match("profile-1"));
	assert!(!regex.is_match("profile-1;id"));
}
