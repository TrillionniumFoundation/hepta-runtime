// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn file_pool_is_an_independent_default_off_startup_option() {
	for arguments in [
		vec!["hepta-runtime", "mcp"],
		vec![
			"hepta-runtime",
			"mcp",
			"--runtime-config",
			"runtime.json",
			"--runtime-observation-pool-profile",
			"profile.json",
		],
	] {
		let Cli {
			command: Commands::Mcp {
				runtime_file_observation_pool,
				..
			},
		} = Cli::try_parse_from(arguments).unwrap();
		assert!(!runtime_file_observation_pool);
	}
}

#[test]
fn file_pool_cli_requires_both_config_and_explicit_profile() {
	for options in [
		vec![],
		vec!["--runtime-config", "runtime.json"],
		vec!["--runtime-observation-pool-profile", "profile.json"],
	] {
		let mut arguments = vec!["hepta-runtime", "mcp", "--runtime-file-observation-pool"];
		arguments.extend(options);
		let error = Cli::try_parse_from(arguments).unwrap_err();
		assert_eq!(
			error.kind(),
			clap::error::ErrorKind::MissingRequiredArgument
		);
	}
	let Cli {
		command:
			Commands::Mcp {
				runtime_file_observation_pool,
				runtime_config,
				runtime_observation_pool_profile,
				..
			},
	} = Cli::try_parse_from([
		"hepta-runtime",
		"mcp",
		"--runtime-file-observation-pool",
		"--runtime-config",
		"runtime.json",
		"--runtime-observation-pool-profile",
		"profile.json",
	])
	.unwrap();
	assert!(runtime_file_observation_pool);
	assert_eq!(runtime_config, Some(PathBuf::from("runtime.json")));
	assert_eq!(
		runtime_observation_pool_profile,
		Some(PathBuf::from("profile.json"))
	);
}
