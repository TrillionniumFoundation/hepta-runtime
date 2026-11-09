// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Default-off and explicit-admission CLI tests for private startup evidence.

use super::*;

#[test]
fn private_config_receipt_is_default_off() {
	for arguments in [
		vec!["hepta-runtime", "mcp"],
		vec!["hepta-runtime", "mcp", "--runtime-config", "runtime.json"],
	] {
		let Cli {
			command: Commands::Mcp {
				runtime_private_config_receipt,
				..
			},
		} = Cli::try_parse_from(arguments).unwrap()
		else {
			panic!("MCP arguments selected an internal helper");
		};
		assert!(!runtime_private_config_receipt);
	}
}

#[test]
fn private_config_receipt_requires_selected_config() {
	let error =
		Cli::try_parse_from(["hepta-runtime", "mcp", "--runtime-private-config-receipt"])
			.unwrap_err();
	assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn private_config_receipt_requires_explicit_opt_in() {
	let Cli {
		command: Commands::Mcp {
			runtime_private_config_receipt,
			runtime_config,
			..
		},
	} = Cli::try_parse_from([
		"hepta-runtime",
		"mcp",
		"--runtime-config",
		"runtime.json",
		"--runtime-private-config-receipt",
	])
	.unwrap()
	else {
		panic!("MCP arguments selected an internal helper");
	};
	assert!(runtime_private_config_receipt);
	assert_eq!(runtime_config, Some(PathBuf::from("runtime.json")));
}
