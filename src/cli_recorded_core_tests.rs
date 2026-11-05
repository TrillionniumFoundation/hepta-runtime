// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! The internal captured-core command never accepts a source path or process ID.

use super::*;
use clap::CommandFactory;

#[test]
fn recorded_core_cli_is_hidden_and_accepts_no_source_arguments() {
	assert!(matches!(
		Cli::try_parse_from(["hepta-runtime", "rea-recorded-core-worker"])
			.unwrap()
			.command,
		Commands::ReaRecordedCoreWorker
	));
	let help = Cli::command().render_long_help().to_string();
	assert!(!help.contains("rea-recorded-core-worker"));
	for tail in [
		vec!["/tmp/recorded.core"],
		vec!["--path", "/tmp/recorded.core"],
		vec!["--request", "request.json"],
		vec!["--pid", "1"],
	] {
		let mut arguments = vec!["hepta-runtime", "rea-recorded-core-worker"];
		arguments.extend(tail);
		assert!(Cli::try_parse_from(arguments).is_err());
	}
}
