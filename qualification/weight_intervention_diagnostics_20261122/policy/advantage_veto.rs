// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Standalone dependency-free entry point to the production finite-policy solver.
#[path = "../../../src/weight_policy/mod.rs"]
mod weight_policy;

fn execute() -> Result<(), String> {
	let mut parts = std::env::args().skip(1);
	let mode = parts.next();
	let values = parts
		.map(|s| {
			s.parse::<f64>()
				.map_err(|_| "invalid numerical parameter".to_string())
		})
		.collect::<Result<Vec<_>, _>>()?;
	match mode.as_deref() {
		None => weight_policy::run(&[], &[], &[]),
		Some("--fee-band") if values.len() == 2 => weight_policy::run(&values, &[], &[]),
		Some("--uncertainty") if values.len() == 3 => weight_policy::run(&[], &values, &[]),
        Some("--plan-q-bias") if values.len() == 3 => weight_policy::run(&[], &[], &values),
		_ => {
			Err("expected --fee-band MIN MAX, --uncertainty MIN MAX RADIUS, --plan-q-bias MIN MAX RADIUS, or no arguments".into())
		}
	}
}
fn main() {
	if let Err(message) = execute() {
		eprintln!("{message}");
		std::process::exit(1);
	}
}
