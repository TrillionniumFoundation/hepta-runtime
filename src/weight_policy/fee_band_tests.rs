// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Finite-graph public contract regression cases.
use super::*;

fn simple(terminal: f64, fee: f64) -> Graph {
	Graph::parse(&format!(
		"HEPTA_DAG_V1 2 0\n0 3 0 0 0 0 1 0 1 1 1 {fee} 0 0\n1 16 0 {terminal} 0 4 4 4 0 0 0"
	))
	.unwrap()
}
#[test]
fn fee_reversal_and_profitable_edit() {
	let fragile = simple(0.45, 0.3);
	let stable = simple(0.75, 0.3);
	for back in [false, true] {
		assert_eq!(solve(&fragile, [1., 1.], false, back).unwrap().0[0], 1);
		assert_eq!(solve(&fragile, [1., 2.], false, back).unwrap().0[0], 0);
		let (policy, v) = solve(&stable, [1., 2.], false, back).unwrap();
		assert_eq!(policy[0], 1);
		assert!((v[0] - 0.45).abs() < 1e-12 && (v[1] - 0.15).abs() < 1e-12);
	}
}
#[test]
fn invalid_fee_band() {
	let graph = simple(0.5, 0.25);
	for bad in [[2., 1.], [-1., 1.], [1., f64::INFINITY], [f64::NAN, 1.]] {
		assert!(solve(&graph, bad, false, true).is_err());
	}
}
