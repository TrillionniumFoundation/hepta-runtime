// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use super::*;
const INPUT:&str = "HEPTA_DAG_V1 2 0\n0 3 0 0 0 0 1 0 1 1 1 .1 0 0\n1 16 0 .8 0 4 4 4 0 0 0\nHEPTA_Q_SCORES_V1\n0 -.125 3 9 7 8\n2 7 8 9 .8 -.8";

#[test]
fn chooses_the_profitable_open_cell_and_checks_both_endpoint_values() {
	let p = solve(INPUT, [1., 2.], 0.25).unwrap();
	assert_eq!(p.shift, 0.1875);
	assert_eq!(p.actions, [1, 4]);
	assert_eq!(p.cells, 2);
	assert!((p.gains[0] - 0.7).abs() < 1e-12 && (p.gains[1] - 0.6).abs() < 1e-12);
}

#[test]
fn keeps_exact_original_at_radius_boundary_ties_and_adverse_fees() {
	for (text, fees, radius) in [
		(INPUT, [1., 2.], 0.125),
		(INPUT, [1., 10.], 0.25),
		(&INPUT.replace("-.125", "0"), [8., 9.], 0.25),
	] {
		let p = solve(text, fees, radius).unwrap();
		assert_eq!((p.shift, p.gains, p.actions), (0., [0.; 2], vec![0, 4]));
	}
}

#[test]
fn refuses_scores_that_do_not_represent_the_incumbent() {
	for input in [
		INPUT.replace("-.125", "1"),
		INPUT.replace("-.125", "NaN"),
		INPUT.replace("HEPTA_Q_SCORES_V1", "OTHER"),
		format!("{INPUT} 1"),
		INPUT.trim_end_matches(" -.8").to_string(),
	] {
		assert!(solve(&input, [1., 2.], 0.25).is_err());
	}
	assert!(solve(INPUT, [2., 1.], 0.25).is_err());
	assert!(solve(INPUT, [1., 2.], 0.).is_err());
}
