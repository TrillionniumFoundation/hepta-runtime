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

#[test]
fn accepts_profitable_edits_only_at_each_closed_radius_endpoint() {
	let positive = "HEPTA_DAG_V1 2 0\n0 18 0 0 0 4 1 4 1 1 1 .1 0 0\n1 16 0 .8 0 4 4 4 0 0 0\nHEPTA_Q_SCORES_V1\n-1 0 -1 -1 .125 -1\n2 7 8 9 .8 -.8";
	let p = solve(positive, [1., 2.], 0.125).unwrap();
	assert_eq!(p.shift, 0.125);
	assert_eq!(p.actions, [1, 4]);
	assert!((p.gains[0] - 0.7).abs() < 1e-12 && (p.gains[1] - 0.6).abs() < 1e-12);
	// Every smaller admissible shift keeps action 4; no open cell can improve.
	let negative = "HEPTA_DAG_V1 2 0\n0 3 .8 0 0 1 0 1 1 1 1 .1 0 0\n1 16 0 0 0 4 4 4 0 0 0\nHEPTA_Q_SCORES_V1\n-.125 0 -1 -1 -1 -1\n0 0 0 0 1 0";
	let p = solve(negative, [1., 2.], 0.125).unwrap();
	assert_eq!(p.shift, -0.125);
	assert_eq!(p.actions, [0, 4]);
	assert!((p.gains[0] - 0.9).abs() < 1e-12 && (p.gains[1] - 1.).abs() < 1e-12);
}

#[test]
fn evaluates_an_isolated_tie_policy_distinct_from_both_open_cells() {
	let input = "HEPTA_DAG_V1 3 0\n0 18 0 0 0 4 1 4 1 1 1 .1 0 0\n1 3 .8 0 0 0 0 0 1 1 2 .1 0 0\n2 1 0 0 0 0 0 0 0 0 0\nHEPTA_Q_SCORES_V1\n-1 0 -1 -1 .125 -1\n.125 0 -1 -1 -1 -1\n0 -1 -1 -1 -1 -1";
	let p = solve(input, [1., 2.], 0.25).unwrap();
	assert_eq!(p.shift, 0.125);
	assert_eq!(p.actions, [1, 0, 0]);
	assert!((p.gains[0] - 0.7).abs() < 1e-12 && (p.gains[1] - 0.6).abs() < 1e-12);
	// Below the tie the first state stops for zero. Above it both states
	// continue, paying two fees for zero reward. Only the tie earns 0.8.
	let rejected = solve(input, [1., 10.], 0.25).unwrap();
	assert_eq!((rejected.shift, rejected.gains), (0., [0.; 2]));
	assert_eq!(rejected.actions, [4, 0, 0]);
}

#[test]
fn includes_boundary_trials_in_the_work_budget_before_evaluation() {
	let count = 6000;
	let mut input = format!("HEPTA_DAG_V1 {} 0\n", count + 1);
	for _ in 0..count {
		input.push_str(&format!("0 18 0 0 0 4 4 4 1 1 {count} .1 0 0\n"));
	}
	input.push_str("1 16 0 .8 0 4 4 4 0 0 0\nHEPTA_Q_SCORES_V1\n");
	for i in 0..count {
		input.push_str(&format!("-1 0 -1 -1 {} -1\n", (i + 1) as f64 / 8192.));
	}
	input.push_str("0 0 0 0 1 0\n");
	// Open cells alone fit the cap; adding legal boundaries must not double
	// the work past the existing cap without being admitted explicitly.
	assert!(solve(&input, [1., 2.], 1.)
		.err()
		.unwrap()
		.contains("planner budget"));
}
