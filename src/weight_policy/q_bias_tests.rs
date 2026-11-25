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

#[test]
fn preserves_an_interior_even_when_a_boundary_predicts_the_same_policy() {
	let text = INPUT
		.replace("0 3 0 0 0 0 1 0", "0 18 0 0 0 4 1 4")
		.replace("0 -.125 3 9 7 8", "-1 0 -1 -1 .125 -1");
	let search = search(&text, [1., 2.], 0.25).unwrap();
	let candidates = search.candidates(2).unwrap();
	assert_eq!(candidates.len(), 2);
	assert_eq!(candidates[0].shift, 0.125);
	assert!(!candidates[0].interior);
	assert_eq!(candidates[1].shift, 0.1875);
	assert!(candidates[1].interior);
	assert_eq!(
		search.actions(candidates[0].shift),
		search.actions(candidates[1].shift)
	);
	for limit in [0, 1, 65, usize::MAX] {
		assert!(search.candidates(limit).is_err());
	}
}

#[test]
fn repeated_gain_ties_do_not_drift_and_unprofitable_pools_are_empty() {
	let trials = [
		Trial {
			shift: 0.5,
			gains: [0.1, 0.1],
			interior: false,
		},
		Trial {
			shift: 0.25,
			gains: [0.1 - 0.75e-12; 2],
			interior: true,
		},
		Trial {
			shift: 0.125,
			gains: [0.1 - 1.5e-12; 2],
			interior: false,
		},
	];
	assert_eq!(best_trial(&trials), Some(1));
	assert!(search(INPUT, [1., 10.], 0.25)
		.unwrap()
		.candidates(2)
		.unwrap()
		.is_empty());
}

#[test]
fn rejects_partial_foreign_or_illegal_reopened_results() {
	let search = search(INPUT, [1., 2.], 0.25).unwrap();
	let trials = search.candidates(2).unwrap();
	for text in [
		"0",
		"1 .1875 14",
		"2 .1875 14",
		"2 .1875 14 .25 99",
		"2 .25 14 .1875 14",
		"2 .1875 14 .25 14 extra",
	] {
		assert!(
			select_reopened(&search, &trials, [1., 2.], text).is_err(),
			"{text}"
		);
	}
}

#[test]
fn reopened_trials_share_the_existing_search_budget() {
	// 5,000 states and 9,999 genuine mathematical representatives fit the
	// original 50M cap. Two physical trials would require 50,005,000 pairs.
	let count = 5000;
	let mut text = format!("HEPTA_DAG_V1 {count} 0\n");
	for _ in 0..count - 2 {
		text.push_str(&format!("0 18 0 0 0 4 4 4 1 1 {} .1 0 0\n", count - 1));
	}
	for _ in 0..2 {
		text.push_str("1 16 0 .8 0 4 4 4 0 0 0\n");
	}
	text.push_str("HEPTA_Q_SCORES_V1\n");
	for i in 0..count - 2 {
		text.push_str(&format!("-1 0 -1 -1 {} -1\n", (i + 1) as f64 / 8192.));
	}
	text.push_str("0 0 0 0 1 0\n0 0 0 0 1 0\n");
	let mut search = search(&text, [1., 2.], 1.).unwrap();
	let candidates = search.candidates(2).unwrap();
	assert_eq!(
		(
			search.graph.states.len(),
			search.trials.len(),
			candidates.len()
		),
		(5000, 9999, 2)
	);
	let rows = format!(
		"2 {:.17e} FAILED {:.17e} FAILED",
		candidates[0].shift, candidates[1].shift
	);
	assert!(select_reopened(&search, &candidates, [1., 2.], &rows)
		.err()
		.unwrap()
		.contains("combined"));
	// An exact 50M total is admitted. Remove one already computed trial from
	// the accounting fixture; no actual forward or candidate policy is altered.
	search.trials.pop();
	assert!(select_reopened(&search, &candidates, [1., 2.], &rows).is_ok());
}
