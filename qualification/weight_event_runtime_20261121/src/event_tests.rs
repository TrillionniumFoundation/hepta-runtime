// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded analytic controls for event-tagged uniformization.

use crate::*;

#[test]
fn reachable_event_basis_has_163_states_and_keeps_order() {
	let nodes = basis();
	assert_eq!(nodes.len(), 163);
	assert_eq!(next_history(0, 31, false), 1);
	assert_eq!(next_history(1, 15, true), 3);
	assert_eq!(next_history(3, 32, false), 5);
	assert_eq!(next_history(4, 31, false), 6);
	assert_ne!(5, 6);
}

#[test]
fn shared_physical_edge_does_not_identify_which_mechanism_reset() {
	// Both decompositions have the same physical Q[0,1]=2. Their reset
	// sub-rate differs, so a current-state-only generator cannot identify it.
	for reset_rate in [0.0, 0.3, 1.7, 2.0] {
		let generator = SparseGenerator::from_rates(
			vec![
				vec![(1, 2.0 - reset_rate), (3, reset_rate)],
				vec![],
				vec![],
				vec![],
			],
			vec![2.0, 0.0, 0.0, 0.0],
		)
		.unwrap();
		let out = generator.propagate(&[1.0, 0.0, 0.0, 0.0], 0.7).unwrap();
		let departed = 1.0 - (-1.4_f64).exp();
		assert!((out.mass[1] + out.mass[3] - departed).abs() < 1e-13);
		assert!((out.mass[3] - reset_rate / 2.0 * departed).abs() < 1e-13);
	}
}

#[test]
fn zero_time_identity_and_work_envelope_fail_closed() {
	let q =
		SparseGenerator::from_rates(vec![vec![(1, 2.0)], vec![(0, 1.0)]], vec![2.0, 1.0]).unwrap();
	assert_eq!(
		q.propagate(&[0.25, 0.75], 0.0).unwrap().mass,
		vec![0.25, 0.75]
	);
	assert!(q.propagate(&[0.25, 0.75], 3.0).is_err());
	assert!(q.propagate(&[0.2, 0.7], 1.0).is_err());
	assert!(SparseGenerator::from_rates(vec![vec![(1, 2.0)], vec![]], vec![1.0, 0.0]).is_err());
}

#[test]
fn two_state_recovery_matches_closed_form() {
	let q =
		SparseGenerator::from_rates(vec![vec![(1, 2.0)], vec![(0, 0.5)]], vec![2.0, 0.5]).unwrap();
	let result = q.propagate(&[1.0, 0.0], 1.3).unwrap();
	let expected = 2.0 / 2.5 * (1.0 - (-2.5_f64 * 1.3).exp());
	assert!((result.mass[1] - expected).abs() < 1e-13);
	assert!(result.omitted_tail_bound <= 1e-15);
}

#[test]
fn normal_bins_integrate_a_unit_truncated_reset_law() {
	let q = rebuild(&[0.0; 8], 0).unwrap();
	for row in q.iter().skip(31) {
		assert!(row.iter().sum::<f64>().abs() < 1e-13);
		assert!(row[..31].iter().all(|v| *v >= 0.0));
	}
}

#[test]
fn legacy_submit_decoder_is_not_admitted_as_current_endpoint_score() {
	let law = EventLaw {
		basis: basis(),
		generators: BTreeMap::new(),
		confusion: [[1.0, 0.0], [0.0, 1.0]],
		checkpoint_sha256: String::new(),
		generator_reconstruction_max_error: 0.0,
	};
	let mut current = vec![0.0; 163];
	current[15] = 0.25;
	current[16] = 0.75;
	assert!(law.decode(&current, "SUBMIT_Q").is_err());
	assert!(law
		.decode(&current, "FIRST_OUTER_HISTORY_AND_ENDPOINT_UTILITY")
		.is_err());
	let decoder = law
		.decode(
			&current,
			"FIRST_OUTER_HISTORY_AND_CURRENT_ENDPOINT_SIGN_SCORE",
		)
		.unwrap();
	assert_eq!(decoder.current_endpoint_positive_sign_score, 0.5);
	assert_eq!(decoder.current_endpoint_nonpositive_sign_score, -0.5);
}
