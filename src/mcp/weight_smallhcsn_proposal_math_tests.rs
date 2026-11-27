// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Analytic and failure controls for the bounded shared sender quadratic.

use super::*;
use std::time::Duration;

fn deadline() -> Instant {
	Instant::now() + Duration::from_secs(5)
}

fn key(feature: f64) -> Key {
	let mut value = [0.0; WIDTH];
	value[0] = feature;
	value[9] = 1.0;
	value
}

#[test]
fn scalar_bias_ridge_matches_closed_form() {
	let rows = [Observation {
		key: key(0.0),
		residual: [0.2, 0.0, 0.0, 0.0],
	}];
	let result = fit(&rows, &[key(0.0)], 1.0, deadline()).unwrap();
	assert!((result.delta[9][0] - 0.2 / 1.27).abs() < 1e-14);
	assert_eq!(result.multiplier, 0.0);
	assert_eq!(result.bisections, 0);
	assert_eq!(result.linear_solves, 1);
	assert!(result.kkt_max_abs < 1e-14);
	assert!(result.objective_after < result.objective_before);
}

#[test]
fn coupled_feature_bias_matches_two_by_two_solution() {
	let rows = [Observation {
		key: key(1.0),
		residual: [0.2, -0.1, 0.05, 0.0],
	}];
	let result = fit(&rows, &[key(-1.0)], 1.0, deadline()).unwrap();
	for (sender, target) in [0.2, -0.1, 0.05, 0.0].into_iter().enumerate() {
		assert!((result.delta[0][sender] - target / 2.02).abs() < 1e-14);
		assert!((result.delta[9][sender] - target / 2.02).abs() < 1e-14);
	}
	for row in &result.delta[1..9] {
		assert_eq!(*row, [0.0; 4]);
	}
}

#[test]
fn joint_four_sender_ball_matches_known_radial_solution() {
	let targets = [1.0, 2.0, 3.0, 4.0];
	let rows = [Observation {
		key: key(0.0),
		residual: targets,
	}];
	let result = fit(&rows, &[key(0.0)], 0.5, deadline()).unwrap();
	let target_norm = 30.0_f64.sqrt();
	for (sender, target) in targets.into_iter().enumerate() {
		assert!((result.delta[9][sender] - 0.5 * target / target_norm).abs() < 1e-13);
	}
	assert!((result.multiplier - (target_norm / 0.5 - 1.27)).abs() < 1e-11);
	assert!(result.norm <= 0.5 && (result.norm - 0.5).abs() < 1e-13);
	assert!(result.bisections <= 128);
	assert_eq!(result.linear_solves, result.bisections + 2);
	assert!(result.kkt_max_abs <= result.kkt_tolerance);
}

#[test]
fn group_means_are_invariant_to_duplicate_rows() {
	let row = Observation {
		key: key(1.0),
		residual: [0.25, -0.5, 0.0, 0.1],
	};
	let first = fit(std::slice::from_ref(&row), &[key(-1.0)], 1.0, deadline()).unwrap();
	let duplicated = fit(&[row.clone(), row], &[key(-1.0); 3], 1.0, deadline()).unwrap();
	for (left, right) in first
		.delta
		.iter()
		.flatten()
		.zip(duplicated.delta.iter().flatten())
	{
		assert!((left - right).abs() < 1e-13);
	}
}

#[test]
fn zero_targets_keep_zero_and_positive_ridge_handles_rank_deficiency() {
	let rows = [Observation {
		key: key(1.0),
		residual: [0.0; 4],
	}];
	let result = fit(&rows, &[key(1.0)], 1.0, deadline()).unwrap();
	assert_eq!(result.delta, [[0.0; 4]; 10]);
	assert_eq!(result.norm, 0.0);
	assert_eq!(result.objective_after, 0.0);
	assert_eq!(result.linear_solves, 1);
	assert!(result.minimum_cholesky_pivot >= 0.01);
}

#[test]
fn declared_domain_and_partition_errors_abstain() {
	let valid = Observation {
		key: key(1.0),
		residual: [0.1; 4],
	};
	assert!(fit(&[], &[key(1.0)], 1.0, deadline()).is_err());
	assert!(fit(std::slice::from_ref(&valid), &[], 1.0, deadline()).is_err());
	assert!(fit(&vec![valid.clone(); 480], &[key(1.0)], 1.0, deadline()).is_err());
	for radius in [0.0, -1.0, 1.01, f64::NAN, f64::INFINITY] {
		assert!(fit(
			std::slice::from_ref(&valid),
			&[key(1.0)],
			radius,
			deadline()
		)
		.is_err());
	}
	for feature in [4096.01, f64::NAN, f64::INFINITY] {
		let bad = Observation {
			key: key(feature),
			residual: [0.1; 4],
		};
		assert!(fit(&[bad], &[key(1.0)], 1.0, deadline()).is_err());
		assert!(fit(
			std::slice::from_ref(&valid),
			&[key(feature)],
			1.0,
			deadline()
		)
		.is_err());
	}
	for target in [64.01, f64::NAN, f64::INFINITY] {
		let bad = Observation {
			key: key(1.0),
			residual: [target; 4],
		};
		assert!(fit(&[bad], &[key(1.0)], 1.0, deadline()).is_err());
	}
	let mut bad_bias = key(1.0);
	bad_bias[9] = 0.0;
	assert!(fit(
		&[Observation {
			key: bad_bias,
			residual: [0.1; 4]
		}],
		&[key(1.0)],
		1.0,
		deadline()
	)
	.is_err());
}

#[test]
fn elapsed_deadline_and_unrepresentable_multiplier_abstain() {
	let row = Observation {
		key: key(0.0),
		residual: [1.0; 4],
	};
	assert!(fit(
		std::slice::from_ref(&row),
		&[key(0.0)],
		1.0,
		Instant::now() - Duration::from_millis(1)
	)
	.is_err());
	assert!(fit(&[row], &[key(0.0)], f64::from_bits(1), deadline()).is_err());
}

#[test]
fn all_ten_shared_columns_follow_their_analytic_diagonal_solution() {
	let mut rows = Vec::new();
	let mut protected = Vec::new();
	for column in 0..9 {
		for sign in [-1.0, 1.0] {
			let mut input = key(0.0);
			input[column] = sign;
			let target = std::array::from_fn(|sender| {
				0.01 * sign * (column + 1) as f64 * (sender + 1) as f64 + 0.01
			});
			rows.push(Observation {
				key: input,
				residual: target,
			});
			protected.push(input);
		}
	}
	let result = fit(&rows, &protected, 1.0, deadline()).unwrap();
	assert_eq!(result.multiplier, 0.0);
	for column in 0..9 {
		for sender in 0..4 {
			let expected = 0.01 * (column + 1) as f64 * (sender + 1) as f64 / (1.25 + 0.18);
			assert!((result.delta[column][sender] - expected).abs() < 1e-13);
		}
	}
	for value in result.delta[9] {
		assert!((value - 0.01 / 1.27).abs() < 1e-13);
	}
}
