// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact represented-number boundaries, width limits and malformed update rejection.

use super::*;

#[test]
fn exact_radius_and_adjacent_f64_values_are_distinguished() {
	let pairs = [(0.0, 3.0), (0.0, 4.0)];
	assert!(check_pairs(pairs, 5.0).unwrap().within_budget);
	assert!(
		!check_pairs(pairs, 5.0_f64.next_down())
			.unwrap()
			.within_budget
	);
	assert!(check_pairs(pairs, 5.0_f64.next_up()).unwrap().within_budget);
	let integer = Integer::shifted(25, 298).unwrap();
	assert_eq!(
		check_pairs(pairs, 5.0).unwrap().squared_update_units_hex,
		integer.hex()
	);
}

#[test]
fn subnormal_update_and_extreme_radii_do_not_use_float_squares() {
	let tiny = f32::from_bits(1);
	let radius = f64::from(tiny);
	let report = check_pairs([(0.0, tiny)], radius).unwrap();
	assert_eq!(report.squared_update_units_hex, "1");
	assert!(report.within_budget);
	assert!(
		!check_pairs([(0.0, tiny)], radius.next_down())
			.unwrap()
			.within_budget
	);
	assert!(
		!check_pairs([(0.0, tiny)], f64::from_bits(1))
			.unwrap()
			.within_budget
	);
	assert!(
		check_pairs([(f32::MAX, -f32::MAX)], f64::MAX)
			.unwrap()
			.within_budget
	);
}

#[test]
fn all_1024_maximum_opposite_updates_fit_the_proven_integer_width() {
	let pairs = vec![(f32::MAX, -f32::MAX); 1024];
	let radius = f64::from(f32::MAX) * 64.0;
	assert!(check_pairs(pairs.clone(), radius).unwrap().within_budget);
	assert!(
		!check_pairs(pairs.clone(), radius.next_down())
			.unwrap()
			.within_budget
	);
	assert!(check_pairs(pairs, radius.next_up()).unwrap().within_budget);
}

#[test]
fn widely_separated_exponents_keep_small_positive_contributions() {
	let pairs = [(0.0, 1.0), (0.0, f32::from_bits(1))];
	// Ordinary F64 addition rounds 1 + 2^-298 to 1, but the exact budget rejects it.
	assert!(!check_pairs(pairs, 1.0).unwrap().within_budget);
	assert!(check_pairs(pairs, 1.0_f64.next_up()).unwrap().within_budget);
	assert!(
		!check_pairs([(f32::from_bits(1), -1.0)], 1.0)
			.unwrap()
			.within_budget
	);
}

#[test]
fn zero_budget_accepts_only_numerically_unchanged_f32_values() {
	assert!(
		check_pairs([(1.0, 1.0), (-0.0, 0.0)], 0.0)
			.unwrap()
			.within_budget
	);
	assert!(check_pairs([], -0.0).unwrap().within_budget);
	assert!(
		!check_pairs([(0.0, f32::from_bits(1))], 0.0)
			.unwrap()
			.within_budget
	);
}

#[test]
fn invalid_radius_nonfinite_elements_and_excess_count_fail_closed() {
	for radius in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
		assert!(check_pairs([], radius).is_err());
	}
	for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
		assert!(check_pairs([(value, 0.0)], 1.0).is_err());
		assert!(check_pairs([(0.0, value)], 1.0).is_err());
	}
	assert!(check_pairs(vec![(0.0, 0.0); 1025], 1.0).is_err());
	let malformed = ExactElementEdit {
		index: 0,
		expected_hex: "0000".into(),
		replacement_hex: "00000000".into(),
	};
	assert!(check_edits(&[malformed], 1.0).is_err());
}
