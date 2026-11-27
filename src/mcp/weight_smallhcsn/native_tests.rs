// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Closed-form operator checks and rejection-path tests; no private fixtures embedded.
use super::{bound_io, matrix::Matrix};

fn close(actual: f64, expected: f64) {
	assert!((actual - expected).abs() < 2e-13, "{actual} vs {expected}");
}
#[test]
fn zero_exponential_is_identity() {
	let out = Matrix::zero(3).exp().unwrap();
	assert_eq!(out.a, Matrix::eye(3).a);
}
#[test]
fn absorbing_chain_matches_first_passage() {
	let mut a = Matrix::zero(2);
	a.a = vec![-2.0, 2.0, 0.0, 0.0];
	let out = a.scale(0.3).exp().unwrap();
	close(out.a[0], (-0.6f64).exp());
	close(out.a[1], 1.0 - (-0.6f64).exp());
	close(out.a[2], 0.0);
	close(out.a[3], 1.0);
}
#[test]
fn repeated_events_are_distinct_from_first_passage() {
	let t = 0.7;
	let mut a = Matrix::zero(3);
	a.a = vec![-2.0, 2.0, 2.0, 3.0, -3.0, 0.0, 0.0, 0.0, 0.0];
	let out = a.scale(t).exp().unwrap();
	let count = 1.2 * t + 0.16 * (1.0 - (-5.0 * t).exp());
	close(out.a[2], count);
	assert!(count > 1.0 - (-2.0 * t).exp());
}
#[test]
fn reward_resolvent_matches_two_state_inverse() {
	let rho = 0.3;
	let mut a = Matrix::zero(2);
	a.a = vec![rho + 2.0, -2.0, -3.0, rho + 3.0];
	let mut b = Matrix::zero(2);
	b.a = vec![1.0, 0.0, -0.2, 0.0];
	let v = a.solve(&b).unwrap();
	let determinant = rho * (rho + 5.0);
	close(v.a[0], (rho + 3.0 - 0.4) / determinant);
	close(v.a[2], (3.0 - 0.2 * (rho + 2.0)) / determinant);
}
#[test]
fn malformed_inputs_and_unbound_artifacts_are_rejected() {
	assert!(bound_io::inputs(b"HCSNIN1\0").is_err());
	assert!(bound_io::bind(b"{}", b"not-an-artifact", b"not-input").is_err());
	assert!(Matrix::zero(13).exp().is_err());
}
#[test]
fn exhausted_deadline_is_rejected() {
	let deadline = super::deadline::Deadline::new(std::time::Duration::ZERO);
	assert!(deadline.check().is_err());
}
