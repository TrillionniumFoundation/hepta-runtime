// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Finite-graph public contract regression cases.
use super::*;

#[test]
fn explicit_asymmetric_probability_endpoints() {
	let l = Law {
		fee_low: 1.,
		fee_high: 3.,
		tilt: 0.4,
	};
	let edges = [
		Edge {
			probability: 0.25,
			next: 0,
			fee: 0.,
		},
		Edge {
			probability: 0.75,
			next: 1,
			fee: 0.,
		},
	];
	let (lo, hi) = l.range(&edges, |e| if e.next == 1 { 1. } else { -1. });
	assert!((lo - 0.125).abs() < 1e-12 && (hi - 0.75).abs() < 1e-12);
}
#[test]
fn a_preferable_worst_case_is_not_uniform_dominance() {
	let g=Graph::parse("HEPTA_DAG_V1 3 0 0 3 0.3 0 0 1 0 0 2 .5 1 0 .5 2 0 0 0 1 16 0 1 0 4 4 4 0 0 0 1 16 0 -1 0 4 4 4 0 0 0").unwrap();
	let law = Law {
		fee_low: 1.,
		fee_high: 3.,
		tilt: 0.8,
	};
	let base = assess(&g, law, &[1, 4, 4]);
	assert_eq!(minimize_risk(&g, law, &base, false)[0], 0);
	assert_eq!(minimize_risk(&g, law, &base, true)[0], 1);
	let bounds = assess(&g, law, &[0, 4, 4]);
	let delta = paired_lower(&g, law, &[0, 4, 4], &bounds, &base);
	assert!((delta[0] + 0.5).abs() < 1e-12);
}
