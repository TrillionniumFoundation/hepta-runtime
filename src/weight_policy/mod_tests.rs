// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Finite-graph public contract regression cases.
use super::*;

const GRAPH: &str = "HEPTA_DAG_V1 2 0\n0 3 0 0 0 0 1 0 1 1 1 .1 0 0\n1 16 0 .8 0 4 4 4 0 0 0";

#[test]
fn known_fee_and_one_more_action_unlock_profitable_continuation() {
	let results = Graph::parse(GRAPH).unwrap().solve().unwrap();
	assert_eq!(results[2].1[0], 0);
	assert_eq!(results[3].1[0], 1);
	assert!((results[3].2 - 0.7).abs() < 1e-12);
	assert_eq!(results[4].1, results[3].1);
}

#[test]
fn malformed_laws_and_proposals_are_refused() {
	for mutation in [
		GRAPH.replace("1 .1", "0 .1"),
		GRAPH.replace(" 1 1 1 .1", " 1 .5 1 .1"),
		GRAPH.replace(" 0 1 0 1", " 4 1 0 1"),
		GRAPH.replace(" .8 0", " NaN 0"),
		GRAPH.replace(" .1 ", " -1 "),
		format!("{GRAPH} 9"),
	] {
		assert!(Graph::parse(&mutation).is_err());
	}
}
