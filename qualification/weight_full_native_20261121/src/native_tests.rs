// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Synthetic controls; no retained model arrays, law tables or financial labels are loaded.

use super::*;
use anyhow::bail;
use hepta_continuation_runtime_study::task::{self, Public};
use hepta_semantic_source_adapter_study::{digest, unique_json};
use hepta_value_intent_study::{exact, readout_sha256, Binding, Edit, Intent, LAYOUT};
use serde_json::{json, Value};

fn model() -> Value {
	let mut w2 = vec![vec![0.0; 48]; 4];
	w2[0][0] = 1.0;
	json!({"schema":"joint-policy-v1","family":"renewal","head_dimensions":[85,48,4],
		"network":{"w1":vec![vec![0.0;85];48],"b1":vec![0.0;48],"w2":w2,"b2":[1.0,0.0,0.0,-0.0]},
		"explicit_synthetic_fixture":true})
}

fn intent(before: &[f64; 196], after: &[f64; 196]) -> Intent {
	let norm = exact::check(before, after).unwrap();
	Intent {
		schema: "hepta.readout196-intent.v1".into(),
		candidate_id: "synthetic".into(),
		layout: LAYOUT.into(),
		binding: Binding {
			compressed_sha256: "a".repeat(64),
			decoded_sha256: "a".repeat(64),
			profile_sha256: "a".repeat(64),
			protected_law_task_sha256: "a".repeat(64),
		},
		protocol_sha256: "a".repeat(64),
		producer_sha256: "a".repeat(64),
		row_mask: 15,
		edits: before
			.iter()
			.zip(after)
			.map(|(a, b)| Edit {
				old_bits: format!("{:016x}", a.to_bits()),
				new_bits: format!("{:016x}", b.to_bits()),
			})
			.collect(),
		expected_readout_sha256: readout_sha256(after),
		delta_squared_units_hex: norm.delta_squared_units_hex,
		anchor_q147_squared_units_hex: norm.anchor_q147_squared_units_hex,
	}
}

fn public() -> Public {
	Public {
		schema: "joint-current-at-due-fixed-deadline-v1".into(),
		id: "synthetic".into(),
		deadline: 6,
		target_tick: 6,
		initial_budget: 3,
		duration: [1.0; 6],
		drive: [0; 6],
		reliability: [0.75; 6],
		read_price: [0.1; 6],
		read_delay: [1; 6],
		packets: std::array::from_fn(|i| format!("p{i}.json")),
		packet_sha256: std::array::from_fn(|_| "a".repeat(64)),
		latency_price: 0.01,
		repair_price: 0.1,
		failure_probability: 0.1,
		prior_distance: 0.125,
	}
}

#[test]
fn lossless_json_f64_bridge_restores_exact_original_whitespace_and_bits() {
	let mut m = model();
	m["network"]["b2"] = json!([f64::from_bits(1), f64::MAX, -0.0, 1.0]);
	let raw = serde_json::to_vec_pretty(&m).unwrap();
	let bridge = codec::encode(&raw).unwrap();
	assert_eq!(codec::decode(&bridge).unwrap(), raw);
	assert_eq!(
		codec::weights_hash(&m).unwrap(),
		codec::weights_hash(&unique_json(&codec::decode(&bridge).unwrap()).unwrap()).unwrap()
	);
}

#[test]
fn direct_readout_edit_uses_original_bits_shared_radius_and_protected_parameters() {
	let raw = serde_json::to_vec(&model()).unwrap();
	let bridge = codec::encode(&raw).unwrap();
	let before = codec::readout(&model()).unwrap();
	let mut after = before;
	after[192] += 0.1;
	let proposal = intent(&before, &after);
	let candidate = codec::edit(&bridge, &digest(&bridge), &proposal).unwrap();
	let decoded = unique_json(&codec::decode(&candidate).unwrap()).unwrap();
	assert_eq!(
		codec::readout(&decoded).unwrap().map(f64::to_bits),
		after.map(f64::to_bits)
	);
	assert_eq!(
		codec::protected_hash(&decoded).unwrap(),
		codec::protected_hash(&model()).unwrap()
	);
	let mut wrong = proposal.clone();
	wrong.edits[195].old_bits = "0000000000000000".into();
	assert!(codec::edit(&bridge, &digest(&bridge), &wrong).is_err());
	let mut outside = before;
	outside[192] += 2.0;
	assert!(codec::edit(&bridge, &digest(&bridge), &intent(&before, &outside)).is_err());
	let mut mask = proposal;
	mask.row_mask = 8;
	assert!(codec::edit(&bridge, &digest(&bridge), &mask).is_err());
}

#[test]
fn bridge_rejects_format_duplicates_shape_nonfinite_and_tampering() {
	assert!(codec::encode(br#"{"schema":"joint-policy-v1","schema":"other"}"#).is_err());
	let mut m = model();
	m["family"] = json!("gru");
	assert!(codec::encode(&serde_json::to_vec(&m).unwrap()).is_err());
	m = model();
	m["network"]["b2"] = json!([0]);
	assert!(codec::encode(&serde_json::to_vec(&m).unwrap()).is_err());
	let mut bridge = codec::encode(&serde_json::to_vec(&model()).unwrap()).unwrap();
	let offset = 8 + u64::from_le_bytes(bridge[..8].try_into().unwrap()) as usize;
	bridge[offset..offset + 8].copy_from_slice(&f64::NAN.to_le_bytes());
	assert!(codec::decode(&bridge).is_err());
	bridge.pop();
	assert!(codec::decode(&bridge).is_err());
}

#[test]
fn callback_failure_and_panic_restore_every_original_byte() {
	let original = b"all original model bytes\0including signed zero".to_vec();
	let candidate = b"candidate".to_vec();
	let mut active = original.clone();
	let (result, receipt) = lifecycle::run::<()>(&mut active, &original, &candidate, |_| {
		bail!("injected evaluation failure")
	})
	.unwrap();
	assert!(result.is_err());
	assert!(receipt.original_bytes_exact);
	assert_eq!(active, original);
	let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let _ = lifecycle::run::<()>(&mut active, &original, &candidate, |_| {
			panic!("injected callback unwind")
		});
	}));
	assert!(unwind.is_err());
	assert_eq!(active, original);
	active[0] ^= 1;
	assert!(lifecycle::run::<()>(&mut active, &original, &candidate, |_| Ok(())).is_err());
}

#[test]
fn full_public_state_contract_keeps_charges_pending_and_last_observation() {
	let p = public();
	let mut s = task::initial(&p).unwrap();
	let original = forward::public_features(&p, &s);
	assert_eq!(original.len(), 43);
	s.charges = 0.2;
	let changed = forward::public_features(&p, &s);
	assert_ne!(original[3], changed[3]);
	assert_eq!(original[0], changed[0]);
	assert_ne!(
		dag::cache_key("law", &p, &task::initial(&p).unwrap(), "cpu6").unwrap(),
		dag::cache_key("law", &p, &s, "cpu6").unwrap()
	);
	assert_ne!(
		dag::cache_key("law", &p, &s, "cpu6").unwrap(),
		dag::cache_key("law", &p, &s, "cpu7").unwrap()
	);
	let mut p2 = p.clone();
	p2.drive[0] = 1;
	assert_ne!(
		dag::cache_key("law", &p, &s, "cpu6").unwrap(),
		dag::cache_key("law", &p2, &s, "cpu6").unwrap()
	);
}

#[test]
fn policy_dp_tracks_candidate_occupancy_and_both_gap_terms() {
	let p = public();
	let s0 = task::initial(&p).unwrap();
	let mut s1 = s0.clone();
	s1.tick = 1;
	s1.elapsed = 1.0;
	let mut edges: Vec<[Vec<dag::Edge>; 6]> = (0..2)
		.map(|_| std::array::from_fn(|_| Vec::new()))
		.collect();
	edges[0][1].push(dag::Edge {
		probability: 1.0,
		target: 1,
		fee: 0.1,
	});
	let g = dag::Graph {
		key: "synthetic".into(),
		public: p,
		states: vec![s0, s1],
		masks: vec![
			[true, true, false, false, true, true],
			[true, false, false, false, true, true],
		],
		posterior: vec![0.5, 0.9],
		edges,
		order: vec![0, 1],
		initial: 0,
		x: vec![],
		hidden: vec![],
		qstar: vec![
			[0.0, 0.7, 0.0, 0.0, 0.0, 0.0],
			[0.0, 0.0, 0.0, 0.0, -0.8, 0.8],
		],
		optimum: vec![0.7, 0.8],
	};
	let result = dag::evaluate_scores(
		&g,
		vec![
			[0.0, 1.0, 0.0, 0.0, 0.0, 0.0],
			[0.0, 0.0, 0.0, 0.0, 1.0, -1.0],
		],
	)
	.unwrap();
	assert!((result.utility + 0.9).abs() < 1e-15);
	assert_eq!(result.occupancy, vec![1.0, 1.0]);
	assert!((result.terminal_gap_contribution - 1.6).abs() < 1e-15);
	assert_eq!(result.continuation_gap_contribution, 0.0);
	assert!(result.pdi_residual.abs() < 1e-15);
	assert!(dag::check_cache(&g, "wrong-law", &g.public, &g.states[0], "cpu6").is_err());
}

#[test]
fn fixed_score_contract_and_lowest_index_ties_are_preserved() {
	let m = model();
	let h = forward::hidden(&m, &[0.0; 85]).unwrap();
	assert_eq!(h.len(), 49);
	let scores = forward::scores(&codec::readout(&m).unwrap(), &h).unwrap();
	assert_eq!(scores, [0.0, 1.0, 0.0, 0.0, 0.0, 0.0]);
	assert_eq!(dag::choose([0.0; 6], [true; 6]), 0);
	assert!(forward::scores(&codec::readout(&m).unwrap(), &[0.0; 48]).is_err());
}
