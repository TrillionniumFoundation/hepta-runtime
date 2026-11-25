// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Local qualification of reopened bias candidates against an authenticated finite law.

use anyhow::{anyhow, bail, Result};
use hepta_continuation_runtime_study::{source::authenticate_source, task::Public};
use hepta_full_native_study::{codec, dag, forward};
use hepta_semantic_source_adapter_study::{
	digest,
	semantics::{verify_profile, ProfilePin},
	unique_json, SourcePin,
};
use hepta_value_intent_study::{exact, readout_sha256, Binding, Edit, Intent, LAYOUT};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(path)?;
	file.write_all(bytes)?;
	file.sync_all()?;
	Ok(())
}

fn invoke(binary: &str, mode: &str, parameters: &[&str], input: &str) -> Result<String> {
	let mut child = Command::new(binary)
		.arg(mode)
		.args(parameters)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()?;
	child
		.stdin
		.take()
		.ok_or_else(|| anyhow!("missing planner stdin"))?
		.write_all(input.as_bytes())?;
	let result = child.wait_with_output()?;
	if !result.status.success() {
		bail!(
			"native policy command rejected input: {}",
			String::from_utf8_lossy(&result.stderr)
		);
	}
	Ok(String::from_utf8(result.stdout)?)
}

fn graph_text(
	graph: &dag::Graph,
	source: &[usize],
	actual: &[usize],
	predicted: &[usize],
) -> String {
	let mut rows = vec![format!(
		"HEPTA_DAG_V1 {} {}",
		graph.states.len(),
		graph.initial
	)];
	for i in 0..graph.states.len() {
		let mask: u8 = graph.masks[i]
			.iter()
			.enumerate()
			.filter(|(_, legal)| **legal)
			.map(|(a, _)| 1 << a)
			.sum();
		let mut row = format!(
			"{} {mask} 0 {:.17e} {:.17e} {} {} {}",
			graph.states[i].tick,
			1. - 2. * graph.posterior[i],
			2. * graph.posterior[i] - 1.,
			source[i],
			actual[i],
			predicted[i]
		);
		for outgoing in graph.edges[i].iter().skip(1).take(3) {
			row.push_str(&format!(" {}", outgoing.len()));
			for edge in outgoing {
				row.push_str(&format!(
					" {:.17e} {} {:.17e}",
					edge.probability, edge.target, edge.fee
				));
			}
		}
		rows.push(row);
	}
	rows.join("\n") + "\n"
}

fn intent(before: &[f64; 196], after: &[f64; 196], binding: &Binding) -> Result<Intent> {
	let norm = exact::check(before, after)?;
	if !norm.within_shared_ball {
		bail!("three-bias proposal exceeds the existing exact shared radius");
	}
	Ok(Intent {
		schema: "hepta.readout196-intent.v1".into(),
		candidate_id: "q-bias-reopened-qualification".into(),
		layout: LAYOUT.into(),
		binding: binding.clone(),
		protocol_sha256: digest(b"q-bias-pool-2-radius-.125-fees-1-1.25"),
		producer_sha256: digest(&std::fs::read(std::env::current_exe()?)?),
		row_mask: 7,
		edits: before
			.iter()
			.zip(after)
			.map(|(old, new)| Edit {
				old_bits: format!("{:016x}", old.to_bits()),
				new_bits: format!("{:016x}", new.to_bits()),
			})
			.collect(),
		expected_readout_sha256: readout_sha256(after),
		delta_squared_units_hex: norm.delta_squared_units_hex,
		anchor_q147_squared_units_hex: norm.anchor_q147_squared_units_hex,
	})
}

fn qualify_pool(
	graph: &dag::Graph,
	model: &Value,
	bridge: &[u8],
	binding: &Binding,
	binary: &str,
	output: &Path,
	inject_first_verifier_error: bool,
) -> Result<Value> {
	let before = codec::readout(model)?;
	let base = dag::evaluate(graph, &before)?;
	let mut input = graph_text(graph, &base.actions, &base.actions, &base.actions);
	input.push_str("HEPTA_Q_SCORES_V1\n");
	for row in &base.scores {
		input.push_str(
			&row.iter()
				.map(|v| format!("{v:.17e}"))
				.collect::<Vec<_>>()
				.join(" "),
		);
		input.push('\n');
	}
	let parameters = ["1", "1.25", ".125", "2"];
	let plan = invoke(binary, "--plan-q-bias-candidates", &parameters, &input)?;
	let lines: Vec<_> = plan.lines().collect();
	let count: usize = lines
		.first()
		.ok_or_else(|| anyhow!("missing plan header"))?
		.split_whitespace()
		.nth(1)
		.ok_or_else(|| anyhow!("missing plan count"))?
		.parse()?;
	if count > 2 || lines.len() != count + 1 {
		bail!("qualified candidate budget differs");
	}
	write_new(&output.join("plan-input.txt"), input.as_bytes())?;
	write_new(&output.join("plan.txt"), plan.as_bytes())?;
	let mut table = format!("HEPTA_Q_REOPENED_V1\n{count}\n");
	let mut receipts = Vec::new();
	let source_sha = digest(bridge);
	let header = u64::from_le_bytes(bridge[..8].try_into()?) as usize + 8;
	let permitted = header + 192 * 8..header + 195 * 8;
	for (id, line) in lines.iter().skip(1).enumerate() {
		let parts: Vec<_> = line.split_whitespace().collect();
		if parts.len() != 7 || parts[0] != "Q_BIAS_CANDIDATE" {
			bail!("unexpected plan member format");
		}
		let shift: f64 = parts[3].parse()?;
		let predicted = parts[6]
			.bytes()
			.map(|c| usize::from(c - b'0'))
			.collect::<Vec<_>>();
		if predicted.len() != graph.states.len() || !shift.is_finite() || shift.abs() > 0.125 {
			bail!("candidate dimensions or radius differ");
		}
		let mut after = before;
		for value in &mut after[192..195] {
			*value += shift;
		}
		let candidate = codec::edit(bridge, &source_sha, &intent(&before, &after, binding)?)?;
		if candidate
			.iter()
			.zip(bridge)
			.enumerate()
			.any(|(i, (a, b))| a != b && !permitted.contains(&i))
		{
			bail!("candidate changed bytes outside the three F64 biases");
		}
		let path = output.join(format!("trial-{}.safetensors", id + 1));
		write_new(&path, &candidate)?;
		let evaluated = (|| -> Result<(String, String, f64)> {
			let reopened = std::fs::read(&path)?;
			if reopened != candidate {
				bail!("reopened candidate bytes differ");
			}
			let current = unique_json(&codec::decode(&reopened)?)?;
			let result = dag::evaluate(graph, &codec::readout(&current)?)?;
			let mut verify_input = graph_text(graph, &base.actions, &result.actions, &predicted);
			if inject_first_verifier_error && id == 0 {
				verify_input.push_str("injected-invalid-trailer\n");
			}
			let verify = invoke(binary, "--verify-q-bias", &["1", "1.25"], &verify_input)?;
			let actions: String = result
				.actions
				.iter()
				.map(|&a| char::from(b'0' + a as u8))
				.collect();
			Ok((actions, verify, result.utility))
		})();
		// The source file is immutable. Every temporary trial is inversely patched
		// and reopened even when forward/verification returned an error.
		let restored = codec::edit(
			&candidate,
			&digest(&candidate),
			&intent(&after, &before, binding)?,
		)?;
		if restored != bridge {
			bail!("inverse byte plan did not restore original");
		}
		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.truncate(true)
			.open(&path)?;
		file.write_all(&restored)?;
		file.sync_all()?;
		drop(file);
		let reopened_restore = std::fs::read(&path)?;
		if reopened_restore != bridge || digest(&reopened_restore) != source_sha {
			bail!("full SHA rollback failed");
		}
		let mut receipt = json!({"id":id+1,"kind":parts[2],"shift":shift,"candidate_sha256":digest(&candidate),
			"parent_sha256":source_sha,"restored_sha256":digest(&reopened_restore),
			"outside_24_bytes_exact":true,"all_original_bytes_restored":true});
		match evaluated {
			Ok((actions, verify, utility)) => {
				table.push_str(&format!("{shift:.17e} {actions}\n"));
				receipt["status"] = json!("EVALUATED");
				receipt["verify"] = json!(verify.trim());
				receipt["actual_nominal_utility"] = json!(utility);
			}
			Err(error) => {
				table.push_str(&format!("{shift:.17e} FAILED\n"));
				receipt["status"] = json!("FAILED");
				receipt["error"] = json!(error.to_string());
			}
		}
		receipts.push(receipt);
	}
	let result = invoke(
		binary,
		"--select-q-bias-candidates",
		&parameters,
		&(input.clone() + &table),
	)?;
	let failed = format!("HEPTA_Q_REOPENED_V1\n{count}\n")
		+ &lines
			.iter()
			.skip(1)
			.map(|line| {
				line.split_whitespace()
					.nth(3)
					.map(|d| format!("{d} FAILED\n"))
					.ok_or_else(|| anyhow!("missing shift"))
			})
			.collect::<Result<Vec<_>>>()?
			.join("");
	let keep = invoke(
		binary,
		"--select-q-bias-candidates",
		&parameters,
		&(input.clone() + &failed),
	)?;
	if !keep.starts_with("Q_BIAS_KEEP 0 ") {
		bail!("all-failed control did not KEEP");
	}
	let malformed_rejected = invoke(
		binary,
		"--select-q-bias-candidates",
		&parameters,
		&(input.clone() + &table + "extra\n"),
	)
	.is_err();
	if !malformed_rejected {
		bail!("malformed verifier table accepted");
	}
	write_new(
		&output.join("reopened-table.txt"),
		(input + &table).as_bytes(),
	)?;
	Ok(
		json!({"schema":"hepta.q-bias-physical-reopening.v1","parent_sha256":source_sha,
		"native_arithmetic":forward::ARITHMETIC,"baseline_utility":base.utility,"candidates":receipts,
		"selection":result.trim(),"all_failed_control":keep.trim(),"malformed_rejected":malformed_rejected,
		"parent_is_immutable":true,"production_adoption":false,"durable_crash_recovery_exercised":false,
			"injected_first_verifier_error":inject_first_verifier_error,
		"scope":"targeted offline engineering qualification; no held-out or model-quality superiority claim"}),
	)
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args().skip(1).collect();
	if args.len() != 3 && !(args.len() == 4 && args[3] == "--inject-first-verifier-error") {
		bail!("usage: q_bias_reopen PRIVATE_INPUT_DIRECTORY NEW_OUTPUT_DIRECTORY POLICY_BINARY [--inject-first-verifier-error]");
	}
	let input = Path::new(&args[0]);
	let output = Path::new(&args[1]);
	let contract_bytes = std::fs::read(input.join("fit_11_evaluation_contract.json"))?;
	if digest(&contract_bytes) != "f46bd7d79f942c4bb87485c21afb15518266b448df52d5d12d496de8d4c013c8"
	{
		bail!("pinned evaluation contract differs");
	}
	let contract = unique_json(&contract_bytes)?;
	let profile_pin: ProfilePin = serde_json::from_value(contract["profile_pin"].clone())?;
	let texts: BTreeMap<String, String> =
		serde_json::from_value(contract["profile_evidence"].clone())?;
	let evidence = texts
		.into_iter()
		.map(|(k, v)| (k, v.into_bytes()))
		.collect();
	let profile = verify_profile(&profile_pin, &evidence)?;
	let compressed_pin: SourcePin =
		serde_json::from_value(contract["task"]["source_model_compressed_pin"].clone())?;
	let decoded_pin: SourcePin =
		serde_json::from_value(contract["task"]["source_model_decoded_pin"].clone())?;
	let compressed = std::fs::read(input.join("fit_11_C.json.gz"))?;
	let source = authenticate_source(&compressed, &compressed_pin, &decoded_pin, &profile)?;
	let bridge = std::fs::read(input.join("original.safetensors"))?;
	if digest(&bridge) != "83f8cbc665bcca76693de68e94eb05fbdf9cb29537e3218879f4ef5579d7920e" {
		bail!("pinned source bridge differs");
	}
	let decoded = codec::decode(&bridge)?;
	decoded_pin.verify(
		&decoded,
		hepta_semantic_source_adapter_study::MAX_JSON_BYTES,
	)?;
	let model = unique_json(&decoded)?;
	let prior_bytes = std::fs::read(input.join("fit11_world000_graph.json"))?;
	if digest(&prior_bytes) != "c5d07bf46657636ca0d52dfb8d0a8a0775795d4f1392058d41d4f7131eb64677" {
		bail!("pinned finite-law graph differs");
	}
	let prior = unique_json(&prior_bytes)?;
	let public: Public = serde_json::from_value(prior["public"].clone())?;
	let graph = dag::build(&source, &model, &public, forward::ARITHMETIC)?;
	if serde_json::to_value(&graph.states)? != prior["states"]
		|| serde_json::to_value(&graph.masks)? != prior["masks"]
		|| serde_json::to_value(&graph.order)? != prior["order"]
	{
		bail!("supplied finite graph structure differs from authenticated source");
	}
	type RetainedEdges = Vec<Vec<Vec<(f64, usize, f64)>>>;
	let prior_edges: RetainedEdges = serde_json::from_value(prior["edges"].clone())?;
	if prior_edges.len() != graph.edges.len() {
		bail!("retained law edge count differs");
	}
	for (native, old) in graph.edges.iter().zip(prior_edges) {
		if old.len() != 3 {
			bail!("retained law action columns differ");
		}
		for (native, old) in native.iter().skip(1).take(3).zip(old) {
			if native.len() != old.len() {
				bail!("retained law branches differ");
			}
			for (native, (probability, target, fee)) in native.iter().zip(old) {
				if native.target != target
					|| native.fee.to_bits() != fee.to_bits()
					|| (native.probability - probability).abs() > 2e-11
				{
					bail!("authenticated native law differs from retained task");
				}
			}
		}
	}
	let result = dag::evaluate(&graph, &codec::readout(&model)?)?;
	let edges: Vec<Vec<Value>> = graph
		.edges
		.iter()
		.map(|row| {
			row.iter()
				.skip(1)
				.take(3)
				.map(|outgoing| {
					json!(outgoing
						.iter()
						.map(|e| (e.probability, e.target, e.fee))
						.collect::<Vec<_>>())
				})
				.collect()
		})
		.collect();
	std::fs::create_dir(output)?;
	std::fs::write(
		output.join("native_graph.json"),
		serde_json::to_vec(&json!({
			"states":graph.states,"masks":graph.masks,"edges":edges,"order":graph.order,
			"initial":graph.initial,"public":graph.public,"posterior":graph.posterior,
			"terminal":graph.posterior.iter().map(|p| [0.,0.,0.,0.,1.-2.*p,2.*p-1.]).collect::<Vec<_>>(),
			"hidden":graph.hidden,"evaluation":result,"graph_key":graph.key,
			"source":source.receipt(),"arithmetic":forward::ARITHMETIC
		}))?,
	)?;
	let receipt = source.receipt();
	let binding = Binding {
		compressed_sha256: receipt.compressed_sha256.clone(),
		decoded_sha256: receipt.decoded_sha256.clone(),
		profile_sha256: receipt.profile_binding_sha256.clone(),
		protected_law_task_sha256: receipt.protected_fields_sha256.clone(),
	};
	let qualification = qualify_pool(
		&graph,
		&model,
		&bridge,
		&binding,
		&args[2],
		output,
		args.len() == 4,
	)?;
	write_new(
		&output.join("receipt.json"),
		&serde_json::to_vec_pretty(&qualification)?,
	)?;
	if std::fs::read(input.join("original.safetensors"))? != bridge {
		bail!("source file changed");
	}
	println!(
		"{}",
		json!({"states":graph.states.len(),"source":source.receipt(),"utility":result.utility,
		"completed_physical_candidates":qualification["candidates"].as_array().map(Vec::len),"parent_preserved":true})
	);
	Ok(())
}
