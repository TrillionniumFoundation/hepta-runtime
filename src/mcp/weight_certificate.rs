// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Read-only, content-bound proof of a fixed TRAIN continuation subproblem.
//!
//! The checkpoint bytes provide C; supplied witness rows provide A and y.
//! Digest checks bind their exact bytes but do not authenticate the caller,
//! recompute hidden features, or authenticate Bellman labels to the original
//! program. A proof excludes copying these weak pairwise orderings in the
//! original ||delta||^2 <= ||C||^2/4 ball. It says nothing about task value,
//! useful partial repairs, a larger budget, or a different representation.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[path = "weight_certificate_exact.rs"]
mod exact;

const SEMANTICS: &str = "binary64_rne_gradual_separate_products_sum49_v1";
const MAX_ROWS: usize = 8192;
const MAX_MODEL_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 512 * 1024;
static VERIFIERS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateParams {
	/// Exact declaration required; the verifier does not probe hardware semantics.
	pub semantics: String,
	/// Original, declared joint-policy-v1 JSON, at most 1 MiB. The first three
	/// affine output rows and biases are the center; no replacement center input.
	pub checkpoint_json: String,
	/// SHA256 of the exact UTF-8 checkpoint_json bytes, supplied by the caller.
	pub expected_checkpoint_sha256: String,
	/// Digest of the documented binary witness encoding, checked independently.
	pub expected_witness_sha256: String,
	pub source: CertificateSource,
	/// Complete supplied witness, at most 8192 rows and 8 MiB canonical request.
	pub rows: Vec<CertificateRow>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateSource {
	pub fit_id: u32,
	pub protocol_sha256: String,
	pub feature_source_sha256: String,
	pub teacher_source_sha256: String,
	/// Binds the upstream record identity; that record is not read by this tool.
	pub original_witness_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateRow {
	pub source_row: u32,
	pub state_sha256: String,
	pub teacher_table_sha256: String,
	/// Exactly 49 little-endian F64 values as 784 lowercase hex characters.
	/// Coordinates must be finite, bounded by one, with an exact final +1 bias.
	pub hidden_f64_le_hex: String,
	pub hidden_sha256: String,
	/// One finite, nonnegative little-endian F64; zero supplies no separation.
	pub multiplier_f64_le_hex: String,
	/// Six finite supplied scores. Selection must be the first legal maximum.
	pub teacher_q_f64_le_hex: String,
	pub legal: [bool; 6],
	/// Fixed action IDs: 1 WAIT, 2 READ, 3 REPAIR.
	pub target_action: u8,
	pub competitor_action: u8,
}

#[derive(Deserialize)]
struct Checkpoint {
	schema: String,
	family: String,
	fit: u32,
	head_dimensions: [usize; 3],
	network: Network,
}

#[derive(Deserialize)]
struct Network {
	w2: Vec<Vec<f64>>,
	b2: Vec<f64>,
}

fn hex(data: impl AsRef<[u8]>) -> String {
	data.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn bytes(text: &str, count: usize) -> Result<Vec<u8>> {
	if text.len() != 2 * count
		|| !text
			.bytes()
			.all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
	{
		bail!(
			"certificate hex must be lowercase and have exactly {} bytes",
			count
		);
	}
	text.as_bytes()
		.chunks_exact(2)
		.map(|x| {
			let nibble = |v: u8| if v <= b'9' { v - b'0' } else { v - b'a' + 10 };
			Ok((nibble(x[0]) << 4) | nibble(x[1]))
		})
		.collect()
}

fn digest(text: &str) -> Result<()> {
	bytes(text, 32).map(|_| ())
}

fn f64_bits(data: &[u8]) -> Result<Vec<u64>> {
	data.chunks_exact(8)
		.map(|v| {
			let raw: [u8; 8] = v
				.try_into()
				.map_err(|_| anyhow!("invalid F64 byte width"))?;
			let bits = u64::from_le_bytes(raw);
			if !f64::from_bits(bits).is_finite() {
				bail!("certificate requires finite binary64 encodings");
			}
			Ok(bits)
		})
		.collect()
}

fn deadline(end: Instant) -> Result<()> {
	if Instant::now() >= end {
		bail!("certificate exceeded its 30-second cooperative compute deadline");
	}
	Ok(())
}

struct Commitment {
	hash: Sha256,
	bytes: usize,
	end: Instant,
}

impl Write for Commitment {
	fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
		if data.len() > MAX_REQUEST_BYTES.saturating_sub(self.bytes) || Instant::now() >= self.end {
			return Err(std::io::Error::other(
				"certificate request byte/deadline budget exceeded",
			));
		}
		self.hash.update(data);
		self.bytes += data.len();
		Ok(data.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

fn validate(params: &CertificateParams, end: Instant) -> Result<(Vec<u64>, String, usize)> {
	if params.semantics != SEMANTICS {
		bail!("certificate requires the fixed binary64 arithmetic declaration");
	}
	if params.checkpoint_json.is_empty() || params.checkpoint_json.len() > MAX_MODEL_BYTES {
		bail!("certificate checkpoint must contain 1..1048576 UTF-8 bytes");
	}
	if !(1..=MAX_ROWS).contains(&params.rows.len()) {
		bail!("certificate requires 1..8192 supplied witness rows");
	}
	for value in [
		&params.expected_checkpoint_sha256,
		&params.expected_witness_sha256,
		&params.source.protocol_sha256,
		&params.source.feature_source_sha256,
		&params.source.teacher_source_sha256,
		&params.source.original_witness_record_sha256,
	] {
		digest(value)?;
	}
	if hex(Sha256::digest(params.checkpoint_json.as_bytes())) != params.expected_checkpoint_sha256 {
		bail!("certificate checkpoint SHA256 mismatch");
	}
	let mut commitment = Commitment {
		hash: Sha256::new(),
		bytes: 0,
		end,
	};
	serde_json::to_writer(&mut commitment, params)?;
	let checkpoint: Checkpoint = serde_json::from_str(&params.checkpoint_json)
		.context("certificate checkpoint parsing failed")?;
	if checkpoint.schema != "joint-policy-v1"
		|| checkpoint.family != "renewal"
		|| checkpoint.fit != params.source.fit_id
		|| checkpoint.head_dimensions != [85, 48, 4]
		|| checkpoint.network.w2.len() != 4
		|| checkpoint.network.b2.len() != 4
		|| checkpoint.network.w2.iter().any(|x| x.len() != 48)
		|| checkpoint
			.network
			.w2
			.iter()
			.flatten()
			.chain(&checkpoint.network.b2)
			.any(|x| !x.is_finite())
	{
		bail!("certificate requires matching renewal 85/48/4 metadata and a finite output head");
	}
	let mut center = Vec::with_capacity(147);
	for action in 0..3 {
		center.extend(checkpoint.network.w2[action].iter().map(|x| x.to_bits()));
		center.push(checkpoint.network.b2[action].to_bits());
	}
	deadline(end)?;
	Ok((center, hex(commitment.hash.finalize()), commitment.bytes))
}

fn solve(params: &CertificateParams) -> Result<Value> {
	let started = Instant::now();
	let end = started + Duration::from_secs(30);
	let (center, request_sha256, request_bytes) = validate(params, end)?;
	let center_bytes: Vec<u8> = center.iter().flat_map(|x| x.to_le_bytes()).collect();
	let mut arithmetic = exact::Arithmetic::new(&center)?;
	let mut witness = Sha256::new();
	witness.update(b"hepta.weight.continuation-witness.v1\0");
	witness.update((params.rows.len() as u64).to_le_bytes());
	let mut ids = HashSet::new();
	let mut source_rows = HashMap::new();
	for row in &params.rows {
		deadline(end)?;
		if !ids.insert((row.source_row, row.target_action, row.competitor_action)) {
			bail!("certificate repeats a source-row/action comparison identity");
		}
		let state = bytes(&row.state_sha256, 32)?;
		let table = bytes(&row.teacher_table_sha256, 32)?;
		let hidden = bytes(&row.hidden_f64_le_hex, 49 * 8)?;
		digest(&row.hidden_sha256)?;
		if hex(Sha256::digest(&hidden)) != row.hidden_sha256 {
			bail!("certificate hidden bytes SHA256 mismatch");
		}
		let multiplier = bytes(&row.multiplier_f64_le_hex, 8)?;
		let scores = bytes(&row.teacher_q_f64_le_hex, 6 * 8)?;
		let q = f64_bits(&scores)?;
		let mut best: Option<usize> = None;
		for action in 0..6 {
			if row.legal[action]
				&& best.is_none_or(|old| f64::from_bits(q[action]) > f64::from_bits(q[old]))
			{
				best = Some(action);
			}
		}
		if !(1..=3).contains(&row.target_action)
			|| !(1..=3).contains(&row.competitor_action)
			|| row.target_action == row.competitor_action
			|| best != Some(row.target_action as usize)
			|| !row.legal[row.competitor_action as usize]
		{
			bail!(
				"certificate needs distinct legal continuations and the supplied first-max target"
			);
		}
		let mut row_identity = Sha256::new();
		row_identity.update(&state);
		row_identity.update(&table);
		row_identity.update(&hidden);
		row_identity.update(&scores);
		row_identity.update(row.legal.map(u8::from));
		row_identity.update([row.target_action]);
		let row_identity = hex(row_identity.finalize());
		if source_rows
			.insert(row.source_row, row_identity.clone())
			.is_some_and(|old| old != row_identity)
		{
			bail!(
				"certificate source row has conflicting feature, state, table or target identities"
			);
		}
		let hidden_bits = f64_bits(&hidden)?;
		let y = f64_bits(&multiplier)?;
		arithmetic.add(
			row.target_action as usize,
			row.competitor_action as usize,
			&hidden_bits,
			y[0],
		)?;
		witness.update(row.source_row.to_le_bytes());
		witness.update(state);
		witness.update(table);
		witness.update(row.legal.map(u8::from));
		witness.update([row.target_action, row.competitor_action]);
		witness.update(multiplier);
		witness.update(hidden);
		witness.update(scores);
	}
	let witness_sha256 = hex(witness.finalize());
	if witness_sha256 != params.expected_witness_sha256 {
		bail!("certificate binary witness SHA256 mismatch");
	}
	deadline(end)?;
	let proof = arithmetic.finish();
	deadline(end)?;
	let implementation = hex(Sha256::digest(include_bytes!("weight_certificate.rs")));
	let arithmetic_source = hex(Sha256::digest(include_bytes!(
		"weight_certificate_exact.rs"
	)));
	Ok(json!({
		"schema":"hepta.weight.continuation-certificate.v1", "semantics":SEMANTICS,
		"request_sha256":request_sha256, "canonical_request_bytes":request_bytes,
		"checkpoint_sha256":params.expected_checkpoint_sha256, "witness_sha256":witness_sha256,
		"source":params.source, "implementation_source_sha256":implementation,
		"arithmetic_source_sha256":arithmetic_source, "witness_rows":params.rows.len(),
		"center_coefficients":147, "hidden_width_including_bias":49,
		"center_f64_le_hex":hex(&center_bytes), "center_f64_le_sha256":hex(Sha256::digest(&center_bytes)),
		"budget":"sum(delta_Q^2) <= exact sum(stored_C_Q^2)/4",
		"arithmetic":"exact bounded binary64 integer units; roundoff denominator 2^53-98",
		"proof":proof, "native_operation_wall_seconds":started.elapsed().as_secs_f64(),
		"byte_budget":MAX_REQUEST_BYTES, "row_budget":MAX_ROWS,
		"cooperative_deadline_seconds":30, "maximum_concurrent_workers":2,
		"checkpoint_bytes_and_head_extraction_verified":true,
		"witness_hidden_bytes_and_supplied_first_max_checked":true,
		"caller_supplied_digests_are_trust_roots":false,
		"external_source_authentication":false, "hidden_or_teacher_program_reexecuted":false,
		"hardware_arithmetic_semantics_verified":false,
		"independent_holdout_verified":false, "task_value_improvement_qualified":false,
		"whole_network_impossibility_qualified":false, "production_eligible":false,
		"weights_modified":false, "gradient_steps":0,
		"scope":"only the supplied fixed-representation continuation ordering system and declared coefficient ball; exact bytes are bound to caller-supplied digests, not authenticated signatures; no source-semantic replay, neural training, task-value proof, installation or whole-network claim",
	}))
}

pub async fn verify(params: CertificateParams) -> Result<String> {
	let permit = VERIFIERS
		.get_or_init(|| Arc::new(Semaphore::new(2)))
		.clone()
		.try_acquire_owned()
		.map_err(|_| anyhow!("native certificate capacity exhausted; no work admitted"))?;
	tokio::task::spawn_blocking(move || {
		// The permit stays with the worker if its asynchronous caller is cancelled.
		let _permit = permit;
		let result =
			serde_json::to_string(&solve(&params)?).context("serializing native certificate")?;
		if result.len() > MAX_RESULT_BYTES {
			bail!("certificate result byte budget exceeded");
		}
		Ok(result)
	})
	.await
	.context("native certificate worker failed")?
}

#[cfg(test)]
#[path = "weight_certificate_tests.rs"]
mod tests;
