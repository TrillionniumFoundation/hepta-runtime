// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact finite-F32 protection rank: a nonzero native integer minor rules out a
//! nonzero exactly preserving real-linear contrast edit. No SVD or model runs.

use anyhow::{bail, ensure, Context, Result};
use num_bigint::{BigInt, Sign};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

use super::rea_model::digest_hex;

const PRIME: u64 = 2_305_843_009_213_693_951;
const MAX_ROWS: usize = 128;
const MAX_COLUMNS: usize = 32;
const MAX_WORK: u64 = 1_000_000;
const MAX_INTEGER_BITS: u64 = 32_768;
const MAX_TIME: Duration = Duration::from_secs(5);

/// Explicit IEEE binary32 bytes and their expected identity. No supplied rank
/// certificate is accepted; every emitted proof is generated from these bytes.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactRankParams {
	pub rows: usize,
	pub columns: usize,
	pub f32_le_hex: String,
	pub expected_raw_sha256: String,
	#[serde(default)]
	pub source_declaration: Option<String>,
}

struct Budget {
	deadline: Instant,
	used: u64,
	limit: u64,
}
impl Budget {
	fn spend(&mut self, count: u64) -> Result<()> {
		ensure!(
			Instant::now() < self.deadline,
			"exact rank deadline exceeded"
		);
		self.used = self
			.used
			.checked_add(count)
			.context("exact rank work overflow")?;
		ensure!(self.used <= self.limit, "exact rank work limit exceeded");
		Ok(())
	}
}
fn sha(bytes: &[u8]) -> String {
	digest_hex(&Sha256::digest(bytes))
}
fn nibble(byte: u8) -> Result<u8> {
	match byte {
		b'0'..=b'9' => Ok(byte - b'0'),
		b'a'..=b'f' => Ok(byte - b'a' + 10),
		b'A'..=b'F' => Ok(byte - b'A' + 10),
		_ => bail!("matrix hex contains a non-hex character"),
	}
}
fn decode(params: &ExactRankParams, budget: &mut Budget) -> Result<Vec<u8>> {
	budget.spend(1)?;
	ensure!(
		(1..=MAX_ROWS).contains(&params.rows) && (1..=MAX_COLUMNS).contains(&params.columns),
		"exact rank dimensions outside bounded profile"
	);
	let bytes = params.rows * params.columns * 4;
	ensure!(
		params.f32_le_hex.len() == bytes * 2,
		"matrix hex length differs from its shape"
	);
	ensure!(
		params.expected_raw_sha256.len() == 64
			&& params
				.expected_raw_sha256
				.bytes()
				.all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x)),
		"expected matrix SHA256 must be lowercase hex"
	);
	ensure!(
		params
			.source_declaration
			.as_ref()
			.is_none_or(|value| value.len() <= 4096),
		"source declaration exceeds bound"
	);
	let raw = params
		.f32_le_hex
		.as_bytes()
		.chunks_exact(2)
		.map(|word| Ok((nibble(word[0])? << 4) | nibble(word[1])?))
		.collect::<Result<Vec<_>>>()?;
	budget.spend(bytes as u64)?;
	ensure!(
		sha(&raw) == params.expected_raw_sha256,
		"matrix byte identity mismatch"
	);
	Ok(raw)
}
fn dyadic(word: u32) -> Result<(i64, i32)> {
	let exponent = (word >> 23) & 255;
	let fraction = word & 0x7f_ffff;
	ensure!(
		exponent != 255,
		"NaN and infinity are not finite dyadic coefficients"
	);
	let (mut mantissa, mut power) = if exponent == 0 {
		(fraction, -149)
	} else {
		((1 << 23) | fraction, exponent as i32 - 150)
	};
	if mantissa == 0 {
		return Ok((0, 0));
	}
	let trailing = mantissa.trailing_zeros();
	mantissa >>= trailing;
	power += trailing as i32;
	let signed = if word >> 31 == 0 {
		i64::from(mantissa)
	} else {
		-i64::from(mantissa)
	};
	Ok((signed, power))
}
fn integer_matrix(
	raw: &[u8],
	columns: usize,
	budget: &mut Budget,
) -> Result<(u32, Vec<Vec<BigInt>>)> {
	let values = raw
		.chunks_exact(4)
		.map(|word| {
			dyadic(u32::from_le_bytes(
				word.try_into().context("binary32 word length")?,
			))
		})
		.collect::<Result<Vec<_>>>()?;
	let exponent = values
		.iter()
		.map(|(_, power)| (-*power).max(0) as u32)
		.max()
		.context("empty dyadic matrix")?;
	ensure!(exponent <= 149, "binary32 denominator exponent bound");
	let mut integers = Vec::with_capacity(values.len());
	for (mantissa, power) in values {
		budget.spend(1)?;
		let shift = usize::try_from(power + exponent as i32)
			.context("non-integral common dyadic scaling")?;
		integers.push(BigInt::from(mantissa) << shift);
	}
	Ok((
		exponent,
		integers
			.chunks_exact(columns)
			.map(<[BigInt]>::to_vec)
			.collect(),
	))
}
fn residue(value: &BigInt) -> Result<u64> {
	let modulus = BigInt::from(PRIME);
	let mut reduced = value % &modulus;
	if reduced.sign() == Sign::Minus {
		reduced += modulus;
	}
	match reduced.to_u64_digits().1.as_slice() {
		[] => Ok(0),
		[value] if *value < PRIME => Ok(*value),
		_ => bail!("integer residue exceeds fixed field"),
	}
}
fn multiply_mod(a: u64, b: u64) -> u64 {
	((u128::from(a) * u128::from(b)) % u128::from(PRIME)) as u64
}
fn inverse_mod(value: u64, budget: &mut Budget) -> Result<u64> {
	ensure!(value != 0, "zero modular pivot");
	budget.spend(128)?;
	let (mut base, mut exponent, mut out) = (value, PRIME - 2, 1);
	while exponent != 0 {
		if exponent & 1 == 1 {
			out = multiply_mod(out, base);
		}
		base = multiply_mod(base, base);
		exponent >>= 1;
	}
	ensure!(
		multiply_mod(value, out) == 1,
		"modular inverse verification"
	);
	Ok(out)
}
fn pivot_rows(matrix: &[Vec<BigInt>], columns: usize, budget: &mut Budget) -> Result<Vec<usize>> {
	let mut a = matrix
		.iter()
		.map(|row| row.iter().map(residue).collect())
		.collect::<Result<Vec<Vec<_>>>>()?;
	let mut identifiers: Vec<_> = (0..a.len()).collect();
	let mut selected = Vec::new();
	for column in 0..columns {
		budget.spend(1)?;
		let rank = selected.len();
		let Some(pivot) = (rank..a.len()).find(|i| a[*i][column] != 0) else {
			continue;
		};
		a.swap(rank, pivot);
		identifiers.swap(rank, pivot);
		selected.push(identifiers[rank]);
		let row = a[rank].clone();
		let inverse = inverse_mod(row[column], budget)?;
		for values in a.iter_mut().skip(rank + 1) {
			let factor = multiply_mod(values[column], inverse);
			for (j, value) in values.iter_mut().enumerate().skip(column) {
				budget.spend(1)?;
				*value = (*value + PRIME - multiply_mod(factor, row[j])) % PRIME;
			}
		}
	}
	Ok(selected)
}
fn bareiss(matrix: &[Vec<BigInt>], budget: &mut Budget) -> Result<BigInt> {
	let mut a = matrix.to_vec();
	let n = a.len();
	let mut previous = BigInt::from(1);
	let mut sign = 1i32;
	for k in 0..n - 1 {
		budget.spend(1)?;
		let pivot = (k..n)
			.find(|i| a[*i][k] != BigInt::from(0))
			.context("exact selected minor is singular")?;
		if pivot != k {
			a.swap(k, pivot);
			sign = -sign;
		}
		let current = a[k][k].clone();
		for i in k + 1..n {
			for j in k + 1..n {
				budget.spend(1)?;
				let numerator = &a[i][j] * &current - &a[i][k] * &a[k][j];
				ensure!(
					numerator.bits() <= MAX_INTEGER_BITS,
					"exact determinant integer work bound"
				);
				ensure!(
					&numerator % &previous == BigInt::from(0),
					"Bareiss division is not exact"
				);
				a[i][j] = numerator / &previous;
			}
			a[i][k] = BigInt::from(0);
		}
		previous = current;
	}
	Ok(&a[n - 1][n - 1] * sign)
}
fn minor_modulus(matrix: &[Vec<BigInt>], budget: &mut Budget) -> Result<u64> {
	let mut a = matrix
		.iter()
		.map(|row| row.iter().map(residue).collect())
		.collect::<Result<Vec<Vec<_>>>>()?;
	let mut determinant = 1;
	for k in 0..a.len() {
		budget.spend(1)?;
		let pivot = (k..a.len())
			.find(|i| a[*i][k] != 0)
			.context("modular selected minor is singular")?;
		if pivot != k {
			a.swap(k, pivot);
			determinant = (PRIME - determinant) % PRIME;
		}
		let row = a[k].clone();
		determinant = multiply_mod(determinant, row[k]);
		let inverse = inverse_mod(row[k], budget)?;
		for values in a.iter_mut().skip(k + 1) {
			let factor = multiply_mod(values[k], inverse);
			for (j, value) in values.iter_mut().enumerate().skip(k) {
				budget.spend(1)?;
				*value = (*value + PRIME - multiply_mod(factor, row[j])) % PRIME;
			}
		}
	}
	Ok(determinant)
}
fn evaluate_inner(params: ExactRankParams, budget: &mut Budget) -> Result<Value> {
	let raw = decode(&params, budget)?;
	let (exponent, matrix) = integer_matrix(&raw, params.columns, budget)?;
	let rows = pivot_rows(&matrix, params.columns, budget)?;
	let full = rows.len() == params.columns;
	let proof = if full {
		let minor: Vec<_> = rows.iter().map(|i| matrix[*i].clone()).collect();
		let determinant = bareiss(&minor, budget)?;
		let modular = minor_modulus(&minor, budget)?;
		ensure!(
			determinant != BigInt::from(0) && modular != 0 && residue(&determinant)? == modular,
			"exact and modular determinant proofs disagree"
		);
		Some(
			json!({"pivot_original_rows":rows,"pivot_original_columns":(0..params.columns).collect::<Vec<_>>(),
			"common_denominator_power_of_two":exponent,"exact_integer_minor_determinant":determinant.to_string(),
			"rational_minor_denominator_power_of_two":exponent as usize*params.columns,
			"fixed_prime":PRIME.to_string(),"minor_determinant_mod_prime":modular.to_string(),
			"bareiss_divisions_exact":true,"independent_modular_determinant_agrees":true}),
		)
	} else {
		None
	};
	budget.spend(1)?;
	Ok(
		json!({"schema":"hepta.weight.exact-protection-rank.v1","status":if full {"EXACT_FULL_COLUMN_RANK"} else {"UNKNOWN"},
		"reason":if full {"nonzero native exact integer minor"} else {"fixed-prime lower bound does not prove full rank; no rank-deficiency claim"},
		"input_raw_sha256":sha(&raw),"rows":params.rows,"columns":params.columns,
		"modular_rank_lower_bound":rows.len(),"exact_rank":if full {Some(params.columns)} else {None},
		"exact_nullity":if full {Some(0)} else {None},"only_zero_exact_preserving_contrast":if full {Some(true)} else {None},
		"proof":proof,"proof_origin":"computed natively from admitted input bytes",
		"source_declaration":params.source_declaration,"source_declaration_independently_verified":false,
		"work_units":budget.used,"work_limit":budget.limit,"model_forward_calls":0,"fit_or_gradient_steps":0,
		"scope":"exact real-linear C*delta=0 on frozen F32 coefficients with fixed coordinate/bias policy; not F32 output-rounding plateaus, approximate protection, unseen inputs or nonlinear rollout"}),
	)
}
/// Compute a bounded native proof; a deficient modular result stays UNKNOWN.
pub fn evaluate(params: ExactRankParams) -> Result<Value> {
	evaluate_with_deadline(params, Instant::now() + MAX_TIME)
}
/// Share an enclosing planner's deadline while retaining the local five-second cap.
pub fn evaluate_with_deadline(params: ExactRankParams, deadline: Instant) -> Result<Value> {
	let mut budget = Budget {
		deadline: deadline.min(Instant::now() + MAX_TIME),
		used: 0,
		limit: MAX_WORK,
	};
	evaluate_inner(params, &mut budget)
}

#[cfg(test)]
#[path = "weight_exact_rank_tests.rs"]
mod tests;
