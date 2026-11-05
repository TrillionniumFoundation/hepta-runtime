// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact L2 budgets for at most 1024 finite F32 before/after pairs.
//!
//! A finite F32 is an integer multiple of 2^-149 with magnitude < 2^277.
//! Its difference therefore has magnitude < 2^278; a sum of at most 2^10
//! squared differences is < 2^566 in units of 2^-298. Nine u64 limbs (576 bits)
//! suffice without rounding. The finite F64 radius is decomposed separately;
//! its square is a <=106-bit integer times a power of two, never a rounded
//! floating-point multiplication. This is feasibility of represented F32 bytes,
//! not an optimality certificate or authentication of their source.

use anyhow::{bail, Result};
use serde::Serialize;
use std::cmp::Ordering;

use super::weight_tensor::{unhex, ExactElementEdit};

const LIMBS: usize = 9;
const MAX_ELEMENTS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Integer([u64; LIMBS]);

impl Integer {
	fn zero() -> Self {
		Self([0; LIMBS])
	}

	fn shifted(value: u64, shift: usize) -> Result<Self> {
		let mut result = Self::zero();
		if value == 0 {
			return Ok(result);
		}
		let word = shift / 64;
		let bit = shift % 64;
		if word >= LIMBS {
			bail!("exact F32 norm integer shift exceeded its proven width");
		}
		result.0[word] = value << bit;
		if bit != 0 {
			let upper = value >> (64 - bit);
			if word + 1 < LIMBS {
				result.0[word + 1] = upper;
			} else if upper != 0 {
				bail!("exact F32 norm integer shift overflow");
			}
		}
		Ok(result)
	}

	fn compare(&self, other: &Self) -> Ordering {
		self.0.iter().rev().cmp(other.0.iter().rev())
	}

	fn add(&mut self, other: &Self) -> Result<()> {
		let mut carry = false;
		for (left, right) in self.0.iter_mut().zip(other.0) {
			let (sum, first) = left.overflowing_add(right);
			let (sum, second) = sum.overflowing_add(u64::from(carry));
			*left = sum;
			carry = first || second;
		}
		if carry {
			bail!("exact F32 norm integer addition overflow");
		}
		Ok(())
	}

	fn subtract(&self, other: &Self) -> Result<Self> {
		let mut result = *self;
		let mut borrow = false;
		for (left, right) in result.0.iter_mut().zip(other.0) {
			let (difference, first) = left.overflowing_sub(right);
			let (difference, second) = difference.overflowing_sub(u64::from(borrow));
			*left = difference;
			borrow = first || second;
		}
		if borrow {
			bail!("exact F32 norm integer subtraction underflow");
		}
		Ok(result)
	}

	fn square(&self) -> Result<Self> {
		let mut result = Self::zero();
		for i in 0..LIMBS {
			let mut carry = 0_u128;
			for j in 0..LIMBS - i {
				// (2^64-1)^2 + two (2^64-1) terms fits exactly in u128.
				let value = u128::from(self.0[i]) * u128::from(self.0[j])
					+ u128::from(result.0[i + j])
					+ carry;
				result.0[i + j] = value as u64;
				carry = value >> 64;
			}
			if carry != 0 || (self.0[i] != 0 && self.0[LIMBS - i..].iter().any(|x| *x != 0)) {
				bail!("exact F32 norm integer square overflow");
			}
		}
		Ok(result)
	}

	fn bits(&self) -> usize {
		self.0
			.iter()
			.rposition(|x| *x != 0)
			.map_or(0, |i| i * 64 + (64 - self.0[i].leading_zeros() as usize))
	}

	fn hex(&self) -> String {
		let text: String = self.0.iter().rev().map(|x| format!("{x:016x}")).collect();
		let text = text.trim_start_matches('0');
		if text.is_empty() {
			"0".into()
		} else {
			text.into()
		}
	}

	fn within_squared_radius(&self, radius: f64) -> Result<bool> {
		if self.bits() == 0 {
			return Ok(true);
		}
		let bits = radius.to_bits();
		let exponent = ((bits >> 52) & 0x7ff) as i32;
		let fraction = bits & ((1_u64 << 52) - 1);
		let (mantissa, exponent) = if exponent == 0 {
			(fraction, -1074)
		} else {
			(fraction | (1_u64 << 52), exponent - 1075)
		};
		let square = u128::from(mantissa) * u128::from(mantissa);
		if square == 0 {
			return Ok(false);
		}
		let shift = 2 * exponent + 298;
		let square_bits = (128 - square.leading_zeros()) as usize;
		if shift >= 0 {
			let shift = shift as usize;
			if square_bits + shift > LIMBS * 64 {
				return Ok(true);
			}
			let mut bound = Self::shifted(square as u64, shift)?;
			bound.add(&Self::shifted((square >> 64) as u64, shift + 64)?)?;
			Ok(self.compare(&bound) != Ordering::Greater)
		} else {
			let left_shift = (-shift) as usize;
			match (self.bits() + left_shift).cmp(&square_bits) {
				Ordering::Less => Ok(true),
				Ordering::Greater => Ok(false),
				Ordering::Equal => {
					// Equality of bit lengths proves both sides fit in <=106 bits.
					let low = u128::from(self.0[0]) | (u128::from(self.0[1]) << 64);
					Ok((low << left_shift) <= square)
				}
			}
		}
	}
}

fn f32_magnitude(value: f32) -> Result<Integer> {
	if !value.is_finite() {
		bail!("exact F32 update budget requires finite original and replacement values");
	}
	let bits = value.to_bits();
	let exponent = ((bits >> 23) & 0xff) as usize;
	let fraction = u64::from(bits & ((1 << 23) - 1));
	if exponent == 0 {
		Integer::shifted(fraction, 0)
	} else {
		Integer::shifted(fraction | (1 << 23), exponent - 1)
	}
}

pub(super) fn validate_radius(radius: f64) -> Result<()> {
	if !radius.is_finite() || radius < 0.0 {
		bail!("maximum update L2 norm must be finite and nonnegative");
	}
	Ok(())
}

#[derive(Debug, Serialize)]
pub(super) struct F32UpdateBudget {
	pub maximum_update_l2_norm: f64,
	pub radius_f64_bits: String,
	pub squared_update_units_hex: String,
	pub squared_update_unit_exponent: i32,
	pub elements_checked: usize,
	pub within_budget: bool,
	pub arithmetic: &'static str,
}

pub(super) fn check_pairs(
	pairs: impl IntoIterator<Item = (f32, f32)>,
	radius: f64,
) -> Result<F32UpdateBudget> {
	validate_radius(radius)?;
	let mut sum = Integer::zero();
	let mut count = 0;
	for (before, after) in pairs {
		count += 1;
		if count > MAX_ELEMENTS {
			bail!("exact F32 update budget supports at most 1024 elements");
		}
		let left = f32_magnitude(before)?;
		let right = f32_magnitude(after)?;
		let difference = if before.is_sign_negative() != after.is_sign_negative() {
			let mut magnitude = left;
			magnitude.add(&right)?;
			magnitude
		} else if left.compare(&right) == Ordering::Less {
			right.subtract(&left)?
		} else {
			left.subtract(&right)?
		};
		sum.add(&difference.square()?)?;
	}
	Ok(F32UpdateBudget {
		maximum_update_l2_norm: radius,
		radius_f64_bits: format!("{:016x}", radius.to_bits()),
		squared_update_units_hex: sum.hex(),
		squared_update_unit_exponent: -298,
		elements_checked: count,
		within_budget: sum.within_squared_radius(radius)?,
		arithmetic: "exact_576_bit_integer_F32_differences_and_exact_F64_radius_square",
	})
}

pub(super) fn check_edits(edits: &[ExactElementEdit], radius: f64) -> Result<F32UpdateBudget> {
	if edits.len() > MAX_ELEMENTS {
		bail!("exact F32 update budget supports at most 1024 elements");
	}
	let pairs = edits
		.iter()
		.map(|edit| {
			let before =
				f32::from_le_bytes(unhex(&edit.expected_hex)?.try_into().map_err(|_| {
					anyhow::anyhow!("update budget requires exactly four F32 bytes per element")
				})?);
			let after =
				f32::from_le_bytes(unhex(&edit.replacement_hex)?.try_into().map_err(|_| {
					anyhow::anyhow!("update budget requires exactly four F32 bytes per element")
				})?);
			Ok((before, after))
		})
		.collect::<Result<Vec<_>>>()?;
	check_pairs(pairs, radius)
}

#[cfg(test)]
#[path = "weight_norm_tests.rs"]
mod tests;
