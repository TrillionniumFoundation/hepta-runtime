// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Numeric adaptation of main weight_norm.rs; this is not an artifact owner.
//! F64 values use integer units 2^-1074. At most 196 squared differences,
//! multiplied by four, are strictly below 2^4208; 66 u64 limbs suffice.

use anyhow::{bail, Result};
use serde::Serialize;
use std::cmp::Ordering;

const LIMBS: usize = 66;
#[derive(Clone, Copy)]
struct Integer([u64; LIMBS]);
impl Integer {
	fn zero() -> Self {
		Self([0; LIMBS])
	}
	fn magnitude(value: f64) -> Result<Self> {
		if !value.is_finite() {
			bail!("exact budget requires finite F64");
		}
		let bits = value.to_bits();
		let exponent = ((bits >> 52) & 0x7ff) as usize;
		let fraction = bits & ((1_u64 << 52) - 1);
		let (mantissa, shift) = if exponent == 0 {
			(fraction, 0)
		} else {
			(fraction | (1_u64 << 52), exponent - 1)
		};
		let mut result = Self::zero();
		let (word, bit) = (shift / 64, shift % 64);
		result.0[word] = mantissa << bit;
		if bit != 0 {
			result.0[word + 1] = mantissa >> (64 - bit);
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
			bail!("exact integer addition overflow");
		}
		Ok(())
	}
	fn subtract(&self, other: &Self) -> Result<Self> {
		let mut result = *self;
		let mut borrow = false;
		for (left, right) in result.0.iter_mut().zip(other.0) {
			let (diff, first) = left.overflowing_sub(right);
			let (diff, second) = diff.overflowing_sub(u64::from(borrow));
			*left = diff;
			borrow = first || second;
		}
		if borrow {
			bail!("exact integer subtraction underflow");
		}
		Ok(result)
	}
	fn square(&self) -> Result<Self> {
		let mut result = Self::zero();
		for i in 0..LIMBS {
			let mut carry = 0_u128;
			for j in 0..LIMBS - i {
				let value = u128::from(self.0[i]) * u128::from(self.0[j])
					+ u128::from(result.0[i + j])
					+ carry;
				result.0[i + j] = value as u64;
				carry = value >> 64;
			}
			if carry != 0 || (self.0[i] != 0 && self.0[LIMBS - i..].iter().any(|x| *x != 0)) {
				bail!("exact integer square overflow");
			}
		}
		Ok(result)
	}
	fn hex(&self) -> String {
		let text: String = self.0.iter().rev().map(|x| format!("{x:016x}")).collect();
		let trimmed = text.trim_start_matches('0');
		if trimmed.is_empty() {
			"0".into()
		} else {
			trimmed.into()
		}
	}
}

#[derive(Debug, Serialize)]
pub struct NormReceipt {
	pub delta_squared_units_hex: String,
	pub anchor_q147_squared_units_hex: String,
	pub unit_exponent: i32,
	pub within_shared_ball: bool,
}

pub fn check(before: &[f64; 196], after: &[f64; 196]) -> Result<NormReceipt> {
	let mut delta = Integer::zero();
	let mut radius_base = Integer::zero();
	for (i, (old, new)) in before.iter().zip(after).enumerate() {
		let left = Integer::magnitude(*old)?;
		let right = Integer::magnitude(*new)?;
		let difference = if old.is_sign_negative() != new.is_sign_negative() {
			let mut sum = left;
			sum.add(&right)?;
			sum
		} else if left.compare(&right) == Ordering::Less {
			right.subtract(&left)?
		} else {
			left.subtract(&right)?
		};
		delta.add(&difference.square()?)?;
		if i < 144 || (192..195).contains(&i) {
			radius_base.add(&left.square()?)?;
		}
	}
	let mut doubled = delta;
	doubled.add(&delta)?;
	let mut quadrupled = doubled;
	quadrupled.add(&doubled)?;
	Ok(NormReceipt {
		delta_squared_units_hex: delta.hex(),
		anchor_q147_squared_units_hex: radius_base.hex(),
		unit_exponent: -2148,
		within_shared_ball: quadrupled.compare(&radius_base) != Ordering::Greater,
	})
}
