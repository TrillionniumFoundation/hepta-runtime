// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact integer algebra for the fixed binary64 continuation certificate.
//!
//! Each finite binary64 is an integer in units of 2^-1074. Consequently v,
//! d, ||C||^2 and ||v||^2 have fixed units; comparisons need only integer
//! products and shifts. The roundoff relaxation has the sole additional
//! denominator 2^53-98. No float product, norm, division or tolerance enters
//! a verdict. Input size and finite encodings are bounded by the caller.

use anyhow::{bail, Result};
use num_bigint::{BigInt, BigUint, Sign};
use serde_json::{json, Value};

const UNIT: usize = 1074;
const HEAD: usize = 49;
const HEADS: usize = 3;

/// Interpret supplied bits exactly; negative zero remains zero in the algebra.
pub(super) fn units(bits: u64) -> Result<BigInt> {
	let exponent = ((bits >> 52) & 0x7ff) as usize;
	if exponent == 0x7ff {
		bail!("certificate requires finite binary64 encodings");
	}
	let fraction = bits & ((1_u64 << 52) - 1);
	let magnitude = if exponent == 0 {
		BigUint::from(fraction)
	} else {
		BigUint::from(fraction | (1_u64 << 52)) << (exponent - 1)
	};
	Ok(BigInt::from_biguint(
		if bits >> 63 == 0 {
			Sign::Plus
		} else {
			Sign::Minus
		},
		magnitude,
	))
}

fn exact(value: &BigInt, exponent: i32, denominator: &BigUint) -> Value {
	let trailing = value.magnitude().trailing_zeros().unwrap_or(0) as usize;
	json!({
		"numerator_hex": (value >> trailing).to_str_radix(16),
		"binary_exponent": exponent + trailing as i32,
		"denominator_hex": denominator.to_str_radix(16),
	})
}

fn dyadic(value: &BigInt, exponent: i32) -> Value {
	exact(value, exponent, &BigUint::from(1_u8))
}

/// ceil(sqrt(||C||^2 / 2^2150)), computed with integer Newton and one exact test.
fn radius_upper(norm: &BigUint) -> BigUint {
	let n = norm >> (2 * UNIT + 2);
	let mut root = if n == BigUint::from(0_u8) {
		BigUint::from(0_u8)
	} else {
		let mut x = BigUint::from(1_u8) << n.bits().div_ceil(2) as usize;
		loop {
			let next = (&x + &n / &x) >> 1_usize;
			if next >= x {
				break x;
			}
			x = next;
		}
	};
	if (&root * &root) << (2 * UNIT + 2) < *norm {
		root += 1_u8;
	}
	root
}

pub(super) struct Arithmetic {
	center: Vec<BigInt>,
	center_norm: BigUint,
	radius_upper: BigUint,
	denominator: BigUint,
	error_numerators: Vec<BigUint>,
	dual: Vec<BigInt>,
	weighted_error: BigUint,
	pub nonzero_rows: usize,
}

impl Arithmetic {
	pub(super) fn new(center_bits: &[u64]) -> Result<Self> {
		if center_bits.len() != HEADS * HEAD {
			bail!("certificate center must contain exactly 147 coefficients");
		}
		let center = center_bits
			.iter()
			.map(|x| units(*x))
			.collect::<Result<Vec<_>>>()?;
		let center_norm = center.iter().fold(BigUint::from(0_u8), |sum, x| {
			sum + x.magnitude() * x.magnitude()
		});
		let radius_upper = radius_upper(&center_norm);
		let max_center = center
			.iter()
			.map(BigInt::magnitude)
			.max()
			.cloned()
			.unwrap_or_default();
		// This uniform bound also covers every coefficient displacement in the ball.
		if (max_center + (&radius_upper << UNIT)) * HEAD >= BigUint::from(1_u8) << (1000 + UNIT) {
			bail!("certificate center violates the uniform 2^1000 no-overflow guard");
		}
		let denominator = (BigUint::from(1_u8) << 53_usize) - 98_u8;
		let error_numerators = center
			.chunks_exact(HEAD)
			.map(|head| {
				let sum = head
					.iter()
					.fold(BigUint::from(0_u8), |sum, x| sum + x.magnitude());
				// E_j = 98*(sum|C_units| + 49*Ru*2^1074 + 2^53)/(D*2^1074).
				(sum + ((&radius_upper * HEAD) << UNIT) + (BigUint::from(1_u8) << 53_usize)) * 98_u8
			})
			.collect();
		Ok(Self {
			center,
			center_norm,
			radius_upper,
			denominator,
			error_numerators,
			dual: vec![BigInt::from(0_u8); HEADS * HEAD],
			weighted_error: BigUint::from(0_u8),
			nonzero_rows: 0,
		})
	}

	pub(super) fn add(
		&mut self,
		target: usize,
		competitor: usize,
		hidden: &[u64],
		multiplier: u64,
	) -> Result<()> {
		if !(1..=HEADS).contains(&target)
			|| !(1..=HEADS).contains(&competitor)
			|| target == competitor
		{
			bail!("certificate comparison needs distinct WAIT/READ/REPAIR actions");
		}
		if hidden.len() != HEAD || hidden[HEAD - 1] != 1.0_f64.to_bits() {
			bail!("certificate hidden row needs 48 coordinates and an exact +1 bias");
		}
		let y = units(multiplier)?;
		if y.sign() == Sign::Minus {
			bail!("certificate multiplier must be nonnegative");
		}
		let one = BigUint::from(1_u8) << UNIT;
		let a = target - 1;
		let b = competitor - 1;
		for (index, bits) in hidden.iter().enumerate() {
			let h = units(*bits)?;
			if h.magnitude() > &one {
				bail!("certificate hidden coordinates must have absolute value at most one");
			}
			let value = &y * h;
			self.dual[a * HEAD + index] += &value;
			self.dual[b * HEAD + index] -= value;
		}
		self.weighted_error +=
			y.magnitude() * (&self.error_numerators[a] + &self.error_numerators[b]);
		self.nonzero_rows += usize::from(y.sign() != Sign::NoSign);
		Ok(())
	}

	pub(super) fn finish(self) -> Value {
		let d = -self
			.dual
			.iter()
			.zip(&self.center)
			.fold(BigInt::from(0_u8), |sum, (v, c)| sum + v * c);
		let dual_norm = self.dual.iter().fold(BigUint::from(0_u8), |sum, v| {
			sum + v.magnitude() * v.magnitude()
		});
		let right = &self.center_norm * &dual_norm;
		let relaxed_d = &d * BigInt::from(self.denominator.clone())
			- BigInt::from(&self.weighted_error << UNIT);
		let denominator_squared = &self.denominator * &self.denominator;
		let ideal = d.sign() == Sign::Plus && (d.magnitude() * d.magnitude()) << 2_usize > right;
		let relaxed = relaxed_d.sign() == Sign::Plus
			&& (relaxed_d.magnitude() * relaxed_d.magnitude()) << 2_usize
				> &right * &denominator_squared;
		let verdict = if relaxed {
			"F64_NECESSARY_SYSTEM_INFEASIBLE"
		} else if ideal {
			"IDEAL_REAL_ONLY_INFEASIBLE"
		} else {
			"NOT_CERTIFIED"
		};
		json!({
			"verdict": verdict,
			"radius_squared": dyadic(&BigInt::from(self.center_norm), -2150),
			"radius_upper": dyadic(&BigInt::from(self.radius_upper), 0),
			"dual_vector": self.dual.iter().map(|x|dyadic(x,-2148)).collect::<Vec<_>>(),
			"dual_vector_squared_norm": dyadic(&BigInt::from(dual_norm), -4296),
			"per_head_f64_absolute_error_bound": self.error_numerators.iter().map(|x|exact(&BigInt::from(x.clone()),-1074,&self.denominator)).collect::<Vec<_>>(),
			"weighted_f64_error_bound": exact(&BigInt::from(self.weighted_error), -2148, &self.denominator),
			"nonzero_multipliers": self.nonzero_rows,
			"ideal_real": {
				"d":dyadic(&d,-3222), "d_positive":d.sign()==Sign::Plus,
				"left_squared":dyadic(&(&d * &d), -6444),
				"right_squared":dyadic(&BigInt::from(right.clone()), -6446),
				"strict_separation":ideal,
			},
			"f64_necessary_relaxation": {
				"d":exact(&relaxed_d,-3222,&self.denominator),
				"d_positive":relaxed_d.sign()==Sign::Plus,
				"left_squared":exact(&(&relaxed_d * &relaxed_d), -6444, &denominator_squared),
				"right_squared":dyadic(&BigInt::from(right), -6446),
				"strict_separation":relaxed,
			},
		})
	}
}
