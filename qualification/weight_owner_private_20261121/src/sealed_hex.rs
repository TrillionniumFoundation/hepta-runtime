// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Decode canonical Python binary64 hex without floating arithmetic or a cast.

use anyhow::{bail, Result};

pub fn decode(text: &str) -> Result<f64> {
	let (negative, text) = text.strip_prefix('-').map_or((false, text), |s| (true, s));
	let sign = u64::from(negative) << 63;
	if text == "0x0.0p+0" {
		return Ok(f64::from_bits(sign));
	}
	let Some((mantissa, exponent)) = text.strip_prefix("0x").and_then(|s| s.split_once('p')) else {
		bail!("canonical Python float.hex required");
	};
	let Some((leading, fraction)) = mantissa.split_once('.') else {
		bail!("hex mantissa required");
	};
	if fraction.len() != 13
		|| !fraction
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
	{
		bail!("exact 52 fraction bits required");
	}
	let exponent: i32 = exponent.parse()?;
	let suffix = format!("p{exponent:+}");
	if !text.ends_with(&suffix) {
		bail!("noncanonical binary exponent");
	}
	let fraction = u64::from_str_radix(fraction, 16)?;
	let bits = match leading {
		"1" if (-1022..=1023).contains(&exponent) => ((exponent + 1023) as u64) << 52 | fraction,
		"0" if exponent == -1022 && fraction != 0 => fraction,
		_ => bail!("nonfinite or noncanonical binary64 mantissa"),
	};
	Ok(f64::from_bits(sign | bits))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn finite_hex_has_exact_bits() -> Result<()> {
		for (text, bits) in [
			("0x0.0p+0", 0),
			("-0x0.0p+0", 1_u64 << 63),
			("0x1.0000000000000p+0", 0x3ff0000000000000),
			("-0x1.0000000000000p+0", 0xbff0000000000000),
			("0x0.0000000000001p-1022", 1),
			("0x0.fffffffffffffp-1022", 0x000fffffffffffff),
			("0x1.0000000000000p-1022", 0x0010000000000000),
			("0x1.fffffffffffffp+1023", 0x7fefffffffffffff),
		] {
			assert_eq!(decode(text)?.to_bits(), bits);
		}
		for text in [
			"NaN",
			"inf",
			"0x1.0p+0",
			"0x1.0000000000000p1024",
			"0x1.0000000000000p+00",
			"0x0.0000000000000p-1022",
			"0x2.0000000000000p+0",
			"0x1.0000000000000p+1024",
		] {
			assert!(decode(text).is_err());
		}
		Ok(())
	}
}
