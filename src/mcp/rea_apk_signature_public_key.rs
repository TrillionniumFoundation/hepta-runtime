// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bounded public-key decoding for the independently nullable X.509 type fact.
//! Point decoding establishes neither signature validity nor certificate trust.

use super::{der_tree, oid, BerReader, Node};
use x509_parser::num_bigint::BigUint;

#[path = "rea_apk_signature_curves.rs"]
mod curves;

const MAX_FIELD_BITS: u64 = 1024;

fn integer(node: &Node<'_>) -> Option<BigUint> {
	if node.tag != 2 || node.content.is_empty() || node.content[0] & 0x80 != 0 || !der_tree(node) {
		return None;
	}
	Some(BigUint::from_bytes_be(node.content))
}

fn sequence(bytes: &[u8]) -> Option<Node<'_>> {
	let node = BerReader::new(bytes).read(0, bytes.len(), 0).ok()?;
	// OpenSSL's RSA public-key decoder accepts bytes following the inner
	// RSAPublicKey sequence. They do not change the two declared key integers.
	(node.tag == 0x30 && der_tree(&node)).then_some(node)
}

fn rsa_key(bytes: &[u8]) -> bool {
	matches!(sequence(bytes), Some(node) if node.children.len() == 2 && node.children.iter().all(|n| n.tag == 2 && !n.content.is_empty()))
}

fn pss_parameters(parameters: Option<&Node<'_>>) -> bool {
	let Some(parameters) = parameters else {
		return true;
	};
	if parameters.tag != 0x30 {
		return false;
	}
	let mut previous = None;
	for field in &parameters.children {
		if !(0xa0..=0xa3).contains(&field.tag)
			|| previous.is_some_and(|p| p >= field.tag)
			|| field.children.len() != 1
		{
			return false;
		}
		previous = Some(field.tag);
		let value = &field.children[0];
		if field.tag < 0xa2 {
			if value.tag != 0x30
				|| value.children.first().is_none_or(|n| n.tag != 6)
				|| value.children.len() > 2
			{
				return false;
			}
		} else if value.tag != 2 || value.content.is_empty() {
			return false;
		}
	}
	true
}

struct Curve {
	binary: bool,
	modulus: BigUint,
	a: BigUint,
	b: BigUint,
	bits: usize,
}

impl Curve {
	fn new(binary: bool, modulus: BigUint, a: BigUint, b: BigUint) -> Option<Self> {
		let bits = modulus.bits().checked_sub(u64::from(binary))?;
		if !(2..=MAX_FIELD_BITS).contains(&bits) || !modulus.bit(0) {
			return None;
		}
		let curve = Self {
			binary,
			modulus,
			a,
			b,
			bits: bits as usize,
		};
		(curve.contains(&curve.a) && curve.contains(&curve.b)).then_some(curve)
	}

	fn contains(&self, value: &BigUint) -> bool {
		if self.binary {
			value.bits() <= self.bits as u64
		} else {
			value < &self.modulus
		}
	}

	fn add(&self, left: &BigUint, right: &BigUint) -> BigUint {
		if self.binary {
			left ^ right
		} else {
			(left + right) % &self.modulus
		}
	}

	fn multiply(&self, left: &BigUint, right: &BigUint) -> BigUint {
		if !self.binary {
			return (left * right) % &self.modulus;
		}
		let (mut left, mut right, mut out) = (left.clone(), right.clone(), BigUint::from(0u8));
		while right.bits() != 0 {
			if right.bit(0) {
				out ^= &left;
			}
			right >>= 1;
			left <<= 1;
			if left.bit(self.bits as u64) {
				left ^= &self.modulus;
			}
		}
		out
	}

	fn power(&self, value: &BigUint, exponent: &BigUint) -> BigUint {
		if !self.binary {
			return value.modpow(exponent, &self.modulus);
		}
		let mut out = BigUint::from(1u8);
		for bit in (0..exponent.bits()).rev() {
			out = self.multiply(&out, &out);
			if exponent.bit(bit) {
				out = self.multiply(&out, value);
			}
		}
		out
	}

	fn binary_inverse(&self, value: &BigUint) -> BigUint {
		self.power(
			value,
			&((BigUint::from(1u8) << self.bits) - BigUint::from(2u8)),
		)
	}

	fn binary_y_bit(&self, x: &BigUint, y: &BigUint) -> bool {
		x.bits() != 0 && self.multiply(y, &self.binary_inverse(x)).bit(0)
	}

	fn is_sm2(&self) -> bool {
		// The frozen Node platform decodes SM2 but does not expose an
		// asymmetricKeyType for it. Explicit domain parameters have the same
		// nullable fact as the named curve; unrelated certificate facts survive.
		!self.binary
			&& curves::NAMED_CURVES
				.iter()
				.find(|(id, ..)| *id == "1.2.156.10197.1.301")
				.is_some_and(|(_, _, p, a, b)| {
					BigUint::parse_bytes(p.as_bytes(), 16).as_ref() == Some(&self.modulus)
						&& BigUint::parse_bytes(a.as_bytes(), 16).as_ref() == Some(&self.a)
						&& BigUint::parse_bytes(b.as_bytes(), 16).as_ref() == Some(&self.b)
				})
	}

	fn point(&self, encoded: &[u8]) -> bool {
		let Some(&tag) = encoded.first() else {
			return false;
		};
		if tag == 0 {
			return encoded.len() == 1;
		}
		let width = self.bits.div_ceil(8);
		let compressed = matches!(tag, 2 | 3);
		if !compressed && !matches!(tag, 4 | 6 | 7) {
			return false;
		}
		if encoded.len() != 1 + width * if compressed { 1 } else { 2 } {
			return false;
		}
		let x = BigUint::from_bytes_be(&encoded[1..1 + width]);
		if !self.contains(&x) {
			return false;
		}
		let square = self.multiply(&x, &x);
		if compressed {
			if self.binary {
				if x.bits() == 0 {
					return tag == 2;
				}
				let beta = self.add(
					&self.add(&x, &self.a),
					&self.multiply(&self.b, &self.binary_inverse(&square)),
				);
				let mut trace = beta.clone();
				let mut power = beta;
				for _ in 1..self.bits {
					power = self.multiply(&power, &power);
					trace ^= &power;
				}
				return trace.bits() == 0;
			}
			let rhs = self.add(
				&self.add(&self.multiply(&square, &x), &self.multiply(&self.a, &x)),
				&self.b,
			);
			if rhs.bits() == 0 {
				return tag == 2;
			}
			return self.power(&rhs, &((&self.modulus - BigUint::from(1u8)) >> 1))
				== BigUint::from(1u8);
		}
		let y = BigUint::from_bytes_be(&encoded[1 + width..]);
		if !self.contains(&y) {
			return false;
		}
		let (left, right) = if self.binary {
			(
				self.add(&self.multiply(&y, &y), &self.multiply(&x, &y)),
				self.add(
					&self.add(
						&self.multiply(&square, &x),
						&self.multiply(&self.a, &square),
					),
					&self.b,
				),
			)
		} else {
			(
				self.multiply(&y, &y),
				self.add(
					&self.add(&self.multiply(&square, &x), &self.multiply(&self.a, &x)),
					&self.b,
				),
			)
		};
		left == right
			&& (tag == 4
				|| (tag & 1 != 0)
					== if self.binary {
						self.binary_y_bit(&x, &y)
					} else {
						y.bit(0)
					})
	}
}

fn curve(parameters: &Node<'_>) -> Option<Curve> {
	if parameters.tag == 6 {
		let name = oid(parameters.content).ok()?;
		let (_, binary, modulus, a, b) =
			curves::NAMED_CURVES.iter().find(|(id, ..)| *id == name)?;
		return Curve::new(
			*binary,
			BigUint::parse_bytes(modulus.as_bytes(), 16)?,
			BigUint::parse_bytes(a.as_bytes(), 16)?,
			BigUint::parse_bytes(b.as_bytes(), 16)?,
		);
	}
	if parameters.tag != 0x30 || !(5..=7).contains(&parameters.children.len()) {
		return None;
	}
	let fields = &parameters.children;
	if integer(&fields[0])? != BigUint::from(1u8)
		|| fields[1].tag != 0x30
		|| fields[1].children.len() != 2
		|| fields[2].tag != 0x30
		|| !(2..=3).contains(&fields[2].children.len())
		|| fields[3].tag != 4
		|| integer(&fields[4])?.bits() == 0
	{
		return None;
	}
	let field = &fields[1].children;
	let kind = oid(field[0].content).ok()?;
	let binary = kind == "1.2.840.10045.1.2";
	let modulus = if kind == "1.2.840.10045.1.1" {
		integer(&field[1])?
	} else if binary {
		let parameters = &field[1];
		if parameters.tag != 0x30 || parameters.children.len() != 3 {
			return None;
		}
		let values = &parameters.children;
		let bits = integer(&values[0])?;
		if bits.bits() > 11 {
			return None;
		}
		let bits = bits.to_u64_digits().first().copied()?;
		if !(2..=MAX_FIELD_BITS).contains(&bits) {
			return None;
		}
		let basis = oid(values[1].content).ok()?;
		let powers = match basis.as_str() {
			"1.2.840.10045.1.2.3.2" => vec![integer(&values[2])?],
			"1.2.840.10045.1.2.3.3" if values[2].tag == 0x30 && values[2].children.len() == 3 => {
				values[2]
					.children
					.iter()
					.map(integer)
					.collect::<Option<Vec<_>>>()?
			}
			_ => return None,
		};
		let mut modulus = (BigUint::from(1u8) << bits as usize) | BigUint::from(1u8);
		let mut previous = 0;
		for power in powers {
			if power.bits() > 11 {
				return None;
			}
			let power = power.to_u64_digits().first().copied()?;
			if power <= previous || power >= bits {
				return None;
			}
			previous = power;
			modulus |= BigUint::from(1u8) << power as usize;
		}
		modulus
	} else {
		return None;
	};
	let coefficients = &fields[2].children;
	if coefficients[0].tag != 4 || coefficients[1].tag != 4 {
		return None;
	}
	let curve = Curve::new(
		binary,
		modulus,
		BigUint::from_bytes_be(coefficients[0].content),
		BigUint::from_bytes_be(coefficients[1].content),
	)?;
	curve.point(fields[3].content).then_some(curve)
}

pub(super) fn key_type(spki: &Node<'_>) -> Option<&'static str> {
	if spki.tag != 0x30 || spki.children.len() != 2 {
		return None;
	}
	let algorithm = &spki.children[0];
	let bits = &spki.children[1];
	if algorithm.tag != 0x30
		|| !(1..=2).contains(&algorithm.children.len())
		|| algorithm.children[0].tag != 6
		|| bits.tag != 3
		|| bits.content.first() != Some(&0)
	{
		return None;
	}
	let id = oid(algorithm.children[0].content).ok()?;
	let parameters = algorithm.children.get(1);
	let bytes = &bits.content[1..];
	match id.as_str() {
		"1.2.840.113549.1.1.1" if rsa_key(bytes) => Some("rsa"),
		"1.2.840.113549.1.1.10" if rsa_key(bytes) && pss_parameters(parameters) => Some("rsa-pss"),
		"1.2.840.10045.2.1" => {
			let curve = curve(parameters?)?;
			(!curve.is_sm2() && curve.point(bytes)).then_some("ec")
		}
		"1.2.840.10040.4.1" => {
			let value = BerReader::new(bytes).read(0, bytes.len(), 0).ok()?;
			(value.end == bytes.len()
				&& integer(&value).is_some()
				&& parameters.is_none_or(|p| {
					p.tag == 0x30
						&& p.children.len() == 3
						&& p.children.iter().all(|n| integer(n).is_some())
				}))
			.then_some("dsa")
		}
		"1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => {
			let value = BerReader::new(bytes).read(0, bytes.len(), 0).ok()?;
			let parameters = parameters?;
			if value.end != bytes.len() || integer(&value).is_none() || parameters.tag != 0x30 {
				return None;
			}
			if id == "1.2.840.113549.1.3.1" {
				((2..=3).contains(&parameters.children.len())
					&& parameters.children.iter().all(|n| integer(n).is_some()))
				.then_some("dh")
			} else {
				((3..=5).contains(&parameters.children.len())
					&& parameters.children[..3]
						.iter()
						.all(|n| integer(n).is_some()))
				.then_some("dh")
			}
		}
		"1.3.101.112" if parameters.is_none() && bytes.len() == 32 => Some("ed25519"),
		"1.3.101.113" if parameters.is_none() && bytes.len() == 57 => Some("ed448"),
		"1.3.101.110" if parameters.is_none() && bytes.len() == 32 => Some("x25519"),
		"1.3.101.111" if parameters.is_none() && bytes.len() == 56 => Some("x448"),
		_ => None,
	}
}
