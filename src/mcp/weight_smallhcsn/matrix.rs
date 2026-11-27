// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded F64 dense algebra for the restricted population kernel.
use anyhow::{bail, Context, Result};

#[derive(Clone)]
pub(super) struct Matrix {
	pub n: usize,
	pub a: Vec<f64>,
}
impl Matrix {
	pub fn zero(n: usize) -> Self {
		Self {
			n,
			a: vec![0.0; n * n],
		}
	}
	pub fn eye(n: usize) -> Self {
		let mut result = Self::zero(n);
		for i in 0..n {
			result.a[i * n + i] = 1.0;
		}
		result
	}
	pub fn scale(&self, value: f64) -> Self {
		Self {
			n: self.n,
			a: self.a.iter().map(|x| x * value).collect(),
		}
	}
	pub fn add(&self, rhs: &Self, factor: f64) -> Self {
		Self {
			n: self.n,
			a: self
				.a
				.iter()
				.zip(&rhs.a)
				.map(|(x, y)| x + factor * y)
				.collect(),
		}
	}
	pub fn mul(&self, rhs: &Self) -> Self {
		let n = self.n;
		let mut out = Self::zero(n);
		for i in 0..n {
			for k in 0..n {
				for j in 0..n {
					out.a[i * n + j] += self.a[i * n + k] * rhs.a[k * n + j];
				}
			}
		}
		out
	}
	pub fn solve(&self, rhs: &Self) -> Result<Self> {
		let n = self.n;
		if n == 0 || n > 12 || rhs.n != n {
			bail!("matrix layout outside profile");
		}
		let mut a = self.a.clone();
		let mut b = rhs.a.clone();
		for k in 0..n {
			let pivot = (k..n)
				.max_by(|i, j| a[i * n + k].abs().total_cmp(&a[j * n + k].abs()))
				.context("empty pivot range")?;
			if a[pivot * n + k].abs() < f64::MIN_POSITIVE {
				bail!("singular pivot");
			}
			for j in 0..n {
				a.swap(k * n + j, pivot * n + j);
				b.swap(k * n + j, pivot * n + j);
			}
			for i in k + 1..n {
				let factor = a[i * n + k] / a[k * n + k];
				for j in k + 1..n {
					a[i * n + j] -= factor * a[k * n + j];
				}
				a[i * n + k] = 0.0;
				for j in 0..n {
					b[i * n + j] -= factor * b[k * n + j];
				}
			}
		}
		for i in (0..n).rev() {
			for j in 0..n {
				for k in i + 1..n {
					b[i * n + j] -= a[i * n + k] * b[k * n + j];
				}
				b[i * n + j] /= a[i * n + i];
			}
		}
		if b.iter().any(|v| !v.is_finite()) {
			bail!("nonfinite linear solution");
		}
		Ok(Self { n, a: b })
	}
	/// Fixed Padé-13 scaling/squaring, Higham (2005), bounded to 32 squarings.
	pub fn exp(&self) -> Result<Self> {
		if self.n == 0 || self.n > 12 || self.a.iter().any(|v| !v.is_finite()) {
			bail!("matrix exponential input outside profile");
		}
		let norm = (0..self.n)
			.map(|j| {
				(0..self.n)
					.map(|i| self.a[i * self.n + j].abs())
					.sum::<f64>()
			})
			.fold(0.0, f64::max);
		let squarings = (norm / 5.371_920_351_148_152).log2().ceil().max(0.0);
		if squarings > 32.0 {
			bail!("matrix exponential scaling bound");
		}
		let a = self.scale(2.0f64.powi(-(squarings as i32)));
		let eye = Self::eye(self.n);
		let a2 = a.mul(&a);
		let a4 = a2.mul(&a2);
		let a6 = a4.mul(&a2);
		let b = [
			64764752532480000.0,
			32382376266240000.0,
			7771770303897600.0,
			1187353796428800.0,
			129060195264000.0,
			10559470521600.0,
			670442572800.0,
			33522128640.0,
			1323241920.0,
			40840800.0,
			960960.0,
			16380.0,
			182.0,
			1.0,
		];
		let odd = a6.scale(b[13]).add(&a4, b[11]).add(&a2, b[9]);
		let u = a.mul(
			&a6.mul(&odd)
				.add(&a6, b[7])
				.add(&a4, b[5])
				.add(&a2, b[3])
				.add(&eye, b[1]),
		);
		let even = a6.scale(b[12]).add(&a4, b[10]).add(&a2, b[8]);
		let v = a6
			.mul(&even)
			.add(&a6, b[6])
			.add(&a4, b[4])
			.add(&a2, b[2])
			.add(&eye, b[0]);
		let mut out = v.add(&u, -1.0).solve(&v.add(&u, 1.0))?;
		for _ in 0..squarings as usize {
			out = out.mul(&out);
		}
		if out.a.iter().any(|v| !v.is_finite()) {
			bail!("nonfinite exponential");
		}
		Ok(out)
	}
}
