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
// Deterministic qualification entropy only; unchanged original constructors do
// all key setup. Actual SystemEntropy and OS entropy are separate required gates.
pub(crate) struct AuthorityFixtureEntropy {
	seed: u64,
	fail: u64,
	calls: std::cell::Cell<u64>,
}

impl AuthorityFixtureEntropy {
	pub(crate) fn new(seed: u64, fail: u64) -> Self {
		Self {
			seed,
			fail,
			calls: std::cell::Cell::new(0),
		}
	}
	pub(crate) fn calls(&self) -> u64 {
		self.calls.get()
	}
	pub(crate) fn stdio(&self) -> Option<Arc<ResultCryptoScope>> {
		ResultCryptoScope::stdio_with_entropy(self)
			.ok()
			.map(Arc::new)
	}
}

impl Entropy for AuthorityFixtureEntropy {
	fn fill(&self, bytes: &mut [u8]) -> CryptoResult<()> {
		assert_eq!(bytes.len(), 32);
		let call = self.calls.get() + 1;
		self.calls.set(call);
		if call == self.fail {
			return Err(CryptoError::EntropyUnavailable);
		}
		let base = self.seed.wrapping_add(call.wrapping_mul(37));
		for (index, byte) in bytes.iter_mut().enumerate() {
			*byte = base.wrapping_add((index as u64).wrapping_mul(19)) as u8;
		}
		Ok(())
	}
}
