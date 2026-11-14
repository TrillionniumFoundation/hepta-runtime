// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Appended only in the oracle to the complete unchanged original module.
// The entropy implementation is a trusted deterministic test fixture. It does
// not replace SystemEntropy or claim real operating-system entropy behavior.

#[derive(Default)]
struct FixtureEntropy {
	configured: std::cell::Cell<bool>,
	seed: std::cell::Cell<u64>,
	fail: std::cell::Cell<u64>,
	mode: std::cell::Cell<u64>,
	partial: std::cell::Cell<u64>,
	calls: std::cell::Cell<u64>,
	requested: std::cell::Cell<u64>,
	failed: std::cell::Cell<u64>,
	last: std::cell::Cell<u64>,
	total_calls: std::cell::Cell<usize>,
	total_requested: std::cell::Cell<usize>,
}

impl Entropy for FixtureEntropy {
	fn fill(&self, bytes: &mut [u8]) -> CryptoResult<()> {
		assert!(self.configured.get() && bytes.len() <= 128);
		let calls = self.calls.get() + 1;
		self.calls.set(calls);
		self.requested
			.set(self.requested.get() + bytes.len() as u64);
		self.last.set(bytes.len() as u64);
		self.total_calls.set(self.total_calls.get() + 1);
		self.total_requested
			.set(self.total_requested.get() + bytes.len());
		let fail = calls == self.fail.get();
		let size = if fail {
			bytes.len().min(self.partial.get() as usize)
		} else {
			bytes.len()
		};
		let seed = self.seed.get().wrapping_add(if self.mode.get() == 0 {
			calls.wrapping_mul(37)
		} else {
			0
		});
		for (index, byte) in bytes[..size].iter_mut().enumerate() {
			*byte = seed.wrapping_add((index as u64).wrapping_mul(19)) as u8;
		}
		if fail {
			self.failed.set(self.failed.get() + 1);
			Err(CryptoError::EntropyUnavailable)
		} else {
			Ok(())
		}
	}
}

fn mapped(error: CryptoError) -> u32 {
	match error {
		CryptoError::InvalidBinding => super::BINDING,
		CryptoError::InvalidInput => super::INPUT,
		CryptoError::PayloadTooLarge => super::PAYLOAD,
		CryptoError::EntropyUnavailable => super::ENTROPY,
		CryptoError::NonceUnavailable => super::NONCE,
		CryptoError::IntegrityUnavailable => super::INTEGRITY,
		CryptoError::KeyUnavailable => super::KEY,
		CryptoError::StateUnavailable => super::STATE,
	}
}

pub(super) struct ScopeReference {
	refs: Vec<ResultCryptoScope>,
	entropy: FixtureEntropy,
	state: u64,
}

impl ScopeReference {
	fn scope(&mut self, raw: &[u8], counts: &mut super::Counts) -> super::RefResult<Vec<u8>> {
		if raw.len() < 24 || raw.get(..8) != Some(b"HRSCOPE1") || super::word(raw, 16)? != 0 {
			return Err(super::INVALID);
		}
		let op = super::word(raw, 8)?;
		if !(1..=9).contains(&op) || (matches!(op, 2 | 8 | 9) && raw.len() != 24) {
			return Err(super::INVALID);
		}
		if op == 1 || op == 2 {
			if self.state != 0 {
				return Err(super::STATE);
			}
			let scope = if op == 1 {
				counts.verified_constructor += 1;
				ResultCryptoScope::from_verified_token(&raw[24..]).map_err(mapped)?
			} else {
				counts.stdio_constructor += 1;
				ResultCryptoScope::stdio_with_entropy(&self.entropy).map_err(mapped)?
			};
			self.refs.push(scope);
			self.state = 2;
			return Ok(Vec::new());
		}
		if self.state != 2 || self.refs.is_empty() {
			return Err(super::STATE);
		}
		if op == 8 {
			counts.clone += 1;
			self.refs.push(self.refs.last().unwrap().clone());
			return Ok(Vec::new());
		}
		if op == 9 {
			counts.release += 1;
			let final_ref = self.refs.len() == 1;
			let key = Arc::downgrade(&self.refs.last().unwrap().keys);
			let nonce = Arc::downgrade(&self.refs.last().unwrap().nonces);
			drop(self.refs.pop().unwrap());
			if final_ref {
				assert!(key.upgrade().is_none() && nonce.upgrade().is_none());
				self.state = 3;
				counts.last_release += 1;
			} else {
				assert_eq!(key.strong_count(), self.refs.len());
				assert_eq!(nonce.strong_count(), self.refs.len());
			}
			return Ok(Vec::new());
		}
		let scope = self.refs.last().unwrap();
		if op == 3 {
			counts.request_binding += 1;
			return scope
				.request_binding(&raw[24..])
				.map(String::into_bytes)
				.map_err(mapped);
		}
		if op == 4 {
			counts.idempotency_binding += 1;
			return scope
				.idempotency_binding(&raw[24..])
				.map(String::into_bytes)
				.map_err(mapped);
		}
		if op == 5 {
			counts.policy_binding += 1;
			return scope
				.policy_binding(&raw[24..])
				.map(String::into_bytes)
				.map_err(mapped);
		}
		let frame = super::parse_record(&raw[24..], if op == 6 { 4 } else { 3 })?;
		// Malformed ASCII binding fixtures deliberately reach the unchanged
		// defensive seal/open admission rather than a copied validation body.
		let fields = frame.fields;
		let trusted = TrustedResultBinding {
			operation_id: fields[0].into(),
			owner: fields[1].into(),
			tool_name: fields[2].into(),
			accepted_unix_ms: frame.timestamp,
			policy_binding: fields[3].into(),
			request_binding: fields[4].into(),
			ledger_identity: fields[5].into(),
			payload_kind: if frame.kind == 1 {
				NativePayloadKind::NativeResult
			} else {
				NativePayloadKind::NativeError
			},
		};
		if op == 6 {
			counts.seal += 1;
			scope
				.seal_with_entropy(&trusted, frame.tail, &self.entropy)
				.map_err(mapped)
		} else {
			counts.open += 1;
			scope
				.open(&trusted, frame.tail)
				.map(|value| value.as_bytes().to_vec())
				.map_err(mapped)
		}
	}
	fn reserve_fixture(
		&mut self,
		raw: &[u8],
		counts: &mut super::Counts,
	) -> super::RefResult<Vec<u8>> {
		if raw.len() != 164
			|| raw.get(..8) != Some(b"HRNONC01")
			|| super::word(raw, 8)? != 2
			|| super::word(raw, 16)? != 0
		{
			return Err(super::INVALID);
		}
		let scope = self.refs.last().ok_or(0xfffffffbu32)?;
		let operation_id = std::str::from_utf8(&raw[24..88]).map_err(|_| 0xfffffffdu32)?;
		let ledger = std::str::from_utf8(&raw[88..152]).map_err(|_| 0xfffffffdu32)?;
		counts.binding_constructor += 1;
		let binding = TrustedResultBinding::new(
			operation_id,
			&"2".repeat(64),
			"binary_read",
			0,
			&"3".repeat(64),
			&"4".repeat(64),
			ledger,
			NativePayloadKind::NativeResult,
		)
		.map_err(|_| 0xfffffffdu32)?;
		counts.nonce_setup += 1;
		scope
			.nonces
			.lock()
			.map_err(|_| 0xfffffffbu32)?
			.reserve(&binding, raw[152..].try_into().unwrap())
			.map_err(|_| 0xfffffffcu32)?;
		Ok(Vec::new())
	}
}

impl ScopeReference {
	pub(super) fn new() -> Self {
		Self {
			refs: Vec::new(),
			entropy: FixtureEntropy::default(),
			state: 0,
		}
	}
	pub(super) fn owner_calls(&self, c: &super::Counts) -> usize {
		c.verified_constructor
			+ c.stdio_constructor
			+ c.request_binding
			+ c.idempotency_binding
			+ c.policy_binding
			+ c.seal + c.open
			+ c.clone + c.release
			+ c.nonce_setup
			+ c.binding_constructor
	}
	pub(super) fn state(&self) -> (u64, u64, u64, u64) {
		if let Some(first) = self.refs.first() {
			assert_eq!(Arc::strong_count(&first.keys), self.refs.len());
			assert_eq!(Arc::strong_count(&first.nonces), self.refs.len());
			for scope in &self.refs {
				assert!(Arc::ptr_eq(&first.keys, &scope.keys));
				assert!(Arc::ptr_eq(&first.nonces, &scope.nonces));
			}
		}
		let nonces = self
			.refs
			.first()
			.map(|s| s.nonces.lock().unwrap().uses.len() as u64)
			.unwrap_or(0);
		(
			self.state,
			self.refs.len() as u64,
			self.entropy.calls.get(),
			nonces,
		)
	}
	pub(super) fn dispatch(
		&mut self,
		target: u64,
		raw: &[u8],
		counts: &mut super::Counts,
	) -> super::RefResult<Vec<u8>> {
		let before = self.entropy.total_calls.get();
		let requested = self.entropy.total_requested.get();
		let result = match target {
			6 => self.scope(raw, counts),
			7 => self.control(raw, counts),
			5 => self.reserve_fixture(raw, counts),
			_ => Err(super::INVALID),
		};
		counts.entropy_fills += self.entropy.total_calls.get() - before;
		counts.entropy_bytes_requested += self.entropy.total_requested.get() - requested;
		result
	}
	fn control(&mut self, raw: &[u8], counts: &mut super::Counts) -> super::RefResult<Vec<u8>> {
		if raw.len() != 48 || raw.get(..8) != Some(b"HRTESTE1") {
			return Err(super::INVALID);
		}
		counts.fixture_controls += 1;
		if super::word(raw, 8)? == 1 {
			let mode = super::word(raw, 32)?;
			let partial = super::word(raw, 40)?;
			if mode > 1 || partial > 128 {
				return Err(super::INVALID);
			}
			self.entropy.configured.set(true);
			self.entropy.seed.set(super::word(raw, 16)?);
			self.entropy.fail.set(super::word(raw, 24)?);
			self.entropy.mode.set(mode);
			self.entropy.partial.set(partial);
			self.entropy.calls.set(0);
			self.entropy.requested.set(0);
			self.entropy.failed.set(0);
			self.entropy.last.set(0);
			return Ok(Vec::new());
		}
		if super::word(raw, 8)? != 2 || raw[16..].iter().any(|b| *b != 0) {
			return Err(super::INVALID);
		}
		Ok([
			self.entropy.calls.get(),
			self.entropy.requested.get(),
			self.entropy.failed.get(),
			self.entropy.last.get(),
		]
		.into_iter()
		.flat_map(u64::to_le_bytes)
		.collect())
	}
}
