// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Test-only access appended after the COMPLETE unchanged original module.
// This calls stdio()/seal() with the real original SystemEntropy.

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
	state: u64,
}

impl ScopeReference {
	pub(super) fn dispatch(
		&mut self,
		raw: &[u8],
		counts: &mut super::Counts,
	) -> super::RefResult<Vec<u8>> {
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
				ResultCryptoScope::stdio().map_err(mapped)?
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
			scope.seal(&trusted, frame.tail).map_err(mapped)
		} else {
			counts.open += 1;
			scope
				.open(&trusted, frame.tail)
				.map(|value| value.as_bytes().to_vec())
				.map_err(mapped)
		}
	}
}
impl ScopeReference {
	pub(super) fn new() -> Self {
		Self {
			refs: Vec::new(),
			state: 0,
		}
	}
}
