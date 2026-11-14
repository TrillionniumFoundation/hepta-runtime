// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Appended only in the oracle to the complete unchanged original module.
// Synthetic scope-key construction tests private byte owners; it is not a
// public key import API or a claim about credential/capability admission.

struct FixtureEntropy([u8; 12]);
impl Entropy for FixtureEntropy {
	fn fill(&self, bytes: &mut [u8]) -> CryptoResult<()> {
		if bytes.len() != 12 {
			return Err(CryptoError::EntropyUnavailable);
		}
		bytes.copy_from_slice(&self.0);
		Ok(())
	}
}

struct StopAtEntropy(std::cell::Cell<usize>);
impl Entropy for StopAtEntropy {
	fn fill(&self, _bytes: &mut [u8]) -> CryptoResult<()> {
		self.0.set(self.0.get() + 1);
		Err(CryptoError::EntropyUnavailable)
	}
}

fn mapped(error: CryptoError) -> u32 {
	match error {
		CryptoError::InvalidBinding => super::BINDING,
		CryptoError::PayloadTooLarge => super::PAYLOAD,
		CryptoError::IntegrityUnavailable => super::INTEGRITY,
		other => panic!("unexpected original owner result: {other}"),
	}
}

pub(super) fn reference(
	frame: &super::Frame<'_>,
	token: Option<&[u8]>,
	counts: &mut super::Counts,
) -> super::RefResult<Vec<u8>> {
	let fields = frame.fields;
	let kind = if frame.kind == 1 {
		NativePayloadKind::NativeResult
	} else {
		NativePayloadKind::NativeError
	};
	if frame.op == 1 {
		counts.constructor += 1;
		let binding = TrustedResultBinding::new(
			fields[0],
			fields[1],
			fields[2],
			frame.timestamp,
			fields[3],
			fields[4],
			fields[5],
			kind,
		)
		.map_err(mapped)?;
		counts.aad += 1;
		return binding.aad().map_err(mapped);
	}
	// Invalid field fixtures intentionally reach the unchanged owners' defensive
	// binding.aad() validation, preserving payload/packet rejection ordering.
	let binding = TrustedResultBinding {
		operation_id: fields[0].into(),
		owner: fields[1].into(),
		tool_name: fields[2].into(),
		accepted_unix_ms: frame.timestamp,
		policy_binding: fields[3].into(),
		request_binding: fields[4].into(),
		ledger_identity: fields[5].into(),
		payload_kind: kind,
	};
	let key = if frame.op == 4 {
		[0u8; 32]
	} else {
		frame.tail[..32].try_into().unwrap()
	};
	let scope = if let Some(token) = token {
		counts.verified_scope += 1;
		let scope = ResultCryptoScope::from_verified_token(token)
			.expect("synthetic verified token admission");
		assert_eq!(
			*scope.keys.aead.as_ref(),
			key,
			"fixture scope key differs from original verified constructor"
		);
		scope
	} else {
		ResultCryptoScope {
			keys: Arc::new(SecretKeys {
				aead: Zeroizing::new(key),
				request: Zeroizing::new([0; 32]),
				idempotency: Zeroizing::new([0; 32]),
				policy: Zeroizing::new([0; 32]),
			}),
			nonces: Arc::new(Mutex::new(NonceLedger::default())),
		}
	};
	if frame.op == 2 {
		counts.seal += 1;
		let nonce = frame.tail[32..44].try_into().unwrap();
		return scope
			.seal_with_entropy(&binding, &frame.tail[44..], &FixtureEntropy(nonce))
			.map_err(mapped);
	}
	if frame.op == 3 {
		counts.open += 1;
		return scope
			.open(&binding, &frame.tail[32..])
			.map(|opened| opened.as_bytes().to_vec())
			.map_err(mapped);
	}
	assert_eq!(frame.op, 4);
	counts.preflight += 1;
	let stop = StopAtEntropy(std::cell::Cell::new(0));
	match scope.seal_with_entropy(&binding, frame.tail, &stop) {
		Err(CryptoError::EntropyUnavailable) => {
			assert_eq!(stop.0.get(), 1);
			assert!(scope.nonces.lock().unwrap().uses.is_empty());
			counts.preflight_entropy_reached += 1;
			counts.aad += 1;
			binding.aad().map_err(mapped)
		}
		Err(error) => {
			assert_eq!(stop.0.get(), 0);
			Err(mapped(error))
		}
		Ok(_) => panic!("original preflight unexpectedly bypassed entropy failure"),
	}
}
