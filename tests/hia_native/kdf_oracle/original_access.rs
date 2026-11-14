// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Test-only access to synthetic secret fixtures. Appended inside the original
// module after its unchanged bytes; never compiled into the runtime product.

pub(super) fn token_keys(token: &[u8]) -> Result<Vec<u8>, CryptoError> {
	let scope = ResultCryptoScope::from_verified_token(token)?;
	let mut out = Vec::with_capacity(128);
	for key in [
		&scope.keys.aead,
		&scope.keys.request,
		&scope.keys.idempotency,
		&scope.keys.policy,
	] {
		out.extend_from_slice(key.as_ref());
	}
	Ok(out)
}

fn synthetic_scope(key: &[u8]) -> ResultCryptoScope {
	let copy = || {
		let mut bytes = Zeroizing::new([0; 32]);
		bytes.copy_from_slice(key);
		bytes
	};
	ResultCryptoScope {
		keys: Arc::new(SecretKeys {
			aead: copy(),
			request: copy(),
			idempotency: copy(),
			policy: copy(),
		}),
		nonces: Arc::new(Mutex::new(NonceLedger::default())),
	}
}

pub(super) fn binding(op: u64, key: &[u8], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
	let scope = synthetic_scope(key);
	let value = match op {
		6 => scope.request_binding(input)?,
		7 => scope.idempotency_binding(input)?,
		8 => scope.policy_binding(input)?,
		_ => return Err(CryptoError::InvalidInput),
	};
	Ok(value.into_bytes())
}

pub(super) fn record_key_bytes(
	key: &[u8],
	operation: &[u8],
	ledger: &[u8],
) -> Result<Vec<u8>, CryptoError> {
	let operation = std::str::from_utf8(operation).map_err(|_| CryptoError::InvalidBinding)?;
	let ledger = std::str::from_utf8(ledger).map_err(|_| CryptoError::InvalidBinding)?;
	let identity = "0".repeat(64);
	let binding = TrustedResultBinding::new(
		operation,
		&identity,
		"reference_tool",
		0,
		&identity,
		&identity,
		ledger,
		NativePayloadKind::NativeResult,
	)?;
	let scope = synthetic_scope(key);
	let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, RECORD_SALT).extract(key);
	let raw = expand(
		&prk,
		&[RECORD_DOMAIN, operation.as_bytes(), ledger.as_bytes()],
	)?;
	// Compare the unchanged record_key() owner through its opaque AEAD result.
	let actual = scope.record_key(&binding)?;
	let projected = aead::LessSafeKey::new(
		aead::UnboundKey::new(&aead::CHACHA20_POLY1305, raw.as_ref())
			.map_err(|_| CryptoError::KeyUnavailable)?,
	);
	let mut first = b"synthetic record-key conformance fixture".to_vec();
	let mut second = first.clone();
	actual
		.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key([0; 12]),
			aead::Aad::from(b"synthetic aad"),
			&mut first,
		)
		.map_err(|_| CryptoError::IntegrityUnavailable)?;
	projected
		.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key([0; 12]),
			aead::Aad::from(b"synthetic aad"),
			&mut second,
		)
		.map_err(|_| CryptoError::IntegrityUnavailable)?;
	if first != second {
		return Err(CryptoError::IntegrityUnavailable);
	}
	Ok(raw.to_vec())
}
