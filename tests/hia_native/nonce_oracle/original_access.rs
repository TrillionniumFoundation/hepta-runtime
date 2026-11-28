// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Test-only access appended after the complete unchanged original crypto owner.

pub(super) fn validated_binding(
	operation: &[u8],
	ledger: &[u8],
) -> Result<TrustedResultBinding, CryptoError> {
	let operation = std::str::from_utf8(operation).map_err(|_| CryptoError::InvalidBinding)?;
	let ledger = std::str::from_utf8(ledger).map_err(|_| CryptoError::InvalidBinding)?;
	let identity = "0".repeat(64);
	TrustedResultBinding::new(
		operation,
		&identity,
		"reference_tool",
		0,
		&identity,
		&identity,
		ledger,
		NativePayloadKind::NativeResult,
	)
}

pub(super) struct ReferenceLedger(NonceLedger);

impl ReferenceLedger {
	pub(super) fn new() -> Self {
		Self(NonceLedger::default())
	}

	pub(super) fn reserve(
		&mut self,
		binding: &TrustedResultBinding,
		nonce: [u8; 12],
	) -> Result<(), CryptoError> {
		self.0.reserve(binding, nonce)
	}

	pub(super) fn count(&self) -> usize {
		self.0.uses.len()
	}
}
