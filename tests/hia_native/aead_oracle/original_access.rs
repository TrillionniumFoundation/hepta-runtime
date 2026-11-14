// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Appended to the complete unchanged original module for synthetic fixtures.

struct FixtureEntropy([u8; 12]);
impl Entropy for FixtureEntropy {
	fn fill(&self, bytes: &mut [u8]) -> CryptoResult<()> {
		if bytes.len() != self.0.len() {
			return Err(CryptoError::EntropyUnavailable);
		}
		bytes.copy_from_slice(&self.0);
		Ok(())
	}
}

fn fixture_text<'a>(
	row: &'a serde_json::Value,
	name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
	row[name]
		.as_str()
		.ok_or_else(|| format!("missing original fixture field {name}").into())
}

pub(super) fn verify_native_fixture(
	row: &serde_json::Value,
	raw: &[u8],
	returned: &[u8],
	status: u64,
) -> Result<(usize, usize, usize), Box<dyn std::error::Error>> {
	let token = super::decode(fixture_text(row, "token_hex")?)?;
	let payload = super::decode(fixture_text(row, "payload_hex")?)?;
	let kind = match fixture_text(row, "payload_kind")? {
		"native_result" => NativePayloadKind::NativeResult,
		"native_error" => NativePayloadKind::NativeError,
		_ => return Err("invalid original fixture payload kind".into()),
	};
	let binding = TrustedResultBinding::new(
		fixture_text(row, "operation_id")?,
		fixture_text(row, "owner")?,
		fixture_text(row, "tool_name")?,
		fixture_text(row, "accepted_unix_ms")?.parse()?,
		fixture_text(row, "policy_binding")?,
		fixture_text(row, "request_binding")?,
		fixture_text(row, "ledger_identity")?,
		kind,
	)?;
	let scope = ResultCryptoScope::from_verified_token(&token)?;
	let op = u64::from_le_bytes(raw[8..16].try_into()?);
	let aad_size = u64::from_le_bytes(raw[24..32].try_into()?) as usize;
	let nonce: [u8; 12] = raw[72..84].try_into()?;
	let aad = binding.aad()?;
	if raw[88..88 + aad_size] != aad {
		return Err("native fixture AAD differs from original binding owner".into());
	}
	let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, RECORD_SALT).extract(scope.keys.aead.as_ref());
	let key = expand(
		&prk,
		&[
			RECORD_DOMAIN,
			binding.operation_id.as_bytes(),
			binding.ledger_identity.as_bytes(),
		],
	)?;
	if raw[40..72] != *key.as_ref() {
		return Err("native fixture key differs from original derivation".into());
	}
	let mut inner = INNER_MAGIC.to_vec();
	inner.extend_from_slice(&(payload.len() as u64).to_be_bytes());
	inner.extend_from_slice(digest::digest(&digest::SHA256, &payload).as_ref());
	inner.extend_from_slice(&payload);
	let sealed = scope.seal_with_entropy(&binding, &payload, &FixtureEntropy(nonce))?;
	let mut packet = PACKET_MAGIC.to_vec();
	packet.extend_from_slice(&nonce);
	packet.extend_from_slice(if op == 1 {
		returned
	} else {
		&raw[88 + aad_size..]
	});
	let opened = scope.open(&binding, &packet);
	if status == u64::from(super::AUTHENTICATION) {
		if op != 2
			|| !returned.is_empty()
			|| !matches!(opened, Err(CryptoError::IntegrityUnavailable))
		{
			return Err("native and original authentication refusals differ".into());
		}
		return Ok((1, 1, 1));
	}
	if packet != sealed || opened?.as_bytes() != payload {
		return Err("native packet differs from complete original seal/open owners".into());
	}
	if (op == 1 && raw[88 + aad_size..] != inner) || (op == 2 && returned != inner) {
		return Err("native cleartext differs from original inner record".into());
	}
	Ok((1, 1, 0))
}
