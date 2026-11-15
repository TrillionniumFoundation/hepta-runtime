// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Independent primitive tests. No credentials, SSH, live services or admission
//! engines are exercised; these are not V9/V10 qualification receipts.
use super::*;
use std::sync::{
	atomic::{AtomicUsize, Ordering},
	Barrier,
};

const TOKEN: &[u8] = b"test-only-verified-bearer-000000000000000000000001";
const PRIVATE_ARGS: &[u8] =
	b"{\"argv\":[\"password=unit-private-arg-95137\"],\"policy\":\"unit-private-policy\"}";
const PRIVATE_KEY: &[u8] = b"unit-private-idempotency-key-26815";
const PRIVATE_OUTPUT: &[u8] =
	b"{\"content\":[{\"type\":\"text\",\"text\":\"unit-private-error-password-64829\"}],\"isError\":true}";

fn scope() -> ResultCryptoScope {
	ResultCryptoScope::from_verified_token(TOKEN).unwrap()
}
fn id(byte: char) -> String {
	std::iter::repeat_n(byte, 64).collect()
}
fn binding(scope: &ResultCryptoScope) -> TrustedResultBinding {
	TrustedResultBinding::new(
		&id('a'),
		&id('b'),
		"host_health",
		1_760_371_200_000,
		&id('c'),
		&scope.request_binding(PRIVATE_ARGS).unwrap(),
		&id('d'),
		NativePayloadKind::NativeResult,
	)
	.unwrap()
}
struct FixedEntropy(u8);
impl Entropy for FixedEntropy {
	fn fill(&self, out: &mut [u8]) -> CryptoResult<()> {
		out.fill(self.0);
		Ok(())
	}
}
struct FailedEntropy;
impl Entropy for FailedEntropy {
	fn fill(&self, _out: &mut [u8]) -> CryptoResult<()> {
		Err(CryptoError::EntropyUnavailable)
	}
}
struct CountingEntropy {
	calls: AtomicUsize,
	fail_on: usize,
}
impl Entropy for CountingEntropy {
	fn fill(&self, out: &mut [u8]) -> CryptoResult<()> {
		let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
		if call == self.fail_on {
			return Err(CryptoError::EntropyUnavailable);
		}
		out.fill(call as u8);
		Ok(())
	}
}
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
	!needle.is_empty() && haystack.windows(needle.len()).any(|row| row == needle)
}

#[test]
fn original_native_sdk_success_and_error_bytes_round_trip_exactly() {
	use rmcp::model::{CallToolResult, ContentBlock, ErrorData};
	let scope = scope();
	let mut binding = binding(&scope);
	let sdk = CallToolResult::success(vec![ContentBlock::text(
		"unit-private-original-native-result",
	)]);
	let original = serde_json::to_vec(&sdk).unwrap();
	let sealed = scope.seal(&binding, &original).unwrap();
	assert_eq!(scope.open(&binding, &sealed).unwrap().as_bytes(), original);
	binding.payload_kind = NativePayloadKind::NativeError;
	let native_error = serde_json::to_vec(&ErrorData::invalid_params(
		"unit-private-native-rpc-error",
		Some(serde_json::json!({"reason":"unit-private-error-data"})),
	))
	.unwrap();
	let sealed = scope.seal(&binding, &native_error).unwrap();
	assert_eq!(
		scope.open(&binding, &sealed).unwrap().as_bytes(),
		native_error
	);
}
#[test]
fn empty_and_binary_payloads_remain_opaque_not_parsed_or_rewritten() {
	let scope = scope();
	let binding = binding(&scope);
	for original in [&b""[..], &b"\0\xff\xfe\r\nSDK opaque bytes"[..]] {
		let sealed = scope.seal(&binding, original).unwrap();
		assert_eq!(scope.open(&binding, &sealed).unwrap().as_bytes(), original);
	}
}
#[test]
fn exact_one_mib_is_retained_without_truncation() {
	let scope = scope();
	let binding = binding(&scope);
	let mut original = vec![b'x'; MAX_PAYLOAD_BYTES];
	original[0] = 0;
	original[MAX_PAYLOAD_BYTES - 1] = 255;
	let sealed = scope.seal(&binding, &original).unwrap();
	assert_eq!(sealed.len(), MAX_PACKET_BYTES);
	assert_eq!(scope.open(&binding, &sealed).unwrap().as_bytes(), original);
}
#[test]
fn overflow_fails_before_entropy_or_nonce_admission() {
	let scope = scope();
	let binding = binding(&scope);
	let entropy = CountingEntropy {
		calls: AtomicUsize::new(0),
		fail_on: 0,
	};
	assert_eq!(
		scope.seal_with_entropy(&binding, &vec![0; MAX_PAYLOAD_BYTES + 1], &entropy),
		Err(CryptoError::PayloadTooLarge)
	);
	assert_eq!(entropy.calls.load(Ordering::SeqCst), 0);
	assert!(scope.nonces.lock().unwrap().uses.is_empty());
}
#[test]
fn hostile_packet_sizes_headers_and_truncations_are_rejected() {
	let scope = scope();
	let binding = binding(&scope);
	let valid = scope.seal(&binding, PRIVATE_OUTPUT).unwrap();
	for packet in [
		vec![],
		vec![0; MAX_PACKET_BYTES + 1],
		valid[..OUTER_BYTES].to_vec(),
		valid[..valid.len() - 1].to_vec(),
	] {
		assert!(matches!(
			scope.open(&binding, &packet),
			Err(CryptoError::IntegrityUnavailable)
		));
	}
	let mut bad_magic = valid.clone();
	bad_magic[PACKET_MAGIC.len() - 1] ^= 1;
	assert!(matches!(
		scope.open(&binding, &bad_magic),
		Err(CryptoError::IntegrityUnavailable)
	));
}
#[test]
fn every_trusted_binding_field_is_authenticated() {
	let scope = scope();
	let binding = binding(&scope);
	let sealed = scope.seal(&binding, PRIVATE_OUTPUT).unwrap();
	let mut changed = Vec::new();
	let mut one = binding.clone();
	one.operation_id = id('e');
	changed.push(one);
	let mut one = binding.clone();
	one.owner = id('e');
	changed.push(one);
	let mut one = binding.clone();
	one.tool_name = "file_read".into();
	changed.push(one);
	let mut one = binding.clone();
	one.accepted_unix_ms += 1;
	changed.push(one);
	let mut one = binding.clone();
	one.policy_binding = id('e');
	changed.push(one);
	let mut one = binding.clone();
	one.request_binding = id('e');
	changed.push(one);
	let mut one = binding.clone();
	one.ledger_identity = id('e');
	changed.push(one);
	let mut one = binding.clone();
	one.payload_kind = NativePayloadKind::NativeError;
	changed.push(one);
	for one in changed {
		assert!(matches!(
			scope.open(&one, &sealed),
			Err(CryptoError::IntegrityUnavailable)
		));
	}
}
#[test]
fn schema_algorithm_and_domain_aad_changes_cannot_decrypt() {
	let scope = scope();
	let binding = binding(&scope);
	let sealed = scope.seal(&binding, PRIVATE_OUTPUT).unwrap();
	let original_aad = binding.aad().unwrap();
	for needle in [AAD_DOMAIN, PAYLOAD_SCHEMA, &b"chacha20_poly1305"[..]] {
		let index = original_aad
			.windows(needle.len())
			.position(|v| v == needle)
			.unwrap();
		let mut altered = original_aad.clone();
		altered[index] ^= 1;
		let mut nonce = [0; NONCE_BYTES];
		nonce.copy_from_slice(&sealed[PACKET_MAGIC.len()..OUTER_BYTES]);
		let mut bytes = sealed[OUTER_BYTES..].to_vec();
		assert!(scope
			.record_key(&binding)
			.unwrap()
			.open_in_place(
				aead::Nonce::assume_unique_for_key(nonce),
				aead::Aad::from(&altered),
				&mut bytes
			)
			.is_err());
	}
}
#[test]
fn nonce_tag_and_ciphertext_tampering_fail_closed() {
	let scope = scope();
	let binding = binding(&scope);
	let sealed = scope.seal(&binding, PRIVATE_OUTPUT).unwrap();
	for index in [
		PACKET_MAGIC.len(),
		OUTER_BYTES,
		OUTER_BYTES + INNER_BYTES,
		sealed.len() - 1,
	] {
		let mut altered = sealed.clone();
		altered[index] ^= 1;
		assert!(matches!(
			scope.open(&binding, &altered),
			Err(CryptoError::IntegrityUnavailable)
		));
	}
}
#[test]
fn cross_operation_and_cross_owner_swaps_are_refused() {
	let scope = scope();
	let first = binding(&scope);
	let mut second = first.clone();
	second.operation_id = id('e');
	let first_packet = scope.seal(&first, b"original one").unwrap();
	let second_packet = scope.seal(&second, b"original two").unwrap();
	assert!(scope.open(&first, &second_packet).is_err());
	assert!(scope.open(&second, &first_packet).is_err());
	second.operation_id = first.operation_id.clone();
	second.owner = id('f');
	assert!(scope.open(&second, &first_packet).is_err());
}
#[test]
fn verified_same_token_resumes_but_wrong_or_rotated_token_does_not() {
	let first = scope();
	let binding = binding(&first);
	let sealed = first.seal(&binding, PRIVATE_OUTPUT).unwrap();
	let reconnect = scope();
	assert_eq!(
		reconnect.open(&binding, &sealed).unwrap().as_bytes(),
		PRIVATE_OUTPUT
	);
	let rotated = ResultCryptoScope::from_verified_token(
		b"test-only-verified-bearer-000000000000000000000002",
	)
	.unwrap();
	assert!(rotated.open(&binding, &sealed).is_err());
	assert_ne!(
		first.request_binding(PRIVATE_ARGS).unwrap(),
		rotated.request_binding(PRIVATE_ARGS).unwrap()
	);
	assert_ne!(
		first.idempotency_binding(PRIVATE_KEY).unwrap(),
		rotated.idempotency_binding(PRIVATE_KEY).unwrap()
	);
}
#[test]
fn persisted_owner_hash_is_not_a_decryption_key_or_key_derivation_input() {
	let scope = scope();
	let binding = binding(&scope);
	let sealed = scope.seal(&binding, PRIVATE_OUTPUT).unwrap();
	let mut owner_input = b"hepta-runtime/private-operator-credential/v1\0".to_vec();
	owner_input.extend_from_slice(TOKEN);
	let persisted_owner = hex(digest::digest(&digest::SHA256, &owner_input).as_ref());
	let guessed = ResultCryptoScope::from_verified_token(persisted_owner.as_bytes()).unwrap();
	assert!(guessed.open(&binding, &sealed).is_err());
	// Binding owner can be public and independent: it authenticates routing,
	// while the raw verified bearer remains the secret key source.
	let mut public_binding = binding.clone();
	public_binding.owner = persisted_owner;
	let sealed = scope.seal(&public_binding, PRIVATE_OUTPUT).unwrap();
	assert!(guessed.open(&public_binding, &sealed).is_err());
}
#[test]
fn hmac_domains_separate_private_args_and_private_idempotency_keys() {
	let scope = scope();
	let same = b"unit-low-entropy-secret";
	let request = scope.request_binding(same).unwrap();
	let key = scope.idempotency_binding(same).unwrap();
	assert_ne!(request, key);
	assert_ne!(request, hex(digest::digest(&digest::SHA256, same).as_ref()));
	assert_ne!(key, hex(digest::digest(&digest::SHA256, same).as_ref()));
	assert_eq!(request.len(), 64);
	assert_eq!(key.len(), 64);
	assert_ne!(
		scope.request_binding(b"policy one").unwrap(),
		scope.request_binding(b"policy two").unwrap()
	);
	assert_eq!(
		scope.request_binding(same).unwrap(),
		scope.clone().request_binding(same).unwrap()
	);
}
#[test]
fn substituting_a_binding_domain_key_for_aead_is_refused() {
	let first = scope();
	let binding = binding(&first);
	let sealed = first.seal(&binding, PRIVATE_OUTPUT).unwrap();
	for wrong in [&first.keys.request, &first.keys.idempotency] {
		let substituted = ResultCryptoScope {
			keys: Arc::new(SecretKeys {
				aead: Zeroizing::new(**wrong),
				request: Zeroizing::new(*first.keys.request),
				idempotency: Zeroizing::new(*first.keys.idempotency),
			}),
			nonces: Arc::new(Mutex::new(NonceLedger::default())),
		};
		assert!(substituted.open(&binding, &sealed).is_err());
	}
}
#[test]
fn stdio_keys_are_independent_and_reset_without_durable_resume() {
	let first = ResultCryptoScope::stdio().unwrap();
	let second = ResultCryptoScope::stdio().unwrap();
	let binding = binding(&first);
	let sealed = first.seal(&binding, PRIVATE_OUTPUT).unwrap();
	assert!(second.open(&binding, &sealed).is_err());
	assert_eq!(
		first.clone().open(&binding, &sealed).unwrap().as_bytes(),
		PRIVATE_OUTPUT
	);
	assert_ne!(
		first.request_binding(PRIVATE_ARGS).unwrap(),
		second.request_binding(PRIVATE_ARGS).unwrap()
	);
	assert_ne!(
		first.idempotency_binding(PRIVATE_KEY).unwrap(),
		second.idempotency_binding(PRIVATE_KEY).unwrap()
	);
	assert_ne!(first.keys.aead.as_ref(), first.keys.request.as_ref());
	assert_ne!(first.keys.aead.as_ref(), first.keys.idempotency.as_ref());
	assert_ne!(first.keys.request.as_ref(), first.keys.idempotency.as_ref());
}
#[test]
fn entropy_failure_never_returns_ciphertext_or_partially_initialized_scope() {
	let scope = scope();
	let binding = binding(&scope);
	assert_eq!(
		scope.seal_with_entropy(&binding, PRIVATE_OUTPUT, &FailedEntropy),
		Err(CryptoError::EntropyUnavailable)
	);
	assert!(scope.nonces.lock().unwrap().uses.is_empty());
	assert!(matches!(
		ResultCryptoScope::stdio_with_entropy(&FailedEntropy),
		Err(CryptoError::EntropyUnavailable)
	));
	for fail_on in 1..=3 {
		let entropy = CountingEntropy {
			calls: AtomicUsize::new(0),
			fail_on,
		};
		assert!(matches!(
			ResultCryptoScope::stdio_with_entropy(&entropy),
			Err(CryptoError::EntropyUnavailable)
		));
		assert_eq!(entropy.calls.load(Ordering::SeqCst), fail_on);
	}
}
#[test]
fn repeated_nonce_is_rejected_even_through_a_cloned_scope() {
	let scope = scope();
	let binding = binding(&scope);
	let entropy = FixedEntropy(7);
	let first = scope
		.seal_with_entropy(&binding, PRIVATE_OUTPUT, &entropy)
		.unwrap();
	assert_eq!(
		scope
			.clone()
			.seal_with_entropy(&binding, b"changed native result", &entropy),
		Err(CryptoError::NonceUnavailable)
	);
	assert_eq!(
		scope.open(&binding, &first).unwrap().as_bytes(),
		PRIVATE_OUTPUT
	);
}
#[test]
fn distinct_operation_subkeys_make_same_nonce_a_distinct_key_namespace() {
	let scope = scope();
	let first = binding(&scope);
	let mut second = first.clone();
	second.operation_id = id('e');
	let entropy = FixedEntropy(8);
	let one = scope
		.seal_with_entropy(&first, b"one original", &entropy)
		.unwrap();
	let two = scope
		.seal_with_entropy(&second, b"two original", &entropy)
		.unwrap();
	assert_eq!(
		scope.open(&first, &one).unwrap().as_bytes(),
		b"one original"
	);
	assert_eq!(
		scope.open(&second, &two).unwrap().as_bytes(),
		b"two original"
	);
	assert!(scope.open(&first, &two).is_err());
}
#[test]
fn concurrent_duplicate_nonce_admits_exactly_one_ciphertext() {
	let scope = scope();
	let binding = binding(&scope);
	let barrier = Arc::new(Barrier::new(8));
	let mut workers = Vec::new();
	for _ in 0..8 {
		let (scope, binding, barrier) = (scope.clone(), binding.clone(), barrier.clone());
		workers.push(std::thread::spawn(move || {
			barrier.wait();
			scope.seal_with_entropy(&binding, PRIVATE_OUTPUT, &FixedEntropy(9))
		}));
	}
	let results: Vec<_> = workers
		.into_iter()
		.map(|worker| worker.join().unwrap())
		.collect();
	assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
	assert_eq!(
		results
			.iter()
			.filter(|result| **result == Err(CryptoError::NonceUnavailable))
			.count(),
		7
	);
}
#[test]
fn bounded_nonce_accounting_fails_closed_before_new_seal() {
	let scope = scope();
	{
		let mut ledger = scope.nonces.lock().unwrap();
		for index in 0..MAX_SEALS_PER_SCOPE {
			let mut entry = [0; 44];
			entry[..8].copy_from_slice(&(index as u64).to_be_bytes());
			ledger.uses.insert(entry);
		}
	}
	assert_eq!(
		scope.seal(&binding(&scope), PRIVATE_OUTPUT),
		Err(CryptoError::NonceUnavailable)
	);
}
#[test]
fn scope_binding_payload_and_errors_debug_never_print_secrets() {
	let scope = scope();
	let binding = binding(&scope);
	let sealed = scope.seal(&binding, PRIVATE_OUTPUT).unwrap();
	let opened = scope.open(&binding, &sealed).unwrap();
	let debug = format!(
		"{scope:?} {binding:?} {opened:?} {:?} {}",
		CryptoError::IntegrityUnavailable,
		CryptoError::IntegrityUnavailable
	);
	for marker in [
		TOKEN,
		PRIVATE_ARGS,
		PRIVATE_KEY,
		PRIVATE_OUTPUT,
		&b"unit-private"[..],
	] {
		assert!(!contains(debug.as_bytes(), marker));
	}
	assert!(debug.contains("[redacted]"));
}
#[test]
fn ciphertext_contains_no_private_args_key_output_or_plaintext_digest_header() {
	let scope = scope();
	let binding = binding(&scope);
	let sealed = scope.seal(&binding, PRIVATE_OUTPUT).unwrap();
	for marker in [
		TOKEN,
		PRIVATE_ARGS,
		PRIVATE_KEY,
		PRIVATE_OUTPUT,
		INNER_MAGIC.as_slice(),
	] {
		assert!(!contains(&sealed, marker));
	}
	assert!(!contains(
		&sealed,
		digest::digest(&digest::SHA256, PRIVATE_OUTPUT).as_ref()
	));
	assert!(!contains(
		&sealed,
		&(PRIVATE_OUTPUT.len() as u64).to_be_bytes()
	));
}
#[test]
fn request_and_key_input_bounds_fail_closed() {
	let scope = scope();
	assert_eq!(scope.request_binding(b""), Err(CryptoError::InvalidInput));
	assert_eq!(
		scope.request_binding(&vec![0; MAX_BINDING_BYTES + 1]),
		Err(CryptoError::InvalidInput)
	);
	assert_eq!(
		scope.idempotency_binding(b""),
		Err(CryptoError::InvalidInput)
	);
	assert_eq!(
		scope.idempotency_binding(&[0; MAX_IDEMPOTENCY_BYTES + 1]),
		Err(CryptoError::InvalidInput)
	);
	assert!(scope
		.idempotency_binding(&[0; MAX_IDEMPOTENCY_BYTES])
		.is_ok());
	for token in [
		&b""[..],
		&b"short"[..],
		&b"1234567890123456789012345678901 "[..],
		&b"12345678901234567890123456789012\n"[..],
	] {
		assert!(matches!(
			ResultCryptoScope::from_verified_token(token),
			Err(CryptoError::InvalidInput)
		));
	}
}
#[test]
fn malformed_trusted_identities_are_refused_before_any_nonce_consumption() {
	let scope = scope();
	let golden = binding(&scope);
	assert_eq!(golden.operation_id(), id('a'));
	let mut changed = Vec::new();
	let mut one = golden.clone();
	one.operation_id = "A".repeat(64);
	changed.push(one);
	let mut one = golden.clone();
	one.owner.pop();
	changed.push(one);
	let mut one = golden.clone();
	one.policy_binding = "g".repeat(64);
	changed.push(one);
	let mut one = golden.clone();
	one.request_binding = "../not-a-binding".into();
	changed.push(one);
	let mut one = golden.clone();
	one.ledger_identity.clear();
	changed.push(one);
	let mut one = golden.clone();
	one.tool_name = "tool; command".into();
	changed.push(one);
	let mut one = golden.clone();
	one.tool_name = "_host_health".into();
	changed.push(one);
	for bad in changed {
		assert_eq!(
			scope.seal(&bad, PRIVATE_OUTPUT),
			Err(CryptoError::InvalidBinding)
		);
	}
	assert!(scope.nonces.lock().unwrap().uses.is_empty());
}
fn authenticated_packet_for_inner(
	scope: &ResultCryptoScope,
	binding: &TrustedResultBinding,
	inner: Vec<u8>,
) -> Vec<u8> {
	let mut nonce = [0; NONCE_BYTES];
	SystemEntropy.fill(&mut nonce).unwrap();
	let mut inner = Zeroizing::new(inner);
	scope
		.record_key(binding)
		.unwrap()
		.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key(nonce),
			aead::Aad::from(binding.aad().unwrap()),
			&mut *inner,
		)
		.unwrap();
	let mut packet = PACKET_MAGIC.to_vec();
	packet.extend_from_slice(&nonce);
	packet.extend_from_slice(&inner);
	packet
}
#[test]
fn authenticated_but_invalid_inner_schema_length_or_sha_is_refused() {
	let scope = scope();
	let binding = binding(&scope);
	let mut golden = INNER_MAGIC.to_vec();
	golden.extend_from_slice(&(PRIVATE_OUTPUT.len() as u64).to_be_bytes());
	golden.extend_from_slice(digest::digest(&digest::SHA256, PRIVATE_OUTPUT).as_ref());
	golden.extend_from_slice(PRIVATE_OUTPUT);
	for index in [0, 15, 16] {
		let mut altered = golden.clone();
		altered[index] ^= 1;
		let packet = authenticated_packet_for_inner(&scope, &binding, altered);
		assert!(matches!(
			scope.open(&binding, &packet),
			Err(CryptoError::IntegrityUnavailable)
		));
	}
}
#[cfg(unix)]
#[test]
fn owned_disk_packet_and_public_metadata_do_not_enable_owner_hash_decryption() {
	use std::{
		fs::OpenOptions,
		io::{Read, Write},
		os::unix::fs::OpenOptionsExt,
	};
	let scope = scope();
	let binding = binding(&scope);
	let packet = scope.seal(&binding, PRIVATE_OUTPUT).unwrap();
	let mut nonce = [0; 32];
	SystemEntropy.fill(&mut nonce).unwrap();
	let path =
		std::env::temp_dir().join(format!("hepta-operation-crypto-unit-{}.bin", hex(&nonce)));
	struct Fixture(std::path::PathBuf);
	impl Drop for Fixture {
		fn drop(&mut self) {
			let _ = std::fs::remove_file(&self.0);
		}
	}
	let fixture = Fixture(path);
	let mut file = OpenOptions::new()
		.read(true)
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&fixture.0)
		.unwrap();
	file.write_all(&packet).unwrap();
	file.sync_all().unwrap();
	drop(file);
	let mut observed = Vec::new();
	std::fs::File::open(&fixture.0)
		.unwrap()
		.read_to_end(&mut observed)
		.unwrap();
	assert_eq!(observed, packet);
	let public_metadata = serde_json::json!({
		"operation_id": binding.operation_id,
		"owner": binding.owner,
		"tool": binding.tool_name,
		"policy": binding.policy_binding,
		"request_binding": binding.request_binding,
		"ledger_identity": binding.ledger_identity
	});
	let public = serde_json::to_vec(&public_metadata).unwrap();
	for marker in [TOKEN, PRIVATE_ARGS, PRIVATE_KEY, PRIVATE_OUTPUT] {
		assert!(!contains(&observed, marker));
		assert!(!contains(&public, marker));
	}
	let attacker = ResultCryptoScope::from_verified_token(binding.owner.as_bytes()).unwrap();
	assert!(attacker.open(&binding, &observed).is_err());
	assert_eq!(
		scope.open(&binding, &observed).unwrap().as_bytes(),
		PRIVATE_OUTPUT
	);
}

#[test]
fn immutable_ledger_nonce_creates_independent_subkey_for_a_reused_operation_id() {
	let scope = scope();
	let first = binding(&scope);
	let mut second = first.clone();
	second.ledger_identity = id('e');
	let entropy = FixedEntropy(10);
	let one = scope
		.seal_with_entropy(&first, b"first ledger original", &entropy)
		.unwrap();
	let two = scope
		.seal_with_entropy(&second, b"second ledger original", &entropy)
		.unwrap();
	assert_eq!(
		scope.open(&first, &one).unwrap().as_bytes(),
		b"first ledger original"
	);
	assert_eq!(
		scope.open(&second, &two).unwrap().as_bytes(),
		b"second ledger original"
	);
	assert!(scope.open(&first, &two).is_err());
	assert!(scope.open(&second, &one).is_err());
}
