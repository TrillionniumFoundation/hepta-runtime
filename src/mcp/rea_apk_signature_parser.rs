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

//! Bounded APK v2/v3 signature and chunked-content verification. Certificate
//! public keys are bound to their exact DER certificate; certificate trust,
//! Android SDK selection, lineage and installation rules remain unevaluated.

use anyhow::{bail, Context, Result};
use ring::signature;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeSet;
use std::fmt::Write as _;

const V2_ID: u32 = 0x7109_871a;
const V3_ID: u32 = 0xf053_68c0;
const V31_ID: u32 = 0x1b93_ad61;
const V32_ID: u32 = 0x70e1_c89f;
const SOURCE_STAMP_ID: u32 = 0x6dff_800d;
const ROTATION_ID: u32 = 0x3ba0_6f8c;
const STRIPPING_ID: u32 = 0xbeef_f00d;
pub(super) const MAX_BLOCK: usize = 16 * 1024 * 1024;
pub(super) const MAX_PAIRS: usize = 128;
pub(super) const MAX_SIGNERS: usize = 32;
pub(super) const MAX_CERTIFICATES: usize = 8;
pub(super) const MAX_CERTIFICATE: usize = 64 * 1024;
pub(super) const MAX_ALGORITHMS: usize = 32;
pub(super) const MAX_ATTRIBUTES: usize = 64;
const CHUNK: usize = 1024 * 1024;

pub(super) fn hex(bytes: &[u8]) -> String {
	let mut text = String::with_capacity(bytes.len().saturating_mul(2));
	for byte in bytes {
		let _ = write!(text, "{byte:02x}");
	}
	text
}

fn sha256(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

fn slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
	let end = offset.checked_add(length).context("APK extent overflow")?;
	bytes.get(offset..end).context("truncated APK structure")
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
	Ok(u16::from_le_bytes(slice(bytes, offset, 2)?.try_into()?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
	Ok(u32::from_le_bytes(slice(bytes, offset, 4)?.try_into()?))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
	Ok(u64::from_le_bytes(slice(bytes, offset, 8)?.try_into()?))
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
	bytes: &'a [u8],
	position: usize,
}

impl<'a> Cursor<'a> {
	fn new(bytes: &'a [u8]) -> Self {
		Self { bytes, position: 0 }
	}

	fn take(&mut self, length: usize) -> Result<&'a [u8]> {
		let result = slice(self.bytes, self.position, length)?;
		self.position += length;
		Ok(result)
	}

	fn u32(&mut self) -> Result<u32> {
		Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
	}

	fn prefixed(&mut self, max: usize) -> Result<&'a [u8]> {
		let length = usize::try_from(self.u32()?)?;
		if length > max {
			bail!("APK length-prefixed field exceeds its {max} byte budget");
		}
		self.take(length)
	}

	fn done(self) -> Result<()> {
		if self.position != self.bytes.len() {
			bail!("APK structure has unconsumed trailing bytes");
		}
		Ok(())
	}

	fn remaining(self) -> bool {
		self.position < self.bytes.len()
	}
}

struct ZipLayout {
	central: usize,
	eocd: usize,
	entry_count: usize,
	last_payload_end: usize,
	v1_markers: usize,
	manifest_present: bool,
}

/// APK signing defines three exact ZIP sections. Resolve a unique classic EOCD
/// and validate central/local header extents before trusting any section offset.
fn zip_layout(bytes: &[u8]) -> Result<ZipLayout> {
	if bytes.len() < 22 {
		bail!("APK is shorter than the ZIP end record");
	}
	let lower = bytes.len().saturating_sub(22 + u16::MAX as usize);
	let mut candidates = Vec::new();
	for offset in lower..=bytes.len() - 22 {
		if slice(bytes, offset, 4)? == b"PK\x05\x06"
			&& offset + 22 + usize::from(u16_at(bytes, offset + 20)?) == bytes.len()
		{
			candidates.push(offset);
		}
	}
	if candidates.len() != 1 {
		bail!("APK requires one unambiguous ZIP end record ending at EOF");
	}
	let eocd = candidates[0];
	if u16_at(bytes, eocd + 4)? != 0 || u16_at(bytes, eocd + 6)? != 0 {
		bail!("multi-volume APK ZIP is unsupported");
	}
	let entry_count = usize::from(u16_at(bytes, eocd + 10)?);
	if usize::from(u16_at(bytes, eocd + 8)?) != entry_count
		|| entry_count == u16::MAX as usize
		|| entry_count > 50_000
	{
		bail!("APK ZIP entry count is inconsistent, ZIP64 or exceeds 50000");
	}
	let central = usize::try_from(u32_at(bytes, eocd + 16)?)?;
	let directory_size = usize::try_from(u32_at(bytes, eocd + 12)?)?;
	if central == u32::MAX as usize
		|| directory_size == u32::MAX as usize
		|| (eocd >= 20 && slice(bytes, eocd - 20, 4)? == b"PK\x06\x07")
	{
		bail!("ZIP64 APK is unsupported");
	}
	if central.checked_add(directory_size) != Some(eocd) {
		bail!("APK ZIP central directory must end exactly at the end record");
	}
	let mut position = central;
	let mut last_payload_end = 0;
	let mut v1_markers = 0;
	let mut manifest_present = false;
	for _ in 0..entry_count {
		if slice(bytes, position, 4)? != b"PK\x01\x02" {
			bail!("invalid APK ZIP central-directory signature");
		}
		let fixed = slice(bytes, position, 46)?;
		let compressed = usize::try_from(u32_at(fixed, 20)?)?;
		let uncompressed = u32_at(fixed, 24)?;
		let local = usize::try_from(u32_at(fixed, 42)?)?;
		if compressed == u32::MAX as usize
			|| uncompressed == u32::MAX
			|| local == u32::MAX as usize
			|| u16_at(fixed, 34)? != 0
		{
			bail!("ZIP64 or split APK entry is unsupported");
		}
		let name_len = usize::from(u16_at(fixed, 28)?);
		let extra_len = usize::from(u16_at(fixed, 30)?);
		let comment_len = usize::from(u16_at(fixed, 32)?);
		let total = 46 + name_len + extra_len + comment_len;
		let record = slice(bytes, position, total)?;
		position = position
			.checked_add(total)
			.context("APK directory extent overflow")?;
		if position > eocd {
			bail!("APK entry exceeds central directory");
		}
		let name = &record[46..46 + name_len];
		manifest_present |= name == b"AndroidManifest.xml";
		let upper = name.iter().map(u8::to_ascii_uppercase).collect::<Vec<_>>();
		if upper.starts_with(b"META-INF/")
			&& [b".RSA".as_slice(), b".DSA", b".EC", b".SF"]
				.iter()
				.any(|suffix| upper.ends_with(suffix))
		{
			v1_markers += 1;
		}
		let local_header = slice(bytes, local, 30)?;
		if &local_header[..4] != b"PK\x03\x04"
			|| u16_at(local_header, 6)? != u16_at(fixed, 8)?
			|| u16_at(local_header, 8)? != u16_at(fixed, 10)?
		{
			bail!("APK local header disagrees with central directory");
		}
		let local_name = usize::from(u16_at(local_header, 26)?);
		let local_extra = usize::from(u16_at(local_header, 28)?);
		if slice(bytes, local + 30, local_name)? != name {
			bail!("APK local and central member names differ");
		}
		let payload_end = local
			.checked_add(30 + local_name + local_extra)
			.and_then(|start| start.checked_add(compressed))
			.context("APK payload extent overflow")?;
		if payload_end > central {
			bail!("APK local payload overlaps central directory");
		}
		last_payload_end = last_payload_end.max(payload_end);
	}
	if position != eocd {
		bail!("APK central-directory count does not consume its exact extent");
	}
	Ok(ZipLayout {
		central,
		eocd,
		entry_count,
		last_payload_end,
		v1_markers,
		manifest_present,
	})
}

struct Block<'a> {
	start: usize,
	pairs: Vec<(u32, &'a [u8])>,
}

fn signing_block<'a>(bytes: &'a [u8], zip: &ZipLayout) -> Result<Option<Block<'a>>> {
	if zip.central < 24 || slice(bytes, zip.central - 16, 16)? != b"APK Sig Block 42" {
		return Ok(None);
	}
	let size = usize::try_from(u64_at(bytes, zip.central - 24)?)?;
	if !(24..=MAX_BLOCK - 8).contains(&size) {
		bail!("APK signing block size is outside 32 bytes through 16 MiB");
	}
	let start = zip
		.central
		.checked_sub(size + 8)
		.context("APK signing block starts before file")?;
	if start < zip.last_payload_end || u64_at(bytes, start)? != size as u64 {
		bail!("APK signing block overlaps payload or size headers disagree");
	}
	let mut pairs = Vec::new();
	let mut seen = BTreeSet::new();
	let mut position = start + 8;
	while position < zip.central - 24 {
		if pairs.len() >= MAX_PAIRS {
			bail!("APK signing block exceeds 128 ID pairs");
		}
		if zip.central - 24 - position < 8 {
			bail!("truncated APK signing-block pair length");
		}
		let length = usize::try_from(u64_at(bytes, position)?)?;
		position = position
			.checked_add(8)
			.context("APK pair offset overflow")?;
		if length < 4 || length > zip.central - 24 - position {
			bail!("APK signing-block pair has invalid length");
		}
		let id = u32_at(bytes, position)?;
		if !seen.insert(id) {
			bail!("APK signing block contains duplicate ID pairs");
		}
		pairs.push((id, slice(bytes, position + 4, length - 4)?));
		position += length;
	}
	if position != zip.central - 24 {
		bail!("APK signing-block pairs do not consume exact block extent");
	}
	Ok(Some(Block { start, pairs }))
}

fn chunked_digest<D: Digest + Default>(
	bytes: &[u8],
	zip: &ZipLayout,
	block_start: usize,
) -> Result<Vec<u8>> {
	let mut end_record = bytes[zip.eocd..].to_vec();
	end_record[16..20].copy_from_slice(&u32::try_from(block_start)?.to_le_bytes());
	let sections = [
		&bytes[..block_start],
		&bytes[zip.central..zip.eocd],
		&end_record,
	];
	let count = sections
		.iter()
		.map(|section| section.len().div_ceil(CHUNK))
		.sum::<usize>();
	let mut result = D::new();
	result.update([0x5a]);
	result.update(u32::try_from(count)?.to_le_bytes());
	for section in sections {
		for chunk in section.chunks(CHUNK) {
			let mut digest = D::new();
			digest.update([0xa5]);
			digest.update(u32::try_from(chunk.len())?.to_le_bytes());
			digest.update(chunk);
			result.update(digest.finalize());
		}
	}
	Ok(result.finalize().to_vec())
}

/// DER is parsed only far enough to bind the certificate's SPKI. Canonical
/// definite lengths and complete envelopes prevent ambiguous key extraction.
#[derive(Clone, Copy)]
struct Der<'a> {
	tag: u8,
	content: &'a [u8],
	full: &'a [u8],
}

fn der_next<'a>(cursor: &mut Cursor<'a>) -> Result<Der<'a>> {
	let start = cursor.position;
	let tag = cursor.take(1)?[0];
	if tag & 0x1f == 0x1f {
		bail!("high-tag-number DER is outside the certificate-key subset");
	}
	let first = cursor.take(1)?[0];
	let length = if first < 128 {
		usize::from(first)
	} else {
		let count = usize::from(first & 0x7f);
		if count == 0 || count > 4 {
			bail!("indefinite or excessive DER length");
		}
		let encoded = cursor.take(count)?;
		if encoded[0] == 0 {
			bail!("non-canonical DER length");
		}
		let mut length = 0usize;
		for byte in encoded {
			length = length
				.checked_mul(256)
				.and_then(|n| n.checked_add(usize::from(*byte)))
				.context("DER length overflow")?;
		}
		if length < 128 {
			bail!("non-minimal DER length");
		}
		length
	};
	let content = cursor.take(length)?;
	Ok(Der {
		tag,
		content,
		full: &cursor.bytes[start..cursor.position],
	})
}

fn der_tag<'a>(cursor: &mut Cursor<'a>, tag: u8) -> Result<Der<'a>> {
	let item = der_next(cursor)?;
	if item.tag != tag {
		bail!("unexpected DER tag in certificate public-key structure");
	}
	Ok(item)
}

fn der_envelope(bytes: &[u8], tag: u8) -> Result<Der<'_>> {
	let mut cursor = Cursor::new(bytes);
	let item = der_tag(&mut cursor, tag)?;
	cursor.done()?;
	Ok(item)
}

fn certificate_spki(bytes: &[u8]) -> Result<&[u8]> {
	let certificate = der_envelope(bytes, 0x30)?;
	let mut outer = Cursor::new(certificate.content);
	let tbs = der_tag(&mut outer, 0x30)?;
	der_tag(&mut outer, 0x30)?;
	let certificate_signature = der_tag(&mut outer, 0x03)?;
	if certificate_signature.content.is_empty() || certificate_signature.content[0] > 7 {
		bail!("invalid certificate signature bit string");
	}
	outer.done()?;
	let mut fields = Cursor::new(tbs.content);
	if fields.bytes.first() == Some(&0xa0) {
		let version = der_tag(&mut fields, 0xa0)?;
		let version = der_envelope(version.content, 0x02)?;
		if version.content.len() != 1 || version.content[0] > 2 {
			bail!("unsupported X.509 certificate version");
		}
	}
	let serial = der_tag(&mut fields, 0x02)?;
	if serial.content.is_empty() {
		bail!("empty X.509 serial number");
	}
	for _ in 0..4 {
		der_tag(&mut fields, 0x30)?;
	}
	let spki = der_tag(&mut fields, 0x30)?;
	// Optional unique IDs/extensions must remain bounded DER envelopes. Their
	// semantics, the issuer signature and certificate dates are not evaluated.
	let mut last_tag = 0;
	while fields.remaining() {
		let optional = der_next(&mut fields)?;
		let order = match optional.tag {
			0x81 => 1,
			0x82 => 2,
			0xa3 => 3,
			_ => bail!("unexpected trailing certificate field"),
		};
		if order <= last_tag {
			bail!("duplicate or out-of-order certificate optional field");
		}
		last_tag = order;
	}
	Ok(spki.full)
}

#[derive(Clone, Copy)]
enum PublicKey<'a> {
	Rsa(&'a [u8]),
	P256(&'a [u8]),
	P384(&'a [u8]),
	Unsupported,
}

fn public_key(bytes: &[u8]) -> Result<PublicKey<'_>> {
	let key = der_envelope(bytes, 0x30)?;
	let mut cursor = Cursor::new(key.content);
	let algorithm = der_tag(&mut cursor, 0x30)?;
	let bits = der_tag(&mut cursor, 0x03)?;
	cursor.done()?;
	if bits.content.first() != Some(&0) {
		bail!("APK public key BIT STRING must have zero unused bits");
	}
	let mut alg = Cursor::new(algorithm.content);
	let oid = der_tag(&mut alg, 0x06)?.content;
	let encoded = &bits.content[1..];
	match oid {
		b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" => {
			if alg.remaining() && !der_tag(&mut alg, 0x05)?.content.is_empty() {
				bail!("invalid RSA NULL parameters");
			}
			alg.done()?;
			let rsa = der_envelope(encoded, 0x30)?;
			let mut integers = Cursor::new(rsa.content);
			let mut modulus_bits = 0;
			let mut exponent_supported = false;
			for index in 0..2 {
				let value = der_tag(&mut integers, 0x02)?.content;
				if value.is_empty()
					|| value[0] & 0x80 != 0
					|| (value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0)
				{
					bail!("non-canonical positive RSA INTEGER");
				}
				let first = value
					.iter()
					.position(|byte| *byte != 0)
					.context("zero RSA component")?;
				let bit_length =
					(value.len() - first - 1) * 8 + 8 - value[first].leading_zeros() as usize;
				if index == 0 {
					modulus_bits = bit_length;
				} else {
					if bit_length < 2 || value[value.len() - 1] & 1 == 0 {
						bail!("RSA public exponent must be odd and at least three");
					}
					// ring 0.17.14 bounds verification exponents to 3..2^33-1.
					// A valid larger exponent is unsupported, not a bad signature.
					exponent_supported = bit_length <= 33;
				}
			}
			integers.done()?;
			Ok(
				if (2048..=8192).contains(&modulus_bits) && exponent_supported {
					PublicKey::Rsa(encoded)
				} else {
					PublicKey::Unsupported
				},
			)
		}
		b"\x2a\x86\x48\xce\x3d\x02\x01" => {
			let curve = der_tag(&mut alg, 0x06)?.content;
			alg.done()?;
			Ok(match curve {
				b"\x2a\x86\x48\xce\x3d\x03\x01\x07" => PublicKey::P256(encoded),
				b"\x2b\x81\x04\x00\x22" => PublicKey::P384(encoded),
				_ => PublicKey::Unsupported,
			})
		}
		_ => Ok(PublicKey::Unsupported),
	}
}

fn verify_signature(
	key: PublicKey<'_>,
	algorithm: u32,
	message: &[u8],
	signature_bytes: &[u8],
) -> Option<bool> {
	let (public, verification): (&[u8], &dyn signature::VerificationAlgorithm) =
		match (key, algorithm) {
			(PublicKey::Rsa(key), 0x0101) => (key, &signature::RSA_PSS_2048_8192_SHA256),
			(PublicKey::Rsa(key), 0x0102) => (key, &signature::RSA_PSS_2048_8192_SHA512),
			(PublicKey::Rsa(key), 0x0103) => (key, &signature::RSA_PKCS1_2048_8192_SHA256),
			(PublicKey::Rsa(key), 0x0104) => (key, &signature::RSA_PKCS1_2048_8192_SHA512),
			(PublicKey::P256(key), 0x0201) => (key, &signature::ECDSA_P256_SHA256_ASN1),
			(PublicKey::P384(key), 0x0201) => (key, &signature::ECDSA_P384_SHA256_ASN1),
			(PublicKey::Unsupported, _) | (_, 0x0202 | 0x0301 | 0x0421 | 0x0423 | 0x0425) => {
				return None
			}
			(_, 0x0101..=0x0104 | 0x0201) => return Some(false),
			_ => return None,
		};
	Some(
		signature::UnparsedPublicKey::new(verification, public)
			.verify(message, signature_bytes)
			.is_ok(),
	)
}

fn algorithm_name(id: u32) -> &'static str {
	match id {
		0x0101 => "rsa_pss_sha256",
		0x0102 => "rsa_pss_sha512",
		0x0103 => "rsa_pkcs1_v1_5_sha256",
		0x0104 => "rsa_pkcs1_v1_5_sha512",
		0x0201 => "ecdsa_sha256",
		0x0202 => "ecdsa_sha512",
		0x0301 => "dsa_sha256",
		0x0421 => "verity_rsa_pkcs1_sha256",
		0x0423 => "verity_ecdsa_sha256",
		0x0425 => "verity_dsa_sha256",
		_ => "unknown",
	}
}

fn records(bytes: &[u8], max_data: usize) -> Result<Vec<(u32, &[u8])>> {
	let mut cursor = Cursor::new(bytes);
	let mut result = Vec::new();
	let mut seen = BTreeSet::new();
	while cursor.remaining() {
		if result.len() >= MAX_ALGORITHMS {
			bail!("APK signer exceeds 32 algorithm records");
		}
		let mut record = Cursor::new(cursor.prefixed(max_data + 8)?);
		let id = record.u32()?;
		if !seen.insert(id) {
			bail!("APK signer has duplicate algorithm records");
		}
		let payload = record.prefixed(max_data)?;
		record.done()?;
		result.push((id, payload));
	}
	if result.is_empty() {
		bail!("APK signer has no algorithm records");
	}
	Ok(result)
}

struct Signer<'a> {
	signed_data: &'a [u8],
	signed_data_tail: &'a [u8],
	digests: Vec<(u32, &'a [u8])>,
	signatures: Vec<(u32, &'a [u8])>,
	certificates: Vec<&'a [u8]>,
	attributes: Vec<(u32, &'a [u8])>,
	public_key: &'a [u8],
	sdk: Option<(u32, u32)>,
	sdk_matches: bool,
}

fn signers<'a>(bytes: &'a [u8], v3: bool) -> Result<Vec<Signer<'a>>> {
	let mut outer = Cursor::new(bytes);
	let mut list = Cursor::new(outer.prefixed(MAX_BLOCK)?);
	outer.done()?;
	let mut result = Vec::new();
	while list.remaining() {
		if result.len() >= MAX_SIGNERS {
			bail!("APK scheme exceeds 32 signers");
		}
		let mut signer = Cursor::new(list.prefixed(MAX_BLOCK)?);
		let signed_data = signer.prefixed(MAX_BLOCK)?;
		let sdk = if v3 {
			Some((signer.u32()?, signer.u32()?))
		} else {
			None
		};
		let signatures = records(signer.prefixed(MAX_BLOCK)?, 16 * 1024)?;
		let public_key = signer.prefixed(MAX_CERTIFICATE)?;
		signer.done()?;
		let mut data = Cursor::new(signed_data);
		let digests = records(data.prefixed(MAX_BLOCK)?, 128)?;
		if signatures
			.iter()
			.map(|r| r.0)
			.ne(digests.iter().map(|r| r.0))
		{
			bail!("APK signature and digest algorithm sequences disagree");
		}
		let mut certificates = Vec::new();
		let mut certs = Cursor::new(data.prefixed(MAX_BLOCK)?);
		while certs.remaining() {
			if certificates.len() >= MAX_CERTIFICATES {
				bail!("APK signer exceeds eight certificates");
			}
			certificates.push(certs.prefixed(MAX_CERTIFICATE)?);
		}
		if certificates.is_empty() {
			bail!("APK signer has no certificates");
		}
		let signed_sdk = if v3 {
			Some((data.u32()?, data.u32()?))
		} else {
			None
		};
		let mut attrs = Cursor::new(data.prefixed(MAX_BLOCK)?);
		// Android signers may append reserved bytes; the complete signed_data
		// remains covered by the signature. Preserve their uninterpreted extent.
		let signed_data_tail = &data.bytes[data.position..];
		let mut attributes = Vec::new();
		let mut seen = BTreeSet::new();
		while attrs.remaining() {
			if attributes.len() >= MAX_ATTRIBUTES {
				bail!("APK signer exceeds 64 additional attributes");
			}
			let mut attr = Cursor::new(attrs.prefixed(MAX_BLOCK)?);
			let id = attr.u32()?;
			if !seen.insert(id) {
				bail!("APK signer has duplicate additional attributes");
			}
			attributes.push((id, &attr.bytes[attr.position..]));
		}
		result.push(Signer {
			signed_data,
			signed_data_tail,
			digests,
			signatures,
			certificates,
			attributes,
			public_key,
			sdk,
			sdk_matches: sdk == signed_sdk && sdk.is_none_or(|(min, max)| min <= max),
		});
	}
	if result.is_empty() {
		bail!("APK signature scheme has no signers");
	}
	Ok(result)
}

fn signer_report(
	signer: &Signer<'_>,
	scheme: &str,
	ordinal: usize,
	source: &str,
	sha256_digest: &[u8],
	sha512_digest: &[u8],
	has_v3: bool,
) -> Result<Value> {
	let key = public_key(signer.public_key)?;
	let mut certificates = Vec::new();
	let mut key_matches = false;
	for (index, certificate) in signer.certificates.iter().enumerate() {
		let spki = certificate_spki(certificate)?;
		if index == 0 {
			key_matches = spki == signer.public_key;
		}
		certificates.push(json!({"ordinal":index,"sha256":sha256(certificate),
			"byte_length":certificate.len(),"subject_public_key_info_sha256":sha256(spki)}));
	}
	let mut invalid = !key_matches || !signer.sdk_matches;
	let mut unsupported = false;
	let mut algorithms = Vec::new();
	for ((id, declared), (_, signed)) in signer.digests.iter().zip(&signer.signatures) {
		let computed = match id {
			0x0101 | 0x0103 | 0x0201 | 0x0301 => Some(sha256_digest),
			0x0102 | 0x0104 | 0x0202 => Some(sha512_digest),
			_ => None,
		};
		let content = computed.map(|value| value == *declared);
		let verified = verify_signature(key, *id, signer.signed_data, signed);
		invalid |= verified == Some(false) || content == Some(false);
		unsupported |= verified.is_none() || content.is_none();
		algorithms.push(json!({"id":format!("0x{id:08x}"),"name":algorithm_name(*id),
			"signature_status":match verified {Some(true)=>"verified",Some(false)=>"invalid",None=>"unsupported"},
			"content_digest_status":match content {Some(true)=>"match",Some(false)=>"mismatch",None=>"unsupported"},
			"declared_digest":hex(declared),"computed_digest":computed.map(hex),"signature_bytes":signed.len()}));
	}
	let mut attributes = Vec::new();
	for (id, value) in &signer.attributes {
		let meaning = match *id {
			ROTATION_ID => "proof_of_rotation_present_unverified",
			STRIPPING_ID if scheme == "v2" => {
				if value.len() != 4 {
					bail!("APK v2 stripping-protection attribute must contain one u32");
				}
				let required = u32_at(value, 0)?;
				if required == 3 && !has_v3 {
					invalid = true;
				}
				if required != 3 {
					unsupported = true;
				}
				if required == 3 && has_v3 {
					"v3_presence_requirement_met"
				} else if required == 3 {
					"v3_presence_requirement_missing"
				} else {
					"unknown_scheme_requirement_unverified"
				}
			}
			_ => "signed_bytes_preserved_semantics_unverified",
		};
		attributes.push(json!({"id":format!("0x{id:08x}"),"byte_length":value.len(),"sha256":sha256(value),"interpretation":meaning}));
	}
	Ok(
		json!({"id":format!("apksig-v1:{source}:{scheme}:{ordinal}"),"scheme":scheme,"ordinal":ordinal,
		"status":if invalid {"invalid"} else if unsupported {"partial"} else {"verified"},
		"signed_data_sha256":sha256(signer.signed_data),"public_key_sha256":sha256(signer.public_key),
		"public_key_bytes":signer.public_key.len(),"uninterpreted_signed_data_bytes":signer.signed_data_tail.len(),
		"uninterpreted_signed_data_sha256":sha256(signer.signed_data_tail),
		"certificate_public_key_binding":if key_matches {"match"} else {"mismatch"},
		"sdk_range":signer.sdk.map(|(min,max)|json!({"min":min,"max":max})),
		"signed_and_unsigned_sdk_ranges_match":signer.sdk_matches,
		"certificates":certificates,"algorithms":algorithms,"additional_attributes":attributes,
		"certificate_trust":"not_evaluated","certificate_signature_and_dates":"not_evaluated",
		"rotation_lineage":if signer.attributes.iter().any(|(id,_)|*id==ROTATION_ID) {"present_unverified"} else {"absent"}}),
	)
}

/// Preserve declared facts that do not meet the additional verifier's stricter
/// subset. Its failure is explicit and can never become a verification pass.
pub(super) fn inspect_with_observations(bytes: &[u8]) -> Result<Value> {
	let observation = super::observation::inspect(bytes)?;
	let mut report = match inspect(bytes) {
		Ok(mut report) => {
			report["cryptographic_inspection"] = json!({"status":"completed","error":null});
			report
		}
		Err(error) => json!({
			"record_format":"hepta.rea-apk-signature.v1","rea_evidence_compatible":false,
			"source":{"sha256":observation.result.artifact.sha256,"byte_length":bytes.len(),"identity_scope":"complete_captured_archive"},
			"cryptographic_inspection":{"status":"not_performed","error":error.to_string()},
			"verification":{"scope":"extra_verifier_did_not_complete","v2_v3_records":"not_performed",
				"complete_android_verification":false,"android_installability":"not_evaluated"},
			"limitations":["The static declaration report is independent of the additional native cryptographic verifier. That verifier did not complete for this input; no signature, trusted identity or Android acceptance is established."]
		}),
	};
	report["static_inspection"] = serde_json::to_value(observation)?;
	Ok(report)
}

pub(super) fn inspect(bytes: &[u8]) -> Result<Value> {
	if bytes.is_empty() || bytes.len() > super::MAX_APK_BYTES {
		bail!("APK signature input must contain 1 byte through 128 MiB");
	}
	let source = sha256(bytes);
	let zip = zip_layout(bytes)?;
	let block = signing_block(bytes, &zip)?;
	let mut signer_rows = Vec::new();
	let mut pair_rows = Vec::new();
	let mut has_v31 = false;
	let mut has_v32 = false;
	let mut has_stamp = false;
	let mut computed = Value::Null;
	if let Some(block) = &block {
		let d256 = chunked_digest::<Sha256>(bytes, &zip, block.start)?;
		let d512 = chunked_digest::<Sha512>(bytes, &zip, block.start)?;
		computed = json!({"chunked_sha256":hex(&d256),"chunked_sha512":hex(&d512)});
		let has_v3 = block.pairs.iter().any(|(id, _)| *id == V3_ID);
		for (id, value) in &block.pairs {
			has_v31 |= *id == V31_ID;
			has_v32 |= *id == V32_ID;
			has_stamp |= *id == SOURCE_STAMP_ID;
			pair_rows.push(
				json!({"id":format!("0x{id:08x}"),"byte_length":value.len(),"sha256":sha256(value)}),
			);
			let scheme = match *id {
				V2_ID => "v2",
				V3_ID => "v3",
				_ => continue,
			};
			for (ordinal, signer) in signers(value, *id == V3_ID)?.iter().enumerate() {
				signer_rows.push(signer_report(
					signer, scheme, ordinal, &source, &d256, &d512, has_v3,
				)?);
			}
		}
	}
	let status = if signer_rows.is_empty() {
		"absent"
	} else if signer_rows.iter().any(|row| row["status"] == "invalid") {
		"invalid"
	} else if signer_rows.iter().any(|row| row["status"] == "partial") {
		"partial"
	} else {
		"verified"
	};
	let lineage = signer_rows
		.iter()
		.any(|row| row["rotation_lineage"] == "present_unverified");
	Ok(json!({
		"record_format":"hepta.rea-apk-signature.v1","rea_evidence_compatible":false,
		"source":{"sha256":source,"byte_length":bytes.len(),"identity_scope":"complete_captured_archive"},
		"zip":{"entry_count":zip.entry_count,"central_directory_offset":zip.central,"eocd_offset":zip.eocd,
			"android_manifest_entry_present":zip.manifest_present,"legacy_signature_marker_count":zip.v1_markers},
		"signing_block":{"present":block.is_some(),"offset":block.as_ref().map(|b|b.start),"pairs":pair_rows},
		"computed_content_digests":computed,"signers":signer_rows,
		"verification":{"scope":"supported_signature_records_and_content_digests_only","v2_v3_records":status,"v1":if zip.v1_markers>0 {"markers_present_unverified"}else{"markers_absent"},
			"v3_1":if has_v31 {"present_unverified"}else{"absent"},
			"v3_2":if has_v32 {"present_unverified"}else{"absent"},
			"rotation_lineage":if lineage {"present_unverified"}else if has_v31 || has_v32 {"newer_scheme_not_examined"}else{"absent"},
			"source_stamp":if has_stamp {"present_unverified"}else{"absent"},"v4":"external_idsig_not_examined",
			"android_sdk_scheme_selection":"not_evaluated","android_installability":"not_evaluated",
			"certificate_identity_or_trust":"not_evaluated","complete_android_verification":false},
		"coverage":{"signature_algorithms":["RSA-PSS SHA-256/SHA-512 (2048..8192 bits, odd exponent 3..2^33-1, digest-length salt)",
			"RSA PKCS#1 v1.5 SHA-256/SHA-512 (2048..8192 bits, odd exponent 3..2^33-1)","ECDSA SHA-256 (P-256/P-384, ASN.1)"],
			"digest_algorithms":["APK 1 MiB chunked SHA-256","APK 1 MiB chunked SHA-512"],
			"certificate_parsing":"bounded DER envelope and exact leaf subjectPublicKeyInfo binding",
			"v2_v3_semantics":"all declared supported signature records; exact digest/signature algorithm order; v3 SDK copy agreement; v2 v3-presence stripping attribute"},
		"budgets":{"archive_max_bytes":super::MAX_APK_BYTES,"signing_block_max_bytes":MAX_BLOCK,
			"max_scheme_signers":MAX_SIGNERS,"max_signer_certificates":MAX_CERTIFICATES,
			"max_certificate_bytes":MAX_CERTIFICATE,"max_signer_algorithms":MAX_ALGORITHMS,"max_block_id_pairs":MAX_PAIRS},
		"limitations":[
			"Verified means mathematical self-consistency of the supported v2/v3 records with these exact captured bytes and their leaf certificate public key. It does not establish trusted signer identity or Android installation acceptance.",
			"v1 JAR signatures and per-entry coverage, v3.1, v3.2, v4 idsig, proof-of-rotation and source-stamp signatures are not verified. Presence never upgrades their verification status.",
			"DSA, ECDSA SHA-512, verity digests and unknown algorithms are explicitly unsupported. All declared supported records are checked; Android strongest-algorithm and SDK selection rules are not implemented.",
			"Certificate parsing extracts and binds the leaf public key; issuer signatures, validity periods, extensions, revocation and chain trust are not evaluated.",
			"Only bounded classic single-volume ZIP is admitted. Manifest/resource semantics, entry decompression/CRC and code execution are outside this operation.",
			"Native record and signer IDs are not REA Evidence or retained analysis-view compatibility. No package is executed, installed, extracted or fetched."
		]
	}))
}
