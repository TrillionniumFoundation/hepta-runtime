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

//! Bounded BER framing and one owner of raw-certificate identity. Parsed X.509
//! display facts never imply a verified issuer, valid date or trusted signer.

use super::{fingerprint, CertificateFacts};
use std::fmt::Write as _;
use x509_parser::asn1_rs::FromDer;
use x509_parser::certificate::X509CertificateParser;
use x509_parser::nom::Parser;
use x509_parser::num_bigint::{BigInt, BigUint};
use x509_parser::time::ASN1Time;
use x509_parser::x509::X509Name;

#[path = "rea_apk_signature_public_key.rs"]
mod public_key;

pub(super) const MAX_ASN1_NODES: usize = 65_536;
const MAX_ASN1_DEPTH: usize = 32;

#[derive(Debug)]
pub(super) struct BerFailure {
	pub detail: String,
	pub exhausted_nodes: bool,
}

impl BerFailure {
	pub fn malformed(detail: impl Into<String>) -> Self {
		Self {
			detail: detail.into(),
			exhausted_nodes: false,
		}
	}
}

pub(super) type BerResult<T> = Result<T, BerFailure>;

pub(super) struct Node<'a> {
	pub tag: u8,
	pub content_start: usize,
	pub content_end: usize,
	pub end: usize,
	pub full: &'a [u8],
	pub content: &'a [u8],
	pub children: Vec<Node<'a>>,
	canonical_length: bool,
}

pub(super) struct BerReader<'a> {
	bytes: &'a [u8],
	remaining: usize,
}

impl<'a> BerReader<'a> {
	pub fn new(bytes: &'a [u8]) -> Self {
		Self {
			bytes,
			remaining: MAX_ASN1_NODES,
		}
	}

	pub fn read(&mut self, at: usize, end: usize, depth: usize) -> BerResult<Node<'a>> {
		if depth > MAX_ASN1_DEPTH {
			return Err(BerFailure::malformed("ASN.1 nesting exceeds 32 levels."));
		}
		if self.remaining == 0 {
			return Err(BerFailure {
				detail: "ASN.1 value count exceeds the 65536-node budget.".into(),
				exhausted_nodes: true,
			});
		}
		self.remaining -= 1;
		if end > self.bytes.len() || at >= end || end - at < 2 {
			return Err(BerFailure::malformed("Truncated ASN.1 tag or length."));
		}
		let tag = self.bytes[at];
		if tag & 0x1f == 0x1f {
			return Err(BerFailure::malformed(format!(
				"High-tag-number form at byte {at} is unsupported."
			)));
		}
		if tag == 0 {
			return Err(BerFailure::malformed(
				"Unexpected end-of-contents marker outside an indefinite value.",
			));
		}
		let constructed = tag & 0x20 != 0;
		let first = self.bytes[at + 1];
		let indefinite = first == 0x80;
		let mut cursor = at + 2;
		let mut length = 0usize;
		let mut canonical_length = !indefinite;
		if indefinite {
			if !constructed {
				return Err(BerFailure::malformed(
					"Primitive ASN.1 values cannot use indefinite length.",
				));
			}
		} else if first < 128 {
			length = first as usize;
		} else {
			let width = (first & 0x7f) as usize;
			if width > 4 {
				return Err(BerFailure::malformed(
					"Unsupported ASN.1 long-form length width.",
				));
			}
			if width > end - cursor {
				return Err(BerFailure::malformed("Truncated ASN.1 long length."));
			}
			canonical_length &= self.bytes[cursor] != 0;
			for byte in &self.bytes[cursor..cursor + width] {
				length = length * 256 + *byte as usize;
			}
			cursor += width;
			canonical_length &= length >= 128;
		}
		let content_start = cursor;
		let content_end;
		let encoded_end;
		let mut children = Vec::new();
		if indefinite {
			loop {
				if cursor >= end {
					return Err(BerFailure::malformed(
						"Indefinite ASN.1 value has no end-of-contents marker.",
					));
				}
				if end - cursor >= 2 && self.bytes[cursor..cursor + 2] == [0, 0] {
					content_end = cursor;
					encoded_end = cursor + 2;
					break;
				}
				let child = self.read(cursor, end, depth + 1)?;
				cursor = child.end;
				children.push(child);
			}
		} else {
			content_end = cursor
				.checked_add(length)
				.ok_or_else(|| BerFailure::malformed("ASN.1 value exceeds its parent."))?;
			if content_end > end {
				return Err(BerFailure::malformed("ASN.1 value exceeds its parent."));
			}
			encoded_end = content_end;
			if constructed {
				while cursor < content_end {
					let child = self.read(cursor, content_end, depth + 1)?;
					cursor = child.end;
					children.push(child);
				}
			}
		}
		Ok(Node {
			tag,
			content_start,
			content_end,
			end: encoded_end,
			full: &self.bytes[at..encoded_end],
			content: &self.bytes[content_start..content_end],
			children,
			canonical_length,
		})
	}
}

pub(super) fn expect<'a, 'b>(
	node: Option<&'b Node<'a>>,
	tag: u8,
	what: &str,
) -> BerResult<&'b Node<'a>> {
	let node = node.ok_or_else(|| BerFailure::malformed(format!("{what} is missing")))?;
	if node.tag != tag {
		return Err(BerFailure::malformed(format!(
			"{what} has tag 0x{:x}, expected 0x{tag:x}",
			node.tag
		)));
	}
	Ok(node)
}

pub(super) fn oid(bytes: &[u8]) -> BerResult<String> {
	if bytes.is_empty() || bytes.len() > 64 {
		return Err(BerFailure::malformed(format!(
			"object identifier of {} bytes",
			bytes.len()
		)));
	}
	let mut arcs = Vec::new();
	let mut value = BigUint::from(0u8);
	for (index, byte) in bytes.iter().enumerate() {
		value = (value << 7) | BigUint::from(byte & 0x7f);
		if byte & 0x80 != 0 {
			if index == bytes.len() - 1 {
				return Err(BerFailure::malformed("object identifier is truncated"));
			}
			continue;
		}
		if arcs.is_empty() {
			let first = if value < BigUint::from(40u8) {
				0u8
			} else if value < BigUint::from(80u8) {
				1
			} else {
				2
			};
			arcs.push(first.to_string());
			arcs.push((&value - BigUint::from(first * 40)).to_string());
		} else {
			arcs.push(value.to_string());
		}
		value = BigUint::from(0u8);
	}
	Ok(arcs.join("."))
}

pub(super) fn algorithm_oid(node: Option<&Node<'_>>, what: &str) -> BerResult<String> {
	let node = expect(node, 0x30, what)?;
	oid(expect(node.children.first(), 0x06, &format!("{what} algorithm"))?.content)
}

fn der_tree(node: &Node<'_>) -> bool {
	if !node.canonical_length {
		return false;
	}
	if node.tag == 0x02
		&& (node.content.is_empty()
			|| (node.content.len() > 1
				&& ((node.content[0] == 0 && node.content[1] & 0x80 == 0)
					|| (node.content[0] == 0xff && node.content[1] & 0x80 != 0))))
	{
		return false;
	}
	node.children.iter().all(der_tree)
}

fn directory_string(tag: u8, bytes: &[u8]) -> Option<String> {
	match tag {
		0x0c => std::str::from_utf8(bytes).ok().map(str::to_owned),
		0x12 | 0x13 | 0x14 | 0x16 | 0x1a | 0x1b => {
			Some(bytes.iter().map(|byte| char::from(*byte)).collect())
		}
		0x1e if bytes.len().is_multiple_of(2) => {
			let units = bytes
				.as_chunks::<2>()
				.0
				.iter()
				.map(|c| u16::from_be_bytes([c[0], c[1]]))
				.collect::<Vec<_>>();
			String::from_utf16(&units).ok()
		}
		0x1c if bytes.len().is_multiple_of(4) => bytes
			.as_chunks::<4>()
			.0
			.iter()
			.map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
			.collect(),
		_ => None,
	}
}

fn object_name(id: &str) -> &str {
	match id {
		"2.5.4.3" => "CN",
		"2.5.4.4" => "SN",
		"2.5.4.5" => "serialNumber",
		"2.5.4.6" => "C",
		"2.5.4.7" => "L",
		"2.5.4.8" => "ST",
		"2.5.4.9" => "street",
		"2.5.4.10" => "O",
		"2.5.4.11" => "OU",
		"2.5.4.12" => "title",
		"2.5.4.13" => "description",
		"2.5.4.15" => "businessCategory",
		"2.5.4.16" => "postalAddress",
		"2.5.4.17" => "postalCode",
		"2.5.4.20" => "telephoneNumber",
		"2.5.4.41" => "name",
		"2.5.4.42" => "GN",
		"2.5.4.43" => "initials",
		"2.5.4.44" => "generationQualifier",
		"2.5.4.45" => "x500UniqueIdentifier",
		"2.5.4.46" => "dnQualifier",
		"2.5.4.65" => "pseudonym",
		"2.5.4.97" => "organizationIdentifier",
		"1.2.840.113549.1.9.1" => "emailAddress",
		"0.9.2342.19200300.100.1.1" => "UID",
		"0.9.2342.19200300.100.1.25" => "DC",
		"1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionL",
		"1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionST",
		"1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionC",
		_ => id,
	}
}

fn escape_name(text: &str) -> String {
	let mut out = String::new();
	for (at, c) in text.char_indices() {
		if c.is_ascii_control() {
			let _ = write!(out, "\\{:02X}", c as u32);
		} else {
			if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
				|| (c == '#' && at == 0)
				|| (c == ' ' && (at == 0 || at + 1 == text.len()))
			{
				out.push('\\');
			}
			out.push(c);
		}
	}
	out
}

fn name_text(name: &X509Name<'_>) -> Option<String> {
	let mut rdns = Vec::new();
	for rdn in name.iter_rdn() {
		let mut attrs = Vec::new();
		for attribute in rdn.iter() {
			let id = attribute.attr_type().to_id_string();
			let any = attribute.attr_value();
			let value = directory_string(any.tag().0 as u8, any.data)?;
			attrs.push(format!("{}={}", object_name(&id), escape_name(&value)));
		}
		rdns.push(attrs.join(" + "));
	}
	Some(rdns.join("\n"))
}

fn serial_text(raw: &[u8]) -> Option<String> {
	if raw.is_empty() {
		return None;
	}
	let value = BigInt::from_signed_bytes_be(raw)
		.to_str_radix(16)
		.to_uppercase();
	if value == "0" {
		return Some(value);
	}
	let (sign, magnitude) = value
		.strip_prefix('-')
		.map_or(("", value.as_str()), |m| ("-", m));
	Some(format!(
		"{sign}{}{magnitude}",
		if magnitude.len() % 2 == 1 { "0" } else { "" }
	))
}

fn iso_date(value: ASN1Time) -> Option<String> {
	// Parsing preserves the encoded offset. Reconstruct from the absolute epoch
	// before emitting a Z suffix, including offsets that cross a calendar day.
	let value = ASN1Time::from_timestamp(value.timestamp())
		.ok()?
		.to_datetime();
	// The platform X.509 date conversion used by the frozen producer drops any
	// ASN.1 fractional seconds before constructing the ECMAScript Date.
	Some(format!(
		"{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
		value.year(),
		value.month() as u8,
		value.day(),
		value.hour(),
		value.minute(),
		value.second()
	))
}

fn der_value(tag: u8, bytes: &[u8]) -> Vec<u8> {
	let mut out = vec![tag];
	if bytes.len() < 128 {
		out.push(bytes.len() as u8);
	} else {
		let encoded = bytes.len().to_be_bytes();
		let first = encoded.iter().position(|b| *b != 0).unwrap_or(0);
		out.push(0x80 | (encoded.len() - first) as u8);
		out.extend_from_slice(&encoded[first..]);
	}
	out.extend_from_slice(bytes);
	out
}

/// x509-parser rejects GeneralizedTime offsets accepted by the producer's
/// platform decoder. Normalize only that known encoding for the parser, while
/// every reported identity continues to hash the original selected DER bytes.
fn normalize_offset_dates(root: &Node<'_>) -> Option<Vec<u8>> {
	let tbs = root.children.first()?;
	let offset = usize::from(tbs.children.first()?.tag == 0xa0);
	let validity_index = offset + 3;
	let validity = tbs.children.get(validity_index)?;
	if validity.tag != 0x30 || validity.children.len() != 2 {
		return None;
	}
	let mut changed = false;
	let mut dates = Vec::new();
	for node in &validity.children {
		let bytes = node.content;
		let suffix = bytes.len().checked_sub(5)?;
		if node.tag != 0x18 || !matches!(bytes.get(suffix), Some(b'+' | b'-')) {
			dates.extend_from_slice(node.full);
			continue;
		}
		if !bytes[suffix + 1..].iter().all(u8::is_ascii_digit) {
			return None;
		}
		let hours = (bytes[suffix + 1] - b'0') as i64 * 10 + (bytes[suffix + 2] - b'0') as i64;
		let minutes = (bytes[suffix + 3] - b'0') as i64 * 10 + (bytes[suffix + 4] - b'0') as i64;
		if hours > 23 || minutes > 59 {
			return None;
		}
		let mut utc = bytes[..suffix].to_vec();
		utc.push(b'Z');
		let encoded = der_value(0x18, &utc);
		let (remaining, wall) = ASN1Time::from_der(&encoded).ok()?;
		if !remaining.is_empty() {
			return None;
		}
		let delta = (hours * 3600 + minutes * 60) * if bytes[suffix] == b'+' { 1 } else { -1 };
		let instant = ASN1Time::from_timestamp(wall.timestamp().checked_sub(delta)?)
			.ok()?
			.to_datetime();
		let utc = format!(
			"{:04}{:02}{:02}{:02}{:02}{:02}Z",
			instant.year(),
			instant.month() as u8,
			instant.day(),
			instant.hour(),
			instant.minute(),
			instant.second()
		);
		dates.extend(der_value(0x18, utc.as_bytes()));
		changed = true;
	}
	if !changed {
		return None;
	}
	let dates = der_value(0x30, &dates);
	let mut fields = Vec::new();
	for (index, node) in tbs.children.iter().enumerate() {
		fields.extend_from_slice(if index == validity_index {
			&dates
		} else {
			node.full
		});
	}
	let mut body = der_value(0x30, &fields);
	for node in root.children.iter().skip(1) {
		body.extend_from_slice(node.full);
	}
	Some(der_value(0x30, &body))
}

/// The DER hash remains available even when every readable fact is unknown.
pub(super) fn facts(der: &[u8]) -> CertificateFacts {
	let mut facts = CertificateFacts {
		sha256_fingerprint: fingerprint(der),
		subject: None,
		issuer: None,
		serial_number: None,
		not_before: None,
		not_after: None,
		public_key_algorithm: None,
	};
	let Ok(root) = BerReader::new(der).read(0, der.len(), 0) else {
		return facts;
	};
	if root.tag != 0x30 || root.end != der.len() || !der_tree(&root) {
		return facts;
	}
	let normalized = normalize_offset_dates(&root);
	let parsing_der = normalized.as_deref().unwrap_or(der);
	let Ok((remaining, certificate)) = X509CertificateParser::new()
		.with_deep_parse_extensions(false)
		.parse(parsing_der)
	else {
		return facts;
	};
	if !remaining.is_empty() || certificate.as_raw() != parsing_der {
		return facts;
	}
	let (Some(subject), Some(issuer)) = (
		name_text(certificate.subject()),
		name_text(certificate.issuer()),
	) else {
		return facts;
	};
	facts.subject = Some(subject);
	facts.issuer = Some(issuer);
	facts.serial_number = serial_text(certificate.raw_serial());
	facts.not_before = iso_date(certificate.validity().not_before);
	facts.not_after = iso_date(certificate.validity().not_after);
	let tbs = &root.children[0].children;
	let offset = usize::from(tbs.first().is_some_and(|n| n.tag == 0xa0));
	facts.public_key_algorithm = tbs
		.get(offset + 5)
		.and_then(public_key::key_type)
		.map(str::to_owned);
	facts
}

/// Restricted RFC 5280 name comparison used solely to resolve a CMS SignerInfo.
/// Exact encoded names can match separately; unknown normalization stays unknown.
pub(super) fn directory_key(name: &Node<'_>) -> Option<Vec<Vec<(String, String)>>> {
	let mut rdns = Vec::new();
	for rdn in &name.children {
		if rdn.tag != 0x31 || rdn.children.is_empty() {
			return None;
		}
		let mut attrs = Vec::new();
		for attribute in &rdn.children {
			if attribute.tag != 0x30 || attribute.children.len() != 2 {
				return None;
			}
			let (id, value) = (&attribute.children[0], &attribute.children[1]);
			if id.tag != 0x06
				|| ![0x0c, 0x13].contains(&value.tag)
				|| value.content.iter().any(|b| !(0x20..=0x7e).contains(b))
			{
				return None;
			}
			let id = oid(id.content).ok()?;
			if ![
				"2.5.4.3", "2.5.4.6", "2.5.4.7", "2.5.4.8", "2.5.4.10", "2.5.4.11",
			]
			.contains(&id.as_str())
			{
				return None;
			}
			let value_text = std::str::from_utf8(value.content).ok()?;
			let text = value_text
				.split(' ')
				.filter(|part| !part.is_empty())
				.collect::<Vec<_>>()
				.join(" ")
				.to_ascii_lowercase();
			if value.tag == 0x13
				&& !text
					.bytes()
					.all(|b| b.is_ascii_alphanumeric() || b" '()+,./:=?-".contains(&b))
			{
				return None;
			}
			attrs.push((id, text));
		}
		attrs.sort();
		rdns.push(attrs);
	}
	Some(rdns)
}
