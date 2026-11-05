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

//! v1 JAR declarations from paired .SF/PKCS#7 blocks. Neither a readable
//! SignerInfo nor certificate membership proves a signature or entry coverage.

use super::archive::{self, Directory, Entry};
use super::certificate::{
	self, algorithm_oid, directory_key, expect, oid, BerFailure, BerReader, BerResult, Node,
};
use super::{
	ApkInspectionError, ApkResult, CertificateSummary, OutputBudget, SignerIdentifier, V1Scheme,
	V1SignerFacts, V1SignerInfo, MAX_CERTIFICATE, MAX_SIGNERS, MAX_V1_BLOCK_BYTES,
	MAX_V1_CERTIFICATES, MAX_V1_SIGNER_INFOS,
};
use flate2::{Decompress, FlushDecompress, Status};
use std::borrow::Cow;
use std::collections::BTreeSet;

const MANIFEST: &str = "META-INF/MANIFEST.MF";

enum DecodeFailure {
	Malformed(String),
	Capacity(&'static str, usize),
}

impl From<BerFailure> for DecodeFailure {
	fn from(error: BerFailure) -> Self {
		if error.exhausted_nodes {
			Self::Capacity("asn1-elements", certificate::MAX_ASN1_NODES)
		} else {
			Self::Malformed(error.detail)
		}
	}
}

impl DecodeFailure {
	fn message(self) -> String {
		match self {
			Self::Malformed(detail) => format!("malformed PKCS#7: {detail}"),
			Self::Capacity(resource, limit) => format!("more {resource} than {limit}"),
		}
	}
}

struct CertificateIdentity<'a> {
	issuer: &'a [u8],
	issuer_key: Option<Vec<Vec<(String, String)>>>,
	serial: &'a [u8],
	key_id: Option<&'a [u8]>,
}

fn certificate_identity<'a>(
	reader: &mut BerReader<'a>,
	cert: &Node<'a>,
) -> BerResult<Option<CertificateIdentity<'a>>> {
	let read = |reader: &mut BerReader<'a>| -> BerResult<CertificateIdentity<'a>> {
		let fields = &expect(cert.children.first(), 0x30, "tbsCertificate")?.children;
		let offset = usize::from(fields.first().is_some_and(|field| field.tag == 0xa0));
		let serial = expect(fields.get(offset), 0x02, "serialNumber")?;
		let issuer = expect(fields.get(offset + 2), 0x30, "issuer")?;
		let mut key_id = None;
		if let Some(extensions) = fields.iter().find(|field| field.tag == 0xa3) {
			let list = expect(extensions.children.first(), 0x30, "extensions")?;
			for extension in &list.children {
				let id = expect(extension.children.first(), 0x06, "extension id")?;
				if oid(id.content)? != "2.5.29.14" {
					continue;
				}
				let value = expect(extension.children.last(), 0x04, "extnValue")?;
				let inner = reader.read(value.content_start, value.content_end, 0)?;
				key_id = Some(expect(Some(&inner), 0x04, "keyIdentifier")?.content);
			}
		}
		Ok(CertificateIdentity {
			issuer: issuer.full,
			issuer_key: directory_key(issuer),
			serial: serial.content,
			key_id,
		})
	};
	match read(reader) {
		Ok(identity) => Ok(Some(identity)),
		Err(error) if !error.exhausted_nodes => Ok(None),
		Err(error) => Err(error),
	}
}

fn octets(node: Option<&Node<'_>>, what: &str) -> BerResult<()> {
	let node = node.ok_or_else(|| BerFailure::malformed(format!("{what} is missing")))?;
	if node.tag == 0x04 {
		return Ok(());
	}
	if node.tag != 0x24 {
		return Err(BerFailure::malformed(format!(
			"{what} has tag 0x{:x}, expected 0x4 or 0x24",
			node.tag
		)));
	}
	for child in &node.children {
		if ![0x04, 0x24].contains(&child.tag) {
			return Err(BerFailure::malformed(format!(
				"{what} has non-OCTET STRING fragment tag 0x{:x}",
				child.tag
			)));
		}
		octets(Some(child), what)?;
	}
	Ok(())
}

struct SignerInfo {
	identified_by: SignerIdentifier,
	certificate: Option<usize>,
	digest_oid: String,
	signature_oid: String,
}

fn signer_info(
	tlv: &Node<'_>,
	identities: &[Option<CertificateIdentity<'_>>],
	index: usize,
) -> BerResult<SignerInfo> {
	let what = format!("signerInfo {index}");
	let fields = &expect(Some(tlv), 0x30, &what)?.children;
	expect(fields.first(), 0x02, &format!("{what} version"))?;
	let sid = fields.get(1);
	let (identified_by, certificate) = match sid {
		Some(sid) if sid.tag == 0x30 => {
			let issuer = expect(sid.children.first(), 0x30, &format!("{what} issuer"))?;
			let serial = expect(sid.children.get(1), 0x02, &format!("{what} serialNumber"))?;
			let key = directory_key(issuer);
			let certificate = identities.iter().position(|identity| {
				identity.as_ref().is_some_and(|identity| {
					(identity.issuer == issuer.full
						|| (key.is_some() && identity.issuer_key == key))
						&& identity.serial == serial.content
				})
			});
			(SignerIdentifier::IssuerAndSerial, certificate)
		}
		Some(sid) if sid.tag == 0x80 => {
			let certificate = identities.iter().position(|identity| {
				identity
					.as_ref()
					.is_some_and(|identity| identity.key_id == Some(sid.content))
			});
			(SignerIdentifier::SubjectKeyIdentifier, certificate)
		}
		_ => {
			return Err(BerFailure::malformed(format!(
				"{what} has no supported signer identifier"
			)))
		}
	};
	let digest_oid = algorithm_oid(fields.get(2), &format!("{what} digestAlgorithm"))?;
	let next = if fields.get(3).is_some_and(|node| node.tag == 0xa0) {
		4
	} else {
		3
	};
	let signature_oid = algorithm_oid(fields.get(next), &format!("{what} signatureAlgorithm"))?;
	octets(fields.get(next + 1), &format!("{what} signature"))?;
	Ok(SignerInfo {
		identified_by,
		certificate,
		digest_oid,
		signature_oid,
	})
}

struct Decoded<'a> {
	certificates: Vec<&'a [u8]>,
	infos: Vec<SignerInfo>,
	trailing: usize,
}

fn decode(bytes: &[u8]) -> Result<Decoded<'_>, DecodeFailure> {
	let mut reader = BerReader::new(bytes);
	let root = reader.read(0, bytes.len(), 0)?;
	let content_info = expect(Some(&root), 0x30, "ContentInfo")?;
	let content_type = oid(expect(content_info.children.first(), 0x06, "contentType")?.content)?;
	if content_type != "1.2.840.113549.1.7.2" {
		return Err(DecodeFailure::Malformed(format!(
			"contentType {content_type} is not SignedData"
		)));
	}
	let explicit = expect(content_info.children.get(1), 0xa0, "content")?;
	let signed_data = expect(explicit.children.first(), 0x30, "SignedData")?;
	let fields = &signed_data.children;
	expect(fields.first(), 0x02, "SignedData version")?;
	expect(fields.get(1), 0x31, "digestAlgorithms")?;
	expect(fields.get(2), 0x30, "encapContentInfo")?;
	let mut at = 3;
	let mut certificates = Vec::new();
	if let Some(list) = fields.get(at).filter(|node| node.tag == 0xa0) {
		for choice in &list.children {
			if choice.tag != 0x30 {
				return Err(DecodeFailure::Malformed(format!(
					"certificate choice with tag 0x{:x} is not an X.509 certificate",
					choice.tag
				)));
			}
			if certificates.len() >= MAX_V1_CERTIFICATES {
				return Err(DecodeFailure::Capacity(
					"v1-block-certificates",
					MAX_V1_CERTIFICATES,
				));
			}
			if choice.full.len() > MAX_CERTIFICATE {
				return Err(DecodeFailure::Capacity(
					"certificate-bytes",
					MAX_CERTIFICATE,
				));
			}
			certificates.push(choice);
		}
		at += 1;
	}
	if fields.get(at).is_some_and(|node| node.tag == 0xa1) {
		at += 1;
	}
	let infos = &expect(fields.get(at), 0x31, "signerInfos")?.children;
	if infos.len() > MAX_V1_SIGNER_INFOS {
		return Err(DecodeFailure::Capacity(
			"v1-signer-infos",
			MAX_V1_SIGNER_INFOS,
		));
	}
	let identities = certificates
		.iter()
		.map(|cert| certificate_identity(&mut reader, cert))
		.collect::<BerResult<Vec<_>>>()?;
	Ok(Decoded {
		certificates: certificates.iter().map(|cert| cert.full).collect(),
		infos: infos
			.iter()
			.enumerate()
			.map(|(index, node)| signer_info(node, &identities, index))
			.collect::<BerResult<_>>()?,
		trailing: bytes.len() - content_info.end,
	})
}

fn inflated<'a>(stored: &'a [u8], entry: &Entry<'_>) -> Result<Cow<'a, [u8]>, String> {
	if entry.uncompressed as usize > MAX_V1_BLOCK_BYTES {
		return Err(format!(
			"signature block declares {} bytes, over the {MAX_V1_BLOCK_BYTES}-byte bound",
			entry.uncompressed
		));
	}
	let data = match entry.method {
		0 => Cow::Borrowed(stored),
		8 => {
			let mut decompressor = Decompress::new(false);
			let mut out = vec![0; MAX_V1_BLOCK_BYTES + 1];
			let status = decompressor
				.decompress(stored, &mut out, FlushDecompress::Finish)
				.map_err(|_| "signature block deflate stream is damaged".to_owned())?;
			let length = decompressor.total_out() as usize;
			if length > MAX_V1_BLOCK_BYTES {
				return Err(format!(
					"signature block inflates past the {MAX_V1_BLOCK_BYTES}-byte bound"
				));
			}
			if status != Status::StreamEnd {
				return Err("signature block deflate stream is damaged".into());
			}
			out.truncate(length);
			Cow::Owned(out)
		}
		other => return Err(format!("compression method {other} is not supported")),
	};
	if data.len() != entry.uncompressed as usize {
		return Err(format!(
			"signature block holds {} bytes, the central directory declares {}",
			data.len(),
			entry.uncompressed
		));
	}
	Ok(data)
}

fn empty_signer(signature_file: &str, block_file: &str, decode_error: String) -> V1SignerFacts {
	V1SignerFacts {
		signature_file: signature_file.into(),
		block_file: block_file.into(),
		certificate: None,
		certificates: Vec::new(),
		signer_infos: Vec::new(),
		decode_error: Some(decode_error),
	}
}

fn signer(
	bytes: &[u8],
	entry: &Entry<'_>,
	signature_file: &str,
	duplicate: Option<&str>,
	entries_end: usize,
	budget: &mut OutputBudget,
) -> ApkResult<(V1SignerFacts, Vec<String>)> {
	budget.add(
		512 + 6 * signature_file.encode_utf16().count() + 6 * entry.name.encode_utf16().count(),
	)?;
	let mut encrypted = entry.flags & 1 != 0;
	let mut notes = Vec::new();
	let read = || -> Result<(&[u8], bool), String> {
		if let Some(name) = duplicate {
			return Err(format!("duplicate entry: {name}"));
		}
		archive::local_data(bytes, entry, entries_end)
	};
	let read = read().and_then(|(stored, declares)| {
		encrypted = declares;
		inflated(stored, entry)
	});
	let result = match read {
		Err(error) => empty_signer(signature_file, &entry.name, error),
		Ok(data) => match decode(&data) {
			Err(error) => empty_signer(signature_file, &entry.name, error.message()),
			Ok(decoded) => {
				let mut largest = 0;
				for der in &decoded.certificates {
					budget.add(128 + 4 * der.len())?;
					largest = largest.max(256 + 4 * der.len());
				}
				budget.add(largest + 768 * decoded.infos.len())?;
				let facts = decoded
					.certificates
					.iter()
					.map(|der| certificate::facts(der))
					.collect::<Vec<_>>();
				let named = |index: Option<usize>| index.and_then(|index| facts.get(index));
				if decoded
					.infos
					.iter()
					.any(|info| info.identified_by == SignerIdentifier::SubjectKeyIdentifier)
				{
					notes.push(format!("{}: a SignerInfo names its certificate by subjectKeyIdentifier, which apksig does not resolve (it matches issuerAndSerialNumber only), so apksig's v1 verification fails for this block. The certificate it names is reported as declared, and v1_signers_match_block_signers treats this signer as unknown.", entry.name));
				}
				if decoded.trailing > 0 {
					notes.push(format!("{}: {} bytes follow the PKCS#7 ContentInfo and were ignored, as apksig ignores them.", entry.name, decoded.trailing));
				}
				V1SignerFacts {
					signature_file: signature_file.into(),
					block_file: entry.name.to_string(),
					certificate: if decoded.infos.len() == 1 {
						named(decoded.infos[0].certificate).cloned()
					} else {
						None
					},
					certificates: facts
						.iter()
						.map(|cert| CertificateSummary {
							sha256_fingerprint: cert.sha256_fingerprint.clone(),
							subject: cert.subject.clone(),
						})
						.collect(),
					signer_infos: decoded
						.infos
						.iter()
						.map(|info| V1SignerInfo {
							identified_by: info.identified_by,
							certificate_sha256: named(info.certificate)
								.map(|cert| cert.sha256_fingerprint.clone()),
							digest_algorithm_oid: info.digest_oid.clone(),
							signature_algorithm_oid: info.signature_oid.clone(),
						})
						.collect(),
					decode_error: None,
				}
			}
		},
	};
	if encrypted {
		notes.insert(0, format!("{}: the entry declares encryption (general-purpose flag bit 0); apksig ignores the flag, so its bytes were read as stored and the PKCS#7 decoding decides.", entry.name));
	}
	Ok((result, notes))
}

pub(super) fn inspect(
	bytes: &[u8],
	directory: &Directory<'_>,
	entries_end: usize,
	budget: &mut OutputBudget,
) -> ApkResult<(V1Scheme, Vec<String>)> {
	let selected = directory
		.metadata
		.iter()
		.map(|index| &directory.entries[*index])
		.collect::<Vec<_>>();
	let signature_files = selected
		.iter()
		.filter(|entry| entry.name.ends_with(".SF"))
		.map(|entry| entry.name.as_ref())
		.collect::<Vec<_>>();
	let blocks = selected
		.iter()
		.filter(|entry| archive::is_block(&entry.name))
		.copied()
		.collect::<Vec<_>>();
	for name in signature_files
		.iter()
		.copied()
		.chain(blocks.iter().map(|block| block.name.as_ref()))
	{
		budget.add(3 + 6 * name.encode_utf16().count())?;
	}
	let sf_names = signature_files.iter().copied().collect::<BTreeSet<_>>();
	let duplicates = directory
		.duplicates
		.iter()
		.map(|(first, _)| directory.entries[*first].name.as_ref())
		.collect::<BTreeSet<_>>();
	let mut paired = BTreeSet::new();
	let mut signers = Vec::new();
	let mut notes = Vec::new();
	for block in &blocks {
		let signature_file = archive::signature_file(&block.name);
		if !sf_names.contains(signature_file.as_str()) || !paired.insert(block.name.as_ref()) {
			continue;
		}
		if signers.len() >= MAX_SIGNERS {
			return Err(ApkInspectionError::capacity("v1-signers", MAX_SIGNERS));
		}
		let duplicate = [block.name.as_ref(), signature_file.as_str(), MANIFEST]
			.into_iter()
			.find(|name| duplicates.contains(*name));
		let (one, extra) = signer(
			bytes,
			block,
			&signature_file,
			duplicate,
			entries_end,
			budget,
		)?;
		signers.push(one);
		notes.extend(extra);
	}
	Ok((
		V1Scheme {
			present: !signers.is_empty(),
			has_manifest: selected.iter().any(|entry| entry.name == MANIFEST),
			signature_files: signature_files.into_iter().map(str::to_owned).collect(),
			block_files: blocks.iter().map(|block| block.name.to_string()).collect(),
			signers,
		},
		notes,
	))
}
