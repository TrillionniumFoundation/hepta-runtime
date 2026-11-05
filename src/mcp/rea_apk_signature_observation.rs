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

//! Declared APK signing facts, independently of the additional native signature
//! verifier. The selected-file path is bound only by the controller after the
//! worker returns. No certificate, lineage, stamp or v1 signature is trusted.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[path = "rea_apk_signature_archive.rs"]
mod archive;
#[path = "rea_apk_signature_certificate.rs"]
mod certificate;
#[path = "rea_apk_signature_v1.rs"]
mod v1;

pub(super) use super::parser::{
	MAX_ALGORITHMS, MAX_ATTRIBUTES, MAX_BLOCK, MAX_CERTIFICATE, MAX_CERTIFICATES, MAX_PAIRS,
	MAX_SIGNERS,
};
const V2: u32 = 0x7109_871a;
const V3: u32 = 0xf053_68c0;
const V31: u32 = 0x1b93_ad61;
const ROTATION: u32 = 0x3ba0_6f8c;
const STAMP_V1: u32 = 0x2b09_189e;
const STAMP_V2: u32 = 0x6dff_800d;
const MAX_LINEAGE_NODES: usize = 32;
const MAX_V1_BLOCK_BYTES: usize = 1024 * 1024;
const MAX_V1_CERTIFICATES: usize = 32;
const MAX_V1_SIGNER_INFOS: usize = 32;
const MAX_V1_ENTRIES: usize = 4096;

pub type ApkResult<T> = std::result::Result<T, ApkInspectionError>;

/// Stable producing-boundary classification; callers need not inspect strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ApkErrorTag {
	AnalysisInputError,
	AnalysisUnsupportedTargetError,
	AnalysisResourceConstraintError,
	AnalysisCancelledError,
	AnalysisTimeoutError,
	AnalysisAccessDeniedError,
	AnalysisArtifactChangedError,
	ProviderAdapterError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApkResource {
	Capacity,
	FileSize,
	Cpu,
	Memory,
	Transport,
}

/// A typed failure is also an anyhow source across the worker/controller bridge.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApkInspectionError {
	#[serde(rename = "_tag")]
	pub tag: ApkErrorTag,
	pub operation: Box<str>,
	pub reason: Box<str>,
	pub path: Option<String>,
	pub offset: Option<usize>,
	pub scheme: Option<Box<str>>,
	pub resource: Option<ApkResource>,
	pub reported_limits: Box<BTreeMap<String, usize>>,
	pub timeout_ms: Option<u64>,
}

impl ApkInspectionError {
	pub fn new(tag: ApkErrorTag, reason: impl Into<String>) -> Self {
		Self {
			tag,
			operation: "inspect_apk_signature".into(),
			reason: reason.into().into_boxed_str(),
			path: None,
			offset: None,
			scheme: None,
			resource: None,
			reported_limits: Box::default(),
			timeout_ms: None,
		}
	}

	fn input(reason: impl Into<String>) -> Self {
		Self::new(ApkErrorTag::AnalysisInputError, reason)
	}

	fn unsupported(reason: impl Into<String>) -> Self {
		Self::new(ApkErrorTag::AnalysisUnsupportedTargetError, reason)
	}

	pub fn capacity(name: &str, limit: usize) -> Self {
		let mut error = Self::new(
			ApkErrorTag::AnalysisResourceConstraintError,
			format!("APK inspection exceeds the fixed {name} allowance of {limit}"),
		);
		error.resource = Some(ApkResource::Capacity);
		error
			.reported_limits
			.insert(format!("max_{}", name.replace('-', "_")), limit);
		error
	}

	pub fn at_path(mut self, path: &str) -> Self {
		self.path = Some(path.into());
		self
	}

	fn at(mut self, offset: usize) -> Self {
		self.offset = Some(offset);
		self
	}

	fn in_scheme(mut self, scheme: &str) -> Self {
		self.scheme = Some(scheme.into());
		self
	}
}

impl fmt::Display for ApkInspectionError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.reason)
	}
}

impl std::error::Error for ApkInspectionError {}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateFacts {
	pub sha256_fingerprint: String,
	pub subject: Option<String>,
	pub issuer: Option<String>,
	pub serial_number: Option<String>,
	pub not_before: Option<String>,
	pub not_after: Option<String>,
	pub public_key_algorithm: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestAlgorithm {
	Sha256,
	Sha512,
	VeritySha256,
	Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredDigest {
	pub uninterpreted_bytes: usize,
	pub signature_algorithm_id: u32,
	pub algorithm: DigestAlgorithm,
	pub declared_digest_hex: String,
	pub matches_apk: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredSignature {
	pub signature_algorithm_id: u32,
	pub algorithm: DigestAlgorithm,
	pub signature_bytes: usize,
	pub uninterpreted_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFacts {
	pub uninterpreted_signed_data_bytes: usize,
	pub uninterpreted_signer_bytes: usize,
	pub certificate: Option<CertificateFacts>,
	pub digests: Vec<DeclaredDigest>,
	pub signatures: Vec<DeclaredSignature>,
	pub public_key_bytes: usize,
	pub min_sdk: Option<u32>,
	pub max_sdk: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotationCapabilities {
	pub installed_data: bool,
	pub shared_uid: bool,
	pub permission: bool,
	pub rollback: bool,
	pub auth: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageNode {
	pub certificate: Option<CertificateFacts>,
	pub flags: u32,
	pub capabilities: RotationCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotationFacts {
	pub present: bool,
	pub lineage: Vec<LineageNode>,
	pub decode_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct V3SignerFacts {
	#[serde(flatten)]
	pub signer: SignerFacts,
	pub rotation: RotationFacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockScheme<S> {
	pub present: bool,
	pub signers: Vec<S>,
	pub uninterpreted_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateSummary {
	pub sha256_fingerprint: String,
	pub subject: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignerIdentifier {
	IssuerAndSerial,
	SubjectKeyIdentifier,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V1SignerInfo {
	pub identified_by: SignerIdentifier,
	pub certificate_sha256: Option<String>,
	pub digest_algorithm_oid: String,
	pub signature_algorithm_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V1SignerFacts {
	pub signature_file: String,
	pub block_file: String,
	pub certificate: Option<CertificateFacts>,
	pub certificates: Vec<CertificateSummary>,
	pub signer_infos: Vec<V1SignerInfo>,
	pub decode_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V1Scheme {
	pub present: bool,
	pub has_manifest: bool,
	pub signature_files: Vec<String>,
	pub block_files: Vec<String>,
	pub signers: Vec<V1SignerFacts>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStamp {
	pub present: bool,
	pub certificate: Option<CertificateFacts>,
	pub decode_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningSchemes {
	pub v1: V1Scheme,
	pub v2: BlockScheme<SignerFacts>,
	pub v3: BlockScheme<V3SignerFacts>,
	#[serde(rename = "v3.1")]
	pub v3_1: BlockScheme<V3SignerFacts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum StrongestScheme {
	#[serde(rename = "none")]
	None,
	#[serde(rename = "v1")]
	V1,
	#[serde(rename = "v2")]
	V2,
	#[serde(rename = "v3")]
	V3,
	#[serde(rename = "v3.1")]
	V31,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPosture {
	pub v1_only: bool,
	pub schemes_agree_on_signer: Option<bool>,
	pub signer_change_declared_by_rotation: Option<bool>,
	pub v1_signers_match_block_signers: Option<bool>,
	pub rotation_present: bool,
	pub source_stamp_present: bool,
	pub strongest_scheme: StrongestScheme,
	pub self_consistent: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApkArtifact {
	/// None in the isolated worker; only the admitting controller supplies a path.
	pub path: Option<String>,
	pub sha256: String,
	pub bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum RuntimeExecution {
	#[serde(rename = "not-performed")]
	NotPerformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApkSignatureReport {
	pub artifact: ApkArtifact,
	pub schemes: SigningSchemes,
	pub source_stamp: SourceStamp,
	pub posture: SigningPosture,
	pub runtime_execution: RuntimeExecution,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApkStaticInspection {
	pub result: ApkSignatureReport,
	pub limitations: Vec<String>,
}

fn hex(bytes: &[u8]) -> String {
	super::parser::hex(bytes)
}

fn fingerprint(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

fn bounded(bytes: &[u8], name: &str, max: usize) -> ApkResult<()> {
	if bytes.len() > max {
		return Err(ApkInspectionError::capacity(name, max));
	}
	Ok(())
}

struct Reader<'a> {
	bytes: &'a [u8],
	at: usize,
}

impl<'a> Reader<'a> {
	fn new(bytes: &'a [u8]) -> Self {
		Self { bytes, at: 0 }
	}

	fn remaining(&self) -> usize {
		self.bytes.len() - self.at
	}

	fn u32(&mut self, detail: &str) -> ApkResult<u32> {
		let bytes = self
			.bytes
			.get(self.at..self.at.saturating_add(4))
			.ok_or_else(|| ApkInspectionError::input(detail))?;
		self.at += 4;
		Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
	}

	fn chunk(&mut self, detail: &str) -> ApkResult<&'a [u8]> {
		let length = self.u32(detail)? as usize;
		let chunk = self
			.bytes
			.get(self.at..self.at.saturating_add(length))
			.ok_or_else(|| ApkInspectionError::input(detail))?;
		self.at += length;
		Ok(chunk)
	}
}

fn chunks<'a>(bytes: &'a [u8], resource: &str, max: usize) -> ApkResult<Vec<&'a [u8]>> {
	let mut reader = Reader::new(bytes);
	let mut items = Vec::new();
	while reader.remaining() > 0 {
		if items.len() >= max {
			return Err(ApkInspectionError::capacity(resource, max));
		}
		items.push(reader.chunk(&format!("{resource} element truncated"))?);
	}
	Ok(items)
}

struct AlgorithmRecord<'a> {
	id: u32,
	bytes: &'a [u8],
	uninterpreted: usize,
}

fn algorithms<'a>(
	bytes: &'a [u8],
	what: &str,
	max_bytes: usize,
) -> ApkResult<Vec<AlgorithmRecord<'a>>> {
	chunks(bytes, what, MAX_ALGORITHMS)?
		.into_iter()
		.map(|item| {
			let mut reader = Reader::new(item);
			let detail = format!("{what} entry truncated");
			let id = reader.u32(&detail)?;
			let bytes = reader.chunk(&detail)?;
			bounded(bytes, &format!("{what}-record-bytes"), max_bytes)?;
			Ok(AlgorithmRecord {
				id,
				bytes,
				uninterpreted: reader.remaining(),
			})
		})
		.collect()
}

struct RawSigner<'a> {
	certificate: Option<&'a [u8]>,
	digests: Vec<AlgorithmRecord<'a>>,
	signatures: Vec<AlgorithmRecord<'a>>,
	public_key_bytes: usize,
	min_sdk: Option<u32>,
	max_sdk: Option<u32>,
	attributes: Vec<(u32, &'a [u8])>,
	signed_tail: usize,
	signer_tail: usize,
}

struct RawScheme<'a> {
	present: bool,
	signers: Vec<RawSigner<'a>>,
	uninterpreted: usize,
}

fn decode_signer<'a>(bytes: &'a [u8], v3: bool) -> ApkResult<RawSigner<'a>> {
	let mut reader = Reader::new(bytes);
	let mut data = Reader::new(reader.chunk("signed data missing or truncated")?);
	let digests = algorithms(
		data.chunk("digests sequence missing or truncated")?,
		"digests",
		128,
	)?;
	let certificates = chunks(
		data.chunk("certificates sequence missing or truncated")?,
		"certificates",
		MAX_CERTIFICATES,
	)?;
	for bytes in &certificates {
		bounded(bytes, "certificate-bytes", MAX_CERTIFICATE)?;
	}
	let (min_sdk, max_sdk) = if v3 {
		(
			Some(data.u32("min/max SDK truncated")?),
			Some(data.u32("min/max SDK truncated")?),
		)
	} else {
		(None, None)
	};
	let attributes = chunks(
		data.chunk("attributes sequence missing or truncated")?,
		"attributes",
		MAX_ATTRIBUTES,
	)?
	.into_iter()
	.map(|bytes| {
		let mut reader = Reader::new(bytes);
		let id = reader.u32("attribute id truncated")?;
		Ok((id, &bytes[reader.at..]))
	})
	.collect::<ApkResult<Vec<_>>>()?;
	if v3 {
		let min = reader.u32("outer min/max SDK truncated")?;
		let max = reader.u32("outer min/max SDK truncated")?;
		if Some(min) != min_sdk || Some(max) != max_sdk {
			return Err(ApkInspectionError::input(
				"outer SDK range disagrees with the signed SDK range",
			));
		}
	}
	let signatures = algorithms(
		reader.chunk("signatures sequence missing or truncated")?,
		"signatures",
		16 * 1024,
	)?;
	let public_key = reader.chunk("public key truncated")?;
	bounded(public_key, "public-key-bytes", MAX_CERTIFICATE)?;
	Ok(RawSigner {
		certificate: certificates.first().copied(),
		digests,
		signatures,
		public_key_bytes: public_key.len(),
		min_sdk,
		max_sdk,
		attributes,
		signed_tail: data.remaining(),
		signer_tail: reader.remaining(),
	})
}

fn scheme<'a>(
	block: &Option<archive::SigningBlock<'a>>,
	id: u32,
	name: &str,
) -> ApkResult<RawScheme<'a>> {
	let value = block.as_ref().and_then(|b| {
		b.pairs
			.iter()
			.find(|(pair, _)| *pair == id)
			.map(|(_, value)| *value)
	});
	let Some(value) = value else {
		return Ok(RawScheme {
			present: false,
			signers: Vec::new(),
			uninterpreted: 0,
		});
	};
	let decode = || {
		let mut reader = Reader::new(value);
		let values = chunks(
			reader.chunk("signers sequence missing or truncated")?,
			"signers",
			MAX_SIGNERS,
		)?;
		let signers = values
			.into_iter()
			.enumerate()
			.map(|(index, bytes)| {
				decode_signer(bytes, id != V2).map_err(|mut e| {
					if e.tag == ApkErrorTag::AnalysisInputError {
						e.reason = format!("signer {index}: {}", e.reason).into_boxed_str();
					}
					e
				})
			})
			.collect::<ApkResult<Vec<_>>>()?;
		Ok(RawScheme {
			present: true,
			signers,
			uninterpreted: reader.remaining(),
		})
	};
	decode().map_err(|e: ApkInspectionError| e.in_scheme(name))
}

fn digest_algorithm(id: u32) -> DigestAlgorithm {
	match id {
		0x0101 | 0x0103 | 0x0201 | 0x0301 => DigestAlgorithm::Sha256,
		0x0102 | 0x0104 | 0x0202 => DigestAlgorithm::Sha512,
		0x0421 | 0x0423 | 0x0425 => DigestAlgorithm::VeritySha256,
		_ => DigestAlgorithm::Unknown,
	}
}

fn content_digest<D: Digest + Default>(
	bytes: &[u8],
	tail: &archive::ZipTail,
	start: usize,
) -> Vec<u8> {
	let mut eocd = bytes[tail.eocd..].to_vec();
	eocd[16..20].copy_from_slice(&(start as u32).to_le_bytes());
	let sections = [&bytes[..start], &bytes[tail.central..tail.eocd], &eocd];
	let count = sections
		.iter()
		.map(|s| s.len().div_ceil(1024 * 1024))
		.sum::<usize>();
	let mut top = D::new();
	top.update([0x5a]);
	top.update((count as u32).to_le_bytes());
	for section in sections {
		for chunk in section.chunks(1024 * 1024) {
			let mut part = D::new();
			part.update([0xa5]);
			part.update((chunk.len() as u32).to_le_bytes());
			part.update(chunk);
			top.update(part.finalize());
		}
	}
	top.finalize().to_vec()
}

/// Admission happens before names/DER expand into readable output. The exact
/// serialized check remains authoritative, and shares the existing 1 MiB cap.
struct OutputBudget(usize);

impl OutputBudget {
	fn add(&mut self, bytes: usize) -> ApkResult<()> {
		self.0 = self.0.saturating_add(bytes);
		if self.0 > super::MAX_RESPONSE_BYTES {
			return Err(ApkInspectionError::capacity(
				"output-bytes",
				super::MAX_RESPONSE_BYTES,
			));
		}
		Ok(())
	}

	fn certificate(&mut self, bytes: &[u8]) -> ApkResult<CertificateFacts> {
		bounded(bytes, "certificate-bytes", MAX_CERTIFICATE)?;
		self.add(256usize.saturating_add(bytes.len().saturating_mul(4)))?;
		Ok(certificate::facts(bytes))
	}
}

fn signer_facts(
	raw: &RawSigner<'_>,
	d256: Option<&[u8]>,
	d512: Option<&[u8]>,
	budget: &mut OutputBudget,
) -> ApkResult<SignerFacts> {
	budget.add(512 + raw.signatures.len() * 160)?;
	let certificate = raw
		.certificate
		.map(|cert| budget.certificate(cert))
		.transpose()?;
	let mut digests = Vec::new();
	for record in &raw.digests {
		budget.add(160 + 2 * record.bytes.len())?;
		let algorithm = digest_algorithm(record.id);
		let computed = match algorithm {
			DigestAlgorithm::Sha256 => d256,
			DigestAlgorithm::Sha512 => d512,
			_ => None,
		};
		digests.push(DeclaredDigest {
			uninterpreted_bytes: record.uninterpreted,
			signature_algorithm_id: record.id,
			algorithm,
			declared_digest_hex: hex(record.bytes),
			matches_apk: computed.map(|digest| digest == record.bytes),
		});
	}
	Ok(SignerFacts {
		uninterpreted_signed_data_bytes: raw.signed_tail,
		uninterpreted_signer_bytes: raw.signer_tail,
		certificate,
		digests,
		signatures: raw
			.signatures
			.iter()
			.map(|r| DeclaredSignature {
				signature_algorithm_id: r.id,
				algorithm: digest_algorithm(r.id),
				signature_bytes: r.bytes.len(),
				uninterpreted_bytes: r.uninterpreted,
			})
			.collect(),
		public_key_bytes: raw.public_key_bytes,
		min_sdk: raw.min_sdk,
		max_sdk: raw.max_sdk,
	})
}

fn rotation(raw: &RawSigner<'_>, budget: &mut OutputBudget) -> ApkResult<RotationFacts> {
	let Some((_, bytes)) = raw.attributes.iter().find(|(id, _)| *id == ROTATION) else {
		return Ok(RotationFacts {
			present: false,
			lineage: Vec::new(),
			decode_error: None,
		});
	};
	let decode = || -> ApkResult<Vec<(&[u8], u32)>> {
		let mut reader = Reader::new(bytes);
		let version = reader.u32("lineage version missing")?;
		if version != 1 {
			return Err(ApkInspectionError::input(format!(
				"unsupported lineage version {version}"
			)));
		}
		let mut nodes = Vec::new();
		while reader.remaining() > 0 {
			if nodes.len() >= MAX_LINEAGE_NODES {
				return Err(ApkInspectionError::capacity(
					"lineage-nodes",
					MAX_LINEAGE_NODES,
				));
			}
			let mut node = Reader::new(reader.chunk("lineage node truncated")?);
			let mut signed = Reader::new(node.chunk("lineage node malformed")?);
			let flags = node.u32("lineage node malformed")?;
			let cert = signed.chunk("lineage certificate missing")?;
			signed.u32("lineage signed algorithm missing or truncated")?;
			node.u32("lineage algorithm or signature missing or truncated")?;
			node.chunk("lineage algorithm or signature missing or truncated")?;
			bounded(cert, "certificate-bytes", MAX_CERTIFICATE)?;
			nodes.push((cert, flags));
		}
		Ok(nodes)
	};
	let nodes = match decode() {
		Ok(nodes) => nodes,
		Err(e) if e.tag == ApkErrorTag::AnalysisInputError => {
			return Ok(RotationFacts {
				present: true,
				lineage: Vec::new(),
				decode_error: Some(e.reason.into_string()),
			})
		}
		Err(e) => return Err(e),
	};
	let mut lineage = Vec::new();
	for (cert, flags) in nodes {
		budget.add(192)?;
		lineage.push(LineageNode {
			certificate: Some(budget.certificate(cert)?),
			flags,
			capabilities: RotationCapabilities {
				installed_data: flags & 1 != 0,
				shared_uid: flags & 2 != 0,
				permission: flags & 4 != 0,
				rollback: flags & 8 != 0,
				auth: flags & 16 != 0,
			},
		});
	}
	Ok(RotationFacts {
		present: true,
		lineage,
		decode_error: None,
	})
}

fn source_stamp(
	block: &Option<archive::SigningBlock<'_>>,
	budget: &mut OutputBudget,
) -> ApkResult<SourceStamp> {
	let pair = block.as_ref().and_then(|b| {
		b.pairs
			.iter()
			.find(|(id, _)| *id == STAMP_V2)
			.or_else(|| b.pairs.iter().find(|(id, _)| *id == STAMP_V1))
	});
	let Some((_, bytes)) = pair else {
		return Ok(SourceStamp {
			present: false,
			certificate: None,
			decode_error: None,
		});
	};
	let decode = || {
		let mut outer = Reader::new(bytes);
		let mut data = Reader::new(outer.chunk("source stamp data truncated")?);
		let cert = data.chunk("source stamp certificate missing")?;
		if cert.is_empty() {
			return Err(ApkInspectionError::input(
				"source stamp certificate missing",
			));
		}
		Ok(cert)
	};
	match decode() {
		Ok(cert) => Ok(SourceStamp {
			present: true,
			certificate: Some(budget.certificate(cert)?),
			decode_error: None,
		}),
		Err(e) => Ok(SourceStamp {
			present: true,
			certificate: None,
			decode_error: Some(e.reason.into_string()),
		}),
	}
}

fn fingerprint_of(cert: &Option<CertificateFacts>) -> Option<&str> {
	cert.as_ref().map(|cert| cert.sha256_fingerprint.as_str())
}

type PostureSigner<'a> = (&'a SignerFacts, Option<&'a RotationFacts>);

fn posture(schemes: &SigningSchemes, stamp: &SourceStamp) -> (SigningPosture, Option<String>) {
	let mut present: Vec<(&str, Vec<PostureSigner<'_>>)> = Vec::new();
	if schemes.v2.present {
		present.push(("v2", schemes.v2.signers.iter().map(|s| (s, None)).collect()));
	}
	if schemes.v3.present {
		present.push((
			"v3",
			schemes
				.v3
				.signers
				.iter()
				.map(|s| (&s.signer, Some(&s.rotation)))
				.collect(),
		));
	}
	if schemes.v3_1.present {
		present.push((
			"v3.1",
			schemes
				.v3_1
				.signers
				.iter()
				.map(|s| (&s.signer, Some(&s.rotation)))
				.collect(),
		));
	}
	let unknown = present
		.iter()
		.any(|(_, signers)| signers.iter().any(|(s, _)| s.certificate.is_none()));
	let sets: Vec<BTreeSet<&str>> = present
		.iter()
		.map(|(_, signers)| {
			signers
				.iter()
				.filter_map(|(s, _)| fingerprint_of(&s.certificate))
				.collect()
		})
		.collect();
	let union: BTreeSet<&str> = sets.iter().flat_map(|set| set.iter().copied()).collect();
	let differ = (!unknown).then(|| sets.windows(2).any(|w| w[0] != w[1]));
	let rotations: Vec<&RotationFacts> = present
		.iter()
		.flat_map(|(_, signers)| signers.iter().filter_map(|(_, r)| *r))
		.filter(|r| r.present)
		.collect();
	let lineage: BTreeSet<&str> = rotations
		.iter()
		.flat_map(|r| {
			r.lineage
				.iter()
				.filter_map(|n| fingerprint_of(&n.certificate))
		})
		.collect();
	let lineage_unknown = rotations.iter().any(|r| r.decode_error.is_some());
	let change = match differ {
		None => None,
		Some(false) => Some(false),
		Some(true) if union.len() <= 1 => Some(false),
		Some(true) if union.is_subset(&lineage) => Some(true),
		Some(true) if lineage_unknown => None,
		Some(true) => Some(false),
	};
	let mut note = None;
	let v1_match = if !schemes.v1.present || schemes.v1.signers.is_empty() {
		None
	} else if let Some((scheme, signers)) = present.iter().find(|(_, signers)| !signers.is_empty())
	{
		let mut expected = BTreeSet::new();
		let mut known = true;
		for (signer, rotation) in signers {
			let fp = fingerprint_of(&signer.certificate);
			let fp = match rotation.filter(|r| r.present && fp.is_some()) {
				None => fp,
				Some(rotation) if rotation.decode_error.is_some() => {
					note = Some(format!("v1_signers_match_block_signers is null: the {scheme} signer's declared rotation lineage could not be decoded, so the original certificate v1 is expected to carry is unknown."));
					None
				}
				Some(rotation) => {
					let origin = rotation
						.lineage
						.first()
						.and_then(|n| fingerprint_of(&n.certificate));
					if origin.is_none() {
						note = Some(format!("v1_signers_match_block_signers is null: the {scheme} signer's declared rotation lineage names no readable original certificate, so the original certificate v1 is expected to carry is unknown."));
					}
					origin
				}
			};
			if let Some(fp) = fp {
				expected.insert(fp);
			} else {
				known = false;
			}
			if note.is_some() {
				break;
			}
		}
		let mut actual = BTreeSet::new();
		for signer in &schemes.v1.signers {
			let fp = if signer
				.signer_infos
				.iter()
				.any(|info| info.identified_by == SignerIdentifier::SubjectKeyIdentifier)
			{
				None
			} else {
				fingerprint_of(&signer.certificate)
			};
			if let Some(fp) = fp {
				actual.insert(fp);
			} else {
				known = false;
			}
		}
		known.then_some(actual == expected)
	} else {
		None
	};
	let computed: Vec<bool> = present
		.iter()
		.flat_map(|(_, signers)| {
			signers
				.iter()
				.flat_map(|(s, _)| s.digests.iter().filter_map(|d| d.matches_apk))
		})
		.collect();
	(
		SigningPosture {
			v1_only: schemes.v1.present && present.is_empty(),
			schemes_agree_on_signer: if union.is_empty() {
				None
			} else {
				differ.map(|d| !d)
			},
			signer_change_declared_by_rotation: change,
			v1_signers_match_block_signers: v1_match,
			rotation_present: !rotations.is_empty(),
			source_stamp_present: stamp.present,
			strongest_scheme: if schemes.v3_1.present {
				StrongestScheme::V31
			} else if schemes.v3.present {
				StrongestScheme::V3
			} else if schemes.v2.present {
				StrongestScheme::V2
			} else if schemes.v1.present {
				StrongestScheme::V1
			} else {
				StrongestScheme::None
			},
			self_consistent: (!computed.is_empty()).then(|| computed.iter().all(|value| *value)),
		},
		note,
	)
}

const LIMITATIONS: &[&str] = &[
	"Static structural inspection only. No Android code executes, no device or adb is involved, and odex/vdex/oat/cdex are not read.",
	"No signature is verified: signer, rotation-lineage and source-stamp signatures are NOT cryptographically checked, and certificate chains, revocation and authenticity are NOT evaluated. Certificates and lineages are what the APK declares.",
	"matches_apk and self_consistent only show that the declared content digest equals the digest of the current bytes. This is not a signature verification: anyone who changes the bytes can recompute the digest and write it into the signed data. SHA-256 identifies the exact bytes, not the producer.",
	"v1 signers are what each signature block's PKCS#7 SignedData declares: its signatures, the .SF and MANIFEST.MF digests and entry coverage are NOT verified.",
	"Not read: v4 .apk.idsig, verity digests (matches_apk null), and the v1 X-Android-APK-Signed marker, so v1_only cannot distinguish a v1-only APK from one whose v2/v3 block was removed.",
];

pub(super) fn inspect(bytes: &[u8]) -> ApkResult<ApkStaticInspection> {
	if bytes.len() > super::MAX_APK_BYTES {
		let mut e = ApkInspectionError::capacity("input-bytes", super::MAX_APK_BYTES);
		e.resource = Some(ApkResource::FileSize);
		return Err(e);
	}
	let tail = archive::zip_tail(bytes)?;
	let block = archive::signing_block(bytes, &tail)?;
	let directory = archive::directory(bytes, &tail)?;
	let mut budget = OutputBudget(8192);
	let (v1, v1_notes) = v1::inspect(
		bytes,
		&directory,
		block.as_ref().map_or(tail.central, |b| b.start),
		&mut budget,
	)?;
	let v2 = scheme(&block, V2, "v2")?;
	let v3 = scheme(&block, V3, "v3")?;
	let v31 = scheme(&block, V31, "v3.1")?;
	let can_recompute =
		block.is_some() && tail.central.checked_add(tail.central_size) == Some(tail.eocd);
	let requested = v2
		.signers
		.iter()
		.chain(&v3.signers)
		.chain(&v31.signers)
		.flat_map(|s| &s.digests)
		.map(|d| digest_algorithm(d.id))
		.collect::<Vec<_>>();
	let d256 = block
		.as_ref()
		.filter(|_| can_recompute && requested.contains(&DigestAlgorithm::Sha256))
		.map(|b| content_digest::<Sha256>(bytes, &tail, b.start));
	let d512 = block
		.as_ref()
		.filter(|_| can_recompute && requested.contains(&DigestAlgorithm::Sha512))
		.map(|b| content_digest::<Sha512>(bytes, &tail, b.start));
	let v2 = BlockScheme {
		present: v2.present,
		uninterpreted_bytes: v2.uninterpreted,
		signers: v2
			.signers
			.iter()
			.map(|s| signer_facts(s, d256.as_deref(), d512.as_deref(), &mut budget))
			.collect::<ApkResult<_>>()?,
	};
	let mut materialize =
		|raw: RawScheme<'_>, name: &str| -> ApkResult<BlockScheme<V3SignerFacts>> {
			let mut signers = Vec::new();
			for signer in raw.signers {
				let rotation = rotation(&signer, &mut budget).map_err(|e| e.in_scheme(name))?;
				signers.push(V3SignerFacts {
					signer: signer_facts(&signer, d256.as_deref(), d512.as_deref(), &mut budget)?,
					rotation,
				});
			}
			Ok(BlockScheme {
				present: raw.present,
				signers,
				uninterpreted_bytes: raw.uninterpreted,
			})
		};
	let v3 = materialize(v3, "v3")?;
	let v3_1 = materialize(v31, "v3.1")?;
	let source_stamp = source_stamp(&block, &mut budget)?;
	let schemes = SigningSchemes { v1, v2, v3, v3_1 };
	let (posture, note) = posture(&schemes, &source_stamp);
	let block_schemes = [
		(
			schemes.v2.uninterpreted_bytes,
			schemes.v2.signers.iter().collect::<Vec<_>>(),
		),
		(
			schemes.v3.uninterpreted_bytes,
			schemes.v3.signers.iter().map(|s| &s.signer).collect(),
		),
		(
			schemes.v3_1.uninterpreted_bytes,
			schemes.v3_1.signers.iter().map(|s| &s.signer).collect(),
		),
	];
	let uninterpreted: usize = block_schemes
		.iter()
		.map(|(tail, signers)| {
			*tail
				+ signers
					.iter()
					.map(|s| {
						s.uninterpreted_signed_data_bytes
							+ s.uninterpreted_signer_bytes
							+ s.digests
								.iter()
								.map(|d| d.uninterpreted_bytes)
								.sum::<usize>() + s
							.signatures
							.iter()
							.map(|s| s.uninterpreted_bytes)
							.sum::<usize>()
					})
					.sum::<usize>()
		})
		.sum();
	let mut limitations = Vec::new();
	if uninterpreted > 0 {
		limitations.push(format!("{uninterpreted} bytes outside known signing fields were not interpreted; suffixes do not by themselves establish malformed signing."));
	}
	limitations.extend(LIMITATIONS.iter().map(|text| (*text).to_owned()));
	if !can_recompute
		&& block.is_some()
		&& requested
			.iter()
			.any(|d| matches!(d, DigestAlgorithm::Sha256 | DigestAlgorithm::Sha512))
	{
		limitations.push("The content digest was not recomputed because the central directory is not immediately followed by the end-of-central-directory record (declared size mismatch or an intervening Zip64 record); matches_apk is null for those digests.".into());
	}
	if let Some(note) = archive::duplicate_note(&directory, tail.classic_count) {
		limitations.push(note);
	}
	limitations.extend(v1_notes);
	limitations.extend(note);
	let result = ApkStaticInspection {
		result: ApkSignatureReport {
			artifact: ApkArtifact {
				path: None,
				sha256: fingerprint(bytes),
				bytes: bytes.len(),
			},
			schemes,
			source_stamp,
			posture,
			runtime_execution: RuntimeExecution::NotPerformed,
		},
		limitations,
	};
	let encoded = serde_json::to_vec(&result).map_err(|e| {
		ApkInspectionError::new(
			ApkErrorTag::ProviderAdapterError,
			format!("APK report serialization failed: {e}"),
		)
	})?;
	if encoded.len() > super::MAX_RESPONSE_BYTES {
		return Err(ApkInspectionError::capacity(
			"output-bytes",
			super::MAX_RESPONSE_BYTES,
		));
	}
	Ok(result)
}

#[cfg(test)]
#[path = "rea_apk_signature_observation_tests.rs"]
mod tests;
