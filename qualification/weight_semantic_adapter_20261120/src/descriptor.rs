// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Source-derived floating tensor descriptors and explicit partial-source receipts.
//!
//! This strict floating-only profile follows the native REA directory invariants.
//! It does not replace the native filesystem admission or immutable artifact owner.

use crate::{digest, unique_json, validate_sha256, SourcePin, MAX_INPUT_BYTES};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_HEADER_BYTES: usize = 1024 * 1024;
const MAX_TENSORS: usize = 8192;
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
pub enum Dtype {
    F16,
    BF16,
    F32,
    F64,
}

impl Dtype {
    pub fn width(self) -> u64 {
        match self {
            Self::F16 | Self::BF16 => 2,
            Self::F32 => 4,
            Self::F64 => 8,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TensorDescriptor {
    pub name: String,
    pub dtype: Dtype,
    pub shape: Vec<u64>,
    pub data_offsets: [u64; 2],
    pub file_offset: u64,
    pub byte_length: u64,
    pub elements: u64,
    pub payload_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    dtype: Dtype,
    shape: Vec<u64>,
    data_offsets: [u64; 2],
}

#[derive(Clone, Debug, Serialize)]
pub struct HeaderDirectory {
    pub source_size_bytes: u64,
    pub header_bytes: u64,
    pub header_sha256: String,
    pub tensors: BTreeMap<String, TensorDescriptor>,
}

/// Header-only inspection never manufactures a complete-source certificate.
pub fn inspect_header(prefix: &[u8], source_size: u64) -> Result<HeaderDirectory> {
    if source_size > MAX_SOURCE_BYTES || prefix.len() < 8 || prefix.len() as u64 > source_size {
        bail!("header prefix or declared source size is outside this profile");
    }
    let length = u64::from_le_bytes(prefix[..8].try_into()?);
    if length == 0 || length > (MAX_HEADER_BYTES - 8) as u64 {
        bail!("safetensors header exceeds the bounded profile");
    }
    let data_offset = 8_u64
        .checked_add(length)
        .ok_or_else(|| anyhow!("header extent overflow"))?;
    if data_offset > source_size || data_offset > prefix.len() as u64 {
        bail!("truncated safetensors header");
    }
    let end = usize::try_from(data_offset)?;
    if prefix.get(8) != Some(&b'{') {
        bail!("safetensors header must begin with a JSON object");
    }
    let document = unique_json(&prefix[8..end])?;
    let object = document
        .as_object()
        .ok_or_else(|| anyhow!("safetensors header is not an object"))?;
    if object.len() > MAX_TENSORS + 1 {
        bail!("tensor directory exceeds the profile limit");
    }
    let mut tensors = BTreeMap::new();
    for (name, value) in object {
        if name == "__metadata__" {
            let metadata = value
                .as_object()
                .ok_or_else(|| anyhow!("metadata must be a string map in this profile"))?;
            if metadata.values().any(|item| !item.is_string()) {
                bail!("metadata must contain only strings");
            }
            continue;
        }
        if name.is_empty() || name.len() > 4096 || name.chars().any(char::is_control) {
            bail!("invalid tensor name");
        }
        let entry: Entry = serde_json::from_value(value.clone())
            .context("floating safetensors descriptor has unsupported fields or dtype")?;
        if entry.shape.is_empty() || entry.shape.len() > 8 || entry.shape.contains(&0) {
            bail!("this weight profile requires positive rank-one through rank-eight shapes");
        }
        let elements = entry.shape.iter().try_fold(1_u64, |product, dimension| {
            product
                .checked_mul(*dimension)
                .ok_or_else(|| anyhow!("tensor shape product overflows u64"))
        })?;
        let bytes = elements
            .checked_mul(entry.dtype.width())
            .ok_or_else(|| anyhow!("tensor storage length overflows u64"))?;
        let [start, stop] = entry.data_offsets;
        if start > stop || stop > source_size - data_offset || stop - start != bytes {
            bail!("actual header shape, dtype and offsets disagree");
        }
        tensors.insert(
            name.clone(),
            TensorDescriptor {
                name: name.clone(),
                dtype: entry.dtype,
                shape: entry.shape,
                data_offsets: entry.data_offsets,
                file_offset: data_offset + start,
                byte_length: bytes,
                elements,
                payload_sha256: None,
            },
        );
    }
    if tensors.is_empty() || tensors.len() > MAX_TENSORS {
        bail!("empty or oversized floating tensor directory");
    }
    let mut ranges: Vec<_> = tensors.values().map(|row| row.data_offsets).collect();
    ranges.sort_unstable();
    let mut cursor = 0;
    for [start, stop] in ranges {
        if start != cursor {
            bail!("safetensors payload has a gap or overlapping tensors");
        }
        cursor = stop;
    }
    if cursor != source_size - data_offset {
        bail!("safetensors has unindexed trailing bytes");
    }
    Ok(HeaderDirectory {
        source_size_bytes: source_size,
        header_bytes: data_offset,
        header_sha256: digest(&prefix[..end]),
        tensors,
    })
}

fn finite_payload(dtype: Dtype, bytes: &[u8]) -> Result<()> {
    let width = usize::try_from(dtype.width())?;
    if !bytes.len().is_multiple_of(width) {
        bail!("tensor bytes are not element aligned");
    }
    for chunk in bytes.chunks_exact(width) {
        let finite = match dtype {
            Dtype::F16 => u16::from_le_bytes(chunk.try_into()?) & 0x7c00 != 0x7c00,
            Dtype::BF16 => u16::from_le_bytes(chunk.try_into()?) & 0x7f80 != 0x7f80,
            Dtype::F32 => f32::from_le_bytes(chunk.try_into()?).is_finite(),
            Dtype::F64 => f64::from_le_bytes(chunk.try_into()?).is_finite(),
        };
        if !finite {
            bail!("nonfinite stored tensor element");
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub struct CompleteReceipt {
    pub source: SourcePin,
    pub header: HeaderDirectory,
    pub tensor_map_sha256: String,
    pub full_file_sha256_verified: bool,
    pub all_payloads_sha256_verified: bool,
    pub remote_owner_attested: bool,
}

/// Not deserializable: only actual captured bytes can construct this type.
pub struct AuthenticatedSafetensors<'a> {
    bytes: &'a [u8],
    receipt: CompleteReceipt,
}

impl<'a> AuthenticatedSafetensors<'a> {
    pub fn receipt(&self) -> &CompleteReceipt {
        &self.receipt
    }
    pub fn tensor(&self, name: &str) -> Result<&TensorDescriptor> {
        self.receipt
            .header
            .tensors
            .get(name)
            .ok_or_else(|| anyhow!("tensor is absent from authenticated source"))
    }
    pub fn payload(&self, name: &str) -> Result<&'a [u8]> {
        let row = self.tensor(name)?;
        let start = usize::try_from(row.file_offset)?;
        let stop = start + usize::try_from(row.byte_length)?;
        Ok(&self.bytes[start..stop])
    }
}

pub fn authenticate_safetensors<'a>(
    bytes: &'a [u8],
    pin: &SourcePin,
) -> Result<AuthenticatedSafetensors<'a>> {
    pin.verify(bytes, MAX_INPUT_BYTES)?;
    let mut header = inspect_header(bytes, bytes.len() as u64)?;
    for row in header.tensors.values_mut() {
        let start = usize::try_from(row.file_offset)?;
        let stop = start + usize::try_from(row.byte_length)?;
        let payload = &bytes[start..stop];
        finite_payload(row.dtype, payload)?;
        row.payload_sha256 = Some(digest(payload));
    }
    let tensor_map_sha256 = digest(&serde_json::to_vec(&header.tensors)?);
    Ok(AuthenticatedSafetensors {
        bytes,
        receipt: CompleteReceipt {
            source: pin.clone(),
            header,
            tensor_map_sha256,
            full_file_sha256_verified: true,
            all_payloads_sha256_verified: true,
            remote_owner_attested: false,
        },
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorClaim {
    pub source_file_sha256: String,
    pub tensor_name: String,
    pub dtype: Dtype,
    pub shape: Vec<u64>,
    pub file_offset: u64,
    pub byte_length: u64,
    pub source_tensor_sha256: String,
}

pub fn authenticate_claims(
    model: &AuthenticatedSafetensors<'_>,
    claims: &[DescriptorClaim],
) -> Result<()> {
    if claims.is_empty() || claims.len() > 32 {
        bail!("descriptor claim cohort must contain 1..32 members");
    }
    let mut names = BTreeSet::new();
    for claim in claims {
        validate_sha256(&claim.source_tensor_sha256)?;
        let row = model.tensor(&claim.tensor_name)?;
        if !names.insert(&claim.tensor_name)
            || claim.source_file_sha256 != model.receipt.source.sha256
            || claim.dtype != row.dtype
            || claim.shape != row.shape
            || claim.file_offset != row.file_offset
            || claim.byte_length != row.byte_length
            || row.payload_sha256.as_deref() != Some(&claim.source_tensor_sha256)
        {
            bail!("claim does not match the complete source descriptor; implicit reshape is forbidden");
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkPin {
    pub name: String,
    pub local: u64,
    pub offset: u64,
    pub limit: u64,
    pub total: u64,
    pub sha256: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubsetPin {
    pub source_path: String,
    pub observed_version: String,
    pub reported_full_sha256: String,
    pub source_size_bytes: u64,
    pub prefix: SourcePin,
    pub header_receipt_sha256: String,
    pub receipt_sha256: String,
    pub chunks: Vec<ChunkPin>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SubsetReceipt {
    pub source_path: String,
    pub observed_version: String,
    pub reported_full_sha256: String,
    pub header: HeaderDirectory,
    pub available_tensors: BTreeMap<String, TensorDescriptor>,
    pub tensor_map_sha256: String,
    pub transfer_receipt_sha256: String,
    pub header_transfer_receipt_sha256: String,
    pub receipt_linked_payloads_verified: bool,
    pub full_source_sha256_verified: bool,
    pub remote_owner_attested: bool,
    pub payload_membership_in_full_digest_proven: bool,
}

pub struct AuthenticatedSubset {
    receipt: SubsetReceipt,
}

impl AuthenticatedSubset {
    pub fn receipt(&self) -> &SubsetReceipt {
        &self.receipt
    }
    pub fn require_complete_source(&self) -> Result<()> {
        bail!("receipt-linked tensor subsets cannot authorize a complete checkpoint claim")
    }
}

/// Receipts bind captured chunks to a shared observed path/version assertion.
/// They are not a cryptographic membership proof against the reported full digest.
pub fn authenticate_subset(
    prefix: &[u8],
    parts: &BTreeMap<String, Vec<u8>>,
    pin: &SubsetPin,
    transfer_receipt: &[u8],
    header_receipt: &[u8],
) -> Result<AuthenticatedSubset> {
    validate_sha256(&pin.reported_full_sha256)?;
    validate_sha256(&pin.receipt_sha256)?;
    validate_sha256(&pin.header_receipt_sha256)?;
    if header_receipt.len() > crate::MAX_JSON_BYTES
        || digest(header_receipt) != pin.header_receipt_sha256
    {
        bail!("header transfer receipt differs from its reviewed identity");
    }
    let header_record = unique_json(header_receipt)?;
    let observed = &header_record["header"];
    if observed["chunk_sha256"] != pin.prefix.sha256
        || observed["size"].as_u64() != Some(pin.source_size_bytes)
        || observed["path"] != pin.source_path
        || observed["version"] != pin.observed_version
        || observed["offset"] != 0
        || observed["next_offset"].as_u64() != Some(prefix.len() as u64)
        || observed["eof"] != false
    {
        bail!("header bytes/path/version/extent do not match the actual transfer receipt");
    }
    if transfer_receipt.len() > crate::MAX_JSON_BYTES
        || digest(transfer_receipt) != pin.receipt_sha256
    {
        bail!("transfer receipt differs from its reviewed identity");
    }
    let actual_chunks: Vec<ChunkPin> = serde_json::from_value(unique_json(transfer_receipt)?)?;
    if serde_json::to_vec(&actual_chunks)? != serde_json::to_vec(&pin.chunks)? {
        bail!("derived chunk pins do not match the actual receipt");
    }
    if pin.source_path.is_empty()
        || pin.source_path.len() > 4096
        || pin.observed_version.is_empty()
        || pin.observed_version.len() > 1024
        || parts.is_empty()
        || parts.len() > 32
        || pin.chunks.len() > 1024
    {
        bail!("partial-source identity or counts are outside the profile");
    }
    pin.prefix.verify(prefix, MAX_HEADER_BYTES)?;
    let header = inspect_header(prefix, pin.source_size_bytes)?;
    let mut available = BTreeMap::new();
    let mut total_bytes = 0usize;
    for (name, bytes) in parts {
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow!("subset byte count overflow"))?;
        if total_bytes > MAX_INPUT_BYTES {
            bail!("tensor subset exceeds bounded capture size");
        }
        let mut row = header
            .tensors
            .get(name)
            .ok_or_else(|| anyhow!("subset tensor missing from actual header"))?
            .clone();
        if bytes.len() as u64 != row.byte_length {
            bail!("tensor subset does not contain its complete declared payload");
        }
        let mut chunks: Vec<_> = pin
            .chunks
            .iter()
            .filter(|chunk| chunk.name == *name)
            .collect();
        chunks.sort_by_key(|chunk| chunk.local);
        let mut next = 0;
        for chunk in chunks {
            validate_sha256(&chunk.sha256)?;
            if chunk.version != pin.observed_version
                || chunk.local != next
                || chunk.total != row.byte_length
                || chunk.limit == 0
                || chunk.limit > 65_536
                || chunk.offset != row.file_offset + chunk.local
                || chunk.limit > row.byte_length - next
            {
                bail!(
                    "chunk receipt has a gap, overlap, changed version or incorrect source offset"
                );
            }
            let start = usize::try_from(chunk.local)?;
            let stop = start + usize::try_from(chunk.limit)?;
            if digest(&bytes[start..stop]) != chunk.sha256 {
                bail!("captured tensor payload differs from chunk receipt");
            }
            next += chunk.limit;
        }
        if next != row.byte_length {
            bail!("receipt does not cover the complete supplied tensor");
        }
        finite_payload(row.dtype, bytes)?;
        row.payload_sha256 = Some(digest(bytes));
        available.insert(name.clone(), row);
    }
    if pin
        .chunks
        .iter()
        .any(|chunk| !parts.contains_key(&chunk.name))
    {
        bail!("receipt includes an omitted tensor");
    }
    let tensor_map_sha256 = digest(&serde_json::to_vec(&available)?);
    Ok(AuthenticatedSubset {
        receipt: SubsetReceipt {
            source_path: pin.source_path.clone(),
            observed_version: pin.observed_version.clone(),
            reported_full_sha256: pin.reported_full_sha256.clone(),
            header,
            available_tensors: available,
            tensor_map_sha256,
            transfer_receipt_sha256: pin.receipt_sha256.clone(),
            header_transfer_receipt_sha256: pin.header_receipt_sha256.clone(),
            receipt_linked_payloads_verified: true,
            full_source_sha256_verified: false,
            remote_owner_attested: false,
            payload_membership_in_full_digest_proven: false,
        },
    })
}
