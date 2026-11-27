// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit caller commitments bind bytes; they do not prove declared model provenance.
use super::deadline::Deadline;
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};
use tokio::{fs::File, io::AsyncReadExt};

pub(super) fn sha(bytes: &[u8]) -> String {
	let alphabet = b"0123456789abcdef";
	Sha256::digest(bytes)
		.iter()
		.flat_map(|byte| {
			[
				char::from(alphabet[(*byte >> 4) as usize]),
				char::from(alphabet[(*byte & 15) as usize]),
			]
		})
		.collect()
}
pub(super) async fn capture(
	path: &Path,
	expected: &str,
	cap: u64,
	deadline: &Deadline,
) -> Result<Vec<u8>> {
	deadline.check()?;
	ensure!(path.is_absolute(), "explicit absolute input path required");
	let file = tokio::time::timeout(deadline.remaining()?, File::open(path))
		.await
		.context("file open deadline")?
		.context("open explicit file")?;
	let metadata = tokio::time::timeout(deadline.remaining()?, file.metadata())
		.await
		.context("metadata deadline")?
		.context("read file metadata")?;
	ensure!(
		metadata.is_file() && metadata.len() <= cap,
		"input is not a bounded regular file"
	);
	let mut raw = Vec::new();
	tokio::time::timeout(
		deadline.remaining()?,
		file.take(cap + 1).read_to_end(&mut raw),
	)
	.await
	.context("file read deadline")?
	.context("read bounded file")?;
	deadline.check()?;
	ensure!(
		raw.len() as u64 == metadata.len() && sha(&raw) == expected,
		"whole input identity mismatch"
	);
	Ok(raw)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TensorPin {
	name: String,
	dtype: String,
	shape: Vec<usize>,
	data_offsets: [usize; 2],
	sha256: String,
	mutable: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
	seed: u64,
	canonical_sha256: String,
	source_pt_sha256: String,
	header_sha256: String,
	header_length: usize,
	file_bytes: usize,
	tensors: Vec<TensorPin>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
	schema: String,
	input_sha256: String,
	input_bytes: usize,
	profiles: Vec<Profile>,
	source_declarations: Value,
	configuration: Value,
}
pub(super) struct BoundModel {
	pub tensors: BTreeMap<String, Vec<f64>>,
	pub source_declarations: Value,
	pub canonical_sha256: String,
	pub source_checkpoint_sha256: String,
	pub profile_identifier: u64,
}
pub(super) fn bind(manifest: &[u8], artifact: &[u8], input: &[u8]) -> Result<BoundModel> {
	let pins: Pins = serde_json::from_slice(manifest)?;
	ensure!(
		pins.schema == "hepta.native-smallhcsn-bound-profile.v1"
			&& (1..=16).contains(&pins.profiles.len()),
		"unsupported profile schema"
	);
	ensure!(
		pins.input_bytes == input.len() && pins.input_sha256 == sha(input),
		"profile/input binding mismatch"
	);
	let config = json!({"neurons":8,"bins":6,"refractory_stages":3,"ticks":6,"choices":2,"input_width":9,
        "dt":0.48,"sigma":0.55,"rho":0.3,"extent":2.0,"refractory":0.2,"gain":0.8,"maintenance":0.25,
        "mode":"qvi-boundary-centered-mixed-value-risk-no-feature-normalization"});
	ensure!(
		pins.configuration == config,
		"unsupported mathematical configuration"
	);
	ensure!(
		(10..=131072).contains(&artifact.len()),
		"artifact length bound"
	);
	let hlen = usize::try_from(u64::from_le_bytes(artifact[..8].try_into()?))?;
	ensure!(
		(2..=65536).contains(&hlen) && 8 + hlen <= artifact.len(),
		"header bound"
	);
	let header_sha = sha(&artifact[8..8 + hlen]);
	let matching: Vec<_> = pins
		.profiles
		.iter()
		.filter(|p| p.header_sha256 == header_sha)
		.collect();
	ensure!(matching.len() == 1, "header is not uniquely committed");
	let pin = matching[0];
	ensure!(
		hlen == pin.header_length && artifact.len() == pin.file_bytes && pin.tensors.len() == 12,
		"committed artifact layout mismatch"
	);
	// The complete known header digest is checked before JSON interpretation.
	let header: Value = serde_json::from_slice(&artifact[8..8 + hlen])?;
	let object = header.as_object().context("header object required")?;
	ensure!(object.len() == 13, "exact canonical tensor set required");
	let metadata = object
		.get("__metadata__")
		.and_then(Value::as_object)
		.context("metadata required")?;
	ensure!(
		metadata.values().all(Value::is_string),
		"non-string metadata"
	);
	ensure!(
		metadata
			.get("source_checkpoint_sha256")
			.and_then(Value::as_str)
			== Some(pin.source_pt_sha256.as_str()),
		"source checkpoint binding"
	);
	let aliases: Value = serde_json::from_str(
		metadata
			.get("alias_map_json")
			.and_then(Value::as_str)
			.context("alias declaration required")?,
	)?;
	ensure!(
		aliases == json!({"head.weight":"body.readout.weight","head.bias":"body.readout.bias"}),
		"unsupported alias layout"
	);
	let mut tensors = BTreeMap::new();
	let mut spans = Vec::new();
	for tensor in &pin.tensors {
		let (dtype, shape): (&str, Vec<usize>) = match tensor.name.as_str() {
			"body.raw_cost" | "body.raw_boundary" => ("F32", vec![8]),
			"body.fixed_boundary" | "body.reset_absolute" => ("F64", vec![8]),
			"body.synaptic_mask" | "body.recurrent.weight" => ("F32", vec![8, 24]),
			"body.input_drive.weight" | "body.input_mark.weight" => ("F32", vec![4, 9]),
			"body.input_drive.bias" | "body.input_mark.bias" => ("F32", vec![4]),
			"body.readout.weight" => ("F32", vec![2, 20]),
			"body.readout.bias" => ("F32", vec![2]),
			_ => bail!("unsupported tensor"),
		};
		ensure!(
			tensor.dtype == dtype
				&& tensor.shape == shape
				&& tensor.mutable == (tensor.name == "body.readout.weight"),
			"profile tensor contract"
		);
		let descriptor = json!({"dtype":dtype,"shape":shape,"data_offsets":tensor.data_offsets});
		ensure!(
			object.get(&tensor.name) == Some(&descriptor),
			"header/shape commitment mismatch"
		);
		let [begin, end] = tensor.data_offsets;
		let width = if dtype == "F32" { 4 } else { 8 };
		ensure!(
			begin <= end
				&& end <= artifact.len() - 8 - hlen
				&& end - begin == shape.iter().product::<usize>() * width,
			"tensor byte bounds"
		);
		let bytes = &artifact[8 + hlen + begin..8 + hlen + end];
		ensure!(
			tensor.mutable || sha(bytes) == tensor.sha256,
			"immutable body tensor changed"
		);
		let values: Vec<f64> = bytes
			.chunks_exact(width)
			.map(|x| -> Result<f64> {
				Ok(if width == 4 {
					f32::from_le_bytes(x.try_into().context("F32 tensor word")?) as f64
				} else {
					f64::from_le_bytes(x.try_into().context("F64 tensor word")?)
				})
			})
			.collect::<Result<_>>()?;
		ensure!(values.iter().all(|x| x.is_finite()), "nonfinite tensor");
		ensure!(
			tensors.insert(tensor.name.clone(), values).is_none(),
			"duplicate tensor pin"
		);
		spans.push((begin, end));
	}
	spans.sort_unstable();
	let mut end = 0;
	for (a, b) in spans {
		ensure!(a == end, "tensor overlap or uncovered bytes");
		end = b;
	}
	ensure!(end == artifact.len() - 8 - hlen, "trailing payload bytes");
	Ok(BoundModel {
		tensors,
		source_declarations: pins.source_declarations,
		canonical_sha256: pin.canonical_sha256.clone(),
		source_checkpoint_sha256: pin.source_pt_sha256.clone(),
		profile_identifier: pin.seed,
	})
}
pub(super) struct Inputs {
	pub n: usize,
	pub x: Vec<f32>,
	pub baseline: Vec<f32>,
	pub labels: Vec<u8>,
}
pub(super) fn inputs(raw: &[u8]) -> Result<Inputs> {
	ensure!(
		raw.len() >= 100 && &raw[..8] == b"HCSNIN1\0",
		"input format"
	);
	let dims: Vec<_> = raw[8..24]
		.chunks_exact(4)
		.map(|b| -> Result<usize> {
			Ok(u32::from_le_bytes(b.try_into().context("dimension word")?) as usize)
		})
		.collect::<Result<_>>()?;
	let n = dims[0];
	ensure!(
		(1..=80).contains(&n)
			&& dims[1..] == [6, 2, 9]
			&& raw.len() == 100 + n * (6 * 2 * 9 * 4 + 2 * 4 + 8),
		"input layout/bound"
	);
	let values: Vec<f32> = raw[24..raw.len() - n * 8]
		.chunks_exact(4)
		.map(|b| -> Result<f32> { Ok(f32::from_le_bytes(b.try_into().context("input F32 word")?)) })
		.collect::<Result<_>>()?;
	ensure!(
		values.iter().all(|v| v.is_finite()) && values[9..19].iter().all(|v| *v > 0.0),
		"normalization values"
	);
	let mut x = values[19..19 + n * 108].to_vec();
	for (i, v) in x.iter_mut().enumerate() {
		*v = (*v - values[i % 9]) / values[9 + i % 9];
	}
	let baseline: Vec<_> = values[19 + n * 108..]
		.iter()
		.map(|v| *v / values[18])
		.collect();
	let labels: Vec<_> = raw[raw.len() - n * 8..]
		.chunks_exact(8)
		.map(|b| -> Result<i64> { Ok(i64::from_le_bytes(b.try_into().context("label word")?)) })
		.collect::<Result<_>>()?;
	ensure!(
		labels.iter().all(|v| *v == 0 || *v == 1)
			&& x.iter().chain(&baseline).all(|v| v.is_finite()),
		"input labels or normalized domain"
	);
	Ok(Inputs {
		n,
		x,
		baseline,
		labels: labels.iter().map(|x| *x as u8).collect(),
	})
}
