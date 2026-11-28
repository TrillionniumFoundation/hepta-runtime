// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit caller commitments bind bytes; they do not prove declared model provenance.
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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
pub struct BoundModel {
	pub(super) tensors: BTreeMap<String, Vec<f64>>,
	pub(super) source_declarations: Value,
	pub(super) canonical_sha256: String,
	pub(super) source_checkpoint_sha256: String,
	pub(super) profile_identifier: u64,
	pub(super) artifact_sha256: String,
	pub(super) header_sha256: String,
	pub(super) profile_sha256: String,
	pub(super) input_sha256: String,
	pub(super) tensor_facts: Vec<Value>,
}
pub(super) fn bind(manifest: &[u8], artifact: &[u8], input: &[u8]) -> Result<BoundModel> {
	bind_in_scope(manifest, artifact, input, false)
}

pub(super) fn bind_sender_candidate(
	manifest: &[u8],
	artifact: &[u8],
	input: &[u8],
) -> Result<BoundModel> {
	bind_in_scope(manifest, artifact, input, true)
}

fn bind_in_scope(
	manifest: &[u8],
	artifact: &[u8],
	input: &[u8],
	sender_scope: bool,
) -> Result<BoundModel> {
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
	let mut tensor_facts = Vec::new();
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
		// The public profile retains its original readout declaration. A fixed sender
		// candidate instead keeps that readout immutable and admits only these two tensors.
		let mutable = if sender_scope {
			matches!(
				tensor.name.as_str(),
				"body.input_drive.weight" | "body.input_drive.bias"
			)
		} else {
			tensor.mutable
		};
		ensure!(
			mutable || sha(bytes) == tensor.sha256,
			"immutable body tensor changed"
		);
		tensor_facts.push(json!({"name":tensor.name,"dtype":dtype,"shape":shape,
			"file_offset":8+hlen+begin,"byte_length":bytes.len(),"payload_sha256":sha(bytes)}));
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
		artifact_sha256: sha(artifact),
		header_sha256: header_sha,
		profile_sha256: sha(manifest),
		input_sha256: sha(input),
		tensor_facts,
	})
}
pub struct Inputs {
	pub(super) n: usize,
	pub(super) x: Vec<f32>,
	pub(super) baseline: Vec<f32>,
	pub(super) labels: Vec<u8>,
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

impl BoundModel {
	pub fn canonical_sha256(&self) -> &str {
		&self.canonical_sha256
	}
	pub fn artifact_sha256(&self) -> &str {
		&self.artifact_sha256
	}
	pub fn input_sha256(&self) -> &str {
		&self.input_sha256
	}
	/// Exact original F32 sender words from this opaque admitted model, without a forward.
	pub fn sender_drive_f32(&self) -> Result<[f32; 40]> {
		let weight = self
			.tensors
			.get("body.input_drive.weight")
			.context("bound sender weight")?;
		let bias = self
			.tensors
			.get("body.input_drive.bias")
			.context("bound sender bias")?;
		ensure!(weight.len() == 36 && bias.len() == 4, "bound sender shape");
		let mut result = [0.0f32; 40];
		for (output, value) in result.iter_mut().zip(weight.iter().chain(bias)) {
			let represented = *value as f32;
			ensure!(
				represented.is_finite() && (represented as f64).to_bits() == value.to_bits(),
				"sender coordinate is not its original exact F32 word"
			);
			*output = represented;
		}
		Ok(result)
	}
	pub fn source_checkpoint_sha256(&self) -> &str {
		&self.source_checkpoint_sha256
	}
	pub fn profile_identifier(&self) -> u64 {
		self.profile_identifier
	}
	pub fn source_declarations(&self) -> &Value {
		&self.source_declarations
	}
}

impl Inputs {
	pub fn queries(&self) -> usize {
		self.n
	}
	/// Validation labels remain separate from the label-free semantic task view.
	pub fn labels(&self) -> &[u8] {
		&self.labels
	}
	/// A normalized raw key for the fixed shared affine sender, without executing its body.
	pub fn normalized_sender_key(
		&self,
		query: usize,
		choice: usize,
		tick: usize,
	) -> Result<[f32; 10]> {
		ensure!(
			query < self.n && choice < 2 && tick < 6,
			"sender key index outside fixed raw batch"
		);
		let begin = ((query * 6 + tick) * 2 + choice) * 9;
		let row = self
			.x
			.get(begin..begin + 9)
			.context("bound normalized sender key")?;
		ensure!(
			row.iter().all(|value| value.is_finite()),
			"nonfinite normalized sender key"
		);
		let mut key = [1.0f32; 10];
		key[..9].copy_from_slice(row);
		Ok(key)
	}
}
