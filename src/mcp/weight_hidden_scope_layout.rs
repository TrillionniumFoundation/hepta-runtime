// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Admit the canonical twelve-tensor layout before locating any sender parameter bytes.

use super::{BIAS_NAME, WEIGHT_NAME};
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
	dtype: String,
	shape: Vec<usize>,
	data_offsets: [usize; 2],
}
pub(super) struct Layout {
	start: usize,
	spans: BTreeMap<String, [usize; 2]>,
}
impl Layout {
	pub(super) fn offset(&self, name: &str, index: usize) -> Result<usize> {
		let [begin, end] = self.spans.get(name).context("missing sender tensor")?;
		let offset = begin
			.checked_add(index.checked_mul(4).context("element offset overflow")?)
			.context("tensor offset overflow")?;
		ensure!(
			offset.checked_add(4).is_some_and(|value| value <= *end),
			"sender element extent"
		);
		self.start
			.checked_add(offset)
			.context("file offset overflow")
	}
}

pub(super) fn inspect(parent: &[u8], expected_header: &str) -> Result<Layout> {
	ensure!(
		(10..=131072).contains(&parent.len()),
		"canonical artifact bound"
	);
	let length = usize::try_from(u64::from_le_bytes(parent[..8].try_into()?))?;
	ensure!(
		(2..=65536).contains(&length) && length + 8 <= parent.len(),
		"canonical header bound"
	);
	ensure!(
		super::digest(&parent[8..8 + length]) == expected_header,
		"canonical header SHA differs"
	);
	let value = super::super::rea_evidence::parse_unique_json(&parent[8..8 + length])?;
	let object = value
		.as_object()
		.context("canonical header object required")?;
	ensure!(
		object.len() == 13,
		"twelve unique tensors and metadata required"
	);
	let metadata = object
		.get("__metadata__")
		.and_then(|value| value.as_object())
		.context("canonical metadata required")?;
	ensure!(
		metadata.values().all(|value| value.is_string()),
		"canonical metadata values must be strings"
	);
	let alias_text = metadata
		.get("alias_map_json")
		.and_then(|value| value.as_str())
		.context("canonical alias map required")?;
	let aliases = super::super::rea_evidence::parse_unique_json(alias_text.as_bytes())?;
	ensure!(
		aliases == json!({"head.weight":"body.readout.weight","head.bias":"body.readout.bias"}),
		"canonical aliases differ"
	);
	let mut spans = BTreeMap::new();
	let mut ordered = Vec::new();
	for (name, value) in object {
		if name == "__metadata__" {
			continue;
		}
		let descriptor: Descriptor = serde_json::from_value(value.clone())?;
		let (dtype, shape): (&str, Vec<usize>) = match name.as_str() {
			"body.raw_cost" | "body.raw_boundary" => ("F32", vec![8]),
			"body.reset_absolute" | "body.fixed_boundary" => ("F64", vec![8]),
			"body.synaptic_mask" | "body.recurrent.weight" => ("F32", vec![8, 24]),
			WEIGHT_NAME | "body.input_mark.weight" => ("F32", vec![4, 9]),
			BIAS_NAME | "body.input_mark.bias" => ("F32", vec![4]),
			"body.readout.weight" => ("F32", vec![2, 20]),
			"body.readout.bias" => ("F32", vec![2]),
			_ => bail!("unsupported canonical tensor"),
		};
		ensure!(
			descriptor.dtype == dtype && descriptor.shape == shape,
			"canonical tensor type/shape"
		);
		let [begin, end] = descriptor.data_offsets;
		let width = if dtype == "F32" { 4 } else { 8 };
		ensure!(
			begin <= end
				&& end <= parent.len() - 8 - length
				&& end - begin == shape.iter().product::<usize>() * width,
			"canonical tensor extent"
		);
		for raw in parent[8 + length + begin..8 + length + end].chunks_exact(width) {
			let finite = if width == 4 {
				f32::from_le_bytes(raw.try_into()?).is_finite()
			} else {
				f64::from_le_bytes(raw.try_into()?).is_finite()
			};
			ensure!(finite, "nonfinite canonical parameter");
		}
		ordered.push((begin, end));
		spans.insert(name.clone(), [begin, end]);
	}
	ordered.sort_unstable();
	let mut prior_end = 0;
	for (begin, end) in ordered {
		ensure!(
			begin == prior_end,
			"overlapping or uncovered canonical payload"
		);
		prior_end = end;
	}
	ensure!(
		prior_end == parent.len() - length - 8,
		"trailing canonical bytes"
	);
	Ok(Layout {
		start: length + 8,
		spans,
	})
}

pub(super) fn f32_word(hex: &str) -> Result<[u8; 4]> {
	ensure!(
		hex.len() == 8
			&& hex
				.bytes()
				.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
		"lowercase exact F32 little-endian hex required"
	);
	let mut word = [0u8; 4];
	for (index, byte) in word.iter_mut().enumerate() {
		*byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
	}
	ensure!(f32::from_le_bytes(word).is_finite(), "nonfinite F32 edit");
	Ok(word)
}
