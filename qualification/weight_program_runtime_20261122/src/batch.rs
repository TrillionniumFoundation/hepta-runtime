// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded collection parsing while retaining the existing per-document guards.

use crate::snapshot::MAX_INPUT_BYTES;
use anyhow::{bail, Result};
use hepta_semantic_source_adapter_study::unique_json;
use serde::{
	de::{DeserializeOwned, Error, SeqAccess, Visitor},
	Deserialize, Deserializer,
};
use serde_json::value::RawValue;
use std::{fmt, marker::PhantomData};

const MAX_REQUESTS: usize = 2048;
struct Requests<T>(Vec<T>);

impl<'de, T: DeserializeOwned> Deserialize<'de> for Requests<T> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
		struct RequestVisitor<T>(PhantomData<T>);
		impl<'de, T: DeserializeOwned> Visitor<'de> for RequestVisitor<T> {
			type Value = Requests<T>;
			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("one to 2048 independently bounded unique JSON requests")
			}
			fn visit_seq<A: SeqAccess<'de>>(
				self,
				mut sequence: A,
			) -> std::result::Result<Self::Value, A::Error> {
				let mut values = Vec::new();
				while let Some(raw) = sequence.next_element::<Box<RawValue>>()? {
					if values.len() >= MAX_REQUESTS {
						return Err(A::Error::custom("batch request count exceeded"));
					}
					let unique = unique_json(raw.get().as_bytes()).map_err(A::Error::custom)?;
					values.push(serde_json::from_value(unique).map_err(A::Error::custom)?);
				}
				if values.is_empty() {
					return Err(A::Error::custom("empty request batch"));
				}
				Ok(Requests(values))
			}
		}
		deserializer.deserialize_seq(RequestVisitor(PhantomData))
	}
}

pub fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<Vec<T>> {
	if bytes.len() > MAX_INPUT_BYTES {
		bail!("total batch byte limit exceeded");
	}
	Ok(serde_json::from_slice::<Requests<T>>(bytes)?.0)
}
