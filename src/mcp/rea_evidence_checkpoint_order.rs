// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Versioned, complete object-order sidecars for private Evidence checkpoints.
//! Paths are flat so the sidecar does not double the JSON parser's depth.

use super::{array_index, ObjectOrder, OrderNode};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_DEPTH: usize = 120;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
enum Part {
	Key(String),
	Index(usize),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::mcp) struct StoredObjectOrder {
	path: Vec<Part>,
	keys: Vec<String>,
}

fn check_keys(object: &serde_json::Map<String, Value>, keys: &[String]) -> Result<()> {
	ensure!(
		keys.len() == object.len(),
		"checkpoint object-order key count differs"
	);
	let mut seen = BTreeSet::new();
	let mut ordinary = false;
	let mut prior = None;
	for key in keys {
		ensure!(
			object.contains_key(key) && seen.insert(key),
			"checkpoint object-order keys are incomplete or duplicated"
		);
		if let Some(index) = array_index(key) {
			ensure!(
				!ordinary && prior.is_none_or(|previous| previous < index),
				"checkpoint object-order numeric keys are not in JavaScript order"
			);
			prior = Some(index);
		} else {
			ordinary = true;
		}
	}
	Ok(())
}

fn charge(remaining: &mut usize, amount: usize) -> Result<()> {
	*remaining = remaining
		.checked_sub(amount)
		.context("native checkpoint object-order budget exceeded")?;
	Ok(())
}

impl ObjectOrder {
	pub(in crate::mcp) fn checkpoint_order(
		&self,
		value: &Value,
		remaining: &mut usize,
	) -> Result<Vec<StoredObjectOrder>> {
		fn visit(
			value: &Value,
			node: &OrderNode,
			path: &mut Vec<Part>,
			out: &mut Vec<StoredObjectOrder>,
			remaining: &mut usize,
		) -> Result<()> {
			ensure!(
				path.len() <= MAX_DEPTH,
				"native checkpoint object-order depth exceeds 120"
			);
			match (value, node) {
				(Value::Object(object), OrderNode::Object { keys, children }) => {
					// Fixed-schema authentication can strip its own __proto__ member.
					// Persist only keys still present in the authenticated immutable value.
					let key_bytes = keys
						.iter()
						.filter(|key| object.contains_key(*key))
						.try_fold(0usize, |sum, key| {
							sum.checked_add(key.len().saturating_mul(6).saturating_add(16))
								.context("checkpoint order size overflow")
						})?;
					let path_bytes = path.iter().try_fold(0usize, |sum, part| {
						sum.checked_add(match part {
							Part::Key(key) => key.len().saturating_mul(6).saturating_add(16),
							Part::Index(_) => 32,
						})
						.context("checkpoint path size overflow")
					})?;
					charge(
						remaining,
						key_bytes.saturating_add(path_bytes).saturating_add(128),
					)?;
					let kept: Vec<_> = keys
						.iter()
						.filter(|key| object.contains_key(*key))
						.cloned()
						.collect();
					check_keys(object, &kept)?;
					out.push(StoredObjectOrder {
						path: path.clone(),
						keys: kept,
					});
					for (key, child) in object {
						path.push(Part::Key(key.clone()));
						visit(
							child,
							children
								.get(key)
								.context("checkpoint source order child is missing")?,
							path,
							out,
							remaining,
						)?;
						path.pop();
					}
				}
				(Value::Array(values), OrderNode::Array(children)) => {
					ensure!(
						values.len() == children.len(),
						"checkpoint source order array length differs"
					);
					for (index, (value, child)) in values.iter().zip(children).enumerate() {
						path.push(Part::Index(index));
						visit(value, child, path, out, remaining)?;
						path.pop();
					}
				}
				(
					Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_),
					OrderNode::Leaf,
				) => {}
				_ => bail!("checkpoint source order does not match its retained value"),
			}
			Ok(())
		}
		let mut result = Vec::new();
		visit(value, &self.0, &mut Vec::new(), &mut result, remaining)?;
		Ok(result)
	}

	pub(in crate::mcp) fn from_checkpoint_order(
		value: &Value,
		stored: Vec<StoredObjectOrder>,
	) -> Result<Self> {
		let mut entries = BTreeMap::new();
		for entry in stored {
			ensure!(
				entry.path.len() <= MAX_DEPTH,
				"checkpoint order path exceeds its depth limit"
			);
			ensure!(
				entries.insert(entry.path, entry.keys).is_none(),
				"checkpoint object-order path is duplicated"
			);
		}
		fn rebuild(
			value: &Value,
			path: &mut Vec<Part>,
			entries: &mut BTreeMap<Vec<Part>, Vec<String>>,
		) -> Result<OrderNode> {
			ensure!(
				path.len() <= MAX_DEPTH,
				"checkpoint value exceeds its order depth limit"
			);
			Ok(match value {
				Value::Object(object) => {
					let keys = entries
						.remove(path)
						.context("checkpoint is missing a complete object-order entry")?;
					check_keys(object, &keys)?;
					let mut children = BTreeMap::new();
					for (key, child) in object {
						path.push(Part::Key(key.clone()));
						let node = rebuild(child, path, entries)?;
						path.pop();
						children.insert(key.clone(), node);
					}
					OrderNode::Object { keys, children }
				}
				Value::Array(values) => {
					let mut children = Vec::with_capacity(values.len());
					for (index, value) in values.iter().enumerate() {
						path.push(Part::Index(index));
						children.push(rebuild(value, path, entries)?);
						path.pop();
					}
					OrderNode::Array(children)
				}
				_ => OrderNode::Leaf,
			})
		}
		let root = rebuild(value, &mut Vec::new(), &mut entries)?;
		ensure!(
			entries.is_empty(),
			"checkpoint contains object-order paths absent from the complete value"
		);
		Ok(Self(root))
	}
}

#[cfg(test)]
#[path = "rea_evidence_checkpoint_order_tests.rs"]
mod tests;
