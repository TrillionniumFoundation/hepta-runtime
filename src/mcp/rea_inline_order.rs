// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Source-owned JavaScript property order for inline Evidence diagnostics.
//! Only the transport's bounded raw frame parser creates this tree. Values are
//! consumed without retaining a second Evidence payload; duplicate properties
//! keep their first position and replace their complete child-order subtree.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::rc::Rc;

const MAX_NODES: usize = 131_072;
pub(super) const BUDGET_ERROR: &str = "native inline Evidence order capture exceeds 131072 nodes";

#[derive(Debug)]
enum Node {
	Leaf,
	Array(Vec<Node>),
	Object {
		keys: Vec<String>,
		children: BTreeMap<String, Node>,
	},
}

#[derive(Debug)]
pub(crate) struct InlineEvidenceOrder(Node);

impl InlineEvidenceOrder {
	pub(crate) fn keys(&self, path: &[Value]) -> Option<Vec<String>> {
		let mut node = &self.0;
		for part in path {
			node = match node {
				Node::Array(children) => children.get(usize::try_from(part.as_u64()?).ok()?)?,
				Node::Object { children, .. } => children.get(part.as_str()?)?,
				Node::Leaf => return None,
			};
		}
		match node {
			Node::Object { keys, .. } => Some(keys.clone()),
			_ => None,
		}
	}
}

impl<'de> Deserialize<'de> for InlineEvidenceOrder {
	fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
		Scanner(Rc::new(Cell::new(MAX_NODES)))
			.deserialize(decoder)
			.map(Self)
	}
}

struct Scanner(Rc<Cell<usize>>);

impl<'de> DeserializeSeed<'de> for Scanner {
	type Value = Node;
	fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Node, D::Error> {
		let remaining = self
			.0
			.get()
			.checked_sub(1)
			.ok_or_else(|| de::Error::custom(BUDGET_ERROR))?;
		self.0.set(remaining);
		decoder.deserialize_any(self)
	}
}

fn array_index(key: &str) -> Option<u32> {
	let index = key.parse::<u32>().ok()?;
	(index != u32::MAX && index.to_string() == key).then_some(index)
}

impl<'de> Visitor<'de> for Scanner {
	type Value = Node;
	fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("a JSON value within the inline order capture allowance")
	}
	fn visit_unit<E: de::Error>(self) -> Result<Node, E> {
		Ok(Node::Leaf)
	}
	fn visit_bool<E: de::Error>(self, _: bool) -> Result<Node, E> {
		Ok(Node::Leaf)
	}
	fn visit_i64<E: de::Error>(self, _: i64) -> Result<Node, E> {
		Ok(Node::Leaf)
	}
	fn visit_u64<E: de::Error>(self, _: u64) -> Result<Node, E> {
		Ok(Node::Leaf)
	}
	fn visit_f64<E: de::Error>(self, _: f64) -> Result<Node, E> {
		Ok(Node::Leaf)
	}
	fn visit_str<E: de::Error>(self, _: &str) -> Result<Node, E> {
		Ok(Node::Leaf)
	}
	fn visit_string<E: de::Error>(self, _: String) -> Result<Node, E> {
		Ok(Node::Leaf)
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Node, A::Error> {
		let mut children = Vec::new();
		while let Some(child) = access.next_element_seed(Scanner(Rc::clone(&self.0)))? {
			children.push(child);
		}
		Ok(Node::Array(children))
	}
	fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Node, A::Error> {
		let mut keys = Vec::new();
		let mut children = BTreeMap::new();
		while let Some(key) = access.next_key::<String>()? {
			if !children.contains_key(&key) {
				keys.push(key.clone());
			}
			let child = access.next_value_seed(Scanner(Rc::clone(&self.0)))?;
			children.insert(key, child);
		}
		keys.sort_by_key(|key| array_index(key).map_or((1, 0), |index| (0, index)));
		Ok(Node::Object { keys, children })
	}
}
