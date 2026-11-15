use anyhow::{Context, Result};
use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Number, Value};
use std::fmt;
/// JSON parsing which refuses duplicate keys, including deeply nested objects.
#[derive(Debug)]
struct UniqueJson(Value);

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
	type Value = UniqueJson;

	fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str("JSON with no repeated object members")
	}
	fn visit_unit<E: DeError>(self) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(Value::Null))
	}
	fn visit_none<E: DeError>(self) -> std::result::Result<Self::Value, E> {
		self.visit_unit()
	}
	fn visit_bool<E: DeError>(self, x: bool) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(json!(x)))
	}
	fn visit_i64<E: DeError>(self, x: i64) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(Value::Number(Number::from(x))))
	}
	fn visit_u64<E: DeError>(self, x: u64) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(Value::Number(Number::from(x))))
	}
	fn visit_f64<E: DeError>(self, x: f64) -> std::result::Result<Self::Value, E> {
		Number::from_f64(x)
			.map(|v| UniqueJson(Value::Number(v)))
			.ok_or_else(|| E::custom("nonfinite JSON value"))
	}
	fn visit_str<E: DeError>(self, x: &str) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(json!(x)))
	}
	fn visit_string<E: DeError>(self, x: String) -> std::result::Result<Self::Value, E> {
		Ok(UniqueJson(Value::String(x)))
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Self::Value, A::Error> {
		let mut values = Vec::new();
		while let Some(UniqueJson(value)) = a.next_element::<UniqueJson>()? {
			values.push(value);
		}
		Ok(UniqueJson(Value::Array(values)))
	}
	fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Self::Value, A::Error> {
		let mut map = Map::new();
		while let Some((key, UniqueJson(value))) = a.next_entry::<String, UniqueJson>()? {
			if map.contains_key(&key) {
				return Err(A::Error::custom(format!("duplicate JSON member {key}")));
			}
			map.insert(key, value);
		}
		Ok(UniqueJson(Value::Object(map)))
	}
}
impl<'de> Deserialize<'de> for UniqueJson {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
		deserializer.deserialize_any(UniqueVisitor)
	}
}

pub(super) fn parse_unique_json(data: &[u8]) -> Result<Value> {
	let record: UniqueJson = serde_json::from_slice(data)
		.context("JSON object contains duplicates or invalid fields")?;
	Ok(record.0)
}
