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

use super::*;
use serde_json::json;
use std::cell::Cell;
use std::collections::BTreeMap;

#[derive(Default)]
struct Orders(BTreeMap<String, Vec<String>>);

impl Orders {
	fn one(keys: &[&str]) -> Self {
		Self(BTreeMap::from([(
			String::new(),
			keys.iter().map(|key| (*key).to_owned()).collect(),
		)]))
	}
}

impl ObjectOrder for Orders {
	fn keys<'a>(
		&self,
		path: &[PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> Result<Vec<&'a str>> {
		self.0
			.get(&pointer(path))
			.context("Missing test order")?
			.iter()
			.map(|name| {
				object
					.get_key_value(name)
					.map(|(key, _)| key.as_str())
					.context("Unknown test member")
			})
			.collect()
	}
}

fn number(value: &Number) -> Result<String> {
	super::super::rea_evidence::canonical_js_number(value)
}

fn budget(bytes: u64, representations: Representations, target_content: bool) -> Budget {
	Budget {
		bytes,
		representations,
		target_content,
	}
}

fn unbounded() -> Budget {
	budget(u64::MAX, Representations::StructuredAndText, false)
}

fn raw_parts(value: &Value, order: &Orders) -> Vec<String> {
	let mut parts = Vec::new();
	assert!(json_parts(value, order, number, &mut |part| {
		parts.push(part.to_owned());
		Ok(true)
	})
	.unwrap());
	parts
}

#[test]
fn exact_wire_budget_and_both_representations_share_the_formatter() {
	let value = json!([1.0, 1e21, 1e20, 1e-6, 1e-7, -0.0, "a\"\\\n\u{0}é😀"]);
	// JavaScript's ordinary numeric wire normalizes 1.0 and negative zero.
	let expected_value = json!([1, 1e21, 1e20, 1e-6, 1e-7, 0, "a\"\\\n\u{0}é😀"]);
	for representations in [
		Representations::StructuredAndText,
		Representations::ErrorText,
	] {
		for target_content in [false, true] {
			let mut wire = Vec::new();
			let b = budget(u64::MAX, representations, target_content);
			let measured =
				write_tool_result(&value, &Orders::default(), number, b, &mut wire).unwrap();
			let Measurement::Fits {
				bytes,
				code_units,
				json_bytes,
				json_code_units,
			} = measured
			else {
				panic!("Unexpected overflow");
			};
			assert_eq!(bytes, wire.len() as u64);
			assert_eq!(
				code_units,
				String::from_utf8(wire.clone())
					.unwrap()
					.encode_utf16()
					.count() as u64
			);
			let response: Value = serde_json::from_slice(&wire).unwrap();
			let text = response["content"][0]["text"].as_str().unwrap();
			assert!(text.starts_with("[1,1e+21,100000000000000000000,0.000001,1e-7,0,"));
			assert_eq!(json_bytes, text.len() as u64);
			assert_eq!(json_code_units, text.encode_utf16().count() as u64);
			assert_eq!(serde_json::from_str::<Value>(text).unwrap(), expected_value);
			if representations == Representations::StructuredAndText {
				assert_eq!(response["structuredContent"], expected_value);
				assert!(response.get("isError").is_none());
			} else {
				assert_eq!(response["isError"], true);
				assert!(response.get("structuredContent").is_none());
			}
			assert_eq!(response.get("_meta").is_some(), target_content);
			assert_eq!(
				measure(&value, &Orders::default(), number, Budget { bytes, ..b }).unwrap(),
				measured
			);
			assert!(
				matches!(measure(&value, &Orders::default(), number, Budget { bytes: bytes - 1, ..b }).unwrap(), Measurement::Overflow { bytes_at_least, constraint: Constraint::ReceiveBuffer, .. } if bytes_at_least == bytes)
			);
		}
	}
}

#[test]
fn short_string_boundary_counts_utf16_instead_of_utf8_bytes() {
	for count in [8191, 8192, 8193] {
		let ascii = Value::String("x".repeat(count));
		let multibyte = Value::String("é".repeat(count));
		for value in [&ascii, &multibyte] {
			let parts = raw_parts(value, &Orders::default());
			assert_eq!(parts.len(), if count <= 8192 { 1 } else { 4 });
			assert_eq!(parts.concat(), serde_json::to_string(value).unwrap());
		}
	}
}

#[test]
fn chunk_boundary_never_splits_a_non_bmp_pair() {
	let value = Value::String(format!("{}😀{}", "a".repeat(8191), "b".repeat(8192)));
	let parts = raw_parts(&value, &Orders::default());
	assert_eq!(
		parts.iter().map(|part| units(part)).collect::<Vec<_>>(),
		[1, 8191, 8192, 2, 1]
	);
	assert!(parts[2].starts_with('😀'));
	assert_eq!(parts.concat(), serde_json::to_string(&value).unwrap());
}

#[test]
fn long_member_names_use_the_same_surrogate_safe_chunks() {
	let key = format!("{}😀tail", "k".repeat(8191));
	let value = Value::Object(Map::from_iter([(key.clone(), json!("value"))]));
	let order = Orders::one(&[&key]);
	let parts = raw_parts(&value, &order);
	assert_eq!(&parts[..4], ["{", "\"", &"k".repeat(8191), "😀tail"]);
	assert_eq!(parts.concat(), serde_json::to_string(&value).unwrap());
}

#[test]
fn sixteen_and_sixty_four_ki_thresholds_flush_whole_parts() {
	let value = json!(vec!["a".repeat(8190); 8]);
	let raw = raw_parts(&value, &Orders::default());
	assert_eq!(
		raw.iter().map(String::len).collect::<Vec<_>>(),
		[16386, 16386, 16386, 16386, 1]
	);
	let mut lengths = Vec::new();
	buffered_parts(&value, &Orders::default(), number, |part| {
		lengths.push(part.len());
		Ok(true)
	})
	.unwrap();
	assert_eq!(lengths, [49158, 16387]);
	assert_eq!(
		measure_json(&value, &Orders::default(), number, 49157).unwrap(),
		JsonMeasurement::Overflow {
			bytes_at_least: 49158
		}
	);
	assert_eq!(
		measure_json(&value, &Orders::default(), number, 49158).unwrap(),
		JsonMeasurement::Overflow {
			bytes_at_least: 65545
		}
	);
}

#[test]
fn escaped_short_key_and_value_can_make_one_part_larger_than_sixty_four_ki() {
	let key = "\0".repeat(8192);
	let value = Value::Object(Map::from_iter([(
		key.clone(),
		Value::String("\0".repeat(8192)),
	)]));
	let order = Orders::one(&[&key]);
	let parts = raw_parts(&value, &order);
	assert_eq!(
		parts.iter().map(String::len).collect::<Vec<_>>(),
		[98310, 1]
	);
	assert_eq!(
		measure_json(&value, &order, number, 65536).unwrap(),
		JsonMeasurement::Overflow {
			bytes_at_least: 98310
		}
	);
	let mut wire = Vec::new();
	let result = write_tool_result(&value, &order, number, unbounded(), &mut wire).unwrap();
	assert!(matches!(result, Measurement::Fits { bytes, .. } if bytes == wire.len() as u64));
}

#[test]
fn control_and_unicode_double_escaping_is_exact() {
	let controls = (0u8..32).map(char::from).collect::<String>();
	let value = Value::String(format!("{controls}\"\\/\u{7f}\u{2028}\u{2029}é😀"));
	let mut wire = Vec::new();
	let measured =
		write_tool_result(&value, &Orders::default(), number, unbounded(), &mut wire).unwrap();
	let expected = json!({"content":[{"type":"text","text":serde_json::to_string(&value).unwrap()}],"structuredContent":value});
	assert_eq!(serde_json::from_slice::<Value>(&wire).unwrap(), expected);
	assert!(matches!(measured, Measurement::Fits { bytes, .. } if bytes == wire.len() as u64));
	let mut escaped = Vec::new();
	EscapeWriter {
		output: &mut escaped,
	}
	.write_all(controls.as_bytes())
	.unwrap();
	let quoted = serde_json::to_string(&controls).unwrap();
	assert_eq!(escaped, quoted.as_bytes()[1..quoted.len() - 1]);
}

#[test]
fn refuses_missing_incomplete_duplicate_and_invalid_numeric_orders() {
	let value = json!({"2":2,"10":10,"z":0,"a":1});
	for order in [
		Orders::default(),
		Orders::one(&["2", "10", "z"]),
		Orders::one(&["2", "10", "z", "z"]),
		Orders::one(&["10", "2", "z", "a"]),
		Orders::one(&["z", "2", "10", "a"]),
		Orders::one(&["2", "10", "z", "absent"]),
	] {
		assert!(measure(&value, &order, number, unbounded()).is_err());
	}
	let mut wire = Vec::new();
	write_json(
		&value,
		&Orders::one(&["2", "10", "z", "a"]),
		number,
		&mut wire,
	)
	.unwrap();
	assert_eq!(wire, br#"{"2":2,"10":10,"z":0,"a":1}"#);
}

#[test]
fn declared_producer_order_handles_optional_fields_and_integer_indices() {
	let value = json!({"4294967295":1,"00":2,"-0":3,"4294967294":4,"10":5,"2":6,"0":7,"z":8});
	let object = value.as_object().unwrap();
	let keys = declared_keys(
		object,
		&[
			"z",
			"4294967295",
			"missing",
			"10",
			"00",
			"2",
			"-0",
			"0",
			"4294967294",
		],
	)
	.unwrap();
	assert_eq!(
		keys,
		["0", "2", "10", "4294967294", "z", "4294967295", "00", "-0"]
	);
	assert!(declared_keys(object, &["z", "z"]).is_err());
	assert!(declared_keys(object, &["z"]).is_err());
}

#[test]
fn explicit_order_changes_the_real_overflow_position() {
	let value = json!({"plain":"a".repeat(150_000),"control":"\0".repeat(150_000)});
	let a = measure(
		&value,
		&Orders::one(&["plain", "control"]),
		number,
		Budget {
			bytes: 100_000,
			..unbounded()
		},
	)
	.unwrap();
	let b = measure(
		&value,
		&Orders::one(&["control", "plain"]),
		number,
		Budget {
			bytes: 100_000,
			..unbounded()
		},
	)
	.unwrap();
	assert_ne!(a, b);
	let complete_a = measure(
		&value,
		&Orders::one(&["plain", "control"]),
		number,
		unbounded(),
	)
	.unwrap();
	let complete_b = measure(
		&value,
		&Orders::one(&["control", "plain"]),
		number,
		unbounded(),
	)
	.unwrap();
	assert_eq!(complete_a, complete_b);
}

#[test]
fn nested_object_order_resolves_full_paths_without_sorting_them() {
	let value = json!({"a/b":[{"~key":{"second":2,"first":1}}],"last":0});
	let orders = Orders(BTreeMap::from([
		(String::new(), vec!["a/b".into(), "last".into()]),
		("/a~1b/0".into(), vec!["~key".into()]),
		(
			"/a~1b/0/~0key".into(),
			vec!["second".into(), "first".into()],
		),
	]));
	let mut wire = Vec::new();
	write_json(&value, &orders, number, &mut wire).unwrap();
	assert_eq!(
		wire,
		br#"{"a/b":[{"~key":{"second":2,"first":1}}],"last":0}"#
	);
}

#[test]
fn early_refusal_does_not_read_later_objects_or_write_partial_wire() {
	struct LateOrder(Cell<usize>);
	impl ObjectOrder for LateOrder {
		fn keys<'a>(
			&self,
			_path: &[PathComponent<'_>],
			_object: &'a Map<String, Value>,
		) -> Result<Vec<&'a str>> {
			self.0.set(self.0.get() + 1);
			bail!("Must not serialize the late object");
		}
	}
	let value = json!(["a".repeat(1_000_000), {"late":1}]);
	let order = LateOrder(Cell::new(0));
	let mut output = Vec::new();
	let result = write_tool_result(
		&value,
		&order,
		number,
		Budget {
			bytes: 1,
			..unbounded()
		},
		&mut output,
	)
	.unwrap();
	assert!(matches!(
		result,
		Measurement::Overflow {
			constraint: Constraint::ReceiveBuffer,
			..
		}
	));
	assert_eq!(order.0.get(), 0);
	assert!(output.is_empty());
}

#[test]
fn iterative_walk_does_not_add_a_depth_128_rejection() {
	let mut value = json!(7);
	for _ in 0..512 {
		value = Value::Array(vec![value]);
	}
	let mut output = Vec::new();
	write_json(&value, &Orders::default(), number, &mut output).unwrap();
	assert_eq!(output.len(), 1025);
	assert_eq!(output[512], b'7');
}

#[test]
fn callback_and_sink_failures_cannot_be_reported_as_success() {
	fn failing_number(_value: &Number) -> Result<String> {
		bail!("Formatter failure");
	}
	assert!(measure(&json!(1), &Orders::default(), failing_number, unbounded()).is_err());
	struct BrokenSink;
	impl Write for BrokenSink {
		fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
			Err(io::Error::new(
				io::ErrorKind::BrokenPipe,
				"injected broken output",
			))
		}
		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}
	}
	assert!(write_tool_result(
		&json!("payload"),
		&Orders::default(),
		number,
		unbounded(),
		&mut BrokenSink
	)
	.is_err());
}

#[test]
fn final_native_json_measurement_has_its_own_real_budget_gate() {
	let value = json!({"id":7,"result":{"x":1.0},"jsonrpc":"2.0"});
	let orders = Orders(BTreeMap::from([
		(
			String::new(),
			vec!["jsonrpc".into(), "id".into(), "result".into()],
		),
		("/result".into(), vec!["x".into()]),
	]));
	let mut wire = Vec::new();
	write_json(&value, &orders, number, &mut wire).unwrap();
	assert_eq!(
		measure_json(&value, &orders, number, wire.len() as u64).unwrap(),
		JsonMeasurement::Fits {
			bytes: wire.len() as u64
		}
	);
	assert_eq!(
		measure_json(&value, &orders, number, wire.len() as u64 - 1).unwrap(),
		JsonMeasurement::Overflow {
			bytes_at_least: wire.len() as u64
		}
	);
	assert_eq!(wire, br#"{"jsonrpc":"2.0","id":7,"result":{"x":1}}"#);
}

#[test]
fn borrowed_bundle_preserves_payload_identity_and_original_field_order() {
	struct IdentityOrder<'a>(&'a Map<String, Value>);
	impl ObjectOrder for IdentityOrder<'_> {
		fn keys<'a>(
			&self,
			path: &[PathComponent<'_>],
			object: &'a Map<String, Value>,
		) -> Result<Vec<&'a str>> {
			assert_eq!(pointer(path), "/result/records/0");
			assert!(
				std::ptr::eq(self.0, object),
				"Record payload must remain borrowed"
			);
			declared_keys(object, &["second", "first"])
		}
	}
	let record = std::sync::Arc::new(json!({"first":1,"second":"x".repeat(100_000)}));
	let records = vec![record.as_ref()];
	let count = Number::from(1);
	let bundle = [
		("artifacts", JsonView::Array(&[])),
		("records", JsonView::Values(&records)),
		("records_count", JsonView::Number(&count)),
		("label", JsonView::String("bundle")),
		("complete", JsonView::Bool(true)),
		("unknown", JsonView::Null),
	];
	let result = [("result", JsonView::Object(&bundle))];
	let view = JsonView::Object(&result);
	let order = IdentityOrder(record.as_object().unwrap());
	let mut wire = Vec::new();
	let measurement = write_tool_result_view(view, &order, number, unbounded(), &mut wire).unwrap();
	assert_eq!(std::sync::Arc::strong_count(&record), 1);
	assert!(matches!(measurement, Measurement::Fits { bytes, .. } if bytes == wire.len() as u64));
	let response: Value = serde_json::from_slice(&wire).unwrap();
	let text = response["content"][0]["text"].as_str().unwrap();
	assert!(text.starts_with("{\"result\":{\"artifacts\":[],\"records\":[{\"second\":\""));
	assert!(text.ends_with("\",\"first\":1}],\"records_count\":1,\"label\":\"bundle\",\"complete\":true,\"unknown\":null}}"));
	assert_eq!(
		response["structuredContent"]["result"]["records"][0],
		*record
	);
}

#[test]
fn borrowed_composition_and_value_have_the_same_refusal_boundary() {
	let payload = Value::String("\0".repeat(150_000));
	let whole = json!({"result":{"payload":payload,"tail":true}});
	let fields = [
		("payload", JsonView::Value(&payload)),
		("tail", JsonView::Bool(true)),
	];
	let root = [("result", JsonView::Object(&fields))];
	let view = JsonView::Object(&root);
	let order = Orders(BTreeMap::from([
		(String::new(), vec!["result".into()]),
		("/result".into(), vec!["payload".into(), "tail".into()]),
	]));
	for bytes in [0, 1, 65535, 65536, 100_000, 1_000_000, u64::MAX] {
		assert_eq!(
			measure_view(
				view,
				&Orders::default(),
				number,
				Budget {
					bytes,
					..unbounded()
				}
			)
			.unwrap(),
			measure(
				&whole,
				&order,
				number,
				Budget {
					bytes,
					..unbounded()
				}
			)
			.unwrap()
		);
		assert_eq!(
			measure_json_view(view, &Orders::default(), number, bytes).unwrap(),
			measure_json(&whole, &order, number, bytes).unwrap()
		);
	}
}

#[test]
fn explicit_borrowed_objects_reject_duplicate_or_reordered_integer_keys() {
	let duplicate = [("x", JsonView::Null), ("x", JsonView::Bool(false))];
	let wrong_numeric = [("10", JsonView::Null), ("2", JsonView::Null)];
	let numeric_after_ordinary = [("x", JsonView::Null), ("2", JsonView::Null)];
	for fields in [&duplicate[..], &wrong_numeric, &numeric_after_ordinary] {
		assert!(measure_view(
			JsonView::Object(fields),
			&Orders::default(),
			number,
			unbounded()
		)
		.is_err());
	}
}

#[test]
fn mixed_borrowed_arrays_and_long_keys_use_the_original_generator() {
	let key = "\0".repeat(8192);
	let text = "\0".repeat(8192);
	let fields = [(key.as_str(), JsonView::String(&text))];
	let children = [JsonView::Object(&fields), JsonView::Bool(false)];
	let view = JsonView::Array(&children);
	let mut parts = Vec::new();
	json_view_parts(view, &Orders::default(), number, &mut |part| {
		parts.push(part.to_owned());
		Ok(true)
	})
	.unwrap();
	assert_eq!(
		parts.iter().map(String::len).collect::<Vec<_>>(),
		[98311, 8]
	);
	let mut plain = Vec::new();
	write_json_view(view, &Orders::default(), number, &mut plain).unwrap();
	assert_eq!(plain, parts.concat().as_bytes());
	assert_eq!(
		serde_json::from_slice::<Value>(&plain).unwrap(),
		json!([{key:text},false])
	);
}
