// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

use super::*;
use rmcp::model::{CallToolResult, ContentBlock};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use serde_json::json;

fn assert_legacy_size<T: Serialize + ?Sized>(value: &T) -> usize {
	let expected = serde_json::to_vec(value).unwrap().len();
	assert_eq!(serialized_json_size(value).unwrap(), expected);
	expected
}

#[test]
fn matches_legacy_ascii_unicode_and_every_control_character() {
	for text in [
		"",
		"plain ASCII text",
		"quotes: \" and backslashes: \\ and slash: /",
		"中文🙂é\u{2028}\u{2029}",
		"\0\u{1}\u{8}\u{c}\n\r\t",
	] {
		assert_legacy_size(text);
	}
	let controls: String = (0u8..=0x1f).map(char::from).collect();
	assert_legacy_size(controls.as_str());
	assert_legacy_size(&[0, -1, 123, i64::MAX][..]);
}

#[test]
fn matches_legacy_nested_values_and_scalars() {
	for value in [
		json!(null),
		json!(true),
		json!(false),
		json!(0),
		json!(-123),
		json!(u64::MAX),
		json!(1.25),
		json!([]),
		json!({}),
		json!({
			"_meta": {"request": "中文\n\"\\", "tags": ["a", null, true]},
			"result": {
				"rows": [{"name": "🙂", "values": [0, -1, 1.25]}, {}],
				"nested": {"empty": [], "control": "\u{1}\t\r\n"}
			}
		}),
	] {
		assert_legacy_size(&value);
	}
}

#[test]
fn matches_legacy_sdk_result_with_meta_and_structured_content() {
	let result: CallToolResult = serde_json::from_value(json!({
		"_meta": {"request": "request-中文", "nested": {"tags": [1, "\n"]}},
		"content": [
			{"type": "text", "text": "ASCII 中文🙂 \"\\\n\u{1}"},
			{"type": "text", "text": "second block"}
		],
		"structuredContent": {
			"meta": {"next": null},
			"result": {"rows": [{"id": 7, "text": "中文\t"}], "ok": true}
		},
		"isError": false
	}))
	.unwrap();
	let serialized = serde_json::to_value(&result).unwrap();
	assert_eq!(serialized["_meta"]["request"], "request-中文");
	assert_eq!(
		serialized["structuredContent"]["result"]["rows"][0]["id"],
		7
	);
	assert_legacy_size(&result);

	#[derive(Serialize)]
	struct Envelope<'a> {
		jsonrpc: &'static str,
		id: u64,
		result: &'a CallToolResult,
	}
	assert_legacy_size(&Envelope {
		jsonrpc: "2.0",
		id: 7,
		result: &result,
	});
	assert_legacy_size(&CallToolResult::error(vec![ContentBlock::text(
		"error 中文\n",
	)]));
}

#[test]
fn reports_exact_sdk_sizes_below_at_and_above_caps() {
	let prefix = "中文🙂\"\\\n\r\t\u{1}";
	let base = assert_legacy_size(&CallToolResult::success(vec![ContentBlock::text(prefix)]));
	for cap in [128usize, 64 * 1024, 256 * 1024] {
		for expected in [cap - 1, cap, cap + 1] {
			let text = format!("{prefix}{}", "a".repeat(expected - base));
			let result = CallToolResult::success(vec![ContentBlock::text(text)]);
			assert_eq!(assert_legacy_size(&result), expected);
			assert_eq!(
				serialized_json_size(&result).unwrap() <= cap,
				expected <= cap
			);
		}
	}
}

#[test]
fn preserves_custom_serialize_error_after_partial_output() {
	struct FailsAfterPrefix;
	impl Serialize for FailsAfterPrefix {
		fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
			let mut object = serializer.serialize_struct("FailsAfterPrefix", 2)?;
			object.serialize_field("prefix", "already serialized 中文")?;
			Err(serde::ser::Error::custom(
				"deliberate serialization failure",
			))
		}
	}

	let legacy_error = serde_json::to_vec(&FailsAfterPrefix).unwrap_err();
	let counted_error = serialized_json_size(&FailsAfterPrefix).unwrap_err();
	assert_eq!(counted_error.classify(), legacy_error.classify());
	assert_eq!(counted_error.to_string(), legacy_error.to_string());
	assert_eq!(
		counted_error.to_string(),
		"deliberate serialization failure"
	);
}

#[test]
fn byte_counter_overflow_returns_io_error_without_changing_count() {
	let mut counter = ByteCounter {
		bytes: usize::MAX - 1,
	};
	assert_eq!(counter.write(b"a").unwrap(), 1);
	assert_eq!(counter.bytes, usize::MAX);
	let error = counter.write(b"b").unwrap_err();
	assert_eq!(error.kind(), io::ErrorKind::Other);
	assert_eq!(counter.bytes, usize::MAX);
	assert_eq!(counter.write(b"").unwrap(), 0);
	counter.flush().unwrap();
}

#[test]
#[ignore = "CPU_only microbenchmark; allocations_unmeasured; run explicitly in release mode"]
fn benchmark_escaped_sdk_result_size_counting() {
	use std::hint::black_box;
	use std::time::{Duration, Instant};

	fn old_to_vec(result: &CallToolResult, iterations: usize) -> Duration {
		let started = Instant::now();
		for _ in 0..iterations {
			black_box(serde_json::to_vec(black_box(result)).unwrap().len());
		}
		started.elapsed()
	}

	fn new_counter(result: &CallToolResult, iterations: usize) -> Duration {
		let started = Instant::now();
		for _ in 0..iterations {
			black_box(serialized_json_size(black_box(result)).unwrap());
		}
		started.elapsed()
	}

	for payload_bytes in [64usize * 1024, 256 * 1024] {
		let mut text = "\"\\\n\r\t".repeat(payload_bytes.div_ceil(5));
		text.truncate(payload_bytes);
		let result = CallToolResult::success(vec![ContentBlock::text(text)]);
		let serialized_bytes = assert_legacy_size(&result);
		let iterations = 16 * 1024 * 1024 / payload_bytes;

		// Build and validate the fixture before either timed operation.
		for round in 0..6 {
			let (old_elapsed, new_elapsed) = if round % 2 == 0 {
				let old = old_to_vec(&result, iterations);
				(old, new_counter(&result, iterations))
			} else {
				let new = new_counter(&result, iterations);
				(old_to_vec(&result, iterations), new)
			};
			println!(
				"{}",
				json!({
					"benchmark": "serialized_json_size",
					"scope": "CPU_only",
					"allocations": "allocations_unmeasured",
					"payload_bytes": payload_bytes,
					"serialized_json_bytes": serialized_bytes,
					"iterations": iterations,
					"round": round + 1,
					"order": if round % 2 == 0 { "old_then_new" } else { "new_then_old" },
					"old_to_vec_total_ns": old_elapsed.as_nanos(),
					"new_counter_total_ns": new_elapsed.as_nanos()
				})
			);
		}
	}
}
