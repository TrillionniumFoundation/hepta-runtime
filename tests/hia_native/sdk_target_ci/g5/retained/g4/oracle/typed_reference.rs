// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Locked SDK serialization reference for the complete qualified corpus.
// Actual locked SDK typed values, including direct serializer order.
use rmcp::model::{
	Annotations, CallToolResult, ContentBlock, CreateTaskResult, ErrorData, InputRequiredResult,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{self, BufRead};

fn project<T: Serialize>(tag: u64, typed: T) -> (u64, Value, String) {
	let bytes = serde_json::to_vec(&typed).unwrap();
	(
		tag,
		serde_json::to_value(&typed).unwrap(),
		String::from_utf8(bytes).unwrap(),
	)
}

pub fn observe(case: Value) -> Value {
		let body = case["body"].clone();
		let (tag, typed, typed_bytes) = match case["variant"].as_str().unwrap() {
			"complete_some_null" => {
				let mut result = CallToolResult::default();
				result.structured_content = Some(Value::Null);
				result.meta = Some(Default::default());
				project(1, result)
			}
			"error_some_null" => {
				project(2, ErrorData::internal_error("some null", Some(Value::Null)))
			}
			"text" => {
				let content = vec![ContentBlock::text(body["text"].as_str().unwrap())];
				let result = if body["error"].as_bool().unwrap() {
					CallToolResult::error(content)
				} else {
					CallToolResult::success(content)
				};
				project(1, result)
			}
			"priority_bits" => {
				let mut result: CallToolResult = serde_json::from_value(body).unwrap();
				let bits = case["bits"].as_u64().unwrap() as u32;
				let annotations = Annotations::default().with_priority(f32::from_bits(bits));
				for block in &mut result.content {
					match block {
						ContentBlock::Text(value) => value.annotations = Some(annotations.clone()),
						ContentBlock::Image(value) => value.annotations = Some(annotations.clone()),
						ContentBlock::Audio(value) => value.annotations = Some(annotations.clone()),
						ContentBlock::Resource(value) => {
							value.annotations = Some(annotations.clone())
						}
						ContentBlock::ResourceLink(value) => {
							value.annotations = Some(annotations.clone())
						}
						_ => panic!("fixed typed content corpus"),
					}
				}
				project(1, result)
			}
			"deep_meta" | "deep_structured" => {
				let mut value = json!({"kept": [null, -0.0]});
				for _ in 0..case["depth"].as_u64().unwrap() {
					value = json!([value]);
				}
				let mut result = CallToolResult::success(vec![ContentBlock::text("deep")]);
				if case["variant"] == "deep_meta" {
					result.meta = Some(serde_json::from_value(json!({"nested": value})).unwrap());
				} else {
					result.structured_content = Some(value);
				}
				project(1, result)
			}
			"complete" => project(1, serde_json::from_value::<CallToolResult>(body).unwrap()),
			"error" => project(2, serde_json::from_value::<ErrorData>(body).unwrap()),
			"input_required" => project(
				3,
				serde_json::from_value::<InputRequiredResult>(body).unwrap(),
			),
			"task" => project(3, serde_json::from_value::<CreateTaskResult>(body).unwrap()),
			other => panic!("unknown fixture variant {other}"),
		};

 json!({"label":case["label"],"tag":tag,"body":serde_json::to_string(&typed).unwrap(),"typed_bytes":typed_bytes})
}
