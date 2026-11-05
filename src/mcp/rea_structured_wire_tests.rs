// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Actual byte framing and producer-order checks for the isolated STDIO writer.

use super::*;
use rmcp::model::{ContentBlock, RequestId};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn result(text: &str) -> CallToolResult {
	let mut result = CallToolResult::success(vec![ContentBlock::text(text.to_owned())]);
	result.structured_content = Some(serde_json::from_str(text).unwrap());
	result.is_error = None;
	result.meta = Some(rmcp::model::MetaObject(
		json!({"keep":"metadata"}).as_object().unwrap().clone(),
	));
	result
}

fn sample() -> &'static str {
	r#"{"operation":"inspect_analysis_view","parameters":{"view":{"offset":0,"limit":1,"collection":"signers","kind":"apk-signature"}},"normalized_result":{"items":[{"z":1,"a":2}]}}"#
}

#[derive(Serialize)]
struct SdkFrame<'a> {
	jsonrpc: &'static str,
	id: RequestId,
	result: &'a CallToolResult,
}

fn frame(result: &CallToolResult) -> Vec<u8> {
	let mut bytes = serde_json::to_vec(&SdkFrame {
		jsonrpc: "2.0",
		id: serde_json::from_value(json!("same-id")).unwrap(),
		result,
	})
	.unwrap();
	bytes.push(b'\n');
	bytes
}

fn structured(frame: &[u8]) -> String {
	let envelope: Frame<'_> = serde_json::from_slice(frame).unwrap();
	let field: StructuredField<'_> = serde_json::from_str(envelope.result.unwrap().get()).unwrap();
	field.structured.unwrap().get().to_owned()
}

#[test]
fn both_representations_keep_current_origin_without_a_request_id_registry() {
	let texts = [
		sample(),
		r#"{"operation":"inspect_analysis_view","parameters":{"view":{"kind":"apk-signature","offset":0,"limit":1,"collection":"signers"}},"normalized_result":{"items":[{"z":1,"a":2}]}}"#,
	];
	let mut semantics = None;
	for text in texts {
		let result = result(text);
		let mut bytes = frame(&result);
		let original: Value = serde_json::from_slice(&bytes).unwrap();
		rewrite(&mut bytes, 16384).unwrap();
		assert_eq!(structured(&bytes), text);
		assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), original);
		if let Some(previous) = &semantics {
			assert_eq!(previous, &original);
		}
		semantics = Some(original);
		let guarded = serde_json::to_vec(&WireToolResult(&result)).unwrap();
		let envelope: Frame<'_> = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(envelope.result.unwrap().get().as_bytes(), guarded);
	}
}

#[test]
fn mismatched_duplicate_error_and_unrelated_results_keep_exact_sdk_bytes() {
	let mut cases = Vec::new();
	let mut mismatch = result(sample());
	mismatch.structured_content.as_mut().unwrap()["operation"] = json!("inspect_apk_signature");
	cases.push(mismatch);
	cases.push(result(
		r#"{"operation":"inspect_analysis_view","n":0,"n":1}"#,
	));
	cases.push(result(r#"{"operation":"unrelated","z":1,"a":2}"#));
	cases.push(result(
		"{\n\"operation\":\"inspect_analysis_view\",\"z\":1,\"a\":2}",
	));
	cases.push(result(
		"{\r\"operation\":\"inspect_analysis_view\",\"z\":1,\"a\":2}",
	));
	let mut error = result(sample());
	error.is_error = Some(true);
	cases.push(error);
	for result in cases {
		let mut bytes = frame(&result);
		let original = bytes.clone();
		rewrite(&mut bytes, 16384).unwrap();
		assert_eq!(bytes, original);
		assert_eq!(
			serde_json::to_vec(&WireToolResult(&result)).unwrap(),
			serde_json::to_vec(&result).unwrap()
		);
	}
}

#[test]
fn guard_and_writer_count_original_number_spelling_and_optional_sdk_fields() {
	let text = r#"{"operation":"inspect_analysis_view","n":0.0000001,"z":1}"#;
	let result = result(text);
	let mut bytes = frame(&result);
	let original_length = bytes.len();
	rewrite(&mut bytes, 16384).unwrap();
	assert!(bytes.len() > original_length);
	assert_eq!(structured(&bytes), text);
	let envelope: Frame<'_> = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(
		envelope.result.unwrap().get().as_bytes(),
		serde_json::to_vec(&WireToolResult(&result)).unwrap()
	);
	assert!(rewrite(&mut frame(&result), original_length).is_err());
}

async fn written(chunks: Vec<Vec<u8>>, limit: usize, flush_first: bool) -> Vec<u8> {
	let (stream, mut receiver) = tokio::io::duplex(37);
	let read = tokio::spawn(async move {
		let mut output = Vec::new();
		receiver.read_to_end(&mut output).await.unwrap();
		output
	});
	let mut writer = StructuredWriter::with_limit(stream, limit);
	for (index, chunk) in chunks.iter().enumerate() {
		writer.write_all(chunk).await.unwrap();
		if flush_first && index == 0 {
			writer.flush().await.unwrap();
		}
	}
	writer.shutdown().await.unwrap();
	drop(writer);
	read.await.unwrap()
}

#[tokio::test]
async fn arbitrary_write_fragments_and_multiple_lines_preserve_frame_boundaries() {
	let input = frame(&result(sample()));
	let chunks = input
		.chunks(13)
		.map(<[u8]>::to_vec)
		.chain(input.chunks(29).map(<[u8]>::to_vec))
		.collect();
	let mut expected = input.clone();
	rewrite(&mut expected, 16384).unwrap();
	assert_eq!(
		written(chunks, 16384, false).await,
		[expected.as_slice(), expected.as_slice()].concat()
	);
}

#[tokio::test]
async fn larger_unrelated_lines_bypass_the_extra_buffer_and_next_frame_recovers() {
	let long = format!("{{\"unrelated\":\"{}\"}}\n", "x".repeat(4096)).into_bytes();
	let input = frame(&result(sample()));
	let mut expected = input.clone();
	rewrite(&mut expected, 2048).unwrap();
	let combined = [long.as_slice(), input.as_slice()].concat();
	assert_eq!(
		written(
			combined.chunks(101).map(<[u8]>::to_vec).collect(),
			2048,
			false
		)
		.await,
		[long.as_slice(), expected.as_slice()].concat()
	);
}

#[tokio::test]
async fn explicitly_flushed_partial_line_is_never_rewritten_after_emission() {
	let input = frame(&result(sample()));
	let mut expected = input.clone();
	rewrite(&mut expected, 16384).unwrap();
	let chunks = vec![input[..23].to_vec(), input[23..].to_vec(), input.clone()];
	assert_eq!(
		written(chunks, 16384, true).await,
		[input.as_slice(), expected.as_slice()].concat()
	);
}

#[tokio::test]
async fn cancelled_flush_retains_accepted_frame_until_later_send_drains() {
	let (stream, mut receiver) = tokio::io::duplex(17);
	let mut writer = StructuredWriter::with_limit(stream, 16384);
	let input = frame(&result(sample()));
	writer.write_all(&input).await.unwrap();
	assert!(
		tokio::time::timeout(std::time::Duration::from_millis(10), writer.flush())
			.await
			.is_err()
	);
	let read = tokio::spawn(async move {
		let mut output = Vec::new();
		receiver.read_to_end(&mut output).await.unwrap();
		output
	});
	writer.write_all(&input).await.unwrap();
	writer.shutdown().await.unwrap();
	drop(writer);
	let mut expected = input;
	rewrite(&mut expected, 16384).unwrap();
	assert_eq!(
		read.await.unwrap(),
		[expected.as_slice(), expected.as_slice()].concat()
	);
}
