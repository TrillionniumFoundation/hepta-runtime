// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Causal serialization and exact-envelope boundary tests; no network changes.
use super::*;
use serde_json::json;

fn sdk_len(text: &str) -> usize {
	serde_json::to_vec(&CallToolResult::success(vec![ContentBlock::text(text)]))
		.unwrap()
		.len()
}
#[test]
fn ordinary_output_preserves_exact_legacy_pretty_bytes() {
	let value = json!({"links":{"exit_code":0,"data":[]},"routes":{"exit_code":0,"data":[]},"listeners":{"exit_code":0,"data":"中文🙂\n"}});
	assert_eq!(
		network_result(&value).unwrap(),
		serde_json::to_string_pretty(&value).unwrap()
	);
}
#[test]
fn dense_routes_compact_all_fields_without_raising_the_one_mib_limit() {
	let value = json!({"routes":{"exit_code":0,"data":vec![json!({"dst":"198.18.0.0/24","dev":"test0","metric":1});13000]},"links":[],"listeners":"quoted \"value\""});
	let pretty = serde_json::to_string_pretty(&value).unwrap();
	let compact = serde_json::to_string(&value).unwrap();
	assert!(sdk_len(&pretty) > LIMIT);
	assert!(sdk_len(&compact) <= LIMIT);
	let actual = network_result(&value).unwrap();
	assert_eq!(actual, compact);
	assert_eq!(serde_json::from_str::<Value>(&actual).unwrap(), value);
	assert!(sdk_len(&actual) <= LIMIT);
}
#[test]
fn escaped_sdk_envelope_not_inner_text_controls_admission() {
	let value = json!({"listeners":"\"\n\\".repeat(90)});
	let compact = serde_json::to_string(&value).unwrap();
	assert!(sdk_len(&compact) > compact.len());
	assert!(network_result_with_limit(&value, compact.len()).is_err());
}
#[test]
fn exact_compact_envelope_boundary_is_accepted_and_one_less_refused() {
	let value = json!({"routes":vec![json!({"a":1,"b":2});10]});
	let compact = serde_json::to_string(&value).unwrap();
	let n = sdk_len(&compact);
	assert_eq!(network_result_with_limit(&value, n).unwrap(), compact);
	assert!(network_result_with_limit(&value, n - 1).is_err());
}
#[test]
fn oversized_full_data_yields_small_explicit_error_not_truncated_success() {
	let value = json!({"listeners":"PRIVATE_UNRETURNED".repeat(LIMIT/4)});
	let error = network_result(&value).unwrap_err().to_string();
	assert!(error.contains("no fields were truncated"));
	assert!(!error.contains("PRIVATE_UNRETURNED"));
	assert!(error.len() < 256);
}
#[test]
fn unicode_and_control_bytes_roundtrip_without_loss() {
	let value = json!({"x":"中文🙂\u{0}\u{1}\n\r\t\\\"","numbers":[0,-1,123,1.25],"empty":null});
	let text = network_result(&value).unwrap();
	assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), value);
}
#[test]
fn bounded_writer_never_accepts_an_over_limit_chunk() {
	let mut writer = LimitedWriter {
		bytes: vec![],
		limit: 3,
	};
	assert_eq!(writer.write(b"ab").unwrap(), 2);
	assert!(writer.write(b"cd").is_err());
	assert_eq!(writer.bytes, b"ab");
	assert_eq!(writer.write(b"c").unwrap(), 1);
	assert!(writer.write(b"d").is_err());
}
#[test]
#[ignore = "requires an explicitly supplied private captured network sample"]
fn exact_rust_current_network_sample_retains_complete_json() {
	let path =
		std::env::var("HEPTA_PRIVATE_NETWORK_SAMPLE").expect("explicit captured sample path");
	let bytes = std::fs::read(path).unwrap();
	let value: Value = serde_json::from_slice(&bytes).unwrap();
	let pretty = serde_json::to_string_pretty(&value).unwrap();
	let actual = network_result(&value).unwrap();
	assert!(sdk_len(&pretty) > LIMIT);
	assert!(sdk_len(&actual) <= LIMIT);
	assert_eq!(serde_json::from_str::<Value>(&actual).unwrap(), value);
	println!(
		"EXACT_RUST_SIZE_PROOF raw={} legacy_sdk={} repaired_sdk={} bound={}",
		bytes.len(),
		sdk_len(&pretty),
		sdk_len(&actual),
		LIMIT
	);
}
