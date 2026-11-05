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

#[test]
fn integer_valued_json_numbers_and_exact_input_shape() {
	for raw in [
		r#"{"path":"/probe","max_entries":1.0,"max_file_bytes":64.0}"#,
		r#"{"path":"/probe","max_entries":1e0,"max_file_bytes":6.4e1}"#,
	] {
		let input = Input::parse(&serde_json::from_str(raw).unwrap()).unwrap();
		assert_eq!(input.max_entries, 1);
		assert_eq!(input.max_file_bytes, 64);
	}
	for raw in [
		json!({"path":"/probe","detail":"complete"}),
		json!({"path":null}),
		json!({"path":"/probe","max_entries":null}),
		json!({"path":"relative"}),
		json!({"path":"/probe","max_entries":1.5}),
		json!({"path":"/probe","max_file_bytes":63}),
	] {
		assert!(Input::parse(&raw).is_err(), "{raw}");
	}
}

#[tokio::test]
async fn captured_identity_is_bound_and_parser_failure_does_not_publish_a_record() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("probe.elf");
	let bytes = [0_u8; 64];
	tokio::fs::write(&path, bytes).await.unwrap();
	let input = Input::parse(&json!({"path":path,"max_file_bytes":64})).unwrap();
	let (snapshot, digest) = capture(
		&input,
		&[dir.path().to_path_buf()],
		&CancellationToken::new(),
	)
	.await
	.unwrap();
	assert_eq!(snapshot, bytes);
	assert_eq!(digest, super::super::rea_source_map::sha256(&bytes));
	let error = execute(
		input,
		&[dir.path().to_path_buf()],
		&CancellationToken::new(),
	)
	.await
	.unwrap_err();
	assert_eq!(error.0["code"], "invalid_request");
	assert!(error.0["details"].get("partial_observation").is_none());
}

#[test]
fn cancellation_and_timeout_are_retryable_and_keep_typed_recovery() {
	assert_eq!(Failure::cancelled(OP).0["retryable"], true);
	let timeout = Failure::timeout(OP, DEADLINE_MS).0;
	assert_eq!(
		timeout["recovery"],
		json!({"kind":"inspect_timeout_state","operation":OP,"timeout_ms":30000})
	);
}
