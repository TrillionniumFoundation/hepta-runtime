// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Native document schemas cannot accept hidden policy or interpreter overrides.
use super::*;

#[test]
fn document_schema_rejects_hidden_roots_and_commands() {
	assert!(serde_json::from_value::<DocumentReadParams>(
		json!({"path":"/tmp/a.pdf","roots":["/"]})
	)
	.is_err());
	assert!(serde_json::from_value::<DocumentReadParams>(
		json!({"path":"/tmp/a.pdf","python":"/bin/sh"})
	)
	.is_err());
	assert!(serde_json::from_value::<DocumentWriteParams>(json!({"path":"/tmp/a.pdf","format":"pdf","content":"Hello","expected_sha256":"absent","command":"echo"})).is_err());
}

#[test]
fn document_formats_and_write_expectations_are_explicit() {
	assert!(serde_json::from_value::<DocumentWriteParams>(
		json!({"path":"/tmp/a.pdf","format":"pdf","content":"Hello"})
	)
	.is_err());
	assert!(serde_json::from_value::<DocumentWriteParams>(
		json!({"path":"/tmp/a.bin","format":"binary","content":"AA==","expected_sha256":"absent"})
	)
	.is_err());
	assert!(serde_json::from_value::<DocumentWriteParams>(
		json!({"path":"/tmp/a.docx","format":"docx","content":"Hello","expected_sha256":"absent"})
	)
	.is_ok());
}

#[tokio::test]
async fn worker_capture_is_bounded() {
	assert_eq!(bounded(&b"valid"[..], 5).await.unwrap(), b"valid");
	assert!(bounded(&b"too large"[..], 3).await.is_err());
}
