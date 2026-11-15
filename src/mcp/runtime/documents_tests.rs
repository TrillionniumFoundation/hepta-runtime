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

#[test]
fn remote_document_schema_keeps_transport_configuration_private() {
	assert!(serde_json::from_value::<DocumentReadParams>(
		json!({"path":"/tmp/a.pdf","host":"main","remote":{"ssh_target":"other"}})
	)
	.is_err());
	assert!(serde_json::from_value::<DocumentReadParams>(
		json!({"path":"/tmp/a.pdf","host":"main","file_helper":"code"})
	)
	.is_err());
	assert!(serde_json::from_value::<DocumentReadParams>(
		json!({"path":"/tmp/a.pdf","host":"main"})
	)
	.is_ok());
}
#[test]
fn pdf_operations_are_typed_not_unrestricted_commands() {
	assert!(serde_json::from_value::<PdfPageOperation>(
		json!({"type":"delete","page_indexes":[0],"command":"x"})
	)
	.is_err());
	assert!(serde_json::from_value::<PdfPageOperation>(
		json!({"type":"execute","page_indexes":[0]})
	)
	.is_err());
	assert!(serde_json::from_value::<PdfPageOperation>(
		json!({"type":"insert","page_index":0,"markdown":"Title"})
	)
	.is_ok());
}

#[test]
fn final_format_tools_reject_hidden_interpreters_and_resources() {
	assert!(serde_json::from_value::<DocumentRenderParams>(json!({"path":"/tmp/a.pdf","input_format":"html","content":"Hello","expected_sha256":"absent","url_fetcher":"x"})).is_err());
	assert!(serde_json::from_value::<WorksheetRecalculateParams>(
		json!({"path":"/tmp/a.xlsx","expected_sha256":"x","external_workbooks":true})
	)
	.is_err());
	assert!(
		serde_json::from_value::<DocumentAsset>(json!({"name":"x","path":"/tmp/a.png"})).is_err()
	);
}

#[test]
fn protected_pdf_schema_rejects_raw_secrets_and_hidden_authority() {
	for name in [
		"password",
		"owner_password",
		"user_password",
		"file_helper",
		"root",
	] {
		let mut value =
			json!({"path":"/tmp/fixture.pdf","expected_sha256":"test","action":"inspect"});
		value[name] = json!("not-an-allowed-field");
		assert!(serde_json::from_value::<PdfSecurityParams>(value).is_err());
	}
	assert!(serde_json::from_value::<PdfSecurityParams>(json!({"path":"/tmp/a.pdf","expected_sha256":"hash","action":"inspect","password_file":"/tmp/private"})).is_ok());
}

#[test]
fn trust_roots_are_paths_not_inline_secrets_or_validator_commands() {
	assert!(serde_json::from_value::<PdfSecurityParams>(json!({"path":"/tmp/a.pdf","expected_sha256":"00","action":"inspect","trust_store_file":"/tmp/ca.pem","trust_store_sha256":"11"})).is_ok());
	assert!(serde_json::from_value::<PdfSecurityParams>(json!({"path":"/tmp/a.pdf","expected_sha256":"00","action":"inspect","openssl_command":"anything"})).is_err());
}

#[test]
fn pdf_policy_parameters_are_typed_and_cannot_inject_authority() {
	assert!(serde_json::from_value::<PdfSecurityParams>(
		json!({"path":"/tmp/source.pdf","expected_sha256":"pin","action":"validate_policy"})
	)
	.is_ok());
	assert!(serde_json::from_value::<PdfSecurityParams>(json!({"path":"/tmp/source.pdf","expected_sha256":"pin","action":"fill_form_copy","form_values":{"Name":"Allowed"}})).is_ok());
	assert!(serde_json::from_value::<PdfSecurityParams>(json!({"path":"/tmp/source.pdf","expected_sha256":"pin","action":"validate_policy","allow_network":true})).is_err());
	assert!(serde_json::from_value::<PdfSecurityParams>(json!({"path":"/tmp/source.pdf","expected_sha256":"pin","action":"fill_form_copy","signing_key":"forbidden"})).is_err());
}
