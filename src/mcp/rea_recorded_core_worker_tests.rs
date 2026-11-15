// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Admission, identity and complete-reply boundaries for the stdin-only worker.

use super::*;
use serde_json::json;
use std::cell::Cell;
use std::io::Cursor;

fn minimal_core() -> Vec<u8> {
	let mut bytes = vec![0_u8; 64];
	bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
	bytes[16..18].copy_from_slice(&4_u16.to_le_bytes());
	bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
	bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
	bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
	bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
	bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
	bytes
}

fn header(bytes: &[u8]) -> Header {
	Header {
		schema: FRAME_SCHEMA.to_owned(),
		sha256: sha256(bytes),
		bytes: bytes.len() as u64,
		max_file_bytes: MAX_INPUT_BYTES,
		max_output_bytes: MAX_OUTPUT_BYTES,
	}
}

fn frame_raw(header: &[u8], bytes: &[u8]) -> Vec<u8> {
	let mut framed = (header.len() as u32).to_le_bytes().to_vec();
	framed.extend_from_slice(header);
	framed.extend_from_slice(bytes);
	framed
}

fn frame(header: &Header, bytes: &[u8]) -> Vec<u8> {
	frame_raw(&serde_json::to_vec(header).unwrap(), bytes)
}

fn invoke(input: &[u8]) -> (i32, Vec<u8>, Vec<u8>) {
	let mut output = Vec::new();
	let mut diagnostics = Vec::new();
	let status = serve_frame(
		&mut Cursor::new(input),
		&mut output,
		&mut diagnostics,
		None,
		|| Ok(()),
	)
	.unwrap();
	(status, output, diagnostics)
}

fn reply(input: &[u8]) -> Value {
	let (status, output, diagnostics) = invoke(input);
	assert_eq!(status, 0);
	assert!(diagnostics.is_empty());
	assert_eq!(output.last(), Some(&b'\n'));
	serde_json::from_slice(&output).unwrap()
}

#[test]
fn admitted_snapshot_has_computed_identity_and_unmodified_core_payload() {
	let bytes = minimal_core();
	let header = header(&bytes);
	let expected = parse_recorded_core(&bytes, MAX_OUTPUT_BYTES).unwrap();
	let value = reply(&frame(&header, &bytes));
	assert_eq!(value["ok"], true);
	assert_eq!(value["profile"], NATIVE_PROFILE);
	assert_eq!(value["snapshot"]["sha256"], header.sha256);
	assert_eq!(value["snapshot"]["bytes"], bytes.len());
	assert_eq!(value["value"], expected);
	assert_eq!(value["value"]["limitations"].as_array().unwrap().len(), 6);
	assert_eq!(value["value"]["target_execution"], "not-performed");
	assert_eq!(value["value"]["live_process_identity"], "unknown");
	assert!(value["value"].get("reported_limits").is_none());
}

#[test]
fn digest_mismatch_never_claims_an_admitted_snapshot_or_parses_it() {
	let bytes = minimal_core();
	let mut claimed = header(&bytes);
	claimed.sha256 = "0".repeat(64);
	let sealed = Cell::new(false);
	let mut output = Vec::new();
	let status = serve_frame(
		&mut Cursor::new(frame(&claimed, &bytes)),
		&mut output,
		&mut Vec::new(),
		None,
		|| {
			sealed.set(true);
			Ok(())
		},
	)
	.unwrap();
	assert_eq!(status, 0);
	assert!(!sealed.get());
	let value: Value = serde_json::from_slice(&output).unwrap();
	assert_eq!(value["ok"], false);
	assert_eq!(value["reason"], "integrity");
	assert!(value.get("snapshot").is_none());
	assert!(value.get("value").is_none());
}

#[test]
fn malformed_headers_and_admission_limits_fail_before_snapshot_read() {
	let bytes = minimal_core();
	let valid = serde_json::to_value(header(&bytes)).unwrap();
	for (field, changed, reason) in [
		("schema", json!("unrecognized"), "protocol"),
		("sha256", json!("A".repeat(64)), "protocol"),
		("sha256", json!("f".repeat(63)), "protocol"),
		("sha256", json!("z".repeat(64)), "protocol"),
		("bytes", json!(-1), "protocol"),
		("bytes", json!(0.5), "protocol"),
		("max_file_bytes", json!(0), "input-limit"),
		("max_file_bytes", json!(MAX_INPUT_BYTES + 1), "input-limit"),
		("max_file_bytes", json!(63), "input-limit"),
		("bytes", json!(u64::MAX), "input-limit"),
		("max_output_bytes", json!(MAX_OUTPUT_BYTES + 1), "protocol"),
	] {
		let mut invalid = valid.clone();
		invalid[field] = changed;
		let raw = serde_json::to_vec(&invalid).unwrap();
		let mut input = Cursor::new(frame_raw(&raw, &bytes));
		let failure = match read_frame(&mut input) {
			Err(failure) => failure,
			Ok(_) => panic!("invalid {field} was admitted"),
		};
		assert_eq!(
			serde_json::to_value(failure.failure.reason).unwrap(),
			reason
		);
		assert_eq!(input.position(), raw.len() as u64 + 4);
	}
}

#[test]
fn header_schema_rejects_duplicates_unknown_fields_and_extra_json() {
	let bytes = minimal_core();
	let raw = serde_json::to_string(&header(&bytes)).unwrap();
	let prefix = raw.strip_suffix('}').unwrap();
	for invalid in [
		format!("{prefix},\"bytes\":64}}"),
		format!("{prefix},\"path\":\"/never/open/this\"}}"),
		format!("{prefix},\"pid\":1}}"),
		format!("{raw}{{}}"),
		"{\"schema\":null}".to_owned(),
	] {
		let value = reply(&frame_raw(invalid.as_bytes(), &bytes));
		assert_eq!(value["reason"], "protocol");
		assert!(value.get("snapshot").is_none());
	}
}

#[test]
fn header_length_boundary_and_every_eof_requirement_are_enforced() {
	let bytes = minimal_core();
	let header = header(&bytes);
	let mut padded = serde_json::to_vec(&header).unwrap();
	padded.resize(MAX_HEADER_BYTES, b' ');
	assert_eq!(reply(&frame_raw(&padded, &bytes))["ok"], true);
	let valid = frame(&header, &bytes);
	let header_end = 4 + serde_json::to_vec(&header).unwrap().len();
	for input in [
		vec![],
		vec![1, 0, 0],
		0_u32.to_le_bytes().to_vec(),
		((MAX_HEADER_BYTES + 1) as u32).to_le_bytes().to_vec(),
		valid[..header_end - 1].to_vec(),
		valid[..valid.len() - 1].to_vec(),
		[valid.as_slice(), &[0]].concat(),
		[valid.as_slice(), b"\n"].concat(),
	] {
		assert_eq!(reply(&input)["reason"], "protocol");
	}
}

#[test]
fn format_and_target_failures_keep_the_reference_reason_and_message() {
	for bytes in [b"not an ELF core".to_vec(), {
		let mut bytes = minimal_core();
		bytes[5] = 2;
		bytes
	}] {
		let expected = parse_recorded_core(&bytes, MAX_OUTPUT_BYTES).unwrap_err();
		let value = reply(&frame(&header(&bytes), &bytes));
		assert_eq!(value["reason"], expected.reason);
		assert_eq!(value["message"], expected.message);
		assert_eq!(value["snapshot"]["bytes"], bytes.len());
		assert!(value.get("value").is_none());
	}
}

#[test]
fn observed_parser_allocation_failure_keeps_its_typed_resource_reason() {
	let failure = WorkerFailure::from(CoreFailure {
		reason: "resource-limit",
		message: "allocation failed; its exact cause remains unknown".to_owned(),
	});
	assert_eq!(failure.reason, Reason::ResourceLimit);
	assert_eq!(
		failure.message,
		"allocation failed; its exact cause remains unknown"
	);
}

#[test]
fn parser_decoder_failure_preserves_the_frozen_upstream_exception_message() {
	let message = "OverflowError: Python int too large to convert to C ssize_t";
	let reply = Reply::failure(
		WorkerFailure::from(CoreFailure {
			reason: "decoder",
			message: message.to_owned(),
		}),
		None,
		None,
	);
	let encoded = serde_json::to_value(reply).unwrap();
	assert_eq!(encoded["ok"], false);
	assert_eq!(encoded["reason"], "decoder");
	assert_eq!(encoded["message"], message);
}

#[test]
fn native_limits_are_outer_metadata_and_policy_failure_is_not_format() {
	let bytes = minimal_core();
	let input = frame(&header(&bytes), &bytes);
	let limits = EffectiveLimits {
		address_space_bytes: 1234,
		cpu_seconds: 2,
		file_size_bytes: 4096,
		open_files: 12,
		core_file_bytes: 0,
	};
	for deny in [false, true] {
		let mut output = Vec::new();
		assert_eq!(
			serve_frame(
				&mut Cursor::new(&input),
				&mut output,
				&mut Vec::new(),
				Some(limits),
				|| if deny {
					anyhow::bail!("fixture isolation failure")
				} else {
					Ok(())
				},
			)
			.unwrap(),
			0
		);
		let value: Value = serde_json::from_slice(&output).unwrap();
		assert_eq!(value["reported_limits"]["address_space_bytes"], 1234);
		assert_eq!(value["reported_limits"]["open_files"], 12);
		if deny {
			assert_eq!(value["reason"], "unavailable");
			assert!(value.get("value").is_none());
		} else {
			assert_eq!(value["value"]["limitations"].as_array().unwrap().len(), 6);
		}
	}
}

#[test]
fn input_io_failure_is_not_misreported_as_malformed_artifact() {
	struct FailedInput(io::ErrorKind);
	impl Read for FailedInput {
		fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
			Err(io::Error::from(self.0))
		}
	}
	for (kind, expected) in [
		(io::ErrorKind::Other, "decoder"),
		(io::ErrorKind::OutOfMemory, "resource-limit"),
	] {
		let mut output = Vec::new();
		let status = serve_frame(
			&mut FailedInput(kind),
			&mut output,
			&mut Vec::new(),
			None,
			|| panic!("unreadable input reached the parser"),
		)
		.unwrap();
		assert_eq!(status, 0);
		let error: Value = serde_json::from_slice(&output).unwrap();
		assert_eq!(error["reason"], expected);
		assert!(error.get("snapshot").is_none());
	}
}

#[test]
fn tiny_output_budgets_deliver_only_the_bounded_original_stderr_diagnostic() {
	let bytes = minimal_core();
	for limit in [0, 1, 16] {
		let mut header = header(&bytes);
		header.max_output_bytes = limit;
		let (status, output, diagnostics) = invoke(&frame(&header, &bytes));
		assert_eq!(status, OUTPUT_LIMIT_EXIT);
		assert!(output.is_empty());
		assert!(diagnostics.len() <= MAX_DIAGNOSTIC_BYTES);
		let diagnostic: Value = serde_json::from_slice(&diagnostics).unwrap();
		assert_eq!(diagnostic["ok"], false);
		assert_eq!(diagnostic["reason"], "output-limit");
		assert!(diagnostic.get("snapshot").is_none());
		assert!(diagnostic.get("value").is_none());
	}
}

#[test]
fn reply_preflight_includes_newline_and_never_writes_a_partial_value() {
	let value = Reply::Success {
		ok: true,
		profile: NATIVE_PROFILE,
		snapshot: Snapshot {
			sha256: "a".repeat(64),
			bytes: 1,
		},
		value: json!({"text": "\0\\\"".repeat(1024)}),
		reported_limits: None,
	};
	let exact = serde_json::to_vec(&value).unwrap().len() + 1;
	assert!(reply_fits(&value, exact).unwrap());
	assert!(!reply_fits(&value, exact - 1).unwrap());
	let mut output = Vec::new();
	let mut diagnostics = Vec::new();
	assert_eq!(
		finish_reply(&mut output, &mut diagnostics, value, 1024).unwrap(),
		0
	);
	assert!(output.len() <= 1024);
	assert!(diagnostics.is_empty());
	let error: Value = serde_json::from_slice(&output).unwrap();
	assert_eq!(error["reason"], "output-limit");
	assert!(error.get("value").is_none());
	assert_eq!(error["snapshot"]["sha256"], "a".repeat(64));
}

#[test]
fn output_flush_failure_is_not_successful_reply_delivery() {
	struct FailedFlush;
	impl Write for FailedFlush {
		fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
			Ok(bytes.len())
		}
		fn flush(&mut self) -> io::Result<()> {
			Err(io::Error::other("fixture reply flush failed"))
		}
	}
	let failure = Reply::failure(
		WorkerFailure::new(Reason::Protocol, "bad input"),
		None,
		None,
	);
	assert!(finish_reply(&mut FailedFlush, &mut Vec::new(), failure, 1024).is_err());
}
