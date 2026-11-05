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
use std::io::{Cursor, Write};

const APK: &[u8] = include_bytes!("../../tests/fixtures/rea_apk_signature/rotation-v31.apk");
const DISPLAY_PATH: &str = "/owned/not-opened-by-worker/rotation.apk";

fn header(bytes: &[u8]) -> Value {
	json!({"input":{"path":DISPLAY_PATH},"sha256":digest_hex(&Sha256::digest(bytes)),"bytes":bytes.len()})
}

fn frame(header: &[u8], payload: &[u8]) -> Vec<u8> {
	let mut bytes = (header.len() as u32).to_le_bytes().to_vec();
	bytes.extend_from_slice(header);
	bytes.extend_from_slice(payload);
	bytes
}

#[test]
fn one_frame_binds_only_its_admitted_snapshot_and_display_metadata() {
	let header = serde_json::to_vec(&header(APK)).unwrap();
	let (header, bytes) = read_frame(&mut Cursor::new(frame(&header, APK))).unwrap();
	let result = serde_json::to_value(parse(&header, &bytes)).unwrap();
	assert_eq!(result.as_object().unwrap().len(), 2);
	assert_eq!(result["report"]["artifact"]["path"], DISPLAY_PATH);
	assert_eq!(result["report"]["artifact"]["bytes"], APK.len());
	assert_eq!(result["report"]["artifact"]["sha256"], header.sha256);
	assert_eq!(result["report"]["schemes"]["v3.1"]["present"], true);
	assert_eq!(result["report"]["runtime_execution"], "not-performed");
	assert!(result.get("failure").is_none());
}

#[test]
fn empty_archive_is_a_typed_business_refusal_after_a_valid_frame() {
	let header = serde_json::to_vec(&header(&[])).unwrap();
	let (header, bytes) = read_frame(&mut Cursor::new(frame(&header, &[]))).unwrap();
	let result = serde_json::to_value(parse(&header, &bytes)).unwrap();
	assert_eq!(result.as_object().unwrap().len(), 1);
	assert_eq!(result["failure"]["_tag"], "AnalysisUnsupportedTargetError");
	assert_eq!(result["failure"]["operation"], OP);
	assert!(result.get("report").is_none());
}

#[test]
fn framing_refuses_truncation_trailing_data_and_other_endianness() {
	let encoded = serde_json::to_vec(&header(APK)).unwrap();
	let good = frame(&encoded, APK);
	for count in [0, 1, 3, 4, 5, 4 + encoded.len() - 1, good.len() - 1] {
		assert!(
			read_frame(&mut Cursor::new(&good[..count])).is_err(),
			"{count}"
		);
	}
	for extra in [
		b" ".as_slice(),
		b"\n".as_slice(),
		b"second-frame".as_slice(),
	] {
		let mut bad = good.clone();
		bad.extend_from_slice(extra);
		assert!(read_frame(&mut Cursor::new(bad))
			.unwrap_err()
			.to_string()
			.contains("trailing"));
	}
	let mut big_endian = good;
	big_endian[..4].copy_from_slice(&(encoded.len() as u32).to_be_bytes());
	assert!(read_frame(&mut Cursor::new(big_endian)).is_err());
}

#[test]
fn headers_are_strict_and_refuse_oversized_payloads_before_reservation() {
	let good = header(APK);
	let mut variants = Vec::new();
	for (name, value) in [
		("sha256", json!("A".repeat(64))),
		("sha256", json!("a".repeat(63))),
		("sha256", Value::Null),
		("bytes", json!(-1)),
		("bytes", json!(1.5)),
		("bytes", json!(MAX_BYTES + 1)),
		("unknown", json!(true)),
	] {
		let mut value_header = good.clone();
		value_header[name] = value;
		variants.push(value_header);
	}
	for input in [
		json!({"path":"relative.apk"}),
		json!({"path":"/x\0.apk"}),
		json!({"path":DISPLAY_PATH,"max_file_bytes":1}),
		json!({"path":null}),
	] {
		let mut value_header = good.clone();
		value_header["input"] = input;
		variants.push(value_header);
	}
	for value in variants {
		let encoded = serde_json::to_vec(&value).unwrap();
		assert!(
			read_frame(&mut Cursor::new(frame(&encoded, &[]))).is_err(),
			"{value}"
		);
	}
	let duplicate = format!(
		"{{\"input\":{{\"path\":\"{DISPLAY_PATH}\"}},\"bytes\":0,\"bytes\":0,\"sha256\":\"{}\"}}",
		digest_hex(&Sha256::digest([]))
	);
	assert!(read_frame(&mut Cursor::new(frame(duplicate.as_bytes(), &[]))).is_err());
	let oversized = serde_json::to_vec(
		&json!({"input":{"path":DISPLAY_PATH},"sha256":"a".repeat(64),"bytes":MAX_BYTES + 1}),
	)
	.unwrap();
	assert!(read_frame(&mut Cursor::new(frame(&oversized, &[])))
		.unwrap_err()
		.to_string()
		.contains("512 MiB"));
}

#[test]
fn header_exact_limit_is_admitted_and_limit_plus_one_is_refused() {
	let mut encoded = serde_json::to_vec(&header(APK)).unwrap();
	encoded.resize(rea_worker_transport::MAX_HEADER, b' ');
	assert!(read_frame(&mut Cursor::new(frame(&encoded, APK))).is_ok());
	encoded.push(b' ');
	assert!(read_frame(&mut Cursor::new(frame(&encoded, APK)))
		.unwrap_err()
		.to_string()
		.contains("64 KiB"));
	assert!(read_frame(&mut Cursor::new(0u32.to_le_bytes())).is_err());
}

#[test]
fn claimed_sha256_cannot_relabel_a_different_snapshot() {
	let encoded = serde_json::to_vec(&header(APK)).unwrap();
	let mut bytes = APK.to_vec();
	bytes[0] ^= 1;
	let error = read_frame(&mut Cursor::new(frame(&encoded, &bytes))).unwrap_err();
	assert!(error.to_string().contains("SHA-256 differs"));
}

struct PartialWriter {
	bytes: Vec<u8>,
	remaining: usize,
}
impl Write for PartialWriter {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if self.remaining == 0 {
			return Err(io::Error::other("owned failing sink"));
		}
		let count = bytes.len().min(7).min(self.remaining);
		self.bytes.extend_from_slice(&bytes[..count]);
		self.remaining -= count;
		Ok(count)
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

#[test]
fn streamed_reply_preserves_complete_json_and_propagates_output_failure() {
	let encoded = serde_json::to_vec(&header(APK)).unwrap();
	let (header, bytes) = read_frame(&mut Cursor::new(frame(&encoded, APK))).unwrap();
	let reply = parse(&header, &bytes);
	let expected = serde_json::to_vec(&reply).unwrap();
	let mut sink = PartialWriter {
		bytes: Vec::new(),
		remaining: expected.len() + 1,
	};
	rea_worker_transport::write_json(&mut sink, &reply, expected.len() + 1).unwrap();
	assert_eq!(sink.bytes, [expected.clone(), vec![b'\n']].concat());
	let mut sink = PartialWriter {
		bytes: Vec::new(),
		remaining: expected.len(),
	};
	assert!(rea_worker_transport::write_json(&mut sink, &reply, expected.len() + 1).is_err());
	assert!(rea_worker_transport::write_json(Vec::new(), &reply, expected.len()).is_err());
}

#[tokio::test]
async fn unit_dispatch_keeps_cancellation_separate_from_a_business_refusal() {
	let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
	let lease = Arc::new(semaphore.clone().acquire_owned().await.unwrap());
	let token = CancellationToken::new();
	let bytes = Arc::new(Vec::new());
	let digest = digest_hex(&Sha256::digest(bytes.as_slice()));
	let result = inspect_isolated(
		DISPLAY_PATH,
		&digest,
		bytes.clone(),
		&token,
		lease.clone(),
		Arc::new(()),
	)
	.await
	.unwrap();
	assert_eq!(result["failure"]["_tag"], "AnalysisUnsupportedTargetError");
	token.cancel();
	let failure = inspect_isolated(
		DISPLAY_PATH,
		&digest,
		bytes,
		&token,
		lease.clone(),
		Arc::new(()),
	)
	.await
	.unwrap_err();
	assert_eq!(failure.0["code"], "cancelled");
	assert_eq!(semaphore.available_permits(), 0);
	drop(lease);
	assert_eq!(semaphore.available_permits(), 1);
}
