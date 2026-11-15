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

//! Adversarial ASAR structures and selected-payload integrity. Independent
//! @electron/asar fixture production is exercised by the external qualification.

use super::*;
use std::io::Write;

fn archive(raw_header: &[u8], data: &[u8]) -> Vec<u8> {
	let aligned = raw_header.len().div_ceil(4) * 4;
	let mut bytes = Vec::new();
	for word in [
		4,
		8 + aligned as u32,
		4 + aligned as u32,
		raw_header.len() as u32,
	] {
		bytes.extend_from_slice(&word.to_le_bytes());
	}
	bytes.extend_from_slice(raw_header);
	bytes.resize(16 + aligned, 0);
	bytes.extend_from_slice(data);
	bytes
}

fn run(bytes: &[u8], request: Request) -> Result<Value> {
	let mut file = tempfile::tempfile()?;
	file.write_all(bytes)?;
	inspect_file(&mut file, &request)
}

fn index(bytes: &[u8]) -> Result<Value> {
	run(
		bytes,
		Request::Index {
			offset: 0,
			limit: 256,
		},
	)
}
fn read(bytes: &[u8], member: &str, offset: u64, length: usize) -> Result<Value> {
	run(
		bytes,
		Request::Read {
			member: member.into(),
			offset,
			length,
			require_complete: false,
		},
	)
}

fn fixture_integrity(data: &[u8], block_size: usize) -> Value {
	let blocks: Vec<_> = if data.is_empty() {
		vec![hex(&Sha256::digest([]))]
	} else {
		data.chunks(block_size)
			.map(|b| hex(&Sha256::digest(b)))
			.collect()
	};
	json!({"algorithm":"SHA256","hash":hex(&Sha256::digest(data)),"blockSize":block_size,"blocks":blocks})
}

fn packed(data: &[u8]) -> Vec<u8> {
	archive(
		&serde_json::to_vec(&json!({"files":{"main.js":{"size":data.len(),"offset":"0",
		"integrity":fixture_integrity(data, 4)}}}))
		.expect("header"),
		data,
	)
}

#[test]
fn complete_inventory_distinguishes_packed_unpacked_links_and_empty_members() {
	let raw = serde_json::to_vec(&json!({"files":{
		"sub":{"files":{"π.js":{"offset":"2","size":3,"executable":true}}},
		"package.json":{"offset":"0","size":2},"empty":{"offset":"5","size":0},
		"external":{"size":123,"unpacked":true},"alias":{"link":"sub/π.js"}
	}}))
	.expect("header");
	let bytes = archive(&raw, b"{}abc");
	let result = index(&bytes).expect("ASAR inventory");
	assert_eq!(result["entry_count"], 6);
	assert_eq!(result["entry_counts"]["packed_file"], 3);
	assert_eq!(result["entry_counts"]["unpacked_file"], 1);
	assert_eq!(result["source"]["referenced_payload_bytes"], 5);
	assert_eq!(result["source"]["unreferenced_payload_bytes"], 0);
	assert!(result["source"]["full_sha256"].is_null());
	assert_eq!(result["result"]["rows"][0]["path"], "alias");
	assert_eq!(
		read(&bytes, "sub/π.js", 1, 1).expect("range")["result"]["bytes_hex"],
		"62"
	);
	assert_eq!(
		read(&bytes, "empty", 0, 1).expect("empty")["result"]["length"],
		0
	);
	for path in ["sub", "alias", "external"] {
		assert!(read(&bytes, path, 0, 1).is_err(), "{path}");
	}
}

#[test]
fn complete_member_hash_and_integrity_blocks_must_agree_before_range_delivery() {
	let data = b"abcdefghij";
	let bytes = packed(data);
	let part = read(&bytes, "main.js", 2, 5).expect("verified partial read");
	assert_eq!(part["result"]["bytes_hex"], "6364656667");
	assert_eq!(part["result"]["member_sha256"], hex(&Sha256::digest(data)));
	assert_eq!(part["result"]["member_bytes_verified"], 10);
	assert_eq!(part["result"]["declared_integrity_verified"], true);
	assert_eq!(
		part["result"]["entry"]["integrity"]["content_verified"],
		true
	);
	assert_eq!(
		index(&bytes).expect("inventory")["result"]["rows"][0]["integrity"]["content_verified"],
		false
	);
	assert_eq!(
		part["source"]["header_sha256_scope"],
		"complete_pickle_header"
	);
	assert_eq!(part["result"]["next_offset"], 7);
	assert_eq!(part["result"]["complete_member"], false);
	let mut corrupt = bytes;
	let end = corrupt.len() - 1;
	corrupt[end] ^= 1;
	assert!(
		index(&corrupt).is_ok(),
		"index does not claim payload validation"
	);
	assert!(
		read(&corrupt, "main.js", 0, 1).is_err(),
		"corruption outside delivered range still refuses"
	);
	for data in [b"".as_slice(), b"abcd", b"abcde", b"abcdefgh"] {
		let result = read(&packed(data), "main.js", 0, 64).expect("block boundary");
		assert_eq!(
			result["result"]["member_sha256"],
			hex(&Sha256::digest(data))
		);
		assert_eq!(result["result"]["complete_member"], true);
	}
}

#[test]
fn integrity_declarations_are_strict_and_not_promoted_to_authentication() {
	let data = b"abcd";
	let good = json!({"files":{"a":{"offset":"0","size":4,"integrity":fixture_integrity(data,4)}}});
	for (field, bad) in [
		("algorithm", json!("SHA512")),
		("hash", json!("G".repeat(64))),
		("blockSize", json!(0)),
		("blockSize", json!(1.0)),
		("blocks", json!([])),
		("blocks", json!(["a".repeat(64), "b".repeat(64)])),
	] {
		let mut header = good.clone();
		header["files"]["a"]["integrity"][field] = bad;
		assert!(
			index(&archive(&serde_json::to_vec(&header).expect("json"), data)).is_err(),
			"{field}"
		);
	}
	let mut wrong_block = good.clone();
	wrong_block["files"]["a"]["integrity"]["blocks"][0] = json!("0".repeat(64));
	let bytes = archive(&serde_json::to_vec(&wrong_block).expect("json"), data);
	assert!(
		read(&bytes, "a", 0, 4).is_err(),
		"whole hash alone is insufficient"
	);
	let result = read(&packed(data), "main.js", 0, 4).expect("consistent");
	assert_eq!(result["result"]["publisher_authenticated"], false);
}

#[test]
fn pickle_lengths_padding_utf8_and_duplicate_json_are_refused() {
	let base = archive(br#"{"files":{"a":{"offset":"0","size":1}}}"#, b"x");
	for offset in [0, 4, 8, 12] {
		let mut altered = base.clone();
		altered[offset] ^= 1;
		assert!(index(&altered).is_err(), "Pickle field {offset}");
	}
	for length in 0..16 {
		assert!(index(&base[..length]).is_err(), "prefix length {length}");
	}
	let short = archive(br#"{"files":{}} "#, b"");
	let mut padding = short.clone();
	*padding.last_mut().expect("padding") = 1;
	assert!(index(&padding).is_err());
	for raw in [
		br#"{"files":{},"files":{}}"#.as_slice(),
		br#"{"files":{"a":{"offset":"0","size":0},"\u0061":{"offset":"0","size":0}}}"#,
		br#"{"files":{"a":{"offset":"0","size":0,"size":0}}}"#,
		br#"{"files":{"\ud800":{"offset":"0","size":0}}}"#,
		b"{\"files\":{\"\xff\":{\"offset\":\"0\",\"size\":0}}}",
	] {
		assert!(index(&archive(raw, b"")).is_err(), "{:?}", raw);
	}
}

#[test]
fn sizes_offsets_and_all_member_extents_are_checked_without_float_coercion() {
	for bad in [
		json!(-1),
		json!(1.0),
		json!("1"),
		json!(true),
		json!(9_007_199_254_740_992u64),
	] {
		let header = json!({"files":{"a":{"offset":"0","size":bad}}});
		assert!(index(&archive(&serde_json::to_vec(&header).expect("json"), b"x")).is_err());
	}
	for bad in [
		json!(0),
		json!(""),
		json!("01"),
		json!("+1"),
		json!("-1"),
		json!("0x0"),
		json!("1x"),
		json!("1e0"),
		json!("9007199254740992"),
		json!("18446744073709551616"),
	] {
		let header = json!({"files":{"a":{"offset":bad,"size":0}}});
		assert!(index(&archive(&serde_json::to_vec(&header).expect("json"), b"x")).is_err());
	}
	for (offset, size) in [
		("1", 1),
		("0", 2),
		("9007199254740991", 9_007_199_254_740_991u64),
	] {
		let h = json!({"files":{"a":{"offset":offset,"size":size}}});
		assert!(index(&archive(&serde_json::to_vec(&h).expect("json"), b"x")).is_err());
	}
	assert!(read(&packed(b"abc"), "main.js", 4, 1).is_err());
}

#[test]
fn ambiguous_paths_and_conflicting_node_kinds_are_rejected() {
	for name in ["", ".", "..", "/a", "a/b", "a\\b", "C:", "x\0y", "x\ny"] {
		let header = json!({"files":{name:{"offset":"0","size":0}}});
		assert!(
			index(&archive(&serde_json::to_vec(&header).expect("json"), b"")).is_err(),
			"{name:?}"
		);
	}
	for node in [
		json!({"files":{},"size":0}),
		json!({"link":"a","offset":"0"}),
		json!({"unpacked":true,"offset":"0","size":0}),
		json!({"offset":"0","size":0,"unpacked":"true"}),
		json!({"size":0,"offset":"0","unknown":1}),
		json!({"link":"../outside"}),
	] {
		assert!(index(&archive(
			&serde_json::to_vec(&json!({"files":{"a":node}})).expect("json"),
			b""
		))
		.is_err());
	}
}

#[test]
fn overlaps_refuse_even_when_selected_page_does_not_include_the_bad_entry() {
	let header =
		json!({"files":{"first":{"size":2,"offset":"0"},"second":{"size":2,"offset":"1"}}});
	let bytes = archive(&serde_json::to_vec(&header).expect("json"), b"abc");
	assert!(run(
		&bytes,
		Request::Index {
			offset: 0,
			limit: 1
		}
	)
	.is_err());
	let header = json!({"files":{"a":{"size":0,"offset":"0"},"b":{"size":1,"offset":"1"},"c":{"size":0,"offset":"1"}}});
	let result = index(&archive(
		&serde_json::to_vec(&header).expect("json"),
		b"xyZ",
	))
	.expect("disjoint with zero ranges");
	assert_eq!(result["source"]["referenced_payload_bytes"], 1);
	assert_eq!(result["source"]["unreferenced_payload_bytes"], 2);
}

#[test]
fn header_entry_depth_and_payload_verification_limits_are_enforced() {
	let mut header = json!({"files":{}});
	for _ in 0..34 {
		header = json!({"files":{"d":header}});
	}
	assert!(index(&archive(&serde_json::to_vec(&header).expect("json"), b"")).is_err());
	let files = (0..MAX_ENTRIES + 1)
		.map(|i| (format!("{i:05}"), json!({"offset":"0","size":0})))
		.collect::<Map<_, _>>();
	assert!(index(&archive(
		&serde_json::to_vec(&json!({"files":files})).expect("json"),
		b""
	))
	.is_err());
	let mut oversized = vec![0u8; 16];
	oversized[..4].copy_from_slice(&4u32.to_le_bytes());
	oversized[4..8].copy_from_slice(&(MAX_HEADER_BYTES as u32 + 4).to_le_bytes());
	assert!(index(&oversized).is_err());
	let raw =
		serde_json::to_vec(&json!({"files":{"large":{"size":MAX_VERIFY_BYTES+1,"offset":"0"}}}))
			.expect("json");
	let head = archive(&raw, b"");
	let mut file = tempfile::tempfile().expect("sparse fixture");
	file.write_all(&head).expect("header");
	file.set_len(head.len() as u64 + MAX_VERIFY_BYTES + 1)
		.expect("sparse extent");
	assert!(inspect_file(
		&mut file,
		&Request::Index {
			offset: 0,
			limit: 1
		}
	)
	.is_ok());
	assert!(inspect_file(
		&mut file,
		&Request::Read {
			member: "large".into(),
			offset: 0,
			length: 1,
			require_complete: false
		}
	)
	.is_err());
}

#[test]
fn complete_source_mode_refuses_truncation_instead_of_parsing_a_prefix() {
	let bytes = packed(b"abcdef");
	assert!(run(
		&bytes,
		Request::Read {
			member: "main.js".into(),
			offset: 0,
			length: 5,
			require_complete: true
		}
	)
	.is_err());
	assert!(run(
		&bytes,
		Request::Read {
			member: "main.js".into(),
			offset: 1,
			length: 6,
			require_complete: true
		}
	)
	.is_err());
	assert!(run(
		&bytes,
		Request::Read {
			member: "main.js".into(),
			offset: 0,
			length: 6,
			require_complete: true
		}
	)
	.is_ok());
}
